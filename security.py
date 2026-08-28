"""Security boundary helpers for MailDT.

This module deliberately has no Flask or database imports so its fail-closed
configuration and network policies can be tested without starting the service.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import socket
from pathlib import Path
from urllib.parse import unquote, urlsplit

from werkzeug.middleware.proxy_fix import ProxyFix


class SecurityConfigurationError(RuntimeError):
    """Raised when a security-sensitive deployment setting is unsafe."""


class SMTPDestinationError(ValueError):
    """Raised when a diagnostic destination violates the egress policy."""


KNOWN_SECRET_DEFAULTS = {
    "admin",
    "changeme",
    "change-me",
    "maildt-default-secret-key-change-me",
    "password",
    "securepassword",
}


def read_secret(name: str, *, minimum_length: int) -> str:
    """Read a required secret from NAME or NAME_FILE and validate it."""
    direct = os.environ.get(name)
    file_name = os.environ.get(f"{name}_FILE")
    if direct and file_name:
        raise SecurityConfigurationError(
            f"set only one of {name} or {name}_FILE"
        )
    if file_name:
        try:
            direct = Path(file_name).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise SecurityConfigurationError(
                f"cannot read {name}_FILE"
            ) from exc
    if not direct:
        raise SecurityConfigurationError(f"{name} is required")
    if len(direct) < minimum_length:
        raise SecurityConfigurationError(
            f"{name} must contain at least {minimum_length} characters"
        )
    if direct.strip().lower() in KNOWN_SECRET_DEFAULTS:
        raise SecurityConfigurationError(f"{name} uses a known default value")
    return direct


def read_optional_secret(name: str) -> str | None:
    """Read an optional secret from NAME or NAME_FILE."""
    direct = os.environ.get(name)
    file_name = os.environ.get(f"{name}_FILE")
    if direct and file_name:
        raise SecurityConfigurationError(
            f"set only one of {name} or {name}_FILE"
        )
    if file_name:
        try:
            direct = Path(file_name).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise SecurityConfigurationError(
                f"cannot read {name}_FILE"
            ) from exc
    return direct or None


def session_version(secret_key: str, username: str, password: str, totp: str) -> str:
    """Bind sessions to the current authentication configuration."""
    material = "\0".join((username, password, totp)).encode()
    return hmac.new(secret_key.encode(), material, hashlib.sha256).hexdigest()


def safe_local_redirect(candidate: str | None) -> str | None:
    """Return a normalized local redirect target or None."""
    if not candidate:
        return None
    decoded = unquote(candidate)
    if any(ord(char) < 32 for char in decoded):
        return None
    if "\\" in decoded or decoded.startswith("//"):
        return None
    parsed = urlsplit(decoded)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
        return None
    return candidate


def parse_cidrs(value: str | None) -> tuple[ipaddress._BaseNetwork, ...]:
    """Parse a comma-separated trusted-proxy CIDR list."""
    if not value:
        return ()
    networks = []
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=True))
        except ValueError as exc:
            raise SecurityConfigurationError(
                f"invalid trusted proxy CIDR: {entry}"
            ) from exc
    return tuple(networks)


class TrustedProxyMiddleware:
    """Apply ProxyFix only when the immediate peer is explicitly trusted."""

    def __init__(self, app, trusted_cidrs):
        self.app = app
        self.trusted_cidrs = tuple(trusted_cidrs)
        self.proxy_app = ProxyFix(
            app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1
        )

    def __call__(self, environ, start_response):
        try:
            peer = ipaddress.ip_address(environ.get("REMOTE_ADDR", ""))
        except ValueError:
            peer = None
        if peer is not None and any(peer in network for network in self.trusted_cidrs):
            return self.proxy_app(environ, start_response)
        return self.app(environ, start_response)


def parse_allowed_hosts(value: str | None) -> frozenset[str]:
    hosts = set()
    for entry in (value or "").split(","):
        entry = entry.strip().rstrip(".").lower()
        if entry:
            hosts.add(entry.encode("idna").decode("ascii"))
    return frozenset(hosts)


def parse_allowed_ports(value: str | None) -> frozenset[int]:
    ports = set()
    for entry in (value or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            port = int(entry)
        except ValueError as exc:
            raise SecurityConfigurationError(
                f"invalid SMTP diagnostic port: {entry}"
            ) from exc
        if not 1 <= port <= 65535:
            raise SecurityConfigurationError(
                f"invalid SMTP diagnostic port: {entry}"
            )
        ports.add(port)
    return frozenset(ports)


def resolve_smtp_destination(
    host: str,
    port: int,
    *,
    allowed_hosts: frozenset[str],
    allowed_ports: frozenset[int],
    resolver=socket.getaddrinfo,
) -> tuple[str, int]:
    """Resolve an allowlisted public SMTP target once and return its IP."""
    candidate = (host or "").strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        raise SMTPDestinationError("invalid SMTP host")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise SMTPDestinationError("IP literals are not allowed")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise SMTPDestinationError("invalid SMTP host") from exc
    if candidate not in allowed_hosts:
        raise SMTPDestinationError("SMTP host is not allowlisted")
    if port not in allowed_ports:
        raise SMTPDestinationError("SMTP port is not allowlisted")

    try:
        answers = resolver(candidate, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SMTPDestinationError("SMTP host could not be resolved") from exc
    if not answers:
        raise SMTPDestinationError("SMTP host could not be resolved")

    public_addresses = []
    for answer in answers:
        address = answer[4][0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise SMTPDestinationError("resolver returned an invalid address") from exc
        if not parsed.is_global:
            raise SMTPDestinationError(
                "SMTP host resolves to a private or reserved address"
            )
        public_addresses.append(str(parsed))
    return public_addresses[0], port
