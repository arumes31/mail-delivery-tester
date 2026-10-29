"""Security boundary helpers for MailDT.

This module deliberately has no Flask or database imports so its fail-closed
configuration and network policies can be tested without starting the service.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import os
import re
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
LOGIN_ENDPOINTS = {
    "/": "homepage",
    "/dashboard": "index",
    "/settings": "settings",
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


def safe_login_endpoint(candidate: str | None) -> str | None:
    """Map an exact local login destination to a server-owned endpoint."""
    target = safe_local_redirect(candidate)
    if target is None:
        return None
    return LOGIN_ENDPOINTS.get(target)


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


# Raster formats accepted for widget icons, keyed by served extension.
WIDGET_ICON_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "ico": "image/x-icon",
}
WIDGET_URL_SCHEMES = frozenset({"http", "https"})
_WIDGET_COLOR = re.compile(r"#[0-9a-fA-F]{3,8}")


def detect_image_type(data: bytes) -> str | None:
    """Return the icon extension matching the file's magic bytes, or None."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    return None


def safe_widget_url(candidate: str | None) -> str | None:
    """Return an absolute http(s) URL suitable for a public link, or None."""
    if not candidate:
        return None
    url = candidate.strip()
    if not url or len(url) > 255 or any(ord(char) < 32 for char in url):
        return None
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in WIDGET_URL_SCHEMES or not parsed.netloc:
        return None
    return url


def safe_widget_color(candidate: str | None, default: str) -> str:
    """Accept only hex colours because the value is rendered into style attributes."""
    if candidate and _WIDGET_COLOR.fullmatch(candidate.strip()):
        return candidate.strip()
    return default


def totp_matched_step(totp, code: str | None, for_time: datetime.datetime, valid_window: int = 1) -> int | None:
    """Return the TOTP time step that CODE matches within the window, or None."""
    if not code:
        return None
    current = totp.timecode(for_time)
    for offset in range(-valid_window, valid_window + 1):
        step = current + offset
        if hmac.compare_digest(str(code), totp.generate_otp(step)):
            return step
    return None


REDACTED_EMAIL = "***"


def mask_email(address: str | None) -> str | None:
    """Mask an address for public display, redacting anything unparseable."""
    if not address:
        return address
    # The domain can never contain "@", so the last one splits even quoted local parts.
    user, sep, domain = address.rpartition("@")
    labels = domain.split(".")
    if not sep or not user or not all(labels):
        return REDACTED_EMAIL
    masked_user = user[0] + "***" + user[-1] if len(user) > 2 else user[0] + "***"
    masked_domain = labels[0][0] + "***"
    if len(labels) > 1:
        masked_domain += "." + labels[-1]
    return f"{masked_user}@{masked_domain}"


_LOG_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _escape_log_char(match: re.Match) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def log_safe(value, limit: int = 200) -> str:
    """Render untrusted text on one log line, escaping control characters."""
    text = str(value)
    if len(text) > limit:
        text = text[:limit] + "..."
    return _LOG_UNSAFE.sub(_escape_log_char, text)


def probe_receipt_token(secret_key: str, guid: str) -> str:
    """Private proof that a returned probe is the one MailDT sent.

    The GUID is a public display identifier; this token travels only in the
    outbound probe and is never returned by the monitoring APIs.
    """
    material = f"maildt-probe-receipt\0{guid}".encode()
    return hmac.new(secret_key.encode(), material, hashlib.sha256).hexdigest()[:32]


def valid_probe_receipt(secret_key: str, guid: str, token: str | None) -> bool:
    return bool(token) and hmac.compare_digest(probe_receipt_token(secret_key, guid), token)
