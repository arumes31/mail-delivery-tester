import socket
from pathlib import Path

import pytest

from security import (
    SMTPDestinationError,
    TrustedProxyMiddleware,
    parse_allowed_hosts,
    parse_allowed_ports,
    parse_cidrs,
    read_secret,
    resolve_smtp_destination,
    safe_local_redirect,
    safe_login_endpoint,
    session_version,
)


def test_required_secret_fails_closed_when_missing_or_weak(monkeypatch):
    monkeypatch.delenv('TEST_SECRET', raising=False)
    monkeypatch.delenv('TEST_SECRET_FILE', raising=False)
    with pytest.raises(RuntimeError, match='required'):
        read_secret('TEST_SECRET', minimum_length=16)
    monkeypatch.setenv('TEST_SECRET', 'admin')
    with pytest.raises(RuntimeError, match='at least'):
        read_secret('TEST_SECRET', minimum_length=16)


def test_required_secret_supports_file_mounts(monkeypatch):
    secret_file = Path(__file__).parent / 'fixtures' / 'secret'
    monkeypatch.delenv('TEST_SECRET', raising=False)
    monkeypatch.setenv('TEST_SECRET_FILE', str(secret_file))
    assert read_secret('TEST_SECRET', minimum_length=16) == 'correct horse battery staple'


def test_required_secret_rejects_ambiguous_sources(monkeypatch):
    secret_file = Path(__file__).parent / 'fixtures' / 'secret'
    monkeypatch.setenv('TEST_SECRET', 'direct-secret-long-enough')
    monkeypatch.setenv('TEST_SECRET_FILE', str(secret_file))
    with pytest.raises(RuntimeError, match='only one'):
        read_secret('TEST_SECRET', minimum_length=16)


def test_proxy_and_port_configuration_reject_invalid_values():
    with pytest.raises(RuntimeError, match='trusted proxy CIDR'):
        parse_cidrs('10.0.0.1/8')
    with pytest.raises(RuntimeError, match='diagnostic port'):
        parse_allowed_ports('not-a-port')
    with pytest.raises(RuntimeError, match='diagnostic port'):
        parse_allowed_ports('0')


def test_session_version_changes_with_every_authentication_input():
    baseline = session_version("s" * 32, "admin", "p" * 16, "totp")
    assert session_version("x" * 32, "admin", "p" * 16, "totp") != baseline
    assert session_version("s" * 32, "other", "p" * 16, "totp") != baseline
    assert session_version("s" * 32, "admin", "q" * 16, "totp") != baseline
    assert session_version("s" * 32, "admin", "p" * 16, "new") != baseline


@pytest.mark.parametrize(
    "candidate",
    [
        "https://evil.example/",
        "//evil.example/",
        "\\\\evil.example\\",
        "/%2f%2fevil.example/",
        "/%5cevil.example/",
        "relative/path",
        "/safe\r\nLocation: https://evil.example/",
    ],
)
def test_redirect_policy_rejects_external_or_ambiguous_targets(candidate):
    assert safe_local_redirect(candidate) is None


def test_redirect_policy_allows_local_path_query_and_fragment():
    assert safe_local_redirect("/dashboard?view=1#status") == "/dashboard?view=1#status"


@pytest.mark.parametrize(
    ("candidate", "endpoint"),
    [("/", "homepage"), ("/dashboard", "index"), ("/settings", "settings")],
)
def test_safe_login_endpoint_maps_only_server_owned_destinations(candidate, endpoint):
    assert safe_login_endpoint(candidate) == endpoint


@pytest.mark.parametrize("candidate", ["/unknown", "/settings?admin=1", "https://evil.test"])
def test_safe_login_endpoint_rejects_unlisted_destinations(candidate):
    assert safe_login_endpoint(candidate) is None


def public_resolver(host, port, *, type):
    assert type == socket.SOCK_STREAM
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", port))]


def test_smtp_destination_resolves_allowlisted_host_once(monkeypatch):
    calls = []

    def resolver(host, port, *, type):
        calls.append((host, port, type))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    destination = resolve_smtp_destination(
        "smtp.example.com",
        465,
        allowed_hosts=parse_allowed_hosts("smtp.example.com"),
        allowed_ports=parse_allowed_ports("465"),
        resolver=resolver,
    )
    assert destination == ("8.8.8.8", 465)
    assert len(calls) == 1


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.2", "169.254.169.254", "::1"])
def test_smtp_destination_rejects_non_public_dns_results(address):
    def resolver(host, port, *, type):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (address, port))]

    with pytest.raises(SMTPDestinationError, match="private or reserved"):
        resolve_smtp_destination(
            "smtp.example.com",
            25,
            allowed_hosts=parse_allowed_hosts("smtp.example.com"),
            allowed_ports=parse_allowed_ports("25"),
            resolver=resolver,
        )


def test_smtp_destination_rejects_mixed_public_and_private_answers():
    def resolver(host, port, *, type):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
        ]

    with pytest.raises(SMTPDestinationError, match="private or reserved"):
        resolve_smtp_destination(
            "smtp.example.com",
            587,
            allowed_hosts=parse_allowed_hosts("smtp.example.com"),
            allowed_ports=parse_allowed_ports("587"),
            resolver=resolver,
        )


def test_smtp_destination_rejects_ip_literals_and_non_allowlisted_values():
    allowed_hosts = parse_allowed_hosts("smtp.example.com")
    allowed_ports = parse_allowed_ports("25")
    with pytest.raises(SMTPDestinationError, match="IP literals"):
        resolve_smtp_destination(
            "127.0.0.1",
            25,
            allowed_hosts=allowed_hosts,
            allowed_ports=allowed_ports,
        )
    with pytest.raises(SMTPDestinationError, match="not allowlisted"):
        resolve_smtp_destination(
            "evil.example",
            25,
            allowed_hosts=allowed_hosts,
            allowed_ports=allowed_ports,
        )
    with pytest.raises(SMTPDestinationError, match="port is not allowlisted"):
        resolve_smtp_destination(
            "smtp.example.com",
            2525,
            allowed_hosts=allowed_hosts,
            allowed_ports=allowed_ports,
        )


@pytest.mark.parametrize('answers', [[], OSError('resolver unavailable')])
def test_smtp_destination_fails_closed_when_resolution_fails(answers):
    def resolver(host, port, *, type):
        if isinstance(answers, Exception):
            raise answers
        return answers

    with pytest.raises(SMTPDestinationError, match='could not be resolved'):
        resolve_smtp_destination(
            'smtp.example.com',
            25,
            allowed_hosts=parse_allowed_hosts('smtp.example.com'),
            allowed_ports=parse_allowed_ports('25'),
            resolver=resolver,
        )


def test_trusted_proxy_middleware_ignores_headers_from_direct_clients():
    captured = []

    def app(environ, start_response):
        captured.append((environ["REMOTE_ADDR"], environ.get("wsgi.url_scheme")))
        start_response("200 OK", [])
        return [b"ok"]

    middleware = TrustedProxyMiddleware(app, parse_cidrs("10.0.0.0/8"))
    environ = {
        "REMOTE_ADDR": "203.0.113.4",
        "HTTP_X_FORWARDED_FOR": "198.51.100.8",
        "HTTP_X_FORWARDED_PROTO": "https",
        "wsgi.url_scheme": "http",
    }
    middleware(environ, lambda status, headers: None)
    assert captured == [("203.0.113.4", "http")]


def test_trusted_proxy_middleware_accepts_headers_from_allowlisted_peer():
    captured = []

    def app(environ, start_response):
        captured.append((environ["REMOTE_ADDR"], environ.get("wsgi.url_scheme")))
        start_response("200 OK", [])
        return [b"ok"]

    middleware = TrustedProxyMiddleware(app, parse_cidrs("10.0.0.0/8"))
    environ = {
        "REMOTE_ADDR": "10.0.0.2",
        "HTTP_X_FORWARDED_FOR": "198.51.100.8",
        "HTTP_X_FORWARDED_PROTO": "https",
        "wsgi.url_scheme": "http",
    }
    middleware(environ, lambda status, headers: None)
    assert captured == [("198.51.100.8", "https")]
