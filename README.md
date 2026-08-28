# MailDT — Mail Delivery Monitor

[![Python CI](https://github.com/arumes31/mail-delivery-tester/actions/workflows/ci.yml/badge.svg)](https://github.com/arumes31/mail-delivery-tester/actions/workflows/ci.yml)
[![Container](https://github.com/arumes31/mail-delivery-tester/actions/workflows/container.yml/badge.svg)](https://github.com/arumes31/mail-delivery-tester/actions/workflows/container.yml)
[![CodeQL](https://github.com/arumes31/mail-delivery-tester/actions/workflows/codeql.yml/badge.svg)](https://github.com/arumes31/mail-delivery-tester/actions/workflows/codeql.yml)

MailDT is a self-hosted SMTP/IMAP delivery monitor. It sends unique probes, watches for their return, measures delivery latency, checks SPF/DKIM/DMARC signals, and exposes authenticated operational diagnostics.

## Security model

MailDT intentionally fails closed:

- the database password, Flask signing key, administrator name, and administrator password have no defaults
- deployment secrets can be mounted from files and the supplied Compose stacks do so
- changing the signing key, administrator password, user, or TOTP secret invalidates every existing session
- authentication stores a versioned user identity, not a forgeable `logged_in` boolean
- TOTP handoff state expires after five minutes and never stores or returns the submitted password
- session cookies are always `Secure`, `HttpOnly`, and `SameSite=Lax`; deploy behind HTTPS
- forwarded client/scheme/host headers are accepted only from `TRUSTED_PROXY_CIDRS`
- state-changing administrator operations require a session-bound CSRF token
- SMTP diagnostics require authentication, an exact host/port allowlist, and a public DNS result; IP literals, loopback, private, link-local, multicast, unspecified, reserved, and mixed public/private answers are rejected
- the validated SMTP IP is dialed directly, preventing a second DNS lookup from rebinding the connection
- decoder HTTP requests require HTTPS, do not follow redirects, have connect/read deadlines, and reject responses above 512 KiB
- the container runs as UID/GID 65532, has no runtime package manager, and is deployed read-only with all Linux capabilities dropped

The normal configured SMTP/IMAP monitor can reach private mail infrastructure. The interactive SMTP diagnostic is deliberately stricter because it accepts a browser-supplied target.

## Required migration from an older deployment

Do this before deploying the updated Compose file:

1. Back up `data/`, `data-web/`, and the current `.env` without placing the backup in the repository.
2. Rotate the old Flask `SECRET_KEY` and administrator password. Reusing either documented default is rejected. The new signing key invalidates all old browser sessions.
3. If the database still uses the example password, rotate the PostgreSQL role interactively before replacing the secret. Avoid putting the new password in shell history or a process argument.
4. Rotate SMTP/IMAP credentials if example or previously disclosed values were used.
5. Create the secret files below with restrictive host permissions.
6. Replace `.env` from `.env.example`; remove legacy `DB_PASS`, `SECRET_KEY`, `ADMIN_PASSWORD`, `SMTP_PASS`, and `IMAP_PASS` entries so they do not conflict with mounted files.
7. Ensure the existing `data-web/` bind mount is writable by UID/GID 65532 on Linux.
8. Configure HTTPS and the narrow immediate-proxy CIDR before exposing the service.

Example secret provisioning on Linux/macOS:

```bash
install -d -m 700 secrets
openssl rand -base64 48 > secrets/session_key
openssl rand -base64 32 > secrets/admin_password
openssl rand -base64 32 > secrets/db_password
printf '%s\n' 'your-smtp-password' > secrets/smtp_password
printf '%s\n' 'your-imap-password' > secrets/imap_password
: > secrets/admin_totp # leave empty to disable TOTP
chmod 600 secrets/*
sudo chown -R 65532:65532 data-web
```

To enable TOTP, put a valid base32 secret in `secrets/admin_totp` before starting the stack. Generate it locally with a trusted password manager/authenticator enrollment workflow and do not commit it.

For an existing PostgreSQL role, an interactive rotation avoids exposing the password in command arguments:

```bash
docker compose exec db psql -U maildt -d maildt -c '\password maildt'
```

Write that same new value to `secrets/db_password`, then deploy the updated stack. If the database username differs, substitute it in both places.

## Deployment

```bash
cp .env.example .env
# edit non-secret settings and provision ./secrets as described above
docker compose pull
docker compose up -d
docker compose ps
```

Use `docker-compose.ghcr.yml` to run the published image:

```bash
docker compose -f docker-compose.ghcr.yml up -d
```

The web port binds to `127.0.0.1:5000` by default. Keep it loopback-only and terminate TLS in a reverse proxy. If the immediate proxy connects from `172.20.0.5`, for example, use its narrow address or subnet:

```dotenv
TRUSTED_PROXY_CIDRS=172.20.0.5/32
```

Do not set a broad public CIDR. When no proxy is used, leave `TRUSTED_PROXY_CIDRS` empty; forwarded headers will be ignored.

### SMTP diagnostic egress policy

Only configured hosts and ports are eligible:

```dotenv
SMTP_DIAGNOSTIC_ALLOWED_HOSTS=smtp1.example.com,smtp2.example.com
SMTP_DIAGNOSTIC_ALLOWED_PORTS=25,465,587
```

Every DNS answer must be globally routable. Use network-level egress policy as an additional control. If the production SMTP host is private, normal probe delivery still works, but the interactive diagnostic will reject it.

## Configuration

The full non-secret template is [.env.example](.env.example). Important settings include:

| Setting | Purpose |
|---|---|
| `ADMIN_USER` | Required administrator identity |
| `TRUSTED_PROXY_CIDRS` | Exact immediate peers allowed to supply forwarded headers |
| `SMTP_DIAGNOSTIC_ALLOWED_HOSTS` | Exact interactive diagnostic hostname allowlist |
| `SMTP_DIAGNOSTIC_ALLOWED_PORTS` | Interactive diagnostic port allowlist |
| `SEND_INTERVAL` | Probe-send interval in seconds |
| `CHECK_INTERVAL` | IMAP polling interval in seconds |
| `ALERT_THRESHOLD` | Delay threshold in seconds |

The Compose stack mounts `DB_PASS_FILE`, `SECRET_KEY_FILE`, `ADMIN_PASSWORD_FILE`, `ADMIN_TOTP_SECRET_FILE`, `SMTP_PASS_FILE`, and `IMAP_PASS_FILE` inside the containers. Direct environment variables remain supported for non-Compose deployments, but setting both forms for one secret is rejected.

## Development and verification

Python 3.14 is the supported runtime. Dependencies are exact and hash-locked.

```bash
uv venv
uv pip install --python .venv/bin/python --require-hashes -r requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/pytest --cov=security --cov=http_utils --cov-fail-under=85
.venv/bin/bandit -c pyproject.toml -r app.py scheduler.py spam_decoder.py decode_wrapper.py security.py http_utils.py -ll -ii
.venv/bin/pip-audit -r requirements.txt
```

Refresh locks only after reviewing upstream changes:

```bash
uv pip compile requirements.in --python-version 3.14 --generate-hashes --output-file requirements.txt
uv pip compile requirements-dev.in --python-version 3.14 --generate-hashes --output-file requirements-dev.txt
```

`decode_spam_headers_official.py` is a vendored upstream decoder and is excluded from the first-party Ruff baseline. Local security fixes are intentionally narrow: duplicate-key removal and bounded HTTPS fetching. Keep its upstream source/version documented when replacing it, and rerun decoder fixtures plus the full security suite.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md). Do not publish credentials, session cookies, email content, or diagnostic transcripts in a public issue.

## License

MIT — see [LICENSE](LICENSE).
