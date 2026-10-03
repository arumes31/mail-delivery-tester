# Dependency assessment — 2026-10-03

## Scope and baseline

Repository: `arumes31/mail-delivery-tester`. The remote default branch was verified
with `git ls-remote --symref origin HEAD`: `main`, commit
`9666bee54f384cca98bc8e4eddb1040b90f04350`. Work is isolated on local branch
`codex/dependency-audit-2026-10-03`. The original `v2_test` checkout at
`b05bc1ba700764e3a3c509565612e3a774e74143` and its existing `.gitignore` edit were
preserved. No publishing, deployment, messages, or application mail delivery was
performed. No matching Claude project memory or repository AGENTS.md was present;
the supplied project instructions were followed.

This is a source and local-build assessment, not an inventory of deployment.
The saved audit's unlocked candidate versions were not treated as installed
versions. A clean pip resolution against PyPI on Windows CPython 3.14.7 selected
idna 3.20 and Werkzeug 3.1.9 before any change.

## Supplied findings

All four records are PyPI runtime dependencies in `requirements.txt`. OSV and
GitHub records were checked for aliases, withdrawals and version boundaries.
None was withdrawn. Count each GHSA/CVE/PYSEC alias group once.

| Advisory and evidence | Relationship / chain | Before → after | Classification and exposure |
| --- | --- | --- | --- |
| [GHSA-65pc-fj4g-8rjx](https://github.com/advisories/GHSA-65pc-fj4g-8rjx), CVE-2026-45409, PYSEC-2026-215 | Transitive: requests → idna; tldextract → idna, also tldextract → requests-file → requests → idna | No direct floor, resolved 3.20 → `idna>=3.15`, resolved 3.20 | Already resolved in fresh resolution; deployed version unresolved. The alleged 3.9 candidate was not observed. Added a narrow floor because the parents still permit affected versions. IDNA processing is used by Requests/domain handling; no vulnerable installed version or exploit was established. Affected `<3.15`. |
| [GHSA-mf9w-mj56-hr94](https://github.com/advisories/GHSA-mf9w-mj56-hr94), CVE-2026-28684, PYSEC-2026-2270 | Direct python-dotenv | `1.2.1` → `1.2.4` | Verified affected pin, remediated. No application call to `set_key`/`unset_key`; Flask/Gunicorn may read dotenv files. The advisory requires local filesystem access and the affected write operations. Affected `<1.2.2`; no reachable vulnerable write path found. |
| [GHSA-29vq-49wr-vm6x](https://github.com/advisories/GHSA-29vq-49wr-vm6x), CVE-2026-27199, PYSEC-2026-2320 | Direct Werkzeug requirement/import, also Flask → Werkzeug | `>=3.1.5`, resolved 3.1.9 → `>=3.1.6`, resolved 3.1.9 | Already resolved in fresh resolution; deployed version unresolved. Raised the unsafe floor. Flask static serving reaches `send_from_directory`/`safe_join`; app.py also serves custom icons. This advisory affects Windows device paths, not the documented Linux container. Affected `<3.1.6`. |
| [GHSA-gc5v-m9x4-r6x2](https://github.com/advisories/GHSA-gc5v-m9x4-r6x2), CVE-2026-25645, PYSEC-2026-2275 | Direct requests; also tldextract → requests / requests-file → requests | `2.32.5` → `2.34.2` | Verified affected pin, remediated. Application HTTP GET/POST use is present, but no direct `extract_zipped_paths` call was found. Vendor says ordinary Requests usage is unaffected. Affected `<2.33.0`. Current GHSA CVSS is 4.4; the PYSEC/source audit score differs. |

OSV records: [idna](https://osv.dev/vulnerability/GHSA-65pc-fj4g-8rjx),
[dotenv](https://osv.dev/vulnerability/GHSA-mf9w-mj56-hr94),
[Werkzeug](https://osv.dev/vulnerability/GHSA-29vq-49wr-vm6x),
[Requests](https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2).

Release compatibility was checked against the
[Requests changelog](https://requests.readthedocs.io/en/latest/community/updates/),
[python-dotenv releases](https://github.com/theskumar/python-dotenv/releases),
[Werkzeug changelog](https://werkzeug.palletsprojects.com/en/stable/changes/),
and PyPI metadata. Requests 2.34.2 and python-dotenv 1.2.4 are current stable
releases on the same major lines and require Python >=3.10, consistent with the
CI interpreter and Python 3.14 runtime. No API/configuration changes were needed.
OSV queries also returned no advisories for the minimum idna 3.15 and Werkzeug
3.1.6 versions, or either new direct pin.

## Inventory and installation boundaries

- One pip manifest (`requirements.txt`), no lockfile, constraints, nested Python
  projects, Go modules/replacements, Node manifests, vendored package manifests,
  SBOM, or trusted deployed environment inventory. No dependency test fixtures
  or examples introduce separate graphs. No govulncheck target exists.
- `app.py`: Flask/SQLAlchemy web app, psycopg2 database driver, Requests webhooks
  and health checks, pyotp authentication, dnspython diagnostics. `scheduler.py`
  shares app models/functions and runs APScheduler under a separate Gunicorn
  process. `decode_wrapper.py` loads `decode_spam_headers_official.py`, which
  imports tldextract/dateutil/packaging/colorama and performs HTTP/domain lookups.
  `spam_decoder.py` uses the standard library. These are production paths.
- Runtime installation: Dockerfile → `pip install -r requirements.txt`;
  `python:3.14-slim` plus apt gcc, libpq-dev and openssl; pip is upgraded with
  `pip>=25.3` as a build tool. Compose runs separate web/scheduler commands and
  `postgres:17.4-alpine`; the GHCR compose variant uses
  `ghcr.io/arumes31/mail-delivery-tester:latest`. Publication targets linux/amd64.
  No other infrastructure definitions were found.
- Frontend assets are vendored Bootstrap 5.3.0 (JS bundle including Popper and
  CSS), SortableJS 1.15.0, and Font Awesome Free 6.4.0 (CSS/fonts). Templates load
  these locally; no external JS/CSS CDN dependency was found. Configurable WHOIS
  and Web-Check iframe services are external runtime integrations, not locked
  package dependencies.
- CI-only tools: unpinned flake8 and bandit on Python 3.10; Trivy image scanning;
  CodeQL JavaScript analysis (init/autobuild/analyze v3), with SARIF upload v4 in
  the image workflows. Actions include checkout v4/v6, setup-python v5,
  docker/setup-buildx-action v3, login-action v3, metadata-action v5,
  build-push-action v6, aquasecurity/trivy-action `master`, and
  delete-package-versions v5. These mutable references were inventoried, not
  represented as audited action bundles. No workflow/action changes were made.
- Dependabot covers pip daily and Docker/Actions weekly on main. Existing
  CodeQL analysis and lint/security checks are preserved. Trivy scans only
  HIGH/CRITICAL and excludes unfixed findings; it does not explicitly configure
  a failing vulnerability exit code. Thus it does not gate the four Medium
  findings. `.trivyignore` contains `linux-libc-dev` with a host-kernel rationale;
  that is a package name, not a CVE ID. The rationale does not establish safety
  of header/build artifacts. Local image assessment must not rely on this entry.
  Existing Bandit `nosec` annotations remain unchanged.

## Reproducibility decision

Keep the existing pip requirements workflow and add only security floors for
the two transitive/ranged findings. Requests and tldextract do not require safe
idna minima themselves, so a parent bump alone cannot enforce this boundary.
A new universal production lock would change the established update workflow
and require a separately maintained platform/interpreter policy. Exact
resolution evidence is retained for this assessment instead. This is not a
claim that future installs are frozen: other unconstrained transitives and
mutable images/actions may change and must be rescanned when rebuilt.

## Validation and remaining coverage

There is no repository test suite or type-checker setup. Validation commands
were run from the isolated checkout unless noted. `AUDIT` below denotes the
local scratch directory `C:\Users\Daniel\AppData\Local\Temp\maildt-audit-20261003`;
tooling was installed separately in `AUDIT/tools`, not in runtime requirements.

| Command / check | Actual result |
| --- | --- |
| `python -m pip --isolated --disable-pip-version-check install --dry-run --ignore-installed --only-binary=:all: --no-cache-dir --index-url https://pypi.org/simple --report AUDIT/before.json -r requirements.txt` before editing | Passed; 30 runtime packages resolved on Windows/Python 3.14.7. Two affected pins; idna/Werkzeug already safe. |
| OSV `/v1/querybatch` for all baseline packages and npm bootstrap 5.3.0, sortablejs 1.15.0, @fortawesome/fontawesome-free 6.4.0 | Two unique advisory groups, both in the supplied audit (four IDs before deduplicating PYSEC aliases). No other matches. This is a version lookup, not integrity verification of vendored bytes or a full bundled Popper audit. |
| Clean `pip install --only-binary=:all: --target AUDIT/runtime --report AUDIT/after-windows.json -r requirements.txt` against PyPI | Passed; 30 packages installed. Only requests and python-dotenv changed selected versions. |
| Same dry-run resolution with `--python-version 3.10` | Passed. All selected packages' Requires-Python metadata also permits 3.10. Cross-version resolution is not a Python 3.10 execution test. |
| OSV batch of all 30 updated Windows packages, plus separate queries at the two security floors | Zero advisory matches. |
| `docker build --pull --platform linux/amd64 --tag maildt-dependency-audit:local .` | Passed using the unchanged Dockerfile. 29 runtime Python packages plus pip installed. |
| `docker run --rm --network none --read-only --entrypoint python maildt-dependency-audit:local -m pip check` | Passed: no broken requirements. |
| `docker run --rm --network none --read-only --tmpfs /tmp --volume AUDIT:/audit:ro --entrypoint python maildt-dependency-audit:local /audit/smoke.py /app` | Passed. SQLite initialization, health/pages, login and protected routes, static assets, invalid file paths, JSON and IDN URL preparation, mocked webhook, dotenv read/set/unset, offline tldextract, decoder imports and scheduler health with start/shutdown mocked. Initial temporary test fixtures had incorrect decoder input/return assumptions; these were corrected without application changes. |
| `python -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics` (flake8 7.4.1) | Passed, zero blocking findings. |
| `python -m flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics` | Exited zero as configured in CI, but reported 1,782 existing style/complexity/advisory findings. Application Python files are unchanged; this is not a clean style result. |
| `python -m bandit -r . -ll -ii -f json -o AUDIT/bandit.json` (Bandit 1.9.4) | Passed, zero findings/errors at the existing CI thresholds. Eleven existing nosec lines remain; this is not an unrestricted security proof. |
| `python -X utf8 AUDIT/smoke.py CHECKOUT AUDIT/runtime` on Windows/Python 3.14.7 | Passed, exit 0, with the same offline assertions. Temporary-directory selection/cleanup was corrected for Windows before the final run. No Gunicorn server was run on Windows. |
| OSV batch of the exact installed Linux inventory including pip (30 packages) | Zero advisory matches. |
| `python -m pip_audit --no-deps --disable-pip -r AUDIT/linux-resolved.txt --cache-dir AUDIT/audit-cache --vulnerability-service osv --timeout 15 --format json --output AUDIT/pip-audit-linux-osv.json` (pip-audit 2.10.1) | Passed, no known vulnerabilities. The first attempt using the default PyPI service failed with a connection reset; it was not counted as passing. `--no-deps --disable-pip` uses the full already-installed inventory, not an incomplete hand-picked manifest. |
| Trivy 0.75 image scan with `--scanners vuln --ignorefile /dev/null --list-all-pkgs --format json --output /audit/trivy-image.json` | **Coverage gap:** both database downloads timed out: default `mirror.gcr.io/aquasec/trivy-db:2` at 5 minutes, then official `ghcr.io/aquasecurity/trivy-db:2` at 3 minutes. No scan report was produced; no OS-layer clean bill is claimed. All severities and unfixed issues were eligible, with no repository ignore file applied. Scanner image was pinned to `aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa`. |
| `git diff --check` | Passed. |

The local image's manifest is
`sha256:d315c8ca6ae7db01f1704a1bafbe74be7a083ca975dd8706f41e863c5179fb7b`,
its image index is
`sha256:7da399611737e0baf2ae5c020896b1be5538c2db4518efd9dffa177dbc364a6d`,
and the resolved Python base index is
`sha256:0741d101873c12ab927e6f8653feb8862b9bd58771177acb1b885b95141f91b4`.
Only the final audit documentation was added after building; runtime source and
requirements match the tested image. No image was pushed.

Exact Linux inventory from `python -m pip freeze --all` in that image:

```text
APScheduler==3.11.2
blinker==1.9.0
certifi==2026.7.22
charset-normalizer==3.5.2
click==8.5.0
colorama==0.4.6
dnspython==2.8.0
filelock==4.0.9
Flask==3.1.3
greenlet==3.5.6
gunicorn==25.1.0
idna==3.20
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.4
packaging==26.0
pip==26.2.1
psycopg2-binary==2.9.11
pyotp==2.9.0
python-dateutil==2.9.0.post0
python-dotenv==1.2.4
requests==2.34.2
requests-file==3.0.1
six==1.17.0
SQLAlchemy==2.0.47
tldextract==5.3.1
typing_extensions==4.16.0
tzlocal==5.4.4
urllib3==2.8.0
Werkzeug==3.1.9
```

Windows selected the same runtime versions plus `tzdata==2026.4`. Scratch
evidence includes pip reports (artifact URLs and hashes), OSV responses,
`linux-resolved.txt`, `smoke.py`, and lint/security output. It contains no
deployed credentials or private application logs.

Smoke validation cannot prove PostgreSQL behavior, real SMTP/IMAP delivery,
third-party integration behavior, production Gunicorn traffic handling, or
deployment exploitability. Python 3.10 was resolved, not executed. CI tools and
action source bundles were not comprehensively vulnerability-scanned. The
separate PostgreSQL image and published GHCR image were not scanned, and the
running deployment's package/image inventory is unknown. No mutable tag is
treated as evidence of a CVE.

## Additional findings, separate from the saved audit

No additional affected package version was confirmed by the fresh OSV queries
or pip-audit of the installed Python inventory. The three frontend package
version queries also returned no matches. The Trivy failures leave operating
system layer vulnerabilities unresolved; they do not demonstrate absence of
findings. Mutable CI action references, the limited Trivy CI configuration,
and the existing non-blocking lint findings above are observations, not newly
verified dependency advisories.

## Maintainer follow-through

Review and apply the local diff, rebuild the web and scheduler images from
these requirements, rerun the image scan and integration checks, and deploy
through the normal separately authorized process. Merely changing this file
does not patch existing environments. Inspect deployed idna/Werkzeug versions
and replace old environments/images where necessary. No new vulnerability
ignore or weakened CI gate is part of this change.
