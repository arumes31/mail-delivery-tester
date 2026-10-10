# syntax=docker/dockerfile:1.19.0@sha256:b6afd42430b15f2d2a4c5a02b919e98a525b785b1aaff16747d2f623364e39b6
FROM python:3.14.8-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv

RUN python -m venv "$VIRTUAL_ENV"
COPY requirements.txt ./requirements.txt
RUN "$VIRTUAL_ENV/bin/pip" install --require-hashes -r requirements.txt

FROM python:3.14.8-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 maildt \
    && useradd --uid 65532 --gid maildt --no-create-home --shell /usr/sbin/nologin maildt

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=65532:65532 . .
RUN rm -rf /opt/venv/bin/pip* \
        /opt/venv/lib/python3.14/site-packages/pip* \
        /usr/local/lib/python3.14/ensurepip \
        /usr/local/lib/python3.14/site-packages/pip* \
    && mkdir -p /app/data /app/data-web/custom_icons \
    && chown -R 65532:65532 /app/data /app/data-web

USER 65532:65532
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3).read()"]

CMD ["gunicorn", "--workers", "2", "--threads", "2", "--bind", "0.0.0.0:5000", "--timeout", "30", "--graceful-timeout", "30", "--keep-alive", "5", "--limit-request-line", "4094", "--limit-request-fields", "100", "--limit-request-field_size", "8190", "--max-requests", "1000", "--max-requests-jitter", "100", "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "app:app"]
