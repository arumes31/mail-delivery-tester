FROM python:3.14-slim

WORKDIR /app

# Install system dependencies (needed for psycopg2) and upgrade base packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gcc \
    libpq-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip to fix CVE-2025-8869
RUN pip install --no-cache-dir --upgrade "pip>=25.3"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]

