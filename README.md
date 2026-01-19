# MailDT - Mail Delivery Monitor

[![Build and Publish Docker Image](https://github.com/arumes31/mail-delivery-tester/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/arumes31/mail-delivery-tester/actions/workflows/docker-publish.yml)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io-blue.svg)](https://github.com/arumes31/mail-delivery-tester/pkgs/container/mail-delivery-tester)
![Python Version](https://img.shields.io/badge/python-3.14-blue.svg)
![License](https://img.shields.io/github/license/arumes31/mail-delivery-tester)
![Repo Size](https://img.shields.io/github/repo-size/arumes31/mail-delivery-tester)
[![Security Scan](https://github.com/arumes31/mail-delivery-tester/actions/workflows/security-scan.yml/badge.svg)](https://github.com/arumes31/mail-delivery-tester/actions/workflows/security-scan.yml)

<p align="center">
  <img src="static/img/logo.svg" width="120" alt="MailDT Logo">
</p>

MailDT is a robust, self-hosted mail delivery monitoring tool designed to verify the reliability, latency, and authentication health of your email infrastructure. It performs "loopback" testing by sending unique probes via SMTP and watching for their arrival via IMAP.

## 🚀 Features

- **Round-Trip Monitoring**: Automated probes to track **RTT (Round Trip Time)** and delivery reliability.
- **Enhanced Live Monitor**: Real-time dashboard showing status, RTT, and **SPF/DKIM/DMARC** results.
- **📊 Sidebar Analytics**: Persistent, real-time widget showing mail and tool usage stats for the last hour, 24h, and all-time.
- **📌 Custom Dashboard Widgets**: Fully customizable home page "pins" with icons or custom images, supporting reordering, private visibility, and various sizes.
- **🎨 Cyber-Purple Aesthetic**: Permanent dark mode with a modern purple/indigo palette, neon accents, and a dynamic SVG mesh background.
- **🛡️ Privacy & Public Access**: 
    - **Email Masking**: Recipient addresses are automatically masked for unauthenticated users.
    - **Public Tools**: Mail Tester, SMTP Diagnostics, and Blacklist Check are accessible without login.
- **🧪 Mail Tester**: Diagnostic tool (similar to mail-tester.com) to manually verify SPF, DKIM, DMARC, and detailed spam headers (O365, Mimecast, Proofpoint, etc.).
- **🩺 SMTP Diagnostics**: Public protocol analyzer with session transcripts, banner checks, TLS verification, and open relay testing.
- **🛡️ Blacklist Check**: Deep DNSBL analysis for domains and their MX nodes against 15+ major providers.
- **🔍 Decode Spam Headers**: Integrated official engine for analyzing 67+ raw email header types.
- **🔍 WHOIS Lookup**: Embedded integration for external domain and IP information.
- **🌐 Web-Check**: Integrated OSINT tool for comprehensive website analysis.
- **Multi-Recipient Support**: Monitor multiple target mailboxes simultaneously with individual schedules.
- **Smart Alerting**: 
    - Notifications via **Discord Webhooks**, **Email**, and **ConnectWise Manage Tickets**.
    - Alert on **Missing** emails, **Send Failures**, and **Service Recovery**.
- **Resilient Infrastructure**:
    - **PostgreSQL 17**: High-performance persistence with host-mapped volume.
    - **Persistent Metrics**: Global counters and event logging ensure statistics survive data cleanups and recipient deletions.
    - **Smart DNS**: Multi-provider DNS resolution with Google DNS fallback for reliable PTR lookups.
    - **Performance**: Intelligent 120s caching for public users with real-time bypass for admins.
- **Security**: **2FA (TOTP)** support for admin access and IP-based rate limiting across all diagnostic tools.

## Screenshots

<img width="2543" height="689" alt="grafik" src="https://github.com/user-attachments/assets/1a2c5631-4385-490a-8baf-512dd6262f99" />
<img width="2519" height="1013" alt="grafik" src="https://github.com/user-attachments/assets/9c6a109e-d20b-471b-9e57-8364f17d5c3b" />
<img width="2519" height="1220" alt="grafik" src="https://github.com/user-attachments/assets/cd2d1402-62cc-4f85-b9c7-25b2609d1ecf" />
<img width="2521" height="1250" alt="grafik" src="https://github.com/user-attachments/assets/b81a3dfe-6cad-428b-82d9-97a65eac6dfa" />
<img width="2553" height="1259" alt="grafik" src="https://github.com/user-attachments/assets/b7e6605b-d462-4594-b79b-47fb296cfe34" />
<img width="2523" height="609" alt="grafik" src="https://github.com/user-attachments/assets/e9cc48d7-c34a-4dbd-8eaf-f70688693a7e" />#
<img width="2529" height="873" alt="grafik" src="https://github.com/user-attachments/assets/bbc51734-e3b7-4212-8de0-6931961e0828" />

## 🛠️ Setup & Installation

### 1. Prerequisites
- Docker and Docker Compose installed.
- A dedicated mail account for monitoring (SMTP and IMAP access).

### 2. Configuration
Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

**Key Environment Variables:**
- `SMTP_HOST` / `IMAP_HOST`: Your mail server addresses.
- `DB_USER` / `DB_PASS` / `DB_NAME`: PostgreSQL credentials.
- `ADMIN_USER` / `ADMIN_PASSWORD`: Credentials for the web UI.
- `ENABLE_PROXY`: Set to `true` if running behind a reverse proxy.
- `CW_URL`, `CW_CLIENT_ID`, `CW_PUBLIC_KEY`, `CW_PRIVATE_KEY`: ConnectWise Manage API credentials for ticket alerting.

### 3. Start the Application

#### Option A: Local Build (Recommended for development)
```bash
docker-compose up -d --build
```

#### Option B: Use Pre-built Images (Recommended for production)
If you don't want to clone the full repository, you can just download the necessary files and run:

```bash
# Download the compose file and example environment
curl -L -O https://raw.githubusercontent.com/arumes31/mail-delivery-tester/main/docker-compose.ghcr.yml
curl -L -O https://raw.githubusercontent.com/arumes31/mail-delivery-tester/main/.env.example

# Setup your environment
cp .env.example .env
# ... edit .env with your credentials ...

# Start the application
docker-compose -f docker-compose.ghcr.yml up -d
```

Access the dashboard at `http://localhost:5000`. Persistent data will be stored in the `./data` folder on your host.

## 🖥️ Navigation

- **Live Monitor**: Publicly viewable health and authentication status (masked emails).
- **Mail Tester**: Public manual verification of mail headers and spam scores.
- **SMTP Diagnostics**: Public deep protocol analysis and session transcripts.
- **Blacklist Check**: Public reputation scanning for domains and IPs.
- **Decode Spam Headers**: Deep analysis of raw email headers.
- **WHOIS Lookup**: Public embedded WHOIS information service.
- **Web-Check**: Public embedded website analysis tool.
- **System Diagnostics**: (Admin) Internal health check of your configured SMTP/IMAP credentials.
- **Recipients**: (Admin) Manage target addresses and alert thresholds.

## 📦 Tech Stack
- **Backend**: Python (Flask)
- **Database**: PostgreSQL 17 / SQLAlchemy
- **Diagnostics**: `dnspython`, `socket`
- **Frontend**: Bootstrap 5 (Dark), FontAwesome 6, Custom Cyber-Purple CSS
- **Messaging**: `smtplib`, `imaplib`
