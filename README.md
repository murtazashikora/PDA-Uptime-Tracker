# PESCOE Systems Uptime Dashboard

A lightweight, heartbeat-based uptime monitor with a real-time web dashboard built for the **Piccadilly Dental Alliance (PDA)** network infrastructure. Remote agents on workstations and servers across ~27 dental practices send periodic heartbeats to a central Flask server, which tracks status, sends digest-based email alerts, and provides a live dashboard with Meraki MX firewall integration.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Flask](https://img.shields.io/badge/Flask-2.x-green)
![SQLite](https://img.shields.io/badge/Storage-SQLite-lightgrey)

---

## Features

- **Heartbeat monitoring** — agents check in every 3 minutes; nodes are marked offline after 240 seconds of silence
- **Real-time dashboard** — polls every 30 seconds with client-side sorting, search, and filtering (no full-page refresh)
- **Digest-based email alerts** — rolled-up outage/recovery digests every 30 minutes + end-of-day summary (no per-outage email spam)
- **Web Push notifications** — mobile/background alerts via VAPID, with automatic fallback to in-tab popups
- **Meraki MX integration** — live appliance status, device-to-cloud speed tests, and uplink loss/latency via the Cisco Meraki Dashboard API
- **OTP login** — username/password + email-based 6-digit verification code
- **PWA support** — installable on mobile with generated icons, service worker, and offline-ready manifest
- **Uptime history** — 24-hour and 7-day uptime percentages computed from SQLite event logs
- **Dark/light theme** — toggleable, with `prefers-reduced-motion` and WCAG keyboard/touch-target support
- **Node retirement** — decommissioned machines can be removed from the dashboard along with their history

## Architecture

```
┌──────────────┐   POST /heartbeat    ┌──────────────────────┐
│  Agent (PC)  │ ──────────────────── │                      │
│  agent.py    │   every 30s          │   Flask Server       │
└──────────────┘                      │   server.py          │
                                      │                      │
┌──────────────┐   POST /heartbeat    │  ┌────────────────┐  │
│  Agent (PC)  │ ──────────────────── │  │ SQLite DB      │  │
│  agent.py    │                      │  │ nodes, events  │  │
└──────────────┘                      │  │ push_subs      │  │
                                      │  └────────────────┘  │
       ...                            │                      │
                                      │  Background workers: │
┌──────────────┐   Meraki API         │  - status checker    │
│ Meraki Cloud │ ◄─────────────────── │  - digest scheduler  │
│              │                      │  - email worker      │
└──────────────┘                      │  - push worker       │
                                      └──────────┬───────────┘
                                                 │
                                      ┌──────────▼───────────┐
                                      │  Web Dashboard       │
                                      │  (browser)           │
                                      │  - live status table │
                                      │  - Meraki MX panel   │
                                      │  - push/desktop      │
                                      │    notifications     │
                                      └──────────────────────┘
```

## Prerequisites

- Python 3.9+
- pip

## Installation

### Server

```bash
pip install flask python-dotenv
```

Optional dependencies for additional features:

```bash
# Web Push notifications (mobile/background)
pip install pywebpush cryptography

# Meraki MX dashboard integration
pip install meraki
```

### Agent

```bash
pip install requests
```

## Configuration

Create a `.env` file in the project root (or set environment variables directly):

```env
# Required
FLASK_SECRET_KEY=your-random-secret-key
DASHBOARD_PASSWORD=your-dashboard-password
SMTP_PASSWORD=your-smtp-app-password

# SMTP settings
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_NAME=PESCOE IT
SENDER_EMAIL=your-sender@gmail.com
ALERT_RECEIVER_EMAIL=alerts@example.com
OTP_RECEIVER_EMAIL=it-team@example.com

# Optional
DASHBOARD_USER=admin                    # default: admin
AGENT_TOKEN=shared-secret-for-agents    # for token-based agent auth
PORT=5000                               # default: 5000
DIGEST_INTERVAL_MIN=30                  # minutes between digest emails
EOD_HOUR=18                             # end-of-day report hour (IST)
EOD_MINUTE=30                           # end-of-day report minute (IST)
TRUST_PROXY=0                           # set to 1 behind a reverse proxy
COOKIE_SECURE=0                         # set to 1 when serving over HTTPS
HEALTHCHECK_PING_URL=                   # dead-man's-switch URL (e.g. healthchecks.io)

# Meraki (optional)
MERAKI_API_KEY=your-meraki-api-key
MERAKI_ORG_ID=your-org-id
```

## Usage

### Start the server

```bash
python server.py
```

The dashboard will be available at `http://localhost:5000`.

### Deploy agents

There are two agent options:

#### Option A: Simple script (`agent.py`)

Edit the server IP in `agent.py` and run it manually or via Task Scheduler:

```python
SERVER_IP = "your-server-ip"
```

```bash
python agent.py
```

#### Option B: Windows Service (`agent_service.py`) — Recommended

Runs as a native Windows service that starts on boot, restarts on failure, and requires no logged-in user. Install from an **elevated (Administrator)** command prompt:

```bash
pip install pywin32 requests
python -m pywin32_postinstall -install
```

Then install and start the service:

```bash
python agent_service.py install
python agent_service.py start
```

The service appears in `services.msc` as **PDA Uptime Monitoring Agent** and starts automatically on boot.

**Configuration** is via environment variables (set system-wide so the service can read them):

| Variable | Default | Description |
|----------|---------|-------------|
| `PDA_SERVER_URL` | `http://20.246.76.65:5000/heartbeat` | Server heartbeat endpoint |
| `PDA_AGENT_TOKEN` | *(empty)* | Shared token for authentication |
| `PDA_SYSTEM_NAME` | Machine hostname | Override the reported system name |
| `PDA_IS_SERVER` | `0` | Set to `1` on servers (vs workstations) |
| `PDA_HEARTBEAT_INTERVAL` | `30` | Seconds between heartbeats |
| `PDA_LOG_DIR` | `C:\ProgramData\PDAUptimeAgent` | Log file location |

**Service management:**

```bash
python agent_service.py stop      # stop the service
python agent_service.py remove    # uninstall the service
python agent_service.py debug     # run interactively for troubleshooting
```

Logs are written to `C:\ProgramData\PDAUptimeAgent\agent.log` (rotated at 2 MB, 3 backups).

Both agents authenticate via source IP (must match a known practice IP) or via `X-Agent-Token` header.

## Agent Authentication

Heartbeats are accepted if **either** condition is met:

| Method | How it works | Use case |
|--------|-------------|----------|
| **Source IP** | Request comes from a known practice public IP (hardcoded in `PRACTICE_NAMES`) | Legacy agents already deployed |
| **Token** | `X-Agent-Token` header matches the `AGENT_TOKEN` env var | New agents from arbitrary IPs |

Set `HEARTBEAT_ALLOW_ANONYMOUS=1` to accept all heartbeats without authentication (not recommended).

## Alerting Model

Instead of sending an email for every individual outage, the system uses a **digest model**:

1. **Periodic digest** (default every 30 min) — lists new outages, resolutions, and ongoing issues since the last digest. Skipped entirely if nothing changed.
2. **End-of-day rollup** (default 18:30 IST) — summarizes all outages detected that day, resolutions, and anything still unresolved.
3. **Web Push** (optional) — individual node transitions are pushed immediately to subscribed browsers/phones.

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/heartbeat` | POST | Agent token/IP | Receive agent heartbeat |
| `/api/status` | GET | Login | Dashboard data (machines + summary) |
| `/api/nodes/<name>` | DELETE | Login + CSRF | Retire a node |
| `/api/digest/test` | POST | Login + CSRF | Manually trigger a digest or EOD report |
| `/api/push/vapid-public-key` | GET | Login | Get VAPID public key for push subscription |
| `/api/push/subscribe` | POST | Login + CSRF | Register a push subscription |
| `/api/push/unsubscribe` | POST | Login + CSRF | Remove a push subscription |
| `/api/push/test` | POST | Login + CSRF | Send a test push notification |
| `/meraki/api/*` | Various | Login | Meraki MX dashboard API (connect, devices, speed tests, uplinks) |

## Project Structure

```
PDA Uptime Tracker/
├── server.py          # Flask server, dashboard, Meraki integration (single file)
├── agent.py           # Simple heartbeat agent (manual / Task Scheduler)
├── agent_service.py   # Windows Service heartbeat agent (recommended)
├── .env               # Environment variables (not committed)
├── .gitignore
└── README.md
```

Runtime files (auto-generated, not committed):
- `network_systems_state.db` — SQLite database (nodes, events, push subscriptions)
- `vapid_keys.json` — persisted VAPID key pair for Web Push
- `vapid_private.pem` — VAPID private key (written from JSON or env var)

## Security Notes

- All secrets are read from environment variables — nothing sensitive in source
- OTP codes are stored as HMAC-SHA256 hashes in the session, never plaintext
- CSRF protection on all state-changing endpoints
- Session cookies are HttpOnly with SameSite=Lax
- `X-Forwarded-For` is only trusted when `TRUST_PROXY=1` is explicitly set
- The Meraki API key stays server-side; the browser never sees a saved key
