"""
PESCOE Systems Uptime Dashboard
================================

A lightweight heartbeat-based uptime monitor with a web dashboard.

Improvements over the original single-file version:
  * Heartbeat endpoint requires a shared agent token (no more anonymous check-ins).
  * All secrets are read from environment variables (nothing sensitive in source).
  * X-Forwarded-For is only trusted when running behind a configured proxy.
  * Secure session cookies + manual CSRF protection on login/OTP/actions.
  * OTP is stored as a keyed hash (not plaintext) and resend is rate-limited.
  * A single threading.Lock guards all shared-state mutations.
  * Alert emails are sent asynchronously by a worker thread with retries,
    so a slow SMTP server never blocks an agent's heartbeat.
  * State + full status history are persisted in SQLite, giving durable storage
    and 24h / 7d uptime percentages for free.
  * The dashboard polls a JSON endpoint instead of doing a full-page refresh,
    so outage timers tick live and search/sort/scroll state is preserved.
  * Client-side column sorting and multi-field search (name / practice / IP / group).
  * Opt-in Chrome desktop notifications on outage/recovery transitions (requires
    HTTPS or localhost; only fires while the dashboard tab is open).
  * Decommissioned nodes can be retired from the dashboard.
  * Optional external "dead-man's-switch" ping so something watches the monitor.

Alerting model (digest-based):
  * Individual outages no longer generate an email each. Transitions are buffered.
  * Every DIGEST_INTERVAL_MIN minutes (default 30) a digest is sent listing new
    outages, resolutions in that window, and everything still offline. If nothing
    changed in the window, no email is sent at all.
  * At EOD_HOUR:EOD_MINUTE (IST) a once-a-day rollup is sent covering all outages
    detected that day, their resolutions, and anything still unresolved.

Required environment variables (see load_config below for the full list):
  FLASK_SECRET_KEY, DASHBOARD_PASSWORD, SMTP_PASSWORD
  (plus the SMTP_* / *_EMAIL settings).

Heartbeat authentication is token-OR-IP: already-deployed agents are accepted
by source IP (the known practice public IPs), so AGENT_TOKEN is optional and
only needed for newer agents that report from arbitrary IPs.
"""

import os
import sys
import json
import time
import hmac
import zlib
import queue
import struct
import base64
import sqlite3
import string
import smtplib
import secrets
import hashlib
import functools
import threading
import urllib.request
from pathlib import Path
from hashlib import sha256
from email.mime.text import MIMEText
from datetime import datetime, timezone, timedelta

from flask import (
    Flask, request, render_template_string, redirect,
    url_for, session, jsonify, abort, Response, Blueprint,
)

# Web Push (mobile/background notifications). Optional: if the libraries aren't
# installed the dashboard still runs, it just falls back to in-tab-only popups.
try:
    from pywebpush import webpush, WebPushException
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    PUSH_LIBS_AVAILABLE = True
except ImportError:
    PUSH_LIBS_AVAILABLE = False
    print("[INFO] pywebpush/cryptography not installed; mobile Web Push disabled. "
          "Run 'pip install pywebpush cryptography' to enable it.")

# Load secrets from a local .env file (if present) before reading os.environ.
# Falls back silently if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv, set_key
    load_dotenv()
except ImportError:
    print("[INFO] python-dotenv not installed; skipping .env file. "
          "Run 'pip install python-dotenv' to use one.")
    def set_key(*_a, **_k):
        raise RuntimeError("python-dotenv is not installed; run: pip install python-dotenv")

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

IST = timezone(timedelta(hours=5, minutes=30))          # India Standard Time
PORT = int(os.environ.get("PORT", "5000"))
OFFLINE_THRESHOLD = 240                                  # seconds before a node is "Offline"
DYNAMIC_HEARTBEAT_INTERVAL = 180                         # advertised back to agents
DB_FILE = os.environ.get("STATE_DB_FILE", "network_systems_state.db")

# OTP
OTP_LENGTH = 6
OTP_EXPIRY_SECONDS = 300
MAX_OTP_ATTEMPTS = 5
OTP_RESEND_COOLDOWN = 60                                 # seconds between resends


def _require_env(name):
    val = os.environ.get(name)
    if not val:
        print(f"[WARN] Environment variable {name} is not set. "
              f"Related functionality will be limited until it is configured.")
    return val


def load_config():
    """Read secrets/settings from the environment. Never hard-code these."""
    cfg = {
        "SECRET_KEY": os.environ.get("FLASK_SECRET_KEY"),
        "DASHBOARD_USER": os.environ.get("DASHBOARD_USER", "admin"),
        "DASHBOARD_PASSWORD": _require_env("DASHBOARD_PASSWORD"),

        # Optional shared token for agents. Newer agents can send it in the
        # X-Agent-Token header; existing agents that can't be updated are
        # authenticated by source IP instead (see below). Leave unset if all
        # agents authenticate by IP.
        "AGENT_TOKEN": os.environ.get("AGENT_TOKEN", ""),

        # Existing agents already report from a known set of public IPs (the
        # keys of PRACTICE_NAMES). A heartbeat is accepted if it carries a valid
        # token OR arrives from one of those known IPs. Add any extra IPs that
        # aren't in the practice table here (comma-separated), e.g. UNKNOWN-group
        # machines you still want to allow.
        "EXTRA_ALLOWED_IPS": {ip.strip() for ip in
                              os.environ.get("HEARTBEAT_ALLOWED_IPS", "").split(",") if ip.strip()},

        # Emergency escape hatch: set to 1 to accept ANY heartbeat (the old
        # anonymous behaviour). Not recommended — leaves the endpoint open.
        "ALLOW_ANONYMOUS_HEARTBEAT": os.environ.get("HEARTBEAT_ALLOW_ANONYMOUS", "0") == "1",

        # Whether to trust X-Forwarded-For (only enable behind a trusted proxy
        # that OVERWRITES the header rather than appending to it).
        "TRUST_PROXY": os.environ.get("TRUST_PROXY", "0") == "1",

        # SMTP / email
        "SMTP_SERVER": os.environ.get("SMTP_SERVER", "smtp.gmail.com"),
        "SMTP_PORT": int(os.environ.get("SMTP_PORT", "587")),
        "SENDER_NAME": os.environ.get("SENDER_NAME", "PESCOE IT"),
        "SENDER_EMAIL": os.environ.get("SENDER_EMAIL", ""),
        "SMTP_PASSWORD": _require_env("SMTP_PASSWORD"),
        "ALERT_RECEIVER_EMAIL": os.environ.get("ALERT_RECEIVER_EMAIL", ""),
        "OTP_RECEIVER_EMAIL": os.environ.get("OTP_RECEIVER_EMAIL", ""),

        # --- Digest / summary alerting -------------------------------------
        # How often (minutes) to send the rolled-up outage digest. 15 or 30 are
        # the usual choices. A digest is skipped entirely when nothing changed.
        "DIGEST_INTERVAL_MIN": int(os.environ.get("DIGEST_INTERVAL_MIN", "30")),
        # Local (IST) time at which the end-of-day rollup is sent.
        "EOD_HOUR": int(os.environ.get("EOD_HOUR", "18")),
        "EOD_MINUTE": int(os.environ.get("EOD_MINUTE", "30")),

        # Optional dead-man's-switch: URL pinged after each successful check loop
        # (e.g. a healthchecks.io / cronitor URL). Leave unset to disable.
        "HEALTHCHECK_PING_URL": os.environ.get("HEALTHCHECK_PING_URL", ""),

        # --- Web Push (mobile) ---------------------------------------------
        # VAPID keys authenticate the server to browser push services. If left
        # unset they're auto-generated on first run and persisted to disk
        # (VAPID_KEYS_FILE), so you don't have to manage them by hand. Set them
        # explicitly here only if you want to control/rotate them yourself.
        "VAPID_PUBLIC_KEY": os.environ.get("VAPID_PUBLIC_KEY", ""),
        "VAPID_PRIVATE_KEY_PEM": os.environ.get("VAPID_PRIVATE_KEY_PEM", ""),
        "VAPID_KEYS_FILE": os.environ.get("VAPID_KEYS_FILE", "vapid_keys.json"),
        # "mailto:" contact the push service can reach if there's a problem.
        "VAPID_CONTACT": os.environ.get(
            "VAPID_CONTACT",
            "mailto:" + (os.environ.get("SENDER_EMAIL") or "admin@example.com")),
        # Send a push for every individual node transition (as well as the
        # digest emails). Set to 0 to keep email-only alerting.
        "PUSH_ON_TRANSITIONS": os.environ.get("PUSH_ON_TRANSITIONS", "1") == "1",
    }

    if not cfg["SECRET_KEY"]:
        # A random key still works, but sessions won't survive a restart.
        cfg["SECRET_KEY"] = secrets.token_hex(32)
        print("[WARN] FLASK_SECRET_KEY not set; generated an ephemeral one. "
              "Existing dashboard sessions will be invalidated on restart.")

    return cfg


CONFIG = load_config()

app = Flask(__name__)
app.secret_key = CONFIG["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set to True when serving over HTTPS (recommended in production).
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

# ---------------------------------------------------------------------------
# MERAKI MX DASHBOARD (blueprint, inlined — single file, single project)
# ---------------------------------------------------------------------------
# Formerly a separate module (meraki_web_dashboard.py). Now defined here so the
# whole app is one file. Every /meraki/api/* route is unchanged; the Meraki UI
# is rendered as a scoped section of the main dashboard page (see below), so the
# old standalone /meraki/ page and the Uptime/Meraki/Both tab nav are gone.
ENV_PATH = Path(__file__).with_name(".env")

# The Meraki SDK is optional: without it the rest of the app still runs and the
# Network section just reports that it is disabled.
try:
    import meraki
    MERAKI_AVAILABLE = True
except ImportError:
    meraki = None
    MERAKI_AVAILABLE = False
    print("[INFO] 'meraki' SDK not installed; Meraki MX dashboard disabled. "
          "Run 'pip install meraki' to enable it.")

meraki_bp = Blueprint("meraki", __name__, url_prefix="/meraki")

def _load_logo():
    for name in ("PDA Logo.png", "PDA_Logo.png", "logo.png"):
        p = Path(__file__).with_name(name)
        if p.exists():
            b64 = base64.b64encode(p.read_bytes()).decode()
            return f"data:image/png;base64,{b64}"
    return ""  # header falls back to a text wordmark if the file is missing

LOGO_DATA_URI = _load_logo()

# ── State ────────────────────────────────────────────────────────────────

state = {
    "api_key": os.environ.get("MERAKI_API_KEY", ""),
    "org_id": os.environ.get("MERAKI_ORG_ID", ""),
    "connected": False,
    "devices": [],
    "last_refresh": None,
    "speed_results": {},
    "uplink_data": [],
    "auto_refresh": False,
}

dashboard_client = None
refresh_thread = None


def get_dashboard():
    global dashboard_client
    if not MERAKI_AVAILABLE:
        return None
    if dashboard_client is None and state["api_key"]:
        dashboard_client = meraki.DashboardAPI(
            state["api_key"], suppress_logging=True, output_log=False
        )
    return dashboard_client


# ── Background auto-refresh ──────────────────────────────────────────────

def auto_refresh_loop():
    while state["auto_refresh"] and state["connected"]:
        try:
            db = get_dashboard()
            if db:
                devices = db.organizations.getOrganizationDevicesStatuses(
                    state["org_id"], productTypes=["appliance"], total_pages="all"
                )
                state["devices"] = sorted(
                    devices, key=lambda d: d.get("name", d.get("serial", ""))
                )
                state["last_refresh"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            print(f"Auto-refresh error: {e}")
        # Sleep in small increments so we can stop quickly
        for _ in range(60):
            if not state["auto_refresh"]:
                break
            time.sleep(5)


# ── API Routes ───────────────────────────────────────────────────────────

@meraki_bp.route("/api/gate", methods=["POST"])
def gate():
    """Legacy no-op: access is now controlled by server.py's unified login, so
    there is nothing to gate here. Kept so any stale frontend call still 200s."""
    return jsonify({"ok": True})


@meraki_bp.route("/api/status")
def status():
    """Report connection state so the frontend can show the right screen and
    auto-connect without the user retyping the key. Login is enforced upstream
    by server.py, so the old gate is always considered satisfied here."""
    return jsonify({
        "gate_required": False,
        "authed": True,
        "meraki_available": MERAKI_AVAILABLE,
        "connected": state["connected"],
        "has_saved_key": bool(os.environ.get("MERAKI_API_KEY", "").strip()),
        "has_saved_org": bool(os.environ.get("MERAKI_ORG_ID", "").strip()),
        "device_count": len(state["devices"]),
    })


@meraki_bp.route("/api/save-key", methods=["POST"])
def save_key():
    """Persist the API key (and optional org id) to a local .env file."""
    data = request.json or {}
    api_key = data.get("api_key", "").strip()
    org_id = data.get("org_id", "").strip()
    if not api_key:
        return jsonify({"error": "No API key to save"}), 400
    try:
        ENV_PATH.touch(exist_ok=True)
        set_key(str(ENV_PATH), "MERAKI_API_KEY", api_key)
        if org_id:
            set_key(str(ENV_PATH), "MERAKI_ORG_ID", org_id)
        # Reflect immediately so /api/status sees it this session.
        os.environ["MERAKI_API_KEY"] = api_key
        if org_id:
            os.environ["MERAKI_ORG_ID"] = org_id
        return jsonify({"saved": True})
    except Exception as e:
        return jsonify({"error": f"Could not save key: {e}"}), 500


@meraki_bp.route("/api/connect", methods=["POST"])
def connect():
    global dashboard_client, refresh_thread
    if not MERAKI_AVAILABLE:
        return jsonify({"error": "Meraki SDK is not installed on the server. "
                                 "Run 'pip install meraki' and restart."}), 503
    data = request.json or {}

    # use_saved: connect with the key already stored in .env / the environment,
    # so the browser never has to send (or even see) the saved key again.
    if data.get("use_saved"):
        api_key = os.environ.get("MERAKI_API_KEY", "").strip()
        org_id = data.get("org_id", "").strip() or os.environ.get("MERAKI_ORG_ID", "").strip()
        if not api_key:
            return jsonify({"error": "No saved API key found"}), 400
    else:
        api_key = data.get("api_key", "").strip()
        org_id = data.get("org_id", "").strip()

    if not api_key:
        return jsonify({"error": "API key is required"}), 400

    dashboard_client = meraki.DashboardAPI(
        api_key, suppress_logging=True, output_log=False
    )

    # If no org_id, list orgs so the user can pick
    if not org_id:
        try:
            orgs = dashboard_client.organizations.getOrganizations()
        except meraki.APIError as e:
            dashboard_client = None
            return jsonify({"error": f"Authentication failed: {e}"}), 401
        except Exception as e:  # network, unexpected SDK errors, etc.
            dashboard_client = None
            return jsonify({"error": f"Could not reach Meraki: {e}"}), 502

        if not orgs:
            dashboard_client = None
            return jsonify({
                "error": "This API key has no organizations. Check that the key is "
                         "correct and has organization access."
            }), 404

        # Only one org — skip the picker and connect straight through.
        if len(orgs) == 1:
            org_id = str(orgs[0].get("id", "")).strip()
        else:
            return jsonify({"needs_org": True, "organizations": orgs})

    # Connect with both key and org
    try:
        devices = dashboard_client.organizations.getOrganizationDevicesStatuses(
            org_id, productTypes=["appliance"], total_pages="all"
        )
        state["api_key"] = api_key
        state["org_id"] = org_id
        state["connected"] = True
        state["devices"] = sorted(
            devices, key=lambda d: d.get("name", d.get("serial", ""))
        )
        state["last_refresh"] = datetime.now(timezone.utc).isoformat()
        return jsonify({
            "connected": True,
            "device_count": len(devices),
        })
    except meraki.APIError as e:
        dashboard_client = None
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        dashboard_client = None
        return jsonify({"error": f"Could not load devices: {e}"}), 502


@meraki_bp.route("/api/disconnect", methods=["POST"])
def disconnect():
    global dashboard_client
    state["connected"] = False
    state["auto_refresh"] = False
    state["devices"] = []
    state["speed_results"] = {}
    state["uplink_data"] = []
    state["api_key"] = ""
    state["org_id"] = ""
    dashboard_client = None
    return jsonify({"ok": True})


@meraki_bp.route("/api/devices")
def get_devices():
    if not state["connected"]:
        return jsonify({"error": "Not connected"}), 400
    return jsonify({
        "devices": state["devices"],
        "last_refresh": state["last_refresh"],
        "speed_results": state["speed_results"],
    })


@meraki_bp.route("/api/refresh", methods=["POST"])
def refresh_devices():
    if not state["connected"]:
        return jsonify({"error": "Not connected"}), 400
    db = get_dashboard()
    try:
        devices = db.organizations.getOrganizationDevicesStatuses(
            state["org_id"], productTypes=["appliance"], total_pages="all"
        )
        state["devices"] = sorted(
            devices, key=lambda d: d.get("name", d.get("serial", ""))
        )
        state["last_refresh"] = datetime.now(timezone.utc).isoformat()
        return jsonify({"ok": True, "device_count": len(devices)})
    except meraki.APIError as e:
        return jsonify({"error": str(e)}), 500


@meraki_bp.route("/api/auto-refresh", methods=["POST"])
def toggle_auto_refresh():
    global refresh_thread
    data = request.json
    enabled = data.get("enabled", False)
    state["auto_refresh"] = enabled

    if enabled and state["connected"]:
        if refresh_thread is None or not refresh_thread.is_alive():
            refresh_thread = threading.Thread(target=auto_refresh_loop, daemon=True)
            refresh_thread.start()
    return jsonify({"auto_refresh": state["auto_refresh"]})


@meraki_bp.route("/api/speed-test/<serial>")
def get_speed_result(serial):
    result = state["speed_results"].get(serial)
    if result is None:
        return jsonify({"status": "none"})
    return jsonify(result)


@meraki_bp.route("/api/throughput-test", methods=["POST"])
def throughput_test():
    if not state["connected"]:
        return jsonify({"error": "Not connected"}), 400
    data = request.json
    serial = data.get("serial", "")
    if not serial:
        return jsonify({"error": "Serial number required"}), 400

    db = get_dashboard()
    try:
        job = db.devices.createDeviceLiveToolsThroughputTest(serial)
        test_id = job.get("throughputTestId") or job.get("id")
    except meraki.APIError as e:
        return jsonify({"error": f"Failed to start speed test: {e}"}), 502
    except Exception as e:
        return jsonify({"error": f"Failed to start speed test: {e}"}), 502

    if not test_id:
        return jsonify({"error": "Speed test did not return a job id."}), 502

    def poll_throughput():
        for _ in range(15):
            time.sleep(5)
            try:
                result = db.devices.getDeviceLiveToolsThroughputTest(serial, test_id)
                if result.get("status") == "complete":
                    speeds = result.get("result", {}).get("speeds", {})
                    state["speed_results"][serial] = {
                        "download": speeds.get("downstream", 0),
                        "upload": 0,
                        "latency": None,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "status": "complete",
                        "test_type": "throughput",
                    }
                    return
            except Exception:
                pass
        state["speed_results"][serial] = {"status": "timeout"}

    state["speed_results"][serial] = {"status": "running"}
    threading.Thread(target=poll_throughput, daemon=True).start()
    return jsonify({"started": True, "serial": serial})


@meraki_bp.route("/api/uplinks")
def get_uplinks():
    if not state["connected"]:
        return jsonify({"error": "Not connected"}), 400
    db = get_dashboard()
    try:
        data = db.organizations.getOrganizationDevicesUplinksLossAndLatency(
            state["org_id"], timespan=300
        )
        state["uplink_data"] = data
        return jsonify({"uplinks": data})
    except meraki.APIError as e:
        return jsonify({"error": str(e)}), 500

LOGO_DATA_URI = _load_logo()

app.register_blueprint(meraki_bp)


# ---------------------------------------------------------------------------
# UNIFIED LOGIN (protects everything except the login flow, the heartbeat
# endpoint, and the public PWA assets). This is what lets a single OTP login
# cover both the Uptime dashboard and the Meraki MX dashboard.
# ---------------------------------------------------------------------------

# Endpoints reachable WITHOUT being logged in. Everything else — including every
# Meraki blueprint route (meraki.*) — requires a completed OTP login.
PUBLIC_ENDPOINTS = {
    "login", "verify_otp", "logout", "receive_heartbeat",
    "service_worker", "web_manifest", "pwa_icon", "apple_touch_icon", "static",
}


@app.before_request
def require_login_globally():
    ep = request.endpoint
    if ep is None:                       # unmatched path -> let Flask 404 it
        return None
    if ep in PUBLIC_ENDPOINTS:
        return None
    if session.get("logged_in"):
        return None
    # Not authenticated: JSON 401 for API/XHR callers, redirect for pages.
    if request.path.startswith("/api") or request.path.startswith("/meraki/api"):
        return jsonify({"error": "Authentication required", "gate": True}), 401
    return redirect(url_for("login"))



# ---------------------------------------------------------------------------
# PRACTICE / GROUP LOOKUP TABLES
# ---------------------------------------------------------------------------

PRACTICE_NAMES = {
    "71.104.53.54": "EON", "100.35.116.224": "BLM", "68.51.97.15": "FWC",
    "68.59.161.50": "FWJ", "68.45.192.90": "HUN", "71.187.15.33": "TLP",
    "100.1.198.179": "NEO", "72.88.219.63": "NWK", "173.54.21.148": "BAC",
    "71.250.13.159": "BAY", "71.168.130.146": "BDG", "108.53.60.187": "BEL",
    "71.168.152.122": "COL", "96.234.116.217": "ELZ", "108.24.45.153": "HAM",
    "71.187.114.93": "HIL", "100.11.251.59": "LEV", "73.146.220.81": "MAP",
    "71.104.45.4": "MLK", "73.64.211.168": "NHA", "108.24.110.206": "TTN",
    "71.25.104.34": "BEN", "108.24.196.218": "EWG", "24.185.36.58": "PED",
    "73.248.188.164": "PLN", "67.82.132.209": "WES", "174.60.168.179": "MHA","72.88.232.18": "AFC","182.156.143.144": "PUN",
}

BUSINESS_GROUPS = {
    "LEV": "PDA", "HIL": "PDA", "ELZ": "PDA", "PLN": "PDA", "HAM": "PDA",
    "BDG": "PDA", "COL": "PDA", "TTN": "PDA", "BAY": "PDA", "BEN": "PDA",
    "BAC": "PDA", "MLK": "PDA", "PED": "PDA", "EWG": "PDA", "WES": "PDA",
    "PSA": "PDA", "ELA": "PDA",
    "EON": "ADMI", "NWK": "ADMI", "NEO": "ADMI", "BLM": "ADMI", "FWC": "ADMI",
    "FWJ": "ADMI", "HUN": "ADMI", "MAP": "ADMI", "BEL": "ADMI", "NHA": "ADMI",
    "TLP": "ADMI", "MHA": "ADMI", "GVD": "ADMI","AFC": "ADMI",
}

# IPs allowed to post heartbeats without a token: every known practice public IP
# plus anything explicitly listed in HEARTBEAT_ALLOWED_IPS. This lets already-
# deployed agents keep reporting unchanged.
HEARTBEAT_ALLOWED_IPS = set(PRACTICE_NAMES.keys()) | CONFIG["EXTRA_ALLOWED_IPS"]

# ---------------------------------------------------------------------------
# SHARED STATE (guarded by state_lock)
# ---------------------------------------------------------------------------

machines = {}                     # system_name -> dict(last_seen, status, ...)
state_lock = threading.RLock()    # protects `machines`, digest buffers and DB writes
email_queue = queue.Queue()       # (subject, body, to_addr) tuples for the mailer
push_queue = queue.Queue()        # dict payloads for the Web Push worker

pending_events = []               # transitions since the last periodic digest
day_events = []                   # transitions since the last end-of-day report

# Populated by ensure_vapid_keys() at startup: the public applicationServerKey
# (base64url) the browser needs, and the path to the private-key PEM pywebpush
# signs with. Empty when Web Push is unavailable/unconfigured.
VAPID = {"public_key": "", "private_pem_path": ""}


def now_ist():
    return datetime.now(timezone.utc).astimezone(IST)


def fmt_duration(total_seconds):
    total_seconds = max(0, int(total_seconds))
    h, m, s = total_seconds // 3600, (total_seconds % 3600) // 60, total_seconds % 60
    return f"{h}h {m}m {s}s"


# ---------------------------------------------------------------------------
# SQLite PERSISTENCE + HISTORY
# ---------------------------------------------------------------------------

def get_db():
    """One connection per calling thread (sqlite objects aren't shared across threads)."""
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")   # better concurrent read/write behaviour
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS nodes (
                system_name   TEXT PRIMARY KEY,
                ip_address    TEXT,
                is_server     INTEGER DEFAULT 0,
                status        TEXT,
                last_seen     TEXT,
                offline_since TEXT,
                alert_sent    INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                system_name TEXT,
                status      TEXT,          -- 'Online' or 'Offline'
                ts          REAL           -- epoch seconds
            );
            CREATE INDEX IF NOT EXISTS idx_events_name_ts ON events(system_name, ts);
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                endpoint   TEXT PRIMARY KEY,
                sub_json   TEXT NOT NULL,   -- full PushSubscription JSON
                created    TEXT
            );
        """)
        conn.commit()
    finally:
        conn.close()


def db_add_subscription(sub):
    """Store (or refresh) a browser push subscription, keyed by its endpoint."""
    endpoint = sub.get("endpoint")
    if not endpoint:
        return
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO push_subscriptions (endpoint, sub_json, created) VALUES (?, ?, ?) "
            "ON CONFLICT(endpoint) DO UPDATE SET sub_json=excluded.sub_json",
            (endpoint, json.dumps(sub), now_ist().isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def db_remove_subscription(endpoint):
    conn = get_db()
    try:
        conn.execute("DELETE FROM push_subscriptions WHERE endpoint=?", (endpoint,))
        conn.commit()
    finally:
        conn.close()


def db_all_subscriptions():
    conn = get_db()
    try:
        rows = conn.execute("SELECT sub_json FROM push_subscriptions").fetchall()
    finally:
        conn.close()
    subs = []
    for r in rows:
        try:
            subs.append(json.loads(r["sub_json"]))
        except (ValueError, TypeError):
            pass
    return subs


def load_state_from_db():
    """Rehydrate the in-memory `machines` dict from disk on startup."""
    global machines
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM nodes").fetchall()
    finally:
        conn.close()

    rehydrated = {}
    for r in rows:
        rehydrated[r["system_name"]] = {
            "last_seen": datetime.fromisoformat(r["last_seen"]),
            "status": r["status"],
            "alert_sent": bool(r["alert_sent"]),
            "offline_since": datetime.fromisoformat(r["offline_since"]) if r["offline_since"] else None,
            "ip_address": r["ip_address"],
            "is_server": bool(r["is_server"]),
        }
    with state_lock:
        machines = rehydrated
    print(f"[{now_ist():%I:%M:%S %p}] Restored {len(rehydrated)} monitored nodes from disk.")


def db_upsert_node(name, info):
    """Write a single node's current state through to disk. Call while holding state_lock."""
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO nodes (system_name, ip_address, is_server, status, last_seen, offline_since, alert_sent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(system_name) DO UPDATE SET
                ip_address=excluded.ip_address,
                is_server=excluded.is_server,
                status=excluded.status,
                last_seen=excluded.last_seen,
                offline_since=excluded.offline_since,
                alert_sent=excluded.alert_sent
        """, (
            name,
            info["ip_address"],
            1 if info["is_server"] else 0,
            info["status"],
            info["last_seen"].isoformat(),
            info["offline_since"].isoformat() if info["offline_since"] else None,
            1 if info["alert_sent"] else 0,
        ))
        conn.commit()
    finally:
        conn.close()


def db_record_event(name, status, when):
    """Append a status-transition row used for uptime history."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO events (system_name, status, ts) VALUES (?, ?, ?)",
            (name, status, when.timestamp()),
        )
        conn.commit()
    finally:
        conn.close()


def db_delete_node(name):
    conn = get_db()
    try:
        conn.execute("DELETE FROM nodes WHERE system_name=?", (name,))
        conn.execute("DELETE FROM events WHERE system_name=?", (name,))
        conn.commit()
    finally:
        conn.close()


def uptime_ratio(conn, name, window_seconds, now_epoch):
    """
    Fraction of the last `window_seconds` the node was Online, reconstructed from
    the events table. Nodes with no history are treated as fully online.
    """
    start = now_epoch - window_seconds

    prior = conn.execute(
        "SELECT status FROM events WHERE system_name=? AND ts<=? ORDER BY ts DESC LIMIT 1",
        (name, start),
    ).fetchone()
    state = prior["status"] if prior else "Online"

    evs = conn.execute(
        "SELECT ts, status FROM events WHERE system_name=? AND ts>? ORDER BY ts ASC",
        (name, start),
    ).fetchall()

    offline = 0.0
    cursor = start
    for ev in evs:
        if state == "Offline":
            offline += ev["ts"] - cursor
        cursor = ev["ts"]
        state = ev["status"]
    if state == "Offline":
        offline += now_epoch - cursor

    ratio = 1.0 - (offline / window_seconds)
    return max(0.0, min(1.0, ratio))


# ---------------------------------------------------------------------------
# EMAIL (single helper, async worker with retries)
# ---------------------------------------------------------------------------

def _send_email_now(subject, body, to_addr):
    """Blocking SMTP send. Returns True on success."""
    if not (CONFIG["SENDER_EMAIL"] and CONFIG["SMTP_PASSWORD"] and to_addr):
        print(f"[WARN] Email not sent (SMTP not fully configured): {subject}")
        return False
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = f'"{CONFIG["SENDER_NAME"]}" <{CONFIG["SENDER_EMAIL"]}>'
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(CONFIG["SMTP_SERVER"], CONFIG["SMTP_PORT"], timeout=20) as server:
            server.starttls()
            server.login(CONFIG["SENDER_EMAIL"], CONFIG["SMTP_PASSWORD"])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[ERROR] SMTP send failed: {e}")
        return False


def email_worker():
    """Consumes the email queue so alerts never block heartbeat handling."""
    while True:
        subject, body, to_addr = email_queue.get()
        for attempt in range(3):
            if _send_email_now(subject, body, to_addr):
                break
            time.sleep(2 * (attempt + 1))     # simple backoff
        else:
            print(f"[ERROR] Giving up on email after 3 attempts: {subject}")
        email_queue.task_done()


# ---------------------------------------------------------------------------
# WEB PUSH (mobile / background notifications) + VAPID KEYS
# ---------------------------------------------------------------------------

def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def ensure_vapid_keys():
    """
    Establish the VAPID key pair used to authenticate push messages. Order of
    preference: explicit env vars -> persisted key file -> freshly generated
    (and then persisted). Populates the global VAPID dict. No-op (leaves Web
    Push disabled) if the crypto libraries aren't installed.
    """
    if not PUSH_LIBS_AVAILABLE:
        return

    pem_path = os.path.abspath("vapid_private.pem")

    # 1) Explicit configuration wins.
    if CONFIG["VAPID_PUBLIC_KEY"] and CONFIG["VAPID_PRIVATE_KEY_PEM"]:
        with open(pem_path, "w") as fh:
            fh.write(CONFIG["VAPID_PRIVATE_KEY_PEM"])
        VAPID["public_key"] = CONFIG["VAPID_PUBLIC_KEY"]
        VAPID["private_pem_path"] = pem_path
        print("[INFO] Using VAPID keys from environment.")
        return

    # 2) Reuse a previously persisted pair so existing subscriptions stay valid.
    keys_file = CONFIG["VAPID_KEYS_FILE"]
    if os.path.exists(keys_file):
        try:
            with open(keys_file) as fh:
                saved = json.load(fh)
            with open(pem_path, "w") as fh:
                fh.write(saved["private_pem"])
            VAPID["public_key"] = saved["public_key"]
            VAPID["private_pem_path"] = pem_path
            print("[INFO] Loaded persisted VAPID keys.")
            return
        except (ValueError, KeyError, OSError) as e:
            print(f"[WARN] Could not read {keys_file} ({e}); regenerating keys.")

    # 3) Generate a fresh pair and persist it.
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_point = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    public_key = _b64url(public_point)

    with open(keys_file, "w") as fh:
        json.dump({"public_key": public_key, "private_pem": private_pem}, fh)
    with open(pem_path, "w") as fh:
        fh.write(private_pem)

    VAPID["public_key"] = public_key
    VAPID["private_pem_path"] = pem_path
    print(f"[INFO] Generated new VAPID key pair (saved to {keys_file}).")


def push_enabled():
    return PUSH_LIBS_AVAILABLE and bool(VAPID["public_key"])


def enqueue_push(title, body, tag="pescoe", url="/"):
    """Buffer a push notification for delivery to all subscribed devices."""
    if not (push_enabled() and CONFIG["PUSH_ON_TRANSITIONS"]):
        return
    push_queue.put({"title": title, "body": body, "tag": tag, "url": url})


def _send_push_now(payload):
    """Fan a single payload out to every stored subscription, pruning dead ones."""
    subs = db_all_subscriptions()
    if not subs:
        return
    data = json.dumps(payload)
    claims = {"sub": CONFIG["VAPID_CONTACT"]}
    for sub in subs:
        try:
            webpush(
                subscription_info=sub,
                data=data,
                vapid_private_key=VAPID["private_pem_path"],
                vapid_claims=dict(claims),   # pywebpush mutates this; give it a copy
                ttl=120,
            )
        except WebPushException as e:
            status = getattr(e.response, "status_code", None)
            try:
                body = e.response.text or ""
            except Exception:
                body = str(e)
            # A VAPID key mismatch means the subscription was created against a
            # DIFFERENT applicationServerKey than we now sign with (e.g. the key
            # pair was rotated after the browser subscribed). Such a subscription
            # can never accept our pushes, so treat it like an expired one and
            # prune it — the device re-subscribes with the current key next time
            # it loads the dashboard with notifications on.
            key_mismatch = ("VapidPkHashMismatch" in body
                            or "do not correspond" in body)
            # 404/410 mean the subscription is gone for good — stop pushing to it.
            if status in (404, 410):
                db_remove_subscription(sub.get("endpoint", ""))
                print(f"[INFO] Pruned expired push subscription ({status}).")
            elif key_mismatch:
                db_remove_subscription(sub.get("endpoint", ""))
                print(f"[INFO] Pruned stale push subscription "
                      f"(VAPID key mismatch, {status}); device will re-subscribe.")
            else:
                print(f"[WARN] Push failed ({status}): {e}")
        except Exception as e:
            print(f"[WARN] Push error: {e}")


def push_worker():
    """Consumes the push queue so notification delivery never blocks handlers."""
    while True:
        payload = push_queue.get()
        try:
            _send_push_now(payload)
        except Exception as e:
            print(f"[ERROR] push_worker: {e}")
        finally:
            push_queue.task_done()


# ---------------------------------------------------------------------------
# PWA ICONS (generated once at startup; no image libraries required)
# ---------------------------------------------------------------------------

_ICON_CACHE = {}


def _encode_png(width, height, pixels):
    """Encode an RGBA bytearray into a PNG byte string (pure stdlib)."""
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff))

    stride = width * 4
    raw = bytearray()
    for y in range(height):
        raw.append(0)                     # filter type 0 (None) per scanline
        raw += pixels[y * stride:(y + 1) * stride]

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)   # 8-bit RGBA
    idat = zlib.compress(bytes(raw), 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _render_icon_png(size):
    """A dark, full-bleed monitor + heartbeat glyph — maskable-safe and crisp."""
    W = H = size
    buf = bytearray(W * H * 4)

    def put(x, y, rgb):
        if 0 <= x < W and 0 <= y < H:
            i = (y * W + x) * 4
            buf[i], buf[i + 1], buf[i + 2], buf[i + 3] = rgb[0], rgb[1], rgb[2], 255

    # Vertical navy gradient background (full bleed => safe as a maskable icon).
    top, bot = (15, 23, 42), (30, 41, 59)
    for y in range(H):
        t = y / (H - 1)
        rgb = (int(top[0] + (bot[0] - top[0]) * t),
               int(top[1] + (bot[1] - top[1]) * t),
               int(top[2] + (bot[2] - top[2]) * t))
        base = y * W * 4
        for x in range(W):
            i = base + x * 4
            buf[i], buf[i + 1], buf[i + 2], buf[i + 3] = rgb[0], rgb[1], rgb[2], 255

    # Monitor screen (rounded rect) centred within the maskable safe zone.
    sx0, sy0 = int(0.24 * W), int(0.28 * H)
    sx1, sy1 = int(0.76 * W), int(0.60 * H)
    radius = max(2, int(0.05 * W))
    screen, border = (2, 6, 23), (71, 85, 105)
    for y in range(sy0, sy1):
        for x in range(sx0, sx1):
            # Rounded-corner test.
            cx = min(max(x, sx0 + radius), sx1 - radius)
            cy = min(max(y, sy0 + radius), sy1 - radius)
            if (x - cx) ** 2 + (y - cy) ** 2 > radius * radius:
                continue
            edge = (x < sx0 + 3 or x >= sx1 - 3 or y < sy0 + 3 or y >= sy1 - 3)
            put(x, y, border if edge else screen)

    # Monitor stand + base.
    for y in range(sy1, int(sy1 + 0.06 * H)):
        for x in range(int(0.47 * W), int(0.53 * W)):
            put(x, y, border)
    for y in range(int(sy1 + 0.06 * H), int(sy1 + 0.09 * H)):
        for x in range(int(0.40 * W), int(0.60 * W)):
            put(x, y, border)

    # Green heartbeat polyline across the screen.
    inner_w, inner_h = (sx1 - sx0), (sy1 - sy0)
    pts = [(0.06, 0.5), (0.30, 0.5), (0.42, 0.24), (0.52, 0.80),
           (0.62, 0.16), (0.72, 0.5), (0.94, 0.5)]
    coords = [(sx0 + px * inner_w, sy0 + py * inner_h) for px, py in pts]
    green = (16, 185, 129)
    half = max(1.0, 0.018 * W)
    for k in range(len(coords) - 1):
        x0, y0 = coords[k]
        x1, y1 = coords[k + 1]
        minx, maxx = int(min(x0, x1) - half - 1), int(max(x0, x1) + half + 1)
        miny, maxy = int(min(y0, y1) - half - 1), int(max(y0, y1) + half + 1)
        dx, dy = x1 - x0, y1 - y0
        seg2 = dx * dx + dy * dy or 1.0
        for y in range(miny, maxy + 1):
            for x in range(minx, maxx + 1):
                t = ((x - x0) * dx + (y - y0) * dy) / seg2
                t = 0.0 if t < 0 else 1.0 if t > 1 else t
                px_, py_ = x0 + t * dx, y0 + t * dy
                if (x - px_) ** 2 + (y - py_) ** 2 <= half * half:
                    put(x, y, green)

    return _encode_png(W, H, buf)


def get_icon_png(size):
    if size not in _ICON_CACHE:
        _ICON_CACHE[size] = _render_icon_png(size)
    return _ICON_CACHE[size]


# ---------------------------------------------------------------------------
# OUTAGE DIGEST / SUMMARY REPORTING
# ---------------------------------------------------------------------------

def _node_label(system_name, ip_address, is_server):
    """Resolve (practice, business group, node type) for display in reports."""
    practice = PRACTICE_NAMES.get(ip_address, "UNKNOWN")
    group = BUSINESS_GROUPS.get(practice, "UNKNOWN")
    node_type = "SERVER" if is_server else "WORKSTATION"
    return practice, group, node_type


def queue_status_alert(system_name, status, event_time, downtime_str="", ip_address="", is_server=False):
    """
    Buffer a status transition for the next digest instead of emailing immediately.
    Called from the heartbeat handler and the background status checker.
    """
    practice, group, node_type = _node_label(system_name, ip_address, is_server)
    ev = {
        "system_name": system_name,
        "status": status,
        "ts": event_time,
        "downtime_str": downtime_str,
        "ip_address": ip_address,
        "practice": practice,
        "group": group,
        "node_type": node_type,
    }
    with state_lock:
        pending_events.append(ev)
        day_events.append(ev)


def _fmt_event_line(ev):
    t = ev["ts"].strftime('%I:%M:%S %p')
    line = (f"  [{ev['group']}] {ev['practice']} / {ev['system_name']} "
            f"({ev['node_type']}, {ev['ip_address']}) at {t}")
    if ev["status"] == "Online" and ev["downtime_str"]:
        line += f" — down for {ev['downtime_str']}"
    return line


def _current_outages(now):
    """Snapshot of everything currently Offline: list of (name, info_copy, duration_str)."""
    out = []
    with state_lock:
        for name, info in machines.items():
            if info["status"] == "Offline":
                dur = (fmt_duration((now - info["offline_since"]).total_seconds())
                       if info["offline_since"] else "unknown")
                out.append((name, dict(info), dur))
    out.sort(key=lambda x: x[0])
    return out


def send_outage_digest():
    """
    Send a rolled-up digest of outages/recoveries since the last digest.
    Stays completely silent when nothing changed in the window.
    """
    now = now_ist()
    with state_lock:
        evs = pending_events[:]
        pending_events.clear()

    went_down = [e for e in evs if e["status"] == "Offline"]
    came_back = [e for e in evs if e["status"] == "Online"]

    # Nothing changed since the last digest — don't send anything.
    if not went_down and not came_back:
        return

    ongoing = _current_outages(now)

    subject = (f"🚨 Outage Digest — {len(went_down)} new, {len(came_back)} resolved, "
               f"{len(ongoing)} ongoing ({now:%I:%M %p IST})")

    lines = [
        f"Outage digest for the {CONFIG['DIGEST_INTERVAL_MIN']}-minute window "
        f"ending {now:%Y-%m-%d %I:%M:%S %p IST}",
        "",
        f"NEW OUTAGES ({len(went_down)}):",
    ]
    lines += [_fmt_event_line(e) for e in went_down] or ["  none"]
    lines.append("")

    lines.append(f"RESOLVED IN THIS WINDOW ({len(came_back)}):")
    lines += [_fmt_event_line(e) for e in came_back] or ["  none"]
    lines.append("")

    lines.append(f"STILL OFFLINE RIGHT NOW ({len(ongoing)}):")
    if ongoing:
        for name, info, dur in ongoing:
            practice, group, node_type = _node_label(name, info["ip_address"], info["is_server"])
            lines.append(f"  [{group}] {practice} / {name} "
                         f"({node_type}, {info['ip_address']}) — down {dur}")
    else:
        lines.append("  none")

    email_queue.put((subject, "\n".join(lines), CONFIG["ALERT_RECEIVER_EMAIL"]))


def send_eod_report():
    """
    End-of-day rollup: every outage detected today, every resolution, and
    anything still unresolved at cut-off. Sent once per day.
    """
    now = now_ist()
    with state_lock:
        evs = day_events[:]
        day_events.clear()
        pending_events.clear()      # this report supersedes the interim buffer

    ongoing = _current_outages(now)
    downs = [e for e in evs if e["status"] == "Offline"]
    ups = [e for e in evs if e["status"] == "Online"]

    subject = (f"📋 End-of-Day Outage Summary — {now:%Y-%m-%d} — "
               f"{len(downs)} outages, {len(ups)} resolved, {len(ongoing)} unresolved")

    lines = [
        f"End-of-day outage summary for {now:%Y-%m-%d} (generated {now:%I:%M:%S %p IST})",
        "",
        f"Total outages detected today: {len(downs)}",
        f"Total resolved today:         {len(ups)}",
        f"Still unresolved:             {len(ongoing)}",
        "",
        "OUTAGES DETECTED TODAY:",
    ]
    lines += [_fmt_event_line(e) for e in downs] or ["  none"]
    lines.append("")

    lines.append("RESOLUTIONS TODAY:")
    lines += [_fmt_event_line(e) for e in ups] or ["  none"]
    lines.append("")

    lines.append("UNRESOLVED AT END OF DAY:")
    if ongoing:
        for name, info, dur in ongoing:
            practice, group, node_type = _node_label(name, info["ip_address"], info["is_server"])
            since = info["offline_since"].strftime('%I:%M:%S %p') if info["offline_since"] else "unknown"
            lines.append(f"  [{group}] {practice} / {name} ({node_type}, {info['ip_address']}) "
                         f"— offline since {since}, down {dur}")
    else:
        lines.append("  none — all clear")

    email_queue.put((subject, "\n".join(lines), CONFIG["ALERT_RECEIVER_EMAIL"]))


# ---------------------------------------------------------------------------
# OTP HELPERS (hashed in session, not plaintext)
# ---------------------------------------------------------------------------

def generate_otp(length=OTP_LENGTH):
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def hash_otp(code):
    return hmac.new(app.secret_key.encode(), code.encode(), sha256).hexdigest()


def send_otp_email(otp_code, event_time):
    ist = event_time.strftime('%Y-%m-%d %I:%M:%S %p IST')
    subject = "🔐 PESCOE Dashboard Login Verification Code"
    body = (f"Your one-time login verification code is: {otp_code}\n\n"
            f"This code expires in {OTP_EXPIRY_SECONDS // 60} minutes. Requested at: {ist}\n\n"
            f"If you did not request this, you can ignore this email.")
    # OTP is sent synchronously: the user is waiting and we need the result to decide the redirect.
    return _send_email_now(subject, body, CONFIG["OTP_RECEIVER_EMAIL"])


# ---------------------------------------------------------------------------
# CSRF (dependency-free, session-backed)
# ---------------------------------------------------------------------------

def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
    return token


def csrf_ok(supplied):
    expected = session.get("csrf_token", "")
    return bool(supplied) and secrets.compare_digest(supplied, expected)


# ---------------------------------------------------------------------------
# AUTH DECORATORS
# ---------------------------------------------------------------------------

def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def client_ip():
    """Resolve the client IP, honouring X-Forwarded-For only behind a trusted proxy."""
    if CONFIG["TRUST_PROXY"] and request.headers.get("X-Forwarded-For"):
        ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
        if ":" in ip and not ip.startswith("["):
            ip = ip.rsplit(":", 1)[0]
        return ip
    return request.remote_addr


# ---------------------------------------------------------------------------
# BACKGROUND WORKERS
# ---------------------------------------------------------------------------

def background_status_checker():
    while True:
        now = now_ist()
        with state_lock:
            for name, info in list(machines.items()):
                elapsed = (now - info["last_seen"]).total_seconds()
                if elapsed > OFFLINE_THRESHOLD and info["status"] == "Online":
                    info["status"] = "Offline"
                    info["offline_since"] = now
                    if not info["alert_sent"]:
                        queue_status_alert(name, "Offline", now,
                                           ip_address=info["ip_address"],
                                           is_server=info["is_server"])
                        practice, group, node_type = _node_label(
                            name, info["ip_address"], info["is_server"])
                        enqueue_push(
                            f"🚨 OFFLINE — {practice} / {name}",
                            f"{group} · {node_type} · {info['ip_address']}",
                            tag="out-" + name)
                        info["alert_sent"] = True
                    db_upsert_node(name, info)
                    db_record_event(name, "Offline", now)

        # Optional dead-man's-switch: tell an external watcher we're alive.
        if CONFIG["HEALTHCHECK_PING_URL"]:
            try:
                urllib.request.urlopen(CONFIG["HEALTHCHECK_PING_URL"], timeout=10)
            except Exception as e:
                print(f"[WARN] Healthcheck ping failed: {e}")

        time.sleep(5)


def digest_scheduler():
    """
    Fires the periodic outage digest every DIGEST_INTERVAL_MIN minutes and the
    end-of-day rollup once per day at EOD_HOUR:EOD_MINUTE IST.
    """
    interval = max(1, CONFIG["DIGEST_INTERVAL_MIN"]) * 60
    next_digest = time.time() + interval
    last_eod_date = None

    print(f"[INFO] Digest scheduler started: every {CONFIG['DIGEST_INTERVAL_MIN']} min, "
          f"EOD report at {CONFIG['EOD_HOUR']:02d}:{CONFIG['EOD_MINUTE']:02d} IST.")

    while True:
        try:
            now = now_ist()

            if time.time() >= next_digest:
                send_outage_digest()
                next_digest = time.time() + interval

            if (now.hour == CONFIG["EOD_HOUR"]
                    and now.minute == CONFIG["EOD_MINUTE"]
                    and last_eod_date != now.date()):
                send_eod_report()
                last_eod_date = now.date()
        except Exception as e:
            print(f"[ERROR] digest_scheduler: {e}")
        time.sleep(20)


# ---------------------------------------------------------------------------
# SUMMARY / SNAPSHOT BUILDERS
# ---------------------------------------------------------------------------

def build_snapshot():
    """Return (machine_list, summary_stats) for rendering. Includes uptime %."""
    now = now_ist()
    now_epoch = now.timestamp()
    conn = get_db()

    stats = {k: 0 for k in (
        "total_nodes", "total_online", "total_offline",
        "total_workstations", "total_servers",
        "pda_total", "pda_online", "pda_offline",
        "admi_total", "admi_online", "admi_offline",
        "unknown_total", "unknown_online", "unknown_offline",
        "srv_pda_total", "srv_pda_online", "srv_pda_offline",
        "srv_admi_total", "srv_admi_online", "srv_admi_offline",
        "srv_unknown_total", "srv_unknown_online", "srv_unknown_offline",
        # Meraki MX firewalls, grouped the same way (see below).
        "fw_pda_total", "fw_pda_online", "fw_pda_offline",
        "fw_admi_total", "fw_admi_online", "fw_admi_offline",
        "fw_unknown_total", "fw_unknown_online", "fw_unknown_offline",
    )}

    machine_list = []
    try:
        with state_lock:
            snapshot_items = list(machines.items())

        for name, info in snapshot_items:
            duration_str = "--"
            if info["status"] == "Offline" and info["offline_since"]:
                duration_str = fmt_duration((now - info["offline_since"]).total_seconds())

            practice = PRACTICE_NAMES.get(info["ip_address"], "UNKNOWN")
            group = BUSINESS_GROUPS.get(practice, "UNKNOWN")
            is_server = info["is_server"]
            online = info["status"] == "Online"

            stats["total_nodes"] += 1
            stats["total_online" if online else "total_offline"] += 1

            gk = "pda" if group == "PDA" else "admi" if group == "ADMI" else "unknown"
            prefix = "srv_" if is_server else ""
            if is_server:
                stats["total_servers"] += 1
            else:
                stats["total_workstations"] += 1
            stats[f"{prefix}{gk}_total"] += 1
            stats[f"{prefix}{gk}_{'online' if online else 'offline'}"] += 1

            machine_list.append({
                "system_name": name,
                "status": info["status"],
                "ip_address": info["ip_address"],
                "practice_name": practice,
                "business_group": group,
                "is_server": is_server,
                "last_seen": info["last_seen"].strftime('%Y-%m-%d %I:%M:%S %p'),
                "duration_str": duration_str,
                "uptime_24h": round(uptime_ratio(conn, name, 86400, now_epoch) * 100, 2),
                "uptime_7d": round(uptime_ratio(conn, name, 604800, now_epoch) * 100, 2),
            })
    finally:
        conn.close()

    # Merge in Meraki MX firewall status, grouped like the nodes. A firewall's
    # name maps to a practice by its prefix (e.g. "BAC-FW" -> "BAC"), then to a
    # business group via BUSINESS_GROUPS. "Online" counts reachable appliances
    # (Meraki 'online' or 'alerting'); everything else counts as offline.
    try:
        fw_devices = list(state.get("devices", []) or [])
    except Exception:
        fw_devices = []
    for d in fw_devices:
        dname = (d.get("name") or d.get("serial") or "").strip()
        practice = dname.split("-")[0].strip().upper() if dname else ""
        grp = BUSINESS_GROUPS.get(practice, "UNKNOWN")
        gk = "pda" if grp == "PDA" else "admi" if grp == "ADMI" else "unknown"
        up = (d.get("status") or "").lower() in ("online", "alerting")
        stats[f"fw_{gk}_total"] += 1
        stats[f"fw_{gk}_{'online' if up else 'offline'}"] += 1

    machine_list.sort(key=lambda x: (x["business_group"], x["practice_name"], x["system_name"]))
    return machine_list, stats


# ---------------------------------------------------------------------------
# TEMPLATES
# ---------------------------------------------------------------------------

_SHARED_CSS = """
    :root {
        --bg-color:#0f172a; --card-bg:#1e293b; --text-main:#f8fafc; --text-muted:#94a3b8;
        --border-color:#334155; --accent-blue:#3b82f6; --accent-hover:#2563eb;
        --error-color:#ef4444; --success-color:#10b981;
    }
    body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:var(--bg-color);
           color:var(--text-main); display:flex; justify-content:center; align-items:center;
           height:100vh; margin:0; }
    .login-card { background:var(--card-bg); border:1px solid var(--border-color); padding:40px;
                  border-radius:12px; width:100%; max-width:400px;
                  box-shadow:0 10px 25px -5px rgba(0,0,0,.3); }
    h2 { margin-top:0; font-size:22px; font-weight:600; margin-bottom:24px; text-align:center; }
    p.subtext { color:var(--text-muted); font-size:13px; text-align:center; margin:0 0 24px; }
    .form-group { margin-bottom:20px; }
    label { display:block; font-size:13px; color:var(--text-muted); margin-bottom:8px;
            text-transform:uppercase; letter-spacing:.5px; }
    input[type=text],input[type=password] { width:100%; padding:12px; background:#0f172a;
            border:1px solid var(--border-color); border-radius:6px; color:#fff; font-size:15px;
            box-sizing:border-box; transition:border-color .2s; }
    input:focus { outline:none; border-color:var(--accent-blue); }
    button { width:100%; padding:12px; background:var(--accent-blue); color:#fff; border:none;
             border-radius:6px; font-size:15px; font-weight:600; cursor:pointer; transition:background .2s; }
    button:hover { background:var(--accent-hover); }
    .resend-btn { background:transparent; border:1px solid var(--border-color); margin-top:10px; color:var(--text-muted); }
    .resend-btn:hover { background:var(--border-color); color:var(--text-main); }
    .error-msg { color:var(--error-color); background:rgba(239,68,68,.1); border:1px solid rgba(239,68,68,.2);
                 padding:10px; border-radius:6px; font-size:14px; margin-bottom:20px; text-align:center; }
    .info-msg { color:var(--success-color); background:rgba(16,185,129,.1); border:1px solid rgba(16,185,129,.2);
                padding:10px; border-radius:6px; font-size:14px; margin-bottom:20px; text-align:center; }
    h2 { display:flex; align-items:center; justify-content:center; gap:10px; }
    h2 .ico { width:22px; height:22px; flex:0 0 auto; }
    button:focus-visible, a:focus-visible, input:focus-visible {
        outline:2px solid var(--accent-blue); outline-offset:2px; }
    @media (prefers-reduced-motion:reduce){
        *,*::before,*::after{ transition:none!important; animation:none!important; }
    }
"""

_PWA_HEAD = """
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0f172a">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="PESCOE Uptime">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="icon" type="image/png" href="/icon-192.png">
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head><title>PESCOE Systems Uptime Dashboard</title>
""" + _PWA_HEAD + """
<style>""" + _SHARED_CSS + """
    body{overflow:hidden;}

    /* ── Splash: Network Nodes ─────────────────────── */
    .splash{position:fixed;inset:0;z-index:9999;background:var(--bg-color);
            display:flex;flex-direction:column;align-items:center;justify-content:center;
            opacity:1;transition:opacity .8s ease;}
    .splash.hide{opacity:0;pointer-events:none;}

    .net-svg{width:min(420px,90vw);height:auto;}
    .net-line{stroke:var(--accent-blue);stroke-width:1.2;stroke-dasharray:200;
              stroke-dashoffset:200;opacity:0.5;filter:drop-shadow(0 0 3px rgba(59,130,246,.3));}
    .net-node{fill:var(--accent-blue);opacity:0;filter:drop-shadow(0 0 4px rgba(59,130,246,.5));}
    .net-hub{fill:#1e3a5f;stroke:var(--accent-blue);stroke-width:2.5;opacity:0;
             filter:drop-shadow(0 0 12px rgba(59,130,246,.4));}
    .net-hub-text{fill:var(--text-main);font-size:16px;font-weight:800;opacity:0;}
    .net-hub-logo{opacity:0;}

    @keyframes netLineDraw{to{stroke-dashoffset:0}}
    @keyframes netNodePop{0%{r:0;opacity:0}60%{r:5;opacity:1}100%{r:4;opacity:0.9}}
    @keyframes netHubGrow{0%{r:0;opacity:0}50%{r:42;opacity:1}100%{r:40;opacity:1}}
    @keyframes netHubText{0%,60%{opacity:0}100%{opacity:1}}
    @keyframes netNodePulse{0%,100%{opacity:0.6;r:4}50%{opacity:1;r:5}}
    @keyframes splashFadeUp{to{opacity:1;transform:translateY(0)}}
    @keyframes splashLoad{to{width:100%}}

    .nl{animation:netLineDraw 1s ease forwards}
    .nn{animation:netNodePop .5s ease forwards,netNodePulse 2s ease infinite}
    .nh{animation:netHubGrow 1s ease forwards}
    .nht{animation:netHubText .8s ease forwards}
    .nhl{animation:netHubText .6s ease forwards}
    .d1{animation-delay:.2s,.2s}.d2{animation-delay:.3s,.3s}.d3{animation-delay:.35s,.35s}
    .d4{animation-delay:.4s,.4s}.d5{animation-delay:.45s,.45s}.d6{animation-delay:.5s,.5s}
    .d7{animation-delay:.55s,.55s}.d8{animation-delay:.6s,.6s}.d9{animation-delay:.65s,.65s}
    .d10{animation-delay:.7s,.7s}
    .nd1{animation-delay:.6s,2s}.nd2{animation-delay:.65s,2.1s}.nd3{animation-delay:.7s,2.2s}
    .nd4{animation-delay:.75s,2.3s}.nd5{animation-delay:.8s,2.4s}.nd6{animation-delay:.85s,2.15s}
    .nd7{animation-delay:.72s,2.05s}.nd8{animation-delay:.78s,2.25s}.nd9{animation-delay:.88s,2.35s}
    .nd10{animation-delay:.95s,2.45s}
    .nh{animation-delay:1.2s}
    .nht{animation-delay:1.8s}
    .nhl{animation-delay:2s}

    .splash-title{margin-top:10px;font-size:22px;font-weight:700;letter-spacing:1px;
                  color:var(--text-main);opacity:0;animation:splashFadeUp .8s 3s ease forwards;}
    .splash-sub{margin-top:6px;font-size:12px;color:var(--text-muted);letter-spacing:4px;
                text-transform:uppercase;opacity:0;animation:splashFadeUp .8s 3.4s ease forwards;}
    .splash-bar{width:200px;height:3px;background:var(--border-color);border-radius:3px;
                margin-top:24px;overflow:hidden;opacity:0;animation:splashFadeUp .5s 3.7s ease forwards;}
    .splash-bar-fill{height:100%;width:0;
                     background:linear-gradient(90deg,#3b82f6,#10b981);
                     border-radius:3px;animation:splashLoad 1.5s 3.9s ease-in-out forwards;}

    /* ── Hero login ────────────────────────────────── */
    body.ready{overflow:auto;}
    .login-hero{opacity:0;transform:translateY(30px);transition:opacity .6s .1s ease,transform .6s .1s ease;}
    .login-hero.show{opacity:1;transform:translateY(0);}

    .login-hero{display:flex;flex-direction:column;align-items:center;width:100%;max-width:420px;}
    .hero-logo-wrap{margin-bottom:28px;text-align:center;}
    .hero-logo-wrap img{width:90px;height:90px;object-fit:contain;
                        filter:drop-shadow(0 0 20px rgba(59,130,246,.25));}
    .hero-brand{font-size:22px;font-weight:700;margin-top:12px;letter-spacing:.5px;}
    .hero-tagline{font-size:12px;color:var(--text-muted);text-transform:uppercase;
                  letter-spacing:3px;margin-top:6px;}

    .login-card{animation:none;}
    .login-card h2{font-size:16px;margin-bottom:20px;color:var(--text-muted);font-weight:600;}
</style>
<style id="splashMotion">
    @media (prefers-reduced-motion:reduce){
        .splash,.splash *,.login-hero{animation:initial!important;transition:initial!important;}
        .nl{animation:netLineDraw 1s ease forwards!important}
        .nn{animation:netNodePop .5s ease forwards,netNodePulse 2s ease infinite!important}
        .nh{animation:netHubGrow 1s ease forwards!important}
        .nht{animation:netHubText .8s ease forwards!important}
        .nhl{animation:netHubText .6s ease forwards!important}
        .splash-title{animation:splashFadeUp .8s 3s ease forwards!important}
        .splash-sub{animation:splashFadeUp .8s 3.4s ease forwards!important}
        .splash-bar{animation:splashFadeUp .5s 3.7s ease forwards!important}
        .splash-bar-fill{animation:splashLoad 1.5s 3.9s ease-in-out forwards!important}
        .splash{transition:opacity .8s ease!important}
        .login-hero{transition:opacity .6s .1s ease,transform .6s .1s ease!important}
    }
</style>
</head><body>

<!-- Splash -->
<div class="splash" id="splash">
    <svg class="net-svg" viewBox="0 0 420 260" xmlns="http://www.w3.org/2000/svg">
        <line class="net-line nl d1"  x1="60"  y1="50"  x2="210" y2="130"/>
        <line class="net-line nl d4"  x1="360" y1="45"  x2="210" y2="130"/>
        <line class="net-line nl d6"  x1="40"  y1="200" x2="210" y2="130"/>
        <line class="net-line nl d10" x1="380" y1="210" x2="210" y2="130"/>
        <line class="net-line nl d2"  x1="30"  y1="130" x2="210" y2="130"/>
        <line class="net-line nl d8"  x1="390" y1="130" x2="210" y2="130"/>
        <line class="net-line nl d3"  x1="140" y1="30"  x2="210" y2="130"/>
        <line class="net-line nl d5"  x1="290" y1="25"  x2="210" y2="130"/>
        <line class="net-line nl d7"  x1="120" y1="230" x2="210" y2="130"/>
        <line class="net-line nl d9"  x1="310" y1="235" x2="210" y2="130"/>
        <circle class="net-node nn nd1"  cx="60"  cy="50"/>
        <circle class="net-node nn nd2"  cx="360" cy="45"/>
        <circle class="net-node nn nd3"  cx="40"  cy="200"/>
        <circle class="net-node nn nd4"  cx="380" cy="210"/>
        <circle class="net-node nn nd5"  cx="30"  cy="130"/>
        <circle class="net-node nn nd6"  cx="390" cy="130"/>
        <circle class="net-node nn nd7"  cx="140" cy="30"/>
        <circle class="net-node nn nd8"  cx="290" cy="25"/>
        <circle class="net-node nn nd9"  cx="120" cy="230"/>
        <circle class="net-node nn nd10" cx="310" cy="235"/>
        <circle class="net-hub nh" cx="210" cy="130" r="0"/>
        <image class="net-hub-logo nht" href="__LOGO_SRC__" x="182" y="102" width="56" height="56"/>
        <text class="net-hub-text nhl" x="210" y="172" text-anchor="middle" font-size="11"
              letter-spacing="3">MONITORING</text>
    </svg>
    <div class="splash-title">PESCOE Systems</div>
    <div class="splash-sub">Uptime Dashboard</div>
    <div class="splash-bar"><div class="splash-bar-fill"></div></div>
</div>

<!-- Hero login -->
<div class="login-hero" id="loginHero">
    <div class="hero-logo-wrap">
        <img src="__LOGO_SRC__" alt="Piccadilly Dental Alliance">
        <div class="hero-brand">PESCOE Systems</div>
        <div class="hero-tagline">Uptime Dashboard</div>
    </div>
    <div class="login-card">
        <h2>Sign in to continue</h2>
        {% if error %}<div class="error-msg">{{ error }}</div>{% endif %}
        <form method="POST" action="/login">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <div class="form-group"><label>Username</label>
                <input type="text" name="username" required autocomplete="off"></div>
            <div class="form-group"><label>Password</label>
                <input type="password" name="password" required></div>
            <button type="submit">Access Dashboard</button>
        </form>
    </div>
</div>

<script>
(function(){
    var splash=document.getElementById('splash');
    var hero=document.getElementById('loginHero');
    setTimeout(function(){
        splash.classList.add('hide');
        document.body.classList.add('ready');
        hero.classList.add('show');
    }, 6500);
    splash.addEventListener('transitionend',function(){splash.style.display='none';});
})();
</script>
</body></html>
"""

OTP_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head><title>Verify Login - PESCOE Systems Uptime Dashboard</title>
""" + _PWA_HEAD + """
<style>""" + _SHARED_CSS + """
    input[type=text]{font-size:20px;letter-spacing:6px;text-align:center;}
</style></head><body>
<div class="login-card">
    <h2><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span>Verification Required</span></h2>
    <p class="subtext">Enter the 6-digit code sent to the registered IT mailbox. It expires in 5 minutes.</p>
    {% if error %}
        {% if "sent" in error %}<div class="info-msg">{{ error }}</div>
        {% else %}<div class="error-msg">{{ error }}</div>{% endif %}
    {% endif %}
    <form method="POST" action="/verify-otp">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div class="form-group"><label>Verification Code</label>
            <input type="text" name="otp_code" maxlength="6" inputmode="numeric" pattern="[0-9]*"
                   autocomplete="off" autofocus required></div>
        <button type="submit">Verify &amp; Continue</button>
    </form>
    <form method="POST" action="/verify-otp">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="resend" value="1">
        <button type="submit" class="resend-btn">Resend Code</button>
    </form>
</div></body></html>
"""

DASHBOARD_TEMPLATE = r"""
<!DOCTYPE html><html lang="en"><head><title>PESCOE Systems Dashboard</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0f172a">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="PESCOE Uptime">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="icon" type="image/png" href="/icon-192.png">
<style>
:root{--bg-color:#0f172a;--card-bg:#1e293b;--th-bg:#1e293b;--text-main:#f8fafc;--text-system-name:#fff;
--text-muted:#94a3b8;--border-color:#334155;--online-color:#10b981;--offline-color:#ef4444;
--accent-blue:#3b82f6;--accent-purple:#a855f7;--accent-orange:#f59e0b;--row-hover:#24334d;
--btn-bg:#334155;--btn-hover:#475569;--search-bg:#0f172a;--search-border:#334155;
--filter-active-bg:#2563eb;--filter-active-text:#fff;}
[data-theme=light]{--bg-color:#f1f5f9;--card-bg:#fff;--th-bg:#e2e8f0;--text-main:#0f172a;
--text-system-name:#1e293b;--text-muted:#64748b;--border-color:#cbd5e1;--online-color:#059669;
--offline-color:#dc2626;--accent-blue:#2563eb;--accent-purple:#7c3aed;--accent-orange:#b45309;
--row-hover:#f8fafc;--btn-bg:#cbd5e1;--btn-hover:#e2e8f0;--search-bg:#fff;--search-border:#cbd5e1;
--filter-active-bg:#bbf7d0;--filter-active-text:#047857;}
body{font-family:'Segoe UI',sans-serif;margin:0;padding:30px;background:var(--bg-color);color:var(--text-main);transition:background .3s,color .3s;}
.container{max-width:1300px;margin:0 auto;}
header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border-color);padding-bottom:20px;margin-bottom:30px;}
h1{margin:0;font-size:24px;font-weight:600;display:flex;align-items:center;gap:10px;}
.header-actions{display:flex;align-items:center;gap:12px;}
.refresh-indicator{font-size:13px;color:var(--text-muted);background:var(--card-bg);padding:6px 12px;border-radius:20px;border:1px solid var(--border-color);}
.theme-btn,.logout-btn{font-size:13px;color:var(--text-main);background:var(--btn-bg);padding:6px 14px;border-radius:6px;text-decoration:none;border:1px solid var(--border-color);cursor:pointer;display:inline-flex;align-items:center;gap:6px;font-weight:600;transition:background .2s;}
.theme-btn:hover,.logout-btn:hover{background:var(--btn-hover);}
.section-title{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin:16px 0 8px;font-weight:700;border-left:3px solid var(--accent-blue);padding-left:8px;display:flex;justify-content:space-between;align-items:center;}
.section-total-badge{font-size:12px;background:var(--card-bg);padding:4px 10px;border-radius:6px;border:1px solid var(--border-color);text-transform:none;font-weight:600;color:var(--text-main);}
.systems-head,.collapse-head{cursor:pointer;user-select:none;}
.systems-head:hover,.collapse-head:hover{color:var(--text-main);}
.systems-head span:first-child,.collapse-head span:first-child{display:inline-flex;align-items:center;gap:8px;}
.systems-head .chev,.collapse-head .chev{width:16px;height:16px;transition:transform .2s ease;}
.systems-head[aria-expanded="true"] .chev,.collapse-head[aria-expanded="true"] .chev{transform:rotate(90deg);}
.metrics-grid.compact{grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;}
.metrics-grid.compact .card{padding:9px 11px;}
.metrics-grid.compact .card-value{font-size:16px;}
.metrics-grid.compact .card-split-values{gap:12px;margin-top:3px;}
.metrics-grid.compact .split-stat{font-size:12px;}
.card-fw{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:6px;padding-top:6px;border-top:1px solid var(--border-color);font-size:12px;font-weight:600;}
.card-fw .fw-caption{display:inline-flex;align-items:center;gap:5px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;font-size:10px;}
.card-fw .fw-caption .ico{width:13px;height:13px;}
.card-fw .split-stat{font-size:12px;}
.metrics-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:12px;margin-bottom:10px;}
.card{background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:12px 14px;position:relative;overflow:hidden;}
.card-title{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-muted);margin-bottom:5px;}
.card-value{font-size:22px;font-weight:bold;}
.card-split-values{display:flex;gap:14px;margin-top:4px;}
.split-stat{font-size:13px;font-weight:600;}
.controls-wrapper{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:15px;margin:25px 0 0;}
.search-container{position:relative;width:100%;max-width:380px;}
.search-input{width:100%;padding:11px 16px 11px 40px;font-size:14px;color:var(--text-main);background:var(--search-bg);border:1px solid var(--search-border);border-radius:8px;box-sizing:border-box;outline:none;}
.search-input:focus{border-color:var(--accent-blue);}
.search-icon{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--text-muted);pointer-events:none;}
.filter-buttons-group{display:flex;align-items:center;gap:10px;}
.filter-pill{font-size:13px;color:var(--text-main);background:var(--card-bg);border:1px solid var(--border-color);padding:10px 16px;border-radius:8px;cursor:pointer;font-weight:600;display:inline-flex;align-items:center;gap:6px;}
.filter-pill:hover{background:var(--btn-hover);}
.filter-pill.active-pill{background:var(--filter-active-bg);color:var(--filter-active-text);border-color:var(--accent-blue);}
.table-container{background:var(--card-bg);border:1px solid var(--search-border);border-radius:12px;overflow:hidden;margin-top:15px;}
table{width:100%;border-collapse:collapse;text-align:left;}
th,td{padding:16px 20px;}
th{background:var(--th-bg);color:var(--text-muted);font-size:13px;font-weight:600;text-transform:uppercase;border-bottom:2px solid var(--border-color);cursor:pointer;user-select:none;}
th .arrow{opacity:.5;font-size:11px;}
tr{border-bottom:1px solid var(--border-color);}
tr:hover{background:var(--row-hover);}
.business-group{font-weight:700;color:var(--accent-blue);font-size:15px;}
.practice-name{font-weight:600;color:var(--text-main);font-size:16px;}
.system-name{font-size:16px;font-weight:600;color:var(--text-system-name);display:flex;align-items:center;gap:6px;}
.server-tag{background:#334155;color:#cbd5e1;font-size:10px;font-weight:800;padding:2px 6px;border-radius:4px;text-transform:uppercase;border:1px solid #475569;}
.status-badge{font-size:12px;font-weight:700;padding:6px 12px;border-radius:6px;display:inline-flex;align-items:center;gap:6px;text-transform:uppercase;}
.status-badge::before{content:"";width:8px;height:8px;border-radius:50%;display:inline-block;}
.online{background:rgba(16,185,129,.15);color:var(--online-color);border:1px solid rgba(16,185,129,.3);}
.online::before{background:var(--online-color);}
.offline{background:rgba(239,68,68,.15);color:var(--offline-color);border:1px solid rgba(239,68,68,.3);}
.offline::before{background:var(--offline-color);}
.time-text{font-family:ui-monospace,'Cascadia Code',Consolas,'Courier New',monospace;color:var(--text-main);font-size:14px;}
.ip-text{font-family:ui-monospace,'Cascadia Code',Consolas,'Courier New',monospace;color:var(--text-muted);font-size:14px;}
.uptime-text{font-family:ui-monospace,'Cascadia Code',Consolas,'Courier New',monospace;font-size:13px;}
.downtime-active{color:var(--offline-color);font-weight:600;}
.retire-btn{background:transparent;border:1px solid var(--border-color);color:var(--text-muted);font-size:11px;padding:4px 8px;border-radius:4px;cursor:pointer;width:auto;}
.retire-btn:hover{background:var(--offline-color);color:#fff;border-color:var(--offline-color);}
.notif-btn.notif-off{opacity:.55;}
.notif-btn.notif-blocked{opacity:.55;cursor:not-allowed;}

/* ---- Icons, focus, live-region ------------------------------------------ */
.ico{width:1.05em;height:1.05em;flex:0 0 auto;vertical-align:-2px;stroke-width:2;}
h1 .ico{width:24px;height:24px;}
.refresh-indicator{display:inline-flex;align-items:center;gap:6px;}
.refresh-indicator .ico{width:14px;height:14px;color:var(--online-color);}
.search-icon .ico{width:16px;height:16px;display:block;}
.mini-dot{width:9px;height:9px;border-radius:50%;display:inline-block;flex:0 0 auto;}
.mini-dot.on{background:var(--online-color);}
.mini-dot.off{background:var(--offline-color);}
.card-title .ico{width:15px;height:15px;vertical-align:-2px;}
.filter-pill .ico{width:14px;height:14px;}
/* Visible keyboard focus on every interactive control (was missing). */
a:focus-visible,button:focus-visible,input:focus-visible,th[data-key]:focus-visible{
    outline:2px solid var(--accent-blue);outline-offset:2px;}
th[data-key]:focus-visible{outline-offset:-2px;}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
    clip:rect(0,0,0,0);white-space:nowrap;border:0;}
/* Honour users who ask for reduced motion. */
@media (prefers-reduced-motion:reduce){
    *,*::before,*::after{transition:none!important;animation:none!important;scroll-behavior:auto!important;}
}

/* ---- Mobile / PWA layout ------------------------------------------------ */
@media (max-width:768px){
    body{padding:16px 12px;padding-top:max(16px,env(safe-area-inset-top));}
    .container{max-width:100%;}
    header{flex-wrap:wrap;gap:12px;padding-bottom:14px;margin-bottom:18px;}
    h1{font-size:19px;}
    .header-actions{width:100%;flex-wrap:wrap;gap:8px;}
    .refresh-indicator{flex:1 1 100%;text-align:center;}
    .theme-btn,.logout-btn{flex:1 1 auto;justify-content:center;padding:9px 10px;font-size:12px;}
    /* WCAG/iOS-Android touch targets: keep every tappable control >= 44px tall. */
    .theme-btn,.logout-btn,.filter-pill,.retire-btn,.search-input{min-height:44px;}
    .metrics-grid{grid-template-columns:1fr 1fr;gap:10px;}
    .metrics-grid .card{padding:10px 12px;}
    .card-value{font-size:18px;}
    .controls-wrapper{gap:10px;}
    .search-container{max-width:100%;}
    .filter-buttons-group{width:100%;flex-wrap:wrap;}
    .filter-pill{flex:1 1 calc(50% - 5px);justify-content:center;padding:11px 8px;}

    /* Turn the wide table into stacked cards, one node per card. */
    .table-container{border:none;background:transparent;overflow:visible;margin-top:10px;}
    #systemsTable thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);}
    #systemsTable, #systemsTable tbody, #systemsTable tr, #systemsTable td{display:block;width:100%;box-sizing:border-box;}
    #systemsTable tr{background:var(--card-bg);border:1px solid var(--border-color);
        border-radius:12px;margin-bottom:12px;padding:6px 0;}
    #systemsTable tr:hover{background:var(--card-bg);}
    #systemsTable td{display:flex;justify-content:space-between;align-items:center;gap:14px;
        padding:9px 16px;border:none;text-align:right;}
    #systemsTable td::before{content:attr(data-label);text-align:left;color:var(--text-muted);
        font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;flex:0 0 auto;}
    #systemsTable td.system-name{font-size:17px;border-bottom:1px solid var(--border-color);
        padding-bottom:12px;margin-bottom:2px;}
    #systemsTable td[data-label="Actions"]{justify-content:flex-end;}
    #systemsTable td[data-label="Actions"]::before{display:none;}
    .retire-btn{padding:7px 14px;font-size:12px;}
}
@media (max-width:420px){
    .metrics-grid{grid-template-columns:1fr;}
}

/* ===== Meraki MX section (scoped under .mrk) ===== */
{% raw %}.mrk{
    
    --bg: #0a0f1c;
    --bg-2: #0d1526;
    --card: rgba(20, 30, 52, 0.55);
    --card-solid: #141e34;
    --glass-border: rgba(120, 150, 200, 0.18);
    --glass-highlight: rgba(255, 255, 255, 0.06);
    --track: rgba(120, 150, 200, 0.16);

    
    --text: #f4f7fb;
    --subtle: #c6d2e4;
    --muted: #93a1bd;      

    
    --brand: #0048a8;          
    --brand-strong: #003c8f;
    --brand-bright: #3b82f6;   
    --brand-soft: rgba(0, 72, 168, 0.16);
    --accent: #0a5bd0;         
    --on-accent: #ffffff;
    --info: #3b82f6;
    --purple: #a855f7;
    --green: #22c55e;
    --yellow: #eab308;
    --red: #ef4444;
    --gray: #64748b;

    
    --ring: #7fb0ff;

    
    --input-bg: rgba(11, 15, 26, 0.6);
    --danger-text: #fca5a5;
    --warn-text: #fde047;

    --radius: 16px;
    --radius-sm: 10px;
    --shadow: 0 10px 34px rgba(3, 12, 32, 0.5);
    --blur: 16px;

    
    --field:
      radial-gradient(40rem 40rem at 10% -10%, rgba(0, 72, 168, 0.30), transparent 60%),
      radial-gradient(34rem 34rem at 110% 6%, rgba(59, 130, 246, 0.18), transparent 58%),
      radial-gradient(42rem 42rem at 50% 122%, rgba(0, 72, 168, 0.14), transparent 60%),
      linear-gradient(180deg, var(--bg-2), var(--bg));

    
    --space-1: 6px;  --space-2: 10px; --space-3: 14px;
    --space-4: 20px; --space-5: 28px; --space-6: 40px;

    --mono: 'Fira Code', ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, Consolas, monospace;
    --sans: 'Source Sans 3', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    --head: 'Lexend', 'Source Sans 3', -apple-system, 'Segoe UI', system-ui, sans-serif;
  }[data-theme="light"] .mrk{
    --bg: #eef2f8;
    --bg-2: #f7f9fc;
    --card: rgba(255, 255, 255, 0.74);
    --card-solid: #ffffff;
    --glass-border: rgba(2, 32, 71, 0.12);
    --glass-highlight: rgba(255, 255, 255, 0.9);
    --track: rgba(2, 32, 71, 0.10);

    --text: #0f1b2d;
    --subtle: #33415c;
    --muted: #566379;          

    --brand-bright: #0a5bd0;   
    --ring: #0a5bd0;

    --input-bg: #ffffff;
    --danger-text: #b91c1c;
    --warn-text: #92610a;
    --shadow: 0 10px 30px rgba(20, 40, 80, 0.12);
    --field:
      radial-gradient(42rem 42rem at 8% -12%, rgba(0, 72, 168, 0.12), transparent 60%),
      radial-gradient(34rem 34rem at 112% 4%, rgba(59, 130, 246, 0.10), transparent 58%),
      radial-gradient(42rem 42rem at 50% 122%, rgba(0, 72, 168, 0.07), transparent 60%),
      linear-gradient(180deg, var(--bg-2), var(--bg));
  }.mrk *{ box-sizing: border-box; margin: 0; padding: 0; }.mrk{ -webkit-text-size-adjust: 100%; }.mrk{
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text);
    
    padding: var(--space-5) var(--space-4);
    line-height: 1.5;
    position: relative;
    overflow-x: hidden;
  }.mrk::before{
    content: "";
    position: absolute;
    inset: 0;
    z-index: -1;
    background: var(--field);
  }.mrk .container{ max-width: 1120px; margin: 0 auto; }.mrk a{ color: var(--brand-bright); }.mrk :focus-visible{
    outline: 2px solid var(--ring);
    outline-offset: 2px;
    border-radius: 6px;
  }.mrk .sr-only{
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
  }.mrk h1{ font-family: var(--head); font-size: 22px; font-weight: 700; letter-spacing: -0.4px; }.mrk h2, .mrk h3{ font-family: var(--head); }.mrk .subtitle{ font-size: 13px; color: var(--muted); margin-top: 2px; }.mrk .header{
    display: flex; align-items: center; gap: var(--space-3);
    margin-bottom: var(--space-5); flex-wrap: wrap;
  }.mrk .logo{
    height: 40px; border-radius: 10px; background: #fff;
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    padding: 6px 12px; box-shadow: 0 6px 18px rgba(0, 72, 168, 0.28);
  }.mrk .logo img{ height: 26px; width: auto; display: block; }.mrk .header-spacer{ flex: 1; }.mrk .theme-toggle{
    width: 38px; height: 38px; flex-shrink: 0; border-radius: 10px; cursor: pointer;
    background: var(--card); border: 1px solid var(--glass-border); color: var(--subtle);
    -webkit-backdrop-filter: blur(var(--blur)); backdrop-filter: blur(var(--blur));
    display: inline-flex; align-items: center; justify-content: center;
    transition: color 0.15s, border-color 0.15s, transform 0.12s;
  }.mrk .theme-toggle:hover{ color: var(--text); border-color: var(--brand-bright); }.mrk .theme-toggle:active{ transform: translateY(1px); }.mrk .theme-toggle svg{ width: 18px; height: 18px; }.mrk .theme-toggle .icon-sun{ display: none; }[data-theme="light"] .mrk .theme-toggle .icon-sun{ display: block; }[data-theme="light"] .mrk .theme-toggle .icon-moon{ display: none; }.mrk .health-pill{
    display: inline-flex; align-items: center; gap: 8px;
    padding: 8px 14px; border-radius: 999px;
    background: var(--card); border: 1px solid var(--glass-border);
    -webkit-backdrop-filter: blur(var(--blur)); backdrop-filter: blur(var(--blur));
    font-size: 13px; font-weight: 600;
  }.mrk .health-pill .beacon{
    width: 9px; height: 9px; border-radius: 50%; background: var(--green);
    box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.6);
    animation: pulse 2.2s ease-out infinite;
  }.mrk .health-pill.warn .beacon{ background: var(--yellow); animation: none; }.mrk .health-pill.crit .beacon{ background: var(--red); animation: none; }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.55); }
    70%  { box-shadow: 0 0 0 8px rgba(34, 197, 94, 0); }
    100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
  }.mrk .glass{
    background: var(--card);
    border: 1px solid var(--glass-border);
    border-radius: var(--radius);
    -webkit-backdrop-filter: blur(var(--blur));
    backdrop-filter: blur(var(--blur));
    box-shadow: var(--shadow), inset 0 1px 0 var(--glass-highlight);
  }.mrk .login-wrap{
    display: grid; grid-template-columns: 1.05fr 0.95fr; gap: var(--space-4);
    align-items: stretch; min-height: min(74vh, 620px); margin-top: var(--space-3);
  }.mrk .hero{
    position: relative; overflow: hidden; border-radius: var(--radius);
    padding: var(--space-6);
    background:
      radial-gradient(30rem 30rem at 120% -10%, rgba(59,130,246,0.45), transparent 60%),
      linear-gradient(160deg, var(--brand) 0%, var(--brand-strong) 60%, #002a66 100%);
    display: flex; flex-direction: column; justify-content: space-between;
    box-shadow: var(--shadow); color: #eaf2ff;
  }.mrk .hero::after{
    content: ""; position: absolute; inset: 0; pointer-events: none; opacity: 0.5;
    background:
      radial-gradient(18rem 18rem at 15% 110%, rgba(255,255,255,0.10), transparent 60%),
      radial-gradient(1px 1px at 20% 30%, rgba(255,255,255,0.5), transparent),
      radial-gradient(1px 1px at 70% 50%, rgba(255,255,255,0.35), transparent),
      radial-gradient(1px 1px at 40% 80%, rgba(255,255,255,0.3), transparent);
  }.mrk .hero > *{ position: relative; z-index: 1; }.mrk .hero-logo{
    background: #fff; border-radius: 12px; padding: 12px 18px;
    align-self: flex-start; box-shadow: 0 10px 30px rgba(0,20,60,0.35);
  }.mrk .hero-logo img{ height: 34px; width: auto; display: block; }.mrk .hero-copy h2{
    font-family: var(--head); font-size: clamp(26px, 3.2vw, 38px); line-height: 1.12;
    font-weight: 700; letter-spacing: -0.6px; margin-top: var(--space-5); color: #fff;
  }.mrk .hero-copy p{ margin-top: var(--space-3); font-size: 15px; color: #cfe0ff; max-width: 40ch; }.mrk .hero-points{ list-style: none; margin-top: var(--space-5); display: grid; gap: 12px; }.mrk .hero-points li{ display: flex; align-items: flex-start; gap: 11px; font-size: 14px; color: #eaf2ff; }.mrk .hero-points .tick{
    flex-shrink: 0; width: 22px; height: 22px; border-radius: 7px; margin-top: 1px;
    background: rgba(255,255,255,0.16); display: flex; align-items: center; justify-content: center;
  }.mrk .hero-points .tick svg{ width: 13px; height: 13px; color: #fff; }.mrk .hero-foot{ margin-top: var(--space-5); font-size: 12px; color: #a9c4f2; }.mrk .login-panel{ display: flex; align-items: center; }.mrk .login-card{ padding: var(--space-6); width: 100%; }.mrk .login-card .eyebrow{
    font-family: var(--head); font-size: 12px; font-weight: 600; letter-spacing: 0.6px;
    text-transform: uppercase; color: var(--brand-bright);
  }.mrk .login-card h2{ font-size: 22px; margin: 6px 0 var(--space-4); font-weight: 700; }.mrk .remember{
    display: flex; align-items: center; gap: 8px; margin: 2px 0 var(--space-3);
    font-size: 13px; color: var(--subtle); cursor: pointer; user-select: none;
  }.mrk .remember input{ width: 16px; height: 16px; accent-color: var(--brand-bright); cursor: pointer; }
  @media (max-width: 860px) {.mrk .login-wrap{ grid-template-columns: 1fr; min-height: 0; }.mrk .hero{ padding: var(--space-5); }.mrk .hero-copy h2{ margin-top: var(--space-4); }.mrk .hero-points{ grid-template-columns: 1fr 1fr; }
  }
  @media (max-width: 520px) {.mrk .hero-points{ grid-template-columns: 1fr; } }.mrk .gate-wrap{ min-height: 66vh; display: flex; align-items: center; justify-content: center; }.mrk .gate-card{ max-width: 400px; width: 100%; text-align: center; }.mrk .gate-card .gate-logo{ display: flex; justify-content: center; margin-bottom: var(--space-4); }.mrk .gate-card .eyebrow{
    font-family: var(--head); font-size: 12px; font-weight: 600; letter-spacing: 0.6px;
    text-transform: uppercase; color: var(--brand-bright);
  }.mrk .gate-card h2{ font-size: 20px; margin: 6px 0 var(--space-4); font-weight: 700; }.mrk .gate-card input{ text-align: center; }.mrk .gate-card .error{ text-align: left; }.mrk label{
    display: block; font-size: 12px; color: var(--subtle);
    margin-bottom: 6px; font-weight: 500;
  }.mrk input[type="password"], .mrk input[type="text"], .mrk select{
    width: 100%; padding: 11px 13px; border-radius: var(--radius-sm);
    border: 1px solid var(--glass-border); background: var(--input-bg);
    color: var(--text); font-size: 14px; margin-bottom: var(--space-3);
    outline: none; font-family: var(--sans);
    transition: border-color 0.15s, box-shadow 0.15s;
  }.mrk input:focus, .mrk select:focus{
    border-color: var(--brand-bright);
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
  }.mrk .btn{
    display: inline-flex; align-items: center; justify-content: center; gap: 7px;
    padding: 10px 20px; border-radius: var(--radius-sm); border: 1px solid transparent;
    font-size: 13px; font-weight: 600; cursor: pointer; font-family: var(--sans);
    min-height: 40px; transition: transform 0.12s, opacity 0.15s, background 0.15s, border-color 0.15s;
  }.mrk .btn:hover:not(:disabled){ transform: translateY(-1px); }.mrk .btn:active:not(:disabled){ transform: translateY(0); }.mrk .btn-primary{ background: var(--accent); color: var(--on-accent); }.mrk .btn-primary:hover:not(:disabled){ background: #1668e0; }.mrk .btn-secondary{
    background: rgba(148, 163, 184, 0.08); border-color: var(--glass-border); color: var(--subtle);
  }.mrk .btn-secondary:hover:not(:disabled){ background: rgba(148, 163, 184, 0.16); }.mrk .btn-sm{ padding: 7px 14px; font-size: 12px; min-height: 36px; }.mrk .btn:disabled{ opacity: 0.45; cursor: not-allowed; }.mrk .btn-row{ display: flex; gap: 10px; margin-top: 4px; }.mrk .error{
    margin-top: var(--space-3); padding: 11px 14px; border-radius: var(--radius-sm);
    background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3);
    color: var(--danger-text); font-size: 12px;
    display: flex; gap: 8px; align-items: flex-start;
  }.mrk .hint{ margin-top: var(--space-4); font-size: 12px; color: var(--muted); line-height: 1.6; }.mrk .summary-grid{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: var(--space-2); margin-bottom: var(--space-4);
  }.mrk .summary-card{ padding: var(--space-3) var(--space-2); text-align: center; }.mrk .summary-card .num{
    font-family: var(--mono); font-size: 30px; font-weight: 700;
    font-variant-numeric: tabular-nums; line-height: 1.1;
  }.mrk .summary-card .lbl{
    font-size: 11px; color: var(--muted); margin-top: 4px;
    display: flex; align-items: center; justify-content: center; gap: 5px;
    text-transform: uppercase; letter-spacing: 0.4px;
  }.mrk .summary-card .lbl svg{ width: 13px; height: 13px; }.mrk .toolbar{
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: var(--space-2); margin-bottom: var(--space-3); font-size: 12px;
  }.mrk .toolbar-left{ color: var(--muted); display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }.mrk .toolbar-right{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }.mrk .stale-chip{
    display: none; align-items: center; gap: 5px; padding: 3px 9px; border-radius: 999px;
    background: rgba(234, 179, 8, 0.14); border: 1px solid rgba(234, 179, 8, 0.35);
    color: var(--warn-text); font-size: 11px; font-weight: 600;
  }.mrk .stale-chip svg{ width: 12px; height: 12px; }.mrk .auto-label{
    display: inline-flex; align-items: center; gap: 6px; color: var(--subtle);
    cursor: pointer; font-size: 12px; user-select: none;
  }.mrk .auto-label input{ accent-color: var(--accent); width: 15px; height: 15px; cursor: pointer; }.mrk .device-grid{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: var(--space-3);
  }.mrk .device-card{ padding: var(--space-4); }.mrk .device-top{
    display: flex; align-items: flex-start; justify-content: space-between; gap: 12px;
  }.mrk .device-name{
    font-weight: 600; font-size: 15px; line-height: 1.3;
    display: flex; align-items: center; gap: 8px;
  }.mrk .device-sub{ font-size: 12px; color: var(--muted); margin-top: 3px; font-family: var(--mono); }.mrk .device-meta{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(90px, 1fr));
    gap: 10px 16px; font-size: 12px; color: var(--subtle); margin-top: var(--space-3);
  }.mrk .device-meta .k{ color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 0.4px; }.mrk .device-meta .v{ font-family: var(--mono); margin-top: 1px; }.mrk .status-badge{
    display: inline-flex; align-items: center; gap: 5px; padding: 4px 10px; border-radius: 7px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.4px; white-space: nowrap; flex-shrink: 0;
  }.mrk .status-badge svg{ width: 13px; height: 13px; }.mrk .status-dot-svg{ width: 14px; height: 14px; flex-shrink: 0; }.mrk .speed-results{
    margin-top: var(--space-3); padding-top: var(--space-3);
    border-top: 1px solid var(--glass-border);
    display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3);
  }.mrk .speed-slot{ margin-top: var(--space-3); min-height: 0; }.mrk .speed-bar-wrap{ min-width: 0; }.mrk .speed-label{ display: flex; justify-content: space-between; font-size: 11px; color: var(--muted); margin-bottom: 4px; }.mrk .speed-label .val{ font-family: var(--mono); font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }.mrk .speed-track{ height: 7px; background: var(--track); border-radius: 4px; overflow: hidden; }.mrk .speed-fill{ height: 100%; border-radius: 4px; transition: width 0.6s ease; }.mrk .speed-meta{ font-size: 11px; color: var(--muted); margin-top: 4px; grid-column: 1 / -1; }.mrk .async-note{
    margin-top: var(--space-3); padding-top: var(--space-3);
    border-top: 1px solid var(--glass-border); font-size: 12px; color: var(--muted);
    display: flex; align-items: center; gap: 8px;
  }.mrk .async-note.warn{ color: var(--warn-text); }.mrk .test-btns{ display: flex; gap: 6px; margin-top: var(--space-3); }.mrk .org-list{ margin-top: 10px; display: flex; flex-direction: column; gap: 6px; }.mrk .org-item{
    width: 100%; text-align: left; padding: 12px 14px; border: 1px solid var(--glass-border);
    border-radius: var(--radius-sm); background: rgba(148, 163, 184, 0.05); cursor: pointer;
    display: flex; justify-content: space-between; align-items: center; gap: 12px;
    color: var(--text); font-family: var(--sans); transition: border-color 0.15s, background 0.15s;
  }.mrk .org-item:hover{ border-color: var(--accent); background: var(--brand-soft); }.mrk .org-name{ font-weight: 600; font-size: 14px; }.mrk .org-id{ font-size: 12px; color: var(--muted); font-family: var(--mono); }.mrk .section-head{
    display: flex; align-items: center; justify-content: space-between;
    margin: var(--space-5) 0 var(--space-3); gap: 12px; flex-wrap: wrap;
  }.mrk .section-head h2{ font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px; }.mrk .section-head h2 svg{ width: 16px; height: 16px; color: var(--muted); }.mrk .uplink-grid{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: var(--space-3); }.mrk .uplink-card{ padding: var(--space-4); }.mrk .uplink-head{ display: flex; justify-content: space-between; align-items: baseline; gap: 10px; }.mrk .uplink-title{ font-weight: 600; font-size: 14px; }.mrk .uplink-tag{
    font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--muted); background: rgba(148, 163, 184, 0.1); padding: 2px 7px; border-radius: 5px;
  }.mrk .uplink-stats{ display: flex; gap: 20px; margin: var(--space-3) 0 var(--space-2); }.mrk .uplink-stat .n{ font-family: var(--mono); font-size: 20px; font-weight: 700; font-variant-numeric: tabular-nums; }.mrk .uplink-stat .u{ font-size: 11px; color: var(--muted); }.mrk .spark{ width: 100%; height: 44px; display: block; }.mrk .spark-caption{ font-size: 11px; color: var(--muted); margin-top: 4px; }.mrk details.data-table{ margin-top: 10px; font-size: 12px; }.mrk details.data-table summary{ cursor: pointer; color: var(--info); font-size: 12px; }.mrk details.data-table table{ width: 100%; border-collapse: collapse; margin-top: 8px; font-family: var(--mono); font-size: 11px; }.mrk details.data-table th, .mrk details.data-table td{ text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--glass-border); color: var(--subtle); }.mrk details.data-table th{ color: var(--muted); font-weight: 600; }.mrk .empty-state{ padding: var(--space-6) var(--space-4); text-align: center; }.mrk .empty-state svg{ width: 40px; height: 40px; color: var(--muted); margin-bottom: 12px; }.mrk .empty-state h3{ font-size: 15px; margin-bottom: 6px; }.mrk .empty-state p{ font-size: 13px; color: var(--muted); max-width: 400px; margin: 0 auto var(--space-3); }.mrk .skeleton{ padding: var(--space-4); }.mrk .sk-line{ height: 12px; border-radius: 6px; background: linear-gradient(90deg, var(--track), rgba(148,163,184,0.28), var(--track)); background-size: 200% 100%; animation: shimmer 1.4s infinite; }.mrk .sk-line + .sk-line{ margin-top: 10px; }
  @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }.mrk .footer{
    margin-top: var(--space-5); padding: var(--space-4);
    font-size: 12px; color: var(--muted); line-height: 1.8;
  }.mrk .footer strong{ color: var(--subtle); }.mrk .footer code{ font-family: var(--mono); font-size: 11px; color: var(--subtle); }.mrk .spinner{
    display: inline-block; width: 14px; height: 14px;
    border: 2px solid var(--track); border-top-color: var(--accent);
    border-radius: 50%; animation: spin 0.8s linear infinite; vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  
  @media (max-width: 640px) {.mrk{ padding: var(--space-4) var(--space-3); }.mrk .device-grid, .mrk .uplink-grid{ grid-template-columns: 1fr; }.mrk .btn, .mrk .btn-sm{ min-height: 44px; }.mrk .health-pill{ width: 100%; justify-content: center; }
  }

  
  @media (prefers-reduced-motion: reduce) {.mrk *, .mrk *::before, .mrk *::after{
      animation-duration: 0.001ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.001ms !important;
    }.mrk .health-pill .beacon{ animation: none; }.mrk .sk-line{ animation: none; background: var(--track); }
  }

.mrk .status-badge::before{content:none;}
.mrk .uplink-inline{margin-top:var(--space-3);padding-top:var(--space-3);border-top:1px solid var(--glass-border);}
.mrk .uplink-embed + .uplink-embed{margin-top:var(--space-3);padding-top:var(--space-3);border-top:1px solid var(--glass-border);}
.mrk .uplink-inline .uplink-head{display:flex;align-items:center;gap:8px;margin-bottom:var(--space-2);}
.mrk .uplink-ip{font-family:var(--mono);font-size:10px;color:var(--muted);}
{% endraw %}

/* ── Terminal Boot overlay ─────────────────────── */
.boot-overlay{position:fixed;inset:0;z-index:9999;background:#0a0e17;
    display:flex;flex-direction:column;align-items:center;justify-content:center;
    opacity:1;transition:opacity .8s ease;font-family:'Courier New',monospace;}
.boot-overlay.hide{opacity:0;pointer-events:none;}
.boot-terminal{width:min(500px,90vw);padding:24px;box-sizing:border-box;}
.boot-line{font-size:13px;color:#10b981;white-space:nowrap;overflow:hidden;
    display:block;margin:5px 0;width:0;opacity:0;}
.boot-line.show{width:100%;opacity:1;transition:width .01s,opacity .01s;}
.boot-prompt{color:#3b82f6;}
.boot-ok{color:#10b981;}
.boot-cursor{display:inline-block;width:8px;height:14px;background:#10b981;
    vertical-align:middle;margin-left:3px;animation:bootBlink .7s step-end infinite;}
@keyframes bootBlink{0%,100%{opacity:1}50%{opacity:0}}
</style>
<style>
@media (prefers-reduced-motion:reduce){
    .boot-overlay,.boot-overlay *{transition:revert!important;animation:revert!important;}
    .boot-cursor{animation:bootBlink .7s step-end infinite!important;}
}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Lexend:wght@300;400;500;600;700&family=Source+Sans+3:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script>const t=localStorage.getItem('theme')||'dark';if(t==='light')document.documentElement.setAttribute('data-theme','light');</script>
</head><body>

<!-- Terminal Boot -->
<div class="boot-overlay" id="bootOverlay">
    <div class="boot-terminal" id="bootTerminal">
        <span class="boot-line" id="bl0"><span class="boot-prompt">$</span> initializing pescoe-uptime v2.1...</span>
        <span class="boot-line" id="bl1"><span class="boot-ok">[✓]</span> database connected</span>
        <span class="boot-line" id="bl2"><span class="boot-ok">[✓]</span> loading practice configurations</span>
        <span class="boot-line" id="bl3"><span class="boot-ok">[✓]</span> 27 practices synchronized</span>
        <span class="boot-line" id="bl4"><span class="boot-ok">[✓]</span> meraki api authenticated</span>
        <span class="boot-line" id="bl5"><span class="boot-ok">[✓]</span> heartbeat monitor active</span>
        <span class="boot-line" id="bl6"><span class="boot-ok">[✓]</span> email notifications ready</span>
        <span class="boot-line" id="bl7"><span class="boot-prompt">$</span> launching dashboard...<span class="boot-cursor"></span></span>
    </div>
</div>
<script>
(function(){
    var lines=document.querySelectorAll('.boot-line');
    var delays=[300,600,400,500,400,350,400,500];
    var t=200;
    for(var i=0;i<lines.length;i++){
        (function(el,d){setTimeout(function(){el.classList.add('show');},d);})(lines[i],t);
        t+=delays[i]||400;
    }
    setTimeout(function(){
        var ov=document.getElementById('bootOverlay');
        ov.classList.add('hide');
        ov.addEventListener('transitionend',function(){ov.style.display='none';});
    },t+800);
})();
</script>

<div class="container">
    <div id="srStatus" role="status" aria-live="polite" aria-atomic="true" class="sr-only"></div>
    <header>
        <h1><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg><span>PESCOE Systems Dashboard</span></h1>
        <div class="header-actions">
            <div class="refresh-indicator" id="refreshInd"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg><span id="refreshLabel">Live · updating…</span></div>
            <button class="theme-btn notif-btn" id="notifToggler" onclick="toggleNotifs()"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg><span id="notifLabel">Notifications</span></button>
            <button class="theme-btn" id="themeToggler" onclick="toggleTheme()"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 2a10 10 0 0 0 0 20z" fill="currentColor" stroke="none"/></svg><span id="themeLabel">Light Theme</span></button>
            <a href="/logout" class="logout-btn"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg><span>Logout</span></a>
        </div>
    </header>

    <div class="section-title"><span>Global Infrastructure Status</span></div>
    <div class="metrics-grid">
        <div class="card"><div class="card-title">Total Monitored Nodes</div><div class="card-value" id="s_total_nodes" style="color:var(--accent-blue)">–</div></div>
        <div class="card"><div class="card-title">Total Systems Online</div><div class="card-value" id="s_total_online" style="color:var(--online-color)">–</div></div>
        <div class="card"><div class="card-title">Total Active Outages</div><div class="card-value" id="s_total_offline" style="color:var(--offline-color)">–</div></div>
    </div>

    <div class="section-title collapse-head" id="clientToggle" role="button" tabindex="0"
         aria-expanded="false" aria-controls="clientCollapsible" onclick="toggleSection('client')"
         onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleSection('client');}">
        <span><svg class="ico chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>Client Summary</span>
        <span class="section-total-badge">Workstations: <span id="s_total_workstations">–</span> · Servers: <span id="s_total_servers">–</span></span></div>
    <div id="clientCollapsible">
    <div class="metrics-grid compact">
        <div class="card" style="border-left:4px solid var(--accent-blue)"><div class="card-title" style="font-weight:bold">PDA Group</div>
            <div class="card-value" style="font-size:16px"><span id="s_pda_total">–</span> <span style="font-size:12px;color:var(--text-muted)">Nodes</span></div>
            <div class="card-split-values"><span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_pda_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_pda_offline">–</span> Outages</span></div>
            <div class="card-fw"><span class="fw-caption"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Firewalls</span>
                <span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_fw_pda_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_fw_pda_offline">–</span> Offline</span></div>
            <div class="card-fw"><span class="fw-caption"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><line x1="6" y1="6.5" x2="6.01" y2="6.5"/><line x1="6" y1="17.5" x2="6.01" y2="17.5"/></svg>Servers</span>
                <span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_srv_pda_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_srv_pda_offline">–</span> Outages</span></div></div>
        <div class="card" style="border-left:4px solid var(--accent-purple)"><div class="card-title" style="font-weight:bold">ADMI Group</div>
            <div class="card-value" style="font-size:16px"><span id="s_admi_total">–</span> <span style="font-size:12px;color:var(--text-muted)">Nodes</span></div>
            <div class="card-split-values"><span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_admi_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_admi_offline">–</span> Outages</span></div>
            <div class="card-fw"><span class="fw-caption"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Firewalls</span>
                <span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_fw_admi_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_fw_admi_offline">–</span> Offline</span></div>
            <div class="card-fw"><span class="fw-caption"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><line x1="6" y1="6.5" x2="6.01" y2="6.5"/><line x1="6" y1="17.5" x2="6.01" y2="17.5"/></svg>Servers</span>
                <span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_srv_admi_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_srv_admi_offline">–</span> Outages</span></div></div>
        <div class="card" id="unknownCard" style="border-left:4px solid var(--accent-orange);display:none"><div class="card-title" style="color:var(--accent-orange);font-weight:bold"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> UNKNOWN Group</div>
            <div class="card-value" style="font-size:16px"><span id="s_unknown_total">–</span> <span style="font-size:12px;color:var(--text-muted)">Nodes</span></div>
            <div class="card-split-values"><span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_unknown_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_unknown_offline">–</span> Outages</span></div>
            <div class="card-fw"><span class="fw-caption"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Firewalls</span>
                <span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_fw_unknown_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_fw_unknown_offline">–</span> Offline</span></div>
            <div class="card-fw"><span class="fw-caption"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><line x1="6" y1="6.5" x2="6.01" y2="6.5"/><line x1="6" y1="17.5" x2="6.01" y2="17.5"/></svg>Servers</span>
                <span class="split-stat" style="color:var(--online-color)"><span class="mini-dot on"></span> <span id="s_srv_unknown_online">–</span> Online</span>
                <span class="split-stat" style="color:var(--offline-color)"><span class="mini-dot off"></span> <span id="s_srv_unknown_offline">–</span> Outages</span></div></div>
    </div>
    </div>

    <div class="section-title systems-head" id="systemsToggle" role="button" tabindex="0"
         aria-expanded="false" aria-controls="systemsCollapsible" onclick="toggleSystems()"
         onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleSystems();}">
        <span><svg class="ico chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>System Nodes<span class="section-total-badge" id="systemsCount" style="margin-left:10px">–</span></span>
        <span id="systemsHint" style="font-size:12px;font-weight:600;text-transform:none;color:var(--text-muted)">Show</span>
    </div>
    <div id="systemsCollapsible" hidden>
    <div class="controls-wrapper">
        <div class="search-container"><span class="search-icon"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
            <input type="text" id="nodeSearchInput" class="search-input" aria-label="Search systems by name, practice, IP, or group"
                   placeholder="Search name / practice / IP / group…" oninput="render()"></div>
        <div class="filter-buttons-group">
            <button id="btnFilterAll" class="filter-pill active-pill" onclick="setFilter('all')">Show All</button>
            <button id="btnFilterWorkstations" class="filter-pill" onclick="setFilter('workstations')">Workstations Only</button>
            <button id="btnFilterServers" class="filter-pill" onclick="setFilter('servers')">Servers Only</button>
            <button id="btnFilterVmServers" class="filter-pill" onclick="setFilter('vm_servers')">VM Servers</button>
            <button id="btnFilterOutages" class="filter-pill" style="border-color:rgba(239,68,68,.4)" onclick="setFilter('outages')"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Active Outages</button>
        </div>
    </div>

    <div class="table-container">
        <table id="systemsTable">
            <thead><tr>
                <th data-key="business_group">Business Group <span class="arrow"></span></th>
                <th data-key="practice_name">Practice Name <span class="arrow"></span></th>
                <th data-key="system_name">System Name <span class="arrow"></span></th>
                <th data-key="ip_address">Public IP <span class="arrow"></span></th>
                <th data-key="status">Network Status <span class="arrow"></span></th>
                <th data-key="last_seen">Last Keep-Alive (IST) <span class="arrow"></span></th>
                <th data-key="uptime_24h">Uptime 24h / 7d <span class="arrow"></span></th>
                <th data-key="duration_str">Active Outage <span class="arrow"></span></th>
                <th>Actions</th>
            </tr></thead>
            <tbody id="tableBody"></tbody>
        </table>
    </div>
    </div>
{% raw %}
    <div class="section-title collapse-head" id="merakiToggle" role="button" tabindex="0"
         aria-expanded="true" aria-controls="merakiCollapsible" onclick="toggleSection('meraki')"
         onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleSection('meraki');}">
        <span><svg class="ico chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>Network · Meraki MX</span>
        <span id="merakiHint" style="font-size:12px;font-weight:600;text-transform:none;color:var(--text-muted)">Hide</span></div>
    <div id="merakiCollapsible">
    <section class="mrk" id="net-root">
<div class="container" id="app">
  <div class="header">
    <div class="logo"><img src="__LOGO_SRC__" alt="Piccadilly Dental Alliance"></div>
    <div>
      <h1>Meraki MX Dashboard</h1>
      <div class="subtitle">Piccadilly Dental Alliance · appliance status, speed tests &amp; uplink health</div>
    </div>
    <div class="header-spacer"></div>
    <div id="health-pill" class="health-pill" style="display:none" role="status" aria-live="polite">
      <span class="beacon" aria-hidden="true"></span>
      <span id="health-text">All systems normal</span>
    </div>
  </div>

  <!-- Password Gate (only shown when DASHBOARD_PASSWORD is set) -->
  <div id="gate-screen" class="gate-wrap" style="display:none">
    <div class="glass login-card gate-card">
      <div class="gate-logo"><div class="logo"><img src="__LOGO_SRC__" alt="Piccadilly Dental Alliance"></div></div>
      <div class="eyebrow">Restricted access</div>
      <h2>Enter dashboard password</h2>
      <label for="gate-pass" class="sr-only">Dashboard password</label>
      <input type="password" id="gate-pass" placeholder="Password" autocomplete="current-password" onkeydown="if(event.key==='Enter'){event.preventDefault();submitGate();}">
      <div class="btn-row"><button class="btn btn-primary" id="gate-btn" onclick="submitGate()" style="width:100%">Unlock</button></div>
      <div id="gate-error" class="error" style="display:none" role="alert"></div>
    </div>
  </div>

  <!-- Login Screen (split hero + connect card) -->
  <div id="login-screen" class="login-wrap" style="display:none">
    <section class="hero" aria-labelledby="hero-title">
      <div class="hero-logo"><img src="__LOGO_SRC__" alt="Piccadilly Dental Alliance"></div>
      <div class="hero-copy">
        <h2 id="hero-title">Network operations for every practice.</h2>
        <p>Monitor every Meraki MX appliance across the Alliance from one place — status, speed, and uplink health at a glance.</p>
        <ul class="hero-points">
          <li><span class="tick"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg></span>Live online / offline status for every site</li>
          <li><span class="tick"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg></span>On-demand device-to-cloud speed tests</li>
          <li><span class="tick"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg></span>Uplink loss &amp; latency trends</li>
          <li><span class="tick"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg></span>Runs locally — your key never leaves this machine</li>
        </ul>
      </div>
      <div class="hero-foot">Powered by the Cisco Meraki Dashboard API</div>
    </section>

    <div class="login-panel">
      <div class="glass login-card">
        <div class="eyebrow">Secure connection</div>
        <h2>Connect to your dashboard</h2>
        <label for="api-key">Meraki API key</label>
        <input type="password" id="api-key" placeholder="Paste your Meraki API key" autocomplete="off" onkeydown="if(event.key==='Enter'){event.preventDefault();handleConnect();}">
        <label class="remember" for="remember-key">
          <input type="checkbox" id="remember-key">
          Remember this key on this computer (.env)
        </label>
        <div id="org-section" style="display:none">
          <label id="org-label">Select your organization to continue</label>
          <div id="org-list" class="org-list" role="group" aria-labelledby="org-label"></div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="connect-btn" onclick="handleConnect()">Connect</button>
        </div>
        <div id="login-error" class="error" style="display:none" role="alert"></div>
        <div class="hint">
          Your API key is sent only to this local server, which proxies requests to api.meraki.com.
          Held in memory for the session unless you choose to remember it in a local <code>.env</code> file.
        </div>
      </div>
    </div>
  </div>

  <!-- Dashboard -->
  <div id="dashboard-screen" style="display:none">
    <div class="summary-grid" id="summary-grid"></div>

    <div class="toolbar">
      <div class="toolbar-left">
        <span id="last-refresh" role="status" aria-live="polite"></span>
        <span id="stale-chip" class="stale-chip">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/><path d="M12 7v5l3 2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          Data may be stale
        </span>
      </div>
      <div class="toolbar-right">
        <label class="auto-label">
          <input type="checkbox" id="auto-refresh-toggle" onchange="toggleAutoRefresh(this.checked)">
          Auto-refresh (5m)
        </label>
        <button class="btn btn-secondary btn-sm" onclick="refreshDevices()">Refresh</button>
        <button class="btn btn-secondary btn-sm" onclick="doDisconnect()">Disconnect</button>
      </div>
    </div>

    <div id="device-list" class="device-grid" aria-busy="false"></div>

    <div class="glass footer">
      <strong>API endpoints used</strong><br>
      <code>GET /organizations/{orgId}/devices/statuses?productTypes[]=appliance</code> — device status<br>
      <code>POST /devices/{serial}/liveTools/throughputTest</code> — device-to-cloud speed test<br>
      <code>GET /organizations/{orgId}/devices/uplinks/lossAndLatency</code> — uplink health
    </div>
  </div>
</div>
    </section>
    </div>
{% endraw %}</div>

<script>
const CSRF = "{{ csrf_token }}";
const EMBED = {{ 'true' if embed else 'false' }};   // rendered inside the "Both" split view
let DATA = [];
let filter = sessionStorage.getItem('activeQuickFilter') || 'all';
let sortKey = sessionStorage.getItem('sortKey') || 'business_group';
let sortDir = sessionStorage.getItem('sortDir') || 'asc';

function setFilter(f){ filter=f; sessionStorage.setItem('activeQuickFilter',f);
    ['all','workstations','servers','vm_servers','outages'].forEach(k=>{
        const id='btnFilter'+k.split('_').map(w=>w.charAt(0).toUpperCase()+w.slice(1)).join('');
        const b=document.getElementById(id);
        if(b) b.classList.toggle('active-pill', k===f);
    }); render(); }

function esc(s){ const d=document.createElement('div'); d.textContent=s==null?'':s; return d.innerHTML; }

function upClass(v){ return v>=99.5?'var(--online-color)':v>=95?'var(--accent-orange)':'var(--offline-color)'; }

function render(){
    const q=(document.getElementById('nodeSearchInput').value||'').trim().toLowerCase();
    sessionStorage.setItem('activeSearchQuery', document.getElementById('nodeSearchInput').value);

    let rows = DATA.filter(m=>{
        const hay = (m.system_name+' '+m.practice_name+' '+m.ip_address+' '+m.business_group).toLowerCase();
        if(q && !hay.includes(q)) return false;
        if(filter==='workstations') return !m.is_server && !m.system_name.toUpperCase().includes('VM-SVR');
        if(filter==='servers') return m.is_server;
        if(filter==='vm_servers') return m.system_name.toUpperCase().includes('VM-SVR');
        if(filter==='outages') return m.status==='Offline';
        return true;
    });

    rows.sort((a,b)=>{
        let x=a[sortKey], y=b[sortKey];
        if(typeof x==='string'){ x=x.toLowerCase(); y=(y||'').toLowerCase(); }
        if(x<y) return sortDir==='asc'?-1:1;
        if(x>y) return sortDir==='asc'?1:-1;
        return 0;
    });

    const body=document.getElementById('tableBody');
    if(rows.length===0){ body.innerHTML='<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:40px">No matching system nodes found.</td></tr>'; }
    else {
        body.innerHTML = rows.map(m=>`<tr>
            <td class="business-group" data-label="Group">${esc(m.business_group)}</td>
            <td class="practice-name" data-label="Practice">${esc(m.practice_name)}</td>
            <td class="system-name" data-label="System">${esc(m.system_name)}${m.is_server?'<span class="server-tag">Server</span>':''}</td>
            <td class="ip-text" data-label="Public IP">${esc(m.ip_address)}</td>
            <td data-label="Status"><span class="status-badge ${m.status==='Online'?'online':'offline'}">${esc(m.status)}</span></td>
            <td class="time-text" data-label="Last Keep-Alive">${esc(m.last_seen)}</td>
            <td class="uptime-text" data-label="Uptime 24h / 7d"><span style="color:${upClass(m.uptime_24h)}">${m.uptime_24h}%</span> / <span style="color:${upClass(m.uptime_7d)}">${m.uptime_7d}%</span></td>
            <td class="time-text" data-label="Active Outage">${m.status==='Offline'&&m.duration_str!=='--'?'<span class="downtime-active">'+esc(m.duration_str)+'</span>':'<span style="color:var(--text-muted)">--</span>'}</td>
            <td data-label="Actions"><button class="retire-btn" onclick="retire('${esc(m.system_name).replace(/'/g,"")}')">Retire</button></td>
        </tr>`).join('');
    }

    document.querySelectorAll('th[data-key]').forEach(th=>{
        const a=th.querySelector('.arrow');
        a.textContent = th.dataset.key===sortKey ? (sortDir==='asc'?'▲':'▼') : '';
    });
}

function applySummary(s){
    for(const k in s){ const el=document.getElementById('s_'+k); if(el) el.textContent=s[k]; }
    document.getElementById('unknownCard').style.display = (s.unknown_total>0 || s.fw_unknown_total>0) ? '' : 'none';
    const sc=document.getElementById('systemsCount');
    if(sc) sc.textContent = (s.total_nodes||0)+' nodes';
}

// Collapse/expand the System Nodes grid so the Meraki section can sit up top.
// Collapsed by default; the choice is remembered per browser.
function setSystemsCollapsed(collapsed){
    const c=document.getElementById('systemsCollapsible');
    const h=document.getElementById('systemsToggle');
    const hint=document.getElementById('systemsHint');
    if(!c||!h) return;
    c.hidden=collapsed;
    h.setAttribute('aria-expanded', String(!collapsed));
    if(hint) hint.textContent = collapsed ? 'Show' : 'Hide';
}
function toggleSystems(){
    const collapsed = !document.getElementById('systemsCollapsible').hidden; // visible -> collapse
    setSystemsCollapsed(collapsed);
    try{ localStorage.setItem('systemsCollapsed', collapsed?'1':'0'); }catch(e){}
}

// Generic collapse for the Client/Server summary sections. The total badge in
// the header stays visible while collapsed, so the at-a-glance count is kept.
function setSection(name, collapsed){
    const c=document.getElementById(name+'Collapsible');
    const h=document.getElementById(name+'Toggle');
    if(!c||!h) return;
    c.hidden=collapsed;
    h.setAttribute('aria-expanded', String(!collapsed));
    const hint=document.getElementById(name+'Hint');
    if(hint) hint.textContent = collapsed ? 'Show' : 'Hide';
}
function toggleSection(name){
    const collapsed = !document.getElementById(name+'Collapsible').hidden; // visible -> collapse
    setSection(name, collapsed);
    try{ localStorage.setItem('collapse_'+name, collapsed?'1':'0'); }catch(e){}
}
function initSection(name, defCollapsed){
    let v=null; try{ v=localStorage.getItem('collapse_'+name); }catch(e){}
    setSection(name, v===null ? defCollapsed : v==='1');
}

async function refresh(){
    try{
        const r = await fetch('/api/status', {headers:{'Accept':'application/json'}});
        if(r.status===401){ location.href='/login'; return; }
        const j = await r.json();
        DATA = j.machines;
        diffAndNotify(DATA);
        applySummary(j.summary); render();
        document.getElementById('refreshLabel').textContent =
            'Live · updated '+new Date().toLocaleTimeString()+' · IST';
    }catch(e){ document.getElementById('refreshLabel').textContent='Update failed — retrying…'; }
}

async function retire(name){
    if(!confirm('Retire "'+name+'" from monitoring? This removes its history.')) return;
    await fetch('/api/nodes/'+encodeURIComponent(name), {method:'DELETE', headers:{'X-CSRF-Token':CSRF}});
    refresh();
}

function applySort(k){
    if(sortKey===k){ sortDir = sortDir==='asc'?'desc':'asc'; } else { sortKey=k; sortDir='asc'; }
    sessionStorage.setItem('sortKey',sortKey); sessionStorage.setItem('sortDir',sortDir);
    render();
}
document.querySelectorAll('th[data-key]').forEach(th=>{
    th.setAttribute('tabindex','0');
    th.setAttribute('role','button');
    th.addEventListener('click', ()=>applySort(th.dataset.key));
    th.addEventListener('keydown', e=>{
        if(e.key==='Enter' || e.key===' '){ e.preventDefault(); applySort(th.dataset.key); }
    });
});

function toggleTheme(){
    const cur=document.documentElement.getAttribute('data-theme')||'dark';
    const nt = cur==='dark'?'light':'dark';
    if(nt==='light') document.documentElement.setAttribute('data-theme','light');
    else document.documentElement.removeAttribute('data-theme');
    localStorage.setItem('theme',nt);
    document.getElementById('themeLabel').textContent = nt==='light'?'Dark Theme':'Light Theme';
}

// --- Notifications: Web Push (mobile/background) + in-tab fallback ---------
// Web Push is delivered by the server and arrives even when the app/tab is
// closed — that's what makes it useful on a phone. If push isn't available
// (older browser, server push disabled), we fall back to the in-tab
// Notification popups, which only fire while this tab is open. Either way it
// needs a secure context (HTTPS, or localhost).
let notifsOn = localStorage.getItem('notifsOn') === '1';
let prevStatus = null;          // system_name -> 'Online'|'Offline' from last poll
let swReg = null;               // ServiceWorkerRegistration once ready
let vapidKey = null;            // server applicationServerKey (base64url), '' if disabled
let pushActive = false;         // true once a live push subscription is registered

function pushSupported(){
    return 'serviceWorker' in navigator && 'PushManager' in window
        && 'Notification' in window && window.isSecureContext;
}
function inTabSupported(){ return 'Notification' in window && window.isSecureContext; }
function notifSupported(){ return pushSupported() || inTabSupported(); }

function urlB64ToUint8Array(base64String){
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const b64 = (base64String + padding).replace(/-/g,'+').replace(/_/g,'/');
    const raw = atob(b64); const arr = new Uint8Array(raw.length);
    for(let i=0;i<raw.length;i++) arr[i] = raw.charCodeAt(i);
    return arr;
}

async function registerSW(){
    if(!('serviceWorker' in navigator)) return;
    try{ swReg = await navigator.serviceWorker.register('/sw.js'); }
    catch(e){ console.warn('Service worker registration failed', e); }
}

async function loadVapidKey(){
    if(vapidKey !== null) return vapidKey;
    try{
        const r = await fetch('/api/push/vapid-public-key');
        const j = await r.json();
        vapidKey = j.enabled ? j.key : '';
    }catch(e){ vapidKey = ''; }
    return vapidKey;
}

async function subscribePush(){
    if(!pushSupported() || !swReg) return false;
    const key = await loadVapidKey();
    if(!key) return false;                 // server push disabled -> caller falls back
    let sub = await swReg.pushManager.getSubscription();
    if(!sub){
        sub = await swReg.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlB64ToUint8Array(key)
        });
    }
    const r = await fetch('/api/push/subscribe', {
        method:'POST',
        headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
        body: JSON.stringify(sub)
    });
    pushActive = r.ok;
    return r.ok;
}

async function unsubscribePush(){
    try{
        if(swReg){
            const sub = await swReg.pushManager.getSubscription();
            if(sub){
                await fetch('/api/push/unsubscribe', {
                    method:'POST',
                    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
                    body: JSON.stringify({endpoint: sub.endpoint})
                });
                await sub.unsubscribe();
            }
        }
    }catch(e){ console.warn('Unsubscribe failed', e); }
    pushActive = false;
}

function isIOS(){
    return /iP(hone|ad|od)/.test(navigator.platform)
        || (navigator.userAgent.includes('Mac') && 'ontouchend' in document);  // iPadOS
}
function isStandalone(){
    return window.matchMedia('(display-mode: standalone)').matches
        || window.navigator.standalone === true;
}

function setNotifLabel(text){ document.getElementById('notifLabel').textContent = text; }

function updateNotifBtn(){
    const b = document.getElementById('notifToggler');
    b.disabled = true;
    if(!window.isSecureContext){
        b.className='theme-btn notif-btn notif-blocked';
        setNotifLabel('Needs HTTPS'); return;
    }
    // Secure origin, but the Notification API isn't exposed. On iOS this is the
    // normal state in a Safari tab — alerts require installing to the Home
    // Screen and opening from that icon (iOS 16.4+).
    if(!('Notification' in window)){
        b.className='theme-btn notif-btn notif-blocked';
        setNotifLabel((isIOS() && !isStandalone()) ? 'Add to Home Screen' : 'Unsupported');
        return;
    }
    if(Notification.permission==='denied'){
        b.className='theme-btn notif-btn notif-blocked';
        setNotifLabel('Blocked'); return;
    }
    b.disabled = false;
    b.className='theme-btn notif-btn'+(notifsOn?'':' notif-off');
    setNotifLabel(notifsOn ? 'Alerts On' : 'Alerts Off');
}

async function toggleNotifs(){
    if(!notifSupported()) return;
    if(!notifsOn){
        // Browsers require a user gesture for this prompt — hence the button.
        const p = await Notification.requestPermission();
        if(p!=='granted'){ updateNotifBtn(); return; }
        notifsOn = true;
        localStorage.setItem('notifsOn','1');
        updateNotifBtn();
        if(pushSupported()) await subscribePush();     // best-effort; in-tab still covers it
    } else {
        notifsOn = false;
        localStorage.setItem('notifsOn','0');
        await unsubscribePush();
        updateNotifBtn();
    }
}

function notify(title, body, tag){
    if(EMBED) return;   // the standalone tab owns notifications; avoid duplicates
    if(!notifsOn || !notifSupported() || Notification.permission!=='granted') return;
    try{
        // tag + renotify: a flapping node replaces its own popup instead of stacking.
        const n = new Notification(title, {body, tag, renotify:true});
        n.onclick = ()=>{ window.focus(); n.close(); };
    }catch(e){ console.warn('notify failed', e); }
}

function diffAndNotify(rows){
    // First poll after load: seed the baseline silently, so pre-existing
    // outages don't fire popups for things you already knew about.
    if(prevStatus === null){
        prevStatus = {};
        rows.forEach(m=>{ prevStatus[m.system_name]=m.status; });
        return;
    }
    const next = {};
    const down = [], up = [];
    rows.forEach(m=>{
        next[m.system_name]=m.status;
        const was = prevStatus[m.system_name];
        if(was === undefined) return;                 // brand-new node, not a transition
        if(was==='Online' && m.status==='Offline') down.push(m);
        if(was==='Offline' && m.status==='Online') up.push(m);
    });
    prevStatus = next;

    // Announce transitions to screen readers as one atomic status message
    // (fires whether or not push/popups are on; stays silent when nothing moved).
    if(down.length || up.length){
        const parts = [];
        if(down.length) parts.push(down.length + (down.length===1?' system went offline':' systems went offline'));
        if(up.length)   parts.push(up.length + (up.length===1?' system recovered':' systems recovered'));
        const sr = document.getElementById('srStatus');
        if(sr) sr.textContent = parts.join(', ');
    }

    // When server-side Web Push is active it already delivers these (even in the
    // background), so don't also fire in-tab popups for the same transitions.
    if(pushActive) return;

    // Batch when several flip at once, so a site-wide drop isn't 12 popups.
    if(down.length===1){
        const m=down[0];
        notify(`🚨 OFFLINE — ${m.practice_name} / ${m.system_name}`,
               `${m.business_group} · ${m.is_server?'SERVER':'WORKSTATION'} · ${m.ip_address}`,
               'out-'+m.system_name);
    } else if(down.length>1){
        notify(`🚨 ${down.length} nodes went OFFLINE`,
               down.map(m=>m.practice_name+'/'+m.system_name).join(', '), 'out-batch');
    }

    if(up.length===1){
        const m=up[0];
        notify(`✅ RESOLVED — ${m.practice_name} / ${m.system_name}`,
               `Back online · down for ${m.duration_str!=='--'?m.duration_str:'unknown'}`,
               'res-'+m.system_name);
    } else if(up.length>1){
        notify(`✅ ${up.length} nodes back ONLINE`,
               up.map(m=>m.practice_name+'/'+m.system_name).join(', '), 'res-batch');
    }
}

(async function init(){
    document.getElementById('themeLabel').textContent =
        (localStorage.getItem('theme')||'dark')==='light'?'Dark Theme':'Light Theme';
    updateNotifBtn();
    // Skip service-worker / push registration in the embedded split view so it
    // doesn't compete with the standalone tab for the SW controller.
    if(!EMBED){
        await registerSW();
        // If alerts were previously enabled, refresh the push subscription so a
        // rotated endpoint keeps working after reinstall/restart.
        if(notifsOn && pushSupported() && Notification.permission==='granted'){
            try{ await subscribePush(); }catch(e){ console.warn(e); }
        }
    }
    const sq=sessionStorage.getItem('activeSearchQuery'); if(sq) document.getElementById('nodeSearchInput').value=sq;
    let _sysCol=null; try{ _sysCol=localStorage.getItem('systemsCollapsed'); }catch(e){}
    setSystemsCollapsed(_sysCol===null ? true : _sysCol==='1');   // default collapsed
    initSection('client', true);   // Summary defaults collapsed; the total
                                   // badges stay visible in the header
    initSection('meraki', false);  // Meraki section defaults expanded
    setFilter(filter);
    refresh();
    setInterval(refresh, 30000);   // live poll every 30s
})();
</script>
<script>
{% raw %}
let devices = [];
let speedResults = {};
let pollTimers = {};
let uplinkOpen = {};      // serial -> bool: is the uplink-health panel expanded on that card
let uplinkData = null;    // cached org-wide uplink loss/latency (fetched on first check)

/* ── SVG icon set (no emoji; color is never the only signal) ── */
const ICON = {
  online:   '<svg class="status-dot-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="currentColor" opacity="0.18"/><path d="M8 12.5l2.5 2.5L16 9" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  alerting: '<svg class="status-dot-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 4l9 15.5H3L12 4z" fill="currentColor" opacity="0.18"/><path d="M12 5.5L20 19H4L12 5.5z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 10v4M12 16.5v.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  offline:  '<svg class="status-dot-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="currentColor" opacity="0.18"/><path d="M9 9l6 6M15 9l-6 6" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>',
  dormant:  '<svg class="status-dot-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="currentColor" opacity="0.14"/><path d="M15.5 14a5 5 0 01-6-6 5.2 5.2 0 106 6z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>'
};
const STATUS = {
  online:   { label: 'ONLINE',   color: 'var(--green)'  },
  alerting: { label: 'ALERTING', color: 'var(--yellow)' },
  offline:  { label: 'OFFLINE',  color: 'var(--red)'    },
  dormant:  { label: 'DORMANT',  color: 'var(--gray)'   }
};



function showError(msg) {
  const el = document.getElementById('login-error');
  el.innerHTML = '<svg viewBox="0 0 24 24" fill="none" width="15" height="15" aria-hidden="true" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/><path d="M12 8v4M12 16v.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg><span>' + esc(msg) + '</span>';
  el.style.display = 'flex';
}
function hideError() { document.getElementById('login-error').style.display = 'none'; }

// On load: show the password gate if required, otherwise pick login/dashboard.
async function bootstrap() {
  try {
    const s = await (await fetch('/meraki/api/status')).json();
    if (s.gate_required && !s.authed) { showGate(); return; }
    if (s.connected) { showDashboard(); loadDevices(); return; }
    if (s.has_saved_key) {
      showLogin();
      const btn = document.getElementById('connect-btn');
      btn.disabled = true; btn.textContent = 'Connecting…';
      const data = await postConnect({ use_saved: true });
      if (data.error) { showError(data.error); resetConnectBtn(); return; }
      if (data.needs_org) { renderOrgPicker(data.organizations, null, true); resetConnectBtn(); return; }
      await afterConnect(null, '');
      return;
    }
    showLogin();
  } catch (e) {
    showLogin();
  }
}

function postConnect(body) {
  return fetch('/meraki/api/connect', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  }).then(r => r.json());
}

async function handleConnect() {
  hideError();
  const apiKey = document.getElementById('api-key').value.trim();
  if (!apiKey) { showError('Enter your API key.'); return; }

  const btn = document.getElementById('connect-btn');
  btn.disabled = true; btn.textContent = 'Connecting…';

  try {
    const data = await postConnect({ api_key: apiKey });
    if (data.error) { showError(data.error); resetConnectBtn(); return; }
    if (data.needs_org) { renderOrgPicker(data.organizations, apiKey, false); resetConnectBtn(); return; }
    await afterConnect(apiKey, '');
  } catch (e) {
    showError('Connection failed: ' + e.message);
  }
  resetConnectBtn();
}

function renderOrgPicker(orgs, apiKey, useSaved) {
  const section = document.getElementById('org-section');
  section.style.display = 'block';
  const list = document.getElementById('org-list');
  list.innerHTML = '';
  orgs.forEach(org => {
    const b = document.createElement('button');
    b.className = 'org-item'; b.type = 'button';
    b.innerHTML = '<span class="org-name">' + esc(org.name) + '</span><span class="org-id">ID ' + esc(org.id) + '</span>';
    b.onclick = () => connectWithOrg(apiKey, org.id, useSaved);
    list.appendChild(b);
  });
  section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  const first = list.querySelector('.org-item');
  if (first) first.focus();
}

function resetConnectBtn() {
  const btn = document.getElementById('connect-btn');
  btn.disabled = false; btn.textContent = 'Connect';
}

async function connectWithOrg(apiKey, orgId, useSaved) {
  hideError();
  const btn = document.getElementById('connect-btn');
  btn.disabled = true; btn.textContent = 'Connecting…';
  try {
    const body = useSaved ? { use_saved: true, org_id: orgId } : { api_key: apiKey, org_id: orgId };
    const data = await postConnect(body);
    if (data.error) { showError(data.error); resetConnectBtn(); return; }
    await afterConnect(useSaved ? null : apiKey, orgId);
  } catch (e) {
    showError('Failed: ' + e.message);
  }
  resetConnectBtn();
}

// Persist the key to .env when the user ticked "Remember", then open the dashboard.
async function afterConnect(apiKey, orgId) {
  const remember = document.getElementById('remember-key');
  if (apiKey && remember && remember.checked) {
    try {
      const r = await fetch('/meraki/api/save-key', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ api_key: apiKey, org_id: orgId || '' })
      });
      const d = await r.json();
      if (!d.saved) showToast(d.error || 'Could not save the key.');
    } catch (e) { showToast('Could not save the key: ' + e.message); }
  }
  showDashboard();
  loadDevices();
}

function showGate() {
  document.getElementById('gate-screen').style.display = 'flex';
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('dashboard-screen').style.display = 'none';
  const p = document.getElementById('gate-pass');
  if (p) { p.value = ''; p.focus(); }
}

async function submitGate() {
  const err = document.getElementById('gate-error');
  err.style.display = 'none';
  const pass = document.getElementById('gate-pass').value;
  const btn = document.getElementById('gate-btn');
  btn.disabled = true; btn.textContent = 'Unlocking…';
  try {
    const res = await fetch('/meraki/api/gate', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ password: pass })
    });
    const data = await res.json();
    if (!data.ok) {
      err.textContent = data.error || 'Incorrect password'; err.style.display = 'block';
      btn.disabled = false; btn.textContent = 'Unlock';
      return;
    }
    btn.disabled = false; btn.textContent = 'Unlock';
    bootstrap();  // gate passed — continue to login/dashboard
  } catch (e) {
    err.textContent = 'Could not verify: ' + e.message; err.style.display = 'block';
    btn.disabled = false; btn.textContent = 'Unlock';
  }
}

function showLogin() {
  document.getElementById('gate-screen').style.display = 'none';
  document.getElementById('login-screen').style.display = '';
  document.getElementById('dashboard-screen').style.display = 'none';
}

function showDashboard() {
  document.getElementById('gate-screen').style.display = 'none';
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('dashboard-screen').style.display = 'block';
}

async function doDisconnect() {
  await fetch('/meraki/api/disconnect', { method: 'POST' });
  devices = []; speedResults = {};
  Object.values(pollTimers).forEach(clearInterval);
  pollTimers = {};
  uplinkOpen = {}; uplinkData = null;
  showLogin();
  document.getElementById('org-section').style.display = 'none';
  document.getElementById('health-pill').style.display = 'none';
  document.getElementById('auto-refresh-toggle').checked = false;
  document.getElementById('api-key').value = '';
}

function showSkeletons() {
  const list = document.getElementById('device-list');
  list.setAttribute('aria-busy', 'true');
  list.innerHTML = Array.from({ length: 4 }).map(() =>
    '<div class="glass skeleton"><div class="sk-line" style="width:55%"></div><div class="sk-line" style="width:35%"></div><div class="sk-line" style="width:80%;margin-top:20px"></div></div>'
  ).join('');
}

async function loadDevices() {
  if (!devices.length) showSkeletons();
  const res = await fetch('/meraki/api/devices');
  const data = await res.json();
  devices = data.devices || [];
  speedResults = data.speed_results || {};
  renderSummary();
  renderDevices();
  updateRefreshLabel(data.last_refresh);
  document.getElementById('device-list').setAttribute('aria-busy', 'false');
  // If any card's uplink panel is open, refresh the cached uplink data too.
  if (Object.values(uplinkOpen).some(Boolean)) { await loadCardUplink(); renderDevices(); }
  // Nudge the Uptime summary so the per-group firewall counts pick up the
  // latest Meraki status without waiting for the next 30s poll.
  if (typeof refresh === 'function') { try { refresh(); } catch (e) {} }
}

async function refreshDevices() {
  await fetch('/meraki/api/refresh', { method: 'POST' });
  loadDevices();
}

async function toggleAutoRefresh(enabled) {
  await fetch('/meraki/api/auto-refresh', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ enabled })
  });
}

function updateRefreshLabel(ts) {
  const el = document.getElementById('last-refresh');
  const stale = document.getElementById('stale-chip');
  if (!ts) { el.textContent = 'Not yet refreshed'; stale.style.display = 'none'; return; }
  const d = new Date(ts);
  el.textContent = 'Last refreshed ' + d.toLocaleTimeString();
  const ageMin = (Date.now() - d.getTime()) / 60000;
  stale.style.display = ageMin > 6 ? 'inline-flex' : 'none';
}

function renderSummary() {
  const counts = { total: devices.length, online: 0, alerting: 0, offline: 0, dormant: 0 };
  devices.forEach(d => { if (counts[d.status] !== undefined) counts[d.status]++; });
  const meta = {
    total:    { color: 'var(--text)',  icon: '' },
    online:   { color: 'var(--green)', icon: ICON.online },
    alerting: { color: 'var(--yellow)',icon: ICON.alerting },
    offline:  { color: 'var(--red)',   icon: ICON.offline },
    dormant:  { color: 'var(--gray)',  icon: ICON.dormant }
  };
  document.getElementById('summary-grid').innerHTML = Object.entries(counts).map(([k, v]) => {
    const m = meta[k];
    const label = k.charAt(0).toUpperCase() + k.slice(1);
    const iconWrap = m.icon ? '<span style="color:' + m.color + '">' + m.icon + '</span>' : '';
    return '<div class="glass summary-card"><div class="num" style="color:' + m.color + '">' + v + '</div>'
      + '<div class="lbl">' + iconWrap + label + '</div></div>';
  }).join('');
  renderHealth(counts);
}

function renderHealth(counts) {
  const pill = document.getElementById('health-pill');
  const txt = document.getElementById('health-text');
  pill.style.display = 'inline-flex';
  pill.classList.remove('warn', 'crit');
  if (counts.offline > 0) {
    pill.classList.add('crit');
    txt.textContent = counts.offline + ' appliance' + (counts.offline > 1 ? 's' : '') + ' offline';
  } else if (counts.alerting > 0) {
    pill.classList.add('warn');
    txt.textContent = counts.alerting + ' appliance' + (counts.alerting > 1 ? 's' : '') + ' alerting';
  } else if (counts.total > 0) {
    txt.textContent = 'All ' + counts.online + ' appliances online';
  } else {
    txt.textContent = 'No appliances';
  }
}

function timeAgo(ts) {
  if (!ts) return 'Never';
  const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return s + 's ago';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ago';
  const h = Math.floor(m / 60);
  if (h < 24) return h + 'h ' + (m % 60) + 'm ago';
  return Math.floor(h / 24) + 'd ago';
}

function renderDevices() {
  const list = document.getElementById('device-list');
  list.className = 'device-grid';

  if (!devices.length) {
    list.innerHTML =
      '<div class="glass empty-state" style="grid-column:1/-1">'
      + '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3" y="8" width="18" height="8" rx="2" stroke="currentColor" stroke-width="2"/><path d="M7 12h.01M11 12h6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'
      + '<h3>No MX appliances found</h3>'
      + '<p>This organization has no appliance-type devices, or the API key lacks access to them. Try refreshing, or confirm the org in the Meraki dashboard.</p>'
      + '<button class="btn btn-primary btn-sm" onclick="refreshDevices()">Refresh</button>'
      + '</div>';
    return;
  }

  list.innerHTML = devices.map(d => {
    const sr = speedResults[d.serial];
    const st = STATUS[d.status] || { label: (d.status || 'UNKNOWN').toUpperCase(), color: 'var(--gray)' };
    const icon = ICON[d.status] || '';
    const canTest = d.status === 'online' || d.status === 'alerting';
    const isRunning = sr && sr.status === 'running';

    let speedHtml = '';
    if (sr && sr.status === 'complete') {
      const maxSpd = 1000;
      const dl = Number(sr.download) || 0;
      const ul = Number(sr.upload) || 0;
      // The MX live tool measures device-to-cloud throughput (download).
      // Only show an upload bar when the result actually carries one.
      const hasUpload = ul > 0;
      speedHtml =
        '<div class="speed-results"' + (hasUpload ? '' : ' style="grid-template-columns:1fr"') + '>'
        + '<div class="speed-bar-wrap">'
          + '<div class="speed-label"><span>Download</span><span class="val">' + dl.toFixed(1) + ' Mbps</span></div>'
          + '<div class="speed-track"><div class="speed-fill" style="width:' + Math.min(dl / maxSpd * 100, 100) + '%;background:var(--info)"></div></div>'
        + '</div>'
        + (hasUpload
          ? '<div class="speed-bar-wrap">'
            + '<div class="speed-label"><span>Upload</span><span class="val">' + ul.toFixed(1) + ' Mbps</span></div>'
            + '<div class="speed-track"><div class="speed-fill" style="width:' + Math.min(ul / maxSpd * 100, 100) + '%;background:var(--purple)"></div></div>'
          + '</div>'
          : '')
        + '<div class="speed-meta">'
          + (sr.latency != null ? 'Latency <strong>' + Number(sr.latency).toFixed(0) + ' ms</strong> · ' : '')
          + 'Device-to-cloud throughput · ' + timeAgo(sr.timestamp)
        + '</div></div>';
    } else if (sr && sr.status === 'running') {
      speedHtml = '<div class="async-note"><span class="spinner" aria-hidden="true"></span> Test running — polling for results…</div>';
    } else if (sr && sr.status === 'timeout') {
      speedHtml = '<div class="async-note warn">Test timed out. Try again.</div>';
    }

    return ''
      + '<div class="glass device-card">'
        + '<div class="device-top">'
          + '<div style="min-width:0">'
            + '<div class="device-name"><span style="color:' + st.color + ';display:inline-flex">' + icon + '</span>' + esc(d.name || d.serial) + '</div>'
            + '<div class="device-sub">' + esc(d.model || '—') + ' · ' + esc(d.serial) + '</div>'
          + '</div>'
          + '<div class="status-badge" style="color:' + st.color + ';background:color-mix(in srgb,' + st.color + ' 16%, transparent)">' + st.label + '</div>'
        + '</div>'
        + '<div class="device-meta">'
          + '<div><div class="k">LAN IP</div><div class="v">' + esc(d.lanIp || '—') + '</div></div>'
          + '<div><div class="k">WAN IP</div><div class="v">' + esc(d.publicIp || '—') + '</div></div>'
          + '<div><div class="k">Last seen</div><div class="v">' + timeAgo(d.lastReportedAt) + '</div></div>'
        + '</div>'
        + '<div class="test-btns">'
          + '<button class="btn btn-primary btn-sm" onclick="startSpeedTest(\'' + esc(d.serial) + '\')" ' + (!canTest || isRunning ? 'disabled' : '') + '>'
            + (isRunning ? '<span class="spinner" aria-hidden="true"></span> Testing…' : 'Run speed test') + '</button>'
          + '<button class="btn btn-secondary btn-sm" onclick="toggleCardUplink(\'' + esc(d.serial) + '\')" aria-pressed="' + (uplinkOpen[d.serial] ? 'true' : 'false') + '">'
            + (uplinkOpen[d.serial] ? 'Hide uplink' : 'Uplink health') + '</button>'
        + '</div>'
        + speedHtml
        + (uplinkOpen[d.serial] ? '<div class="uplink-inline">' + renderCardUplinkHtml(d.serial) + '</div>' : '')
      + '</div>';
  }).join('');
}

/* ── Speed / throughput tests ── */
function pollUntilDone(serial) {
  pollTimers[serial] = setInterval(async () => {
    const r = await fetch('/meraki/api/speed-test/' + encodeURIComponent(serial));
    const result = await r.json();
    if (result.status === 'complete' || result.status === 'timeout') {
      clearInterval(pollTimers[serial]);
      speedResults[serial] = result;
      renderDevices();
    }
  }, 4000);
}

// The MX "speed test" is Meraki's device-to-cloud throughput live tool —
// there is no separate liveTools/speedTest endpoint in the Dashboard API.
async function startSpeedTest(serial) {
  const res = await fetch('/meraki/api/throughput-test', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ serial })
  });
  const data = await res.json();
  if (data.error) { showToast(data.error); return; }
  speedResults[serial] = { status: 'running' };
  renderDevices();
  pollUntilDone(serial);
}

/* Lightweight non-blocking toast (replaces alert) */
function showToast(msg) {
  let t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    t.setAttribute('role', 'alert');
    t.style.cssText = 'position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:50;'
      + 'background:var(--card-solid);border:1px solid rgba(239,68,68,0.4);color:var(--danger-text);'
      + 'padding:12px 18px;border-radius:12px;font-size:13px;box-shadow:var(--shadow);max-width:90vw';
    (document.getElementById('net-root') || document.body).appendChild(t);
  }
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => { t.style.display = 'none'; }, 4200);
}

/* ── Uplink health (inline, per device card) ── */
async function toggleCardUplink(serial) {
  const open = !uplinkOpen[serial];
  uplinkOpen[serial] = open;
  renderDevices();                       // reflect button + show a loader in the slot
  if (open && uplinkData === null) {
    await loadCardUplink();
    renderDevices();                     // fill the panel(s) once data arrives
  }
}

// Fetch the org-wide uplink loss/latency once and cache it; each card filters it
// to its own serial. Cached so opening several cards doesn't re-hit the API.
async function loadCardUplink() {
  try {
    const res = await fetch('/meraki/api/uplinks');
    const data = await res.json();
    uplinkData = data.error ? [] : (data.uplinks || []);
  } catch (e) {
    uplinkData = [];
  }
}

/* Hand-drawn SVG line (no chart library); color reflects threshold,
   but exact values are always shown as text + in the data table. */
function sparkline(series, key, opts) {
  const pts = series.map(p => p[key]).filter(v => v != null && !isNaN(v));
  if (pts.length < 2) return '<div class="spark-caption">Not enough samples to chart.</div>';
  const W = 260, H = 44, pad = 3;
  const max = Math.max(opts.min, ...pts), min = Math.min(0, ...pts);
  const span = (max - min) || 1;
  const step = (W - pad * 2) / (pts.length - 1);
  const coords = pts.map((v, i) => {
    const x = pad + i * step;
    const y = H - pad - ((v - min) / span) * (H - pad * 2);
    return x.toFixed(1) + ',' + y.toFixed(1);
  });
  const last = pts[pts.length - 1];
  const color = last >= opts.crit ? 'var(--red)' : last >= opts.warn ? 'var(--yellow)' : 'var(--green)';
  const area = 'M' + pad + ',' + (H - pad) + ' L' + coords.join(' L') + ' L' + (pad + (pts.length - 1) * step).toFixed(1) + ',' + (H - pad);
  return '<svg class="spark" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="' + esc(opts.aria) + '">'
    + '<path d="' + area + '" fill="' + color + '" opacity="0.14"/>'
    + '<polyline points="' + coords.join(' ') + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
    + '</svg>';
}

// Build the inline uplink-health panel shown inside a single device card.
function renderCardUplinkHtml(serial) {
  if (uplinkData === null) {
    return '<div class="async-note"><span class="spinner" aria-hidden="true"></span> Checking uplink health…</div>';
  }
  const rows = uplinkData.filter(r => r.serial === serial);
  if (!rows.length) {
    return '<div class="async-note warn">No uplink loss/latency samples in the last 5 minutes.</div>';
  }

  return rows.map(r => {
    const series = Array.isArray(r.timeSeries) ? r.timeSeries : [];
    const latVals = series.map(p => p.latencyMs).filter(v => v != null);
    const lossVals = series.map(p => p.lossPercent).filter(v => v != null);
    const lastLat = latVals.length ? latVals[latVals.length - 1] : null;
    const lastLoss = lossVals.length ? lossVals[lossVals.length - 1] : null;
    const avgLat = latVals.length ? (latVals.reduce((a, b) => a + b, 0) / latVals.length) : null;

    const latColor = lastLat == null ? 'var(--muted)' : lastLat >= 150 ? 'var(--red)' : lastLat >= 60 ? 'var(--yellow)' : 'var(--green)';
    const lossColor = lastLoss == null ? 'var(--muted)' : lastLoss >= 5 ? 'var(--red)' : lastLoss >= 1 ? 'var(--yellow)' : 'var(--green)';

    const chart = sparkline(series, 'latencyMs', {
      min: 20, warn: 60, crit: 150,
      aria: 'Latency trend, currently ' + (lastLat != null ? lastLat.toFixed(0) + ' milliseconds' : 'no data')
    });

    const tableRows = series.slice(-12).map(p =>
      '<tr><td>' + (p.ts ? new Date(p.ts).toLocaleTimeString() : '—') + '</td>'
      + '<td>' + (p.latencyMs != null ? p.latencyMs.toFixed(1) + ' ms' : '—') + '</td>'
      + '<td>' + (p.lossPercent != null ? p.lossPercent.toFixed(1) + ' %' : '—') + '</td></tr>'
    ).join('');

    return '<div class="uplink-embed">'
      + '<div class="uplink-head"><span class="uplink-tag">' + esc(r.uplink || 'WAN') + '</span>'
        + (r.ip ? '<span class="uplink-ip">' + esc(r.ip) + '</span>' : '') + '</div>'
      + '<div class="uplink-stats">'
        + '<div class="uplink-stat"><div class="n" style="color:' + latColor + '">' + (lastLat != null ? lastLat.toFixed(0) : '—') + '</div><div class="u">Latency (ms)' + (avgLat != null ? ' · avg ' + avgLat.toFixed(0) : '') + '</div></div>'
        + '<div class="uplink-stat"><div class="n" style="color:' + lossColor + '">' + (lastLoss != null ? lastLoss.toFixed(1) : '—') + '</div><div class="u">Loss (%)</div></div>'
      + '</div>'
      + chart
      + '<div class="spark-caption">Loss &amp; latency · last 5 min</div>'
      + (series.length ? '<details class="data-table"><summary>View samples</summary>'
          + '<table><thead><tr><th>Time</th><th>Latency</th><th>Loss</th></tr></thead><tbody>' + tableRows + '</tbody></table></details>' : '')
      + '</div>';
  }).join('');
}

/* Decide what to show as soon as the page is ready. */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootstrap);
} else {
  bootstrap();
}
{% endraw %}
</script>
</body></html>
"""

# Embed the PDA logo (or hide the <img> tags if no logo file is present).
for _tpl_name in ("DASHBOARD_TEMPLATE", "LOGIN_TEMPLATE"):
    _tpl = globals()[_tpl_name]
    if LOGO_DATA_URI:
        globals()[_tpl_name] = _tpl.replace("__LOGO_SRC__", LOGO_DATA_URI)
    else:
        _tpl = _tpl.replace('<img src="__LOGO_SRC__"', '<img alt="" hidden src="#"')
        globals()[_tpl_name] = _tpl.replace('href="__LOGO_SRC__"', 'href="#" visibility="hidden"')

# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if not csrf_ok(request.form.get('csrf_token')):
            abort(400)
        user_ok = request.form.get('username') == CONFIG["DASHBOARD_USER"]
        pass_ok = CONFIG["DASHBOARD_PASSWORD"] and secrets.compare_digest(
            request.form.get('password', ''), CONFIG["DASHBOARD_PASSWORD"])
        if user_ok and pass_ok:
            now = now_ist()
            otp_code = generate_otp()
            csrf = session.get("csrf_token")     # preserve CSRF token across the clear
            session.clear()
            if csrf:
                session["csrf_token"] = csrf
            session['otp_hash'] = hash_otp(otp_code)
            session['otp_expiry'] = (now + timedelta(seconds=OTP_EXPIRY_SECONDS)).isoformat()
            session['otp_pending'] = True
            session['otp_attempts'] = 0
            session['otp_last_sent'] = now.timestamp()
            if send_otp_email(otp_code, now):
                return redirect(url_for('verify_otp'))
            session.clear()
            error = "Could not send the verification code. Please contact IT support."
        else:
            error = "Invalid username or password credentials."
    return render_template_string(LOGIN_TEMPLATE, error=error, csrf_token=get_csrf_token())


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if not session.get('otp_pending'):
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        if not csrf_ok(request.form.get('csrf_token')):
            abort(400)
        now = now_ist()

        if request.form.get('resend') == '1':
            last = session.get('otp_last_sent', 0)
            if now.timestamp() - last < OTP_RESEND_COOLDOWN:
                wait = int(OTP_RESEND_COOLDOWN - (now.timestamp() - last))
                error = f"Please wait {wait}s before requesting a new code."
            else:
                otp_code = generate_otp()
                session['otp_hash'] = hash_otp(otp_code)
                session['otp_expiry'] = (now + timedelta(seconds=OTP_EXPIRY_SECONDS)).isoformat()
                session['otp_attempts'] = 0
                session['otp_last_sent'] = now.timestamp()
                error = ("A new verification code has been sent." if send_otp_email(otp_code, now)
                         else "Could not send a new code. Please try again shortly.")
        else:
            entered = (request.form.get('otp_code') or '').strip()
            expiry = datetime.fromisoformat(session['otp_expiry'])
            session['otp_attempts'] = session.get('otp_attempts', 0) + 1

            if session['otp_attempts'] > MAX_OTP_ATTEMPTS:
                session.clear()
                return redirect(url_for('login'))
            if now > expiry:
                error = "Verification code expired. Please request a new one."
            elif secrets.compare_digest(hash_otp(entered), session.get('otp_hash', '')):
                csrf = session.get("csrf_token")
                session.clear()
                if csrf:
                    session["csrf_token"] = csrf
                session['logged_in'] = True
                return redirect(url_for('dashboard'))
            else:
                error = "Incorrect verification code."
    return render_template_string(OTP_TEMPLATE, error=error, csrf_token=get_csrf_token())


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route('/')
@login_required
def dashboard():
    return render_template_string(
        DASHBOARD_TEMPLATE, csrf_token=get_csrf_token(), embed=False)


@app.route('/api/status')
@login_required
def api_status():
    machine_list, stats = build_snapshot()
    return jsonify({"machines": machine_list, "summary": stats})


@app.route('/api/nodes/<path:name>', methods=['DELETE'])
@login_required
def api_delete_node(name):
    if not csrf_ok(request.headers.get('X-CSRF-Token')):
        abort(400)
    with state_lock:
        machines.pop(name, None)
        db_delete_node(name)
    return jsonify({"status": "success", "removed": name})


@app.route('/api/digest/test', methods=['POST'])
@login_required
def api_digest_test():
    """Manually fire a digest or the EOD report (handy for verifying SMTP/format)."""
    if not csrf_ok(request.headers.get('X-CSRF-Token')):
        abort(400)
    kind = (request.args.get('kind') or 'digest').lower()
    if kind == 'eod':
        send_eod_report()
    else:
        send_outage_digest()
    return jsonify({"status": "success", "sent": kind})


# ---------------------------------------------------------------------------
# PWA: manifest, service worker, icons
# ---------------------------------------------------------------------------

SERVICE_WORKER_JS = r"""
// PESCOE Uptime service worker — handles background Web Push + install.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
    let data = { title: 'PESCOE Uptime', body: '', tag: 'pescoe', url: '/' };
    try {
        if (event.data) data = Object.assign(data, event.data.json());
    } catch (e) {
        if (event.data) data.body = event.data.text();
    }
    event.waitUntil(self.registration.showNotification(data.title, {
        body: data.body,
        tag: data.tag,
        renotify: true,
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        data: { url: data.url || '/' }
    }));
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const target = (event.notification.data && event.notification.data.url) || '/';
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
            for (const c of list) {
                if ('focus' in c) { c.navigate(target); return c.focus(); }
            }
            if (self.clients.openWindow) return self.clients.openWindow(target);
        })
    );
});
"""


@app.route('/sw.js')
def service_worker():
    resp = Response(SERVICE_WORKER_JS, mimetype='application/javascript')
    resp.headers['Cache-Control'] = 'no-cache'          # always pick up SW updates
    resp.headers['Service-Worker-Allowed'] = '/'
    return resp


@app.route('/manifest.webmanifest')
def web_manifest():
    manifest = {
        "name": "PESCOE Systems Uptime Dashboard",
        "short_name": "PESCOE Uptime",
        "description": "Live uptime monitoring for PESCOE systems.",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "background_color": "#0f172a",
        "theme_color": "#0f172a",
        "orientation": "any",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png",
             "purpose": "any maskable"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
             "purpose": "any maskable"},
        ],
    }
    return Response(json.dumps(manifest), mimetype='application/manifest+json')


@app.route('/icon-<int:size>.png')
def pwa_icon(size):
    if size not in (192, 512):
        abort(404)
    resp = Response(get_icon_png(size), mimetype='image/png')
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


@app.route('/apple-touch-icon.png')
@app.route('/apple-touch-icon-precomposed.png')
def apple_touch_icon():
    resp = Response(get_icon_png(192), mimetype='image/png')
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


# ---------------------------------------------------------------------------
# PUSH SUBSCRIPTION API
# ---------------------------------------------------------------------------

@app.route('/api/push/vapid-public-key')
@login_required
def api_vapid_public_key():
    return jsonify({"enabled": push_enabled(), "key": VAPID["public_key"]})


@app.route('/api/push/subscribe', methods=['POST'])
@login_required
def api_push_subscribe():
    if not csrf_ok(request.headers.get('X-CSRF-Token')):
        abort(400)
    if not push_enabled():
        return jsonify({"status": "error", "message": "Push not configured"}), 503
    sub = request.get_json(silent=True) or {}
    if not sub.get("endpoint"):
        return jsonify({"status": "error", "message": "Invalid subscription"}), 400
    db_add_subscription(sub)
    return jsonify({"status": "success"})


@app.route('/api/push/unsubscribe', methods=['POST'])
@login_required
def api_push_unsubscribe():
    if not csrf_ok(request.headers.get('X-CSRF-Token')):
        abort(400)
    data = request.get_json(silent=True) or {}
    endpoint = data.get("endpoint")
    if endpoint:
        db_remove_subscription(endpoint)
    return jsonify({"status": "success"})


@app.route('/api/push/test', methods=['POST'])
@login_required
def api_push_test():
    if not csrf_ok(request.headers.get('X-CSRF-Token')):
        abort(400)
    if not push_enabled():
        return jsonify({"status": "error", "message": "Push not configured"}), 503
    push_queue.put({
        "title": "🔔 PESCOE Uptime",
        "body": "Test notification — mobile push is working.",
        "tag": "test", "url": "/",
    })
    return jsonify({"status": "success"})


def heartbeat_authorized(ip):
    """
    Accept a heartbeat if EITHER a valid token is supplied OR it comes from a
    known IP. This keeps already-deployed (tokenless) agents working while
    letting newer agents authenticate with a token from anywhere.
    """
    if CONFIG["ALLOW_ANONYMOUS_HEARTBEAT"]:
        return True
    token = request.headers.get('X-Agent-Token', '')
    if CONFIG["AGENT_TOKEN"] and secrets.compare_digest(token, CONFIG["AGENT_TOKEN"]):
        return True
    return ip in HEARTBEAT_ALLOWED_IPS


@app.route('/heartbeat', methods=['POST'])
def receive_heartbeat():
    now = now_ist()
    ip = client_ip()

    # Authenticate the agent before trusting anything it says.
    if not heartbeat_authorized(ip):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json or {}
    system_name = data.get("system_name")
    is_server = bool(data.get("is_server", False))
    if not system_name:
        return jsonify({"status": "error", "message": "Missing system_name"}), 400

    with state_lock:
        if system_name not in machines:
            machines[system_name] = {
                "last_seen": now, "status": "Online", "alert_sent": False,
                "offline_since": None, "ip_address": ip, "is_server": is_server,
            }
            db_record_event(system_name, "Online", now)
        else:
            m = machines[system_name]
            m["ip_address"] = ip
            m["is_server"] = is_server
            if m["status"] == "Offline":
                downtime = fmt_duration((now - m["offline_since"]).total_seconds()) if m["offline_since"] else "unknown"
                queue_status_alert(system_name, "Online", now, downtime, ip_address=ip, is_server=is_server)
                practice, group, node_type = _node_label(system_name, ip, is_server)
                enqueue_push(
                    f"✅ RESOLVED — {practice} / {system_name}",
                    f"Back online · was down for {downtime}",
                    tag="res-" + system_name)
                db_record_event(system_name, "Online", now)
                m["alert_sent"] = False
                m["offline_since"] = None
            m["last_seen"] = now
            m["status"] = "Online"

        db_upsert_node(system_name, machines[system_name])

    return jsonify({"status": "success", "heartbeat_interval": DYNAMIC_HEARTBEAT_INTERVAL}), 200


# ---------------------------------------------------------------------------
# STARTUP
# ---------------------------------------------------------------------------

def start_background_workers():
    threading.Thread(target=email_worker, daemon=True).start()
    threading.Thread(target=push_worker, daemon=True).start()
    threading.Thread(target=background_status_checker, daemon=True).start()
    threading.Thread(target=digest_scheduler, daemon=True).start()


if __name__ == "__main__":
    init_db()
    load_state_from_db()
    ensure_vapid_keys()
    if push_enabled():
        # Warm the icon cache off the request path (first render takes a moment).
        threading.Thread(target=lambda: (get_icon_png(192), get_icon_png(512)),
                         daemon=True).start()
        print(f"[INFO] Web Push enabled. VAPID public key: {VAPID['public_key'][:16]}…")
    else:
        print("[INFO] Web Push disabled; dashboard will use in-tab notifications only.")
    start_background_workers()
    app.run(host="0.0.0.0", port=PORT, debug=False)