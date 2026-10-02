"""
Frozen entry point for the PDA Uptime Agent Windows Service.

PyInstaller bundles this into a standalone .exe. The exe is then packaged
into an MSI by WiX, which registers it as a Windows service that starts
on boot.

This is a thin wrapper around the real agent logic — it resolves paths
relative to the frozen exe so logging and config work correctly when
running as a service from C:\\Program Files\\PDAUptimeAgent\\.
"""

import os
import sys
import time
import socket
import logging
import platform
from pathlib import Path
from logging.handlers import RotatingFileHandler

import requests
import win32serviceutil
import win32service
import win32event
import servicemanager

# ---------------------------------------------------------------------------
# CONFIGURATION (all via environment variables for zero-touch deployment)
# ---------------------------------------------------------------------------

SERVER_URL = os.environ.get(
    "PDA_SERVER_URL", "https://uptimetracker.withbytecycle.com/heartbeat"
)
AGENT_TOKEN = os.environ.get("PDA_AGENT_TOKEN", "")
SYSTEM_NAME = os.environ.get("PDA_SYSTEM_NAME", platform.node())
IS_SERVER = os.environ.get("PDA_IS_SERVER", "0") == "1"
HEARTBEAT_INTERVAL = int(os.environ.get("PDA_HEARTBEAT_INTERVAL", "30"))
REQUEST_TIMEOUT = int(os.environ.get("PDA_REQUEST_TIMEOUT", "10"))

LOG_DIR = os.environ.get(
    "PDA_LOG_DIR",
    str(Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "PDAUptimeAgent"),
)


# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------

def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, "agent.log")

    logger = logging.getLogger("PDAAgent")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = RotatingFileHandler(
            log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(handler)

    return logger


# ---------------------------------------------------------------------------
# HEARTBEAT
# ---------------------------------------------------------------------------

def send_heartbeat(log):
    payload = {"system_name": SYSTEM_NAME, "is_server": IS_SERVER}
    headers = {}
    if AGENT_TOKEN:
        headers["X-Agent-Token"] = AGENT_TOKEN

    try:
        resp = requests.post(
            SERVER_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT
        )
        if resp.status_code == 200:
            data = resp.json()
            log.info(
                "Heartbeat OK from %s (interval=%ss)",
                SYSTEM_NAME,
                data.get("heartbeat_interval", "?"),
            )
            return True
        else:
            log.warning("Server rejected heartbeat: HTTP %s", resp.status_code)
            return False
    except requests.ConnectionError:
        log.warning("Could not connect to %s", SERVER_URL)
        return False
    except requests.Timeout:
        log.warning("Request timed out (%ss)", REQUEST_TIMEOUT)
        return False
    except Exception as e:
        log.error("Unexpected error: %s", e)
        return False


# ---------------------------------------------------------------------------
# WINDOWS SERVICE
# ---------------------------------------------------------------------------

class PDAUptimeAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PDAUptimeAgent"
    _svc_display_name_ = "PDA Uptime Monitoring Agent"
    _svc_description_ = (
        "Sends periodic heartbeats to the PESCOE Systems Uptime Dashboard "
        "so the IT team can monitor this machine's connectivity."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        self.log = setup_logging()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.stop_event)
        self.log.info("Service stop requested.")

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self.log.info(
            "Service started. system_name=%s server=%s interval=%ss is_server=%s",
            SYSTEM_NAME, SERVER_URL, HEARTBEAT_INTERVAL, IS_SERVER,
        )
        self.main_loop()

    def main_loop(self):
        consecutive_failures = 0
        while self.running:
            success = send_heartbeat(self.log)

            if success:
                consecutive_failures = 0
            else:
                consecutive_failures += 1

            if consecutive_failures > 3:
                wait = min(
                    HEARTBEAT_INTERVAL * (2 ** min(consecutive_failures - 3, 3)), 300
                )
            else:
                wait = HEARTBEAT_INTERVAL

            for _ in range(wait):
                if not self.running:
                    break
                rc = win32event.WaitForSingleObject(self.stop_event, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break

        self.log.info("Service stopped.")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(PDAUptimeAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(PDAUptimeAgentService)
