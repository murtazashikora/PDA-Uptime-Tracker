import time
import requests
import platform

# --- CLIENT CONFIGURATION ---
HEARTBEAT_URL = "https://uptimetracker.withbytecycle.com/heartbeat"
HEARTBEAT_INTERVAL = 30
SYSTEM_NAME = platform.node()

URL = HEARTBEAT_URL

def send_pulse():
    payload = {"system_name": SYSTEM_NAME}
    try:
        response = requests.post(URL, json=payload, timeout=4)
        if response.status_code == 200:
            print(f"Sent heartbeat successfully from: {SYSTEM_NAME}")
        else:
            print(f"Server rejected heartbeat: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Could not connect to monitoring server: {e}")

if __name__ == "__main__":
    print(f"Starting Client Uptime Pulse for '{SYSTEM_NAME}'...")
    print(f"Targeting Server: {URL}")
    while True:
        send_pulse()
        time.sleep(HEARTBEAT_INTERVAL)