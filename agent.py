import time
import requests
import platform

# --- CLIENT CONFIGURATION ---
SERVER_IP = "182.156.143.144"  # 👈 CHANGE to your server's static IP address or URL
SERVER_PORT = 5000
HEARTBEAT_INTERVAL = 30      # Send pulse every 10 seconds
SYSTEM_NAME = platform.node()

URL = f"http://{SERVER_IP}:{SERVER_PORT}/heartbeat"

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