import asyncio
import threading
import subprocess
import socket

HONEYPOT_PORT = 2222
HONEYPOT_SCRIPT = "honeyssh.py"

honeypot_process = None

def is_port_open(port: int) -> bool:
    """Check if a TCP port is already bound locally."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        result = sock.connect_ex(('127.0.0.1', port))
        return result == 0  # 0 = connection OK, so port is open

def start_honeypot():
    global honeypot_process

    if is_port_open(HONEYPOT_PORT):
        print(f"[⚡] Honeypot already active on port {HONEYPOT_PORT}.")
        return

    print("[🔥] Launching SSH Honeypot...")

    def _launch():
        global honeypot_process
        try:
            honeypot_process = subprocess.Popen(["python3", HONEYPOT_SCRIPT])
            print("[✅] Honeypot successfully launched.")
        except Exception as e:
            print(f"[❌] Error while launching honeypot: {e}")

    threading.Thread(target=_launch, daemon=True).start()
