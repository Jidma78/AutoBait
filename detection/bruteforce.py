"""
Brute-force detector.

Raises an alert when a remote IP opens more than
BRUTEFORCE_THRESHOLD connections to the *same* destination port
within TIME_WINDOW.
"""

from __future__ import annotations
import time
from scapy.all import IP, TCP

from config import (
    MY_LOCAL_IP,
    TIME_WINDOW,
    BRUTEFORCE_THRESHOLD,
    ALERT_INTERVAL,
)
from core.logger import log_alert
from utils.netinfo import list_local_ips
from core.shared_state import bruters
from core.honeypot_launcher import start_honeypot  # 🔥 Just trigger the honeypot, no redirect.

# Set of local IPs
LOCAL_IPS: set[str] = {ip for _, ip in list_local_ips()}

# (ip_src, port_dst) -> incident state
_incidents: dict[tuple[str, int], dict] = {}

def analyze(pkt) -> None:
    """Scapy callback: inspect each TCP packet."""
    if IP not in pkt or TCP not in pkt:
        return

    ip_src, ip_dst = pkt[IP].src, pkt[IP].dst

    # Ignore local-originated or non-local-destination packets
    if ip_src in LOCAL_IPS or ip_dst not in LOCAL_IPS:
        return
    if MY_LOCAL_IP and ip_dst != MY_LOCAL_IP:
        return

    port_dst = int(pkt[TCP].dport)
    now = time.time()
    key = (ip_src, port_dst)

    rec = _incidents.setdefault(
        key,
        {
            "times": [],
            "incident": False,
            "total": 0,
            "start": 0.0,
            "last_alert": 0.0,
        },
    )

    rec["times"].append(now)
    # Keep only connections within the time window
    rec["times"] = [t for t in rec["times"] if now - t <= TIME_WINDOW]
    current_conn = len(rec["times"])

    if not rec["incident"] and current_conn > BRUTEFORCE_THRESHOLD:
        rec.update(incident=True, start=now, total=current_conn, last_alert=now)
        log_alert(
            f"[BRUTEFORCE] {ip_src} ➜ {ip_dst}:{port_dst} "
            f"{current_conn} connections (begin)"
        )
        bruters.add(ip_src)
        start_honeypot()  # ✅ Trigger honeypot activation
        return

    if rec["incident"]:
        rec["total"] += 1

        if now - rec["last_alert"] >= ALERT_INTERVAL:
            log_alert(
                f"[BRUTEFORCE] {ip_src} ➜ {ip_dst}:{port_dst} "
                f"{current_conn} connections (Δ {ALERT_INTERVAL}s)"
            )
            rec["last_alert"] = now

        if current_conn <= BRUTEFORCE_THRESHOLD:
            duration = int(now - rec["start"])
            log_alert(
                f"[BRUTEFORCE] END {ip_src} ➜ {ip_dst}:{port_dst} : "
                f"{rec['total']} total connections in {duration}s"
            )
            rec.update(incident=False, total=0)
