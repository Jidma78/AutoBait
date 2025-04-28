"""
SYN-scan detector.

Raises an alert when a remote IP touches more than
PORT_SCAN_THRESHOLD *unique* destination ports on the local host
within the sliding TIME_WINDOW.
"""

from __future__ import annotations
import time
from scapy.all import IP, TCP

from config import (
    MY_LOCAL_IP,
    TIME_WINDOW,
    PORT_SCAN_THRESHOLD,
    ALERT_INTERVAL,
)
from core.logger import log_alert, log_error
from utils.netinfo import list_local_ips
from core.honeypot_launcher import start_honeypot  # 🔥 Just trigger the honeypot

# Set of local IPs
LOCAL_IPS: set[str] = {ip for _, ip in list_local_ips()}

# Incident state per remote IP
_incidents: dict[str, dict] = {}

def analyze(pkt) -> None:
    """Scapy callback: inspect each TCP packet."""
    try:
        if IP not in pkt or TCP not in pkt:
            return

        ip_src, ip_dst = pkt[IP].src, pkt[IP].dst

        # Ignore local-originated or non-local-destination packets
        if ip_src in LOCAL_IPS or ip_dst not in LOCAL_IPS:
            return
        if MY_LOCAL_IP and ip_dst != MY_LOCAL_IP:
            return

        flags = int(pkt[TCP].flags)
        # Only look for pure SYN packets (SYN set, ACK not set)
        if not (flags & 0x02) or (flags & 0x10):
            return

        port_dst = int(pkt[TCP].dport)
        now = time.time()

        rec = _incidents.setdefault(
            ip_src,
            {
                "ports": {},
                "incident": False,
                "ports_total": set(),
                "start": 0.0,
                "last_alert": 0.0,
            },
        )

        rec["ports"][port_dst] = now
        # Keep only ports touched within the time window
        rec["ports"] = {p: ts for p, ts in rec["ports"].items() if now - ts <= TIME_WINDOW}
        current_port_count = len(rec["ports"])

        if not rec["incident"] and current_port_count > PORT_SCAN_THRESHOLD:
            rec.update(
                incident=True,
                start=now,
                last_alert=now,
                ports_total=set(rec["ports"]),
            )
            log_alert(
                f"[SYN SCAN] {ip_src} ➜ {ip_dst} : "
                f"{current_port_count} unique ports (begin)"
            )
            start_honeypot()  # ✅ Trigger honeypot on SYN scan detection
            return

        if rec["incident"]:
            rec["ports_total"].add(port_dst)

            if now - rec["last_alert"] >= ALERT_INTERVAL:
                log_alert(
                    f"[SYN SCAN] {ip_src} ➜ {ip_dst} : "
                    f"{current_port_count} ports (Δ {ALERT_INTERVAL}s)"
                )
                rec["last_alert"] = now

            if current_port_count <= PORT_SCAN_THRESHOLD:
                duration = int(now - rec["start"])
                total_ports = len(rec["ports_total"])
                log_alert(
                    f"[SYN SCAN] END {ip_src} ➜ {ip_dst} : "
                    f"{total_ports} unique ports in {duration}s"
                )
                rec.update(incident=False, ports_total=set())

    except Exception as exc:
        log_error(f"[SYN SCAN] exception: {exc}")
