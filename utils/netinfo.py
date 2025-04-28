import netifaces
import sys

def list_local_ips():
    """Return [(interface, ip)] without duplicates, including loopback."""
    seen = set()
    for iface in netifaces.interfaces():
        for fam, addrs in netifaces.ifaddresses(iface).items():
            if fam == netifaces.AF_INET:
                for a in addrs:
                    ip = a["addr"]
                    if ip not in seen:
                        seen.add(ip)
                        yield iface, ip

def choose_local_ip():
    """Let the user choose which local IP/interface to monitor."""
    ips = list(list_local_ips())
    print("╭─ Detected interfaces ───────────────────────────")
    for idx, (iface, ip) in enumerate(ips, 1):
        print(f"│ {idx:2d}. {iface:<10}  {ip}")
    print("│  0. (all)")
    print("╰──────────────────────────────────────────────────")

    try:
        choice = int(input("Select the interface number to monitor: "))
    except (ValueError, EOFError):
        choice = -1

    if choice == 0:
        return None              # Monitor all IPs
    if 1 <= choice <= len(ips):
        return ips[choice-1][1]  # Return the selected IP
    print("Invalid choice, monitoring all IPs.")
    return None
