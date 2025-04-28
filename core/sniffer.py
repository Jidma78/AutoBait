from scapy.all import sniff, get_if_list, get_if_addr
from detection import syn_scan, bruteforce
import threading
import ipaddress

def process_packet(packet):
    syn_scan.analyze(packet)
    bruteforce.analyze(packet)

def is_valid_interface(iface):
    try:
        ip = get_if_addr(iface)
        # Check if the IP address is private and starts with 192 or 172
        return ip.startswith(("192.", "172.", "127."))
    except Exception:
        return False

def sniff_on_interface(iface):
    try:
        print(f"[*] Sniffing sur {iface}...")
        sniff(filter="tcp", prn=process_packet, iface=iface, store=False)
    except Exception as e:
        print(f"[!] Erreur sur interface {iface} : {e}")

def sniff_packets():
    interfaces = get_if_list()
    valid_ifaces = [i for i in interfaces if is_valid_interface(i)]

    print(f"[*] Interfaces valides : {valid_ifaces}")

    threads = []
    for iface in valid_ifaces:
        t = threading.Thread(target=sniff_on_interface, args=(iface,), daemon=True)
        t.start()
        threads.append(t)


    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[*] Sniffing interrupted.")
