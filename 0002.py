from scapy.all import ARP, Ether, srp
import socket
import argparse

banner = """
   ___   ___   ___ ___  
  / _ \ / _ \ / _ \__ \ 
 | | | | | | | | | | ) |
 | | | | | | | | | |/ / 
 | |_| | |_| | |_| / /_ 
  \___/ \___/ \___/____|    Kuroshiro
"""

def get_mac_and_name(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"
    return hostname

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        hostname = get_mac_and_name(received.psrc)
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'name': hostname})
    return devices

def display_results(devices):
    print("IP Address\t\tMAC Address\t\t\tDevice Name")
    print("-" * 67)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['name']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner to identify devices on a given IP range.")
    parser.add_argument('ip_range', type=str, help="IP range to scan, e.g., 192.168.1.1/24")
    args = parser.parse_args()
    ip_range = args.ip_range
    devices = scan_network(ip_range)
    display_results(devices)
