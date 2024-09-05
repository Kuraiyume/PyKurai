from scapy.all import *
import time
import logging
import argparse

banner = r"""
   ___   ___   ___ ____
  / _ \ / _ \ / _ \___ \
 | | | | | | | | | |__) |
 | | | | | | | | | |__ <
 | |_| | |_| | |_| |__) |
  \___/ \___/ \___/____/    Kuraiyume
"""

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_dhcp_options(dhcp_options):
    requested_ip, hostname, vendor_id = [None] * 3
    for label, value in dhcp_options:
        if label == 'requested_addr':
            requested_ip = value
        elif label == 'hostname':
            hostname = value.decode(errors='ignore')
        elif label == 'vendor_class_id':
            vendor_id = value.decode(errors='ignore')
    return requested_ip, hostname, vendor_id

def process_packet(packet):
    if not (packet.haslayer(Ether) and packet.haslayer(DHCP)):
        return
    target_mac = packet[Ether].src
    dhcp_options = packet[DHCP].options
    requested_ip, hostname, vendor_id = parse_dhcp_options(dhcp_options)
    if target_mac and requested_ip and hostname and vendor_id:
        logging.info(f"{target_mac} - {hostname} / {vendor_id} requested {requested_ip}")

def listen_dhcp(interface):
    sniff(prn=process_packet, filter='udp and (port 67 or port 68)', store=0, iface=interface)

def main():
    print(banner)
    parser = argparse.ArgumentParser(description="DHCP Listener")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to sniff on")
    args = parser.parse_args()
    try:
        listen_dhcp(args.interface)
    except KeyboardInterrupt:
        logging.info("[-] Sniffing stopped by user.")
    except Exception as e:
        logging.error(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
