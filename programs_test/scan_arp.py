#!/usr/bin/env python3
import argparse
import socket
import json
from scapy.all import ARP, Ether, srp

def mac_oui_vendors_identify(mac_oui):
    with open('./mac-vendors-export.json', 'r', encoding='utf-8') as file:
         data = json.load(file)
         vendors_name = {}
         for line in data:
             vendors_name[line['macPrefix']] = line['vendorName']
         return vendors_name.get(mac_oui.upper()[:8], 'Unknown Vendor Type')

def scan_arp(ifname: str, network: str, timeout: int = 5):
    print(f"\n[+] Scanning network {network} on interface {ifname} ...")

    hosts_online = []

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

    answered, _ = srp(packet, timeout=timeout, iface=ifname, verbose=0)

    for sent, recv in answered:
        ip = recv.psrc
        mac = recv.hwsrc
        vendor = mac_oui_vendors_identify(mac)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = ip
        hosts_online.append((ip, mac, vendor, hostname))

    return hosts_online

def main():
    parser = argparse.ArgumentParser(description="ARP Scanner - Scan networks to discover hosts")
    parser.add_argument("-i", "--ifname", required=True, help="Network interface to use, ex: wlan0")
    parser.add_argument("network", help="Network to scan, ex: 192.168.0.0/24")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for ARP responses")
    args = parser.parse_args()

    online = scan_arp(args.ifname, args.network, args.timeout)

    print("\n[+] Hosts ONLINE:")
    if online:
        for ip, mac, vendor, hostname in online:
            print(f" - {ip} | {mac} | {vendor} | {hostname}")
    else:
        print(" No hosts online found.")

if __name__ == "__main__":
    main()
