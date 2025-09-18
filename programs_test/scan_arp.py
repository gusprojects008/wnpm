from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP
from scapy.sendrecv import srp, srp1
import socket

def scan_arp():
    hosts_on = []
    hosts_off = []
    mac_address = 'a4:f9:33:ed:5b:75'
    packet_arp = Ether(src=mac_address, dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, hwsrc=mac_address, pdst='192.168.0.0/24')

    packets_sent_recv, packets_no_response = srp(packet_arp, timeout=6, iface='wlan0')

    for sent_packet, recv_packet in packets_sent_recv:
        if recv_packet:
           ip_host = recv_packet.psrc
           try:
              hostname = socket.gethostbyaddr(ip_host)
              hosts_on.append(hostname)
           except socket.herror:
                  pass

    for packet in packets_no_response:
        ip_host = packet.pdst
        try:
           hostname = socket.gethostbyaddr(ip_host)
           hosts_on.append(hostname)
        except socket.herror as error:
               hosts_off.append(f'HOST OFF: {ip_host}')
    
    for host in hosts_off:
        print(host)
    print('\n')

    print(packets_sent_recv.summary())
    print('\n')

    try:
       print(hosts_on)
       print('\n')
       gateway_ip = hosts_on[0][2][0]
       print(f"GATEWAY ROUTER: {gateway_ip}")
    except:
          print("\nhosts on, not found );")

scan_arp()
print('\n')
