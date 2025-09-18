from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dot11 import sniff
from scapy.layers.dhcp import BOOTP, DHCP, RandInt
from scapy.sendrecv import sendp, srp1, send, srp, sr1

def dhcp_discover():

    mac_address = '86:94:7a:42:a1:9d'
    mac_broadcast = 'ff:ff:ff:ff:ff:ff'
    mac_router = '78:8c:b5:32:68:e0'

    dhcp_options = [('message-type', 'discover'), ('router-discovery', 1), 'end', ('pad', b'\x00')]
 
    build_dhcp_pkt = Ether(dst=mac_broadcast, src=mac_address) / IP(src='0.0.0.0', dst='255.255.255.255') / \
                     UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=mac_address, xid=RandInt(), flags=0x8000) / \
                     DHCP(options=dhcp_options) 

    send_packet_recv = sendp(build_dhcp_pkt, iface='wlan0')

    if send_packet_recv:
       print(send_packet_recv.show())
    else:
        print('No reply );')

dhcp_discover()
