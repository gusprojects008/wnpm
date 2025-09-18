from scapy.layers.dot11 import sniff
from scapy.sendrecv import srp
#from scapy.layers.l2 import

def sniffer_packets(pkt):
    print('\n')
    packet_captured_summary = pkt.summary()
    print(f"PACKET FUNCTION SUMMARY() ===> : {packet_captured_summary}")

# PRN = NOTIFICATION PACKET RECEIVED
sniff(filter="arp", iface="wlan0", count=10, prn=sniffer_packets)
