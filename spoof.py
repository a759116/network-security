#!/usr/bin/python3
from scapy.all import *

print("Spoofed packets ...")

a = IP()
a.dst = '10.0.2.4'
a.src = '8.8.8.8'
b = ICMP()
pkt = a/b
pkt.show()
send(pkt)