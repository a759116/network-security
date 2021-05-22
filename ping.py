#!/usr/bin/python3

from scapy.all import *

print("pinging ...")

pkt = IP(dst='8.8.8.8')/ICMP(id=1)
pkt.show()
sr = sr(pkt)
print(sr)