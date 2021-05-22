#!/usr/bin/python3

from scapy.all import *

print("Sniffing packets ...")

def print_pkt(pkt):
    pkt.show()

# capture only ICMP packet
pkt = sniff(filter='icmp', prn=print_pkt)