#!/usr/bin/python3
from scapy.all import *

print("Trace ...")

for ttl in range(1,25):
    ip = IP(dst='8.8.8.8', ttl=ttl)
    sr = sr1(ip/ICMP(),retry=1,timeout=3, verbose=0)

    if sr is None:
        break
    elif sr.type == 0:
        print("host {} {} hops away:".format(sr.src,ttl))
        print("Complete ...")
        break
    else:
        print("host {} {} hops away:".format(sr.src, ttl))

