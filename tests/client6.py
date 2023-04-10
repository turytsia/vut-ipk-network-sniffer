from scapy.all import *
import time

# Set the interface to use
iface = "eth0"

# Construct an ICMPv6 Neighbor Solicitation message with the target IPv6 address
ns_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
    IPv6(src="::", dst="fe80::215:5dff:fe5a:d592") / \
    ICMPv6ND_NS(tgt="fe80::215:5dff:fe5a:d592")

while True:
    # Send the Neighbor Solicitation message
    sendp(ns_pkt)

    time.sleep(5)
