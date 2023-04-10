from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.contrib.igmp import IGMP
from scapy.all import IPv6, ICMPv6ND_NA, ICMPv6MLQuery
import socket
import time
from scapy.all import *

HOST = '172.25.3.177'
PORT = 2000

while True:
    try:
        #TCP
        # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        # s.connect((HOST, PORT))
        # s.sendall(b'H')
        # Sleep for some time to keep the connection alive

        # create an IGMP packet
        # igmp_pkt = IP(dst=HOST)/IGMP(type=0x16)/Raw(load="Test IGMP packet")

        #create an ARP packet
        arp_pck = IP(dst=HOST)/ARP(pdst=HOST)/Raw(load="Test Arp packet")

        #create ndp packet
        # na_packet = IPv6(src="fe80::9f6e:fd1a:9014:4d0d", dst="fe80::215:5dff:fe5a:de1c") / \
        #     ICMPv6ND_NA(tgt="fe80::215:5dff:fe5a:de1c", R=0)
        send(arp_pck)

        time.sleep(1)

        # TCP close
        #s.close()

    except Exception as e:
        print(f'Error: {e}')
