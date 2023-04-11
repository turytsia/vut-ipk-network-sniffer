# @author (xturyt00)

from scapy.all import *
import time
import getopt
import signal

LONG_OPTS = [
    "host=",
    "port=",
    "mode=",
    "timeout=",
    "help",
]

USAGE="""
Usage:
    python3 packegen.py [OPTIONS]

OPTIONS
--help\t\tshow this message
--host\t\tip address (can be IPv6 address)
--port\t\tport 
--mode\t\tpacket type (tcp|udp|icmp4|igmp|icmp6|arp|ndp|mld)
--timeout\tinterval between packets
"""

SHORT_OPTS = "h"

def error(msg: str):
    print(msg, file=sys.stderr)
    sys.exit(1)

def sigint(signal, frame):
    sys.exit(0)

def main():
    host = None
    port = None
    mode = None
    timeout = 3

    signal.signal(signal.SIGINT, sigint)

    try:
        opts, args = getopt.getopt(sys.argv[1:], SHORT_OPTS, LONG_OPTS)
    except getopt.GetoptError as e:
        error(e)
    
    try:
        for opt, arg in opts:
            if opt == "--host":
                host = arg
            elif opt == "--port":
                port = int(arg)
            elif opt == "--mode":
                mode = arg
            elif opt == "--timeout":
                timeout = int(arg)
            elif opt in ("-h", "--help"):
                print(USAGE)
                sys.exit()
            else:
                error(f"unknown option {opt}. Use --help.")
    except ValueError as e:
        error(f"{e}. Use --help")

    if mode is None or host is None:
        error("--mode or --host is not defined. Use --help")

    message = f"Testing {mode} packet"

    while True:

        try:
            if mode == "tcp":
                tcp_pck = IP(dst=host) / TCP(dport=port) / Raw(load=message)
                sr1(tcp_pck, timeout=timeout)
            elif mode == "udp":
                udp_pck = IP(dst=host)/UDP(dport=port) / \
                    Raw(load=message)
                sr1(udp_pck, timeout=timeout)
            elif mode == "icmp4":
                icmp_pck = IP(dst=host)/ICMP() / message
                send(icmp_pck)
            elif mode == "igmp":
                igmp_pkt = IP(dst=host)/IGMP(type=0x16) / \
                    Raw(load=message)
                send(igmp_pkt)
            elif mode == "arp":
                arp_pck = IP(dst=host)/ARP(pdst=host) / \
                    Raw(load=message)
                send(arp_pck)
            elif mode == "ndp":
                na_packet = IPv6(dst=host) / \
                    ICMPv6ND_NA(tgt=host, R=0) / message
                send(na_packet)
            elif mode == "mld":
                na_packet = IPv6(dst=host) / \
                    ICMPv6MLReport() / message
                send(na_packet)
            elif mode == "icmp6":
                na_packet = IPv6(dst=host) / \
                    ICMPv6EchoRequest() / message
                send(na_packet)
            else:
                error(f"unknown mode {mode}")

            time.timeout(timeout)

        except Exception as e:
            error(f'Error: {e}')

if __name__ == "__main__":
    main()
