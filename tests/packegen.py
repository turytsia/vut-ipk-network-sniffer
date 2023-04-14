# @author (xturyt00)
import typing
from dataclasses import dataclass

from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6MLReport
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import ARP
from scapy.sendrecv import send, sr1
from scapy.contrib.igmp import IGMP

from scapy.all import Raw

import time
import getopt
import signal
import sys

LONG_OPTS = [
    "host=",
    "port=",
    "mode=",
    "timeout=",
    "help",
]

USAGE = """
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


def error(msg: str) -> typing.NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(1)


def sigint(*_):
    sys.exit(0)


@dataclass
class Neighbour:
    host: str
    port: int
    timeout: int = 5

    def send_packet(self, mode, message=None, host=None, port=None):
        lmap = {"tcp": TCP, "udp": UDP}

        if message is None:
            message = f"Testing {mode} packet"
        try:
            if mode in {"tcp", "udp"}:
                pack = IP(dst=host or self.host) / lmap[mode](dport=port or self.port) / Raw(load=message)
                sr1(pack, timeout=self.timeout)
                return
            elif mode == "icmp4":
                packet = IP(dst=host or self.host) / ICMP() / message
            elif mode == "igmp":
                packet = IP(dst=host or self.host) / IGMP(type=0x16) / Raw(load=message)
            elif mode == "arp":
                packet = IP(dst=host or self.host) / ARP(pdst=host or self.host) / Raw(load=message)
            elif mode == "ndp":
                packet = IPv6(dst=host or self.host) / ICMPv6ND_NA(tgt=host or self.host, R=0) / message
            elif mode == "mld":
                packet = IPv6(dst=host or self.host) / ICMPv6MLReport() / message
            elif mode == "icmp6":
                packet = IPv6(dst=host or self.host) / ICMPv6EchoRequest() / message
            else:
                error(f"unknown mode {mode}")
                return
            send(packet)

        except Exception as e:
            error(f'Error: {e}')


def main():
    host = None
    port = None
    mode = None
    timeout = 3

    signal.signal(signal.SIGINT, sigint)

    opts: typing.Optional[list[tuple[str, str]]] = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], SHORT_OPTS, LONG_OPTS)
    except getopt.GetoptError as e:
        error(str(e))

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

    nb = Neighbour(host, port, timeout)

    if mode is None or host is None:
        error("--mode or --host is not defined. Use --help")

    while True:
        nb.send_packet(mode)
        time.sleep(timeout)


if __name__ == "__main__":
    main()
