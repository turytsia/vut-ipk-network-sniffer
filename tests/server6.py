from scapy.all import *

def ndp_server(pkt):
    if pkt.haslayer(ICMPv6ND_NS):
        # Received a Neighbor Solicitation message
        ns_pkt = pkt.getlayer(ICMPv6ND_NS)
        target_addr = ns_pkt.tgt
        # Construct a Neighbor Advertisement message with the source MAC address and IPv6 address of the current interface
        na_pkt = Ether(src=get_if_hwaddr(iface), dst=pkt.src) / \
            IPv6(src=get_if_addr(iface), dst=target_addr) / \
            ICMPv6ND_NA(tgt=target_addr, S=get_if_addr(iface))
        # Send the Neighbor Advertisement message
        sendp(na_pkt, iface=iface)
        print(f"Sent NDP response to {pkt.src} for {target_addr}")


# Set the interface to listen on
iface = "eth0"

# Set the filter to capture only ICMPv6 Neighbor Solicitation messages
filter_str = "icmp6 and icmp6[0] == 135"

# Start the packet sniffer
sniff(filter=filter_str, prn=ndp_server, iface=iface)
