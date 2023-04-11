## IPK Sniffer

The IPK sniffer is a C-based network sniffer which is inspired by [wireshar](https://www.wireshark.org/) sniffer, but it is a lot more simple to use. It can capture and analyze network IPv4, IPv6 and ARP packets of various types on a specified network interface.

### Installation
> **Note!**
The program is made for UNIX-based systems only. In other cases the sniffer won't work.

To install the sniffer program, follow these steps:
1. Download the source code from the repository.
2. Compile the source code using Makefile:
```bash
make
```
3. Run the program (launch example)
```bash
./ipk-sniffer -i eth0
```

- `ipk-sniffer` is the name of the sniffer program that will be created after `make`.
- `-i` option stands for **interface** sniffer captures packets from.

Program will start and print out first packet that it captures.

### Usage

```bash
./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
```

- `-i interface` or `--interface interface`, where **interface** is network interface sniffer will listen to. If **interface** is not specified then the program will print list of available interfaces on user's device.
- `-p port` will filter captured packets by port. If this option is not set - all ports are considered.
`-t` or `--tcp` will show only TCP packets.
`-u` or `--idp` will show only UDP packets.
`--icmp4` will show only ICMPv4 packets.
`--icmp6` will display only ICMPv6 echo request/response.
`--arp` will display only ARP frames.
`--ndp` will display only ICMPv6 NDP packets.
`--igmp` will display only IGMP packets
`--mld` will display only MLD packets.
If none protocols are specified for filtering - all protocols are considered.
`-n N` where (N >= 0). It limits the amout of packets that should be captured by sniffer. By defailt its value is 1 (one packet).
### Output
Capture packet will have the following form:
```bash
timestamp: 2021-03-19T18:42:52.362+01:00
src MAC: 00:1c:2e:92:03:80
dst MAC: 00:1b:3f:56:8a:00
frame length: 512 bytes
src IP: 147.229.13.223
dst IP: 10.10.10.56
src port: 4093
dst port: 80

0x0000: 00 19 d1 f7 be e5 00 04 96 1d 34 20 08 00 45 00 ........ ..4 ..
0x0010: 05 a0 52 5b 40 00 36 06 5b db d9 43 16 8c 93 e5 ..R[@.6. [..C....
0x0020: 0d 6d 00 50 0d fb 3d cd 0a ed 41 d1 a4 ff 50 18 .m.P..=. ..A...P.
0x0030: 19 20 c7 cd 00 00 99 17 f1 60 7a bc 1f 97 2e b7 . ...... .`z.....
0x0040: a1 18 f4 0b 5a ff 5f ac 07 71 a8 ac 54 67 3b 39 ....Z._. .q..Tg;9
0x0050: 4e 31 c5 5c 5f b5 37 ed bd 66 ee ea b1 2b 0c 26 N1.\_.7. .f...+.&
0x0060: 98 9d b8 c8 00 80 0c 57 61 87 b0 cd 08 80 00 a1 .......W a.......
```
Header data of the packet will display timestamp, source and destination info in various forms (for IPv4 protocol it is ip address, for IPv6 protocol it is IPv6 address) with MAC addresses.

Below will be displayed packet itself in form where:
- First part represents content of the packet in hexadecimal form.
- Second - ASCII form of each hexadecimal value in the first part.

### Protocols
As you have noticed, sniffer works with limitted amount of protocols. Such as:

#### IPv4
##### TCP
TCP packets are used for reliable, ordered, and error-checked
delivery of data between applications over an IP network. TCP packets operate
at the Transport layer (Layer 4) of the OSI model.

##### UDP
UDP is a transport protocol used for sending data over IP networks. It is a connectionless protocol that does not guarantee reliable delivery of data or error checking. Mostly it is used in cases when amount of data is more required than its quality (such as streaming)

##### ICMPv4
ICMPv4 is used for diagnostics and error checking only.
There is no such concept as 'port' for this type of protocol, additionaly
it operates within layer 3, while the ports are at layer 4 of OSI. For generating such traffic people usually use `ping <ip>`.

##### IGMP
IGMP protocol operates at network layer 3 of the OSI model, while ports are associated with layer 4 (transport level). IGMP is a network layer protocol used to set up multicasting on networks that use the Internet Protocol version 4 (IPv4)

#### ARP
ARP is a protocol used to map a network address
to a physical address. It has its limitations - it works only in local enviroment

#### IPv6
IPv6 is the most recent version of the Internet Protocol, designed to eventually replace IPv4.

##### NDP
NDP is a protocol in IPv6 that is used to
discover and maintain information about other nodes on the same link.NDP does not use ports, instead they use message type just like ICMPv6

##### MLD
MLD operates at the network layer (Layer 3) of the OSI model, and does not use any ports like transport layer protocols such as TCP or UDP.

##### ICMPv6
ICMPv6 is a protocol that operates at the network layer (Layer 3) of the OSI model, just like MLD. ICMPv6 messages are sent and received using IPv6 protocol, and do not use ports. ICMPv6 messages are identified by their message type field, which is part of the ICMPv6 header in the IPv6 packet.

## Testing
For testing was created separate program [packegen](https://scapy.readthedocs.io/en/latest/layers/tcp.html) in python3. It can generate packets to test IPK sniffer.

The goal of packegen is to test wether sniffer can filter packets correctly, display address information etc.

Additionally I have used [wireshark](https://www.wireshark.org/) in order to compare incoming packets and its content with IPK sniffer.

#### How to run test?
Packegen is using well-known library [scapy](https://scapy.readthedocs.io/en/latest/usage.html) for managing packets. 

First you will have to install scapy
```bash
pip install scapy
```

Then just run
```bash
python3 packegen.py [OPTIONS|--help]
```

Where **OPTIONS** are
- --help (prints usage info in console)
- --host (dest ip address)
- --port (dest port)
- --mode (packet type: tcp, udp, icmp4, igmp, icmp6, arp, ndp, mld)
- --timeout (interval between packets)

> **Note!**
Be aware that for IPv4 packets you will need dummy server in order to see this packets flying over your network. The server is not provided with packegen [since it's pretty easy to build](https://realpython.com/python-sockets/).

Here is the example for TCP packet
```bash
python3 packegen.py --host 123.456.7.8 --port 2023 --mode tcp
```

## Bibliography
[TCP/IP layers, IPv4 protocols. Header format](https://book.huihoo.com/iptables-tutorial/c171.htm)<br/>
[PCAP tutorial in C. How to create sniffer](https://www.tcpdump.org/pcap.html)<br/>
[IPv6 protocols and how they work](https://www.spiceworks.com/tech/networking/articles/what-is-ipv6/)<br/>
[Scapy. Python library for generating traffic](https://scapy.readthedocs.io/en/latest/layers/tcp.html)<br/>
Also was used a lot of official C header files of specific packet headers in order to understand what was inside of it.<br/>