## Packegen
Packegen is a python tester for IPK sniffer project. It can generate packets of various types and send it over the network. 

### Usage

Tester is using well-known library [scapy](https://scapy.readthedocs.io/en/latest/usage.html) for managing packets. 

First you will have to install scapy.
You can install new environment for python
```bash
pip install virtualenv
virtualenv venv
source bin activate
pip install scapy -i https://pypi.org/simple/
```
or
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

Here is the example for TCP packet
```bash
python3 packegen.py --host 123.456.7.8 --port 2023 --mode tcp
```

Here is the example for MLD packet (IPv6 host)
```bash
python3 packegen.py --host ip:ad:dr:es:s: --mode mld
```