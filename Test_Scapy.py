from scapy.all import *
from scapy_http import http


# packets = rdpcap("example_network_traffic.pcap")

packets = sniff(filter="tcp port 80", timeout=10)

# packets.summary()

for one in packets:
    one.show()
