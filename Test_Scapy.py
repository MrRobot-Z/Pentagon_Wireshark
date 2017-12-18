import scapy.all as scpy
import scapy_http.http


packets = scpy.rdpcap("example_network_traffic.pcap")

for one in packets:
    print("*"*100)
    one.show()
