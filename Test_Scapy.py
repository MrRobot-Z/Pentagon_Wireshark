import scapy.all as scpy

packets = scpy.sniff("example_network_traffic.pcap")

for one in packets:
    print("*"*100)
    one.show()
