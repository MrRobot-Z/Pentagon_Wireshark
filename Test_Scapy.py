import scapy.all as spy
import Wireshark_utils as WsU

print("Scapy is Imported")


rd_packets = spy.rdpcap("example_network_traffic.pcap")
print(len(rd_packets))
for one in rd_packets:
    p = WsU.get_show_data(one)
    for i in p:
        print(i)
spy.hexdump(rd_packets[0])


print("Start Sniffing")
packets = spy.sniff(filter="", timeout=10)
for i in packets:
    print(i.summary())
print(len(packets))
