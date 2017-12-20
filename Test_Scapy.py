import scapy.all as spy
import Wireshark_utils as WsU
from threading import Thread
import time

print("Scapy is Imported")
# packets = spy.rdpcap("example_network_traffic.pcap")

packets = []


def test_sniff():
    global packets
    packets.append(spy.sniff(filter="tcp port 80", timeout=20))
    print("Packet Added =D ", len(packets))


t = Thread(target=test_sniff)
print("Thread Started")
t.start()

time.sleep(10)
print("I'm back")
try:
    t._stop()
except AssertionError:
    pass

print(len(packets))
for one in packets:
    print("I'm In heeeeeeeeeere")
    p = WsU.get_show_data(one)
    for i in p:
        print(i)
