import Wireshark_utils as WsU
import scapy.all as spy
import datetime
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot

# from threading import Timer
print("Scapy is Imported")


class PSniffer(QObject):
    packet_received = pyqtSignal(list, list, list)

    def __init__(self):
        QObject.__init__(self)
        self.all_sniffed_packets = []
        self.all_detailed_packets = []
        self.all_summary_packets = []
        self.all_hex_packets = []
        self.packet_id = 0
        self.s_timeout = 0
        self.s_count = 0
        self.filter = None
        self.s_stop = False


    def pritay7aga(self):
        print("ay 7aga")

    def start_sniffing(self):
        spy.sniff(prn=self.process_packet, timeout=self.s_timeout, count=self.s_count,
                  filter=self.filter, stop_callback=self.should_stop)

    def should_stop(self):
        return self.s_stop

    def stop_sniffing(self):
        self.s_stop = True

    def process_packet(self, sniffed_pkt):
        self.all_sniffed_packets.append(sniffed_pkt)
        self.parse_summary(sniffed_pkt)

        layers_lst = []
        for x in range(5):
            try:
                layers_lst.append(WsU.get_show_data(sniffed_pkt[x]))
            except IndexError:
                break
        for x in range(len(layers_lst) - 2, -1, -1):
            layers_lst[x] = layers_lst[x][:layers_lst[x].index(layers_lst[x + 1][0])]
        pkt_details = []
        for layer in layers_lst:
            pkt_details.append(self.analyze_layer(layer))

        self.all_detailed_packets.append(pkt_details)

        hx = WsU.get_hex_data(sniffed_pkt, spy.hexdump)
        hx = "\n".join(hx)
        self.all_hex_packets.append(hx)

        print("*"*70 + str(self.packet_id) + "*"*70)
        print(self.all_summary_packets[-1])

        self.packet_id += 1
        self.packet_received.emit(self.all_sniffed_packets, self.all_detailed_packets, self.all_summary_packets)

    def read_pcap_file(self, file_path="example_network_traffic.pcap"):
        packets = spy.rdpcap(file_path)
        for one in packets:
            self.process_packet(one)

    def analyze_layer(self, layer_list):
        if layer_list[0] == "###[ Raw ]###":
            if "HTTP/1." in layer_list[1] or "GET" in layer_list[1] or "POST" in layer_list[1]:
                return self.parse_http(layer_list)
        for i in range(1, len(layer_list)):
            s = layer_list[i].split("=", 1)
            s = list(map(str.strip, s))
            if len(s) < 2:
                layer_list[i] = ("", s[0])
                continue
            layer_list[i] = (s[0], s[1])
        return layer_list

    def parse_http(self, raw_tcp):
        fields = raw_tcp[1].split("=", 1)[1].split("\\r\\n\\r\\n", 1)
        load = ""
        if len(fields) == 2:
            load = fields[1]
        http = fields[0].split("\\r\\n")
        out = [("HTTP", x) for x in http]
        out.append(("Load", load))
        out.insert(0, "###[ HTTP ]###")
        self.all_summary_packets[self.packet_id]["Protocol"] = "HTTP"
        return out

    def parse_summary(self, pkt):
        summery_dict = {}
        t = datetime.datetime.now().strftime("%H:%M:%S.%f")
        summery_dict["ID"] = self.packet_id
        summery_dict["Time"] = t
        summery_dict["Length"] = len(pkt)
        s = pkt.summary()
        print(s)
        summery_dict["Info"] = s
        s = s.split()
        index = s.index(">")
        summery_dict["Source"] = s[index - 1]
        summery_dict["Destination"] = s[index - 1]
        summery_dict["Protocol"] = s[index - 2]
        self.all_summary_packets.append(summery_dict)

    def write_into_pcap(self, file_path_name="test.pcap"):
        spy.wrpcap(file_path_name, self.all_sniffed_packets)


if __name__ == "__main__":
    pws = PSniffer()
    # t = Timer(10, pws.stop_sniffing)
    # t.start()
    try:
        pws.read_pcap_file()
        # pws.start_sniffing()
        pws.write_into_pcap()
    except ValueError:
        print("Hello from exception")
