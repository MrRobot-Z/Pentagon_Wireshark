import Wireshark_utils as WsU
import re
import scapy.all as spy
import datetime
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot


print("Scapy is Imported")


class PSniffer(QObject):
    packet_received = pyqtSignal(dict, list, str)

    def __init__(self):
        QObject.__init__(self)
        self.all_sniffed_packets = []
        self.all_detailed_packets = []
        self.all_summary_packets = []
        self.all_hex_packets = []
        self.packet_id = 0
        self.s_timeout = None
        self.s_count = 0
        self.filter = None
        self.s_stop = False
        self.start_time = datetime.datetime.today()

    @pyqtSlot()
    def start_sniffing(self):
        self.s_stop = False
        try:
            spy.sniff(prn=self.process_packet, timeout=self.s_timeout, count=self.s_count, stop_callback=self.should_stop,
                      filter=self.filter)
        except NameError:
            pass
        print("Done Sniffing")

    def should_stop(self):
        return self.s_stop

    def stop_sniffing(self):
        self.s_stop = True

    def process_packet(self, sniffed_pkt):
        try:
            pkt_lines = WsU.get_show_data(sniffed_pkt)
        except AttributeError:
            return

        self.all_sniffed_packets.append(sniffed_pkt)

        protocol_lines = [i for i, word in enumerate(pkt_lines) if re.search(r'###\[ .* \]###', word)]
        pkt_details = []
        for i in range(len(protocol_lines) - 1):
            single_layer = pkt_lines[protocol_lines[i]:protocol_lines[i+1]]
            pkt_details.append(self.analyze_layer(single_layer))
        single_layer = pkt_lines[protocol_lines[-1]:]
        pkt_details.append(self.analyze_layer(single_layer))

        self.all_detailed_packets.append(pkt_details)

        hx = WsU.get_hex_data(sniffed_pkt, spy.hexdump)
        hx = "\n".join(hx)
        self.all_hex_packets.append(hx)

        sry = self.parse_summary(sniffed_pkt)
        self.all_summary_packets.append(sry)

        # print("*"*70 + str(self.packet_id) + "*"*70)
        # print(sry)

        self.packet_id += 1
        self.packet_received.emit(self.all_summary_packets[-1], self.all_detailed_packets[-1], self.all_hex_packets[-1])

    @pyqtSlot()
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

    @staticmethod
    def parse_http(raw_tcp):
        fields = raw_tcp[1].split("=", 1)[1].split("\\r\\n\\r\\n", 1)
        load = ""
        if len(fields) == 2:
            load = fields[1]
        http = fields[0].split("\\r\\n")
        out = [("HTTP", x) for x in http]
        out.append(("Load", load))
        out = ["###[ HTTP ]###"] + out
        return out

    def parse_summary(self, pkt):
        summary_dict = {}
        t = (datetime.datetime.now()).strftime("%H:%M:%S.%f")
        summary_dict["ID"] = self.packet_id
        summary_dict["Time"] = t
        summary_dict["Length"] = len(pkt)
        s = pkt.summary()
        summary_dict["Info"] = s
        source = ""
        destination = ""

        details = self.all_detailed_packets[self.packet_id]
        raw_index = 0
        for i, layer in enumerate(details):
            if layer[0] == "###[ IP ]###":
                d = dict(layer[1:])
                source = d["src"]
                destination = d["dst"]
            elif layer[0] == "###[ Raw ]###":
                raw_index = i

        if re.search(r'http', s):
            protocol = "HTTP"
        elif raw_index:
            protocol = details[raw_index - 1][0].replace("###[ ", "").replace(" ]###", "")
        elif len(details) >= 4:
            protocol = details[3][0].replace("###[ ", "").replace(" ]###", "")
        else:
            protocol = details[-1][0].replace("###[ ", "").replace(" ]###", "")

        summary_dict["Source"] = source
        summary_dict["Destination"] = destination
        summary_dict["Protocol"] = protocol.strip()

        return summary_dict

    def write_into_pcap(self, file_path_name="test.pcap"):
        spy.wrpcap(file_path_name, self.all_sniffed_packets)

    def refresh(self):
        self.all_detailed_packets.clear()
        self.all_summary_packets.clear()
        self.all_hex_packets.clear()
        self.all_sniffed_packets.clear()
        self.packet_id = 0


if __name__ == "__main__":
    pws = PSniffer()
    try:
        # pws.read_pcap_file()
        pws.start_sniffing()
        # pws.write_into_pcap()
    except ValueError:
        pass
