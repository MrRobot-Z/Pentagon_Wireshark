import sys
from gui import *
from P_Sniffer import *


class GUI(object):
    def __init__(self):
        self.app = QtWidgets.QApplication(sys.argv)
        self.MainWindow = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self.MainWindow)

        '''self.ethernet_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
        self.ethernet_view.setText(0, "Ethernet")
        self.ethernet_details = QtWidgets.QTreeWidgetItem(self.ethernet_view)

        self.ip_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
        self.ip_view.setText(0, "Internet Protocol Version 4")
        self.ip_details = QtWidgets.QTreeWidgetItem(self.ip_view)

        self.tcp_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
        self.tcp_view.setText(0, "Transimission Control Protocol")
        self.tcp_details = QtWidgets.QTreeWidgetItem(self.tcp_view)

        self.http_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
        self.http_view.setText(0, "Hypertext Transfer Protocol")
        self.http_details = QtWidgets.QTreeWidgetItem(self.http_view)
        self.http_view.setHidden(True)
        self.ethernet_view.setHidden(True)
        self.ip_view.setHidden(True)
        self.tcp_view.setHidden(True)'''
        self.ui.actionExit.triggered.connect(self.MainWindow.close)

        self.packets_details = []
        self.packets_summary = []
        self.packets_hex = []

        self.sniffer = PSniffer()
        self.sniffer.packet_received.connect(self.view_packet)
        self.ui.start.clicked.connect(self.sniffer.read_pcap_file)

        self.ui.ListView.itemClicked.connect(self.view_packet_details)
        self.MainWindow.show()

    def view_packet(self, packet_summary, packet_detail, packet_hex):
        '''if packet_summary['ID'] == 0:
            self.http_view.setHidden(False)
            self.ethernet_view.setHidden(False)
            self.ip_view.setHidden(False)
            self.tcp_view.setHidden(False)'''

        new_packet = QtWidgets.QTreeWidgetItem(self.ui.ListView)
        new_packet.setText(0, str(packet_summary['ID']))
        new_packet.setText(1, str(packet_summary['Time']))
        new_packet.setText(2, str(packet_summary['Source']))
        new_packet.setText(3, str(packet_summary['Destination']))
        new_packet.setText(4, str(packet_summary['Protocol']))
        new_packet.setText(5, str(packet_summary['Length']))
        new_packet.setText(6, str(packet_summary['Info']))

        self.packets_summary.append(packet_summary)
        self.packets_details.append(packet_detail)
        self.packets_hex.append(packet_hex)

    def view_packet_details(self):
        s = self.ui.ListView.selectedItems()
        if s:
            packet_no = s[0].text(0)
            self.ui.DetailView.clear()
            packet_details = self.packets_details[int(packet_no)]
            for protocol in packet_details:
                tmp = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
                tmp.setText(0, self.header_rename(protocol[0]))
                for i in range(1, len(protocol[1:])):
                    tmp2 = QtWidgets.QTreeWidgetItem(tmp)
                    tmp2.setText(0, protocol[i][0] + " : " + protocol[i][1])
            self.ui.HexView.setText(self.packets_hex[int(packet_no)])

    def header_rename(self, header):
        header = header.replace(']', '')
        header = header.replace('[', '')
        header = header.replace('###', '')
        header = header.replace(' ', '')
        if header == 'Ethernet':
            return "Ethernet"
        elif header == 'IP':
            return "Internet Protocol Version 4"
        elif header == 'TCP':
            return 'Transmission Control Protocol'
        elif header == 'UDP':
            return 'User datagram Protocol'
        elif header == 'DNS':
            return 'Domain Name Server'
        elif header == 'Raw':
            return 'Hypertext Transfer Protocol'
        else:
            return header

    def start_sniff(self):
        self.sniffer.read_pcap_file(file_path="example_network_traffic.pcap")

    def receive_packets(self, sniffed_packets, detailed_packets, summary_packets):
        self.view_packet(sniffed_packets[1])


if __name__ == "__main__":
    temp = GUI()
    sys.exit(temp.app.exec_())