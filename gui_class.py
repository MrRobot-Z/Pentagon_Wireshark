import sys
from gui import *
from P_Sniffer import *

class GUI(object):
    def __init__(self):
        self.app = QtWidgets.QApplication(sys.argv)
        self.MainWindow = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self.MainWindow)

        self.ethernet_view = QtWidgets.QTreeWidgetItem(self.ui.DetailView)
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
        self.tcp_view.setHidden(True)
        self.ui.actionExit.triggered.connect(self.MainWindow.close)

        self.packets_details = []
        self.packets_summary = []
        self.packets_hex = []

        self.sniffer = PSniffer()
        self.sniffer.packet_received.connect(self.view_packet)
        self.ui.start.clicked.connect(self.sniffer.read_pcap_file)

        self.ui.ListView.itemClicked.connect(self.view_packet_details)
        self.MainWindow.show()

    ''' Packet form for the GUI is tuple(time, Source, Destination, Length, Info.) '''
    def view_packet(self, packet_summary, packet_detail, packet_hex):
        if packet_summary['ID'] == 0:
            self.http_view.setHidden(False)
            self.ethernet_view.setHidden(False)
            self.ip_view.setHidden(False)
            self.tcp_view.setHidden(False)

        new_packet = QtWidgets.QTreeWidgetItem(self.ui.ListView)
        new_packet.setText(0, packet_summary['ID'])
        new_packet.setText(1, packet_summary['Time'])
        new_packet.setText(2, packet_summary['Source'])
        new_packet.setText(3, packet_summary['Destination'])
        new_packet.setText(4, packet_summary['Protocol'])
        new_packet.setText(5, packet_summary['Length'])
        new_packet.setText(6, packet_summary['Info'])

        self.packets_summary.append(packet_summary)
        self.packets_details.append(packet_detail)
        self.packets_hex.append(packet_hex)
        #TODO view packet 1

    def view_packet_details(self):
        s = self.ui.ListView.selectedItems()
        if s:
            packet_no = s[0].text(0)
            self.ethernet_details.setText(0, "Detail for Packet No. " + str(packet_no))
            self.ip_details.setText(0, "Detail for Packet No. " + str(packet_no))
            self.tcp_details.setText(0, "Detail for Packet No. " + str(packet_no))
            self.http_details.setText(0, "Detail for Packet No. " + str(packet_no))
            self.ui.HexView.setText(self.packets_hex[packet_no])

    def start_sniff(self):
        #temp.view_packet(("0.00000", "192.168.1.1", "192.168.1.3", "TCP", "54", "nmdfhdbfms"))
        pass

    def receive_packets(self, sniffed_packets, detailed_packets, summary_packets):
        self.view_packet(sniffed_packets[1])


if __name__ == "__main__":
    temp = GUI()
    sys.exit(temp.app.exec_())