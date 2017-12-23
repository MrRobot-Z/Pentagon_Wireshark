import sys
from gui import *


class GUI(object):
    def __init__(self):
        self.app = QtWidgets.QApplication(sys.argv)
        self.MainWindow = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self.MainWindow)
        self.packet_number = 0
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
        self.ui.ListView.itemClicked.connect(self.view_packet_details)
        self.ui.start.clicked.connect(self.start_sniff)
        self.MainWindow.show()

    ''' Packet form for the GUI is tuple(time, Source, Destination, Length, Info.) '''
    def view_packet(self, packet):
        if self.packet_number == 0:
            self.http_view.setHidden(False)
            self.ethernet_view.setHidden(False)
            self.ip_view.setHidden(False)
            self.tcp_view.setHidden(False)

        new_packet = QtWidgets.QTreeWidgetItem(self.ui.ListView)
        new_packet.setText(0, str(self.packet_number))
        self.packet_number += 1
        for i in range(1, 7):
            new_packet.setText(i, packet[i-1])

        #TODO view packet 1

    def view_packet_details(self):
        s = self.ui.ListView.selectedItems()
        if s:
            packet_no = s[0].text(0)
            self.ethernet_details.setText(0, "Detail for Packet No. " + str(packet_no))
            self.ip_details.setText(0, "Detail for Packet No. " + str(packet_no))
            self.tcp_details.setText(0, "Detail for Packet No. " + str(packet_no))
            self.http_details.setText(0, "Detail for Packet No. " + str(packet_no))
            self.ui.HexView.setText("Hex Data for packet No. " + str(packet_no))

    def start_sniff(self):
        temp.view_packet(("0.00000", "192.168.1.1", "192.168.1.3", "TCP", "54", "nmdfhdbfms"))

    def receive_packets(self, sniffed_packets, detailed_packets, summary_packets):
        self.view_packet(sniffed_packets[1])


if __name__ == "__main__":
    temp = GUI()
    sys.exit(temp.app.exec_())