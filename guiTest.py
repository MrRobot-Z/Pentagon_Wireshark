def ay7aga():
    s = ui.ListView.selectedItems()
    if s:
        packet_no = s[0].text(0)
        Detailchild.setText(0, "Detail for Packet No. " + str(packet_no))
        ui.HexView.setText("Hex Data for packet No. " + str(packet_no))

if __name__ == "__main__":
    import sys
    from gui import *
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    child = QtWidgets.QTreeWidgetItem(ui.ListView)
    child2 = QtWidgets.QTreeWidgetItem(ui.ListView)
    child.setText(0, "0")
    child.setText(1, "da Time")
    child.setText(2, "da Source")
    child.setText(3, "da Dest")
    child2.setText(0, "1")
    Detailchild = QtWidgets.QTreeWidgetItem(ui.DetailView)
    Detailchild.setText(0, "skjdgjdfghdfjg")
    subchild = QtWidgets.QTreeWidgetItem(Detailchild)
    subchild.setText(0, "sdjjhsihgsakjf")
    ui.DetailView.expandAll()
    ui.ListView.itemClicked.connect(ay7aga)
    MainWindow.show()
    sys.exit(app.exec_())
