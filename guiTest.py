if __name__ == "__main__":
    import sys
    from gui import *
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    child = QtWidgets.QTreeWidgetItem(ui.ListView)
    child2 = QtWidgets.QTreeWidgetItem(ui.ListView)
    child.setText(0, "Da ID")
    child.setText(1, "da Time")
    child.setText(2, "da Source")
    child.setText(3, "da Dest")
    child2.setText(0, "da tany time")
    Detailchild = QtWidgets.QTreeWidgetItem(ui.DetailView)
    Detailchild.setText(0, "skjdgjdfghdfjg")
    subchild = QtWidgets.QTreeWidgetItem(Detailchild)
    subchild.setText(0, "sdjjhsihgsakjf")
    ui.DetailView.expandAll()
    ui.DetailView.itemClicked(child2).connect(ay7aga)
    MainWindow.show()
    sys.exit(app.exec_())

def ay7aga():
    ui.HexView.setText("A7aaaaaaaaaaaaaaaaaaa")