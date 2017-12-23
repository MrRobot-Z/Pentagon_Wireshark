import sys
from gui_class import GUI
from P_Sniffer import PSniffer
from PyQt5.QtCore import *
from PyQt5.QtGui import *

def main():
    MySniffer = PSniffer()
    MyGui     = GUI()
    sys.exit(MyGui.app.exec_())

if __name__ == "__main__":
    main()
