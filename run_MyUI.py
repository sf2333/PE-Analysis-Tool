import sys
from PyQt5.QtWidgets import QApplication, QMainWindow
import MyUI


if __name__ == '__main__':

    myapp = QApplication(sys.argv)
    mainW = QMainWindow()
    ui = MyUI.Ui_MainWindow()
    ui.setupUi(mainW)

    mainW.show()
    sys.exit(myapp.exec_())