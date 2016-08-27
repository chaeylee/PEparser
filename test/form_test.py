import sys
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4 import uic

form_class = uic.loadUiType("test.ui")[0]

class MyWindow(QMainWindow, form_class):
    def __init__(self):
        super().__init__() 
        self.setupUi(self)
        self.connect(self.pushButton, SIGNAL("clicked()"), self.btn_clicked)

    def btn_clicked(self):
        text = self.lineEdit.text()
        self.label.setText(text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = MyWindow()
    myWindow.show()
    app.exec_()
