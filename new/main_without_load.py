import sys
from PyQt5.QtWidgets import QMainWindow, QApplication
from PyQt5 import QtCore, QtGui, QtWidgets
from login_ui import Ui_LoginWindow
from mainWindow_ui import Ui_MainWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow,self).__init__()

        self.mainWindow = Ui_MainWindow()
        self.mainWindow.setupUi(self)

        self.mainWindow.icon_only_widget.hide()
        self.mainWindow.stackedWidget.setCurrentIndex(5)
        self.mainWindow.account_btn.setChecked(True)

        self.loginWindow = LoginWindow()
        self.loginWindow.show()

class LoginWindow(QMainWindow):
    def __init__(self):
        super(LoginWindow,self).__init__()

        self.loginWindow = Ui_LoginWindow()
        self.loginWindow.setupUi(self)

        self.loginWindow.widget.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.loginWindow.login_btn.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))

        self.loginWindow.login_btn.clicked.connect(lambda: self.loggg())
    
    def loggg(self):
        self.close()
        mainWindow.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)

    mainWindow = MainWindow()

    app.exec_()