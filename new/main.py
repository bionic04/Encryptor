import os
import shutil
import sys,res,resources
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from PyQt5 import QtCore, QtGui, QtWidgets, uic
from PyQt5.QtWidgets import QMainWindow, QApplication, QMessageBox, QWidget, QPushButton, QFileDialog, QTableWidgetItem
from PyQt5.QtCore import Qt
from PyQt5 import QtCore
from PyQt5.QtGui import QFont
import pymysql as mycon
from qtacrylic import WindowEffect

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow,self).__init__()

        uic.loadUi("D:\Documents\Diplom\program\mainWindow_ui.ui",self)

        self.msg = MessageBox()
        
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        # creating a blur effect and blur radius
        # self.blur_effect = QtWidgets.QGraphicsBlurEffect()
        # self.blur_effect.setBlurRadius(15)

        self.windowFX = WindowEffect()  #WindowEffect class
        self.windowFX.setAcrylicEffect(self.winId())  # set the Acrylic effect by specifying the window id
       
        self.icon_only_widget.hide()
        self.stackedWidget.setCurrentIndex(5)
        self.account_btn.setChecked(True)

        #нажатие на кнопки меню
        self.encrypt_menu_btn.clicked.connect(lambda: self.encrypt_menu_pressed())
        self.encrypt_menu_btn_2.clicked.connect(lambda: self.encrypt_menu2_pressed())  
        self.decrypt_menu_btn.clicked.connect(lambda: self.decrypt_menu_pressed())
        self.decrypt_menu_btn_2.clicked.connect(lambda: self.decrypt_menu2_pressed())   
        self.key_menu_btn.clicked.connect(lambda: self.securePlus_menu_pressed())
        self.key_menu_btn_2.clicked.connect(lambda: self.securePlus_menu2_pressed())
        self.unlock_plus_menu_btn.clicked.connect(lambda: self.unlock_plus_pressed())
        self.unlock_plus_menu_btn_2.clicked.connect(lambda: self.unlock_plus_pressed2())
        self.files_menu_btn.clicked.connect(lambda: self.files_menu_pressed())
        self.files_menu_btn_2.clicked.connect(lambda: self.files_menu2_pressed())
        self.settings_menu_btn.clicked.connect(lambda: self.settings_menu_pressed())
        self.settings_menu_btn_2.clicked.connect(lambda: self.settings_menu2_pressed()) 
        self.account_btn.clicked.connect(lambda: self.acc_menu_pressed())

        self.files_menu_btn.setVisible(False)
        self.files_menu_btn_2.setVisible(False)

        #нажатия на основные кнопки
        self.choose_file_btn.clicked.connect(lambda: self.choose_file())
        self.choose_file_btn_2.clicked.connect(lambda: self.s_plus_choose_file())
        self.choose_file_btn_3.clicked.connect(lambda: self.un_choose_dir())

        self.encrypt_btn.clicked.connect(lambda: self.encrypt_f())
        self.decrypt_btn.clicked.connect(lambda: self.decrypt_f())
        self.encrypt_btn_2.clicked.connect(lambda: self.s_plus_encrypt())
        self.decrypt_btn_2.clicked.connect(lambda: self.s_plus_decrypt())

        self.delete_btn_2.clicked.connect(lambda: self.delete_file())

        self.exit_btn.clicked.connect(lambda: self.close())
        self.exit_btn_2.clicked.connect(lambda: self.close())

        self.tableWidget_all_data_2.selectionModel().selectionChanged.connect(lambda: self.decrypt_btn.setGraphicsEffect(None))
        self.tableWidget_all_data.selectionModel().selectionChanged.connect(lambda: self.delete_btn.setGraphicsEffect(None))
        self.tableWidget_all_data_2.selectionModel().selectionChanged.connect(lambda: self.delete_btn_2.setGraphicsEffect(None))
        self.login = LoginWindow()
        self.login.show()  


    #функции кнопокменю
    def encrypt_menu_pressed(self):
        self.res_file_line.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.encrypt_btn.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(0)


    def encrypt_menu2_pressed(self):
        self.res_file_line.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.encrypt_btn.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(0)
    
    
    def decrypt_menu_pressed(self):
        self.decrypt_btn.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.delete_btn_2.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(1)
        self.tableWidget_all_data_2.clear()
        self.tableWidget_all_data_2.setRowCount(1)
        self.tableWidget_all_data_2.setColumnCount(2)
        try:
            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            mycursor.execute("SELECT file_path, username FROM protected_files WHERE username='{0}'".format(self.label_username.text()))
            result = mycursor.fetchall()
            print(result)
        except Exception as ex:
            print("conn problem!")
            print(ex)
        finally:
            db_con.close()
        for row_number, row_data in enumerate(result):
            self.tableWidget_all_data_2.insertRow(row_number)
            for column_number, data in enumerate(row_data):
                self.tableWidget_all_data_2.setItem(row_number, column_number, QTableWidgetItem(str(data)))

        
    def decrypt_menu2_pressed(self):
        self.decrypt_btn.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.delete_btn_2.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(1)
        self.tableWidget_all_data_2.clear()
        self.tableWidget_all_data_2.setRowCount(1)
        self.tableWidget_all_data_2.setColumnCount(2)
        try:
            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            mycursor.execute("SELECT file_path, username FROM protected_files WHERE username='{0}'".format(self.label_username.text()))
            result = mycursor.fetchall()
            print(result)
        except Exception as ex:
            print("conn problem!")
            print(ex)
        finally:
            db_con.close()
        for row_number, row_data in enumerate(result):
            self.tableWidget_all_data_2.insertRow(row_number)
            for column_number, data in enumerate(row_data):
                self.tableWidget_all_data_2.setItem(row_number, column_number, QTableWidgetItem(str(data)))

    
    def securePlus_menu_pressed(self):
        self.encrypt_btn_2.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.secure_plus_res_line.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(2)
        
    def securePlus_menu2_pressed(self):
        self.encrypt_btn_2.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.secure_plus_res_line.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(2)
    
    def unlock_plus_pressed(self):
        self.decrypt_btn_2.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.unlock_plus_res_line.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(6)

    def unlock_plus_pressed2(self):
        self.decrypt_btn_2.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.unlock_plus_res_line.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(6)

    
    def files_menu_pressed(self):
        self.delete_btn.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(3)
        self.tableWidget_all_data.clear()
        self.tableWidget_all_data.setRowCount(1)
        self.tableWidget_all_data.setColumnCount(2)
        try:
            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            mycursor.execute("SELECT file_path, username FROM protected_files WHERE username='{0}'".format(self.label_username.text()))
            result = mycursor.fetchall()
            print(result)
        except Exception as ex:
            print("conn problem!")
            print(ex)
        finally:
            db_con.close()
        # self.tableWidget.setColumnCount(1)
        for row_number, row_data in enumerate(result):
            self.tableWidget_all_data.insertRow(row_number)
            for column_number, data in enumerate(row_data):
                self.tableWidget_all_data.setItem(row_number, column_number, QTableWidgetItem(str(data)))

        
    def files_menu2_pressed(self):
        self.delete_btn.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.stackedWidget.setCurrentIndex(3)
        self.tableWidget_all_data.clear()
        self.tableWidget_all_data.setRowCount(1)
        self.tableWidget_all_data.setColumnCount(2)
        try:
            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            mycursor.execute("SELECT file_path, username FROM protected_files WHERE username='{0}'".format(self.label_username.text()))
            result = mycursor.fetchall()
            print(result)
        except Exception as ex:
            print("conn problem!")
            print(ex)
        finally:
            db_con.close()
        # self.tableWidget.setColumnCount(1)
        for row_number, row_data in enumerate(result):
            self.tableWidget_all_data.insertRow(row_number)
            for column_number, data in enumerate(row_data):
                self.tableWidget_all_data.setItem(row_number, column_number, QTableWidgetItem(str(data)))

    
    def settings_menu_pressed(self):
        self.stackedWidget.setCurrentIndex(4)
        
    def settings_menu2_pressed(self):
        self.stackedWidget.setCurrentIndex(4)
    
    def acc_menu_pressed(self):
        self.stackedWidget.setCurrentIndex(5)

    
    #Основная логика
    def choose_file(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileNames(self, 'Hey! Select a File')
        #file = str(QFileDialog.getExistingDirectory(self, "Select Directory"))
        files_list = ''
        for file in filename:
            files_list += f'{file}\n'
        self.encrypt_btn.setGraphicsEffect(None)
        self.encrypt_btn.setEnabled(True)
        self.res_file_line.setGraphicsEffect(None)
        self.res_file_line.setPlainText(files_list)
        #for 2d page
        # self.decrypt_btn.setGraphicsEffect(None)
        # self.decrypt_btn.setEnabled(True)


    def encrypt_f(self):
        write_key()
        key = load_key()
        files = self.res_file_line.toPlainText()
        files_list = files.split('\n')
        print('FILES TO ENCRYPT: ', files_list)
        if len(files_list) > 1:
            files_list.pop()
        try:
            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            with open('mykey.key', 'r') as keyfile:
                key_data = keyfile.readline()
            os.remove('mykey.key')
            query = "INSERT INTO protected_files(file_data, key_data, file_path, username) VALUES(%s, %s, %s, %s)"
            username = self.label_username.text()
            for file in files_list:
                binary_file_data = encrypt(file, key)
                mycursor.execute(query, (binary_file_data, key_data, file, username))
                os.remove(file)
            db_con.commit()
            print("FILES LOADING SUCCED!")
        except Exception as ex:
            print("ERROR! CAN'T LOAD TO THE STORAGE!")
            print(ex)
        finally:
            db_con.close()

        self.res_file_line.clear()
        self.res_file_line.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.encrypt_btn.setGraphicsEffect(QtWidgets.QGraphicsBlurEffect(blurRadius=15))
        self.msg.label.setText("Выбранные файлы зашифрованы!")#26 знаков идеал, пока не подгоню
        self.msg.show()

    
    def decrypt_f(self):
        try:
            file_path = self.tableWidget_all_data_2.currentItem().text()
            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            mycursor.execute("SELECT file_data, key_data FROM protected_files WHERE file_path=('"+ file_path +"')")
            data = mycursor.fetchall()
            encrypted_file_data = data[0][0]
            key = data[0][1]
            print("ДАННЫЕ ЗАГРУЖЕНЫ ИЗ ХРАНИЛИЩА!")
            decrypt(file_path, key, encrypted_file_data)
            mycursor.execute("DELETE FROM protected_files WHERE file_path=('"+ file_path +"')")
            db_con.commit()
            self.tableWidget_all_data_2.removeRow(self.tableWidget_all_data_2.currentRow())
            print(f'фАЙЛ {file_path} УДАЛЕН ИЗ БАЗЫ!')
        except Exception as ex:
            print("conn problem!")
            print(ex)
        finally:
            db_con.close()

        self.msg.label.setText("Выбранные файлы расшифрованы!")#26 знаков идеал, пока не подгоню
        self.msg.show()

    
    def s_plus_choose_file(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileNames(self, 'Hey! Select a File')
        files_list = ''
        for file in filename:
            files_list += f'{file}\n'
        self.secure_plus_res_line.setText(files_list)
        self.encrypt_btn_2.setEnabled(True)
        self.encrypt_btn_2.setGraphicsEffect(None)
        self.secure_plus_res_line.setGraphicsEffect(None)

    
    def s_plus_encrypt(self):
        #увеличить ID директории, которая хранится в counter.txt
        with open("counter.txt",'r') as file:
            cnt = file.read()
        number = int(cnt)
        number+=1
        cnt_inc = str(number)
        with open("counter.txt",'w') as file:
            file.write(cnt_inc)
        
        #создать новую дерикторию
        directory = f"{self.label_username.text()}_ProtectedFiles_{cnt}"
        parent_dir = "D:/ArcherProtect/"
        path = os.path.join(parent_dir, directory)
        if os.path.exists(path):
            print("ALREADY EXISTS")
        else:
            os.mkdir(path)
            print('DIRECTORY {0} CREATED'.format(path))
        
        files = self.secure_plus_res_line.toPlainText()
        files_list = files.split('\n')
        if len(files_list) > 1:
            files_list.pop()
        print('FILES TO ENCRYPT: ', files_list)
        #перекинуть зашифр файлы в новую папку
        if os.path.exists(path):
            for file in files_list:
                res = shutil.move(file, path)
                print("{0} ПЕРЕМЕЩАЕТСЯ В НУЖНОЕ МЕСТО, {1}".format(file,path))
            
        protected_files_list = []
        for file in os.listdir(path):
            protected_files_list.append(f'{path}/{file}')
        print("PROTECTED FILES IN NEW DIREC: ", protected_files_list)

        try:
            if os.path.isfile('public.pem'):
                for address, dirs, files in os.walk(path):
                    for name in files:
                        protect(os.path.join(address,name))
            else:
                gen_two_keys()
                for address, dirs, files in os.walk(path):
                    for name in files:
                        protect(os.path.join(address,name))
        except Exception as ex:
            print('Ошибка при попытке шифрования!')
            print(ex)

        
    def un_choose_dir(self):
        file = str(QFileDialog.getExistingDirectory(self, "Выберите папку", "D:\ArcherProtect"))
        self.unlock_plus_res_line.setText(file)
        self.decrypt_btn_2.setEnabled(True)
        self.decrypt_btn_2.setGraphicsEffect(None)
        self.unlock_plus_res_line.setGraphicsEffect(None)
        print(file)
    

    def s_plus_decrypt(self):
        path = self.unlock_plus_res_line.toPlainText()
        try:
            if os.path.isfile('private.pem'):
                for address, dirs, files in os.walk(path):
                    for name in files:
                        unprotect(os.path.join(address,name))
                self.msg.label.setText("Папка расшифрована!")#26 знаков идеал, пока не подгоню
                self.msg.show()
            else:
                print('Не найден закрытый ключ!')
        except Exception as ex:
            print('Ошибка при попытке дешифровки!')
            print(ex)
        
    
    def delete_file(self):
        file_path = self.tableWidget_all_data_2.currentItem().text()
        try:
            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            mycursor.execute("DELETE FROM protected_files WHERE file_path=('"+ file_path +"')")
            db_con.commit()
            self.tableWidget_all_data.removeRow(self.tableWidget_all_data.currentRow())
            print(f'фАЙЛ {file_path} УДАЛЕН ИЗ БАЗЫ!')
            self.msg.label.setText("Файл безвозвратно удален!")#26 знаков идеал, пока не подгоню
            self.msg.show()
        except Exception as ex:
            print("conn problem!")
            print(ex)
        finally:
            db_con.close()


class LoginWindow(QMainWindow):
    def __init__(self):
        super(LoginWindow,self).__init__()

        uic.loadUi("D:\Documents\Diplom\program\login_ui.ui",self)

        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

        #Micro optimization!!!
        self.msg = MessageBox()

        #тени
        self.widget.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.login_btn.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))

        #переключение страниц
        self.register_btn.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(1))
        self.exit_btn_2.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(0))

        self.login_btn.clicked.connect(lambda: self.loginF())
        self.signup_btn.clicked.connect(lambda: self.registerF())
        
        self.exit_btn.clicked.connect(lambda: self.close())


    def loginF(self):
        try:
            username = self.username_input.text()
            password = self.password_input.text()

            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            mycursor.execute("SELECT * FROM users WHERE username = '"+ username +"' and password = '"+ password +"'")
            result = mycursor.fetchone()

            if result:
                self.close()
                mainWindow.show()
                mainWindow.label_username.setText(username)
                db_con.close()
            else:
                self.wrong_data()
        except Exception as ex:
            self.con_problem()
            print(ex)

    
    def registerF(self):
        try:
            username = self.username_input_2.text()
            password = self.password_input_2.text()
            confpass = self.confirmpass_input.text()
            
            db_con = mycon.connect(host = "localhost", user = "root", password = "dima1234", database = "diplom")
            mycursor = db_con.cursor()
            mycursor.execute("SELECT * FROM users WHERE username = '"+ username +"'")
            result = mycursor.fetchone()

            if result:
                self.login_taken()
            else:
                mycursor.execute("INSERT INTO users(username, password) VALUES('"+ username +"', '"+ password +"')")
                db_con.commit()
                print("Приятно познакомиться!")
                self.stackedWidget.setCurrentIndex(0)
        except Exception as ex:
            self.con_problem()
            print(ex)
        finally:
            db_con.close()

    
    def wrong_data(self):
        self.msg.label.setText("Неверный логин или пароль!")
        self.msg.show()

    
    def con_problem(self):
        self.msg.label.setText("Connection error! Try again later!")
        self.msg.show()


    def login_taken(self):
        self.msg.label.setText("Имя пользователя недоступно!")
        self.msg.show()


class MessageBox(QWidget):
    def __init__(self,):
        super(MessageBox, self).__init__()
        self.setFixedWidth(330)  
        self.setFixedHeight(200)  

        self.setWindowFlags(Qt.FramelessWindowHint)  
        self.setAttribute(Qt.WA_TranslucentBackground)  

        #Чтобы
        # self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.CustomizeWindowHint | Qt.WindowStaysOnTopHint)

        #создать лейаут и сделать его по центру
        self.ui_layout = QtWidgets.QGridLayout(self) 
        self.ui_layout.setAlignment(Qt.AlignCenter) 

        self.button = QPushButton("OK")
        self.button.setFont(QFont("Segoe UI", 14))
        self.button.setStyleSheet("QPushButton{\n"
                                "background-color: rgba(20,20,20,30);\n"
                                "color:rgb(255,255,255);\n"
                                "border-radius:6px;\n"
                                "}\n"
                                "QPushButton:hover{\n"
                                "background-color:rgba(20,20,20,100);\n"
                                "border-radius:6px;\n"
                                "}\n"
                                "QPushButton:pressed{\n"
                                "border: 1px solid rgba(176, 243, 241, 255);\n"
                                "background-color: rgba(20, 20, 20, 255);"
                                "border-radius:15px;\n"
                                "}")
        self.label = QtWidgets.QLabel("placeholder", self)  
        self.label.setFont(QFont("Segoe UI", 14))  
        self.label.setStyleSheet("QLabel{\n"
                                 "color: rgba(255,255,255,200);\n"
                                 "}")
        
        # self.label_title = QtWidgets.QLabel("Error", self) 
        # self.label_title.setFont(QFont("Segoe UI", 18))  
        # self.label_title.setStyleSheet("QLabel{\n"
        #                          "color: rgb(195,7,63);\n"
        #                          "margin-left:100px;\n"
        #                          "margin-bottom:30px;\n"
        #                          "}\n")
        # self.ui_layout.addWidget(self.label_title)
        self.ui_layout.addWidget(self.label) 
        self.ui_layout.addWidget(self.button)

        self.windowFX = WindowEffect()  # instatiate the WindowEffect class
        self.windowFX.setAcrylicEffect(self.winId())  # set the Acrylic effect by specifying the window id
        
        self.button.clicked.connect(lambda: self.close())


"""
AES алгоритм шифрования. Основной
"""
#создрать ключ и записать в файл
def write_key():
    key = Fernet.generate_key()
    with open('mykey.key', 'wb') as key_file:
        key_file.write(key)

#закинуть ключ в переменную
def load_key():
    return open('mykey.key', 'rb').read()

#зашифровать файл и записать
def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, 'rb') as file:
        #прочитать все из файла
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    #rewrite encrypted data
    # with open(filename, 'wb') as file:
    #     file.write(encrypted_data)
    return encrypted_data

#Расшифровать файл и записать
def decrypt(filename, key, encrypted_data):
    f = Fernet(key)
    #рсишфровать данные
    decrypted_data = f.decrypt(encrypted_data)
    #записать оригинальный файл
    with open(filename, 'wb') as file:
        file.write(decrypted_data)
    return decrypted_data


"""
RSA Ассиметричный алгоритм шифрования. Продвинутый
"""
def gen_two_keys():
    key = RSA.generate(2048)
    with open('private.pem', 'wb') as private:
        private.write(key.export_key())
    print('Приватный ключ создан! private.pem')

    with open('public.pem', 'wb') as public:
        public.write(key.publickey().export_key())
    print('Публичный ключ сохранен! public.pem')

def protect(path):
    with open(path, 'rb') as enc_file:
        encrypt_data = enc_file.read()
    
    if os.path.isfile('public.pem'):
        public_rsa = RSA.import_key(open('public.pem').read())
        session_key = get_random_bytes(16)

        #Шифруем сессионный ключ открытым ключом RSA
        chips_rsa = PKCS1_OAEP.new(public_rsa)
        enc_session_key = chips_rsa.encrypt(session_key)

        #Шифрую файл с сессионным ключом олгоритмом AES
        chips_aes = AES.new(session_key, AES.MODE_EAX)
        chips_text, tag = chips_aes.encrypt_and_digest(encrypt_data)

        with open(f'{path}.bin', 'wb') as output_file:
            for x in (enc_session_key, chips_aes.nonce, tag, chips_text):
                output_file.write(x)
        print(f'файл {path} зашифрован!')
        os.remove(path)
    else:
        print('Нема ключа!')

def unprotect(path):
    if os.path.isfile('private.pem'):
        private_key_rsa = RSA.import_key(open("private.pem").read())
        with open(path, 'rb') as input_file:
            enc_session_key, nonce, tag, chips_text = [input_file.read(x) for x in (private_key_rsa.size_in_bytes(), 16, 16, -1)]
        
        #Расшифровка сессионного ключа закрытым ключом RSA 
        chips_rsa = PKCS1_OAEP.new(private_key_rsa)
        session_key = chips_rsa.decrypt(enc_session_key)

        #Расшифровка данных сессионным ключом алоритм AES
        chips_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = chips_aes.decrypt_and_verify(chips_text, tag)
        with open(path[:-4], 'wb') as output_file:
            output_file.write(data)
        print(f'файл {path} расшифрован!')
        os.remove(path)
    else:
        print('Нема ключа!')


#App initialize
app = QApplication(sys.argv)
mainWindow = MainWindow()
app.exec_()
