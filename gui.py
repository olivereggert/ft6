# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui.ui'
#
# Created: Wed Jun 19 15:24:05 2013
#      by: PyQt4 UI code generator 4.7.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

class Ui_MainWindow(object):
	def setupUi(self, MainWindow):
		MainWindow.setObjectName("MainWindow")
		MainWindow.resize(535, 500)
		sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
		sizePolicy.setHorizontalStretch(0)
		sizePolicy.setVerticalStretch(0)
		sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
		MainWindow.setSizePolicy(sizePolicy)
		MainWindow.setMinimumSize(QtCore.QSize(535, 500))
		MainWindow.setMaximumSize(QtCore.QSize(535, 500))
		self.centralwidget = QtGui.QWidget(MainWindow)
		self.centralwidget.setObjectName("centralwidget")
		self.settings_GroupBox = QtGui.QGroupBox(self.centralwidget)
		self.settings_GroupBox.setGeometry(QtCore.QRect(10, 10, 500, 101))
		self.settings_GroupBox.setMinimumSize(QtCore.QSize(0, 0))
		self.settings_GroupBox.setMaximumSize(QtCore.QSize(16777215, 16777215))
		self.settings_GroupBox.setObjectName("settings_GroupBox")
		self.gridLayoutWidget = QtGui.QWidget(self.settings_GroupBox)
		self.gridLayoutWidget.setGeometry(QtCore.QRect(10, 20, 480, 71))
		self.gridLayoutWidget.setObjectName("gridLayoutWidget")
		self.settings_gridLayout = QtGui.QGridLayout(self.gridLayoutWidget)
		self.settings_gridLayout.setObjectName("settings_gridLayout")
		self.label_target_address = QtGui.QLabel(self.gridLayoutWidget)
		self.label_target_address.setObjectName("label_target_address")
		self.settings_gridLayout.addWidget(self.label_target_address, 0, 0, 1, 1)
		self.label_open_port = QtGui.QLabel(self.gridLayoutWidget)
		self.label_open_port.setObjectName("label_open_port")
		self.settings_gridLayout.addWidget(self.label_open_port, 3, 0, 1, 1)
		self.lineEdit_open_port = QtGui.QLineEdit(self.gridLayoutWidget)
		self.lineEdit_open_port.setMaxLength(5)
		self.lineEdit_open_port.setObjectName("lineEdit_open_port")
		self.settings_gridLayout.addWidget(self.lineEdit_open_port, 3, 1, 1, 1)
		self.label_closed_port = QtGui.QLabel(self.gridLayoutWidget)
		self.label_closed_port.setObjectName("label_closed_port")
		self.settings_gridLayout.addWidget(self.label_closed_port, 3, 2, 1, 1)
		self.lineEdit_closed_port = QtGui.QLineEdit(self.gridLayoutWidget)
		self.lineEdit_closed_port.setMaxLength(5)
		self.lineEdit_closed_port.setObjectName("lineEdit_closed_port")
		self.settings_gridLayout.addWidget(self.lineEdit_closed_port, 3, 3, 1, 1)
		self.lineEdit_target_address = QtGui.QLineEdit(self.gridLayoutWidget)
		self.lineEdit_target_address.setObjectName("lineEdit_target_address")
		self.settings_gridLayout.addWidget(self.lineEdit_target_address, 0, 1, 1, 3)
		self.tests_groupBox = QtGui.QGroupBox(self.centralwidget)
		self.tests_groupBox.setGeometry(QtCore.QRect(10, 110, 245, 361))
		self.tests_groupBox.setObjectName("tests_groupBox")
		self.pushButton_none = QtGui.QPushButton(self.tests_groupBox)
		self.pushButton_none.setGeometry(QtCore.QRect(10, 250, 93, 27))
		self.pushButton_none.setObjectName("pushButton_none")
		self.layoutWidget = QtGui.QWidget(self.tests_groupBox)
		self.layoutWidget.setGeometry(QtCore.QRect(10, 20, 210, 212))
		self.layoutWidget.setObjectName("layoutWidget")
		self.tests_verticalLayout = QtGui.QVBoxLayout(self.layoutWidget)
		self.tests_verticalLayout.setObjectName("tests_verticalLayout")
		self.pushButton_start = QtGui.QPushButton(self.tests_groupBox)
		self.pushButton_start.setGeometry(QtCore.QRect(130, 250, 93, 27))
		self.pushButton_start.setObjectName("pushButton_start")
		self.pushButton_all = QtGui.QPushButton(self.tests_groupBox)
		self.pushButton_all.setEnabled(True)
		self.pushButton_all.setGeometry(QtCore.QRect(10, 250, 93, 27))
		self.pushButton_all.setAutoDefault(False)
		self.pushButton_all.setObjectName("pushButton_all")
		self.results_GroupBox = QtGui.QGroupBox(self.centralwidget)
		self.results_GroupBox.setGeometry(QtCore.QRect(265, 110, 245, 361))
		self.results_GroupBox.setObjectName("results_GroupBox")
		self.results_listView = QtGui.QListView(self.results_GroupBox)
		self.results_listView.setGeometry(QtCore.QRect(10, 20, 225, 301))
		self.results_listView.setSpacing(2)
		self.results_listView.setWordWrap(True)
		self.results_listView.setObjectName("results_listView")
		self.pushButton_logFile = QtGui.QPushButton(self.results_GroupBox)
		self.pushButton_logFile.setGeometry(QtCore.QRect(80, 330, 80, 27))
		self.pushButton_logFile.setObjectName("pushButton_logFile")
		MainWindow.setCentralWidget(self.centralwidget)
		self.statusbar = QtGui.QStatusBar(MainWindow)
		self.statusbar.setObjectName("statusbar")
		MainWindow.setStatusBar(self.statusbar)

		self.retranslateUi(MainWindow)
		QtCore.QMetaObject.connectSlotsByName(MainWindow)

	def retranslateUi(self, MainWindow):
		MainWindow.setWindowTitle(QtGui.QApplication.translate("MainWindow", "IPv6 Firewall Testsuite", None, QtGui.QApplication.UnicodeUTF8))
		self.settings_GroupBox.setTitle(QtGui.QApplication.translate("MainWindow", "Settings", None, QtGui.QApplication.UnicodeUTF8))
		self.label_target_address.setText(QtGui.QApplication.translate("MainWindow", "target address", None, QtGui.QApplication.UnicodeUTF8))
		self.label_open_port.setText(QtGui.QApplication.translate("MainWindow", "open port", None, QtGui.QApplication.UnicodeUTF8))
		self.lineEdit_open_port.setText(QtGui.QApplication.translate("MainWindow", "80", None, QtGui.QApplication.UnicodeUTF8))
		self.label_closed_port.setText(QtGui.QApplication.translate("MainWindow", "closed port", None, QtGui.QApplication.UnicodeUTF8))
		self.lineEdit_closed_port.setText(QtGui.QApplication.translate("MainWindow", "22", None, QtGui.QApplication.UnicodeUTF8))
		self.lineEdit_target_address.setText(QtGui.QApplication.translate("MainWindow", "2001:2:2::b", None, QtGui.QApplication.UnicodeUTF8))
		self.tests_groupBox.setTitle(QtGui.QApplication.translate("MainWindow", "Tests", None, QtGui.QApplication.UnicodeUTF8))
		self.pushButton_none.setText(QtGui.QApplication.translate("MainWindow", "None", None, QtGui.QApplication.UnicodeUTF8))
		self.pushButton_start.setText(QtGui.QApplication.translate("MainWindow", "Start", None, QtGui.QApplication.UnicodeUTF8))
		self.pushButton_all.setText(QtGui.QApplication.translate("MainWindow", "All", None, QtGui.QApplication.UnicodeUTF8))
		self.results_GroupBox.setTitle(QtGui.QApplication.translate("MainWindow", "Results", None, QtGui.QApplication.UnicodeUTF8))
		self.pushButton_logFile.setText(QtGui.QApplication.translate("MainWindow", "create logfile", None, QtGui.QApplication.UnicodeUTF8))

