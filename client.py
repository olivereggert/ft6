#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       client.py
#       
#       Copyright 2012 www.idsv6.de -- contact@idsv6.de
#       Author: Oliver Eggert -- oliver.eggert@uni-potsdam.de
#
#       Licensed under Creative Commons Attribution-NonCommercial-ShareAlike 3.0
#       (see https://creativecommons.org/licenses/by-nc-sa/3.0/)
#
#       Icons via http://www.freeiconsweb.com/Free-Downloads.asp?id=1894
#      


import sys
import os
import subprocess
from PyQt4 import QtGui, QtCore
from PyQt4.QtCore import SIGNAL
from PyQt4.QtGui import QMainWindow, QApplication, QStandardItemModel, QStandardItem, QDialog, QMessageBox, QListWidgetItem
from gui import Ui_MainWindow
from DetailsWindow import DetailsWindow
import socket
import time 
import pdb
import logging
import re
import errno
from PyQt4.QtGui import QCheckBox

import tests
from tests.TestManager import TestManager
from tests.TestSettings import TestSettings
from tests import *
    
# inherit from the gui so we can access the widgets
class Testsuite(QMainWindow):
    
    trigger = QtCore.pyqtSignal(int)
    socket_error = QtCore.pyqtSignal()
    update_status = QtCore.pyqtSignal(str)
    tests_finished = QtCore.pyqtSignal()
    
    demorun = False
    
    if "--demo" in sys.argv:
        demorun = True
        print "Running ft6 in demo mode!"

    def keyPressEvent(self, event):
        if type(event) == QtGui.QKeyEvent:
            if event.key() == QtCore.Qt.Key_Escape:
                self.close()

            event.accept()
        else:
            event.ignore()

    def __init__(self):
        QMainWindow.__init__(self)
        
        self.tm = TestManager.TestManager(self)

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
        self.ui.pushButton_all.hide()
        self.ui.pushButton_logFile.hide()
        
        # add all checkboxes to class variable
        self.checkboxes = []
        self.allthetests = []
        self.add_checkboxes()
        
        # attatch widgets to handlers
        self.ui.pushButton_none.clicked.connect(self.noneButtonHandler)
        self.ui.pushButton_all.clicked.connect(self.allButtonHandler)
        self.ui.pushButton_logFile.clicked.connect(self.logfileButtonHandler)
    
        if Testsuite.demorun:
            self.ui.pushButton_start.clicked.connect(self.demoButtonHandler)
            self.ui.pushButton_start.setText("Simulate")
        else:
            self.ui.pushButton_start.clicked.connect(self.startButtonHandler)
            

        # the list view needs this model
        self.model = QStandardItemModel()

        self.ui.results_listView.setModel(self.model)
        self.ui.results_listView.clicked.connect(self.listViewClickHandler)
        
        self.trigger.connect(self.testFinished)
        self.socket_error.connect(self.socketErrorHandler)
        self.update_status.connect(self.updateStatusHandler)
        self.tests_finished.connect(self.testsFinishedHandler)
        
        self.update_status.emit("Disconnected.")

        # fix the order in which pressing the tab key cycles through the widgets
        # http://stackoverflow.com/questions/9371007/programmatically-edit-tab-order-in-pyqt4-python
        self.setTabOrder(self.ui.lineEdit_target_address, self.ui.lineEdit_open_port)
        self.setTabOrder(self.ui.lineEdit_open_port, self.ui.lineEdit_closed_port)
        self.setTabOrder(self.ui.lineEdit_closed_port, self.ui.pushButton_start)

        self.loadSettings()

        
    """ shows the details for the test """
    def listViewClickHandler(self, index):
        # take into account the mapping between the list of selected test to the list of available tests
        # eg, we've selected tests [1,2,4,6]
        # the index.row() will be the n-th element of that list, eg the value '4' will be at index 2
        # so we have to translate the index (2) to the value (4). 
        # fortunately, these are stored in the allthettests list.
        # we can now ask the testmanager what the id'th test is     
        id = self.allthetests[index.row()]
        if Testsuite.demorun:
            self.demoTests[index.row()].showDetailsWindow()
        else:
            self.tm.getTest(id).showDetailsWindow()
        
    """ handles clicks to the 'None' button: uncheck all checkboxes """
    def noneButtonHandler(self):
        self.ui.pushButton_none.hide()
        self.ui.pushButton_all.show()
        
        for checkbox in self.checkboxes:
            checkbox.setChecked(0)
        
    """ handles clicks to the 'All' button: check all checkboxes """
    def allButtonHandler(self):
        self.ui.pushButton_all.hide()
        self.ui.pushButton_none.show()
        
        for checkbox in self.checkboxes:
            checkbox.setChecked(1)
                
    def saveSettings(self):
        try:
            f = open("ft6.conf", "w")
            f.write("%s\n" % str(self.ui.lineEdit_target_address.text()))
            f.write("%d\n" % int(self.ui.lineEdit_open_port.text()))
            f.write("%d\n" % int(self.ui.lineEdit_closed_port.text()))
            f.close()
        except IOError:
            print "Uh-Oh!"
            raise

    def loadSettings(self):
        settings = []
        try: 
            f = open("ft6.conf", "r")
            for i in range(3):
                settings.append(f.readline().strip())

            f.close()
        except IOError,e:
            if e[0] == errno.ENOENT:
                print "no configuration file ft6.conf found. using defaults"
                self.loadDefaults()
            else:
                raise


        if len(settings) == 3:
            self.ui.lineEdit_target_address.setText(settings[0])
            self.ui.lineEdit_open_port.setText(settings[1])
            self.ui.lineEdit_closed_port.setText(settings[2])
        else:
            print "something wrong with configuration file ft6.conf. using defaults"
            self.loadDefaults()

    def loadDefaults(self):
        self.ui.lineEdit_target_address.setText("2001:db8::1")
        self.ui.lineEdit_open_port.setText("80")
        self.ui.lineEdit_closed_port.setText("22")

    def startButtonHandler(self):
        
        inputs_are_valid = self.validate_inputs()
        if not inputs_are_valid:
            return
        
        self.lockUi(True)
        self.ui.pushButton_logFile.hide()
        
        # clear the list
        self.model.clear()
        
        self.allthetests = []

        # parse the ui settings into a TestSettings-Object
        ts = TestSettings.TestSettings(str(self.ui.lineEdit_target_address.text()), int(self.ui.lineEdit_open_port.text()), int(self.ui.lineEdit_closed_port.text()))
        
        # parse the checkboxes. Create integer indices for each test and add them to the list
        for test_id in range(len(self.checkboxes)):
            if self.checkboxes[test_id].isChecked():
                self.allthetests.append(test_id+1)  # add +1 because array indiecs start at 0
        
        # connect to the server
        try:
            self.s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            self.s.connect((ts.dst, ts.open_port, 0, 0))
            ts.add_src_addr(self.s.getsockname()[0])
        
            print "connected to [%s]:%i" % (self.s.getpeername(), 80)
        except socket.error:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setText("Socket Error. Unable to connect to the server (is it running?)")
            msg.exec_()
            self.lockUi(False)
            return
            
        self.saveSettings()     

        # create a testmanager object and tell it what tests to execute
        self.tm.tests_list = self.allthetests
        self.tm.test_settings = ts
        self.tm.s = self.s

        self.startTime = time.strftime("%d. %b %Y, at %H:%M:%S")
        self.tm.start()
            
    
    def logfileButtonHandler(self):
        
        # build log
        log = []
        
        log.append("******************************")
        log.append("* IPv6 Autotester -- Logfile *")
        log.append("******************************\n")
        log.append("Started %s\n" % self.startTime)
        
        log.append("The following tests were executed:")
        for testid in self.allthetests:
            log.append("  + %s" % self.tm.tests[testid].name)
                
        log.append("\n")
        log.append("The following tests were skipped:")
        
        for testid in self.tm.tests.keys():
            if not testid in self.allthetests:
                log.append("  - %s" % self.tm.tests[testid].name)
                
        log.append("\n\n")
        
        for testid in self.allthetests:
            currentTest = self.tm.tests[testid]
            log.append("Details for %s:" % currentTest.name)
            log.append("------------" + "-"*len(currentTest.name) + "-")
            for detail in currentTest.details:
                log.append(" + %s" % detail)
                
            log.append("\n\n")
        
        log.append("Ended %s" % self.endTime)
        
        # output
        
        try:
            currentFileName = "ft6-report-%s" % time.strftime("%d-%m-%Y_%H:%M:%S")
            filepath = os.getcwd() + os.sep + currentFileName + ".txt"
            logfile = open(filepath, 'w')
        
            for l in log:
                logfile.write(l)
                logfile.write('\n')
                
            logfile.close()
        
            # open the file in the editor - from http://stackoverflow.com/questions/434597/open-document-with-default-application-in-python
            if sys.platform.startswith('darwin'):
                subprocess.call(('open', filepath))
            elif os.name == 'nt':
                os.startfile(filepath)
            elif os.name == 'posix':
                subprocess.call(('xdg-open', filepath))
                
        except:
            print "Error writing to file. Logfile will now be printed to the console."
            raw_input("Press any key to continue.") 
            for l in log:
                print l
            
        finally:
            logfile.close()

    def fakeResult(self, input):
        raw = "ipv6-qab" + input.rjust(16, "X")
        return IPv6(dst="2001:db8::1", src="2001:db8::2")/UDP(sport=1234, dport=80)/Raw(raw)
    
    def demoButtonHandler(self):
        if not self.validate_inputs():
            return
    
        # needed so that the click listener can find the correct id's
        for test_id in range(len(self.checkboxes)):
            if self.checkboxes[test_id].isChecked():
                self.allthetests.append(test_id+1)  

        
        red = QtGui.QColor(255,64,0)
        green = QtGui.QColor(121,158,0)
        yellow = QtGui.QColor(205,249,62)

        self.lockUi(True)

        # create a bunch of demo test objects
        self.demoTests = []
        self.demoTests.append(TestICMP(1, "ICMPv6 Filtering", "", None, self))
        self.demoTests.append(TestRoutingHeader(2, "Routing Header Test", "", None, self))
        self.demoTests.append(TestHeaderChain(3, "Header Chain Test", "", None, self))
        self.demoTests.append(TestOverlappingFragments(4, "Overlapping Fragments Test", "", None, self))
        self.demoTests.append(TestTinyFramgents(5, "Tiny Fragments Test", "", None, self))
        self.demoTests.append(TestTinyFramgentsTimeout(6, "Tiny Fragments Timeout", "", None, self))
        self.demoTests.append(TestExcessiveHBHOptions(7, "Excessive Extension Options Test", "", None, self))
        self.demoTests.append(TestPadNCovertChannel(8, "PadN Covert Channel Test", "", None, self))
        self.demoTests.append(TestAddressScopes(9, "Address Scopes Test", "", None, self))

        # create a list of fake results
        fakeICMP = [self.fakeResult("Test1Type1"), self.fakeResult("Test1Type2"),
            self.fakeResult("Test1Type3Code0"), self.fakeResult("Test1Type4Code1"), 
            self.fakeResult("Test1Type4Code2"), self.fakeResult("Test1Type128"),
            self.fakeResult("Test1Type129")]

        fakeRH = [self.fakeResult("Test2Step1"), self.fakeResult("Test2Step4"),
            self.fakeResult("Test2Step5")]
        
        fakeHC = []
        for step in range(1,8):
            fakeHC.append(self.fakeResult("Test3Step%d" % step))

        fakeOverlap = [self.fakeResult("Test4Step1")]
        
        fakeTiny = []
        fakeTimeout = []

        fakeExcess = [self.fakeResult("Test6Step2"), self.fakeResult("Test6Step3"),
            self.fakeResult("Test6Step4"), self.fakeResult("Test6Step5"),
            self.fakeResult("Test6Step6"), self.fakeResult("Test6Step8")]

        fakePadN = []
        for step in range(1,5):
            fakePadN.append(self.fakeResult("Test7Step%d" % step))

        fakeAddress = []

        fakeResults = [ fakeICMP, fakeRH, fakeHC, fakeOverlap,
            fakeTiny, fakeTimeout, fakeExcess, fakePadN, fakeAddress]

        
        sleepTimes = [5, 1, 1, 1, 1, 0, 1, 1, 3]

        # iterate over all tests, call evaluate for each.
        # build gui items and set colors according to the results
        for test in self.demoTests:

            self.update_status.emit("Executing test: %s %s" % (test.name, test.statusbar_detail))
            self.repaint()
            time.sleep(sleepTimes[test.id - 1])
            item = QtGui.QStandardItem(test.name)
            item.setToolTip(test.description)
        
            results = test.evaluate(fakeResults[test.id -1 ])
            state = "Success"
            for result in results:

                if "Warning!" in (result[:8]):
                    state = "Warning"
                if "Failure!" in (result[:8]):
                    state = "Failure"
                    break

            if state is "Success":
                item.setBackground(green)
                item.setIcon(QtGui.QIcon(os.getcwd() + "/icns/success.png"))
            elif state is "Failure":
                item.setBackground(red)
                item.setIcon(QtGui.QIcon(os.getcwd() + "/icns/failure.png"))
            elif state is "Warning":
                item.setBackground(yellow)
                item.setIcon(QtGui.QIcon(os.getcwd() + "/icns/warning.png"))
    
            if test.id == 6:
                item.setBackground(yellow)
                item.setIcon(QtGui.QIcon(os.getcwd() + "/icns/warning.png"))

            self.model.appendRow(item)
            self.repaint()
            dw = DetailsWindow()
            dw.setWindowTitle("Details for %s" % test.name)

            if test.id == 6:
                item = QListWidgetItem("Information: Since Tiny Fragments can't traverse your firewall, there is no point in determining the timeout for such fragments. This test is therefore skipped!")
                dw. addDetail(item)
                test.setDetailsWindow(dw)
                continue

            for r in results:
                item = QListWidgetItem(r)
                if r.startswith("Failure"):
                    item.setBackgroundColor(red)
                if r.startswith("Warning"):
                    item.setBackgroundColor(yellow)
                if r.startswith("Success"):
                    item.setBackgroundColor(green)

                dw.addDetail(item)
            
            test.setDetailsWindow(dw)
            self.repaint()

    def validate_inputs(self):
        
        # one shared message box for all input validations
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        
        # target ip address
        try:
            dummy = socket.inet_pton(socket.AF_INET6, str(self.ui.lineEdit_target_address.text()))
        except socket.error:
            msg.setText("The target address you specified is invalid.")
            msg.exec_()
            self.ui.lineEdit_target_address.setFocus()
            return False
        except:
            msg.setText("An unknown error occurred while parsing the target address.")
            msg.exec_()
            self.ui.lineEdit_target_address.setFocus()
            return False
            
        
        # target link-local address
        #try:
        #   dummy = socket.inet_pton(socket.AF_INET6, str(self.ui.lineEdit_target_ll.text()))
        #except socket.error:
    #       msg.setText("The target link-local address you specified is invalid.")
    #       msg.exec_()
    #       self.ui.lineEdit_target_ll.setFocus()
    #       return False
    #   except:
    #       msg.setText("An unknown error occurred while parsing the target link-local address.")
    #       msg.exec_()
    #       self.ui.lineEdit_target_ll.setFocus()
    #       return False    
            
        # source link-local address
        #try:
    #       dummy = socket.inet_pton(socket.AF_INET6, str(self.ui.lineEdit_source_ll.text()))
    #   except socket.error:
    #       msg.setText("The source link-local address you specified is invalid.")
    #       msg.exec_()
    #       self.ui.lineEdit_source_ll.setFocus()
    #       return False
    #   except:
    #       msg.setText("An unknown error occurred while parsing the source link-local address.")
    #       msg.exec_()
    #       self.ui.lineEdit_source_ll.setFocus()
    #       return False    
                            
        # open port
        try:
            open_port = int(self.ui.lineEdit_open_port.text())
        except ValueError:
            msg.setText("The open port is not an integer.")
            msg.exec_()
            self.ui.lineEdit_open_port.setFocus()
            return False
        except:
            msg.setText("An unknown error occurred while parsing the open port.")
            msg.exec_()
            self.ui.lineEdit_open_port.setFocus()
            return False
            
        if open_port < 1 or open_port > 2**16:
            msg.setText("The port number for the open port must be in range 1 - 65536.")
            msg.exec_()
            self.ui.lineEdit_open_port.setFocus()
            return False
            
        # closed port
        try:
            closed_port = int(self.ui.lineEdit_closed_port.text())
        except ValueError:
            msg.setText("The closed port is not an integer.")
            msg.exec_()
            self.ui.lineEdit_closed_port.setFocus()
            return False
        except:
            msg.setText("An unknown error occurred while parsing the closed port.")
            msg.exec_()
            self.ui.lineEdit_closed_port.setFocus()
            return False
            
        if closed_port < 1 or closed_port > 2**16:
            msg.setText("The port number for the closed port must be in range 1 - 65536.")
            msg.exec_()
            self.ui.lineEdit_closed_port.setFocus()
            return False
        
        if closed_port == open_port:
            msg.setText("The port numbers for open and closed port must be different.")
            msg.exec_()
            self.ui.lineEdit_open_port.setFocus()
            return False
            
        return True
    
    """ adds all the checkboxes from the UI to the 'checkboxes' class variable """
    def add_checkboxes(self):
        
        for id, test in self.tm.tests.items():
            cb = QtGui.QCheckBox(self.ui.layoutWidget)
            cb.setChecked(True)
            cb.setObjectName("checkbox_%d" % id)
            self.ui.tests_verticalLayout.addWidget(cb)

            cb.setText(QtGui.QApplication.translate("MainWindow", self.tm.tests[id].name, None, QtGui.QApplication.UnicodeUTF8))
            self.checkboxes.append(cb)
        
        
    def testFinished(self, id):
        # build the gui item from the test object
        currentTest = self.tm.tests[id]
        
        red = QtGui.QColor(255,64,0)
        green = QtGui.QColor(121,158,0)
        yellow = QtGui.QColor(205,249,62)
        
        item = QtGui.QStandardItem(currentTest.name)
        item.setToolTip(currentTest.description)
        
        if currentTest.state is "Success":
            item.setBackground(green)
            item.setIcon(QtGui.QIcon(os.getcwd() + "/icns/success.png"))
        elif currentTest.state is "Failure":
            item.setBackground(red)
            item.setIcon(QtGui.QIcon(os.getcwd() + "/icns/failure.png"))
        elif currentTest.state is "Warning":
            item.setBackground(yellow)
            item.setIcon(QtGui.QIcon(os.getcwd() + "/icns/warning.png"))

        currentTest.setResultWidget(item)
        self.model.appendRow(item)
        
        dw = DetailsWindow()
        dw.setWindowTitle("Details for %s" % currentTest.name)
        for detail in currentTest.details:
            
            item = QListWidgetItem(detail)
            if detail.startswith("Failure"):
                item.setBackgroundColor(red)
            elif detail.startswith("Warning"):
                item.setBackgroundColor(yellow)
            elif detail.startswith("Success"):
                item.setBackgroundColor(green)
            
            dw.addDetail(item)
        
        currentTest.setDetailsWindow(dw)
        self.ui.results_GroupBox.setTitle("Results (click to view details)")


    def socketErrorHandler(self):
        msg = QMessageBox()
        msg.setText("Socket Error! Make sure the server is running.")
        msg.setIcon(QMessageBox.Critical)
        msg.exec_()
        exit()
        
    def updateStatusHandler(self, message):
        self.ui.statusbar.showMessage(message)
    
    def testsFinishedHandler(self):
        self.lockUi(False)
        self.update_status.emit("All tests finished!")
        self.ui.pushButton_logFile.show()
        self.endTime = time.strftime("%d. %b %Y, at %H:%M:%S")
        
    def lockUi(self, boolvalue):
        self.ui.pushButton_none.setDisabled(boolvalue)
        self.ui.pushButton_all.setDisabled(boolvalue)
        self.ui.pushButton_start.setDisabled(boolvalue)
        self.ui.pushButton_logFile.setDisabled(boolvalue)
        self.ui.lineEdit_target_address.setDisabled(boolvalue)
        self.ui.lineEdit_open_port.setDisabled(boolvalue)
        self.ui.lineEdit_closed_port.setDisabled(boolvalue)
    
def main():

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    
    app = QApplication(sys.argv)
    ts = Testsuite()
    
    ts.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()

