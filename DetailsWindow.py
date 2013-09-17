#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       DetailsWindow.py
#       
#       Copyright 2012 www.idsv6.de -- contact@idsv6.de
#		Author: Oliver Eggert -- oliver.eggert@uni-potsdam.de
#
#       Licensed under Creative Commons Attribution-NonCommercial-ShareAlike 3.0
#		(see https://creativecommons.org/licenses/by-nc-sa/3.0/)
#
#		Icons via http://www.freeiconsweb.com/Free-Downloads.asp?id=1894
#      


from details import Ui_Dialog
from PyQt4.QtGui import QDialog
class DetailsWindow(QDialog):
	def __init__(self):
		QDialog.__init__(self)
		
		self.ui = Ui_Dialog()
		self.ui.setupUi(self)
		
	def addDetail(self, item):
		
		self.ui.listWidget.addItem(item)

	def show(self):
		self.exec_()
