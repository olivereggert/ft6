from PyQt4 import QtCore
from tests import *
from scapy.all import *

class BaseTest(object):
    def __init__(self, id, name, description, test_settings=None, app=None):
        self.id = id
        self.name = name
        self.description = description
        self.details = []
        self.statusbar_detail = ""
        self.app = app
        self._num_packets = 0
        self.packets = []

    def execute(self):
        pass
        
    def evaluate(self):
        pass

    def setResultWidget(self, w):
        self.widget = w

    def setState(self, state):
        if state not in set(('Success', 'Failure', 'Warning', 'Running')):
            exit("CodingError. This should not happen. See tests.py:setState()")
            
        self.state = state

    def setDescription(self, description):
        self.description = description
        
    def addDetail(self, detail):
        self.details.append(detail)
        
    def setDetailsWindow(self, dw):
        self.detailsWindow = dw
        
    def showDetailsWindow(self):
        self.detailsWindow.show()

    def setTestSettings(self, test_settings):
        self.test_settings = test_settings

        conf.verb = False
        if test_settings:
            conf.iface = test_settings.iface

    def _addPacket(self, p):
        self._num_packets = self._num_packets + 1
        p.addPayload(self.id, self._num_packets)

        self.packets.append(p)

    def _getPacket(self, tag):
        for packet in self.packets:
            if packet.tag == tag:
                return packet

        return None
