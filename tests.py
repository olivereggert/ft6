#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       tests.py
#       
#       Copyright 2012 www.idsv6.de -- contact@idsv6.de
#       Author: Oliver Eggert -- oliver.eggert@uni-potsdam.de
#
#       Licensed under Creative Commons Attribution-NonCommercial-ShareAlike 3.0
#       (see https://creativecommons.org/licenses/by-nc-sa/3.0/)
#
#       Icons via http://www.freeiconsweb.com/Free-Downloads.asp?id=1894
#     

import socket
import time
from scapy.all import *
import os
import re
from PyQt4 import QtGui, QtCore
from PyQt4.QtGui import QMessageBox

# This class is now a thread!
# code for threading from http://diotavelli.net/PyQtWiki/Threading,_Signals_and_Slots/
class TestManager(QtCore.QThread):
    def __init__(self, app=None):
        
        QtCore.QThread.__init__(self)
        self.exiting = False
        
        self.tests_list = None
        self.test_settings = None
        self.s = None
        self.app = app
        
        self.tests = dict() 
        
        # create test classes and register them with the application
        tMyTest = TestMyTest(1, "My Test", "My Test", self.test_settings, app)
        self.registerTest(tMyTest)

        #tICMP = TestICMP(1, "ICMPv6 Filtering", "The ICMP Test", self.test_settings, app)
        #self.registerTest(tICMP)        

        tRoutingHeader = TestRoutingHeader(2, "Routing Header Test", "The Routing Header Test", self.test_settings, app)
        self.registerTest(tRoutingHeader)

        tHeaderChain = TestHeaderChain(3, "Header Chain Test", "The Header Chain Test", self.test_settings, app)
        self.registerTest(tHeaderChain)     

        tOverlappingFragments = TestOverlappingFragments(4, "Overlapping Fragments Test", "The Overlapping Fragments Test", self.test_settings, app)
        self.registerTest(tOverlappingFragments)

        tTinyFragments = TestTinyFramgents(5, "Tiny Fragments Test", "The Tiny Fragments Test", self.test_settings, app)
        self.registerTest(tTinyFragments)

        tTinyFragmentsTimeout = TestTinyFramgentsTimeout(6, "Tiny Fragments Timeout", "The Tiny Fragments Timeout Test", self.test_settings, app)
        self.registerTest(tTinyFragmentsTimeout)

        tExcessiveHBH = TestExcessiveHBHOptions(7, "Excessive Extension Options Test" , "The Excessive Hop-By-Hop and Destination Options Test", self.test_settings, app)
        self.registerTest(tExcessiveHBH)

        tPadNCovertChannel = TestPadNCovertChannel(8, "PadN Covert Channel Test", "The PadN Covert Channel Test", self.test_settings, app)
        self.registerTest(tPadNCovertChannel)

        tAddressScopes = TestAddressScopes(9, "Address Scopes Test", "The Address Scopes Test", self.test_settings, app)
        self.registerTest(tAddressScopes)
    
        self.tinyFragments = tTinyFragments.id
        self.tinyFragmentsTimeout = tTinyFragmentsTimeout.id

    def __del__(self):
        self.exiting = True
        self.wait()
    
    def getTest(self, id):
        return self.tests[id]
                
    def teardown(self):
        self.s.send("BYE")
        self.s.close()
        
        print "disconnected"
        
    def registerTest(self, test):
        self.tests[test.id] = test

    def updateStatus(self, message):
        self.app.update_status.emit(message)

    def run(self):

        self.s.send("InfoLinkLocal")
        self.test_settings.target_ll = self.s.recv(1024).strip()[14:]

        print "Found that the server's link local address is %s" % self.test_settings.target_ll


        for key in self.tests_list:
    
            if key == self.tinyFragmentsTimeout and self.tests[self.tinyFragments].state != "Success":
                self.tests[key].setState("Warning")
                self.tests[key].setDescription("Warning")
                self.tests[key].addDetail("Information: This test was skipped as Tiny Fragments seem to be dropped completely. So no point in waiting") 
                self.app.trigger.emit(key)
                continue
        
            # signal the server that we're about to start the test
            self.s.send("StartTest %i" % key)
            response = self.s.recv(1024).strip()
            if response != "StartTest %d ACKNOWLEDGED" % key:
                print "Uh-Oh! While waiting for the server to respond to 'StartTest %d' we got the following reply:" % key
                print response
                sys.exit("Exiting")
            
            # now we know the server is ready for us to send the test packets
            
            self.app.update_status.emit("Executing test: %s %s" % (self.tests[key].name, self.tests[key].statusbar_detail))
            
            self.tests[key].setTestSettings(self.test_settings)
            self.tests[key].execute()

            self.app.update_status.emit("Waiting for the server's resuls for: %s" % self.tests[key].name)
            
            # That's it. Signal the server that we're done with the test packets and would now like to receive the result
            self.s.send("EndTest %i" % key)
            response = self.s.recv(1024).strip()
            if response != "EndTest %i ACKNOWLEDGED" % key:
                print "Uh-Oh! While waiting for the server to respond to 'StartTest %d' we got the following reply:" % key
                print response
                sys.exit("Exiting")
    
            # receive the result
            response = self.s.recv(1024).strip()
            if response != "StartResult %i" % key:
                print "Uh-Oh! While waiting for the server to send the result for test %d we got the following reply:" % key
                print response
                sys.exit("Exiting")
            
            result_total = ""
            done = False
            while not done:
                if ("EndResult %d" % key) in result_total:
                    done = True
                    break
                else:
                    result_total = result_total + self.s.recv(4096)#.strip()
                    
            results = [line.strip().split(':') for line in result_total.split('\n') if line.strip()]
            
            
            # check the 'aggregate state of the test': if there is at least one 'FAILURE' then the state of the whole test is 'FAILURE'
            # if there is at least one 'WARNING' then the state of the whole test is 'WARNING'. If neither is the case, the
            # state is 'SUCCESS'

            state = "Success"
            for result in results:
                if "Warning!" in (result[0])[:8]:
                    state = "Warning"
                if "Failure!" in (result[0])[:8]:
                    state = "Failure"
                    
                if state == "Failure":
                    break
            
            self.tests[key].setState(state)
            self.tests[key].setDescription(state)
            
            for result in results:
                if (result[0])[:9] != "EndResult":
                    self.tests[key].addDetail(result[0])
            
            # tell the UI that the test is finished
            self.app.trigger.emit(key)
        
        self.teardown()
        self.app.tests_finished.emit()
        

class Ft6Packet():

    payload = 'ipv6-qab'*128
    valid_states = ["Success!", "Warning!", "Failure!"]

    def __init__(self, p):
        self.p = p
        self.isValid = None
        self.payload = None

    def __str__(self):
        lines = "-"*len(self.description)
        return "%s\n%s\n  Drop:\t%s %s\n  Forward:\t%s %s\n  Tag:\t%s\n" % (self.description, lines, self.dropped_state, self.dropped_message, self.forwarded_state, self.forwarded_message, self.tag)

    def setDescription(self, d):
        self.description = d
        self.dropped_message = "The Firewall DROPPED %s." % d
        self.forwarded_message = "The Firewall FORWARDED %s." %d

    def setValid(self):
        self.isValid = True
        self.dropped_state = "Failure!"
        self.forwarded_state = "Success!"

    def setInvalid(self):
        self.isValid = False
        self.dropped_state = "Success!"
        self.forwarded_state = "Failure!"

    def ifDropped(self, message):
        self.dropped_message = self.dropped_message + " %s" % message

    def ifForwarded(self, message):
        self.forwarded_message = self.forwarded_message + " %s" % message

    def setDropState(self, state):
        if state not in Ft6Packet.valid_states:
            print "Internal Coding Error! Incorrect dropped state used for packet:"
            p.show()
            sys.exit()

        self.dropped_state = state

    def setForwardState(self, state):
        if state not in Ft6Packet.valid_states:
            print "Internal Coding Error! Incorrect forward state used for packet:"
            p.show()
            sys.exit()

        self.forwarded_state = state

    def addPayload(self, test_id, packet_id):
        self.tag = "Test%dStep%d" % (test_id, packet_id)
        if len(self.tag) > 16:
            print "Error building the packet tag."
            print "Tags are designed to be 16 characters at max."
            sys.exit()

        self.tag = self.tag.rjust(16, "X")
        self.payload = Ft6Packet.payload + self.tag
        self.p = self.p/self.payload
    

class TestSettings():
    def __init__(self, dst, open_port, closed_port):
        self.dst = dst
        self.open_port = open_port
        self.closed_port = closed_port
        
        self.build_routing_info()
        
    def add_src_addr(self, src):
        self.src = src
        print "found that the local address is %s and added it to this session's settings" % src

    
    # scapy's routing engine doesn't work properly -- it always uses the multicast mac address.
    # our Cisco ASA doesn't forward packets addressed to the multicast address, it requires individual layer 2 addresses.
    # so, we have to fix this ourselves by sending all packets at layer 2 with the sendp-function.
    # you need to pass the interface to that function, so we have to find that out too.
    # parts of this code are copied from scapy's route6
    def build_routing_info(self):
        
        try:
            self.iface = conf.route6.route(self.dst)[0]
            self.gw = conf.route6.route(self.dst)[2]
            
        except:
            print "ERROR: Couldn't find out the correct interface."

        # try to find out link local address
        for route in conf.route6.routes:
            if route[3] == self.iface:
                if in6_islladdr(route[4][0]):
                    self.source_ll = route[4][0]

        # find out the mac address of the gateway - ping the router at layer 2 so we can see the ethernet header
        e = Ether()
        i = IPv6(dst=self.gw)
        p = ICMPv6EchoRequest()
        
        packet = e/i/p
        result = srp1(packet, iface=self.iface)
        # dirty hack to make my virtual machine environment working -- fix soon!        
        if result == None:
            result = "08:00:27:c8:2a:ff"
        else:
            result = result[Ether].src
            result = str(result).lower()
        
        # see if this is actually a mac address
        mac_regex = '[0-9a-f]{2}([-:][0-9a-f]{2}){5}$'
        if not re.match( mac_regex, result ):
            print "DEBUG: there's something wrong with that mac address: %s" % result
        
        self.router_mac = result    
            
class Test(object):
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



class TestICMP(Test):
    def __init__(self, id, name, description, test_settings, app):
        super(TestICMP, self).__init__(id, name, description, test_settings, app)
        self.initICMPTypes()
        self.statusbar_detail = "(this may take a while)"
        
        
    def initICMPTypes(self):
        self.ICMPTypes = { 
                0 : "Reserved",
                1 : "Destination Unreachable",
                2 : "Packet Too Big",
                3 : "Time Exceeded",
                4 : "Parameter Problem",
                100 : "Private experimentation",
                101 : "Private experimentation",
                127 : "Reserved for expansion of ICMPv6 error messages",
                128 : "Echo Request",
                129 : "Echo Reply",
                130 : "Multicast Listener Query",
                131 : "Multicast Listener Report",
                132 : "Multicast Listener Done",
                133 : "Router Solicitation",
                134 : "Router Advertisement",
                135 : "Neighbor Solicitation",
                136 : "Neighbor Advertisement",
                137 : "Redirect Message",
                138 : "Router Renumbering",
                139 : "ICMP Node Information Query",
                140 : "ICMP Node Information Response",
                141 : "Inverse Neighbor Discovery Solicitation Message",
                142 : "Inverse Neighbor Discovery Advertisement Message",
                143 : "Version 2 Multicast Listener Report",
                144 : "Home Agent Address Discovery Request Message",
                145 : "Home Agent Address Discovery Reply Message",
                146 : "Mobile Prefix Solicitation",
                147 : "Mobile Prefix Advertisement",
                148 : "Certification Path Solicitation Message",
                149 : "Certification Path Advertisement Message",
                150 : "ICMP messages utilized by experimental mobility protocols such as Seamoby",
                151 : "Multicast Router Advertisement",
                152 : "Multicast Router Solicitation",
                153 : "Multicast Router Termination",
                154 : "FMIPv6 Messages",
                155 : "RPL Control Message",
                156 : "ILNPv6 Locator Update Message",
                157 : "Duplicate Address Request",
                158 : "Duplicate Address Confirmation",
                200 : "Private experimentation",
                201 : "Private experimentation",
                255 : "Reserved for expansion of ICMPv6 informational messages"}

        for i in range(5, 100):
            self.ICMPTypes[i] = "Unassigned ICMPv6 Error Message"

        for i in range(102, 127):
            self.ICMPTypes[i] = "Unassigned ICMPv6 Error Message"
        
        for i in range(159, 200):
            self.ICMPTypes[i] = "Unassigned ICMPv6 Informational Message"
            
        for i in range(202, 255):
            self.ICMPTypes[i] = "Unassigned ICMPv6 Informational Message"

    def execute(self):
        self.details = []

        self.send_mandatory()
        self.send_nonfiltered()
        self.send_optional()

    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
            
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        typecodes = []
        
        # do some regex magic that will convert each ICMP-Type into one of these data structures:
        #
        # [ int ICMPType, int ICMPCode, bool Done]
        # 
        # where ICMPType is the type number, ICMPCode is the code number and
        # Done represents whether this packet has already been processed and doesn't 
        # need to be examined again.
        for p in packets:
            tag = str(p.lastlayer())
                    
            # stop examining this packet if it doesn't belong to our test.
            if not "ipv6-qab" in tag:
                continue
            
            # only examine the last 16 letters
            tag = tag[-16:]
            
            icmpcode=None
            icmptype = (re.sub(r"[X]+Test1Type", "", tag))
            
            if "Code" in icmptype:
                icmpcode = re.sub(r"[0-9]+Code", "", icmptype)
                icmptype = re.sub(r"Code[0-9]+", "", icmptype)
            
            # cast icmptype and icmpcode to int
            icmptype = int(icmptype)
            if icmpcode is not None:
                icmpcode = int(icmpcode)
            
            typecodes.append([icmptype, icmpcode])
            
            
        # Set up the list of mandatory, optional and nonfiltered typenumbers to check against
        # Mandatory Filter: those MUST NOT have made it to the other side
        mandatory_numbers = [ 100, 101, 127, 148, 149, 151, 152, 153, 200, 201, 255 ]
        for i in range(130, 144):
            mandatory_numbers.append(i)
        
        # Optional Filter: those SHOULD NOT have made it to the other side
        optional_numbers = []
        for i in range(5, 100):
            optional_numbers.append(i)
        
        for i in range(102, 127):
            optional_numbers.append(i)
        
        for i in range(144, 148):
            optional_numbers.append(i)
            
        optional_numbers.append(150)
        
        for i in range(154, 200):
            optional_numbers.append(i)
        
        for i in range(202, 255):
            optional_numbers.append(i)
        
        # this list will have results
        results = []
        
        # check for packets that must not have traversed the firewall
        for number in mandatory_numbers:
            if [number, None] in typecodes:
                results.append("Failure! The firewall FORWARDED an ICMPv6 packet with type %d (%s)." % (number, self.ICMPTypes[number]))
            else:
                results.append("Success! The firewall DROPPED an ICMPv6 packet with type %d (%s)." % (number, self.ICMPTypes[number]))
        
        # check for packets that should not have traversed the firewall
        for number in optional_numbers:
            if [number, None] in typecodes:
                results.append("Warning! The firewall FORWARDED an ICMPv6 packet with type %d (%s). You should filter it unless you really need it in your network" % (number, self.ICMPTypes[number]))
            else:
                results.append("Success! The firewall DROPPED an ICMPv6 packet with type %d (%s)." % (number, self.ICMPTypes[number]))
        
        ### NOTE: Type 3 is only optional when it's code is '1'
        ### NOTE: Type 4 is only optional when it's code is '0'
        ### Big thanks to the guy who came up with the brilliant idea to have code fields!!
        if [3,1] in typecodes:
            results.append("Warning! The firewall FORWARDED an ICMPv6 packet with type 3 code 1 (%s). You should filter it unless you really need it in your network" % self.ICMPTypes[3])
        else:
            results.append("Success! The firewall DROPPED an ICMPv6 packet with type 3 code 1 (%s)." % self.ICMPTypes[3])
            
        if [4,0] in typecodes:
            results.append("Warning! The firewall FORWARDED an ICMPv6 packet with type 4 code 0 (%s). You should filter it unless you really need it in your network" % self.ICMPTypes[4])
        else:
            results.append("Success! The firewall DROPPED an ICMPv6 packet with type 4 code 0 (%s)." % self.ICMPTypes[4])
        
        # check for packets that must have traversed the firewall
        for number in [1,2]:
            if [number, None] in typecodes:
                results.append("Warning! The firewall FORWARDED an ICMPv6 packet with type %d (%s). This is technically correct, but as a message with type %d is usually in response to a request (and our server didn't even send that request) you can't be sure this behaviour is fine." % (number, self.ICMPTypes[number], number))
            else:
                results.append("Warning! The firewall DROPPED an ICMPv6 packet with type %d (%s). This is technically not correct, but as a message with type %d is usually in response to a request (and our server didn't even send that request) you can't be sure this behaviour is wrong" % (number, self.ICMPTypes[number], number))
                
        ### NOTE AGAIN! Now 3 is only nonfiltered when it's code is '0', 
        ### and 4 is only nonfiltered when it's code is either '1' or '2'
        
        if [3,0] in typecodes:
            results.append("Warning! The firewall FORWARDED an ICMPv6 packet with type 3 code 0 (%s). This is technically correct, but as a message with type 3, code 0 is usually in response to a request (and our server didn't even send that request) you can't be sure this behaviour is fine." % self.ICMPTypes[3])
        else:
            results.append("Warning! The firewall DROPPED an ICMPv6 packet with type 3 code 0 (%s). This is technically not correct, but as a message with type 3, code 0 is usually in response to a request (and our server didn't even send that request) you can't be sure this behaviour is wrong." % self.ICMPTypes[3])
        
        if [4,1] in typecodes:
            results.append("Warning! The firewall FORWARDED an ICMPv6 packet with type 4 code 1 (%s). This is technically correct, but as a message with type 4, code 1 is usually in response to a request (and our server didn't even send that request) you can't be sure this behaviour is fine." % self.ICMPTypes[3])
        else:
            results.append("Warning! The firewall DROPPED an ICMPv6 packet with type 4 code 1 (%s). This is technically not correct, but as a message with type 4, code 1 is usually in response to a request (and our server didn't even send that request) you can't be sure this behaviour is wrong." % self.ICMPTypes[3])
            
        if [4,2] in typecodes:
            results.append("Warning! The firewall FORWARDED an ICMPv6 packet with type 4 code 2 (%s). This is technically correct, but as a message with type 4, code 2 is usually in response to a request (and our server didn't even send that request) you can't be sure this behaviour is fine." % self.ICMPTypes[3])
        else:
            results.append("Warning! The firewall DROPPED an ICMPv6 packet with type 4 code 2 (%s). This is technically not correct, but as a message with type 4, code 2 is usually in response to a request (and our server didn't even send that request) you can't be sure this behaviour is wrong." % self.ICMPTypes[3])
        

        if [128, None] in typecodes:
            results.append("Success! The firewall FORWARDED an ICMPv6 packet with type %d (%s)." % (number, self.ICMPTypes[number]))
        else:
            results.append("Failure! The firewall DROPPED an ICMPv6 packet with type %d (%s)." % (number, self.ICMPTypes[number]))

        if [129, None] in typecodes:
            results.append("Success! The firewall FORWARDED an ICMPv6 packet with type %d (%s)." % (number, self.ICMPTypes[number]))
        else:
            results.append("Warning! The firewall DROPPED an ICMPv6 packet with type %d (%s). This is technically not correct, but as an Echo Reply is usually in response to a Echo Request (and our server didn't even send one) you can't be sure this behaviour is wrong" % (number, self.ICMPTypes[number]))
        
        
    
        return results      



    ### NOTE ###
    # three of the following packets are marked as being MALFORMED
    # We won't fix that here because there's no real advantage of doing so
    # (and fixing will take a lot of time)
    #
    # these packets are:
    # ICMPv6 Type 143 (MLDv2), 138 (Router Renumbering), 140 (Node Information Reply).
    # 
    ###


    # send packets that are on the mandatory filter list
    # these MUST be filtered by the firewall at all times
    def send_mandatory(self):
        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        payload="ipv6-qab" * 128 # "1024 Bytes of Payload
        
        # these types are not recognized by wireshark/tcpdump.. we can send
        # these w/o conforming to the actual packet format
        sendp(e/ip/ICMPv6Unknown(type=100, msgbody=payload+"XXXXTest1Type100"))
        sendp(e/ip/ICMPv6Unknown(type=101, msgbody=payload+"XXXXTest1Type101"))
        sendp(e/ip/ICMPv6Unknown(type=200, msgbody=payload+"XXXXTest1Type200"))
        sendp(e/ip/ICMPv6Unknown(type=201, msgbody=payload+"XXXXTest1Type201"))
        sendp(e/ip/ICMPv6Unknown(type=127, msgbody=payload+"XXXXTest1Type127"))
        sendp(e/ip/ICMPv6Unknown(type=255, msgbody=payload+"XXXXTest1Type255"))
        sendp(e/ip/ICMPv6Unknown(type=141, msgbody=payload+"XXXXTest1Type141"))
        sendp(e/ip/ICMPv6Unknown(type=142, msgbody=payload+"XXXXTest1Type142"))
        sendp(e/ip/ICMPv6Unknown(type=143, msgbody=payload+"XXXXTest1Type143"))
        sendp(e/ip/ICMPv6Unknown(type=138, msgbody=payload+"XXXXTest1Type138"))
        sendp(e/ip/ICMPv6Unknown(type=148, msgbody=payload+"XXXXTest1Type148"))
        sendp(e/ip/ICMPv6Unknown(type=149, msgbody=payload+"XXXXTest1Type149"))
        sendp(e/ip/ICMPv6Unknown(type=151, msgbody=payload+"XXXXTest1Type151"))
        sendp(e/ip/ICMPv6Unknown(type=152, msgbody=payload+"XXXXTest1Type152"))
        sendp(e/ip/ICMPv6Unknown(type=153, msgbody=payload+"XXXXTest1Type153"))

        # with the others we have to conform to the packet format and use 
        # the packets pre-defined by scapy
        sendp(e/ip/ICMPv6ND_RS()/(payload+"XXXXTest1Type133"))      # ND
        sendp(e/ip/ICMPv6ND_RA()/(payload+"XXXXTest1Type134"))
        sendp(e/ip/ICMPv6ND_NS()/(payload+"XXXXTest1Type135"))
        sendp(e/ip/ICMPv6ND_NA()/(payload+"XXXXTest1Type136"))
        sendp(e/ip/ICMPv6ND_Redirect()/(payload+"XXXXTest1Type137"))
        sendp(e/ip/ICMPv6NIQueryIPv6()/(payload+"XXXXTest1Type139"))    # Node Information
        sendp(e/ip/ICMPv6NIReplyIPv6()/(payload+"XXXXTest1Type140"))

        # MLD requires these strange options to be set.
        # src and dst have to be link-local addresses, the hop limit has to be 1
        # see http://tools.ietf.org/html/rfc2710 (chapter 3)
        ipv6_base=IPv6(src=self.test_settings.source_ll, dst=self.test_settings.target_ll, hlim=1)
        hbh= IPv6ExtHdrHopByHop(options = RouterAlert())
        
        
        sendp(e/ipv6_base/hbh/ICMPv6MLQuery()/(payload+"XXXXTest1Type130")) # MLD

        # some more options: for Report's and Done's we have to specify
        # the multicast address we are (or have finished) listening to.
        sendp(e/ipv6_base/hbh/ICMPv6MLReport(mladdr='ff01::2')/(payload+"XXXXTest1Type131")) 
        sendp(e/ipv6_base/hbh/ICMPv6MLDone(mladdr='ff01::2')/(payload+"XXXXTest1Type132"))


    # send packets that are on the optional filter list
    # these SHOULD be filtered by the firewall, but that is not neccessary.
    def send_optional(self):
        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        payload="ipv6-qab" * 128 # "1024 Bytes of Payload
        
        sendp(e/ip/ICMPv6TimeExceeded(code=1)/(payload+"XTest1Type3Code1"))
        sendp(e/ip/ICMPv6ParamProblem(code=0)/(payload+"XTest1Type4Code0"))
        sendp(e/ip/ICMPv6HAADRequest()/(payload+"XXXXTest1Type144"))    # Type 144 -> Home Agent Address Discovery Request
        sendp(e/ip/ICMPv6HAADReply()/(payload+"XXXXTest1Type145"))  # Type 145 -> Home Agent Address Discovery Reply
        sendp(e/ip/ICMPv6MPSol()/(payload+"XXXXTest1Type146"))      # Type 146 -> Mobile Prefix Solicitation
        sendp(e/ip/ICMPv6MPAdv()/(payload+"XXXXTest1Type147"))      # Type 147 -> Mobile Prefix Advertisement
        sendp(e/ip/ICMPv6Unknown(type=150, msgbody=payload+"XXXXTest1Type150")) # Seamoby
        
        for i in range(5,100):      # this should loop from 5 to 99
            typecode="Test1Type%d" % i
            typecode = typecode.rjust(16, "X")  
            sendp(e/ip/ICMPv6Unknown(type=i, msgbody=payload+typecode))

        for i in range(102,127):    # this should loop from 102 to 126
            typecode="Test1Type%d" % i
            typecode = typecode.rjust(16, "X")
            sendp(e/ip/ICMPv6Unknown(type=i, msgbody=payload+typecode))

        for i in range(154,200):    # this should loop from 154 to 199
            typecode="Test1Type%d" % i
            typecode = typecode.rjust(16, "X")
            sendp(e/ip/ICMPv6Unknown(type=i, msgbody=payload+typecode))

        for i in range(202,255):    # this should loop from 202 to 254
            typecode="Test1Type%d" % i
            typecode = typecode.rjust(16, "X")
            sendp(e/ip/ICMPv6Unknown(type=i, msgbody=payload+typecode))

                    
    # send packets that are on the nonfiltered list
    # the firewall MUST NOT drop any of these at any time
    # send some additional junk so that packets won't look malformed.
    def send_nonfiltered(self):
        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        payload="ipv6-qab" * 128 # "1024 Bytes of Payload

        sendp(e/ip/ICMPv6DestUnreach()/(payload+"XXXXXXTest1Type1"))
        sendp(e/ip/ICMPv6PacketTooBig()/(payload+"XXXXXXTest1Type2"))
        sendp(e/ip/ICMPv6TimeExceeded(code=0)/(payload+"XTest1Type3Code0"))
        sendp(e/ip/ICMPv6ParamProblem(code=1)/(payload+"XTest1Type4Code1"))
        sendp(e/ip/ICMPv6ParamProblem(code=2)/(payload+"XTest1Type4Code2"))
        sendp(e/ip/ICMPv6EchoRequest()/(payload+"XXXXTest1Type128"))
        sendp(e/ip/ICMPv6EchoReply()/(payload+"XXXXTest1Type129"))
        
class TestRoutingHeader(Test):
    
    def __init__(self, id, name, description, test_settings, app):
        super(TestRoutingHeader, self).__init__(id, name, description, test_settings, app)
        
    def execute(self):
        
        self.details = []

        # configure the settings shared between packets
        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP(dport=self.test_settings.open_port, sport=4444)
        payload="ipv6-qab"*128 # 1024 Bytes Payload
        

        # send RH Type 0 with segments left == 0
        rh=IPv6ExtHdrRouting(type=0, addresses=[self.test_settings.source_ll, self.test_settings.target_ll], segleft=0)
        packet=e/ip/rh/udp/(payload+"XXXXXXTest2Step1")

        p = Ft6Packet(e/ip/rh/udp)
        p.setValid()
        p.setDescription("")
        p.ifDropped("The firewall forwarded a valid RH")
        p.ifForwarded("The firewall dropped a valid RH")


        sendp(packet)
        
        # send RH Type 0 with segments left set to a non-zero value (arbitrarily chosen to 'two')
        rh.segleft=2
        packet=e/ip/rh/udp/(payload+"XXXXXXTest2Step2")
        sendp(packet)
        
        # send RH Type 2 with sements left set to a value other than one (arbitrarily chosen to 'two')
        rh.type=2
        rh.segleft=2
        packet=e/ip/rh/udp/(payload+"XXXXXXTest2Step3")
        sendp(packet)
        
        # send RH Type 2 with segments left set to one
        rh.type=2
        rh.segleft=1
        packet=e/ip/rh/udp/(payload+"XXXXXXTest2Step4")
        sendp(packet)
        
        # send RH with an unknown Type (arbirtrarily chosen to be '200') with segments left set to zero
        rh.type=200
        rh.segleft=0
        packet=e/ip/rh/udp/(payload+"XXXXXXTest2Step5")
        sendp(packet)

        # send RH with an unknown Type (arbitrarily chosen to be '200') with segments left set to a non-zero value
        rh.type=200
        rh.segleft=2
        packet=e/ip/rh/udp/(payload+"XXXXXXTest2Step6")
        sendp(packet)
        
        
    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())
                    
            # stop examining this packet if it doesn't belong to our test.
            if not "ipv6-qab" in tag:
                continue
            
            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test2Step", "", tag)
            
            steps.append(step)
        
        # RH 0 with segments left = 0 must make it to the other side
        if '1' in steps:
            results.append("Success! The firewall FORWARDED a 'routing header type 0' packet with 'segments left' set to zero")
        else:
            results.append("Warning! The firewall DROPPED a 'routing header type 0' packet with 'segments left' set to zero. This is not in accordance with RFC 5095. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
            
        # RH 0 with segmetns left != 0 must be dropped
        if '2' in steps:
            results.append("Failure! The firewall FORWARADED a 'routing header type 0' (with 'segments left' set to a non-zero value). This is not in accordance with RFC 5095.")
        else:
            results.append("Success! The firewall DROPPED a 'routing header type 0' packet with 'segments left' set to a non-zero value")
        
        
        
        # RH 2 with segments left != 1 must be dropped
        if '3' in steps:
            results.append("Failure! The firewall FORWARDED a 'routing header type 2' (with 'segments left' set to a value other than one). This is not in accordance with RFC 3775. Even if you need routing header 2, 'segments left' must be equal to 'one' ")
        else:
            results.append("Success! The firewall DROPPED a 'routing header type 2' packet with 'segments left' set to a value other than one")
        
        # RH 2 with segments left = 1 may make it to the other side
        if '4' in steps:
            results.append("Warning! The firewall FORWARDED a 'routing header type 2' packet with 'segments left' set to one. However, you should only allow Routing Header Type 2 if you need MobileIP Support.");
        else:
            results.append("Warning! The firewall DROPPED a 'routing header type 2' packet with 'segments left' set to one. This is not in accordance with RFC 3775. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
        
        
            
        # RH 200 with segments left = 0 may make it to the other side
        if '5' in steps:
            results.append("Warning! The firewall FORWARDED an unallocated routing header type 200 (with 'segments left' set to zero). You should filter those unless you really need it")
        else:
            results.append("Warning! The firewall DROPPED an 'unallocated routing header type 200' with 'segments left' set to zero. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
    
        # RH 200 with segments left != 0 must be dropped
        if '6' in steps:
            results.append("Failure! The firewall FORWARDED an unallocated routing header type 200 (with 'segments left' set to a non-zero value). This violates RFC 2460")
        else:
            results.append("Success! The firewall DROPPED an 'unallocated routing header type 200' with 'segments left' set to a non-zero value")

        return results

class TestHeaderChain(Test):
    def __init__(self, id, name, description, test_settings, app):
        super(TestHeaderChain, self).__init__(id, name, description, test_settings, app)
        
    def execute(self):

        self.details = []

        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP(dport=self.test_settings.open_port, sport=4444)
        payload="ipv6-qab"*128 # 1024 Bytes Payload
    
        # configure the extension headers
        dstopt=IPv6ExtHdrDestOpt()
        hbh=IPv6ExtHdrHopByHop()

        # we want the chain that contains the RH to be valid, so we have to
        # set type and segleft to something that is not deprecated
        rh=IPv6ExtHdrRouting(type=2, segleft=1, addresses=[self.test_settings.source_ll, self.test_settings.target_ll])
    
        # send a variety of different chains
        sendp(e/ip/dstopt/udp/(payload+"XXXXXXTest3Step1"))
        sendp(e/ip/hbh/udp/(payload+"XXXXXXTest3Step2"))
        sendp(e/ip/dstopt/hbh/udp/(payload+"XXXXXXTest3Step3")) # invalid
        sendp(e/ip/dstopt/dstopt/udp/(payload+"XXXXXXTest3Step4")) # invalid
        sendp(e/ip/hbh/hbh/udp/(payload+"XXXXXXTest3Step5")) # invalid
        sendp(e/ip/dstopt/rh/dstopt/udp/(payload+"XXXXXXTest3Step6"))
        sendp(e/ip/hbh/dstopt/rh/hbh/udp/(payload+"XXXXXXTest3Step7")) # invalid
        
                                      
    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())
                    
            # stop examining this packet if it doesn't belong to our test.
            if not "ipv6-qab" in tag:
                continue
             
            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test3Step", "", tag)
            
            steps.append(step)
            
        
        # iterate over steps
        if '1' not in steps:
            results.append("Failure! The firewall DROPPED a valid Destination Options header. If you didn't configure your firewall to do so this indicates that your firewall is not behaving according to official specifications")
        else:
            results.append("Success! The firewall FORWARDED a valid Destination Options header")
            
            
        if '2' not in steps:
            results.append("Failure! The firewall DROPPED a valid Hop-By-Hop header. If you didn't configure your firewall to do so this indicates that your firewall is not behaving according to official specifications")
        else:
            results.append("Success! The firewall FORWARDED a valid Hop-By-Hop header")
        
        if '3' in steps:
            results.append("Failure! The firewall FORWARDED an invalid header chain (Destination Options, Hop-By-Hop). This violates RFC 2460")
        else:
            results.append("Success! The firewall DROPPED an invalid header chain (Destination Options, Hop-By-Hop)")
        
        if '4' in steps:
            results.append("Failure! The firewall FORWARDED an invalid header chain (Destination Options, Destination Options). This violates RFC 2460")
        else:
            results.append("Success! The firewall DROPPED an invalid header chain (Destination Options, Destination Options)")
            
        if '5' in steps:
            results.append("Failure! The firewall FORWARDED an invalid header chain (Hop-By-Hop, Hop-By-Hop). This violates RFC 2460")
        else:
            results.append("Success! The firewall DROPPED an invalid header chain (Hop-By-Hop, Hop-By-Hop)")
            
        if '6' not in steps:
            results.append("Failure! The firewall DROPPED a valid header chain (Destination Options, Routing Header, Destination Options). If you didn't configure your firewall to do so this indicates that your firewall is not behaving according to official specifications")
        else:
            results.append("Success! The firewall FORWARDED a valid header chain (Destination Options, Routing Header, Destination Options)")
        
        if '7' in steps:
            results.append("Failure! The firewall FORWARDED an invalid header chain (Hop-By-Hop, Destination Options, Routing Header, Hop-By-Hop). This violates RFC 2460")
        else:
            results.append("Success! The firewall DROPPED an invalid header chain (Hop-By-Hop, Destination Options, Routing Header, Hop-By-Hop)")
        return results

class TestOverlappingFragments(Test):
    def __init__(self, id, name, description, test_settings, app):
        super(TestOverlappingFragments, self).__init__(id, name, description, test_settings, app)
        
    def execute(self):

        self.details = []

        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP(dport=self.test_settings.open_port, sport=4444)
        
        self.send_non_overlapping(ip, udp)
        self.send_overlapping_rewrite_udp(ip, udp)
        self.send_overlapping_rewrite_payload(ip, udp)
        
        
    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            if "Test4Step" not in tag:
                continue

            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test4Step", "", tag)
            
            steps.append(step)
            
        if '1' not in steps:
            results.append("Failure! The firewall DROPPED a correctly fragmented packet.")
        else:
            results.append("Success! The firewall FORWARDED forwarded a correctly fragmented packet")   
        
        if '2' in steps:
            results.append("Failure! The firewall FORWARDED overlapping fragments that rewrite the udp port.")
        else:
            results.append("Success! The firewall DROPPED overlapping fragments that rewrite the udp port")
        
        if '3' in steps:
            results.append("Failure! The firewall FORWARDED overlapping fragments that rewrite payload.")
        else:
            results.append("Success! The firewall DROPPED overlapping fragments that rewrite the payload")
        
        return results
        
    def send_non_overlapping(self, ip, udp):
        e = Ether(dst=self.test_settings.router_mac)
            
        payload='a'*128 # 1024 Bytes Payload
        payload2='b'*128
        
        # build the first fragment:
        # http://tools.ietf.org/html/rfc2460#section-4.5 specifies the Fragment Header.
        # it contains 2 'reserved'-fields. Those are set to zero
        FH1=IPv6ExtHdrFragment()
        
        FH1.res1=0
        FH1.res2=0

        # as this is the first fragment there were no fragments before this, so offset is 0
        FH1.offset=0

        # there will be another fragment following
        FH1.m=1

        # assign a randomly chosen number
        random.seed()
        rand_id = random.randint(1, 2**32)
        FH1.id=rand_id

        # assemble first packet
        packet1=e/ip/FH1/udp/(payload+"XXXXXXTest4Step1")

        # buid the second fragment
        FH2=IPv6ExtHdrFragment()
        FH2.res1=0
        FH2.res2=0

        # this will be the last fragment
        FH2.m=0

        # it belongs to the same 'original packet'
        FH2.id=rand_id

        # and we have to set Next Header to the header type of the upper layer protocol
        # from the original packet (UDP)
        # another verschlimmbesserung;-) should work now
        FH2.nh=17

        #The offset, in 8-octet units, of the data following this header,
        #relative to the start of the Fragmentable Part of the original packet.
        #
        # That's what I'm thinking:
        # We want to send 2048 bit in the original packet
        # We do this by sending 'a' (8 bit character) 256 times
        # (8 * 256 = 2048)
        # 
        # We've split the payload up into two equally sized chunks, each 1024 bit long
        # (thats 'a' 128 times)
        # 
        # So in the second fragment we start at bit #1024 (or octet #128).
        # Since 128 / 8 = 16, we need to enter 16 into the offset field. Plus the UDP Header (8 Byte, so 1 8-Byte thing)
        #
        # Let's see if that works...
        #
        # assemble second packet
        #
        # SK: sorry Oliver, you forgot the "XXXXXXTest4Step1" is another + 16 Byte!
        # so i try 19 as offset instead of 17
        FH2.offset=19

        packet2=e/ip/FH2/(payload2+"XXXXXXTest4Step1")

        sendp(packet1)
        sendp(packet2)

    def send_overlapping_rewrite_udp(self, ip, udp):
        e = Ether(dst=self.test_settings.router_mac)
        
        payload='a'*128 # 1024 Bytes Payload
        payload2='b'*128
    
        # specifically, we want to overwrite the destination port to set it to <closed_port>
        #
        # the testcase looks like this:
        # Original Packet: [IPv6][UDP (dport=<open_port>][PAYLOAD ('a' * 128)]
        #
        # Fragmentation Attack: 
        # Fragment 1: [IPv6][FRAGMENT #1][UDP (dport=<open_port>)][PAYLOAD (all of it)]
        # Fragment 2: [IPV6][FRAGMENT #2][UDP(dport=<closed_port>)][PAYLAOD (all of it again)]

        # build the first fragment:
        FH1=IPv6ExtHdrFragment()
        FH1.res1=0
        FH1.res2=0
        FH1.offset=0
        FH1.m=1

        # we have to provide a new id
        random.seed()
        rand_id=random.randint(1,2**32) 
        FH1.id=rand_id

        # assemble first packet
        packet1=e/ip/FH1/udp/(payload+"XXXXXXTest4Step2")


        # setup the second fragment.
        FH2=IPv6ExtHdrFragment()
        FH2.res1=0
        FH2.res2=0
        FH2.m=0
        FH2.id=rand_id

        # as seen in the diagram below, the udp-header in the first fragment
        # will start at address 320 or at the sixth 8-octet thing.
        FH2.offset=0 

        # replace udp port number and build packet
        fake_udp=UDP(dport=self.test_settings.closed_port,sport=4444)
        fake_packet=e/ip/FH2/fake_udp/(payload+"XXXXXXTest4Step2")
        
        # send packets
        sendp(packet1)
        sendp(fake_packet)
    
    def send_overlapping_rewrite_payload(self, ip, udp):
        e = Ether(dst=self.test_settings.router_mac)

        payload='a'*128 # 1024 Bytes Payload
        payload2='b'*128

        # this is basically the same as send_overlapping_rewrite_udp, but this time
        # we have the offset set to 7 (64 bits further into the packet than before)
        # so we end up at the beginning of the paylaod

        # build the first fragment
        FH1=IPv6ExtHdrFragment()
        FH1.res1=0
        FH1.res2=0
        FH1.offset=0
        FH1.m=1

        # we have to provide a new id
        random.seed()
        rand_id=random.randint(1,2**32)
        FH1.id=rand_id

        # assemble first packet
        packet1=e/ip/FH1/udp/(payload+"XXXXXXTest4Step3")

        # setup the second fragment.
        FH2=IPv6ExtHdrFragment()
        FH2.res1=0
        FH2.res2=0
        FH2.m=0
        FH2.id=rand_id
        FH2.offset=1
        FH2.nh=17
        # replace udp port number and build packet
        fake_payload='z'*128
        fake_packet=e/ip/FH2/(fake_payload+"XXXXXXTest4Step3")

        # send packets
        sendp(packet1)
        sendp(fake_packet)


class TestTinyFramgents(Test):
    def __init__(self, id, name, description, test_settings, app):
        super(TestTinyFramgents, self).__init__(id, name, description, test_settings, app)

    def execute(self):

        self.details = []

        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP()
        payload1='a'*128 # 1024 Bytes Payload
        payload2='b'*128 # 1024 Bytes Payload

        ### FIRST FRAGMENT ###  
        fh1=IPv6ExtHdrFragment()
        fh1.nh=17
        fh1.offset=0
        fh1.m=1

        ### SECOND FRAGMENT ###
        # offset is just after the Fragment Header.
        # That is, at bit 384 (or at the sixth 8-octet thing)
        fh2=IPv6ExtHdrFragment()
        fh2.nh=17
        fh2.offset=0
        fh2.m=1

        ### THIRD FRAGMENT ###
        # offset is at the end of the second fragment.
        # That is, at bit 1408 (or at the twentysecond 8-octet thing)
        # Better start finding a more suitable name for '8-octet thing' soon
        fh3=IPv6ExtHdrFragment()
        fh3.nh=17
        fh3.offset=17
        fh3.m=0

        self.tiny_fragment_processing(fh1, fh2, fh3, ip, udp, payload1, (payload2+"XXXXXXTest5Step1"), self.test_settings.open_port)
        self.tiny_fragment_processing(fh1, fh2, fh3, ip, udp, payload1, (payload2+"XXXXXXTest5Step2"), self.test_settings.closed_port)

    def tiny_fragment_processing(self, fh1, fh2, fh3, ip, udp, payload1, payload2, port):
        e = Ether(dst=self.test_settings.router_mac)
        
        # assign a random id
        random.seed()
        rand_id = random.randint(1, 2**32)
        fh1.id=rand_id
        fh2.id=rand_id
        fh3.id=rand_id

        packet1=e/ip/fh1
        udp=UDP(dport=port, sport=4444) 
        
        packet2=e/ip/fh2/udp/payload1
        packet3=e/ip/fh3/payload2

        sendp(packet1)
        sendp(packet2)
        sendp(packet3)
        
        
    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            if "Test5Step" not in tag:
                continue

            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test5Step", "", tag)
            
            steps.append(step)
        
        if '1' in steps:
            results.append("Success! The firewall FORWARDED the whole packet although there was no upper layer header present in the first fragment.")
        else:
            results.append("Failure! The firewall DROPPED the whole packet just because there was no upper layer header present in the first fragment. Also, the upper layer header didn't use a forbidden port!")
            
        if '2' in steps:
            results.append("Failure! The firewall FORWARDED a fragmented packet to a forbidden port. It appears your firewall does only inspect the first fragment.")
        else:
            results.append("Success! The firewall DROPPED a packet that had the upper layer protocol (targetting a forbidden port) in the second fragment.")
            
        return results
        
    

class TestTinyFramgentsTimeout(Test):
    def __init__(self, id, name, description, test_settings, app):
        super(TestTinyFramgentsTimeout, self).__init__(id, name, description, test_settings, app)
        self.statusbar_detail = "(takes about two minutes)"

    def execute(self):

        self.details = []

        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP()
        payload1='a'*128 # 1024 Bytes Payload
        payload2='b'*128 # 1024 Bytes Payload

        ### FIRST FRAGMENT ###  
        fh1=IPv6ExtHdrFragment()
        fh1.nh=17
        fh1.offset=0
        fh1.m=1

        ### SECOND FRAGMENT ###
        # offset is just after the Fragment Header.
        # That is, at bit 384 (or at the sixth 8-octet thing)
        fh2=IPv6ExtHdrFragment()
        fh2.nh=17
        fh2.offset=0
        fh2.m=1

        ### THIRD FRAGMENT ###
        # offset is at the end of the second fragment.
        # That is, at bit 1408 (or at the twentysecond 8-octet thing)
        # Better start finding a more suitable name for '8-octet thing' soon
        fh3=IPv6ExtHdrFragment()
        fh3.nh=17
        fh3.offset=17
        fh3.m=0

        self.tiny_fragment_timeout(fh1, fh2, fh3, ip, udp, payload1, (payload2+"XXXXXXTest5Step3"), 60)
        self.tiny_fragment_timeout(fh1, fh2, fh3, ip, udp, payload1, (payload2+"XXXXXXTest5Step4"), 61)

        
    def tiny_fragment_timeout(self, fh1, fh2, fh3, ip, udp, payload1, payload2, waiting_time):
        e = Ether(dst=self.test_settings.router_mac)
        
        # assign a random id
        random.seed()
        rand_id = random.randint(1, 2**32)
        fh1.id=rand_id
        fh2.id=rand_id
        fh3.id=rand_id

        packet1=e/ip/fh1
        packet2=e/ip/fh2/UDP(dport=self.test_settings.open_port, sport=4444)/payload1
        packet3=e/ip/fh3/payload2

        # send first and last packet
        sendp(packet1)
        sendp(packet3)

        # wait for timeout (was that 60 seconds?!)
        print "Waiting for " + str(waiting_time) + " sec."
        time.sleep(waiting_time)
    
        sendp(packet2)
        print "Done"
        
    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            if "Test5Step" not in tag:
                continue

            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test5Step", "", tag)
            
            steps.append(step)
        
        
        if '3' not in steps:
            results.append("Warning! The firewall DROPPED a fragment arriving late. After 60 seconds the packet should still have been forwarded but was dropped. This is not in accordance with the RFCs, but not that big of a deal")
        else:
            results.append("Success! The firewall FORWARDED a fragment arriving late packets. After 60 seconds the packet was still forwarded.")
        
        if '4' in steps:
            results.append("Failure! The firewall FORWARDED a fragment arriving too late. After 61 seconds the packet should have been dropped but was still forwarded.")
        else:
            results.append("Success! The firewall DROPPED a fragment arriving too late. After 61 seconds the packet was dropped.")
            
        return results
        



    
class TestExcessiveHBHOptions(Test):
    def __init__(self, id, name, description, test_settings, app):
        super(TestExcessiveHBHOptions, self).__init__(id, name, description, test_settings, app)
        
    def execute(self):

        self.details = []

        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP(dport=self.test_settings.open_port, sport=4444)
        payload='ipv6-qab'*128 # 1024 Bytes Payload
        
        
        # Test 1a: JumboPayload, PadN, JumboPayload in a Hop-By-Hop Header.
        hbh = '\x11\x01\xc2\x04\x00\x10\x00\x00\x01\x00\xC2\x04\x00\x10\x00\x00'

        ip.nh=0
        packet=e/ip/hbh/udp/(payload+"XXXXXXTest6Step1")
        sendp(packet)
        
        # Test 1b: JumboPayload, PadN, JumboPayload in a Destination Options Header.
        ip.nh= 60
        packet=e/ip/hbh/udp/(payload+"XXXXXXTest6Step2")
        sendp(packet)
        

        
        # Test 2a: Router Alert, Pad1, Router Alert in a Hop-By-Hop Header
        opts=RouterAlert()/Pad1()/RouterAlert()
        packet = e/ip/IPv6ExtHdrHopByHop(options=opts)/udp/(payload+"XXXXXXTest6Step3")
        sendp(packet)

        # Test 2b: Router Alert, Pad1, Router Alert in a Destination Options Header
        packet = e/ip/IPv6ExtHdrDestOpt(options=opts)/udp/(payload+"XXXXXXTest6Step4")
        sendp(packet)
            
        
        
        # Test 3a: Quick Start. Tunnel Encapsulatipon Limit, PadN, Quick Start in a Hop-By-Hop Header
        opts = "\x11\x02\x26\x06\x08\x99\x9B\x3D\x1D\xD6\x04\x01\x2A\x01\x01\x00\x26\x06\x08\x29\x34\x59\x81\x06"
        ip.nh = 0
        packet = e/ip/opts/udp/(payload+"XXXXXXTest6Step5")
        sendp(packet)
    
        # Test 3b: Quick Start. Tunnel Encapsulatipon Limit, PadN, Quick Start in a Destination Options Header
        ip.nh = 60  
        packet = e/ip/opts/udp/(payload+"XXXXXXTest6Step6")
        sendp(packet)
        
    
        # Test 4a: RPL Option, PadN, RPL Option in a Hop-By-Hop Header
        rpl = HBHOptUnknown(otype=0x63, optlen=4, optdata="\x00\x66\x00\x00")
        opts = "\x11\x01\x63\x04\x00\x66\x00\x00\x01\x00\x63\x04\x00\x66\x00\x00"
        ip.nh = 0
        packet = e/ip/opts/udp/(payload+"XXXXXXTest6Step7")
        sendp(packet)

        # Test 4b: RPL Option, PadN, RPL Option in a Hop-By-Hop Header
        ip.nh = 60
        packet = e/ip/opts/udp/(payload+"XXXXXXTest6Step8")
        sendp(packet)
        
        
    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            if "Test6Step" not in tag:
                continue

            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test6Step", "", tag)
            
            steps.append(step)
            
        
        if '1' in steps:
            results.append("Failure! The firewall FORWARDED a packet with the following invalid Hop-By-Hop Options Chain (Jumbo Payload, PadN, Jumbo Payload). See RFC 4942, section 2.1.9.4")
        else:
            results.append("Success! The firewall DROPPED a packet with the following invalid Hop-By-Hop Options Chain (Jumbo Payload, PadN, Jumbo Payload).")
            
        if '2' in steps:
            results.append("Failure! The firewall FORWARDED a packet with the following invalid Destination Options Chain (Jumbo Payload, PadN, Jumbo Payload). See RFC 4942, section 2.1.9.4")
        else:
            results.append("Success! The firewall DROPPED a packet with the following invalid Destination Options Chain (Jumbo Payload, PadN, Jumbo Payload).")
        
        if '3' in steps:
            results.append("Failure! The firewall FORWARDED a packet with the following invalid Hop-By-Hop Options Chain (Router Alert, Pad1, Router Alert). See RFC 4942, section 2.1.9.4")
        else:
            results.append("Success! The firewall DROPPED a packet with the following invalid Hop-By-Hop Options Chain (Router Alert, Pad1, Router Alert).")
            
        if '4' in steps:
            results.append("Failure! The firewall FORWARDED a packet with the following invalid Destination Options Chain (Router Alert, Pad1, Router Alert). See RFC 4942, section 2.1.9.4")
        else:
            results.append("Success! The firewall DROPPED a packet with the following invalid Destination Options Chain (Router Alert, Pad1, Router Alert).")
            
        if '5' in steps:
            results.append("Failure! The firewall FORWARDED a packet with the following invalid Hop-By-Hop Options Chain (Quick Start. Tunnel Encapsulatipon Limit, PadN, Quick Start). See RFC 4942, section 2.1.9.4")
        else:
            results.append("Success! The firewall DROPPED a packet with the following invalid Hop-By-Hop Options Chain (Quick Start. Tunnel Encapsulatipon Limit, PadN, Quick Start).")
            
            
        if '6' in steps:
            results.append("Failure! The firewall FORWARDED a packet with the following invalid Destination Options Chain (Quick Start. Tunnel Encapsulatipon Limit, PadN, Quick Start). See RFC 4942, section 2.1.9.4")
        else:
            results.append("Success! The firewall DROPPED a packet with the following invalid Destination Options Chain (Quick Start. Tunnel Encapsulatipon Limit, PadN, Quick Start).")
        
        if '7' in steps:
            results.append("Failure! The firewall FORWARDED a packet with the following invalid Hop-By-Hop Options Chain (RPL Option, PadN, RPL Option). See RFC 4942, section 2.1.9.4")
        else:
            results.append("Success! The firewall DROPPED a packet with the following invalid Hop-By-Hop Options Chain (RPL Option, PadN, RPL Option).")
            
        if '8' in steps:
            results.append("Failure! The firewall FORWARDED a packet with the following invalid Destination Options Chain (RPL Option, PadN, RPL Option). See RFC 4942, section 2.1.9.4")
        else:
            results.append("Success! The firewall DROPPED a packet with the following invalid Destination Options Chain (RPL Option, PadN, RPL Option).")
            
            
        return results
        
class TestPadNCovertChannel(Test):
    def __init__(self, id, name, description, test_settings, app):
        super(TestPadNCovertChannel, self).__init__(id, name, description, test_settings, app)
        
    def execute(self):
        
        self.details = []

        e = Ether(dst=self.test_settings.router_mac)
                
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP(dport=self.test_settings.open_port, sport=4444)
        payload='ipv6-qab'*128 # 1024 Bytes Payload


        ### send a valid packet ###
        packet = e/ip/IPv6ExtHdrHopByHop(options=PadN(optlen=4, optdata="\x00\x00\x00\x00"))/udp/(payload+"XXXXXXTest7Step1")
        sendp(packet)


        ### send an invalid packet ###
        packet = e/ip/IPv6ExtHdrHopByHop(options=PadN(optlen=4, optdata="\x08\x15\x23\x42"))/udp/(payload+"XXXXXXTest7Step2")
        sendp(packet)


        packet = e/ip/IPv6ExtHdrDestOpt(options=PadN(optlen=4, optdata="\x00\x00\x00\x00"))/udp/(payload+"XXXXXXTest7Step3")
        sendp(packet)


        ### send an invalid packet ###
        packet = e/ip/IPv6ExtHdrDestOpt(options=PadN(optlen=4, optdata="\x08\x15\x23\x42"))/udp/(payload+"XXXXXXTest7Step4")
        sendp(packet)
    
                
    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))

        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            if "Test7Step" not in tag:
                continue

            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test7Step", "", tag)
            
            steps.append(step)
        
        if '1' not in steps:
            results.append("Failure! The firewall DROPPED a packet containing a Hop-By-Hop header with a valid PadN option.")
        else:
            results.append("Success! The firewall FORWARDED a packet containing a Hop-By-Hop header with a valid PadN option.")
        
        if '2' in steps:
            results.append("Failure! The firewall FORWARDED a packet containing a Hop-By-Hop header with a PadN option with non-zero payload (possibly a covert channel)")
        else:
            results.append("Success! The firewall DROPPED a packet containing a Hop-By-Hop header with a PadN option with non-zero payload (possibly a covert channel)")
            
        if '3' not in steps:
            results.append("Failure! The firewall DROPPED a packet containing a Destination Option header with a valid PadN option.")
        else:
            results.append("Success! The firewall FORWARDED a packet containing a Destination Option header with a valid PadN option.")
            
        if '4' in steps:
            results.append("Failure! The firewall FORWARDED a packet containing a Destination Option header with a PadN option with non-zero payload (possibly a covert channel)")
        else:
            results.append("Success! The firewall DROPPED a packet containing a Destination Option header with a PadN option with non-zero payload (possibly a covert channel)")
        
        return results
    
class TestAddressScopes(Test):
    def __init__(self, id, name, description, test_settings, app):
        super(TestAddressScopes, self).__init__(id, name, description, test_settings, app)
        self.statusbar_detail = "(this may take a while)"
        
    def execute(self):
        
        self.details = []

        e = Ether(dst=self.test_settings.router_mac)
        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP(dport=self.test_settings.open_port, sport=4444)
        payload='ipv6-qab'*128 # 1024 Bytes Payload

        self.test(0xff00, 0xffff, e, ip, udp, (payload+"XXXXXXTest8Step1"))
        self.test(0xfe80, 0xfebf, e, ip, udp, (payload+"XXXXXXTest8Step2")) 
        

    def test(self, addr_base, addr_max, e, ip, udp, payload):

        for mcast_current in range(addr_base, addr_max+1):
            source_addr = str(hex(mcast_current)).replace("0x", "")+ "::1"
            
            ip.src=source_addr
            sendp(e/ip/udp/payload)


    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))

        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            if "Test8Step" not in tag:
                continue

            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test8Step", "", tag)
            
            steps.append(step)
        
        if '1' in steps:
            results.append("Failure! The firewall FORWARDED packets addressed to a multicast address.")
        else:
            results.append("Success! The firewall DROPPED all packets addressed to a multicast address.")
        
        if '2' in steps:
            results.append("Failure! The firewall FORWARDED packets addressed to a link-local address.")
        else:
            results.append("Success! The firewall DROPPED all packets addressed to a link-local address.")
        
        return results
 

class TestMyTest(Test):
    
    def __init__(self, id, name, description, test_settings, app):
        super(TestMyTest, self).__init__(id, name, description, test_settings, app)

    def prepare(self):

        # configure the settings shared between packets
        if not hasattr(self, "test_settings") or self.test_settings == None:
            e = Ether()
            ip = IPv6()
            udp = UDP()
            source_ll = ""
            target_ll = ""
        else :
            e = Ether(dst=self.test_settings.router_mac)
            ip = IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
            udp = UDP(dport=self.test_settings.open_port, sport=4444)
            source_ll = self.test_settings.source_ll
            target_ll = self.test_settings.target_ll

        rh=IPv6ExtHdrRouting(type=0, addresses=[source_ll, target_ll], segleft=0)
        p = Ft6Packet(e/ip/rh/udp)
        p.setValid()
        p.setDescription("a valid Routing Header Type 0, with 'segments left' set to zero") 
        p.ifDropped("This is violates RFC 5095. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
        p.setDropState("Warning!")
        self._addPacket(p)

        rh.segleft=2
        p = Ft6Packet(e/ip/rh/udp)
        p.setInvalid()
        p.setDescription("an invalid Routing Header Type 0, with 'segments left' set to a non-zero value (2).")
        p.ifForwarded("This is violates RFC 5095.")
        self._addPacket(p)

        rh.type=2
        rh.segleft=2
        p = Ft6Packet(e/ip/rh/udp)
        p.setInvalid()
        p.setDescription("an invalid Routing Header Type 2, with 'segments left' set to a value other than one.")
        p.ifForwarded("This violates RFC 3775. Even if you need RH2, 'segments left' must be equal to 'one'.")
        self._addPacket(p)

        rh.type=2
        rh.segleft=1
        p = Ft6Packet(e/ip/rh/udp)
        p.setValid()
        p.setDescription("a valid Routing Header Type 2, with 'segments left' set to 'one'.")
        p.ifForwarded("However, you should only Routing Header Type 2 if you need MobileIP Support.")
        p.ifDropped("This violates RFC 3775. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
        p.setForwardState("Warning!")
        p.setDropState("Warning!")
        self._addPacket(p)

        rh.type=200
        rh.segleft=0
        p = Ft6Packet(e/ip/rh/udp)
        p.setValid()
        p.setDescription("a valid but unallocated Routing Header Type 200, with 'segments left' set to zero.")
        p.ifForwarded("You should filter those unless you really need them.")
        p.ifDropped("However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
        p.setForwardState("Warning!")
        p.setDropState("Warning!")
        self._addPacket(p)

        rh.type=200
        rh.segleft=2
        p = Ft6Packet(e/ip/rh/udp)
        p.setInvalid()
        p.setDescription("an invalid, unallocated Routing Header Type 200, with 'segments left' set to a non-zero value (2).")
        p.ifForwarded("This violates RFC 2460.")
        self._addPacket(p)

    def _addPacket(self, p):
        self._num_packets = self._num_packets + 1
        p.addPayload(self.id, self._num_packets)

        self.packets.append(p)

    def execute(self):
        
        self.details = []

        self.prepare()
        for i in range(len(self.packets)):
            sendp(self.packets[i].p)
            self.app.update_status.emit("Executing Test %d (%s). Sending Packet %d of %d." % (self.id, self.name, i+1, len(self.packets)))
            time.sleep(1)

    def evaluate(self, packets):
        
        self.prepare()
        
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        tags = []
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            # stop examining this packet if it doesn't belong to our test.
            if not "ipv6-qab" in tag:
                continue
            
            # only examine the last 16 letters
            tag = tag[-16:]
            tags.append(tag) 
            

        for packet in self.packets:
            
            if packet.tag in tags:
                results.append(packet.forwarded_state + packet.forwarded_message)
            else:
                results.append(packet.dropped_state + packet.dropped_message)

        return results

##        # RH 0 with segments left = 0 must make it to the other side
#        if '1' in steps:
#            results.append("Success! The firewall FORWARDED a 'routing header type 0' packet with 'segments left' set to zero")
#        else:
#            results.append("Warning! The firewall DROPPED a 'routing header type 0' packet with 'segments left' set to zero. This is not in accordance with RFC 5095. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
#            
#        # RH 0 with segmetns left != 0 must be dropped
#        if '2' in steps:
#            results.append("Failure! The firewall FORWARADED a 'routing header type 0' (with 'segments left' set to a non-zero value). This is not in accordance with RFC 5095.")
#        else:
#            results.append("Success! The firewall DROPPED a 'routing header type 0' packet with 'segments left' set to a non-zero value")
#        
#        
#        
#        # RH 2 with segments left != 1 must be dropped
#        if '3' in steps:
#            results.append("Failure! The firewall FORWARDED a 'routing header type 2' (with 'segments left' set to a value other than one). This is not in accordance with RFC 3775. Even if you need routing header 2, 'segments left' must be equal to 'one' ")
#        else:
#            results.append("Success! The firewall DROPPED a 'routing header type 2' packet with 'segments left' set to a value other than one")
#        
#        # RH 2 with segments left = 1 may make it to the other side
#        if '4' in steps:
#            results.append("Warning! The firewall FORWARDED a 'routing header type 2' packet with 'segments left' set to one. However, you should only allow Routing Header Type 2 if you need MobileIP Support.");
#        else:
#            results.append("Warning! The firewall DROPPED a 'routing header type 2' packet with 'segments left' set to one. This is not in accordance with RFC 3775. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
#        
#        
#            
#        # RH 200 with segments left = 0 may make it to the other side
#        if '5' in steps:
#            results.append("Warning! The firewall FORWARDED an unallocated routing header type 200 (with 'segments left' set to zero). You should filter those unless you really need it")
#        else:
#            results.append("Warning! The firewall DROPPED an 'unallocated routing header type 200' with 'segments left' set to zero. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
#    
#        # RH 200 with segments left != 0 must be dropped
#        if '6' in steps:
#            results.append("Failure! The firewall FORWARDED an unallocated routing header type 200 (with 'segments left' set to a non-zero value). This violates RFC 2460")
#        else:
#            results.append("Success! The firewall DROPPED an 'unallocated routing header type 200' with 'segments left' set to a non-zero value")
#    
#        return results

