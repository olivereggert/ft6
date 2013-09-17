#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       server.py
#       
#       Copyright 2012 www.idsv6.de -- contact@idsv6.de
#		Author: Oliver Eggert -- oliver.eggert@uni-potsdam.de
#
#       Licensed under Creative Commons Attribution-NonCommercial-ShareAlike 3.0
#		(see https://creativecommons.org/licenses/by-nc-sa/3.0/)
#
#		Icons via http://www.freeiconsweb.com/Free-Downloads.asp?id=1894
#      

import socket
import SocketServer
import sys
from tests import TestManager, TestICMP
import threading
from threading import Thread
import time
import re
from scapy.all import *
from subprocess import Popen
import logging

def main():
	
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

	if len(sys.argv) != 3:
		destination = interactive_startup()
	else:
		destination = (sys.argv[1], int(sys.argv[2]))
		
	SocketServer.TCPServer.allow_reuse_address = True
	SocketServer.TCPServer.address_family = socket.AF_INET6
	server = SocketServer.TCPServer(destination, Handler)
	print "IPv6 Testsuite Server listening to %s on port %d" % destination

	try:
		while True:
			server.handle_request()
	except KeyboardInterrupt:
		server.socket.settimeout(0)
		print "IPv6 Testsuite Server shutting down"
		sys.exit()
	
	
	#server.shutdown()
	
def interactive_startup():
	
	# get local ipv6 addresses. 
	ipv6_globals = []
	ipv6_locals = []

        for routes in conf.route6.routes:
            if routes[3] == "lo":
                continue
            
            for route in routes[4]:
                if in6_islladdr(route):
                    ipv6_locals.append(route)

                if in6_isgladdr(route):
                    ipv6_globals.append(route)
    
        # remove duplicates from lists
        ipv6_globals = list(set(ipv6_globals))
        ipv6_locals  = list(set(ipv6_locals))
	ipv6_addrs = ipv6_globals + ipv6_locals

	print "Usage: %s <listen address> <listen port>" % sys.argv[0]
	print "\nPlease select which address to listen to:"
		
	choice = -1
	while choice < 0 or choice > len(ipv6_addrs):
		
		count = 1
		for addr in ipv6_addrs:
			print "\t%d: %s" % (count, addr)
			count = count + 1
		
		print "\n\t0: Cancel\n"
		choice = raw_input("\tInput: ")
		
		try:
			os.system('clear')
			choice = int(choice)
		except ValueError:
			continue
				
	if choice == 0:
		sys.exit("Exiting")
	
	addr_index = choice
	
	# check for port:
	choice = -1
	
	while choice < 0 or choice > 65536:
		choice = raw_input("Please select what port to listen to (0 to exit): ")
		try:
			os.system('clear')
			choice = int(choice)
		except ValueError:
			continue
	
	if choice == 0:
		sys.exit("Exiting")
		
	port = choice
	
	# addr_index comes from user. on the ui the enumeration of addresses starts at 1,
	# in our array it starts at 0
	return (ipv6_addrs[addr_index - 1], port)	


class Handler(SocketServer.BaseRequestHandler):
	
	def handle(self):
		self.tm = TestManager()
		self.running = True

                self.client_addr = self.client_address[0]
                self.client_port = self.client_address[1]
                self.server_addr = self.server.server_address[0]
                self.server_port = self.server.server_address[1]
		
		addr = self.client_address[0]
		print "[%s] connected" % self.client_addr
		print "Ctrl-C to quit"

                # figure out link local addresses
                iface = conf.route6.route(self.client_addr)[0]
                self.target_ll = "fe80::1"
                for route in conf.route6.routes:
                    if route[3] == iface:
                        if in6_islladdr(route[4][0]):
                            self.target_ll = route[4][0]


		while self.running:
			data = self.request.recv(1024).strip()
			if data:
				print "[%s] %s" % (self.client_addr, data)
				self.handle_message(data)
			else:
				print "[%s] disconnected." % self.client_addr
				break

	# we split the received messages so that we can easily access the test numbers inside the request strings
	def handle_message(self, data):
		
		if data == "BYE":
			self.running = False
			return 
			
                if data == "InfoLinkLocal":
                    self.request.send("InfoLinkLocal " + self.target_ll)
                    return

		# we split the input string, so that the first part will always either be "StartTest" or "EndTest"
		# and the second part will always be the number of the current test.
		split_data = data.split()
		
		if len(split_data) != 2:
			sys.exit("Urgh. Received a message I didn't expect. I'll go hang myself.")
	    

		# handle start commands
		if split_data[0] == "StartTest":

                    # build filter string - have to take special care for test 8
                    if split_data[1] == 9:
                        filterstring = ""
#                        filterstring = "dst " + self.server_addr + " and udp and dst port " + self.client_port
                    else:

                        filterstring = "src " + self.client_addr

		    self.st = SnifferThread(split_data[1], filterstring)
		    self.st.start()
		        
                    # sleep a bit to give the sniffer-thread time to start up. TODO: improve this, have the snifferthread somehow signal that it's ready
                    time.sleep(1)	

		    split_data.append("ACKNOWLEDGED")
		    response =  " ".join(split_data)
			
		    self.request.send(response)
			
		# handle end commands
		if split_data[0] == "EndTest":
			split_data.append("ACKNOWLEDGED")
			response =  " ".join(split_data)
			self.request.send(response)
			packets = self.st.packets
			self.st = None
			
			# evaluate the result
			currentTest = self.tm.tests[int(split_data[1])]
			results = currentTest.evaluate(packets)
			
			print "sending StartResult %d" % int(split_data[1])
			self.request.send("StartResult %d" % int(split_data[1]))
			time.sleep(1)
			
        		for result in results:
				self.request.send(result + '\n')
							
			print "sending EndResult %d" % int(split_data[1])
			self.request.send("EndResult %d" % int(split_data[1]))
			print "EndResult %d done" % int(split_data[1])
			
class SnifferThread(threading.Thread):
	daemon = True
	
	def __init__(self, testnumber, filterstring):
		threading.Thread.__init__(self)
		self.packets = []
		self.testnumber=testnumber
                self.filterstring = filterstring

	def run(self):
		sniff(filter=self.filterstring, prn= lambda x: self.packets.append(x), stop_filter=self.stopfunction)
				
	def stopfunction(self, p):
		return str(p.lastlayer()) == "EndTest %s" % str(self.testnumber)
		
if __name__ == '__main__':
	main()
