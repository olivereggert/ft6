from tests.TestMyTest import TestMyTest
from tests.TestICMP import TestICMP
from tests.TestRoutingHeader import TestRoutingHeader
from tests.TestOverlappingFragments import TestOverlappingFragments
from tests.TestHeaderChain import TestHeaderChain
from tests.TestTinyFragments import TestTinyFragments
from tests.TestTinyFragmentsTimeout import TestTinyFragmentsTimeout
from tests.TestExcessiveHBHOptions import TestExcessiveHBHOptions
from tests.TestPadNCovertChannel import TestPadNCovertChannel
from tests.TestAddressScopes import TestAddressScopes

from PyQt4 import QtCore


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

        tTinyFragments = TestTinyFragments(5, "Tiny Fragments Test", "The Tiny Fragments Test", self.test_settings, app)
        self.registerTest(tTinyFragments)

        tTinyFragmentsTimeout = TestTinyFragmentsTimeout(6, "Tiny Fragments Timeout", "The Tiny Fragments Timeout Test", self.test_settings, app)
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
