import tests
from tests.Ft6Packet import Ft6Packet
from scapy.all import *

class TestICMP(tests.BaseTest):
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
