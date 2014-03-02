import tests
from scapy.all import *
from tests.Ft6Packet import Ft6Packet

class TestExcessiveHBHOptions(tests.BaseTest):
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
