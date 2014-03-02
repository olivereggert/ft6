import tests
from scapy.all import *
from tests.Ft6Packet import Ft6Packet

class TestHeaderChain(tests.BaseTest):
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
