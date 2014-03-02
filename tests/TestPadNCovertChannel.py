import tests
from scapy.all import *
from tests.Ft6Packet import Ft6Packet

class TestPadNCovertChannel(tests.BaseTest):
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
