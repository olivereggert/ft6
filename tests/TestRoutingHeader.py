import tests
from scapy.all import *
from tests.Ft6Packet import Ft6Packet

class TestRoutingHeader(tests.BaseTest):
    
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
