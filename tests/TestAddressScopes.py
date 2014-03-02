import tests
from scapy.all import *
from tests.Ft6Packet import Ft6Packet

class TestAddressScopes(tests.BaseTest):
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
