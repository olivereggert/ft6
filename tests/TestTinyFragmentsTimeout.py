import tests
from scapy.all import *

class TestTinyFragmentsTimeout(tests.BaseTest):
    def __init__(self, id, name, description, test_settings, app):
        super(TestTinyFragmentsTimeout, self).__init__(id, name, description, test_settings, app)
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
