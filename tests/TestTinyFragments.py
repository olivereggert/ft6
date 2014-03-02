import tests
from scapy.all import *

class TestTinyFragments(tests.BaseTest):
    def __init__(self, id, name, description, test_settings, app):
        super(TestTinyFragments, self).__init__(id, name, description, test_settings, app)

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
