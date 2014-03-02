import tests
from scapy.all import *
from tests.Ft6Packet import Ft6Packet

class TestOverlappingFragments(tests.BaseTest):
    def __init__(self, id, name, description, test_settings, app):
        super(TestOverlappingFragments, self).__init__(id, name, description, test_settings, app)
        
    def execute(self):

        self.details = []

        ip=IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
        udp=UDP(dport=self.test_settings.open_port, sport=4444)
        
        self.send_non_overlapping(ip, udp)
        self.send_overlapping_rewrite_udp(ip, udp)
        self.send_overlapping_rewrite_payload(ip, udp)
        
        
    def evaluate(self, packets):
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            if "Test4Step" not in tag:
                continue

            # only examine the last 16 letters
            tag = tag[-16:]
            step = re.sub(r"[X]+Test4Step", "", tag)
            
            steps.append(step)
            
        if '1' not in steps:
            results.append("Failure! The firewall DROPPED a correctly fragmented packet.")
        else:
            results.append("Success! The firewall FORWARDED forwarded a correctly fragmented packet")   
        
        if '2' in steps:
            results.append("Failure! The firewall FORWARDED overlapping fragments that rewrite the udp port.")
        else:
            results.append("Success! The firewall DROPPED overlapping fragments that rewrite the udp port")
        
        if '3' in steps:
            results.append("Failure! The firewall FORWARDED overlapping fragments that rewrite payload.")
        else:
            results.append("Success! The firewall DROPPED overlapping fragments that rewrite the payload")
        
        return results
        
    def send_non_overlapping(self, ip, udp):
        e = Ether(dst=self.test_settings.router_mac)
            
        payload='a'*128 # 1024 Bytes Payload
        payload2='b'*128
        
        # build the first fragment:
        # http://tools.ietf.org/html/rfc2460#section-4.5 specifies the Fragment Header.
        # it contains 2 'reserved'-fields. Those are set to zero
        FH1=IPv6ExtHdrFragment()
        
        FH1.res1=0
        FH1.res2=0

        # as this is the first fragment there were no fragments before this, so offset is 0
        FH1.offset=0

        # there will be another fragment following
        FH1.m=1

        # assign a randomly chosen number
        random.seed()
        rand_id = random.randint(1, 2**32)
        FH1.id=rand_id

        # assemble first packet
        packet1=e/ip/FH1/udp/(payload+"XXXXXXTest4Step1")

        # buid the second fragment
        FH2=IPv6ExtHdrFragment()
        FH2.res1=0
        FH2.res2=0

        # this will be the last fragment
        FH2.m=0

        # it belongs to the same 'original packet'
        FH2.id=rand_id

        # and we have to set Next Header to the header type of the upper layer protocol
        # from the original packet (UDP)
        # another verschlimmbesserung;-) should work now
        FH2.nh=17

        #The offset, in 8-octet units, of the data following this header,
        #relative to the start of the Fragmentable Part of the original packet.
        #
        # That's what I'm thinking:
        # We want to send 2048 bit in the original packet
        # We do this by sending 'a' (8 bit character) 256 times
        # (8 * 256 = 2048)
        # 
        # We've split the payload up into two equally sized chunks, each 1024 bit long
        # (thats 'a' 128 times)
        # 
        # So in the second fragment we start at bit #1024 (or octet #128).
        # Since 128 / 8 = 16, we need to enter 16 into the offset field. Plus the UDP Header (8 Byte, so 1 8-Byte thing)
        #
        # Let's see if that works...
        #
        # assemble second packet
        #
        # SK: sorry Oliver, you forgot the "XXXXXXTest4Step1" is another + 16 Byte!
        # so i try 19 as offset instead of 17
        FH2.offset=19

        packet2=e/ip/FH2/(payload2+"XXXXXXTest4Step1")

        sendp(packet1)
        sendp(packet2)

    def send_overlapping_rewrite_udp(self, ip, udp):
        e = Ether(dst=self.test_settings.router_mac)
        
        payload='a'*128 # 1024 Bytes Payload
        payload2='b'*128
    
        # specifically, we want to overwrite the destination port to set it to <closed_port>
        #
        # the testcase looks like this:
        # Original Packet: [IPv6][UDP (dport=<open_port>][PAYLOAD ('a' * 128)]
        #
        # Fragmentation Attack: 
        # Fragment 1: [IPv6][FRAGMENT #1][UDP (dport=<open_port>)][PAYLOAD (all of it)]
        # Fragment 2: [IPV6][FRAGMENT #2][UDP(dport=<closed_port>)][PAYLAOD (all of it again)]

        # build the first fragment:
        FH1=IPv6ExtHdrFragment()
        FH1.res1=0
        FH1.res2=0
        FH1.offset=0
        FH1.m=1

        # we have to provide a new id
        random.seed()
        rand_id=random.randint(1,2**32) 
        FH1.id=rand_id

        # assemble first packet
        packet1=e/ip/FH1/udp/(payload+"XXXXXXTest4Step2")


        # setup the second fragment.
        FH2=IPv6ExtHdrFragment()
        FH2.res1=0
        FH2.res2=0
        FH2.m=0
        FH2.id=rand_id

        # as seen in the diagram below, the udp-header in the first fragment
        # will start at address 320 or at the sixth 8-octet thing.
        FH2.offset=0 

        # replace udp port number and build packet
        fake_udp=UDP(dport=self.test_settings.closed_port,sport=4444)
        fake_packet=e/ip/FH2/fake_udp/(payload+"XXXXXXTest4Step2")
        
        # send packets
        sendp(packet1)
        sendp(fake_packet)
    
    def send_overlapping_rewrite_payload(self, ip, udp):
        e = Ether(dst=self.test_settings.router_mac)

        payload='a'*128 # 1024 Bytes Payload
        payload2='b'*128

        # this is basically the same as send_overlapping_rewrite_udp, but this time
        # we have the offset set to 7 (64 bits further into the packet than before)
        # so we end up at the beginning of the paylaod

        # build the first fragment
        FH1=IPv6ExtHdrFragment()
        FH1.res1=0
        FH1.res2=0
        FH1.offset=0
        FH1.m=1

        # we have to provide a new id
        random.seed()
        rand_id=random.randint(1,2**32)
        FH1.id=rand_id

        # assemble first packet
        packet1=e/ip/FH1/udp/(payload+"XXXXXXTest4Step3")

        # setup the second fragment.
        FH2=IPv6ExtHdrFragment()
        FH2.res1=0
        FH2.res2=0
        FH2.m=0
        FH2.id=rand_id
        FH2.offset=1
        FH2.nh=17
        # replace udp port number and build packet
        fake_payload='z'*128
        fake_packet=e/ip/FH2/(fake_payload+"XXXXXXTest4Step3")

        # send packets
        sendp(packet1)
        sendp(fake_packet)
