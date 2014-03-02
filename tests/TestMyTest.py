import tests
from tests.Ft6Packet import Ft6Packet
from scapy.all import *

class TestMyTest(tests.BaseTest):
    
    def __init__(self, id, name, description, test_settings, app):
        super(TestMyTest, self).__init__(id, name, description, test_settings, app)

    def prepare(self):

        # configure the settings shared between packets
        if not hasattr(self, "test_settings") or self.test_settings == None:
            e = Ether()
            ip = IPv6()
            udp = UDP()
            source_ll = ""
            target_ll = ""
        else :
            e = Ether(dst=self.test_settings.router_mac)
            ip = IPv6(dst=self.test_settings.dst, src=self.test_settings.src)
            udp = UDP(dport=self.test_settings.open_port, sport=4444)
            source_ll = self.test_settings.source_ll
            target_ll = self.test_settings.target_ll

        rh=IPv6ExtHdrRouting(type=0, addresses=[source_ll, target_ll], segleft=0)
        p = Ft6Packet(e/ip/rh/udp)
        p.setValid()
        p.setDescription("a valid Routing Header Type 0, with 'segments left' set to zero") 
        p.ifDropped("This is violates RFC 5095. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
        p.setDropState("Warning!")
        self._addPacket(p)

        rh.segleft=2
        p = Ft6Packet(e/ip/rh/udp)
        p.setInvalid()
        p.setDescription("an invalid Routing Header Type 0, with 'segments left' set to a non-zero value (2).")
        p.ifForwarded("This is violates RFC 5095.")
        self._addPacket(p)

        rh.type=2
        rh.segleft=2
        p = Ft6Packet(e/ip/rh/udp)
        p.setInvalid()
        p.setDescription("an invalid Routing Header Type 2, with 'segments left' set to a value other than one.")
        p.ifForwarded("This violates RFC 3775. Even if you need RH2, 'segments left' must be equal to 'one'.")
        self._addPacket(p)

        rh.type=2
        rh.segleft=1
        p = Ft6Packet(e/ip/rh/udp)
        p.setValid()
        p.setDescription("a valid Routing Header Type 2, with 'segments left' set to 'one'.")
        p.ifForwarded("However, you should only Routing Header Type 2 if you need MobileIP Support.")
        p.ifDropped("This violates RFC 3775. However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
        p.setForwardState("Warning!")
        p.setDropState("Warning!")
        self._addPacket(p)

        rh.type=200
        rh.segleft=0
        p = Ft6Packet(e/ip/rh/udp)
        p.setValid()
        p.setDescription("a valid but unallocated Routing Header Type 200, with 'segments left' set to zero.")
        p.ifForwarded("You should filter those unless you really need them.")
        p.ifDropped("However, many firewalls chose to drop Routing Headers in general, so dropping this valid header is in some way better than forwarding the invalid header!")
        p.setForwardState("Warning!")
        p.setDropState("Warning!")
        self._addPacket(p)

        rh.type=200
        rh.segleft=2
        p = Ft6Packet(e/ip/rh/udp)
        p.setInvalid()
        p.setDescription("an invalid, unallocated Routing Header Type 200, with 'segments left' set to a non-zero value (2).")
        p.ifForwarded("This violates RFC 2460.")
        self._addPacket(p)

    def _addPacket(self, p):
        self._num_packets = self._num_packets + 1
        p.addPayload(self.id, self._num_packets)

        self.packets.append(p)

    def execute(self):
        
        self.details = []

        self.prepare()
        for i in range(len(self.packets)):
            sendp(self.packets[i].p)
            self.app.update_status.emit("Executing Test %d (%s). Sending Packet %d of %d." % (self.id, self.name, i+1, len(self.packets)))
            time.sleep(1)

    def evaluate(self, packets):
        
        self.prepare()
        
        print "Evaluating the %s Test. Got %d packets" % (self.name, len(packets))
        
        results = []
        
        # store the the last 16 Characters of the uppermost layer of every packet.
        # those should contain the strings that tell the server which packets arrived
        steps = []
        tags = []
        # do some minor regex magic that will prase out the "step numbers" of all tags that have "test2" in them
        for p in packets:
            tag = str(p.lastlayer())

            # stop examining this packet if it doesn't belong to our test.
            if not "ipv6-qab" in tag:
                continue
            
            # only examine the last 16 letters
            tag = tag[-16:]
            tags.append(tag) 
            

        for packet in self.packets:
            
            if packet.tag in tags:
                results.append(packet.forwarded_state + packet.forwarded_message)
            else:
                results.append(packet.dropped_state + packet.dropped_message)

        return results

