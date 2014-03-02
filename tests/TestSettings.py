from scapy.all import *

class TestSettings():
    def __init__(self, dst, open_port, closed_port):
        self.dst = dst
        self.open_port = open_port
        self.closed_port = closed_port
        
        self.build_routing_info()
        
    def add_src_addr(self, src):
        self.src = src
        print "found that the local address is %s and added it to this session's settings" % src

    
    # scapy's routing engine doesn't work properly -- it always uses the multicast mac address.
    # our Cisco ASA doesn't forward packets addressed to the multicast address, it requires individual layer 2 addresses.
    # so, we have to fix this ourselves by sending all packets at layer 2 with the sendp-function.
    # you need to pass the interface to that function, so we have to find that out too.
    # parts of this code are copied from scapy's route6
    def build_routing_info(self):
        
        try:
            self.iface = conf.route6.route(self.dst)[0]
            self.gw = conf.route6.route(self.dst)[2]
            
        except:
            print "ERROR: Couldn't find out the correct interface."

        # try to find out link local address
        for route in conf.route6.routes:
            if route[3] == self.iface:
                if in6_islladdr(route[4][0]):
                    self.source_ll = route[4][0]

        # find out the mac address of the gateway - ping the router at layer 2 so we can see the ethernet header
        e = Ether()
        i = IPv6(dst=self.gw)
        p = ICMPv6EchoRequest()
        
        packet = e/i/p
        result = srp1(packet, iface=self.iface)
        # dirty hack to make my virtual machine environment working -- fix soon!        
        if result == None:
            result = "08:00:27:c8:2a:ff"
        else:
            result = result[Ether].src
            result = str(result).lower()
        
        # see if this is actually a mac address
        mac_regex = '[0-9a-f]{2}([-:][0-9a-f]{2}){5}$'
        if not re.match( mac_regex, result ):
            print "DEBUG: there's something wrong with that mac address: %s" % result
        
        self.router_mac = result    
