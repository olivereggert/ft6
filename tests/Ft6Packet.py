
class Ft6Packet():
    payload = 'ipv6-qab'*128
    valid_states = ["Success!", "Warning!", "Failure!"]

    def __init__(self, p):
        self.p = p
        self.isValid = None
        self.payload = None

    def __str__(self):
        lines = "-"*len(self.description)
        return "%s\n%s\n  Drop:\t%s %s\n  Forward:\t%s %s\n  Tag:\t%s\n" % (self.description, lines, self.dropped_state, self.dropped_message, self.forwarded_state, self.forwarded_message, self.tag)

    def setDescription(self, d):
        self.description = d
        self.dropped_message = "The Firewall DROPPED %s." % d
        self.forwarded_message = "The Firewall FORWARDED %s." %d

    def setValid(self):
        self.isValid = True
        self.dropped_state = "Failure!"
        self.forwarded_state = "Success!"

    def setInvalid(self):
        self.isValid = False
        self.dropped_state = "Success!"
        self.forwarded_state = "Failure!"

    def ifDropped(self, message):
        self.dropped_message = self.dropped_message + " %s" % message

    def ifForwarded(self, message):
        self.forwarded_message = self.forwarded_message + " %s" % message

    def setDropState(self, state):
        if state not in Ft6Packet.valid_states:
            print "Internal Coding Error! Incorrect dropped state used for packet:"
            p.show()
            sys.exit()

        self.dropped_state = state

    def setForwardState(self, state):
        if state not in Ft6Packet.valid_states:
            print "Internal Coding Error! Incorrect forward state used for packet:"
            p.show()
            sys.exit()

        self.forwarded_state = state

    def addPayload(self, test_id, packet_id):
        self.tag = "Test%dStep%d" % (test_id, packet_id)
        if len(self.tag) > 16:
            print "Error building the packet tag."
            print "Tags are designed to be 16 characters at max."
            sys.exit()

        self.tag = self.tag.rjust(16, "X")
        self.payload = Ft6Packet.payload + self.tag
        self.p = self.p/self.payload

