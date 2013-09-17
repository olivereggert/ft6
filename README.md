# ft6 -- the firewall tester for IPv6

Got a firewall? Think it is _ipv6-ready_? With ft6 you can find out just _how_ ready it is!
ft6 is a _client-server_ program written in python that tests various IPv6 related features and security aspects.

## Meta

First things first: This is a fork of the software developed during [this project](http://www.idsv6.de/en). The project was held at University of Potsdam and is now finished.
I was a student assistent working on the project and programmer of ft6.
I now continue to develop ft6 on my own, without any involvement of the university.

My thanks to [all](http://cs.uni-potsdam.de/bs) [project](http://prof.beuth-hochschule.de/scheffler) [associates](http://www.eantc.de)

## License

Ft6 is released under [CC BY-NC-SA 3.0](http://creativecommons.org/licenses/by-nc-sa/3.0/).


## Setup
To use ft6 you'll need two machines connected directly to your firewall.
On the _'internal'_ side of the firewall, run ./server.py. On the _'external'_ side, run ./client.py
Again: ft6 assumes that there is a firewall in between the client and server.

Once started the _client_ sends a number of packets to the _server_. The server captures the packets and can figure
out which packets didn't make it through the firewall. All 'missing' packets are assumed to have been dropped by the firewall.
The _server_ then sends a list of _results_ back to the _client_. Finally, the _client_ displays the results in the 
graphcial user interface.


## Requirements
ft6 is powered by 

- [python](http://www.python.org/)
- [scapy](http://www.secdev.org/projects/scapy/)
- [pyqt](http://www.riverbankcomputing.co.uk/software/pyqt/intro)

Make sure to use correct versions!

- python 2.7 -- python3 is currently not supported
- scapy 2.2.0 -- on scapy's download page the 'latest' version is only 2.1.0 (!) Use [this](http://www.secdev.org/projects/scapy/files/scapy-2.2.0.tar.gz) link to manually download scapy-2.2.0
- pyqt 4

It is supported for Linux, currently tested for Debian Linux 6.0
Other OSes may work, too.
