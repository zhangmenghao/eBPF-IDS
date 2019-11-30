#!/usr/bin/env python

import sys
from scapy.all import *

if __name__ == '__main__':
	if len(sys.argv) < 3:
		print("pass 2 arguments: <T/I/U> <payload>")
		sys.exit(1)
	print sys.argv[0],sys.argv[1],sys.argv[2]
	pkt=Ether(src="1e:01:78:dd:9d:70", dst = "ce:44:a4:e1:74:1a")/IPv6(src="fc00:dead:cafe:1::2", dst="fc00:dead:cafe:1::1")
	if sys.argv[1] == 'T':
		pkt = pkt/TCP()/Raw(sys.argv[2])
	elif sys.argv[1] == 'I':
		pkt = pkt/ICMPv6EchoRequest()
	elif sys.argv[1] == 'U':
		pkt = pkt/UDP()/Raw(sys.argv[2])
	else:
		print "Error!"
	pkt.show()
	send(pkt)