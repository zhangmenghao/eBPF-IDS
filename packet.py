#!/usr/bin/env python

import sys
from scapy.all import *

str = "dog"
pkt=Ether(src="1e:01:78:dd:9d:70", dst = "ce:44:a4:e1:74:1a")/IPv6(src="fc00:dead:cafe:1::2", dst="fc00:dead:cafe:1::1")/TCP()/Raw(str)
pkt.show()
send(pkt)