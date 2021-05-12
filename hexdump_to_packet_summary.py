#!/usr/bin/env python3

import scapy.all as net

raw_packet = open("/tmp/packet_hexdump.bytes", "rb").read()
net.Ether(raw_packet).show()
