#!/usr/bin/env python3

from ipaddress import ip_network, IPv4Address
import sys

take_two_ip_ranges = [ip_network(x) for x in ["185.56.65.0/24", "192.81.240.0/21"]]
microsoft_ip_ranges = [ip_network(x) for x in ["20.33.0.0/16", "20.40.0.0/13", "20.128.0.0/16", "20.36.0.0/14", "20.48.0.0/12", "20.34.0.0/15", "20.64.0.0/10"]]
blacklist = take_two_ip_ranges + microsoft_ip_ranges
#blacklist = [ip_network("192.168.0.0/24")]

with open("source/blacklist.c", "w") as f:
	f.write("//generated with generate_blacklisted_ips.py\n")
	f.write("#include \"routing.h\"\n")
	f.write("BlacklistRange_t blacklisted_ips[] = {")
	for x in blacklist:
		start = int.from_bytes(x[0].packed, byteorder=sys.byteorder) #try to keep byte-order as consistent and portable as possible
		end = int.from_bytes(x[-1].packed, byteorder=sys.byteorder)
		f.write("{0x%x,0x%x}," % (start, end))
	f.write("{0,0}};") #null at end
