#!/usr/bin/env python3

import scapy.all as net
import sys, time, math
import get_machines

VERBOSITY = 0

print("Finding network devices...")
machines = get_machines.search(ps4=True)

print("Restoring ARP...")
net.send(net.ARP(op="who-has", hwdst="ff:ff:ff:ff:ff:ff", pdst=machines["target"].ip, hwsrc=machines["gateway"].mac, psrc=machines["gateway"].ip), verbose=VERBOSITY)
net.send(net.ARP(op="who-has", hwdst="ff:ff:ff:ff:ff:ff", pdst=machines["gateway"].ip, hwsrc=machines["target"].mac, psrc=machines["target"].ip), verbose=VERBOSITY)

