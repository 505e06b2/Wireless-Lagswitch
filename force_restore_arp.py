#!/usr/bin/env python3

import scapy.all as net
import sys, time, math
from utils import get_machines

VERBOSITY = 0

print("Finding network devices...")
machines = get_machines.default()

print("Restoring ARP...")
net.send(net.ARP(op="who-has", hwdst="ff:ff:ff:ff:ff:ff", pdst=machines["ps4"].ip, hwsrc=machines["gateway"].mac, psrc=machines["gateway"].ip), verbose=VERBOSITY)
net.send(net.ARP(op="who-has", hwdst="ff:ff:ff:ff:ff:ff", pdst=machines["gateway"].ip, hwsrc=machines["ps4"].mac, psrc=machines["ps4"].ip), verbose=VERBOSITY)

