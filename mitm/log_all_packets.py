#!/usr/bin/env python3

import os, sys, scapy.all as net, packet_analysis

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

local_colour = "\x1b[96m"
remote_colour = "\x1b[91m"

def logPacket(raw):
	raw.accept()
	packet = net.IP(raw.get_payload())
	if net.DNS in packet or net.ICMP in packet: #ignore there as they're not used for "actual" game netcode
		return

	IP = packet[net.IP]
	remote_ip = IP.src if IP.src == machines["target"].ip else IP.dst

	left = (local_colour if IP.src == machines["target"].ip else remote_colour) + f"{IP.src:>15}:{IP.sport:<5}\x1b[0m"
	right = (local_colour if IP.dst == machines["target"].ip else remote_colour) + f"{IP.dst:>15}:{IP.dport:<5}\x1b[0m"
	print(f"{left} > {right}")

print("Finding network devices...")
machines = get_machines.search(ps4=True)

#will default to UDP
network_thread = packet_analysis.NFQueueThread(machines["target"], callback=logPacket)
try:
	print("Starting nfqueue...")
	network_thread.start()
	network_thread.join()

except KeyboardInterrupt:
	print("Closing...")

except Exception as e:
	print(e)




