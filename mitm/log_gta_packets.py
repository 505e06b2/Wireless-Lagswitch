#!/usr/bin/env python3

import os, sys, scapy.all as net, packet_analysis

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

import ipaddress
import ipinfo #python3 -m pip install ipinfo
ip_handler = ipinfo.getHandler("c74b5a4469d554") #will only work from my IP

local_colour = "\x1b[96m"
remote_colour = "\x1b[91m"

take_two_ip_ranges = ["185.56.65."] + [f"192.81.24{x}." for x in range(0, 8)]
microsoft_ip_ranges = [f"20.{x}." for x in range(33, 129)]
ip_range_whitelist = take_two_ip_ranges + microsoft_ip_ranges

catalogue = {}

def logPacket(raw):
	raw.accept()
	packet = net.IP(raw.get_payload())
	if net.DNS in packet or net.ICMP in packet: #ignore there as they're not used for "actual" game netcode
		return

	IP = packet[net.IP]
	remote_ip = IP.dst if IP.src == machines["target"].ip else IP.src
	if not ipaddress.ip_address(remote_ip).is_global: #skip if internal
		return
	for x in ip_range_whitelist:
		if remote_ip.startswith(x):
			return
	remote_port = IP.dport if IP.src == machines["target"].ip else IP.sport

	ip_info = catalogue.get(remote_ip)
	if not ip_info:
		catalogue[remote_ip] = ip_handler.getDetails(remote_ip)
		ip_info = catalogue[remote_ip]
	else: #don't need to display more than once
		return

	if not ip_info:
		return

	"""
	if remote_ip.startswith("52.40.62."): #SONY/Amazon
		return
	"""

	if IP.src == machines["target"].ip:
		if IP.sport != 6672: return
		try:
			print(f"{IP.dst:>15} {ip_info.org}")
		except AttributeError:
			print(f"{IP.dst:>15} ???")
	else:
		if IP.dport != 6672: return
		try:
			print(f"{IP.src:>15} {ip_info.org}")
		except AttributeError:
			print(f"{IP.dst:>15} ???")

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




