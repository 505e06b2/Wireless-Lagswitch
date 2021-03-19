#!/usr/bin/env python3

from ipaddress import ip_network as net_range #makes the following shorter

take_two_ip_ranges = [net_range(x) for x in ["185.56.65.0/24", "192.81.240.0/21"]]
microsoft_ip_ranges = [net_range(x) for x in ["20.33.0.0/16", "20.40.0.0/13", "20.128.0.0/16", "20.36.0.0/14", "20.48.0.0/12", "20.34.0.0/15", "20.64.0.0/10"]]

ip_range_blacklist = take_two_ip_ranges + microsoft_ip_ranges

import os, sys, scapy.all as net, packet_analysis, ipaddress

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

import argparse

def filterPacket(raw):
	packet = net.IP(raw.get_payload())
	if net.DNS in packet or net.ICMP in packet: #ignore there as they're not used for "actual" game netcode
		return

	IP = packet[net.IP]
	remote_ip = IP.dst if IP.src == machines["target"].ip else IP.src
	remote_address = ipaddress.ip_address(remote_ip)

	for x in ip_range_blacklist:
		if remote_address in x:
			raw.drop()
			return

	raw.accept()


parser = argparse.ArgumentParser()
parser.add_argument("--gateway_ip")
parser.add_argument("--target_ip")
parser.add_argument("--target_mac")

parser.add_argument("--game_protocol")
parser.add_argument("--game_port")
args = parser.parse_args()

print("Finding network devices...")
machines = get_machines.search(
	ps4=True,
	gateway_ip=args.gateway_ip,
	target_ip=args.target_ip,
	mac_startswith=args.target_mac
)

game_settings = {}
if args.game_protocol: game_settings["game_protocol"] = args.game_protocol
game_settings["game_port"] = args.game_port if args.game_port else 6672

#will default to UDP
network_thread = packet_analysis.NFQueueThread(machines["target"], callback=filterPacket, **game_settings)
try:
	print("Starting nfqueue...")
	network_thread.start()
	network_thread.join()

except KeyboardInterrupt:
	print("Closing...")

except Exception as e:
	print(e)




