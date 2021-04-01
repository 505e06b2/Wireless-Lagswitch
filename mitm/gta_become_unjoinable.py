#!/usr/bin/env python3

from ipaddress import ip_network as net_range #makes the following shorter

take_two_ip_ranges = [net_range(x) for x in ["185.56.65.0/24", "192.81.240.0/21"]]
microsoft_ip_ranges = [net_range(x) for x in ["20.33.0.0/16", "20.40.0.0/13", "20.128.0.0/16", "20.36.0.0/14", "20.48.0.0/12", "20.34.0.0/15", "20.64.0.0/10"]]

ip_range_blacklist = take_two_ip_ranges + microsoft_ip_ranges

import os, sys, scapy.all as net, packet_analysis, ipaddress

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines


class Unjoinable(packet_analysis.NFQueueThread):
	def __init__(self, stdout=True):
		if stdout: print("Finding network devices...")
		self.machines = get_machines.search(ps4=True)
		super().__init__(target=self.machines["target"], callback=self.filterPacket)
		self.allow_all = False

	def filterPacket(self, raw):
		if self.allow_all:
			raw.accept()
			return

		packet = net.IP(raw.get_payload())
		if net.DNS in packet or net.ICMP in packet: #ignore there as they're not used for "actual" game netcode
			return

		IP = packet[net.IP]
		remote_ip = IP.dst if IP.src == self.machines["target"].ip else IP.src
		remote_address = ipaddress.ip_address(remote_ip)

		for x in ip_range_blacklist:
			if remote_address in x:
				raw.drop()
				return

		raw.accept()

if __name__ == "__main__":
	ON = "\x1b[32;1mON\x1b[0m "
	OFF = "\x1b[91mOFF\x1b[0m"

	network_thread = Unjoinable()
	network_thread.allow_all = True
	try:
		print("Starting nfqueue...")
		network_thread.start()
		while True:
			input(f"[ {OFF if network_thread.allow_all else ON} ] - Press ENTER to toggle")
			network_thread.allow_all = not network_thread.allow_all
		network_thread.join()

	except KeyboardInterrupt:
		print("Closing...")

	except Exception as e:
		print(e)




