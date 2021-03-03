#!/usr/bin/env python3

import scapy.all as net
import sys, os, time, subprocess, shlex, threading, ipaddress, json
import atexit

import http.server
import urllib.parse

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

from netfilterqueue import NetfilterQueue as nfqueue # sudo apt install libnetfilter-queue-dev - sudo python3 -m pip install NetfilterQueue


VERBOSITY = 0
HTTP_ADDRESS = "" # "" for anyone
HTTP_PORT = 8181

#iptables settings
GAME_PROTOCOL = "udp" #usual game connection type

class NFQueueThread(threading.Thread):
	def __init__(self, target):
		super().__init__()
		self.target = target
		self.daemon = True #will exit when the program does
		print("Altering iptables...")
		#if these rules are very specific, they should allow for performance gains as the kernel will handle more requests directly
		subprocess.run(shlex.split(f"iptables -I FORWARD -p {GAME_PROTOCOL} -d {self.target.ip} -j NFQUEUE --queue-num 1")) #ps4 destination
		subprocess.run(shlex.split(f"iptables -I FORWARD -p {GAME_PROTOCOL} -s {self.target.ip} -j NFQUEUE --queue-num 1")) #ps4 source
		atexit.register(self.__del__) #force running __del__, even

	def __del__(self):
		print("Restoring iptables...")
		subprocess.run(shlex.split("iptables -F"))
		subprocess.run(shlex.split("iptables -X"))
		atexit.unregister(self.__del__)

	#returns remote IP address
	def _checkPort(self, packet, port_number):
		ip = packet[net.IP]
		try: #target is the PS4
			if ip.src == self.target.ip and ip.sport == port_number:
				return ip.dst
			elif ip.dst == self.target.ip and ip.dport == port_number:
				return ip.src
		except AttributeError:
			pass
		return None

	def run(self):
		def callback(raw):
			raw.accept()
			packet = net.IP(raw.get_payload())

			if net.TCP in packet or net.DNS in packet or net.ICMP in packet: #ignore there as they're not used for "actual" game netcode
				raw.accept()
				return

			remote_ip = self._checkPort(packet, GAME_PORT)

			if remote_ip and remote_ip.startswith("52.40.62."): #SONY/Amazon
				return

			if remote_ip and ipaddress.ip_address(remote_ip).is_global:
				print(packet.summary())


			#print(packet.summary())

		q = nfqueue()
		q.bind(1, callback)
		q.run()

if __name__ == "__main__":
	print("Finding network devices...")
	machines = get_machines.search(ps4=True)

	network_thread = NFQueueThread(machines["target"])
	try:
		print("Starting nfqueue...")
		network_thread.start()
		network_thread.join()

	except KeyboardInterrupt:
		print("Closing...")

	except Exception as e:
		print(e)




