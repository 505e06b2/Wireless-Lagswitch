args = {} #set by main

ARP_REQUEST_TIMEOUT = 2

import scapy.all as net
from ipaddress import IPv4Address as IPAddress
import sys

sony_entertainment_prefixes = ["00:04:1f","00:13:15","00:15:c1","00:19:c5","00:1d:0d","00:1f:a7","00:24:8d","00:d9:d1","00:e4:21","0c:fe:45","28:0d:fc","2c:cc:44","70:9e:29","78:c8:81","a8:e3:ee","bc:60:a7","c8:63:f1","f8:46:1c","f8:d0:ac","fc:0f:e6"]
HonHaiPr_prefixes = ["ec:0e:c4"] #my wlan mac starts with this
all_vendor_macs = sony_entertainment_prefixes + HonHaiPr_prefixes

class Interface:
	def __init__(self, name, ip_address=IPAddress(0), gateway=IPAddress(0), netmask=IPAddress(0)):
		self.name = name
		self.ip = ip_address
		self.gateway = gateway
		self.netmask = netmask
		self.mac = net.get_if_hwaddr(name)

class FoundNetworkDevice:
	def __init__(self, ip_address=IPAddress(0), mac_address=""):
		self.ip = ip_address
		self.mac = mac_address

def findInterfaces(requested_interface=None):
	ret = {}
	for network, netmask, gateway, interface, ip_address, metric in net.conf.route.routes:
		current_interface = Interface(interface)
		if ret.get(interface):
			current_interface = ret[interface]

		if network == 0: #gateway is on a different line
			current_interface.gateway = IPAddress(gateway)
			ret[interface] = current_interface
			continue

		netmask_bitcount = bin(netmask).count("1")
		if netmask_bitcount < 16 or netmask_bitcount >= 32: continue #too many other machines
		if requested_interface != None and interface != requested_interface: continue #wanted specific interface - not this
		current_interface.ip = IPAddress(ip_address)
		current_interface.netmask = IPAddress(netmask)
		ret[interface] = current_interface

	return [x for x in ret.values()]

def findNetworkDevices(interface):
	ret = []
	min_ipv4 = IPAddress(int(interface.ip) & int(interface.netmask))
	netmask_bitcount = bin(int(interface.netmask)).count("1")
	cidr_address = f"{min_ipv4}/{netmask_bitcount}"

	request = net.Ether(dst="ff:ff:ff:ff:ff:ff") / net.ARP(pdst=cidr_address)
	for _, found in net.srp(request, timeout=ARP_REQUEST_TIMEOUT, verbose=0)[0]:
		ret.append( FoundNetworkDevice(IPAddress(found.psrc), found.hwsrc) )
	return ret

def findNetworkDevice(network_devices, target_mac="", target_ip=""):
	found_targets = 0
	last_found = None
	target_ip = IPAddress(target_ip) if target_ip else None

	for x in network_devices:
		if target_mac or target_ip:
			if (target_mac and x.mac.startswith(target_mac)) or (target_ip and x.ip == target_ip):
				last_found = x
				found_targets += 1

		elif x.mac[:len(all_vendor_macs[0])] in all_vendor_macs:
			last_found = x
			found_targets += 1

	if found_targets > 1:
		print(f"Too many targets found ({found_targets}) - IP: {target_ip} / MAC: {target_mac}")
		print("Try being more specific with the IP and/or MAC address")
		sys.exit(1)
	elif found_targets <= 0:
		print(f"No targets found, are you sure your target is online?")
		sys.exit(1)

	return last_found


