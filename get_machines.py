import scapy.all as net

import sys, os

SonyEntertainment_macs = ["00:04:1f","00:13:15","00:15:c1","00:19:c5","00:1d:0d","00:1f:a7","00:24:8d","00:d9:d1","00:e4:21","0c:fe:45","28:0d:fc","2c:cc:44","70:9e:29","78:c8:81","a8:e3:ee","bc:60:a7","c8:63:f1","f8:46:1c","f8:d0:ac","fc:0f:e6"]
HonHaiPr_macs = ["ec:0e:c4"] #my wlan mac starts with this

class Machine:
	def __init__(self, ip, mac=None):
		self.ip = ip
		if mac:
			self.mac = mac
		else:
			self.mac = net.getmacbyip(ip)
			if not self.mac:
				raise PermissionError("Couldn't find MAC address of %s" % ip)

	def __repr__(self):
		return "ip: %s | mac: %s" % (self.ip, self.mac)

def search(gateway_ip="", ip_range="", target_ip="", mac_startswith="", ps4=False):
	if not gateway_ip:
		gateway_ip = net.conf.route.route("0.0.0.0")[2]

	if not ip_range:
		ip_range = gateway_ip + "/24" #mine would be "192.168.0.1/24"

	if not (ps4 or target_ip or mac_startswith):
		print("ERROR: No search parameters given")
		sys.exit(1)

	request = net.Ether(dst="ff:ff:ff:ff:ff:ff") / net.ARP(pdst=ip_range)
	answered, unanswered = net.srp(request, timeout=1, verbose=0)

	found = []
	for i in answered:
		if (not target_ip or target_ip == i[1].psrc) and (not mac_startswith or i[1].hwsrc.startswith(mac_startswith)):
			if ps4:
				if i[1].hwsrc[:8] in SonyEntertainment_macs or i[1].hwsrc[:8] in HonHaiPr_macs:
					found.append((i[1].psrc, i[1].hwsrc))
			else:
				found.append((i[1].psrc, i[1].hwsrc))


	if len(found) > 1:
		print("ERROR: More than one device found with ip: %s and mac: %s" % (target_ip, mac_startswith))
		sys.exit(1)
	elif len(found) == 0:
		print("ERROR: No devices found with ip: %s, mac: %s, ps4: %s" % (target_ip, mac_startswith, ps4))
		sys.exit(1)

	ret = default(gateway_ip)
	ret["target"] = Machine(found[0][0], found[0][1])
	return ret

def default(gateway_ip=""):
	if not gateway_ip:
		gateway_ip = net.conf.route.route("0.0.0.0")[2]

	return {
		"this": Machine(net.get_if_addr(net.conf.iface), net.get_if_hwaddr(net.conf.iface)),
		"gateway": Machine(gateway_ip) #set manually if needed
	}

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument("--gateway_ip")

	program_arguments = parser.parse_args()
	print(search(gateway_ip=program_arguments.gateway_ip, ps4=True))
