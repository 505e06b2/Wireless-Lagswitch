import scapy.all as net

import sys, os, argparse

parser = argparse.ArgumentParser()
parser.add_argument("--gateway_ip")
parser.add_argument("--target_ip")

program_arguments = parser.parse_args()

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

def search(ip_range=None, target_ip=None, mac_startswith=None):
	if not ip_range:
		gateway = program_arguments.gateway_ip or net.conf.route.route("0.0.0.0")[2]
		ip_range = gateway + "/24" #mine would be "192.168.0.1/24"

	if not target_ip and program_arguments.target_ip:
		target_ip = program_arguments.target_ip
		print("TESTED")

	request = net.Ether(dst="ff:ff:ff:ff:ff:ff") / net.ARP(pdst=ip_range)
	answered, unanswered = net.srp(request, timeout=1, verbose=0)

	found = []
	for i in answered:
		if (not target_ip or target_ip == i[1].psrc) and (not mac_startswith or i[1].hwsrc.startswith(mac_startswith)):
			found.append((i[1].psrc, i[1].hwsrc))

	if len(found) > 1:
		print("ERROR: More than one device found with ip: %s and mac: %s" % (target_ip, mac_startswith))
		sys.exit(1)
	elif len(found) == 0:
		print("ERROR: No devices found with ip: %s and mac: %s" % (target_ip, mac_startswith))
		sys.exit(1)

	ret = default()
	ret["target"] = Machine(found[0][0], found[0][1])
	return ret

def default():
	return {
		"this": Machine(net.get_if_addr(net.conf.iface), net.get_if_hwaddr(net.conf.iface)),
		"gateway": Machine(program_arguments.gateway_ip or net.conf.route.route("0.0.0.0")[2]) #set manually if needed
	}

if __name__ == "__main__":
	print(default())
