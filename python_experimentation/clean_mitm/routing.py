import platform

import scapy.all as net
from ipaddress import IPv4Network as IPNetwork
import atexit, time, threading, os

take_two_ip_ranges = [IPNetwork(x) for x in ["185.56.65.0/24", "192.81.240.0/21"]]
microsoft_ip_ranges = [IPNetwork(x) for x in ["20.33.0.0/16", "20.40.0.0/13", "20.128.0.0/16", "20.36.0.0/14", "20.48.0.0/12", "20.34.0.0/15", "20.64.0.0/10"]]
default_blacklist = take_two_ip_ranges + microsoft_ip_ranges

ready = False
drop_packets = False

def determineDrop(raw_bytes):
	packet = net.IP(raw_bytes)
	return drop_packets

def start(target):
	global ready
	ready = False

	if platform.system() == "Linux":
		# Ubuntu 18.04:  sudo apt install libnetfilter-queue-dev && sudo python3 -m pip install NetfilterQueue
		# Newer systems: sudo apt install libnetfilter-queue-dev && sudo python -m pip install -U git+https://github.com/kti/python-netfilterqueue
		from netfilterqueue import NetfilterQueue as nfqueue

		with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
			f.write("1")

		os.system("iptables -X")
		os.system("iptables -F")
		os.system(f"iptables -I FORWARD -p udp -d {target.ip} -j NFQUEUE --queue-num 1")
		os.system(f"iptables -I FORWARD -p udp -s {target.ip} -j NFQUEUE --queue-num 1")

		def nativeCallback(nfqueue_obj):
			drop = determineDrop(nfqueue_obj.get_payload())
			if drop:
				return nfqueue_obj.drop()
			return nfqueue_obj.accept()


		def nativeCleanup():
			print("Closing NFQueue")
			q.unbind() #should be global
			os.system("iptables -X")
			os.system("iptables -F")
			with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
				f.write("0")

		atexit.register(nativeCleanup)
		q = nfqueue()
		q.bind(1, nativeCallback)
		ready = True
		q.run()

	elif platform.system() == "Windows":
		#python -m pip install pydivert
		from pydivert import WinDivert as windivert
		import winreg

		#winreg.OpenKey()

		with windivert(f"udp and (ip.SrcAddr == {target.ip} or ip.DstAddr == {target.ip})") as w:
			def nativeCleanup():
				pass

			atexit.register(nativeCleanup)

			ready = True
			for packet in w:
				drop = determineDrop(packet.payload)
				if drop:
					continue
				w.send(packet)

	else:
		print("lol not implemented")
		exit(1)
