#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue as nfqueue
import os, sys, atexit, scapy.all as net

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

print("Finding network devices...")
machines = get_machines.search(ps4=True)

os.system("iptables -X")
os.system("iptables -F")
os.system(f"iptables -I FORWARD -p udp -s {machines['target'].ip} --dport 53 -j NFQUEUE --queue-num 1")

def nativeCallback(nfqueue_obj):
	packet = net.IP(nfqueue_obj.get_payload())
	try:
		dns = packet[net.DNS]
		print(dns.summary())
	except:
		print("Not DNS????")
	return nfqueue_obj.accept()


def nativeCleanup():
	print("Closing NFQueue")
	q.unbind() #should be global
	os.system("iptables -X")
	os.system("iptables -F")

atexit.register(nativeCleanup)
q = nfqueue()
q.bind(1, nativeCallback)
print("Starting...")
q.run()
