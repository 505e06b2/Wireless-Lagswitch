#!/usr/bin/env python3
dns_requests = """DNS Qry "b'auth-prod.ros.rockstargames.com.'"
DNS Qry "b'gb-ivt.np.community.playstation.net.'"
DNS Qry "b'gb-prof.np.community.playstation.net.'"
DNS Qry "b'inbox-gta5-prod.ros.rockstargames.com.'"
DNS Qry "b'prod.ros.rockstargames.com.'"
DNS Qry "b'mm-gta5-prod.ros.rockstargames.com.'"
DNS Qry "b'crews-gta5-prod.ros.rockstargames.com.'"
DNS Qry "b'prs-gta5-prod.ros.rockstargames.com.'"
DNS Qry "b'commerce.api.np.km.playstation.net.'"
DNS Qry "b'prs57-prod.ros.rockstargames.com.'"
DNS Qry "b'prod.cloud.rockstargames.com.'"
DNS Qry "b'prod.cloud.rockstargames.com.'"
DNS Qry "b'prod.ros.rockstargames.com.'"
DNS Qry "b'prod.ros.rockstargames.com.'"
DNS Qry "b'prod.ros.rockstargames.com.'"
DNS Qry "b'ps-gta5-prod.ros.rockstargames.com.'"
DNS Qry "b'prod.cloud.rockstargames.com.'"
DNS Qry "b'prod.cloud.rockstargames.com.'"
DNS Qry "b'cs-gta5-prod.ros.rockstargames.com.'"
DNS Qry "b'gb-prof.np.community.playstation.net.'"
DNS Qry "b'asm.np.community.playstation.net.'"
DNS Qry "b'gb-prof.np.community.playstation.net.'"
DNS Qry "b'ugc-gta5-prod.ros.rockstargames.com.'"
DNS Qry "b'prod.telemetry.ros.rockstargames.com.'"
DNS Qry "b'gb-ivt.np.community.playstation.net.'"
DNS Qry "b'prod.ros.rockstargames.com.'"
DNS Qry "b'prod.cloud.rockstargames.com.'"
DNS Qry "b'asm.np.community.playstation.net.'"
DNS Qry "b'activity.api.np.km.playstation.net.'"
DNS Qry "b'prod.telemetry.ros.rockstargames.com.'"
DNS Qry "b'ugc-gta5-prod.ros.rockstargames.com.'"
DNS Qry "b'prod.ros.rockstargames.com.'"
DNS Qry "b'prod.cloud.rockstargames.com.'"
DNS Qry "b'gb-prof.np.community.playstation.net.'"
DNS Qry "b'prod.telemetry.ros.rockstargames.com.'"
DNS Qry "b'prod.ros.rockstargames.com.'"
DNS Qry "b'gb-ivt.np.community.playstation.net.'"
DNS Qry "b'prod.cloud.rockstargames.com.'"
""".split("\n")

import socket
from ipaddress import ip_network, ip_address

take_two_ip_ranges = [ip_network(x) for x in ["185.56.65.0/24", "192.81.240.0/21"]]
unique = {}

for x in dns_requests:
	x = x.strip()
	if x and not "playstation" in x:
		unique[ x[11:-3] ] = "" #will make sure of no dupes

for x in list(unique):
	ip = ip_address(socket.gethostbyname(x))
	match = False
	for cidr_range in take_two_ip_ranges:
		if ip in cidr_range:
			match = True
			break
	if match:
		print(f"\"{str(ip)}/32\", //{x}")
