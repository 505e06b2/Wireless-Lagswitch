#!/usr/bin/env python3

import scapy.all as net
import time, subprocess, shlex, threading, ipaddress, json
import atexit #force iptables fixing

import http.server
import urllib.parse

from netfilterqueue import NetfilterQueue as nfqueue # sudo apt install libnetfilter-queue-dev - sudo pip3 install -U git+https://github.com/kti/python-netfilterqueue

import ipinfo #python3 -m pip install ipinfo
ip_handler = ipinfo.getHandler("c74b5a4469d554") #will only work from my IP

ip_catalogue = {}
kill_all = False
no_more = 0

class IP:
	def __init__(self, ip):
		self.ip = ip
		self.kill = False
		self.protect = False
		self.first_received = time.time()
		self.heartbeat()
		self.updateIpinfo()

	def heartbeat(self):
		self.last_received = time.time()

	def updateIpinfo(self):
		try:
			self.ip_info = ip_handler.getDetails(self.ip)
		except:
			self.ip_info = None

	def isdead(self):
		return time.time() - self.last_received > 20

	def __str__(self):
		ret = self.__dict__.copy() #copy so things doesn't get overwritten
		if ret["ip_info"]:
			info = ret["ip_info"]
			ret["ip_info"] = {
				"location": {
					"city": info.city,
					"region": info.region,
					"country": info.country,
					"country_name": info.country_name,
					"timezone": info.timezone
				},
				"provider": info.org
			}
		return json.dumps(ret)

class NFQueueThread(threading.Thread):
	def __init__(self, target, callback=None, game_protocol="udp", game_port=0):
		super().__init__()
		self.target = target
		self.callback = callback if callback else self._defaultCallback
		self.daemon = True #will exit when the program does
		#if these rules are very specific, they should allow for performance gains as the kernel will handle more requests directly
		dport = f"--dport {game_port}" if game_port != 0 else ""
		sport = f"--sport {game_port}" if game_port != 0 else ""
		subprocess.run(shlex.split(f"iptables -I FORWARD -p {game_protocol} -d {self.target.ip} {dport} -j NFQUEUE --queue-num 1")) #ps4 destination
		subprocess.run(shlex.split(f"iptables -I FORWARD -p {game_protocol} -s {self.target.ip} {sport} -j NFQUEUE --queue-num 1")) #ps4 source
		atexit.register(self.__del__) #force running __del__, even

	def __del__(self):
		subprocess.run(shlex.split("iptables -F"))
		subprocess.run(shlex.split("iptables -X"))
		atexit.unregister(self.__del__)

	def _getRemoteIPAddress(self, packet):
		ip = packet[net.IP]
		try: #target is the PS4
			if ip.src == self.target.ip:
				return ip.dst
			elif ip.dst == self.target.ip:
				return ip.src
		except AttributeError:
			pass
		return None

	def _defaultCallback(self, raw):
		packet = net.IP(raw.get_payload())

		if net.DNS in packet or net.ICMP in packet: #ignore there as they're not used for "actual" game netcode
			raw.accept()
			return

		remote_ip = self._getRemoteIPAddress(packet)

		if remote_ip and remote_ip.startswith("52.40.62."): #SONY/Amazon
			raw.accept()
			return

		if remote_ip and ipaddress.ip_address(remote_ip).is_global:
			if remote_ip in ip_catalogue:
				if (kill_all and not ip_catalogue[remote_ip].protect) or ip_catalogue[remote_ip].kill:
					raw.drop()
					ip_catalogue[remote_ip].heartbeat()
					return

				raw.accept()
				if ip_catalogue[remote_ip].ip_info:
					ip_catalogue[remote_ip].heartbeat()

				else: #not found
					ip_catalogue[remote_ip].updateIpinfo()

			elif no_more != 0 and time.time() > no_more:
				raw.drop()

			else:
				raw.accept()
				ip_catalogue[remote_ip] = IP(remote_ip)

			return

		raw.accept()

	def run(self):
		q = nfqueue()
		q.bind(1, self.callback)
		q.run()

class UIServer:
	def __init__(self, server_address="", server_port=8181):
		self.httpd = http.server.HTTPServer((server_address, server_port), self.CustomHTTPRequestHandler)

	def run(self):
		self.httpd.serve_forever()


	class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
		def log_message(self, format, *args):
			pass

		def do_GET(self):
			global kill_all

			parsed = urllib.parse.urlparse(self.path)
			if parsed.path == "/":
				self.send_response(200)
				self.send_header("Content-type", "text/html")
				self.end_headers()
				try:
					with open("ui.html", "rb") as f:
						self.wfile.write(f.read())
				except FileNotFoundError:
					self.wfile.write(b"ui.html not found, make sure your cwd is correct")

			elif parsed.path == "/data":
				self.send_response(200)
				self.send_header("Content-type", "application/json")
				self.end_headers()
				catalogue = ip_catalogue.copy() #hopefully no race conditions?
				ret = []
				for [key, value] in catalogue.items():
					if value.isdead():
						del ip_catalogue[key]
						continue
					ret.append(value.__str__().encode("utf-8"))

				self.wfile.write(b'{"kill_all": %s, "catalogue": [%s]}' % (
					b"true" if kill_all else b"false",
					b",".join(ret))
				)

			elif parsed.path == "/kill_all":
				kill_all = not kill_all
				print("Kill All =", kill_all)
				self.send_response(200)
				self.end_headers()

			elif parsed.path == "/kill":
				try:
					query = urllib.parse.parse_qs(parsed.query)
					for x in query.get("target", []):
						ip_catalogue[x].kill = not ip_catalogue[x].kill
						print("Kill -", x, "=", ip_catalogue[x].kill)

					self.send_response(200)
				except AttributeError:
					self.send_response(404)
				self.end_headers()

			elif parsed.path == "/protect":
				try:
					query = urllib.parse.parse_qs(parsed.query)
					for x in query.get("target", []):
						ip_catalogue[x].protect = not ip_catalogue[x].protect
						print("Protect -", x, "=", ip_catalogue[x].protect)

					self.send_response(200)
				except AttributeError:
					self.send_response(404)
				self.end_headers()

			else:
				self.send_response(404)
				self.end_headers()


if __name__ == "__main__":
	import os, sys, scapy.all as net, packet_analysis

	sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
	import get_machines

	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument("--gateway_ip")
	parser.add_argument("--target_ip")
	parser.add_argument("--target_mac")
	parser.add_argument("--ps4", action="store_true")

	parser.add_argument("--game_protocol")
	parser.add_argument("--game_port")

	parser.add_argument("--http_port")
	parser.add_argument("--http_address")
	args = parser.parse_args()

	print("Finding network devices...")
	machines = get_machines.search(
		ps4=args.ps4,
		gateway_ip=args.gateway_ip,
		target_ip=args.target_ip,
		mac_startswith=args.target_mac
	)

	game_settings = {}
	if args.game_protocol: game_settings["game_protocol"] = args.game_protocol
	if args.game_port: game_settings["game_port"] = args.game_port

	http_settings = {}
	if args.http_port: http_settings["server_port"] = int(args.http_port)
	if args.http_address: http_settings["server_address"] = args.http_address

	#will default to UDP
	network_thread = packet_analysis.NFQueueThread(machines["target"], **game_settings)
	try:
		print(f"Starting NFQueueThread - target: ({machines['target']}) - params: {game_settings}")
		network_thread.start()

		print(f"Starting HTTP server at http://{machines['this'].ip}:{args.http_port if args.http_port else 8181}...")
		packet_analysis.UIServer(**http_settings).run()

	except KeyboardInterrupt:
		print("Closing...")

	except Exception as e:
		print(e)




