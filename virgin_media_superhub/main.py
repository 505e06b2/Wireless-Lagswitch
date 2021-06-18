#!/usr/bin/env python3

import Superhub3_CLI as superhub
import os, sys, requests, json

nmap_mac_prefixes_url = "https://svn.nmap.org/nmap/nmap-mac-prefixes"
nmap_mac_prefixes_cache = "mac_prefixes.txt"

def makeOrdinal(n): #https://stackoverflow.com/a/50992575
    n = int(n)
    suffix = ['th', 'st', 'nd', 'rd', 'th'][min(n % 10, 4)]
    if 11 <= (n % 100) <= 13:
        suffix = 'th'
    return str(n) + suffix

def getPlaystationMACs():
	file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), nmap_mac_prefixes_cache)
	if not os.path.isfile(file_path):
		print("Downloading MAC Vendor Prefixes for future use (700kB)...")
		with requests.get(nmap_mac_prefixes_url) as r:
			with open(nmap_mac_prefixes_cache, "w") as f:
				f.write(r.text)
	else:
		print(f"Using MAC Vendor Prefixes from disk (delete {nmap_mac_prefixes_cache} to update)")

	ret = []
	with open(nmap_mac_prefixes_cache) as f:
		for line in f.readlines():
			mac_hex, name = line.strip().split(" ", 1)
			name = name.strip().lower()
			if name.startswith("sony interactive entertainment"):
				ret.append(":".join([mac_hex[i:i+2].lower() for i in range(0, len(mac_hex), 2)]))
	return ret

def findPlaystationIP(connected_devices, ps4_mac_prefixes):
	count = 0
	ret = ""

	for key, value in connected_devices.items(): #from superhub
		if value["online"] and value["mac"][:8] in ps4_mac_prefixes:
			count += 1
			ret = key

	if count > 1:
		print(f"{count} PS4s found on the network, aborting...")
		sys.exit(1)
	elif count <= 0:
		print(f"No PS4 found on the network, aborting...")
		sys.exit(1)

	return ret

if __name__ == "__main__":
	settings_filename = "settings.json"
	settings_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), settings_filename)
	settings = {}

	try:
		with open(settings_path) as f:
			settings = json.load(f)
	except:
		pass

	settings["admin_password"] = settings.get("admin_password", "")
	settings["ip_address"] = settings.get("ip_address", "")

	print(f"Writing current settings to file ({settings_filename})")
	with open(settings_path, "w") as f:
		json.dump(settings, f, indent=4)

	if not settings["admin_password"]:
		print(f"Set admin_password in {settings_filename} to access your Superhub")
		exit(1)

	target_mac_prefixes = getPlaystationMACs()

	with superhub.Superhub(settings["admin_password"]) as hub:
		if not hub:
			print("Failed to log in, password incorrect?")
			sys.exit(1)

		print("Finding PS4...")
		if ip_address:
			print(f"Using IP address for search: {ip_address}")
		playstation_ip = findPlaystationIP(hub.getConnectedDeviceInfo(ip_address), target_mac_prefixes)
		print("Playstation IP:", playstation_ip)

		filter_count = hub.countPortFilters()
		print(f"{filter_count} IPv4 port filters found on the hub")

		filter_index = -1#hub.getIndexOfPortFilter(playstation_ip)
		if filter_index < 0:
			print(f"No filter found for {playstation_ip}")
			yes_no = input(f"Create a filter for {playstation_ip}? (you MUST make your Playstation's IP static) [Y/N] ")
			if yes_no.lower() == "y":
				print(f"Creating GTA Online IPv4 port filter for {playstation_ip}...")
				filter_index = hub.createPortFilter(playstation_ip, None, "185.56.65.0", "185.56.65.255", False)
			else:
				print("Exiting...")
				sys.exit(0)
		print(f"Using the {makeOrdinal(filter_index+1)} IPv4 port filter")

		current_state = hub.getPortFilterState(filter_index)
		print("Ready, press CTRL+C to exit")
		try:
			while True:
				show_str = "Blocking requests" if current_state else "Allowing requests"
				input(f"{show_str} - Press ENTER to toggle")
				current_state = not current_state
				hub.setPortFilterState(filter_index, current_state)
		except KeyboardInterrupt:
			pass

		print("\nExiting...")
