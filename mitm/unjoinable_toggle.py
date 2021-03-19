#!/usr/bin/env python3

import os, sys
import subprocess

if os.geteuid() != 0:
	sys.exit("Must be root.")

arp_poisoner = subprocess.Popen("./arp_poison_ps4.py", stdout=subprocess.DEVNULL)
print("Started ARP poison")

unjoiner = None
ON = "\x1b[32;1mON\x1b[0m "
OFF = "\x1b[91mOFF\x1b[0m"
try:
	while True:
		input(f"[ {ON if unjoiner else OFF} ] - Press ENTER to toggle")
		if unjoiner:
			unjoiner.kill()
			unjoiner.communicate()
			unjoiner = None
		else:
			unjoiner = subprocess.Popen("./gta_become_unjoinable.py", stdout=subprocess.DEVNULL)

except:
	arp_poisoner.kill()
	arp_poisoner.communicate()
	print("Stopped ARP poison")
