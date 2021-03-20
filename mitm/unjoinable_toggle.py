#!/usr/bin/env python3

import os, sys
import subprocess, threading
from arp_poison_ps4 import ARPPoison

if os.geteuid() != 0:
	sys.exit("Must be root.")

poison = ARPPoison()
poison.start()
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
	poison.running = False
	poison.join()
	print("Stopped ARP poison")
