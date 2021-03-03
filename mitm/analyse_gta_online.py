#!/usr/bin/env python3

import os, sys, scapy.all as net, packet_analysis

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import get_machines

print("Finding network devices...")
machines = get_machines.search(ps4=True)

#will default to UDP
network_thread = packet_analysis.NFQueueThread(machines["target"], game_port=9306)
try:
	print("Starting nfqueue...")
	network_thread.start()

	print(f"Starting HTTP server at http://{machines['this'].ip}:8181...")
	packet_analysis.UIServer().run()

except KeyboardInterrupt:
	print("Closing...")

except Exception as e:
	print(e)




