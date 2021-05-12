# Wireless Lagswitch
``This repo contains tools for manipulating the network traffic for local devices - do not use these tools on networks you do not own. Skiddies GTFO.``

The tools in this repo have been made specifically to "cut" lobbies in GTA: Online on PS4. There's both a "basic" way, and an "mitm" way, but both require Python 3, the `scapy` module, and administrator access to a machine on the network. All Python scripts should restore the network state when terminated with CTRL+C.

## tl;dr
### Good OS?
```bash
sudo python3 -m pip install scapy
git clone https://github.com/505e06b2/Wireless-Lagswitch
cd Wireless-Lagswitch/basic
sudo ./toggle_arp_spoof.py
```

### Bad OS?
Have fun with netcut (for the time being)

## Basic
In the `basic` folder, there's a method that simply ARP cache poisons the PS4 for 20s, then restores the ARP state. This script should work cross-platform and is confirmed working for both Linux and a rooted Android device (running Termux). Personally, I'd recommend getting `toggle_arp_spoof.py` to work, since then you'd be able to precisely control when to lag out

## MITM
### Extra Requirements
- `sudo apt install libnetfilter-queue-dev`
- `sudo python3 -m pip install ipinfo`
- `sudo python3 -m pip install NetfilterQueue` OR `sudo python3 -m pip install -U git+https://github.com/kti/python-netfilterqueue`
- An [ipinfo.io](http://ipinfo.io) token

In the `mitm` folder, there are 2 scripts. These both require a Linux host, but should be easy enough to modify for other platforms. The first is `arp_poison_ps4`. This forces the network connection of the PS4 through the host device via ip_forward and ARP cache poison, while continuously poisoning the PS4 and Gateway to maintain access. The second is `analyse_packets`. This script creates an iptables rule that redirects any traffic for the PS4 to the `NFQueueThread` class, where it is manipulated. [It also starts an HTTP server for managing the script.](http://localhost:8181)
