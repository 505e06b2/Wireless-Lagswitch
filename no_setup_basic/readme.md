## Basic ARP Cache Poison (Portable)
### Details
* Works on any platform that supports pcap
* Can be imprecise - it may take a few seconds for the poison to take hold / reset
* Takes down your entire connection to the internet

### Installation
#### \*nix
```bash
sudo apt install libpcap-dev
git clone https://github.com/505e06b2/Wireless-Lagswitch
cd Wireless-Lagswitch/no_setup_basic
make -j5 release
```

#### Windows
1. [Download and start the npcap installer](https://nmap.org/npcap/)
2. Choose these settings for npcap:

![](https://raw.githubusercontent.com/505e06b2/Wireless-Lagswitch/master/no_setup_basic/npcap_1_00_setup.png)
3. Download the [Session Cutter](https://github.com/505e06b2/Wireless-Lagswitch/releases)

### Mac
lol
