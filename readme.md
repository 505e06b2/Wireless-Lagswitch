# Wireless Lagswitch
``This repo contains tools for manipulating the network traffic for local devices - do not use these tools on networks you do not own. Skiddies GTFO.``

The tools in this repo have been made specifically to "cut" lobbies in GTA: Online on PS4. To use anything in this repo, you must have a machine with Root/Administrator access. For the scripts in the "basic and "mitm" folders, Python 3 with the `scapy` module is required. All Python scripts should restore the network state when terminated with CTRL+C. For the "no_setup_basic" project, you must have `libpcap-dev` installed, or if compiling for Windows, the [npcap SDK](https://nmap.org/npcap/) in the *empty* "no_setup_basic/npcap" folder. Be careful with this, as if you leave the switch ON, your network won't be *immediately* restored (reopen the application if this happens).

## Man-In-The-Middle (\*NIX Only)
### Details
* Only works on systems that provide `iptables` and `netfilter_queue`
* Routes all of the target's traffic through the host machine (the one running the program) - ethernet recommended
* *Very* precise - should take effect immediately
* Can be used to block traffic to specific IPs

### Installation
#### \*nix
```bash
sudo apt install libpcap-dev libnetfilter-queue-dev
git clone https://github.com/505e06b2/Wireless-Lagswitch
cd Wireless-Lagswitch/mitm_nfqueue_linux
make -j5 release
```

#### Other (Virtual Machine)
1. Download and install VirtualBox
2. Download the [latest VM](https://github.com/505e06b2/Wireless-Lagswitch/releases)
3. Open VirtualBox and click File > Import Appliance
4. Select the `.ova` file and run through the setup - the defaults should be good
5. As long as the network settings are correct, everything else is up to you
![](https://raw.githubusercontent.com/505e06b2/Wireless-Lagswitch/master/mitm_nfqueue_linux/virtualbox_network.png)
6. Run the VM and wait until you are automatically logged in as `x@leaveMeAlone`
7. Type `./go.sh` and it should automatically update, compile, then run the program
8. If that doesn't work, this should be a "standard" Ubuntu installation, so all coreutils should be available - try `ls` and `cd`

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
