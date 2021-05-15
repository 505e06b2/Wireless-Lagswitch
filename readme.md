# Wireless Lagswitch
``This repo contains tools for manipulating the network traffic for local devices - do not use these tools on networks you do not own. Skiddies GTFO.``

The tools in this repo have been made specifically to "cut" lobbies in GTA: Online on PS4. To use anything in this repo, you must have a machine with Root/Administrator access. For the scripts in the "basic and "mitm" folders, Python 3 with the `scapy` module is required. All Python scripts should restore the network state when terminated with CTRL+C. For the "no_setup_basic" project, you must have `libpcap-dev` installed, or if compiling for Windows, the [npcap SDK](https://nmap.org/npcap/) in the *empty* "no_setup_basic/npcap" folder. Be careful with this, as if you leave the switch ON, your network won't be *immediately* restored (reopen the application if this happens).

## Installation
### \*nix
```bash
sudo apt install libpcap-dev
git clone https://github.com/505e06b2/Wireless-Lagswitch
cd Wireless-Lagswitch/no_setup_basic
make release
```

### Windows
1. [Download and start the npcap installer](https://nmap.org/npcap/)
2. For the options that come up, choose these (the Administrator option will keep you safe):
 ![](https://raw.githubusercontent.com/505e06b2/Wireless-Lagswitch/master/no_setup_basic/nmap_setup.png)
 ![](https://raw.githubusercontent.com/505e06b2/Wireless-Lagswitch/master/no_setup_basic/npcap_1_00_setup.png)
 3. Download the [Session Cutter](https://github.com/505e06b2/Wireless-Lagswitch/releases)

### Mac
lol
