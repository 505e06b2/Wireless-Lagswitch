## Gateway IPv4 Port Filter
### Details
* Works on any device on your network that can run Python
* Relatively imprecise - should take effect after a few seconds
* Can be used to block traffic to specific IPs
* Can be completely ignored and done manually via the web browser if needed

### Installation
#### \*nix
```bash
sudo apt install python3
git clone https://github.com/505e06b2/Wireless-Lagswitch
cd Wireless-Lagswitch/virgin_media_superhub
make -j5 release
```

#### Other (Virtual Machine)
1. Download and [install VirtualBox](https://www.virtualbox.org)
2. Download the [latest VM](https://github.com/505e06b2/Wireless-Lagswitch/releases)
3. Open VirtualBox and click File > Import Appliance
4. Select the `.ova` file and run through the setup - the defaults should be good
5. As long as the network settings are correct (Promiscuous Mode: Allow All), everything else is up to you

![](https://raw.githubusercontent.com/505e06b2/Wireless-Lagswitch/master/mitm_nfqueue_linux/virtualbox_network.png)

6. Run the VM and wait until you are automatically logged in as `x@leaveMeAlone`
7. Type `./go.sh` and it should automatically update, compile, then run the program
8. If that doesn't work, this should be a "standard" Ubuntu installation, so all coreutils should be available - try `ls` and `cd`
