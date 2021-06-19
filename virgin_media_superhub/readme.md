## Gateway IPv4 Port Filter
### Details
* Works on any device on your network that can run Python
* Relatively imprecise - should take effect after a few seconds
* Can be used to block traffic to specific IPs
* Can be completely ignored and done manually via the web browser if needed

### Warnings
* This program will modify your router settings - use at your own risk
* If you do not trust the program to create a network filter for you, manually create one and it will use it
* While the program is running, you will not be able to access your admin control panel - ensure the program closes properly so it has a chance to log out

### Installation
```bash
git clone https://github.com/505e06b2/Wireless-Lagswitch
cd Wireless-Lagswitch
git submodule update --init --recursive --remote
cd virgin_media_superhub
./main.py
```
