#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pthread.h>

#include "os_specific.h"
#include "arp.h"
#include "networking_types.h"

#if __MINGW32__
	#include <windows.h> //sleep
#else
	#include <unistd.h> //sleep
#endif

char errbuf[PCAP_ERRBUF_SIZE];
ARPPacket_t poison_packet;
ARPPacket_t restore_packet;
int poison = 0; //determine if we should currently poison

void printMac(const mac_address_t mac_array) {
	printf("%02x", mac_array[0]);
	for(int i = 1; i < 6; i++) printf(":%02x", mac_array[i]);
}

void printIP(const ip_address_t ip) {
	const uint8_t *ptr = ip; //remove warning with cast
	printf("%3u.%3u.%3u.%3u", ptr[0], ptr[1], ptr[2], ptr[3]);
}

void printMachineInfo(const char *name, const Machine_t *m) {
	printf("%10s: ", name);
	printIP(m->ip);
	printf(" / ");
	printMac(m->mac);
	printf("\n");
}

void *arpThreadFunction(void *arg) {
	pcap_t *pcap = (pcap_t *)arg;
	int ret;
	while(1) {
		if(poison) ret = pcap_sendpacket(pcap, (const unsigned char *)&poison_packet, sizeof(poison_packet));
		else ret = pcap_sendpacket(pcap, (const unsigned char *)&restore_packet, sizeof(restore_packet));
		if(ret != 0) {
			printf("!Failed to send packet!\n");
		}
		#if __MINGW32__
			Sleep(1000);
		#else
			sleep(1);
		#endif
	}
	return NULL;
}

int main() {
	#if DEBUG
		printf("\n\n                 !!! Debug Build !!!\n\n");
	#endif

	pcap_if_t *all_devices;
	pcap_findalldevs(&all_devices, errbuf);
	if(all_devices == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	ThisMachine_t this_machine = {0};
	pcap_if_t *this_machine_interface = all_devices;

	for(pcap_if_t *ptr = all_devices; ptr->next; ptr = ptr->next) {
		if(ptr->addresses == NULL) continue;
		//if(strcmp(ptr->name, wanted_name) != 0) continue; //add it later?, just use first working one for now
		for(pcap_addr_t *addr_ptr = ptr->addresses; addr_ptr; addr_ptr = addr_ptr->next) {
			switch(addr_ptr->addr->sa_family) { // /usr/include/bits/socket.h
				case AF_PACKET: {//(17) MAC for Linux + WINE - NETBIOS for Windows (which probably won't trigger)
					const struct sockaddr_ll *socket_addr = (struct sockaddr_ll *)addr_ptr->addr;
					memcpy(this_machine.mac, socket_addr->sll_addr, sizeof(this_machine.mac));
				} break;

				case AF_INET: {//(2) ipv4 - if any of these are NULL, just crash lol
					const struct sockaddr_in *address = (struct sockaddr_in *)addr_ptr->addr;
					*((in_addr_t *)this_machine.ip) = address->sin_addr.s_addr;

					const struct sockaddr_in *netmask = (struct sockaddr_in *)addr_ptr->netmask;
					*((in_addr_t *)this_machine.netmask) = netmask->sin_addr.s_addr;
				} break;

				//case 23: //Windows inet6 - https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
					//break;
			}
		}

		if(*((in_addr_t *)this_machine.ip) == 0 || *((in_addr_t *)this_machine.netmask) == 0) continue; //didn't manage to get ipv4 info, trying another device

		strncpy(this_machine.name, (ptr->description) ? ptr->description : ptr->name, sizeof(this_machine.name)-1); //windows uses GUID as interface name
		this_machine_interface = ptr;
		break;
	}

	if(this_machine_interface == NULL || *((in_addr_t *)this_machine.ip) == 0 || *(in_addr_t *)this_machine.netmask == 0) {
		fprintf(stderr, "No valid interfaces found - ensure IPv4 is enabled\n");
		return 1;
	}

	//will always trigger on Windows
	if(memcmp(this_machine.mac, "\0\0\0\0\0\0", 6) == 0) {
		os_getMACFromDeviceName(this_machine.mac, this_machine_interface->name); //attempt 2 - OS specific
	}

	//check again and if failed, that's it...
	if(memcmp(this_machine.mac, "\0\0\0\0\0\0", 6) == 0) {
		fprintf(stderr, "Cannot find MAC address for device: %s", this_machine_interface->name);
		if(this_machine_interface->description) fprintf(stderr, " (%s)", this_machine_interface->description);
		fprintf(stderr, "\n");
		return 1;
	}

	printf("%10s: %-15s", "Interface", this_machine.name); printf("\n");
	printf("%10s: ", "MAC"); printMac(this_machine.mac); printf("\n");
	printf("%10s: ", "IPv4"); printIP(this_machine.ip); printf("\n");
	printf("%10s: ", "Netmask"); printIP(this_machine.netmask); printf("\n");
	printf("\n");

	//start
	pcap_t *pcap = pcap_open_live(this_machine_interface->name,
		64,			// buffer len
		1,				// promiscuous mode
		100,			// timeout
		errbuf			// error buffer
	);
	if(pcap == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}
	if(pcap_datalink(pcap) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", this_machine_interface->name);
		return 1;
	}
	{ //filtering
		struct bpf_program pcap_filter_arp;
		if(pcap_compile(pcap, &pcap_filter_arp, "arp [6:2] = 2", 1, *(in_addr_t *)this_machine.netmask) == -1) {
			fprintf(stderr, "Couldn't parse arp filter: %s\n", pcap_geterr(pcap));
			return 1;
		}
		if(pcap_setfilter(pcap, &pcap_filter_arp) == -1) {
			fprintf(stderr, "error setting arp filter: %s\n", pcap_geterr(pcap));
			return(2);
		}
	}
	pcap_setnonblock(pcap, 1, errbuf); //or could be an infinite wait

	//create machines
	Machine_t src_machine = {0}; //Gateway
	os_getGatewayIPv4FromDeviceName(src_machine.ip, this_machine_interface->name);
	pcap_freealldevs(all_devices);
	all_devices = NULL;
	this_machine_interface = NULL;

	Machine_t dst_machine = {0}; //PS4

	findPS4(&src_machine, &dst_machine, &this_machine, pcap);

	printMachineInfo("Gateway", &src_machine);
	printMachineInfo("PS4", &dst_machine);

	//fill restore packet with real values
	memcpy(restore_packet.eth.dst, dst_machine.mac, sizeof(mac_address_t));
	memcpy(restore_packet.eth.src, this_machine.mac, sizeof(mac_address_t));
	restore_packet.eth.ethertype = htons(0x0806);

	restore_packet.arp.htype = htons(0x0001);
	restore_packet.arp.ptype = htons(0x0800);
	restore_packet.arp.hlen = sizeof(mac_address_t);
	restore_packet.arp.plen = sizeof(ip_address_t);
	restore_packet.arp.op = htons(ARPOP_REPLY);
	memcpy(restore_packet.arp.src_mac, src_machine.mac, sizeof(mac_address_t));
	memcpy(restore_packet.arp.src_ip, src_machine.ip, sizeof(ip_address_t));
	memcpy(restore_packet.arp.dst_mac, dst_machine.mac, sizeof(mac_address_t));
	memcpy(restore_packet.arp.dst_ip, dst_machine.ip, sizeof(ip_address_t));

	//fill poison packet
	memcpy(&poison_packet, &restore_packet, sizeof(poison_packet));
	//memset(&poison_packet.arp.dst_ip, 0, sizeof(poison_packet.arp.dst_ip));
	memset(&poison_packet.arp.src_mac, 0, sizeof(poison_packet.arp.src_mac));

	#if DEBUG
		{
			FILE *f = fopen("/tmp/packet_hexdump.bytes", "wb");
			if(f) { //just ignore it
				fwrite((uint8_t *)&poison_packet, sizeof(uint8_t), sizeof(ARPPacket_t), f);
				fclose(f);
				printf("\nDEBUG: Wrote raw packet to /tmp/packet_hexdump.bytes\n");
			}
		}
	#endif

	pthread_t arp_thread;
	pthread_create(&arp_thread, NULL, arpThreadFunction, (void*)pcap);
	printf("\nReady to cut - press ENTER to toggle\n");
	while(1) {
		printf("Switch is currently %s", (poison) ? "ON" : "OFF");
		fflush(stdout);
		getchar();
		poison = !poison;
	}
	pcap_close(pcap);

	return 0;
}
