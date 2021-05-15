#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pthread.h>

#include "arp.h"
#include "networking.h"
#include "os_specific.h"
#include "args.h"

#if __MINGW32__
	#include <windows.h> //sleep
#else
	#include <unistd.h> //sleep
#endif

extern ip_address_t ARGUMENT_gateway_ip;

char errbuf[PCAP_ERRBUF_SIZE];
ARPPacket_t poison_packet;
ARPPacket_t restore_packet;
int poison = 0; //determine if we should currently poison

static pcap_t *openPcap(const char *interface_name) {
	pcap_t *pcap = pcap_open_live(interface_name,
		100,			// buffer len
		1,				// promiscuous mode
		100,			// timeout
		errbuf			// error buffer
	);
	if(pcap == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}
	if(pcap_datalink(pcap) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface_name);
		return NULL;
	}
	{ //filtering
		struct bpf_program pcap_filter_arp;
		if(pcap_compile(pcap, &pcap_filter_arp, "arp [6:2] = 2", 1, PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "Couldn't parse arp filter: %s\n", pcap_geterr(pcap));
			return NULL;
		}
		if(pcap_setfilter(pcap, &pcap_filter_arp) == -1) {
			fprintf(stderr, "Error setting arp filter: %s\n", pcap_geterr(pcap));
			return NULL;
		}
	}
	if(pcap_setnonblock(pcap, 1, errbuf) == -1) { //or could be an infinite wait
		fprintf(stderr, "Error setting non blocking mode: %s\n", errbuf);
		return NULL;
	}
	return pcap;
}

static void printMac(const mac_address_t mac_array) {
	printf("%02x", mac_array[0]);
	for(int i = 1; i < 6; i++) printf(":%02x", mac_array[i]);
}

static void printIP(const ip_address_t ip) {
	const uint8_t *ptr = ip; //remove warning with cast
	printf("%3u.%3u.%3u.%3u", ptr[0], ptr[1], ptr[2], ptr[3]);
}

static void *arpThreadFunction(void *arg) {
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

int main(int argc, char **argv) {
	parseCommandlineParameters(argc, argv);

	#if DEBUG
		printf("\n\n                 !!! Debug Build !!!\n\n");
	#endif

	printf("            Session Cutter\n");
	printf(" ========== github.com/505e06b2/Wireless-Lagswitch\n");
	printf("\n");

	pcap_if_t *all_devices;
	pcap_findalldevs(&all_devices, errbuf);
	if(all_devices == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	//create machines
	ThisMachine_t this_machine = {0};
	pcap_if_t *this_machine_interface = findInterfaceInformation(&this_machine, all_devices);

	Machine_t src_machine = {0}; //Gateway
	if(*(in_addr_t *)ARGUMENT_gateway_ip != 0) {
		memcpy(src_machine.ip, ARGUMENT_gateway_ip, sizeof(ip_address_t));
	} else {
		os_getGatewayIPv4FromDeviceName(src_machine.ip, this_machine_interface->name);
	}

	printf("%10s: %-15s", "Interface", this_machine.name); printf("\n");
	printf("%10s: ", "MAC"); printMac(this_machine.mac); printf("\n");
	printf("%10s: ", "IPv4"); printIP(this_machine.ip); printf("\n");
	printf("%10s: ", "Netmask"); printIP(this_machine.netmask); printf("\n");
	printf("%10s: ", "Gateway"); printIP(src_machine.ip); printf("\n");
	printf("\n");

	pcap_t *pcap = openPcap(this_machine_interface->name);
	if(pcap == NULL) {
		fprintf(stderr, "Could not initialise pcap\n");
		return 1;
	}

	pcap_freealldevs(all_devices);
	all_devices = NULL;
	this_machine_interface = NULL;

	//this requires ARP requests to be ready
	Machine_t dst_machine = {0}; //PS4
	findPS4(&src_machine, &dst_machine, &this_machine, pcap);

	printf("%10s: ", "Router"); printIP(src_machine.ip); printf(" / "); printMac(src_machine.mac); printf("\n");
	printf("%10s: ", "PS4"); printIP(dst_machine.ip); printf(" / "); printMac(dst_machine.mac); printf("\n");

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
	memset(&poison_packet.arp.src_mac, 0, sizeof(poison_packet.arp.src_mac)); //send your gateway requests to 00:00:00:00:00:00 >:)

	pthread_t arp_thread;
	pthread_create(&arp_thread, NULL, arpThreadFunction, (void*)pcap);
	printf("\n =================================================\n");
	printf("\n            Ready to cut\n");
	while(1) {
		printf("  [ %s ] - Press ENTER to toggle", (poison) ? " ON" : "OFF");
		fflush(stdout);
		getchar();
		poison = !poison;
	}
	pcap_close(pcap);
	return 0;
}
