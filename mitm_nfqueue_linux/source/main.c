#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "arp.h"
#include "networking.h"
#include "routing.h"
#include "os_specific.h"
#include "args.h"

extern ip_address_t ARGUMENT_gateway_ip;
extern ip_address_t ARGUMENT_netmask;
extern int received_packet; //routing.c
extern BlacklistRange_t *blacklisted_ip_ranges; //blacklist.c

char errbuf[PCAP_ERRBUF_SIZE];
ARPPacket_t poison_ps4_packet;
ARPPacket_t poison_gateway_packet;
ARPPacket_t restore_ps4_packet;
ARPPacket_t restore_gateway_packet;
int running = 1;
int enable_blacklist = 0; //used in routing.c
pcap_t *signal_handler_pcap = NULL;

static pcap_t *openPcap(const char *interface_name) {
	pcap_t *pcap = pcap_open_live(interface_name,
		MTU, //buffer length
		1, //promiscuous mode
		100, //timeout (ms)
		errbuf //error buffer
	);
	if(pcap == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}
	if(pcap_datalink(pcap) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface_name);
		return NULL;
	}
	return pcap;
}

static void printMac(const mac_address_t mac_array) {
	printf("%02x", mac_array[0]);
	for(int i = 1; i < 6; i++) printf(":%02x", mac_array[i]);
}

static void printIP(const ip_address_t ptr) {
	printf("%3u.%3u.%3u.%3u", ptr[0], ptr[1], ptr[2], ptr[3]);
}

static void *arpThreadFunction(void *arg) {
	pcap_t *pcap = (pcap_t *)arg;
	while(running) {
		pcap_sendpacket(pcap, (const unsigned char *)&poison_ps4_packet, sizeof(ARPPacket_t));
		pcap_sendpacket(pcap, (const unsigned char *)&poison_gateway_packet, sizeof(ARPPacket_t));

		sleep(1);
	}
	return NULL;
}

//signal handler
static void restoreNetwork(int x) {
	if(running == 0) return; //already exiting
	running = 0;
	if(system("stty sane")) fprintf(stderr, "Can't put terminal into sane mode\n");
	const int seconds_left = 15;
	printf("\n            Restoring network for %ds...\n", seconds_left);
	for(int i = 0; i < seconds_left; i++) {
		pcap_sendpacket(signal_handler_pcap, (const unsigned char *)&restore_ps4_packet, sizeof(ARPPacket_t));
		pcap_sendpacket(signal_handler_pcap, (const unsigned char *)&restore_gateway_packet, sizeof(ARPPacket_t));
		sleep(1);
	}
	setIPForwardState('0');
	exit(1);
}

int main(int argc, char **argv) {
	parseCommandlineParameters(argc, argv);

	#if DEBUG
		printf("\n\n                 !!! Debug Build !!!\n\n");
	#endif

	printf("            Session Cutter - MITM\n");
	printf("            github.com/505e06b2/Wireless-Lagswitch\n\n");

	printf(" ========== Blacklist ============================ \n");
	{
		BlacklistRange_t *current_ip_range = blacklisted_ip_ranges;
		for(; current_ip_range; current_ip_range = current_ip_range->next) {
			printf("          - ");
			printIP((uint8_t *)&current_ip_range->start);
			printf(" -> ");
			printIP((uint8_t *)&current_ip_range->end);
			printf("\n");
		}
		printf("\n");
	}

	pcap_if_t *all_devices;
	pcap_findalldevs(&all_devices, errbuf);
	if(all_devices == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	//create machines
	ThisMachine_t this_machine = {0};
	pcap_if_t *this_machine_interface = findInterfaceInformation(&this_machine, all_devices);
	if(*(in_addr_t *)ARGUMENT_netmask) memcpy(this_machine.netmask, ARGUMENT_netmask, sizeof(ip_address_t));

	Machine_t src_machine = {0}; //Gateway
	if(*(in_addr_t *)ARGUMENT_gateway_ip != 0) {
		memcpy(src_machine.ip, ARGUMENT_gateway_ip, sizeof(ip_address_t));
	} else {
		os_getGatewayIPv4FromDeviceName(src_machine.ip, this_machine_interface->name);
	}

	printf(" ========== Hardware ============================= \n");
	printf(" %10s %-15s", "Interface", this_machine.name); printf("\n");
	printf(" %10s ", "MAC"); printMac(this_machine.mac); printf("\n");
	printf(" %10s ", "IPv4"); printIP(this_machine.ip); printf("\n");
	printf(" %10s ", "Netmask"); printIP(this_machine.netmask); printf("\n");
	printf(" %10s ", "Gateway"); printIP(src_machine.ip); printf("\n");
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

	printf(" %10s ", "Router"); printIP(src_machine.ip); printf(" / "); printMac(src_machine.mac); printf("\n");
	printf(" %10s ", "Target"); printIP(dst_machine.ip); printf(" / "); printMac(dst_machine.mac); printf("\n");

	//fill restore PS4 packet with real values - from Gateway -> PS4
	fillARPPacket(&restore_ps4_packet, &src_machine, &dst_machine, ARPOP_REPLY, this_machine.mac);

	//fill poison PS4 packet
	memcpy(&poison_ps4_packet, &restore_ps4_packet, sizeof(ARPPacket_t));
	memcpy(&poison_ps4_packet.arp.src_mac, this_machine.mac, sizeof(mac_address_t)); //send your gateway packets here >:)

	//fill restore Gateway packet with real values - from PS4 -> Gateway
	fillARPPacket(&restore_gateway_packet, &dst_machine, &src_machine, ARPOP_REPLY, this_machine.mac);

	//fill poison Gateway packet
	memcpy(&poison_gateway_packet, &restore_gateway_packet, sizeof(ARPPacket_t));
	memcpy(&poison_gateway_packet.arp.src_mac, this_machine.mac, sizeof(mac_address_t)); //send your gateway packets here >:)

	printf("\n =================================================\n\n");
	printf("            Initialising IP forward\n");
	setIPForwardState('1');
	setIPTablesRules(*(in_addr_t *)dst_machine.ip);
	pthread_t routing_thread;
	pthread_create(&routing_thread, NULL, routingThreadFunction, (void *)dst_machine.ip);

	printf("            Redirecting traffic (ARP)\n");
	pthread_t arp_thread;
	pthread_create(&arp_thread, NULL, arpThreadFunction, (void *)pcap);

	//set up signal handler
	signal_handler_pcap = pcap;
	signal(SIGINT, restoreNetwork); //CTRL+C
	#if __MINGW32__
		//Windows
		signal(SIGBREAK, restoreNetwork); //Generic Termination
	#else
		//Linux
		signal(SIGTERM, restoreNetwork); //Generic Termination
		signal(SIGHUP, restoreNetwork); //Disconnect from SSH etc
	#endif

	printf("            Waiting for first packet...\n");
	while(received_packet == 0) usleep(100000); //100ms

	printf("            Ready to toggle blacklist :)\n");
	printf("\n =================================================\n\n");
	if(system("stty -echo")) fprintf(stderr, "Can't put terminal into non-echo mode\n");
	printf("            Press CTRL+C to exit\n");
	while(1) {
		printf("\r  [ %s ] - Press ENTER to toggle", (enable_blacklist) ? "\x1b[32;1mON\x1b[0m " : "\x1b[91mOFF\x1b[0m");
		fflush(stdout);
		getchar();
		enable_blacklist = !enable_blacklist;
	}
	//pcap_close(pcap);
	return 0;
}
