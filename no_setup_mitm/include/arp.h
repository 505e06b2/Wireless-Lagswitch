#ifndef ARP_H
#define ARP_H

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "networking.h"

#pragma pack(push, 1)
	struct ArpHeader {
		uint16_t htype;
		uint16_t ptype;
		uint8_t hlen;
		uint8_t plen;
		uint16_t op;
		mac_address_t src_mac;
		ip_address_t src_ip;
		mac_address_t dst_mac;
		ip_address_t dst_ip;
	};

	typedef struct ARPPacket {
		struct EthHeader eth;
		struct ArpHeader arp;
	} ARPPacket_t;
#pragma pack(pop)

void findPS4(Machine_t *, Machine_t *, const ThisMachine_t *, pcap_t *);
void fillARPPacket(ARPPacket_t *, Machine_t *, Machine_t *, uint16_t, mac_address_t);

#endif
