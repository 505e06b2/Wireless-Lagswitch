#ifndef ROUTING_H
#define ROUTING_H

#include <pcap.h>
#include <pthread.h>

#include "networking.h"

#pragma pack(push, 1)
	typedef struct IpHeader { //remember to convert between network / host byte order - THIS STRUCT IS INCORRECT; GO LOOK AT THE LINUX SOURCE
		uint8_t version: 4; //always == 4 for ipv4
		uint8_t internet_header_length: 4; //size of header -> ihl*32bits
		uint8_t differentiated_services_code_point: 6; //used in VoIP?
		uint8_t explicit_congestion_notification: 2; //helps to not drop packets
		uint16_t total_length; //header + data in bytes
		uint16_t identification;
		uint8_t flags: 3;
		uint16_t fragment_offset: 13;
		uint8_t time_to_live;
		uint8_t protocol; //will be layer 4 - UDP/TCP/etc
		uint16_t header_checksum;
		ip_address_t source_ip_address;
		ip_address_t destination_ip_address;
		uint8_t options[0];
	} IpHeader_t;

	typedef struct TransportHeaderStub {
		uint16_t src_port;
		uint16_t dst_port;
	} TransportHeaderStub_t;

	typedef struct IpPacket {
		EthHeader_t eth;
		IpHeader_t ip;
	} IpPacket_t;
#pragma pack(pop)

void initialiseRoutingThread(pthread_t *, pcap_t *, int *, Machine_t *, Machine_t *, ThisMachine_t *);

#endif
