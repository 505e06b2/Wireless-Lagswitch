#include "arp.h"

extern char *errbuf; //main.c

//args.c
extern ip_address_t ARGUMENT_target_ip;
extern mac_address_t ARGUMENT_target_mac;
extern uint32_t ARGUMENT_arp_timeout;

static FoundMachines_t *findMachinesOnTheNetwork(Machine_t *gateway, const ThisMachine_t *this_machine, pcap_t *pcap) {
	uint32_t host_order_netmask = ntohl(*(in_addr_t *)this_machine->netmask);
	uint32_t min_ipv4 = ntohl(*(in_addr_t *)gateway->ip) & host_order_netmask; //will be in host format, so it can be incremented properly
	min_ipv4++; //one more than 0
	uint32_t max_ipv4 = min_ipv4 | (~host_order_netmask);
	max_ipv4--; //one less than broadcast

	uint32_t current_ipv4 = min_ipv4;
	ARPPacket_t arp_request = {0};
	ARPPacket_t *arp_response = NULL;
	FoundMachines_t *ret = NULL;
	FoundMachines_t **current_found_machine = &ret;

	//set this here, so capturing is given the full amount of time
	setPcapFilter(pcap, "arp [6:2] = 2");
	if(pcap_setnonblock(pcap, 1, errbuf) == -1) { //or could be an infinite wait
		fprintf(stderr, "Error setting non blocking mode: %s\n", errbuf);
		return NULL;
	}

	//fill arp packet
	memset(arp_request.eth.dst, 0xff, sizeof(mac_address_t));
	memcpy(arp_request.eth.src, this_machine->mac, sizeof(mac_address_t));
	arp_request.eth.ethertype = htons(0x0806); //arp

	arp_request.arp.htype = htons(0x0001); //ethernet
	arp_request.arp.ptype = htons(0x0800); //ipv4
	arp_request.arp.hlen = sizeof(mac_address_t); //hardware address len
	arp_request.arp.plen = sizeof(ip_address_t); //ip address len
	arp_request.arp.op = htons(ARPOP_REQUEST);
	memcpy(arp_request.arp.src_mac, this_machine->mac, sizeof(mac_address_t));
	memcpy(arp_request.arp.src_ip, this_machine->ip, sizeof(ip_address_t));
	memset(arp_request.arp.dst_mac, 0x00, sizeof(mac_address_t));
	*(in_addr_t *)arp_request.arp.dst_ip = htonl(current_ipv4);

	//send all requests
	#if DEBUG
		printf("DEBUG: Sending %u ARP requests\n", (max_ipv4 - min_ipv4));
	#endif
	for(current_ipv4 = min_ipv4; current_ipv4 <= max_ipv4; current_ipv4++) {
		*(in_addr_t *)arp_request.arp.dst_ip = htonl(current_ipv4);
		if(*(in_addr_t *)arp_request.arp.dst_ip == *(in_addr_t *)this_machine->ip) continue; //don't need to scan self
		if(pcap_sendpacket(pcap, (const unsigned char *)&arp_request, sizeof(arp_request)) != 0) {
			#if DEBUG //debug as these errors are annoying in Termux - may need to account for Try Again?
				fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
			#endif
		}
	}

	int next_ret;
	struct pcap_pkthdr *response_packet_header;
	#if DEBUG
		printf("DEBUG: Waiting %u second(s) for ARP responses\n", ARGUMENT_arp_timeout);
	#endif
	for(time_t now = time(NULL); (time(NULL) - now) < ARGUMENT_arp_timeout; ) { //wait ARP_REPLY_WAIT_TIME seconds
		next_ret = pcap_next_ex(pcap, &response_packet_header, (const unsigned char **)&arp_response);
		if(next_ret != 1) { //if not got a new packet, don't continue
			if(next_ret == PCAP_ERROR) fprintf(stderr, "Error reading packet\n");
			continue;
		}
		if(arp_response == NULL) continue; //safeguard - probably not needed
		if(arp_response->eth.ethertype == htons(0x0806) && arp_response->arp.op == htons(0x0002)) { //arp packet && reply
			if(*(in_addr_t *)arp_response->arp.src_ip == *(in_addr_t *)gateway->ip) {
				memcpy(gateway->mac, arp_response->arp.src_mac, sizeof(mac_address_t));
				#if DEBUG
					printf("DEBUG: Found gateway mac: %02x:%02x:%02x:%02x:%02x:%02x\n", gateway->mac[0], gateway->mac[1], gateway->mac[2], gateway->mac[3], gateway->mac[4], gateway->mac[5]);
				#endif
			} else { //don't do any checks, just add to foundmachines so as many requests can be handled in ARP_REPLY_WAIT_TIME - this also makes this function generic and reusable
				*current_found_machine = calloc(1, sizeof(FoundMachines_t)); //calloc for safety
				memcpy((*current_found_machine)->ip, arp_response->arp.src_ip, sizeof(ip_address_t));
				memcpy((*current_found_machine)->mac, arp_response->arp.src_mac, sizeof(mac_address_t));
				current_found_machine = &(*current_found_machine)->next;
			}
		}
	}
	//never found gateway MAC
	if(memcmp(gateway->mac, "\0\0\0\0\0\0", sizeof(mac_address_t)) == 0) {
		fprintf(stderr, "Didn't find the gateway's MAC address (is the IP correct?)\n");
		exit(2);
	}

	//back to default (blocking)
	if(pcap_setnonblock(pcap, 0, errbuf) == -1) { //or could be an infinite wait
		fprintf(stderr, "Error setting non blocking mode: %s\n", errbuf);
		return NULL;
	}

	return ret;
}

static const mac_address_prefix_t known_ps4_mac_prefixes[] = {
	//sony entertainment
	{0x00,0x04,0x1f}, {0x00,0x13,0x15}, {0x00,0x15,0xc1}, {0x00,0x19,0xc5}, {0x00,0x1d,0x0d}, {0x00,0x1f,0xa7}, {0x00,0x24,0x8d}, {0x00,0xd9,0xd1}, {0x00,0xe4,0x21}, {0x0c,0xfe,0x45}, {0x28,0x0d,0xfc}, {0x2c,0xcc,0x44}, {0x70,0x9e,0x29}, {0x78,0xc8,0x81}, {0xa8,0xe3,0xee}, {0xbc,0x60,0xa7}, {0xc8,0x63,0xf1}, {0xf8,0x46,0x1c}, {0xf8,0xd0,0xac}, {0xfc,0x0f,0xe6},
	//hon hai precision - my PS4's WAN card has this address
	{0xec, 0x0e, 0xc4}
};

void findPS4(Machine_t *gateway, Machine_t *ps4, const ThisMachine_t *this_machine, pcap_t *pcap) {
	size_t found_devices = 0;
	int using_commandline_ip = 0;
	int using_commandline_mac = 0;
	FoundMachines_t *previous_machine = NULL;
	FoundMachines_t *current_machine = findMachinesOnTheNetwork(gateway, this_machine, pcap);

	if(memcmp(ARGUMENT_target_ip, "\0\0\0\0", sizeof(ip_address_t)) != 0) using_commandline_ip = 1;
	if(memcmp(ARGUMENT_target_mac, "\0\0\0\0\0\0", sizeof(mac_address_t)) != 0) using_commandline_mac = 1;

	while(current_machine) {
		//check hasn't been specified, continue || check has been specified and passes, continue
		if(using_commandline_ip == 0 || memcmp(current_machine->ip, ARGUMENT_target_ip, sizeof(ip_address_t)) == 0) {
			if(using_commandline_mac) {
				if(memcmp(current_machine->mac, ARGUMENT_target_mac, sizeof(mac_address_t)) == 0) {
					memcpy(ps4->ip, current_machine->ip, sizeof(ip_address_t));
					memcpy(ps4->mac, current_machine->mac, sizeof(mac_address_t));
					found_devices++;
				}
			} else {
				for(size_t i = 0; i < sizeof(known_ps4_mac_prefixes); i++) {
					if(memcmp(current_machine->mac, known_ps4_mac_prefixes[i], sizeof(mac_address_prefix_t)) == 0) {
						#if DEBUG
							printf("DEBUG: Found PS4 mac: %02x:%02x:%02x:%02x:%02x:%02x\n", current_machine->mac[0], current_machine->mac[1], current_machine->mac[2], current_machine->mac[3], current_machine->mac[4], current_machine->mac[5]);
						#endif
						memcpy(ps4->ip, current_machine->ip, sizeof(ip_address_t));
						memcpy(ps4->mac, current_machine->mac, sizeof(mac_address_t));
						found_devices++;
						break;
					}
				}
			}
		}

		previous_machine = current_machine;
		current_machine = current_machine->next;
		free(previous_machine);
	}

	if(found_devices > 1) {
		fprintf(stderr, "Found %zu valid devices on the network; can't determine target\n", found_devices);
		exit(1);
	} else if(found_devices < 1) {
		fprintf(stderr, "No valid devices found on the network\n");
		exit(1);
	}
}

void fillARPPacket(ARPPacket_t *packet, Machine_t *src_machine, Machine_t *dst_machine, uint16_t arp_operation, mac_address_t interface_mac) {
	memcpy(packet->eth.dst, dst_machine->mac, sizeof(mac_address_t));
	memcpy(packet->eth.src, interface_mac, sizeof(mac_address_t));
	packet->eth.ethertype = htons(0x0806);

	packet->arp.htype = htons(0x0001);
	packet->arp.ptype = htons(0x0800);
	packet->arp.hlen = sizeof(mac_address_t);
	packet->arp.plen = sizeof(ip_address_t);
	packet->arp.op = htons(arp_operation);
	memcpy(packet->arp.src_mac, src_machine->mac, sizeof(mac_address_t));
	memcpy(packet->arp.src_ip, src_machine->ip, sizeof(ip_address_t));
	memcpy(packet->arp.dst_mac, dst_machine->mac, sizeof(mac_address_t));
	memcpy(packet->arp.dst_ip, dst_machine->ip, sizeof(ip_address_t));
}
