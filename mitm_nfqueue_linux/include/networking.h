#ifndef NETWORKING_TYPES_H
#define NETWORKING_TYPES_H

#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#define MTU 1500

#include <arpa/inet.h> //htons & in_addr_t
#include <net/if_arp.h> //ARPOP_REQUEST
#include <linux/if_packet.h> //sockaddr_ll

typedef uint8_t mac_address_t[6];
typedef uint8_t mac_address_prefix_t[3];
typedef uint8_t ip_address_t[4];

typedef struct Machine {
	ip_address_t ip; //run it through htons / inet_addr then cast it
	mac_address_t mac;
} Machine_t;

typedef struct FoundMachines { //linked list
	struct FoundMachines *next;
	ip_address_t ip; //run it through htons / inet_addr then cast it
	mac_address_t mac;
} FoundMachines_t;

typedef struct ThisMachine {
	ip_address_t netmask;
	ip_address_t ip;
	mac_address_t mac;
	char name[36]; //36 since IP addresses + MAC are 35 chars long + \0
} ThisMachine_t;

void setPcapFilter(pcap_t *, const char *);
pcap_if_t *findInterfaceInformation(ThisMachine_t *, pcap_if_t *);

#endif
