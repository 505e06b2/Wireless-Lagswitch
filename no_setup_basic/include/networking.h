#ifndef NETWORKING_TYPES_H
#define NETWORKING_TYPES_H

#include <pcap.h>
#include <string.h>

#if __MINGW32__
	struct sockaddr_ll { //doesn't exist on Windows
		unsigned short sll_family;   /* Always AF_PACKET */
		unsigned short sll_protocol; /* Physical-layer protocol */
		int            sll_ifindex;  /* Interface number */
		unsigned short sll_hatype;   /* ARP hardware type */
		unsigned char  sll_pkttype;  /* Packet type */
		unsigned char  sll_halen;    /* Length of address */
		unsigned char  sll_addr[8];  /* Physical-layer address */
	};

	#define AF_PACKET 17
	typedef uint32_t in_addr_t;
	#define ARPOP_REQUEST 1
	#define ARPOP_REPLY 2
#else
	#include <arpa/inet.h> //htons & in_addr_t
	#include <net/if_arp.h> //ARPOP_REQUEST
	#include <linux/if_packet.h> //sockaddr_ll
#endif

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

pcap_if_t *findInterfaceInformation(ThisMachine_t *, pcap_if_t *);

#endif
