#include "networking.h"
#include "os_specific.h"

//will get the interface name, while also getting its mac/ip/netmask
pcap_if_t *findInterfaceInformation(ThisMachine_t *this_machine, pcap_if_t *all_devices) {
	pcap_if_t *ret = NULL;

	for(pcap_if_t *ptr = all_devices; ptr->next; ptr = ptr->next) {
		if(ptr->addresses == NULL) continue;
		//if(strcmp(ptr->name, wanted_name) != 0) continue; //add it later?, just use first working one for now
		for(pcap_addr_t *addr_ptr = ptr->addresses; addr_ptr; addr_ptr = addr_ptr->next) {
			switch(addr_ptr->addr->sa_family) { // /usr/include/bits/socket.h
				case AF_PACKET: {//(17) MAC for Linux + WINE - NETBIOS for Windows (which probably won't trigger)
					const struct sockaddr_ll *socket_addr = (struct sockaddr_ll *)addr_ptr->addr;
					memcpy(this_machine->mac, socket_addr->sll_addr, sizeof(mac_address_t));
				} break;

				case AF_INET: {//(2) ipv4 - if any of these are NULL, just crash lol
					const struct sockaddr_in *address = (struct sockaddr_in *)addr_ptr->addr;
					*((in_addr_t *)this_machine->ip) = address->sin_addr.s_addr;

					const struct sockaddr_in *netmask = (struct sockaddr_in *)addr_ptr->netmask;
					*((in_addr_t *)this_machine->netmask) = netmask->sin_addr.s_addr;
				} break;
			}
		}

		if(*((in_addr_t *)this_machine->ip) == 0 || *((in_addr_t *)this_machine->netmask) == 0) continue; //didn't manage to get ipv4 info, trying another device

		strncpy(this_machine->name, (ptr->description) ? ptr->description : ptr->name, sizeof(this_machine->name)-1); //windows uses GUID as interface name
		ret = ptr;
		break;
	}

	if(ret == NULL || *((in_addr_t *)this_machine->ip) == 0 || *(in_addr_t *)this_machine->netmask == 0) {
		fprintf(stderr, "No valid interfaces found - ensure IPv4 is enabled\n");
		return NULL;
	}

	//will always trigger on Windows
	if(memcmp(this_machine->mac, "\0\0\0\0\0\0", sizeof(mac_address_t)) == 0) {
		os_getMACFromDeviceName(this_machine->mac, ret->name); //attempt 2 - OS specific
	}

	//check again and if failed, that's it...
	if(memcmp(this_machine->mac, "\0\0\0\0\0\0", sizeof(mac_address_t)) == 0) {
		fprintf(stderr, "Cannot find MAC address for device: %s", ret->name);
		if(ret->description) fprintf(stderr, " (%s)", ret->description);
		fprintf(stderr, "\n");
		return NULL;
	}

	return ret;
}
