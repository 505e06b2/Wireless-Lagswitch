#include "os_specific.h"

#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>

#define ADAPTER_ARRAY_SIZE (64 * 1024) //64k

/*

!! GetAdaptersAddresses WILL CRASH WINE !!

*/

//IF YOU USE THIS, MAKE SURE TO FREE
static IP_ADAPTER_ADDRESSES *getMatchingAdapter(IP_ADAPTER_ADDRESSES **found_interface, const char *name) {
	const char *guid = name+12; //remove prefix
	IP_ADAPTER_ADDRESSES *adapter_addresses = (IP_ADAPTER_ADDRESSES *)malloc(ADAPTER_ARRAY_SIZE);
	long unsigned int out_length = ADAPTER_ARRAY_SIZE;
	int ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, adapter_addresses, &out_length);
	if(ret == NO_ERROR) {
		IP_ADAPTER_ADDRESSES *current_address = adapter_addresses;
		for(; current_address; current_address = current_address->Next) {
			if(strcmp(current_address->AdapterName, guid) == 0) {
				*found_interface = current_address;
				return adapter_addresses;
			}
		}
	} else {
		fprintf(stderr, "Error calling GetAdaptersAddresses\n");
		exit(1);
	}
	*found_interface = NULL;
	free(adapter_addresses);
	return NULL;
}

void os_getMACFromDeviceName(mac_address_t out, const char *name) {
	IP_ADAPTER_ADDRESSES *found_interface;
	IP_ADAPTER_ADDRESSES *all_interfaces = getMatchingAdapter(&found_interface, name);
	memcpy(out, found_interface->PhysicalAddress, sizeof(mac_address_t));
	free(all_interfaces);
}

//this will only work on Vista+
void os_getGatewayIPv4FromDeviceName(ip_address_t out, const char *name) {
	IP_ADAPTER_ADDRESSES *found_interface;
	IP_ADAPTER_ADDRESSES *all_interfaces = getMatchingAdapter(&found_interface, name);
	for(IP_ADAPTER_GATEWAY_ADDRESS_LH *gateway_address = found_interface->FirstGatewayAddress; gateway_address; gateway_address = gateway_address->Next) {
		const struct sockaddr_in *gateway_sockaddr = (struct sockaddr_in *)gateway_address->Address.lpSockaddr;
		if(gateway_sockaddr->sin_family == AF_INET) {
			memcpy(out, &gateway_sockaddr->sin_addr.s_addr, sizeof(ip_address_t)); //this is the Vista+ property
			break;
		}
	}
	free(all_interfaces);
}
