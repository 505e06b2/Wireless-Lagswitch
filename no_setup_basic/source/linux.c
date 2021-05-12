#include "os_specific.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAC_ADDRESS_FILE "/sys/class/net/%s/address"
#define GATEWAY_IP_FILE "/proc/net/route"

//used as fallback if not given by pcap_findalldevs, the windows version is required
void os_getMACFromDeviceName(mac_address_t out, const char *name) {
	char *buffer = malloc(strlen(name) + sizeof(MAC_ADDRESS_FILE)); //keep it simple, but should be enough
	sprintf(buffer, MAC_ADDRESS_FILE, name);
	FILE *f = fopen(buffer, "r");
	if(f == NULL) {
		fprintf(stderr, "Can't open %s for reading", buffer);
		return;
	}
	if(fscanf(f, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", out,out+1,out+2,out+3,out+4,out+5) < 6) {
		memset(out, 0, sizeof(mac_address_t)); //set to 00:00:00:00:00:00 on fail
	}
	fclose(f);

	free(buffer);
}

void os_getGatewayIPv4FromDeviceName(ip_address_t out, const char *name) {
	char buffer[512];
	FILE *f = fopen(GATEWAY_IP_FILE, "r");
	if(f == NULL) {
		fprintf(stderr, "Can't open %s for reading", GATEWAY_IP_FILE);
		return;
	}
	if(fgets(buffer, sizeof(buffer), f) == NULL) { //skip first line - then no more contents so return
		fclose(f);
		return;
	}

	while(fgets(buffer, sizeof(buffer), f)) {
		const char *interface_name = strtok(buffer, "\t");
		if(strcmp(interface_name, name) == 0) {
			const uint32_t destination = strtoul(strtok(NULL, "\t"), NULL, 16);
			if(destination == 0) { //0.0.0.0
				const uint32_t gateway = strtoul(strtok(NULL, "\t"), NULL, 16);
				memcpy(out, &gateway, sizeof(ip_address_t));
				break;
			}
		}
	}
	fclose(f);
}
