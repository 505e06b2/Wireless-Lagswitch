#include "blacklist.h"

#define MAX_RANGE_BUFFER_SIZE sizeof("255.255.255.255/32")

BlacklistRange_t *blacklisted_ip_ranges = NULL;

static const char *default_blacklist[] = { //GTA: Online
	"185.56.65.0/24", //Take-Two "dedicated" servers
	//"185.56.65.0/24", "192.81.240.0/21", //take-two - Matchmaking is located in here
	//"20.33.0.0/16", "20.40.0.0/13", "20.128.0.0/16", "20.36.0.0/14", "20.48.0.0/12", "20.34.0.0/15", "20.64.0.0/10" //Microsoft
};

static void formatError(const char *given) {
	fprintf(stderr, "\"%s\" is not in the correct format - e.g. 20.33.0.0/16\n", given);
	exit(2);
}

void parseBlacklistIPRanges(int length, const char **ranges) {
	if(length <= 0) {
		length = sizeof(default_blacklist) / sizeof(default_blacklist[0]);
		ranges = default_blacklist;
	}

	char buffer[MAX_RANGE_BUFFER_SIZE];
	char *netmask_str;
	char *int_convert_check;

	int netmask_bits;
	BlacklistRange_t **current_ip_range = &blacklisted_ip_ranges;
	for(int i = 0; i < length; i++) {
		strcpy(buffer, ranges[i]);
		netmask_str = strchr(buffer, '/');
		if(netmask_str == NULL) formatError(ranges[i]);
		*netmask_str = '\0';
		netmask_str++;
		if(*netmask_str == '\0') formatError(ranges[i]);

		netmask_bits = strtol(netmask_str, &int_convert_check, 10);
		if(int_convert_check == netmask_str) formatError(ranges[i]);
		if(netmask_bits < 0 || netmask_bits > 32) {
			fprintf(stderr, "\"%s\" has invalid netmask bits: %d\n", ranges[i], netmask_bits);
			exit(2);
		}

		*current_ip_range = calloc(1, sizeof(BlacklistRange_t));
		(*current_ip_range)->start = inet_addr(buffer);
		if((*current_ip_range)->start == INADDR_NONE) formatError(ranges[i]); //will fail on 255.255.255.255
		if(netmask_bits == 32) {
			(*current_ip_range)->end = (*current_ip_range)->start;
		} else {
			(*current_ip_range)->end = (*current_ip_range)->start | (~htonl(~(0xffffffff >> netmask_bits)));
		}
		current_ip_range = &(*current_ip_range)->next;
	}
}
