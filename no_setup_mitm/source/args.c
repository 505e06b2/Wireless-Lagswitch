#include "args.h"

#define DEFAULT_ARP_TIMEOUT 1

ip_address_t ARGUMENT_gateway_ip = {0};
ip_address_t ARGUMENT_netmask = {0};
ip_address_t ARGUMENT_target_ip = {0};
mac_address_t ARGUMENT_target_mac = {0};
uint32_t ARGUMENT_arp_timeout = DEFAULT_ARP_TIMEOUT;

static void getMACFromString(mac_address_t mac_out, const char *str) {
	if(sscanf(str, "%3hhx:%3hhx:%3hhx:%3hhx:%3hhx:%3hhx", mac_out, mac_out+1, mac_out+2, mac_out+3, mac_out+4, mac_out+5) < 6) {
		fprintf(stderr, "Invalid MAC: %s\n", str);
		exit(2);
	}
}

static void getIPFromString(ip_address_t ip_out, const char *str) {
	if(sscanf(str, "%3hhu.%3hhu.%3hhu.%3hhu", ip_out, ip_out+1, ip_out+2, ip_out+3) < 4) {
		fprintf(stderr, "Invalid IP: %s\n", str);
		exit(2);
	}
}

void parseCommandlineParameters(int argc, char **argv) {
	int c;
	int option_index = 0;

    struct option long_options[] = {
		{"gateway_ip", required_argument, NULL, 'g'},
		{"netmask", required_argument, NULL, 'n'},
		{"target_ip", required_argument, NULL, 'i'},
		{"target_mac", required_argument, NULL, 'm'},
		{"arp_timeout", required_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};

	while(1) {
		c = getopt_long(argc, argv, "g:n:i:m:t:h", long_options, &option_index);
		if(c == -1)
			break;

		switch(c) {
			case 'g':
				getIPFromString(ARGUMENT_gateway_ip, optarg);
				break;

			case 'n': {
					int netmask_bits = strtol(optarg, NULL, 10);
					if(netmask_bits < 0 || netmask_bits > 32) {
						fprintf(stderr, "Invalid netmask bits: %d\n", netmask_bits);
						exit(2);
					}
					*(in_addr_t*)ARGUMENT_netmask = htonl(~(0xffffffff >> netmask_bits));
				} break;

			case 'i':
				getIPFromString(ARGUMENT_target_ip, optarg);
				break;

			case 'm':
				getMACFromString(ARGUMENT_target_mac, optarg);
				break;

			case 't':
				ARGUMENT_arp_timeout = strtol(optarg, NULL, 10);
				if(ARGUMENT_arp_timeout == 0) ARGUMENT_arp_timeout = DEFAULT_ARP_TIMEOUT;
				break;

			case 'h':
				printf("usage: give_me_a_clean [-h] [-g GATEWAY_IP] [-n NETMASK] [-i TARGET_IP] [-m TARGET_MAC] [-t ARP_TIMEOUT]");
				printf("\n");
				printf("optional arguments:\n");
				printf("-h, --help         Show this help message\n");
				printf("-g, --gateway_ip   Specify the gateway IP address\n");
				printf("-n, --netmask      Specify the netmask to use for network search\n");
				printf("-i, --target_ip    Specify the target IP address\n");
				printf("-m, --target_mac   Specify the target MAC address\n");
				printf("-t, --arp_timeout  Specify the length of time to wait for ARP responses (in seconds)\n");
				exit(1);

			default:
				exit(2);
        }
    }
}
