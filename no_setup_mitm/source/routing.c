#include "routing.h"

#define LONGEST_FILTER "ip host 255.255.255.255"
#define FILTER_TEMPLATE "ip host %hhu.%hhu.%hhu.%hhu"

static void printMac(const mac_address_t mac_array) {
	printf("%02x", mac_array[0]);
	for(int i = 1; i < 6; i++) printf(":%02x", mac_array[i]);
}

static void helper_checkPacket(const uint8_t *packet) {
	printf("===== PACKET =====\n");
	printf("Target MAC: "); printMac(((EthHeader_t *)packet)->dst); printf("\n");
	printf("Source MAC: "); printMac(((EthHeader_t *)packet)->src); printf("\n");
}

typedef struct RoutingThreadArgs {
	pcap_t *pcap;
	int *toggled_on;
	Machine_t *src;
	Machine_t *dst;
	ThisMachine_t *this;
} RoutingThreadArgs_t;

//UNFINISHED, WITH NO INTENTION TO BE COMPLETED
static void *routingThreadFunction(void *args) {
	pcap_t *pcap = ((RoutingThreadArgs_t *)args)->pcap;
	int *toggled_on = ((RoutingThreadArgs_t *)args)->toggled_on;
	Machine_t *src = ((RoutingThreadArgs_t *)args)->src;
	Machine_t *dst = ((RoutingThreadArgs_t *)args)->dst;
	ThisMachine_t *this = ((RoutingThreadArgs_t *)args)->this;
	free(args);

	{
		const uint8_t *ip = dst->ip;
		char filter_buffer[sizeof(LONGEST_FILTER)];
		sprintf(filter_buffer, FILTER_TEMPLATE, ip[0], ip[1], ip[2], ip[3]);
		setPcapFilter(pcap, filter_buffer);
	}

	const uint8_t *received_packet = NULL;
	uint8_t sending_packet[MTU];
	int next_ret;
	struct pcap_pkthdr *response_packet_header;
	while(1) { //don't need to check for running, since this should continue to work while trying to restore
		next_ret = pcap_next_ex(pcap, &response_packet_header, &received_packet);
		if(next_ret != 1) {
			if(next_ret == PCAP_ERROR) fprintf(stderr, "Error reading packet\n");
			continue;
		}
		if(received_packet == NULL) continue; //safeguard - probably not needed
		if(((EthHeader_t *)received_packet)->ethertype != htons(0x0800)) continue; //probably don't need to check since the filter's in place?

		memcpy(sending_packet, received_packet, response_packet_header->caplen); //editable packet
		if(memcmp(((EthHeader_t *)received_packet)->src, src->mac, sizeof(mac_address_t)) == 0) { //sent from gateway
			memcpy(((EthHeader_t *)sending_packet)->dst, dst->mac, sizeof(mac_address_t));
		} else {
			memcpy(((EthHeader_t *)sending_packet)->dst, src->mac, sizeof(mac_address_t));
		}
		memcpy(((EthHeader_t *)sending_packet)->src, this->mac, sizeof(mac_address_t));
		//helper_checkPacket(sending_packet);
		pcap_sendpacket(pcap, sending_packet, response_packet_header->caplen);
	}
	return NULL;
}

void initialiseRoutingThread(pthread_t *thread, pcap_t *pcap, int *toggled_on, Machine_t *src, Machine_t *dst, ThisMachine_t *this) {
	RoutingThreadArgs_t *args = malloc(sizeof(RoutingThreadArgs_t)); //scope will be destroyed immediately, so put on heap
	args->pcap = pcap;
	args->toggled_on = toggled_on;
	args->src = src;
	args->dst = dst;
	args->this = this;

	pthread_create(thread, NULL, routingThreadFunction, args);
}
