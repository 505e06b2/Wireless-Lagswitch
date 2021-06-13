#include "routing.h"

#define IPTABLES_TEMPLATE "iptables -I FORWARD -p UDP -%c %hhu.%hhu.%hhu.%hhu -j NFQUEUE --queue-num 0"
#define IPTABLES_MAX_EXAMPLE "iptables -I FORWARD -p UDP -d 255.255.255.255 -j NFQUEUE --queue-num 0"

#define ACCEPT nfq_set_verdict(nfq, id, NF_ACCEPT, 0, NULL)
#define DROP nfq_set_verdict(nfq, id, NF_DROP, 0, NULL)

extern int enable_blacklist; //main.c
extern BlacklistRange_t *blacklisted_ip_ranges; //blacklist.c

uint32_t target_ip = 0; //set when thread starts - host order
int received_packet = 0; //can be externed to determine if at least one packet has been captured

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
static void exitWithError(const char *err) {
	fprintf(stderr, err);
	exit(2);
}
#pragma GCC diagnostic pop

void setIPForwardState(const char c) {
	FILE *f = fopen(IP_FORWARD_PATH, "w");
	if(f == NULL) {
		fprintf(stderr, "Could not write to %s\n", IP_FORWARD_PATH);
		exit(2);
	}
	fputc(c, f);
	fclose(f);
}

void setIPTablesRules(const in_addr_t ip) {
	//no usable API: https://www.netfilter.org/documentation/FAQ/netfilter-faq.html#toc4.5
	//THIS IS A NIGHTMARE FOR SECURITY, BUT YOU'RE ALREADY ROOT
	const uint8_t *printable_ip = (uint8_t *)&ip;
	char buffer[sizeof(IPTABLES_MAX_EXAMPLE)] = {0};
	if(system("iptables -X")) exitWithError("Failed to execute 'iptables -X'");
	if(system("iptables -F")) exitWithError("Failed to execute 'iptables -F'");
	sprintf(buffer, IPTABLES_TEMPLATE, 'd', printable_ip[0], printable_ip[1], printable_ip[2], printable_ip[3]);
	if(system(buffer)) exitWithError("Failed to execute iptables for destination");
	sprintf(buffer, IPTABLES_TEMPLATE, 's', printable_ip[0], printable_ip[1], printable_ip[2], printable_ip[3]);
	if(system(buffer)) exitWithError("Failed to execute iptables for source");
}

static int routingCallback(struct nfq_q_handle *nfq, struct nfgenmsg *nfmsg, struct nfq_data *nfdata, void *data) {
	struct nfqnl_msg_packet_hdr *packet_header = nfq_get_msg_packet_hdr(nfdata);
	uint32_t id = ntohl(packet_header->packet_id);

	int payload_length = nfq_get_payload(nfdata, (unsigned char **)&data);
	if(payload_length < sizeof(struct iphdr)) return ACCEPT;
	received_packet = 1; //global flag

	struct iphdr *ip_header = data;
	uint32_t remote_ip = ntohl(ip_header->daddr); //this way saves a call to ntohl
	if(remote_ip == target_ip) remote_ip = ntohl(ip_header->saddr);

	if(enable_blacklist) {
		BlacklistRange_t *current_ip_range = blacklisted_ip_ranges;
		for(; current_ip_range; current_ip_range = current_ip_range->next) {
			if(remote_ip >= ntohl(current_ip_range->start) && remote_ip <= ntohl(current_ip_range->end)) {
				#if DEBUG
					const in_addr_t ip = htonl(remote_ip);
					const uint8_t *ptr = (uint8_t *)&ip;
					fprintf(stderr, "DROP %3u.%3u.%3u.%3u\n", ptr[0], ptr[1], ptr[2], ptr[3]);
				#endif
				return DROP;
			}
		}
	}
	return ACCEPT;
}

void *routingThreadFunction(void *args) {
	target_ip = ntohl(*(in_addr_t *)args);
	char packet_buffer[4096];

	struct nfq_handle *nf = nfq_open();
	if(nf == NULL) exitWithError("Could not initialise NetFilterQueue\n");
	if(nfq_unbind_pf(nf, AF_INET) < 0) exitWithError("Could not unbind existing NetFilterQueue handler\n");
	if(nfq_bind_pf(nf, AF_INET) < 0) exitWithError("Could not bind NetFilterQueue handler\n");

	struct nfq_q_handle *nfq = nfq_create_queue(nf, 0, &routingCallback, NULL);
	if(nfq == NULL) exitWithError("Could not create NetFilter queue\n");
	if(nfq_set_mode(nfq, NFQNL_COPY_PACKET, 0xffff) < 0) exitWithError("Could not set NetFilter queue mode\n");

	int sockfd = nfq_fd(nf);
	ssize_t ret;
	while ((ret = recv(sockfd, packet_buffer, sizeof(packet_buffer), 0))) {
		nfq_handle_packet(nf, packet_buffer, ret);
	}

	nfq_destroy_queue(nfq);
	nfq_close(nf);
	return NULL;
}
