#ifndef ROUTING_H
#define ROUTING_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define IP_FORWARD_PATH "/proc/sys/net/ipv4/ip_forward"

typedef struct BlacklistRange {
	in_addr_t start; //inclusive
	in_addr_t end; //inclusive
} BlacklistRange_t;

void setIPForwardState(const char);
void setIPTablesRules(const in_addr_t);
void *routingThreadFunction(void *);

#endif
