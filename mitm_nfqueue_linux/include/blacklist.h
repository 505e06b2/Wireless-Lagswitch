#ifndef BLACKLIST_H
#define BLACKLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct BlacklistRange {
	in_addr_t start; //inclusive
	in_addr_t end; //inclusive
	struct BlacklistRange *next;
} BlacklistRange_t;

void parseBlacklistIPRanges(int, const char **);

#endif
