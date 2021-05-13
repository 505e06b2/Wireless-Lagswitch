#ifndef OS_SPECIFIC_H
#define OS_SPECIFIC_H

#include <stdint.h>
#include "networking.h"

void os_getMACFromDeviceName(mac_address_t, const char *);

void os_getGatewayIPv4FromDeviceName(ip_address_t, const char *);

#endif
