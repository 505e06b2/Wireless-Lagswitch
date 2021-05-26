#ifndef ARGS_H
#define ARGS_H

#include <stdint.h>
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <getopt.h>

#include "networking.h"
#include "blacklist.h"

void parseCommandlineParameters(int, char **);

#endif
