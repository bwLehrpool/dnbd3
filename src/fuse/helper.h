#ifndef IMAGEHELPER_H
#define IMAGEHELPER_H

#include "../protocol.h"
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>


typedef struct log_info {
	uint64_t imageSize;
	uint64_t receivedBytes;
	uint64_t imageBlockCount;
	uint8_t *blockRequestCount;
} log_info;



void printLog(log_info *info);

bool sock_printable(struct sockaddr *addr, socklen_t addrLen, char *output, int len);

int connect_to_server(char *server_adress, int port);

#endif