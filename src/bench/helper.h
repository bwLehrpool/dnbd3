#ifndef IMAGEHELPER_H
#define IMAGEHELPER_H

#include "../types.h"

#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

typedef struct log_info {
	uint64_t imageSize;
	uint64_t receivedBytes;
	uint64_t imageBlockCount;
	uint8_t *blockRequestCount;
} log_info;


typedef struct BenchCounters {
	int attempts;
	int success;
	int fails;
} BenchCounters;


typedef struct BenchThreadData {
	BenchCounters* counter;
	char* server_address;
	char * image_name;
	int runs;
	int threadNumber;
	bool closeSockets;
} BenchThreadData;



#endif
