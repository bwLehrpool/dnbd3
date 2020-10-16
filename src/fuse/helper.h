#ifndef IMAGEHELPER_H
#define IMAGEHELPER_H

#include <dnbd3/types.h>

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



void printLog( log_info *info );

int connect_to_server( char *server_adress, int port );

static inline bool isSameAddressPort( const dnbd3_host_t * const a, const dnbd3_host_t * const b )
{
	return ( a->type == b->type ) && ( a->port == b->port ) && ( 0 == memcmp( a->addr, b->addr, ( a->type == HOST_IP4 ? 4 : 16 ) ) );
}

static inline bool isSameAddress( const dnbd3_host_t * const a, const dnbd3_host_t * const b )
{
	return ( a->type == b->type ) && ( 0 == memcmp( a->addr, b->addr, ( a->type == HOST_IP4 ? 4 : 16 ) ) );
}

#endif
