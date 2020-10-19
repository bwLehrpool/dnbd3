#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <dnbd3/shared/fdsignal.h>
#include <dnbd3/shared/timing.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#define FUSE_USE_VERSION 30
#include <fuse_lowlevel.h>


extern atomic_bool keepRunning;
struct _dnbd3_async;

typedef struct _dnbd3_async {
	struct _dnbd3_async *next; // Next in this linked list (provate field, not set by caller)
	ticks time;        // When request was put on wire, 0 if not measuring
	uint64_t offset;
	uint32_t length;
	fuse_req_t fuse_req;
	char buffer[]; // Must be last member!
} dnbd3_async_t;

bool connection_init( const char *hosts, const char *image, const uint16_t rid, const bool learnNewServers );

bool connection_initThreads();

uint64_t connection_getImageSize();

bool connection_read( dnbd3_async_t *request );

void connection_close();

void connection_join();

size_t connection_printStats( char *buffer, const size_t len );

#endif /* CONNECTION_H_ */
