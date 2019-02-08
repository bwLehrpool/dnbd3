#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "../shared/fdsignal.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct _dnbd3_async;

typedef struct _dnbd3_async {
	struct _dnbd3_async *next; // Next in this linked list (provate field, not set by caller)
	dnbd3_signal_t* signal; // Used to signal the caller
	char* buffer;      // Caller-provided buffer to be filled
	uint64_t time; // When request was put on wire, 0 if not measuring
	uint64_t offset;
	uint32_t length;
	bool finished;     // Will be set to true if the request has been handled
	bool success;      // Will be set to true if the request succeeded
} dnbd3_async_t;

bool connection_init(const char *hosts, const char *image, const uint16_t rid);

bool connection_initThreads();

uint64_t connection_getImageSize();

bool connection_read(dnbd3_async_t *request);

void connection_close();

size_t connection_printStats(char *buffer, const size_t len);

#endif /* CONNECTION_H_ */
