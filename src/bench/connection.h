#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "../shared/fdsignal.h"
#include <stdbool.h>
#include <stdint.h>
#include "helper.h"

struct _dnbd3_async;

typedef struct _dnbd3_async {
	struct _dnbd3_async *next; // Next in this linked list (provate field, not set by caller)
	char* buffer;      // Caller-provided buffer to be filled
	uint64_t offset;
	uint32_t length;
	dnbd3_signal_t* signal; // Used to signal the caller
	bool finished;     // Will be set to true if the request has been handled
	bool success;      // Will be set to true if the request succeeded
} dnbd3_async_t;


bool connection_init_n_times(const char *hosts, const char *image, const uint16_t rid, int ntimes, uint64_t blockSize, BenchCounters* counters);

bool connection_init(const char *hosts, const char *image, const uint16_t rid);

#endif /* CONNECTION_H_ */
