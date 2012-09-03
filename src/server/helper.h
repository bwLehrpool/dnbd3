#ifndef HELPER_H_
#define HELPER_H_

#include "server.h"
#include <netinet/in.h>
#include <string.h>

char parse_address(char *string, dnbd3_host_t *host);
char host_to_string(const dnbd3_host_t *host, char *target, size_t targetlen);
char is_valid_namespace(char *namespace);
char is_valid_imagename(char *namespace);
void strtolower(char *string);

static inline int is_same_server(const dnbd3_trusted_server_t *const a, const dnbd3_trusted_server_t *const b)
{
	return (a->host.type == b->host.type)
	       && (a->host.port == b->host.port)
	       && (0 == memcmp(a->host.addr, b->host.addr, (a->host.type == AF_INET ? 4 : 16)));
}

// one byte in the map covers 8 4kib blocks, so 32kib per byte
// "+ (1 << 15) - 1" is required to account for the last bit of
// the image that is smaller than 32kib
// this would be the case whenever the image file size is not a
// multiple of 32kib (= the number of blocks is not divisible by 8)
// ie: if the image is 49152 bytes and you do 49152 >> 15 you get 1,
// but you actually need 2 bytes to have a complete cache map
#define IMGSIZE_TO_MAPBYTES(bytes) ((int)(((bytes) + (1 << 15) - 1) >> 15))

#endif
