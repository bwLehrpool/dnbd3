#ifndef HELPER_H_
#define HELPER_H_

#include "server.h"
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

char parse_address(char *string, dnbd3_host_t *host);
char host_to_string(const dnbd3_host_t *host, char *target, size_t targetlen);
char is_valid_namespace(char *namespace);
char is_valid_imagename(char *namespace);
void strtolower(char *string);
void remove_trailing_slash(char *string);
int file_exists(char *file);
int file_writable(char *file);

static inline int is_same_server(const dnbd3_host_t *const a, const dnbd3_host_t *const b)
{
	return (a->type == b->type)
	       && (a->port == b->port)
	       && (0 == memcmp(a->addr, b->addr, (a->type == AF_INET ? 4 : 16)));
}

/**
 * Send message to client, return !=0 on success, 0 on failure
 */
static inline int send_data(int client_sock, void *data_in, int len)
{
	if (len <= 0) // Nothing to send
		return 1;
	char *data = data_in; // Needed for pointer arithmetic
	int ret, i;
	for (i = 0; i < 3; ++i) // Retry at most 3 times, each try takes at most 0.5 seconds (socket timeout)
	{
		ret = send(client_sock, data, len, 0);
		if (ret == 0) // Connection closed
			return 0;
		if (ret < 0)
		{
			if (errno != EAGAIN) // Some unexpected error
				return 0;
			usleep(1000); // 1ms
			continue;
		}
		len -= ret;
		if (len <= 0) // Sent everything
			return 1;
		data += ret; // move target buffer pointer
	}
	return 0;
}

/**
 * Receive data from client, return !=0 on success, 0 on failure
 */
static inline int recv_data(int client_sock, void *buffer_out, int len)
{
	if (len <= 0) // Nothing to receive
		return 1;
	char *data = buffer_out; // Needed for pointer arithmetic
	int ret, i;
	for (i = 0; i < 3; ++i) // Retry at most 3 times, each try takes at most 0.5 seconds (socket timeout)
	{
		ret = recv(client_sock, data, len, MSG_WAITALL);
		if (ret == 0) // Connection closed
			return 0;
		if (ret < 0)
		{
			if (errno != EAGAIN) // Some unexpected error
				return 0;
			usleep(1000); // 1ms
			continue;
		}
		len -= ret;
		if (len <= 0) // Received everything
			return 1;
		data += ret; // move target buffer pointer
	}
	return 0;
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
