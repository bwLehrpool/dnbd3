#ifndef HELPER_H_
#define HELPER_H_

#include "server.h"
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "../types.h"

#define ERROR_GOTO(jumplabel, errormsg) do { memlogf(errormsg); goto jumplabel; } while (0);
#define ERROR_GOTO_VA(jumplabel, errormsg, ...) do { memlogf(errormsg, __VA_ARGS__); goto jumplabel; } while (0);

char parse_address(char *string, dnbd3_host_t *host);
char host_to_string(const dnbd3_host_t *host, char *target, size_t targetlen);
void strtolower(char *string);
void remove_trailing_slash(char *string);
void trim_right(char * const string);
int file_exists(char *file);
int file_writable(char *file);
int mkdir_p(const char* path);

static inline int is_same_server(const dnbd3_host_t * const a, const dnbd3_host_t * const b)
{
	return (a->type == b->type) && (a->port == b->port) && (0 == memcmp( a->addr, b->addr, (a->type == AF_INET ? 4 : 16) ));
}

/**
 * Send message to client, return !=0 on success, 0 on failure
 */
static inline int send_data(int client_sock, void *data_in, int len)
{
	if ( len <= 0 ) // Nothing to send
	return 1;
	char *data = data_in; // Needed for pointer arithmetic
	int ret, i;
	for (i = 0; i < 3; ++i) // Retry at most 3 times, each try takes at most 0.5 seconds (socket timeout)
	        {
		ret = send( client_sock, data, len, 0 );
		if ( ret == 0 ) // Connection closed
		return 0;
		if ( ret < 0 ) {
			if ( errno != EAGAIN ) // Some unexpected error
			return 0;
			usleep( 1000 ); // 1ms
			continue;
		}
		len -= ret;
		if ( len <= 0 ) // Sent everything
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
	if ( len <= 0 ) // Nothing to receive
	return 1;
	char *data = buffer_out; // Needed for pointer arithmetic
	int ret, i;
	for (i = 0; i < 3; ++i) // Retry at most 3 times, each try takes at most 0.5 seconds (socket timeout)
	        {
		ret = recv( client_sock, data, len, MSG_WAITALL );
		if ( ret == 0 ) // Connection closed
		return 0;
		if ( ret < 0 ) {
			if ( errno != EAGAIN ) // Some unexpected error
			return 0;
			usleep( 1000 ); // 1ms
			continue;
		}
		len -= ret;
		if ( len <= 0 ) // Received everything
		return 1;
		data += ret; // move target buffer pointer
	}
	return 0;
}

static inline int strend(char *string, char *suffix)
{
	if ( string == NULL ) return FALSE;
	if ( suffix == NULL || *suffix == '\0' ) return TRUE;
	const size_t len1 = strlen( string );
	const size_t len2 = strlen( suffix );
	if ( len2 > len1 ) return FALSE;
	return strcmp( string + len1 - len2, suffix ) == 0;
}

#endif
