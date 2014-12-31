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

bool parse_address(char *string, dnbd3_host_t *host);
bool host_to_string(const dnbd3_host_t *host, char *target, size_t targetlen);
void strtolower(char *string);
void remove_trailing_slash(char *string);
void trim_right(char * const string);
void setThreadName(char *name);
void blockNoncriticalSignals();

static inline bool isSameAddress(const dnbd3_host_t * const a, const dnbd3_host_t * const b)
{
	return (a->type == b->type) && (0 == memcmp( a->addr, b->addr, (a->type == AF_INET ? 4 : 16) ));
}

static inline bool isSameAddressPort(const dnbd3_host_t * const a, const dnbd3_host_t * const b)
{
	return (a->type == b->type) && (a->port == b->port) && (0 == memcmp( a->addr, b->addr, (a->type == AF_INET ? 4 : 16) ));
}

/**
 * Send message to client.
 * @return true on success, false on failure
 */
static inline int send_data(int client_sock, void *data_in, int len)
{
	if ( len <= 0 ) return true; // Nothing to send
	char *data = data_in; // Needed for pointer arithmetic
	int ret, i;
	for (i = 0; i < 3; ++i) // Retry at most 3 times, each try takes at most 0.5 seconds (socket timeout)
	{
		ret = send( client_sock, data, len, 0 );
		if ( ret == 0 ) return false; // Connection closed
		if ( ret < 0 ) {
			if ( errno != EAGAIN ) return false; // Some unexpected error
			usleep( 1000 ); // 1ms
			continue;
		}
		len -= ret;
		if ( len <= 0 ) return true; // Sent everything
		data += ret; // move target buffer pointer
	}
	return false;
}

/**
 * Receive data from client.
 * @return true on success, false otherwise
 */
static inline bool recv_data(int client_sock, void *buffer_out, int len)
{
	if ( len <= 0 ) return true; // Nothing to receive
	char *data = buffer_out; // Needed for pointer arithmetic
	int ret, i;
	for (i = 0; i < 3; ++i) // Retry at most 3 times, each try takes at most 0.5 seconds (socket timeout)
	        {
		ret = recv( client_sock, data, len, MSG_WAITALL );
		if ( ret == 0 ) return false; // Connection closed
		if ( ret < 0 ) {
			if ( errno != EAGAIN ) return false; // Some unexpected error
			usleep( 1000 ); // 1ms
			continue;
		}
		len -= ret;
		if ( len <= 0 ) return true; // Received everything
		data += ret; // move target buffer pointer
	}
	return false;
}

/**
 * Test whether string ends in suffix.
 * @return true if string =~ /suffix$/
 */
static inline int strend(char *string, char *suffix)
{
	if ( string == NULL ) return false;
	if ( suffix == NULL || *suffix == '\0' ) return true;
	const size_t len1 = strlen( string );
	const size_t len2 = strlen( suffix );
	if ( len2 > len1 ) return false;
	return strcmp( string + len1 - len2, suffix ) == 0;
}

#endif
