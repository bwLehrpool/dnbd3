#ifndef HELPER_H_
#define HELPER_H_

#include "server.h"
#include "../shared/log.h"
#include "../types.h"
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

bool parse_address(char *string, dnbd3_host_t *host);
bool host_to_string(const dnbd3_host_t *host, char *target, size_t targetlen);
void remove_trailing_slash(char *string);
void trim_right(char * const string);
void setThreadName(const char *name);
void blockNoncriticalSignals();

static inline bool isSameAddress(const dnbd3_host_t * const a, const dnbd3_host_t * const b)
{
	return (a->type == b->type) && (0 == memcmp( a->addr, b->addr, (a->type == HOST_IP4 ? 4 : 16) ));
}

static inline bool isSameAddressPort(const dnbd3_host_t * const a, const dnbd3_host_t * const b)
{
	return (a->type == b->type) && (a->port == b->port) && (0 == memcmp( a->addr, b->addr, (a->type == HOST_IP4 ? 4 : 16) ));
}

/**
 * Test whether string ends in suffix.
 * @return true if string =~ /suffix$/
 */
static inline bool strend(char *string, char *suffix)
{
	if ( string == NULL ) return false;
	if ( suffix == NULL || *suffix == '\0' ) return true;
	const size_t len1 = strlen( string );
	const size_t len2 = strlen( suffix );
	if ( len2 > len1 ) return false;
	return strcmp( string + len1 - len2, suffix ) == 0;
}

#endif
