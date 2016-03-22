#include "helper.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>

#ifdef HAVE_THREAD_NAMES
#include <sys/prctl.h> // For thread names
#endif

/**
 * Parse IPv4 or IPv6 address in string representation to a suitable format usable by the BSD socket library
 * !! Contents of 'string' might be modified by this function !!
 *
 * @param string eg. "1.2.3.4" or "2a01::10:5", optially with port appended, eg "1.2.3.4:6666" or "[2a01::10:5]:6666"
 * @param host pointer to dnbd3_host_t that will be filled with the following data:
 *    .type will contain either AF_INET or AF_INET6
 *    .addr will contain the address in network representation
 *    .port will contain the port in network representation, defaulting to #define PORT if none was given
 * @return true on success, false in failure. contents of af, addr and port are undefined in the latter case
 */
bool parse_address(char *string, dnbd3_host_t *host)
{
	struct in_addr v4;
	struct in6_addr v6;

	memset( host, 0, sizeof(*host) );
	// Try IPv4 without port
	if ( 1 == inet_pton( AF_INET, string, &v4 ) ) {
		host->type = AF_INET;
		memcpy( host->addr, &v4, 4 );
		host->port = htons( PORT );
		return true;
	}
	// Try IPv6 without port
	if ( 1 == inet_pton( AF_INET6, string, &v6 ) ) {
		host->type = AF_INET6;
		memcpy( host->addr, &v6, 16 );
		host->port = htons( PORT );
		return true;
	}

	// Scan for port
	char *portpos = NULL, *ptr = string;
	while ( *ptr ) {
		if ( *ptr == ':' ) portpos = ptr;
		++ptr;
	}
	if ( portpos == NULL ) return false; // No port in string
	// Consider IP being surrounded by [ ]
	if ( *string == '[' && *(portpos - 1) == ']' ) {
		++string;
		*(portpos - 1) = '\0';
	}
	*portpos++ = '\0';
	int p = atoi( portpos );
	if ( p < 1 || p > 65535 ) return false; // Invalid port
	host->port = htons( (uint16_t)p );

	// Try IPv4 with port
	if ( 1 == inet_pton( AF_INET, string, &v4 ) ) {
		host->type = AF_INET;
		memcpy( host->addr, &v4, 4 );
		return true;
	}
	// Try IPv6 with port
	if ( 1 == inet_pton( AF_INET6, string, &v6 ) ) {
		host->type = AF_INET6;
		memcpy( host->addr, &v6, 16 );
		return true;
	}

	// FAIL
	return false;
}

/**
 * Convert a host and port (network byte order) to printable representation.
 * Worst case required buffer len is 48, eg. [1234:1234:1234:1234:1234:1234:1234:1234]:12345 (+ \0)
 * Returns true on success, false on error
 */
bool host_to_string(const dnbd3_host_t *host, char *target, size_t targetlen)
{
	// Worst case: Port 5 chars, ':' to separate ip and port 1 char, terminating null 1 char = 7, [] for IPv6
	if ( targetlen < 10 ) return false;
	if ( host->type == AF_INET6 ) {
		*target++ = '[';
		inet_ntop( AF_INET6, host->addr, target, targetlen - 10 );
		target += strlen( target );
		*target++ = ']';
	} else if ( host->type == AF_INET ) {
		inet_ntop( AF_INET, host->addr, target, targetlen - 8 );
		target += strlen( target );
	} else {
		snprintf( target, targetlen, "<?addrtype=%d>", (int)host->type );
		return false;
	}
	*target = '\0';
	if ( host->port != 0 ) {
		// There are still at least 7 bytes left in the buffer, port is at most 5 bytes + ':' + '\0' = 7
		snprintf( target, 7, ":%d", (int)ntohs( host->port ) );
	}
	return true;
}

void remove_trailing_slash(char *string)
{
	char *ptr = string + strlen( string ) - 1;
	while ( ptr >= string && *ptr == '/' )
		*ptr-- = '\0';
}

void trim_right(char * const string)
{
	char *end = string + strlen( string ) - 1;
	while ( end >= string && (*end == '\r' || *end == '\n' || *end == ' ' || *end == '\t') )
		*end-- = '\0';
}

void setThreadName(const char *name)
{
	char newName[16];
	if ( strlen( name ) > 15 ) {
		snprintf( newName, sizeof(newName), "%s", name );
		newName[15] = '\0';
		name = newName;
	}
#ifdef HAVE_THREAD_NAMES
	prctl( PR_SET_NAME, (unsigned long)name, 0, 0, 0 );
#endif
	//TODO: On FreeBSD set threadname with pthread_setname_np
}

void blockNoncriticalSignals()
{
	sigset_t sigmask;
	sigemptyset( &sigmask );
	sigaddset( &sigmask, SIGUSR1 );
	sigaddset( &sigmask, SIGUSR2 );
	sigaddset( &sigmask, SIGHUP );
	sigaddset( &sigmask, SIGPIPE );
	pthread_sigmask( SIG_BLOCK, &sigmask, NULL );
}

