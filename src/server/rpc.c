#include "rpc.h"
#include "helper.h"
#include "net.h"
#include "uplink.h"
#include "locks.h"
#include "image.h"
#include "../shared/sockhelper.h"
#include "fileutil.h"

#include <jansson.h>

#define ACL_ALL        0x7fffffff
#define ACL_STATS               1
#define ACL_CLIENT_LIST         2
#define ACL_IMAGE_LIST          4

#define HTTP_CLOSE 4
#define HTTP_KEEPALIVE 9

#define MAX_ACLS 100
static bool aclLoaded = false;
static int aclCount = 0;
static dnbd3_access_rule_t aclRules[MAX_ACLS];

static bool handleStatus(int sock, const char *request, int permissions);
static bool sendReply(int sock, const char *status, const char *ctype, const char *payload, ssize_t plen, int keepAlive);
static int getacl(dnbd3_host_t *host);
static void addacl(int argc, char **argv, void *data);
static void loadAcl();

void rpc_sendStatsJson(int sock, dnbd3_host_t* host, const void* data, const int dataLen)
{
	// TODO use some small HTTP parser (picohttpparser or similar)
	// TODO Parse Connection-header sent by client to see if keep-alive is supported
	bool ok;
	loadAcl();
	int permissions = getacl( host );
	if ( permissions == 0 ) {
		sendReply( sock, "403 Forbidden", "text/plain", "Access denied", -1, HTTP_CLOSE );
		return;
	}
	char header[1000];
	if ( dataLen > 0 ) {
		// We call this function internally with a maximum data len of sizeof(dnbd3_request_t) so no bounds checking
		memcpy( header, data, dataLen );
	}
	size_t hoff = dataLen;
	do {
		// Read request from client
		char *end = NULL;
		int state = 0;
		do {
			for (char *p = header; p < header + hoff; ++p) {
				if ( *p == '\r' && ( state == 0 || state == 2 ) ) {
					state++;
				} else if ( *p == '\n' ) {
					if ( state == 3 ) {
						end = p + 1;
						break;
					}
					if ( state == 1 ) {
						state = 2;
					} else {
						state = 0;
					}
				} else if ( state != 0 ) {
					state = 0;
				}
			}
			if ( end != NULL ) break;
			if ( hoff >= sizeof(header) ) return; // Request too large
			const size_t space = sizeof(header) - hoff;
			const ssize_t ret = recv( sock, header + hoff, space, 0 );
			if ( ret == 0 || ( ret == -1 && errno == EAGAIN ) ) return;
			if ( ret == -1 && ( errno == EWOULDBLOCK || errno == EINTR ) ) continue;
			hoff += ret;
		} while ( true );
		// Now end points to the byte after the \r\n\r\n of the header,
		if ( strncmp( header, "GET ", 4 ) != 0 && strncmp( header, "POST ", 5 ) != 0 ) return;
		char *br = strstr( header, "\r\n" );
		if ( br == NULL ) return; // Huh?
		*br = '\0';
		if ( strstr( header, " /query" ) != NULL ) {
			ok = handleStatus( sock, header, permissions );
		} else {
			ok = sendReply( sock, "404 Not found", "text/plain", "Nothing", -1, HTTP_KEEPALIVE );
		}
		if ( !ok ) break;
		// hoff might be beyond end if the client sent another request (burst)
		const ssize_t extra = ( header + hoff ) - end;
		if ( extra > 0 ) {
			memmove( header, end, extra );
			hoff = extra;
		} else {
			hoff = 0;
		}
	} while (true);
}

static bool handleStatus(int sock, const char *request, int permissions)
{
	bool ok;
	bool stats = false, images = false, clients = false;
	if ( strstr( request, "stats" ) != NULL ) {
		if ( !(permissions & ACL_STATS) ) {
			return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access statistics", -1, HTTP_KEEPALIVE );
		}
		stats = true;
	}
	if ( strstr( request, "images" ) != NULL ) {
		if ( !(permissions & ACL_IMAGE_LIST) ) {
			return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access image list", -1, HTTP_KEEPALIVE );
		}
		images = true;
	}
	if ( strstr(request, "clients" ) != NULL ) {
		if ( !(permissions & ACL_CLIENT_LIST) ) {
			return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access client list", -1, HTTP_KEEPALIVE );
		}
		clients = true;
	}
	// Call this first because it will update the total bytes sent counter
	json_t *jsonClients = NULL;
	if ( stats || clients ) {
		jsonClients = net_clientsToJson( clients );
	}
	const int uptime = dnbd3_serverUptime();
	json_t *statisticsJson;
	if ( stats ) {
		const uint64_t bytesReceived = uplink_getTotalBytesReceived();
		const uint64_t bytesSent = net_getTotalBytesSent();
		statisticsJson = json_pack( "{sIsIsI}",
				"bytesReceived", (json_int_t) bytesReceived,
				"bytesSent", (json_int_t) bytesSent,
				"uptime", (json_int_t) uptime );
	} else {
		statisticsJson = json_pack( "{sI}",
				"uptime", (json_int_t) uptime );
	}
	if ( jsonClients != NULL ) {
		if ( clients ) {
			json_object_set_new( statisticsJson, "clients", jsonClients );
		} else if ( stats ) {
			json_object_set_new( statisticsJson, "clientCount", jsonClients );
		}
	}
	if ( images ) {
		json_object_set_new( statisticsJson, "images", image_getListAsJson() );
	}

	char *jsonString = json_dumps( statisticsJson, 0 );
	json_decref( statisticsJson );
	ok = sendReply( sock, "200 OK", "application/json", jsonString, -1, HTTP_KEEPALIVE );
	free( jsonString );
	return ok;
}

static bool sendReply(int sock, const char *status, const char *ctype, const char *payload, ssize_t plen, int keepAlive)
{
	if ( plen == -1 ) plen = strlen( payload );
	char buffer[600];
	const char *connection = ( keepAlive == HTTP_KEEPALIVE ) ? "Keep-Alive" : "Close";
	int hlen = snprintf(buffer, sizeof(buffer), "HTTP/1.1 %s\r\n"
			"Connection: %s\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %u\r\n"
			"\r\n",
			status, connection, ctype, (unsigned int)plen );
	if ( hlen < 0 || hlen >= (int)sizeof(buffer) ) return false; // Truncated
	if ( send( sock, buffer, hlen, MSG_MORE ) != hlen ) return false;
	if ( !sock_sendAll( sock, payload, plen, 10 ) ) return false;
	if ( keepAlive == HTTP_CLOSE ) {
		// Wait for flush
		shutdown( sock, SHUT_WR );
		while ( read( sock, buffer, sizeof buffer ) > 0 );
	}
	return true;
}

static int getacl(dnbd3_host_t *host)
{
	if ( aclCount == 0 ) return 0x7fffff; // For now compat mode - no rules defined == all access
	for (int i = 0; i < aclCount; ++i) {
		if ( aclRules[i].bytes == 0 && aclRules[i].bitMask == 0 ) return aclRules[i].permissions;
		if ( memcmp( aclRules[i].host, host->addr, aclRules[i].bytes ) != 0 ) continue;
		if ( aclRules[i].bitMask != 0 && aclRules[i].host[aclRules[i].bytes] != ( host->addr[aclRules[i].bytes] & aclRules[i].bitMask ) ) continue;
		return aclRules[i].permissions;
	}
	return 0;
}

#define SETBIT(x) else if ( strcmp( argv[i], #x ) == 0 ) mask |= ACL_ ## x

static void addacl(int argc, char **argv, void *data UNUSED)
{
	if ( argv[0][0] == '#' ) return;
	if ( aclCount >= MAX_ACLS ) {
		logadd( LOG_WARNING, "Too many ACL rules, ignoring %s", argv[0] );
		return;
	}
	int mask = 0;
	for (int i = 1; i < argc; ++i) {
		if (false) {}
		SETBIT(ALL);
		SETBIT(STATS);
		SETBIT(CLIENT_LIST);
		SETBIT(IMAGE_LIST);
		else logadd( LOG_WARNING, "Invalid ACL flag '%s' for %s", argv[i], argv[0] );
	}
	if ( mask == 0 ) {
		logadd( LOG_INFO, "Ignoring empty rule for %s", argv[0] );
		return;
	}
	dnbd3_host_t host;
	char *slash = strchr( argv[0], '/' );
	if ( slash != NULL ) {
		*slash++ = '\0';
	}
	if ( !parse_address( argv[0], &host ) ) return;
	long int bits;
	if ( slash != NULL ) {
		char *last;
		bits = strtol( slash, &last, 10 );
		if ( last == slash ) slash = NULL;
		if ( host.type == AF_INET && bits > 32 ) bits = 32;
		if ( bits > 128 ) bits = 128;
	}
	if ( slash == NULL ) {
		if ( host.type == AF_INET ) {
			bits = 32;
		} else {
			bits = 128;
		}
	}
	memcpy( aclRules[aclCount].host, host.addr, 16 );
	aclRules[aclCount].bytes = bits / 8;
	aclRules[aclCount].bitMask = 0;
	aclRules[aclCount].permissions = mask;
	bits %= 8;
	if ( bits != 0 ) {
		for (long int i = 0; i < bits; ++i) {
			aclRules[aclCount].bitMask = ( aclRules[aclCount].bitMask >> 1 ) | 0x80;
		}
		aclRules[aclCount].host[aclRules[aclCount].bytes] &= aclRules[aclCount].bitMask;
	}
	// We now have .bytes set to the number of bytes to memcmp.
	// In case we have an odd bitmask, .bitMask will be != 0, so when comparing,
	// we need AND the host[.bytes] of the address to compare with the value
	// in .bitMask, and compate it, otherwise, a simple memcmp will do.
	aclCount++;
}

static void loadAcl()
{
	char *fn;
	// TODO <guard>
	if ( aclLoaded ) return;
	aclLoaded = true;
	// </guard>
	if ( asprintf( &fn, "%s/%s", _configDir, "rpc.acl" ) == -1 ) return;
	file_loadLineBased( fn, 1, 20, &addacl, NULL );
	free( fn );
	logadd( LOG_INFO, "%d HTTPRPC ACL rules loaded", (int)aclCount );
}

