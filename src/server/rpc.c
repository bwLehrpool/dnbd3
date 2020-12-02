#include "rpc.h"
#include "helper.h"
#include "net.h"
#include "uplink.h"
#include "locks.h"
#include "image.h"
#include "altservers.h"
#include <dnbd3/shared/sockhelper.h>
#include <dnbd3/version.h>
#include <dnbd3/build.h>
#include "fileutil.h"
#include "picohttpparser/picohttpparser.h"
#include "urldecode.h"
#include "reference.h"

#include <jansson.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#if JANSSON_VERSION_HEX < 0x020600
#define json_stringn_nocheck(a,b) json_string_nocheck(a)
#endif

#define ACL_ALL        0x7fffffff
#define ACL_STATS               1
#define ACL_CLIENT_LIST         2
#define ACL_IMAGE_LIST          4
#define ACL_CONFIG              8
#define ACL_LOG                16
#define ACL_ALTSERVERS         32

#define HTTP_CLOSE 4
#define HTTP_KEEPALIVE 9

// Make sure compiler does not reserve more space for static strings than required (or rather, does not tell so in sizeof calls)
// TODO Might be time for a dedicated string.h
_Static_assert( sizeof("test") == 5 && sizeof("test2") == 6, "Stringsize messup :/" );
#define STRCMP(str,chr) ( (str).s != NULL && (str).l == sizeof(chr)-1 && strncmp( (str).s, (chr), MIN((str).l, sizeof(chr)-1) ) == 0 )
#define STRSTART(str,chr) ( (str).s != NULL && (str).l >= sizeof(chr)-1 && strncmp( (str).s, (chr), MIN((str).l, sizeof(chr)-1) ) == 0 )
#define SETSTR(name,value) do { name.s = value; name.l = sizeof(value)-1; } while (0)
#define DEFSTR(name,value) static struct string name = { .s = value, .l = sizeof(value)-1 };
#define chartolower(c) ((char)( (c) >= 'A' && (c) <= 'Z' ? (c) + ('a'-'A') : (c) ))

DEFSTR(STR_CONNECTION, "connection")
DEFSTR(STR_CLOSE, "close")
DEFSTR(STR_QUERY, "/query")
DEFSTR(STR_CACHEMAP, "/cachemap")
DEFSTR(STR_Q, "q")
DEFSTR(STR_ID, "id")

static inline bool equals(struct string *s1,struct string *s2)
{
	if ( s1->s == NULL ) {
		return s2->s == NULL;
	} else if ( s2->s == NULL || s1->l != s2->l ) {
		return false;
	}
	return memcmp( s1->s, s2->s, s1->l ) == 0;
}

static inline bool iequals(struct string *cmpMixed, struct string *cmpLower)
{
	if ( cmpMixed->s == NULL ) {
		return cmpLower->s == NULL;
	} else if ( cmpLower->s == NULL || cmpMixed->l != cmpLower->l ) {
		return false;
	}
	for ( size_t i = 0; i < cmpMixed->l; ++i ) {
		if ( chartolower( cmpMixed->s[i] ) != cmpLower->s[i] ) return false;
	}
	return true;
}

#define MAX_ACLS 100
static int aclCount = 0;
static dnbd3_access_rule_t aclRules[MAX_ACLS];
static json_int_t randomRunId;
static pthread_mutex_t aclLock;
#define MAX_CLIENTS 50
#define CUTOFF_START 40
static struct {
	atomic_int count;
	atomic_bool overloaded;
} status;

static bool handleStatus(int sock, int permissions, struct field *fields, size_t fields_num, int keepAlive);
static bool handleCacheMap(int sock, int permissions, struct field *fields, size_t fields_num, int keepAlive);
static bool sendReply(int sock, const char *status, const char *ctype, const char *payload, ssize_t plen, int keepAlive);
static void parsePath(struct string *path, struct string *file, struct field *getv, size_t *getc);
static bool hasHeaderValue(struct phr_header *headers, size_t numHeaders, struct string *name, struct string *value);
static int getacl(dnbd3_host_t *host);
static void addacl(int argc, char **argv, void *data);
static void loadAcl();

void rpc_init()
{
	mutex_init( &aclLock, LOCK_RPC_ACL );
	randomRunId = (((json_int_t)getpid()) << 16) | (json_int_t)time(NULL);
	// </guard>
	if ( sizeof(randomRunId) > 4 ) {
		int fd = open( "/dev/urandom", O_RDONLY );
		if ( fd != -1 ) {
			uint32_t bla = 1;
			(void)!read( fd, &bla, 4 );
			randomRunId = (randomRunId << 32) | bla;
		}
		close( fd );
	}
	loadAcl();
}

#define UPDATE_LOADSTATE(cnt) do { \
	if ( cnt < (CUTOFF_START/2) ) {                        \
		if ( status.overloaded ) status.overloaded = false; \
	} else if ( cnt > CUTOFF_START ) {                     \
		if ( !status.overloaded ) status.overloaded = true; \
	}                                                      \
} while (0)

void rpc_sendStatsJson(int sock, dnbd3_host_t* host, const void* data, const int dataLen)
{
	int permissions = getacl( host );
	if ( permissions == 0 ) {
		sendReply( sock, "403 Forbidden", "text/plain", "Access denied", -1, HTTP_CLOSE );
		return;
	}
	do {
		const int curCount = ++status.count;
		UPDATE_LOADSTATE( curCount );
		if ( curCount > MAX_CLIENTS ) {
			sendReply( sock, "503 Service Temporarily Unavailable", "text/plain", "Too many HTTP clients", -1, HTTP_CLOSE );
			goto func_return;
		}
	} while (0);
	char headerBuf[3000];
	if ( dataLen > 0 ) {
		// We call this function internally with a maximum data len of sizeof(dnbd3_request_t) so no bounds checking
		memcpy( headerBuf, data, dataLen );
	}
	size_t hoff = dataLen;
	bool hasName = false;
	bool ok;
	int keepAlive = HTTP_KEEPALIVE;
	while ( !_shutdown ) {
		// Read request from client
		struct phr_header headers[100];
		size_t numHeaders, prevLen = 0, consumed = 0;
		struct string method, path;
		int minorVersion;
		while ( !_shutdown ) {
			// Parse before calling recv, there might be a complete pipelined request in the buffer already
			// If the request is incomplete, we allow exactly one additional recv() to complete it.
			// This should suffice for real world scenarios as I don't know of any
			// HTTP client that sends the request headers in multiple packets. Even
			// with pipelining this should not break as we re-enter this loop after
			// processing the requests one by one, so a potential partial request in the
			// buffer will get another recv() (blocking mode)
			// The alternative would be manual tracking of idle/request time to protect
			// against never ending requests (slowloris)
			int pret;
			if ( hoff >= sizeof(headerBuf) ) goto func_return; // Request too large
			if ( hoff != 0 ) {
				numHeaders = 100;
				pret = phr_parse_request( headerBuf, hoff, &method, &path, &minorVersion, headers, &numHeaders, prevLen );
			} else {
				// Nothing in buffer yet, just set to -2 which is the phr goto func_return code for "partial request"
				pret = -2;
			}
			if ( pret > 0 ) {
				// > 0 means parsing completed without error
				consumed = (size_t)pret;
				break;
			}
			// Reaching here means partial request or parse error
			if ( pret == -2 ) { // Partial, keep reading
				prevLen = hoff;
#ifdef DNBD3_SERVER_AFL
				ssize_t ret = recv( 0, headerBuf + hoff, sizeof(headerBuf) - hoff, 0 );
#else
				ssize_t ret = recv( sock, headerBuf + hoff, sizeof(headerBuf) - hoff, 0 );
#endif
				if ( ret == 0 ) goto func_return;
				if ( ret == -1 ) {
					if ( errno == EINTR ) continue;
					if ( errno != EAGAIN && errno != EWOULDBLOCK ) {
						sendReply( sock, "500 Internal Server Error", "text/plain", "Server made a boo-boo", -1, HTTP_CLOSE );
					}
					goto func_return; // Timeout or unknown error
				}
				hoff += ret;
			} else { // Parse error
				sendReply( sock, "400 Bad Request", "text/plain", "Server cannot understand what you're trying to say", -1, HTTP_CLOSE );
				goto func_return;
			}
		} // Loop while request header incomplete
		if ( _shutdown )
			break;
		if ( keepAlive == HTTP_KEEPALIVE ) {
			// Only keep the connection alive (and indicate so) if the client seems to support this
			if ( minorVersion == 0 || hasHeaderValue( headers, numHeaders, &STR_CONNECTION, &STR_CLOSE ) ) {
				keepAlive = HTTP_CLOSE;
			} else { // And if there aren't too many active HTTP sessions
				if ( status.overloaded ) keepAlive = HTTP_CLOSE;
			}
		}
		if ( method.s != NULL && path.s != NULL ) {
			// Basic data filled from request parser
			// Handle stuff
			struct string file;
			struct field getv[10];
			size_t getc = 10;
			parsePath( &path, &file, getv, &getc );
			if ( method.s && method.s[0] == 'P' ) {
				// POST only methods
			}
			// Don't care if GET or POST
			if ( equals( &file, &STR_QUERY ) ) {
				ok = handleStatus( sock, permissions, getv, getc, keepAlive );
			} else if ( equals( &file, &STR_CACHEMAP ) ) {
				ok = handleCacheMap( sock, permissions, getv, getc, keepAlive );
			} else {
				ok = sendReply( sock, "404 Not found", "text/plain", "Nothing", -1, keepAlive );
			}
			if ( !ok )
				break;
		}
		// hoff might be beyond end if the client sent another request (burst)
		const ssize_t extra = hoff - consumed;
		if ( extra > 0 ) {
			memmove( headerBuf, headerBuf + consumed, extra );
		}
		hoff = extra;
		if ( !hasName ) {
			hasName = true;
			setThreadName( "HTTP" );
		}
	} // Loop while more requests
func_return:;
	do {
		const int curCount = --status.count;
		UPDATE_LOADSTATE( curCount );
	} while (0);
}

void rpc_sendErrorMessage(int sock, const char* message)
{
	static const char *encoded = NULL;
	static size_t len;
	if ( encoded == NULL ) {
		json_t *tmp = json_pack( "{ss}", "errorMsg", message );
		encoded = json_dumps( tmp, 0 );
		json_decref( tmp );
		len = strlen( encoded );
	}
	sendReply( sock, "200 Somewhat OK", "application/json", encoded, len, HTTP_CLOSE );
}

static bool handleStatus(int sock, int permissions, struct field *fields, size_t fields_num, int keepAlive)
{
	bool ok;
	bool stats = false, images = false, clients = false, space = false;
	bool logfile = false, config = false, altservers = false, version = false;
#define SETVAR(var) if ( !var && STRCMP(fields[i].value, #var) ) var = true
	for (size_t i = 0; i < fields_num; ++i) {
		if ( !equals( &fields[i].name, &STR_Q ) ) continue;
		SETVAR(stats);
		else SETVAR(space);
		else SETVAR(images);
		else SETVAR(clients);
		else SETVAR(logfile);
		else SETVAR(config);
		else SETVAR(altservers);
		else SETVAR(version);
	}
#undef SETVAR
	if ( ( stats || space || version ) && !(permissions & ACL_STATS) ) {
		return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access statistics", -1, keepAlive );
	}
	if ( images && !(permissions & ACL_IMAGE_LIST) ) {
		return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access image list", -1, keepAlive );
	}
	if ( clients && !(permissions & ACL_CLIENT_LIST) ) {
		return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access client list", -1, keepAlive );
	}
	if ( logfile && !(permissions & ACL_LOG) ) {
		return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access log", -1, keepAlive );
	}
	if ( config && !(permissions & ACL_CONFIG) ) {
		return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access config", -1, keepAlive );
	}
	if ( altservers && !(permissions & ACL_ALTSERVERS) ) {
		return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access altservers", -1, keepAlive );
	}

	json_t *statisticsJson;
	if ( stats ) {
		int clientCount, serverCount;
		uint64_t bytesSent;
		const uint64_t bytesReceived = uplink_getTotalBytesReceived();
		net_getStats( &clientCount, &serverCount, &bytesSent );
		statisticsJson = json_pack( "{sIsIsisisIsI}",
				"bytesReceived", (json_int_t) bytesReceived,
				"bytesSent", (json_int_t) bytesSent,
				"clientCount", clientCount,
				"serverCount", serverCount,
				"uptime", (json_int_t) dnbd3_serverUptime(),
				"runId", randomRunId );
	} else {
		statisticsJson = json_pack( "{sI}",
				"runId", randomRunId );
	}
	if ( version ) {
		json_object_set_new( statisticsJson, "version", json_string( DNBD3_VERSION_LONG ", built " DNBD3_BUILD_DATE ) );
		json_object_set_new( statisticsJson, "build", json_string( DNBD3_BUILD ) );
	}
	if ( space ) {
		uint64_t spaceTotal = 0, spaceAvail = 0;
		file_freeDiskSpace( _basePath, &spaceTotal, &spaceAvail );
		json_object_set_new( statisticsJson, "spaceTotal", json_integer( spaceTotal ) );
		json_object_set_new( statisticsJson, "spaceFree", json_integer( spaceAvail ) );
	}
	if ( clients ) {
		json_object_set_new( statisticsJson, "clients", net_getListAsJson() );
	}
	if ( images ) {
		json_object_set_new( statisticsJson, "images", image_getListAsJson() );
	}
	if ( logfile ) {
		char logbuf[4000];
		ssize_t len = log_fetch( logbuf, sizeof(logbuf) );
		json_t *val;
		if ( len <= 0 ) {
			val = json_null();
		} else {
			val = json_stringn_nocheck( logbuf, (size_t)len );

		}
		json_object_set_new( statisticsJson, "logfile", val );
	}
	if ( config ) {
		char buf[2000];
		size_t len = globals_dumpConfig( buf, sizeof(buf) );
		json_object_set_new( statisticsJson, "config", json_stringn_nocheck( buf, len ) );
	}
	if ( altservers ) {
		json_object_set_new( statisticsJson, "altservers", altservers_toJson() );
	}

	char *jsonString = json_dumps( statisticsJson, 0 );
	json_decref( statisticsJson );
	ok = sendReply( sock, "200 OK", "application/json", jsonString, -1, keepAlive );
	free( jsonString );
	return ok;
}

static bool handleCacheMap(int sock, int permissions, struct field *fields, size_t fields_num, int keepAlive)
{
	if ( !(permissions & ACL_IMAGE_LIST) ) {
		return sendReply( sock, "403 Forbidden", "text/plain", "No permission to access image list", -1, keepAlive );
	}
	int imgId = -1;
	static const char one = (char)0xff;
	for (size_t i = 0; i < fields_num; ++i) {
		if ( equals( &fields[i].name, &STR_ID ) ) {
			char *broken;
			imgId = (int)strtol( fields[i].value.s, &broken, 10 );
			if ( broken != fields[i].value.s )
				break;
			imgId = -1;
		}
	}
	if ( imgId == -1 )
		return sendReply( sock, "400 Bad Request", "text/plain", "Missing parameter 'id'", -1, keepAlive );
	dnbd3_image_t *image = image_byId( imgId );
	if ( image == NULL )
		return sendReply( sock, "404 Not found", "text/plain", "Image not found", -1, keepAlive );
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	image_release( image );
	int len;
	const char *map;
	if ( cache == NULL ) {
		map = &one;
		len = 1;
	} else {
		_Static_assert( sizeof(const char) == sizeof(_Atomic uint8_t), "Atomic assumption exploded" );
		map = (const char*)cache->map;
		len = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
	}
	bool ok = sendReply( sock, "200 OK", "application/octet-stream", map, len, keepAlive );
	if ( cache != NULL ) {
		ref_put( &cache->reference );
	}
	return ok;
}

static bool sendReply(int sock, const char *status, const char *ctype, const char *payload, ssize_t plen, int keepAlive)
{
	if ( plen == -1 ) plen = strlen( payload );
	char buffer[600];
	const char *connection = ( keepAlive == HTTP_KEEPALIVE ) ? "Keep-Alive" : "Close";
	int hlen = snprintf(buffer, sizeof(buffer), "HTTP/1.1 %s\r\n"
			"Connection: %s\r\n"
			"Content-Type: %s; charset=utf-8\r\n"
			"Content-Length: %u\r\n"
			"\r\n",
			status, connection, ctype, (unsigned int)plen );
	if ( hlen < 0 || hlen >= (int)sizeof(buffer) ) return false; // Truncated
	if ( send( sock, buffer, hlen, MSG_MORE ) != hlen ) return false;
	if ( !sock_sendAll( sock, payload, plen, 10 ) ) return false;
	if ( keepAlive == HTTP_CLOSE ) {
		// Wait for flush
		shutdown( sock, SHUT_WR );
#ifdef DNBD3_SERVER_AFL
		sock = 0;
#endif
		// Don't wait too long in case other side ignores the shutdown
		sock_setTimeout( sock, 600 );
		while ( read( sock, buffer, sizeof buffer ) > 0 );
		return false;
	}
	return true;
}

static void parsePath(struct string *path, struct string *file, struct field *getv, size_t *getc)
{
	size_t i = 0;
	while ( i < path->l && path->s[i] != '?' ) ++i;
	if ( i == path->l ) {
		*getc = 0;
		*file = *path;
		return;
	}
	file->s = path->s;
	file->l = i;
	++i;
	path->s += i;
	path->l -= i;
	urldecode( path, getv, getc );
	path->s -= i;
	path->l += i;
}

static bool hasHeaderValue(struct phr_header *headers, size_t numHeaders, struct string *name, struct string *value)
{
	for (size_t i = 0; i < numHeaders; ++i) {
		if ( !iequals( &headers[i].name, name ) ) continue;
		if ( iequals( &headers[i].value, value ) ) return true;
	}
	return false;
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
#ifdef DNBD3_SERVER_AFL
	return 0x7fffff;
#else
	return 0;
#endif
}

#define SETBIT(x) else if ( strcmp( argv[i], #x ) == 0 ) mask |= ACL_ ## x

static void addacl(int argc, char **argv, void *data UNUSED)
{
	if ( argv[0][0] == '#' ) return;
	mutex_lock( &aclLock );
	if ( aclCount >= MAX_ACLS ) {
		logadd( LOG_WARNING, "Too many ACL rules, ignoring %s", argv[0] );
		goto unlock_end;
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
		goto unlock_end;
	}
	dnbd3_host_t host;
	char *slash = strchr( argv[0], '/' );
	if ( slash != NULL ) {
		*slash++ = '\0';
	}
	if ( !parse_address( argv[0], &host ) ) goto unlock_end;
	long int bits = 0;
	if ( slash != NULL ) {
		char *last;
		bits = strtol( slash, &last, 10 );
		if ( last == slash ) slash = NULL;
		if ( host.type == HOST_IP4 && bits > 32 ) bits = 32;
		if ( bits > 128 ) bits = 128;
	}
	if ( slash == NULL ) {
		if ( host.type == HOST_IP4 ) {
			bits = 32;
		} else {
			bits = 128;
		}
	}
	memcpy( aclRules[aclCount].host, host.addr, 16 );
	aclRules[aclCount].bytes = (int)( bits / 8 );
	aclRules[aclCount].bitMask = 0;
	aclRules[aclCount].permissions = mask;
	bits %= 8;
	if ( bits != 0 ) {
		for (long int i = 0; i < bits; ++i) {
			aclRules[aclCount].bitMask = ( aclRules[aclCount].bitMask >> 1 ) | 0x80;
		}
		aclRules[aclCount].host[aclRules[aclCount].bytes] &= (uint8_t)aclRules[aclCount].bitMask;
	}
	// We now have .bytes set to the number of bytes to memcmp.
	// In case we have an odd bitmask, .bitMask will be != 0, so when comparing,
	// we need AND the host[.bytes] of the address to compare with the value
	// in .bitMask, and compate it, otherwise, a simple memcmp will do.
	aclCount++;
unlock_end:;
	mutex_unlock( &aclLock );
}

static void loadAcl()
{
	static bool inProgress = false;
	char *fn;
	if ( asprintf( &fn, "%s/%s", _configDir, "rpc.acl" ) == -1 ) return;
	mutex_lock( &aclLock );
	if ( inProgress ) {
		mutex_unlock( &aclLock );
		return;
	}
	aclCount = 0;
	inProgress = true;
	mutex_unlock( &aclLock );
	file_loadLineBased( fn, 1, 20, &addacl, NULL );
	mutex_lock( &aclLock );
	inProgress = false;
	mutex_unlock( &aclLock );
	free( fn );
	logadd( LOG_INFO, "%d HTTPRPC ACL rules loaded", (int)aclCount );
}

