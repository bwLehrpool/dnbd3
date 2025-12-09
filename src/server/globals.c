#include "globals.h"
#include "ini.h"
#include "locks.h"
#include <dnbd3/shared/log.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/resource.h>
#include <errno.h>

char *_configDir = NULL;
atomic_bool _shutdown = false;
// [dnbd3]
atomic_int _listenPort = PORT;
char *_basePath = NULL;
atomic_int _serverPenalty = 0;
atomic_int _clientPenalty = 0;
atomic_bool _isProxy = false;
atomic_int _backgroundReplication = BGR_FULL;
atomic_int _bgrMinClients = 0;
atomic_int _bgrWindowSize = 1;
atomic_bool _lookupMissingForProxy = true;
atomic_bool _sparseFiles = false;
atomic_bool _ignoreAllocErrors = false;
atomic_bool _removeMissingImages = true;
atomic_uint _uplinkTimeout = SOCKET_TIMEOUT_UPLINK;
atomic_uint _clientTimeout = SOCKET_TIMEOUT_CLIENT;
atomic_bool _closeUnusedFd = false;
atomic_bool _vmdkLegacyMode = false;
// Not really needed anymore since we have '+' and '-' in alt-servers
atomic_bool _proxyPrivateOnly = false;
atomic_bool _pretendClient = false;
atomic_int _autoFreeDiskSpaceDelay = 3600 * 10;
atomic_bool _iScsiServer = true;
// [limits]
atomic_int _maxClients = SERVER_MAX_CLIENTS;
atomic_int _maxImages = SERVER_MAX_IMAGES;
atomic_uint _maxPayload = 9000000; // 9MB
atomic_uint_fast64_t _maxReplicationSize = (uint64_t)100000000000LL;
atomic_uint _maxPrefetch = 262144; // 256KB
atomic_uint _minRequestSize = 0;

/**
 * True when loading config the first time. Consecutive loads will
 * ignore certain values which cannot be changed safely at runtime.
 */
static atomic_bool initialLoad = true;
static pthread_mutex_t loadLock;

#define IS_TRUE(value) (atoi(value) != 0 || strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "TRUE") == 0)
#define SAVE_TO_VAR_STR(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) { if (_ ## kk != NULL) free(_ ## kk); _ ## kk = strdup(value); } } while (0)
#define SAVE_TO_VAR_BOOL(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) _ ## kk = IS_TRUE(value); } while (0)
#define SAVE_TO_VAR_INT(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) parse32(value, &_ ## kk, #ss); } while (0)
#define SAVE_TO_VAR_UINT(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) parse32u(value, &_ ## kk, #ss); } while (0)
#define SAVE_TO_VAR_UINT64(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) parse64u(value, &_ ## kk, #ss); } while (0)

static void sanitizeFixedConfig();

static void handleMaskString( const char *value, void(*func)(logmask_t) );

static const char* units = "KMGTPEZY";

static bool parse64(const char *in, atomic_int_fast64_t *out, const char *optname);
static bool parse64u(const char *in, atomic_uint_fast64_t *out, const char *optname);
static bool parse32(const char *in, atomic_int *out, const char *optname);
static bool parse32u(const char *in, atomic_uint *out, const char *optname);

static int ini_handler(void *custom UNUSED, const char* section, const char* key, const char* value)
{
	if ( initialLoad ) {
		if ( _basePath == NULL ) SAVE_TO_VAR_STR( dnbd3, basePath );
		SAVE_TO_VAR_BOOL( dnbd3, vmdkLegacyMode );
		SAVE_TO_VAR_INT( dnbd3, listenPort );
		SAVE_TO_VAR_INT( limits, maxClients );
		SAVE_TO_VAR_INT( limits, maxImages );
	}
	SAVE_TO_VAR_BOOL( dnbd3, isProxy );
	SAVE_TO_VAR_BOOL( dnbd3, proxyPrivateOnly );
	SAVE_TO_VAR_INT( dnbd3, bgrMinClients );
	SAVE_TO_VAR_INT( dnbd3, bgrWindowSize );
	SAVE_TO_VAR_BOOL( dnbd3, lookupMissingForProxy );
	SAVE_TO_VAR_BOOL( dnbd3, sparseFiles );
	SAVE_TO_VAR_BOOL( dnbd3, ignoreAllocErrors );
	SAVE_TO_VAR_BOOL( dnbd3, removeMissingImages );
	SAVE_TO_VAR_BOOL( dnbd3, closeUnusedFd );
	SAVE_TO_VAR_INT( dnbd3, serverPenalty );
	SAVE_TO_VAR_INT( dnbd3, clientPenalty );
	SAVE_TO_VAR_UINT( dnbd3, uplinkTimeout );
	SAVE_TO_VAR_UINT( dnbd3, clientTimeout );
	SAVE_TO_VAR_UINT( limits, maxPayload );
	SAVE_TO_VAR_UINT64( limits, maxReplicationSize );
	SAVE_TO_VAR_UINT( limits, maxPrefetch );
	SAVE_TO_VAR_UINT( limits, minRequestSize );
	SAVE_TO_VAR_BOOL( dnbd3, pretendClient );
	SAVE_TO_VAR_INT( dnbd3, autoFreeDiskSpaceDelay );
	SAVE_TO_VAR_BOOL( dnbd3, iScsiServer );
	if ( strcmp( section, "dnbd3" ) == 0 && strcmp( key, "backgroundReplication" ) == 0 ) {
		if ( strcmp( value, "hashblock" ) == 0 ) {
			_backgroundReplication = BGR_HASHBLOCK;
		} else if ( IS_TRUE( value ) ) {
			_backgroundReplication = BGR_FULL;
		} else {
			_backgroundReplication = BGR_DISABLED;
		}
	}
	if ( strcmp( section, "logging" ) == 0 && strcmp( key, "fileMask" ) == 0 ) handleMaskString( value, &log_setFileMask );
	if ( strcmp( section, "logging" ) == 0 && strcmp( key, "consoleMask" ) == 0 ) handleMaskString( value, &log_setConsoleMask );
	if ( strcmp( section, "logging" ) == 0 && strcmp( key, "consoleTimestamps" ) == 0 ) log_setConsoleTimestamps( IS_TRUE(value) );
	if ( strcmp( section, "logging" ) == 0 && strcmp( key, "file" ) == 0 ) {
		if ( log_openLogFile( value ) ) {
			logadd( LOG_INFO, "Opened log file %s", value );
		} else {
			logadd( LOG_ERROR, "Could not open log file %s", value );
			exit( EXIT_FAILURE );
		}
	}
	return 1;
}

void globals_loadConfig()
{
	char *name = NULL;
	if ( asprintf( &name, "%s/%s", _configDir, CONFIG_FILENAME ) == -1 ) {
		logadd( LOG_ERROR, "Memory allocation error for config filename" );
		exit( 1 );
	}
	if ( name == NULL ) return;
	if ( initialLoad ) {
		mutex_init( &loadLock, LOCK_LOAD_CONFIG );
	}
	if ( mutex_trylock( &loadLock ) != 0 ) {
		logadd( LOG_INFO, "Ignoring config reload request due to already running reload" );
		return;
	}
	ini_parse( name, &ini_handler, NULL );
	free( name );
	if ( initialLoad ) {
		sanitizeFixedConfig();
	}
	if ( _isProxy ) {
		if ( _backgroundReplication == BGR_FULL && _sparseFiles && _bgrMinClients < 5 ) {
			logadd( LOG_WARNING, "Ignoring 'sparseFiles=true' since backgroundReplication is set to true and bgrMinClients is too low" );
			_sparseFiles = false;
		}
		if ( _bgrWindowSize < 1 ) {
			_bgrWindowSize = 1;
		} else if ( _bgrWindowSize > UPLINK_MAX_QUEUE - 10 ) {
			_bgrWindowSize = UPLINK_MAX_QUEUE - 10;
			logadd( LOG_MINOR, "Limiting bgrWindowSize to %d, because of UPLINK_MAX_QUEUE",
					_bgrWindowSize );
		}
		if ( _maxPayload < 256 * 1024 ) {
			logadd( LOG_WARNING, "maxPayload was increased to 256k" );
			_maxPayload = 256 * 1024;
		}
		if ( _maxPrefetch > _maxPayload ) {
			logadd( LOG_WARNING, "Reducing maxPrefetch to maxPayload" );
			_maxPrefetch = _maxPayload;
		}
		if ( _minRequestSize > _maxPayload ) {
			logadd( LOG_WARNING, "Reducing minRequestSize to maxPayload" );
			_minRequestSize = _maxPayload;
		}
	}
	// Dump config as interpreted
	char buffer[2000];
	globals_dumpConfig( buffer, sizeof(buffer) );
	logadd( LOG_DEBUG1, "Effective configuration:\n%s", buffer );
	initialLoad = false;
	mutex_unlock( &loadLock );
}

static void sanitizeFixedConfig()
{
	// Validate settings after loading:
	// base path for images valid?
	if ( _basePath == NULL || _basePath[0] == '\0' ) {
		logadd( LOG_WARNING, "No/empty basePath in " CONFIG_FILENAME );
		free( _basePath );
		_basePath = NULL;
	} else if ( _basePath[0] != '/' ) {
		logadd( LOG_WARNING, "basePath must be absolute!" );
		free( _basePath );
		_basePath = NULL;
	} else {
		char *end = _basePath + strlen( _basePath ) - 1;
		while ( end >= _basePath && *end == '/' ) {
			*end-- = '\0';
		}
	}
	// listen port
	if ( _listenPort < 1 || _listenPort > 65535 ) {
		logadd( LOG_ERROR, "listenPort must be 1-65535, but is %d", _listenPort );
		exit( EXIT_FAILURE );
	}
	// Cap to hard limit
	if ( _maxClients > SERVER_MAX_CLIENTS ) _maxClients = SERVER_MAX_CLIENTS;
	if ( _maxImages > SERVER_MAX_IMAGES ) _maxImages = SERVER_MAX_IMAGES;
	// Consider rlimits
	struct rlimit limit;
	if ( getrlimit( RLIMIT_NOFILE, &limit ) != 0 ) {
		logadd( LOG_DEBUG1, "getrlimit failed, errno %d", errno );
	} else {
		const rlim_t required = (rlim_t)( _maxClients + _maxImages * ( _isProxy ? 2 : 1 ) + 50 );
		if ( limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < required ) {
			rlim_t current = limit.rlim_cur;
			if ( required <= limit.rlim_max || limit.rlim_max == RLIM_INFINITY ) {
				limit.rlim_cur = required;
			} else {
				limit.rlim_cur = limit.rlim_max;
			}
			if ( current != limit.rlim_cur && setrlimit( RLIMIT_NOFILE, &limit ) == 0 ) {
				current = limit.rlim_cur;
				logadd( LOG_INFO, "LIMIT_NOFILE (ulimit -n) soft limit increased to %d", (int)current );
			}
			if ( current < required ) {
				logadd( LOG_WARNING, "This process can only have %d open file handles,"
						" which is not enough for the selected maxClients and maxImages counts."
						" Consider increasing the limit to at least %d (RLIMIT_NOFILE, ulimit -n)"
						" to support the current configuration. maxClients and maxImages have"
						" been lowered for this session.", (int)current, (int)required );
				do {
					if ( _maxClients > 500 && _maxImages > 150 ) {
						_maxImages -= _maxImages / 20 + 1;
						_maxClients -= _maxClients / 20 + 1;
					} else if ( _maxImages > 100 ) {
						_maxImages -= _maxImages / 20 + 1;
						if ( _maxClients > 200 ) _maxClients -= _maxClients / 25 + 1;
					} else {
						break;
					}
				} while ( (rlim_t)( _maxClients + _maxImages * ( _isProxy ? 2 : 1 ) + 50 ) > current );
			}
		}
	}
}

#define SETLOGBIT(name) do { if ( strstr( value, #name ) != NULL ) mask |= LOG_ ## name; } while (0)
static void handleMaskString( const char *value, void(*func)(logmask_t) )
{
	logmask_t mask = 0;
	SETLOGBIT( ERROR );
	SETLOGBIT( WARNING );
	SETLOGBIT( MINOR );
	SETLOGBIT( INFO );
	SETLOGBIT( DEBUG1 );
	SETLOGBIT( DEBUG2 );
	(*func)( mask );
}

static bool parse64(const char *in, atomic_int_fast64_t *out, const char *optname)
{
	if ( *in == '\0' ) {
		logadd( LOG_WARNING, "Ignoring empty numeric setting '%s'", optname );
		return false;
	}
	char *end;
	long long int num = strtoll( in, &end, 10 );
	if ( end == in ) {
		logadd( LOG_WARNING, "Ignoring value '%s' for '%s': Not a number", in, optname );
		return false;
	}
	int exp, base = 1024;
	while ( *end == ' ' ) end++;
	if ( *end == '\0' ) {
		exp = 0;
	} else if ( *end == 'm' ) {
		exp = 1;
		base = 60;
	} else if ( *end == 'h' ) {
		exp = 1;
		base = 3600;
	} else if ( *end == 'd' ) {
		exp = 1;
		base = 24 * 3600;
	} else {
		char *pos = strchr( units, *end > 'Z' ? (*end - 32) : *end );
		if ( pos == NULL ) {
			logadd( LOG_ERROR, "Invalid unit '%s' for '%s'", end, optname );
			return false;
		}
		exp = (int)( pos - units ) + 1;
		end++;
		if ( *end == 'B' || *end == 'b' ) {
			base = 1000;
		}
	}
	while ( exp-- > 0 ) num *= base;
	*out = (int64_t)num;
	return true;
}

static bool parse64u(const char *in, atomic_uint_fast64_t *out, const char *optname)
{
	atomic_int_fast64_t v;
	if ( !parse64( in, &v, optname ) ) return false;
	if ( v < 0 ) {
		logadd( LOG_WARNING, "Ignoring value '%s' for '%s': Cannot be negative", in, optname );
		return false;
	}
	*out = (uint64_t)v;
	return true;
}

static bool parse32(const char *in, atomic_int *out, const char *optname)
{
	atomic_int_fast64_t v;
	if ( !parse64( in, &v, optname ) ) return false;
	if ( v < INT_MIN || v > INT_MAX ) {
		logadd( LOG_WARNING, "'%s' must be between %d and %d, but is '%s'", optname, (int)INT_MIN, (int)INT_MAX, in );
		return false;
	}
	*out = (int)v;
	return true;
}

static bool parse32u(const char *in, atomic_uint *out, const char *optname)
{
	atomic_int_fast64_t v;
	if ( !parse64( in, &v, optname ) ) return false;
	if ( v < 0 || v > INT_MAX ) {
		logadd( LOG_WARNING, "'%s' must be between %d and %d, but is '%s'", optname, (int)0, (int)INT_MAX, in );
		return false;
	}
	*out = (unsigned int)v;
	return true;
}

#define P_ARG(...) do { \
	int r = snprintf(buffer, rem, __VA_ARGS__); \
	if ( r < 0 || (size_t)r >= rem ) return size - 1; \
	rem -= r; \
	buffer += r; \
} while (0)
#define PVAR(var,type,cast) P_ARG(#var "=%" type "\n", (cast) _ ## var)
#define PINT(var) PVAR(var, "d", int)
#define PUINT64(var) PVAR(var, PRIu64, uint64_t)
#define PSTR(var) PVAR(var, "s", const char*)
#define PBOOL(var) P_ARG(#var "=%s\n", _ ## var ? "true" : "false")

size_t globals_dumpConfig(char *buffer, size_t size)
{
	size_t rem = size;
	P_ARG("[dnbd3]\n");
	PINT(listenPort);
	PSTR(basePath);
	PINT(serverPenalty);
	PINT(clientPenalty);
	PBOOL(isProxy);
	if ( _backgroundReplication == BGR_HASHBLOCK ) {
		P_ARG("backgroundReplication=hashblock\n");
	} else {
		PBOOL(backgroundReplication);
	}
	PINT(bgrMinClients);
	PINT(bgrWindowSize);
	PBOOL(lookupMissingForProxy);
	PBOOL(sparseFiles);
	PBOOL(ignoreAllocErrors);
	PBOOL(removeMissingImages);
	PINT(uplinkTimeout);
	PINT(clientTimeout);
	PBOOL(closeUnusedFd);
	PBOOL(vmdkLegacyMode);
	PBOOL(proxyPrivateOnly);
	PBOOL(pretendClient);
	PINT(autoFreeDiskSpaceDelay);
	PBOOL(iScsiServer);
	P_ARG("[limits]\n");
	PINT(maxClients);
	PINT(maxImages);
	PINT(maxPayload);
	PUINT64(maxReplicationSize);
	PINT(maxPrefetch);
	PINT(minRequestSize);
	return size - rem;
}

