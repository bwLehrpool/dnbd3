#include "globals.h"
#include "ini.h"
#include "../shared/log.h"
#include <string.h>
#include <stdlib.h>

char *_configDir = NULL;
char *_basePath = NULL;
bool _vmdkLegacyMode = false;
volatile bool _shutdown = false;
int _serverPenalty = 0;
int _clientPenalty = 0;
bool _removeMissingImages = true;
bool _isProxy = false;
bool _proxyPrivateOnly = false;
bool _backgroundReplication = true;
int _listenPort = PORT;
int _uplinkTimeout = 1250;
int _clientTimeout = 15000;

#define SAVE_TO_VAR_STR(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) { if (_ ## kk != NULL) free(_ ## kk); _ ## kk = strdup(value); } } while (0)
#define SAVE_TO_VAR_BOOL(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) _ ## kk = atoi(value) != 0 || strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "TRUE") == 0; } while (0)
#define SAVE_TO_VAR_INT(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) _ ## kk = atoi(value); } while (0)

static void handleMaskString( const char *value, void(*func)(logmask_t) );

static int ini_handler(void *custom UNUSED, const char* section, const char* key, const char* value)
{
	if ( _basePath == NULL ) SAVE_TO_VAR_STR( dnbd3, basePath );
	SAVE_TO_VAR_BOOL( dnbd3, vmdkLegacyMode );
	SAVE_TO_VAR_BOOL( dnbd3, isProxy );
	SAVE_TO_VAR_BOOL( dnbd3, proxyPrivateOnly );
	SAVE_TO_VAR_BOOL( dnbd3, backgroundReplication );
	SAVE_TO_VAR_BOOL( dnbd3, removeMissingImages );
	SAVE_TO_VAR_INT( dnbd3, serverPenalty );
	SAVE_TO_VAR_INT( dnbd3, clientPenalty );
	SAVE_TO_VAR_INT( dnbd3, uplinkTimeout );
	SAVE_TO_VAR_INT( dnbd3, clientTimeout );
	SAVE_TO_VAR_INT( dnbd3, listenPort );
	if ( strcmp( section, "logging" ) == 0 && strcmp( key, "fileMask" ) == 0 ) handleMaskString( value, &log_setFileMask );
	if ( strcmp( section, "logging" ) == 0 && strcmp( key, "consoleMask" ) == 0 ) handleMaskString( value, &log_setConsoleMask );
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
	asprintf( &name, "%s/%s", _configDir, CONFIG_FILENAME );
	if ( name == NULL ) return;
	ini_parse( name, &ini_handler, NULL );
	free( name );
	// Validate settings after loading:
	// base path for images valid?
	if ( _basePath == NULL || _basePath[0] == '\0' ) {
		logadd( LOG_ERROR, "Need to specify basePath in " CONFIG_FILENAME );
		exit( EXIT_FAILURE );
	}
	if ( _basePath[0] != '/' ) {
		logadd( LOG_ERROR, "_basePath must be absolute!" );
		exit( EXIT_FAILURE );
	}
	char *end = _basePath + strlen( _basePath ) - 1;
	while ( end >= _basePath && *end == '/' )
		*end-- = '\0';
	// listen port
	if ( _listenPort < 1 || _listenPort > 65535 ) {
		logadd( LOG_ERROR, "listenPort must be 1-65535, but is %d", _listenPort );
		exit( EXIT_FAILURE );
	}
	// Silently "fix" invalid values
	if ( _serverPenalty < 0 ) _serverPenalty = 0;
	if ( _clientPenalty < 0 ) _clientPenalty = 0;
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

