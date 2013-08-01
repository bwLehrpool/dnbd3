#include "globals.h"
#include "ini.h"
#include "memlog.h"
#include "../types.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

char *_configDir = NULL;
char *_basePath = NULL;
int _vmdkLegacyMode = FALSE;
int _shutdown = 0;

#define SAVE_TO_VAR_STR(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) { if (_ ## kk != NULL) free(_ ## kk); _ ## kk = strdup(value); } } while (0)
#define SAVE_TO_VAR_BOOL(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) _ ## kk = atoi(value) != 0 || strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "TRUE") == 0; } while (0)
#define SAVE_TO_VAR_INT(ss, kk) do { if (strcmp(section, #ss) == 0 && strcmp(key, #kk) == 0) _ ## kk = atoi(value); } while (0)

static int ini_handler(void *custom, const char* section, const char* key, const char* value)
{
	SAVE_TO_VAR_STR( dnbd3, basePath );
	SAVE_TO_VAR_BOOL( dnbd3, vmdkLegacyMode );
	return TRUE;
}

void globals_loadConfig()
{
	char *name = NULL;
	asprintf( &name, "%s/%s", _configDir, CONFIG_FILENAME );
	if ( name == NULL ) return;
	ini_parse( name, &ini_handler, NULL );
	free( name );
	if ( _basePath == NULL || _basePath[0] == '\0' ) {
		memlogf( "[ERROR] Need to specify basePath in " CONFIG_FILENAME );
		exit( EXIT_FAILURE );
	}
	if ( _basePath[0] != '/' ) {
		memlogf( "[ERROR] _basePath must be absolute!" );
		exit( EXIT_FAILURE );
	}
	char *end = _basePath + strlen( _basePath ) - 1;
	while ( end >= _basePath && *end == '/' )
		*end-- = '\0';
}
