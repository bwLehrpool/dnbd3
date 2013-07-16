#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include "../types.h"
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <glib/gslist.h>

// ######### All structs/types used by the server ########

typedef struct
{
	int fd;
} dnbd3_connection_t;

typedef struct
{
	uint16_t len;
	uint8_t data[65535];
} dnbd3_binstring_t;
// Do not always allocate as much memory as required to hold the entire binstring struct,
// but only as much as is required to hold the actual data
#define NEW_BINSTRING(_name, _len) \
	dnbd3_binstring_t *_name = malloc(sizeof(uint16_t) + _len); \
	_name->len = _len

typedef struct
{
	char comment[COMMENT_LENGTH];
	time_t last_told;
	dnbd3_host_t host;
} dnbd3_alt_server_t;

typedef struct
{
	char comment[COMMENT_LENGTH];
	dnbd3_host_t host;
	dnbd3_host_t mask;
} dnbd3_acess_rules_t;

/**
 * Image struct. An image path could be something like
 * /mnt/images/rz/zfs/Windows7 ZfS.vmdk.1
 * and the lower_name would then be
 * rz/zfs/windows7 zfs.vmdk
 */
typedef struct
{
	char *path;            // absolute path of the image
	char *lower_name;      // relative path, all lowercase, minus revision ID
	uint8_t *cache_map;    // cache map telling which parts are locally cached, NULL if complete
	uint32_t *crc32;       // list of crc32 checksums for each 16MiB block in image
	dnbd3_connection_t *uplink; // pointer to a server connection
	uint64_t filesize;     // size of image
	int rid;               // revision of image
	int users;             // clients currently using this image
	time_t atime;          // last access time
	char working;          // TRUE if image exists and completeness is == 100% or a working upstream proxy is connected
	pthread_spinlock_t lock;
} dnbd3_image_t;

typedef struct
{
	int sock;
	dnbd3_host_t host;
	uint8_t is_server;         // TRUE if a server in proxy mode, FALSE if real client
	pthread_t thread;
	dnbd3_image_t *image;
	pthread_spinlock_t lock;
	GSList *sendqueue;         // list of dnbd3_binstring_t*
} dnbd3_client_t;

// #######################################################

/**
 * Base directory where all images are stored in. Will always have a trailing slash
 */
extern char *_basePath;

/**
 * Whether or not simple *.vmdk files should be treated as revision 1
 */
extern int _vmdkLegacyMode;

extern int _shutdown;

#endif /* GLOBALS_H_ */
