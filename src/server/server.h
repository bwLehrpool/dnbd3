/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
 *
 * This file may be licensed under the terms of of the
 * GNU General Public License Version 2 (the ``GPL'').
 *
 * Software distributed under the License is distributed
 * on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied. See the GPL for the specific language
 * governing rights and limitations.
 *
 * You should have received a copy of the GPL along with this
 * program. If not, go to http://www.gnu.org/licenses/gpl.html
 * or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef SERVER_H_
#define SERVER_H_

#include <stdint.h>
#include <stdio.h>
#include <glib.h>

#include "../config.h"
#include "../types.h"

typedef struct
{
	int fd;
} dnbd3_connection_t;

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
	int rid;               // revision of image
	uint64_t filesize;     // size of image
	time_t atime;          // last access time
	uint8_t *cache_map;    // cache map telling which parts are locally cached
	dnbd3_connection_t *uplink; // NULL = local image / completely cached, pointer to a server connection otherwise
	char working;          // TRUE if image exists and completeness is == 100% or a working upstream proxy is connected
	time_t delete_soft;    // unixtime telling when this image should be deleted. if there are still clients using this image it weill be kept, but new clients requesting the image will be rejected. 0 = never
	time_t delete_hard;    // unixtime telling when this image should be deleted, no matter if there are still clients connected. 0 = never
	pthread_spinlock_t lock;
} dnbd3_image_t;

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
	int sock;
	dnbd3_host_t host;
	uint8_t is_server;         // TRUE if a server in proxy mode, FALSE if real client
	pthread_t thread;
	dnbd3_image_t *image;
	pthread_spinlock_t lock;
	GSList *sendqueue;         // list of dnbd3_binstring_t*
} dnbd3_client_t;

typedef struct
{
	time_t         last_told;
	dnbd3_host_t   host;
	char           comment[COMMENT_LENGTH];
} dnbd3_alt_server_t;

typedef struct
{
	char          comment[COMMENT_LENGTH];
	dnbd3_host_t  host;
	dnbd3_host_t  mask;
} dnbd3_acess_rules_t;

extern dnbd3_client_t *_clients[SERVER_MAX_CLIENTS];
extern int _num_clients;
extern pthread_spinlock_t _clients_lock;

extern dnbd3_image_t *_images[SERVER_MAX_IMAGES];
extern int _num_images;
extern pthread_spinlock_t _images_lock;

extern dnbd3_alt_server_t *_alt_servers[SERVER_MAX_ALTS];
extern int _num_alts;
extern pthread_spinlock_t _alts_lock;

extern char *_config_file_name, *_rpc_password, *_cache_dir;

#ifdef _DEBUG
extern int _fake_delay;
#endif

void dnbd3_cleanup();
void dnbd3_free_client(dnbd3_client_t *client);

#if !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS != 64
#error Please set _FILE_OFFSET_BITS to 64 in your makefile/configuration
#endif

#endif /* SERVER_H_ */
