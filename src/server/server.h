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

// one byte in the map covers 8 4kib blocks, so 32kib per byte
// "+ (1 << 15) - 1" is required to account for the last bit of
// the image that is smaller than 32kib
// this would be the case whenever the image file size is not a
// multiple of 32kib (= the number of blocks is not divisible by 8)
// ie: if the image is 49152 bytes and you do 49152 >> 15 you get 1,
// but you actually need 2 bytes to have a complete cache map
#define IMGSIZE_TO_MAPBYTES(bytes) ((int)(((bytes) + (1 << 15) - 1) >> 15))

typedef struct
{
	char *config_group; // exact name of group in config file that represents this image
	char *low_name; // full (global) name of image, lowercased for comparison, eg. "uni-freiburg/rz/ubuntu-12.04"
    int rid; // revision of provided image
    char *file; // path to image file or device
    uint64_t filesize; // size of image
    dnbd3_server_entry_t servers[NUMBER_SERVERS]; // known alt servers that also offer that image
    time_t atime; // last access time
    uint8_t *cache_map; // cache map telling which parts are locally cached
    char *cache_file; // path to local cache of image (in case the image is read from a dnbd3 device)
    char working;	// whether this image is considered working. local images are "working" if the local file exists, proxied images have to have at least one working upstream server or a complete local cache file
    time_t delete_soft; // unixtime telling when this image should be deleted. if there are still clients using this image it weill be kept, but new clients requesting the image will be rejected. 0 = never
    time_t delete_hard; // unixtime telling when this image should be deleted, no matter if there are still clients connected. 0 = never
    uint8_t relayed;		// TRUE if relayed from other server (needs dnbd3 client module loaded)
} dnbd3_image_t;

typedef struct
{
    int sock;
    uint8_t ipaddr[16];
    uint8_t addrtype; 	       // ip version (AF_INET or AF_INET6)
    uint8_t is_server;         // TRUE if a server in proxy mode, FALSE if real client
    pthread_t thread;
    dnbd3_image_t *image;
} dnbd3_client_t;

extern GSList *_dnbd3_clients; // of dnbd3_client_t
extern pthread_spinlock_t _spinlock;
extern char *_config_file_name, *_local_namespace, *_ipc_password;
extern GSList *_dnbd3_images; // of dnbd3_image_t


#ifdef _DEBUG
extern int _fake_delay;
#endif

void dnbd3_cleanup();

#if !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS != 64
#error Please set _FILE_OFFSET_BITS to 64 in your makefile/configuration
#endif

#endif /* SERVER_H_ */
