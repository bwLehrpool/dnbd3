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

#include "config.h"
#include "../types.h"

typedef struct
{
	char *name; // full name of image, eg. "uni-freiburg.ubuntu-12.04"
	char *low_name; // full name of image, lowercased for comparison
    int rid; // revision of provided image
    char *file; // path to image file or device
    uint64_t filesize; // size of image
    dnbd3_server_entry_t servers[NUMBER_SERVERS]; // known alt servers that also offer that image
    time_t atime; // last access time
    uint8_t *cache_map; // cache map telling which parts are locally cached
    char *cache_file; // path to local cache of image (in case the image is read from a dnbd3 device)
    char working;	// whether this image is considered working. local images are "working" if the local file exists, proxied images have to have at least one working upstream server or a complete local cache file
} dnbd3_image_t;

typedef struct
{
    int sock;
    uint8_t ipaddr[16];
    uint8_t addrtype; 	// ip version (AF_INET or AF_INET6)
    pthread_t thread;
    dnbd3_image_t *image;
} dnbd3_client_t;

extern GSList *_dnbd3_clients; // of dnbd3_client_t
extern pthread_spinlock_t _spinlock;
extern char *_config_file_name;
extern GSList *_dnbd3_images; // of dnbd3_image_t

void dnbd3_cleanup();

#endif /* SERVER_H_ */
