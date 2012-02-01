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
#include <glib-2.0/glib.h>

#include "config.h"
#include "../types.h"

typedef struct
{
    int sock;
    char ip[16];
    pthread_t *thread;
} dnbd3_client_t;

extern pthread_spinlock_t _spinlock;
extern char *_config_file_name;
extern GSList *_dnbd3_clients;

void dnbd3_cleanup();

#endif /* SERVER_H_ */
