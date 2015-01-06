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

#include "../config.h"
#include "../types.h"
#include "globals.h"

struct sockaddr_storage;

extern dnbd3_client_t *_clients[SERVER_MAX_CLIENTS];
extern int _num_clients;
extern pthread_spinlock_t _clients_lock;

#ifdef _DEBUG
extern int _fake_delay;
#endif

void dnbd3_cleanup();
void dnbd3_removeClient(dnbd3_client_t *client);
dnbd3_client_t* dnbd3_freeClient(dnbd3_client_t *client);
dnbd3_client_t* dnbd3_initClient(struct sockaddr_storage *client, int fd);
int dnbd3_serverUptime();

#if !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS != 64
#error Please set _FILE_OFFSET_BITS to 64 in your makefile/configuration
#endif

#endif /* SERVER_H_ */
