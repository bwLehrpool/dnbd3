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

#ifndef NET_H_
#define NET_H_

#include "dnbd3.h"

#define init_msghdr(h) do { \
        h.msg_name = NULL; \
        h.msg_namelen = 0; \
        h.msg_control = NULL; \
        h.msg_controllen = 0; \
        h.msg_flags = MSG_WAITALL | MSG_NOSIGNAL; \
	} while (0)

int dnbd3_net_connect(dnbd3_device_t *lo);

int dnbd3_net_disconnect(dnbd3_device_t *lo);

int dnbd3_net_send(void *data);

int dnbd3_net_receive(void *data);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
void dnbd3_net_heartbeat(struct timer_list *arg);
#else
void dnbd3_net_heartbeat(unsigned long arg);
#endif

int dnbd3_net_discover(void *data);

#endif /* NET_H_ */
