/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
 *
 * This file may be licensed under the terms of the
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

#include "dnbd3_main.h"

void dnbd3_net_work_init(dnbd3_device_t *dev);

int dnbd3_new_connection(dnbd3_device_t *dev, struct sockaddr_storage *addr, bool init);

int dnbd3_net_disconnect(dnbd3_device_t *dev);

#endif /* NET_H_ */
