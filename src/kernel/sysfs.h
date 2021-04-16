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

#ifndef SYSFS_H_
#define SYSFS_H_

#include "dnbd3_main.h"

void dnbd3_sysfs_init(dnbd3_device_t *dev);

void dnbd3_sysfs_exit(dnbd3_device_t *dev);

typedef struct {
	struct attribute attr;
	ssize_t (*show)(char *buf, dnbd3_device_t *dev);
	ssize_t (*store)(const char *buf, size_t len, dnbd3_device_t *dev);
} device_attr_t;

#endif /* SYSFS_H_ */
