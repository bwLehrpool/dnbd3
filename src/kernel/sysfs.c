// SPDX-License-Identifier: GPL-2.0
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

#include <linux/kobject.h>

#include "sysfs.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/**
 * Print currently connected server IP:PORT
 */
ssize_t show_cur_server_addr(char *buf, dnbd3_device_t *dev)
{
	ssize_t ret;

	spin_lock(&dev->blk_lock);
	ret =  MIN(snprintf(buf, PAGE_SIZE, "%pISpc\n", &dev->cur_server.host), PAGE_SIZE);
	spin_unlock(&dev->blk_lock);
	return ret;
}

/**
 * List alt servers. One line per server, format is:
 * IP:PORT RTT consecutive_failures best_count
 */
ssize_t show_alt_servers(char *buf, dnbd3_device_t *dev)
{
	int i, size = PAGE_SIZE;
	ssize_t ret;

	if (mutex_lock_interruptible(&dev->alt_servers_lock) != 0)
		return 0;

	for (i = 0; i < NUMBER_SERVERS; ++i) {
		if (dev->alt_servers[i].host.ss_family == 0)
			continue;

		ret = MIN(snprintf(buf, size, "%pISpc %llu %d %d\n", &dev->alt_servers[i].host,
					(unsigned long long)((dev->alt_servers[i].rtts[0] +
							 dev->alt_servers[i].rtts[1] +
							 dev->alt_servers[i].rtts[2] +
							 dev->alt_servers[i].rtts[3]) / 4),
					(int)dev->alt_servers[i].failures,
					(int)dev->alt_servers[i].best_count),
			size);
		size -= ret;
		buf += ret;
		if (size <= 0) {
			size = 0;
			break;
		}
	}
	mutex_unlock(&dev->alt_servers_lock);
	return PAGE_SIZE - size;
}

/**
 * Show name of image in use
 */
ssize_t show_image_name(char *buf, dnbd3_device_t *dev)
{
	ssize_t ret;

	spin_lock(&dev->blk_lock);
	ret = MIN(snprintf(buf, PAGE_SIZE, "%s\n", dev->imgname), PAGE_SIZE);
	spin_unlock(&dev->blk_lock);
	return ret;
}

/**
 * Show rid of image in use
 */
ssize_t show_rid(char *buf, dnbd3_device_t *dev)
{
	// No locking here, primitive type, no pointer to allocated memory
	return MIN(snprintf(buf, PAGE_SIZE, "%d\n", dev->rid), PAGE_SIZE);
}

ssize_t show_update_available(char *buf, dnbd3_device_t *dev)
{
	// Same story
	return MIN(snprintf(buf, PAGE_SIZE, "%d\n", dev->update_available), PAGE_SIZE);
}

device_attr_t cur_server_addr = {
	.attr = { .name = "cur_server_addr", .mode = 0444 },
	.show = show_cur_server_addr,
	.store = NULL,
};

device_attr_t alt_servers = {
	.attr = { .name = "alt_servers", .mode = 0444 },
	.show = show_alt_servers,
	.store = NULL,
};

device_attr_t image_name = {
	.attr = { .name = "image_name", .mode = 0444 },
	.show = show_image_name,
	.store = NULL,
};

device_attr_t rid = {
	.attr = { .name = "rid", .mode = 0444 },
	.show = show_rid,
	.store = NULL,
};

device_attr_t update_available = {
	.attr = { .name = "update_available", .mode = 0444 },
	.show = show_update_available,
	.store = NULL,
};

ssize_t device_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	device_attr_t *device_attr = container_of(attr, device_attr_t, attr);
	dnbd3_device_t *dev = container_of(kobj, dnbd3_device_t, kobj);

	return device_attr->show(buf, dev);
}

struct attribute *device_attrs[] = {
	&cur_server_addr.attr,
	&alt_servers.attr,
	&image_name.attr,	&rid.attr,
	&update_available.attr,
	NULL,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
ATTRIBUTE_GROUPS(device);
#endif

const struct sysfs_ops device_ops = {
	.show = device_show,
};

void release(struct kobject *kobj)
{
	kobj->state_initialized = 0;
}

struct kobj_type device_ktype = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
	.default_attrs = device_attrs,
#else
	.default_groups = device_groups,
#endif
	.sysfs_ops = &device_ops,
	.release = release,
};

void dnbd3_sysfs_init(dnbd3_device_t *dev)
{
	int error;
	struct kobject *kobj = &dev->kobj;
	struct kobj_type *ktype = &device_ktype;
	struct kobject *parent = &disk_to_dev(dev->disk)->kobj;

	error = kobject_init_and_add(kobj, ktype, parent, "%s", "net");
	if (error)
		dev_err(dnbd3_device_to_dev(dev), "initializing sysfs for device failed!\n");
}

void dnbd3_sysfs_exit(dnbd3_device_t *dev)
{
	kobject_put(&dev->kobj);
}
