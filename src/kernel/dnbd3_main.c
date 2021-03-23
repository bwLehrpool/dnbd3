// SPDX-License-Identifier: GPL-2.0
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <dnbd3/config/client.h>
#include <dnbd3/version.h>
#include "dnbd3_main.h"
#include "blk.h"

int major;
static unsigned int max_devs = NUMBER_DEVICES;
static dnbd3_device_t *dnbd3_devices;

struct device *dnbd3_device_to_dev(dnbd3_device_t *dev)
{
	return disk_to_dev(dev->disk);
}

int is_same_server(const dnbd3_server_t *const a, const dnbd3_server_t *const b)
{
	return (a->host.type == b->host.type) && (a->host.port == b->host.port) &&
	       (0 == memcmp(a->host.addr, b->host.addr, (a->host.type == HOST_IP4 ? 4 : 16)));
}

/**
 * Get a free slot pointer from the alt_servers list. Tries to find an
 * entirely empty slot first, then looks for a slot with a server that
 * wasn't reachable recently, finally returns NULL if none of the
 * conditions match.
 * The caller has to hold dev->alt_servers_lock.
 */
static inline dnbd3_server_t *get_free_alt_server(dnbd3_device_t *const dev)
{
	int i;

	for (i = 0; i < NUMBER_SERVERS; ++i) {
		if (dev->alt_servers[i].host.type == 0)
			return &dev->alt_servers[i];
	}
	for (i = 0; i < NUMBER_SERVERS; ++i) {
		if (dev->alt_servers[i].failures > 10)
			return &dev->alt_servers[i];
	}
	return NULL;
}

/**
 * Returns pointer to existing entry in alt_servers that matches the given
 * alt server, or NULL if not found.
 * The caller has to hold dev->alt_servers_lock.
 */
dnbd3_server_t *get_existing_server(const dnbd3_host_t *const newserver, dnbd3_device_t *const dev)
{
	int i;

	for (i = 0; i < NUMBER_SERVERS; ++i) {
		if ((newserver->type == dev->alt_servers[i].host.type) &&
		    (newserver->port == dev->alt_servers[i].host.port) &&
		    (0 == memcmp(newserver->addr, dev->alt_servers[i].host.addr,
				 (newserver->type == HOST_IP4 ? 4 : 16)))) {
			return &dev->alt_servers[i];
		}
	}
	return NULL;
}

int dnbd3_add_server(dnbd3_device_t *dev, dnbd3_host_t *host)
{
	int result;
	dnbd3_server_t *alt_server;
	/* protect access to 'alt_servers' */
	mutex_lock(&dev->alt_servers_lock);
	alt_server = get_existing_server(host, dev);
	// ADD
	if (alt_server != NULL) {
		// Exists
		result = -EEXIST;
	} else {
		// OK add
		alt_server = get_free_alt_server(dev);
		if (alt_server == NULL) {
			result = -ENOSPC;
		} else {
			alt_server->host = *host;
			alt_server->failures = 0;
			result = 0;
		}
	}
	mutex_unlock(&dev->alt_servers_lock);
	return result;
}

int dnbd3_rem_server(dnbd3_device_t *dev, dnbd3_host_t *host)
{
	dnbd3_server_t *alt_server;
	int result;
	/* protect access to 'alt_servers' */
	mutex_lock(&dev->alt_servers_lock);
	alt_server = get_existing_server(host, dev);
	// REMOVE
	if (alt_server == NULL) {
		// Not found
		result = -ENOENT;
	} else {
		// Remove
		alt_server->host.type = 0;
		result = 0;
	}
	mutex_unlock(&dev->alt_servers_lock);
	return result;
}

static int __init dnbd3_init(void)
{
	int i;

	dnbd3_devices = kcalloc(max_devs, sizeof(*dnbd3_devices), GFP_KERNEL);
	if (!dnbd3_devices)
		return -ENOMEM;

	// initialize block device
	major = register_blkdev(0, "dnbd3");
	if (major == 0) {
		pr_err("register_blkdev failed\n");
		return -EIO;
	}

	pr_info("kernel module in version %s loaded\n", DNBD3_VERSION);
	pr_debug("machine type %s\n", DNBD3_ENDIAN_MODE);

	// add MAX_NUMBER_DEVICES devices
	for (i = 0; i < max_devs; i++) {
		if (dnbd3_blk_add_device(&dnbd3_devices[i], i) != 0) {
			pr_err("dnbd3_blk_add_device failed\n");
			// TODO: delete all devices added so far.
			// It could happen that it's not the first one that fails.
			// Also call unregister_blkdev and free memory.
			return -EIO;
		}
	}

	pr_info("init successful (%i devices)\n", max_devs);

	return 0;
}

static void __exit dnbd3_exit(void)
{
	int i;

	pr_debug("exiting kernel module...\n");
	for (i = 0; i < max_devs; i++)
		dnbd3_blk_del_device(&dnbd3_devices[i]);

	unregister_blkdev(major, "dnbd3");
	kfree(dnbd3_devices);

	pr_info("exit kernel module done\n");
}

module_init(dnbd3_init);
module_exit(dnbd3_exit);

MODULE_DESCRIPTION("Distributed Network Block Device 3");
MODULE_LICENSE("GPL");
MODULE_VERSION(DNBD3_VERSION);

module_param(max_devs, int, 0444);
MODULE_PARM_DESC(max_devs, "number of network block devices to initialize (default: 8)");
