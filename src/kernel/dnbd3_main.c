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
#include <net/ipv6.h>
#include "dnbd3_main.h"
#include "blk.h"

int major;
static unsigned int max_devs = NUMBER_DEVICES;
static dnbd3_device_t *dnbd3_devices;

struct device *dnbd3_device_to_dev(dnbd3_device_t *dev)
{
	return disk_to_dev(dev->disk);
}

int dnbd3_host_to_sockaddr(const dnbd3_host_t *host, struct sockaddr_storage *dest)
{
	struct sockaddr_in *sin4;
	struct sockaddr_in6 *sin6;

	memset(dest, 0, sizeof(*dest));
	if (host->type == HOST_IP4) {
		sin4 = (struct sockaddr_in*)dest;
		sin4->sin_family = AF_INET;
		memcpy(&(sin4->sin_addr), host->addr, 4);
		sin4->sin_port = host->port;
	} else if (host->type == HOST_IP6) {
		sin6 = (struct sockaddr_in6*)dest;
		sin6->sin6_family = AF_INET6;
		memcpy(&(sin6->sin6_addr), host->addr, 16);
		sin6->sin6_port = host->port;
	} else
		return 0;
	return 1;
}

int is_same_server(const struct sockaddr_storage *const x, const struct sockaddr_storage *const y)
{
	if (x->ss_family != y->ss_family)
		return 0;
	switch (x->ss_family) {
	case AF_INET: {
		const struct sockaddr_in *sinx = (const struct sockaddr_in *)x;
		const struct sockaddr_in *siny = (const struct sockaddr_in *)y;
		if (sinx->sin_port != siny->sin_port)
			return 0;
		if (sinx->sin_addr.s_addr != siny->sin_addr.s_addr)
			return 0;
		break;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sinx = (const struct sockaddr_in6 *)x;
		const struct sockaddr_in6 *siny = (const struct sockaddr_in6 *)y;
		if (sinx->sin6_port != siny->sin6_port)
			return 0;
		if (!ipv6_addr_equal(&sinx->sin6_addr, &siny->sin6_addr))
			return 0;
		break;
	}
	default:
		return 0;
	}
	return 1;
}

/**
 * Get a free slot pointer from the alt_servers list. Tries to find an
 * entirely empty slot first, then looks for a slot with a server that
 * wasn't reachable recently, finally returns NULL if none of the
 * conditions match.
 * The caller has to hold dev->alt_servers_lock.
 */
static dnbd3_alt_server_t *get_free_alt_server(dnbd3_device_t *const dev)
{
	int i;

	for (i = 0; i < NUMBER_SERVERS; ++i) {
		if (dev->alt_servers[i].host.ss_family == 0)
			return &dev->alt_servers[i];
	}
	for (i = 0; i < NUMBER_SERVERS; ++i) {
		if (dev->alt_servers[i].failures > 10)
			return &dev->alt_servers[i];
	}
	return NULL;
}

dnbd3_alt_server_t *get_existing_alt_from_addr(const struct sockaddr_storage *const addr,
		dnbd3_device_t *const dev)
{
	int i;

	for (i = 0; i < NUMBER_SERVERS; ++i) {
		if (is_same_server(addr, &dev->alt_servers[i].host))
			return &dev->alt_servers[i];
	}
	return NULL;
}

/**
 * Returns pointer to existing entry in alt_servers that matches the given
 * alt server, or NULL if not found.
 * The caller has to hold dev->alt_servers_lock.
 */
dnbd3_alt_server_t *get_existing_alt_from_host(const dnbd3_host_t *const host, dnbd3_device_t *const dev)
{
	struct sockaddr_storage addr;

	if (!dnbd3_host_to_sockaddr(host, &addr))
		return NULL;
	return get_existing_alt_from_addr(&addr, dev);
}

int dnbd3_add_server(dnbd3_device_t *dev, dnbd3_host_t *host)
{
	int result;
	dnbd3_alt_server_t *alt_server;

	if (host->type != HOST_IP4 && host->type != HOST_IP6)
		return -EINVAL;

	/* protect access to 'alt_servers' */
	mutex_lock(&dev->alt_servers_lock);
	alt_server = get_existing_alt_from_host(host, dev);
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
			dnbd3_host_to_sockaddr(host, &alt_server->host);
			alt_server->protocol_version = 0;
			alt_server->rtts[0] = alt_server->rtts[1] = alt_server->rtts[2]
				= alt_server->rtts[3] = RTT_UNREACHABLE;
			alt_server->failures = 0;
			result = 0;
		}
	}
	mutex_unlock(&dev->alt_servers_lock);
	return result;
}

int dnbd3_rem_server(dnbd3_device_t *dev, dnbd3_host_t *host)
{
	dnbd3_alt_server_t *alt_server;
	int result;

	/* protect access to 'alt_servers' */
	mutex_lock(&dev->alt_servers_lock);
	alt_server = get_existing_alt_from_host(host, dev);
	// REMOVE
	if (alt_server == NULL) {
		// Not found
		result = -ENOENT;
	} else {
		// Remove
		alt_server->host.ss_family = 0;
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
