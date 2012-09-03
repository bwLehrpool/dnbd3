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

#include <linux/kobject.h>

#include "sysfs.h"
#include "utils.h"

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

ssize_t show_cur_server_addr(char *buf, dnbd3_device_t *dev)
{
	if (dev->cur_server.hostaddrtype == AF_INET)
		return MIN(snprintf(buf, PAGE_SIZE, "%pI4,%d\n", dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port)), PAGE_SIZE);
	else if (dev->cur_server.hostaddrtype == AF_INET6)
		return MIN(snprintf(buf, PAGE_SIZE, "%pI6,%d\n", dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port)), PAGE_SIZE);
	*buf = '\0';
	return 0;
}

ssize_t show_cur_server_rtt(char *buf, dnbd3_device_t *dev)
{
	return MIN(snprintf(buf, PAGE_SIZE, "%llu\n", (unsigned long long)dev->cur_rtt), PAGE_SIZE);
}

ssize_t show_alt_server_num(char *buf, dnbd3_device_t *dev)
{
	int i, num = 0;
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if (dev->alt_servers[i].hostaddrtype) ++num;
	}
	return MIN(snprintf(buf, PAGE_SIZE, "%d\n", num), PAGE_SIZE);
}

ssize_t show_alt_servers(char *buf, dnbd3_device_t *dev)
{
	int i, size = PAGE_SIZE, ret;
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if (dev->alt_servers[i].hostaddrtype == AF_INET)
			ret = MIN(snprintf(buf, size, "%pI4,%d,%llu,%d\n",
			                   dev->alt_servers[i].hostaddr,
			                   (int)ntohs(dev->alt_servers[i].port),
			                   (unsigned long long)((dev->alt_servers[i].rtts[0] + dev->alt_servers[i].rtts[1] + dev->alt_servers[i].rtts[2] + dev->alt_servers[i].rtts[3]) / 4),
			                   (int)dev->alt_servers[i].failures)
			          , size);
		else if (dev->alt_servers[i].hostaddrtype == AF_INET6)
			ret = MIN(snprintf(buf, size, "%pI6,%d,%llu,%d\n",
			                   dev->alt_servers[i].hostaddr,
			                   (int)ntohs(dev->alt_servers[i].port),
			                   (unsigned long long)((dev->alt_servers[i].rtts[0] + dev->alt_servers[i].rtts[1] + dev->alt_servers[i].rtts[2] + dev->alt_servers[i].rtts[3]) / 4),
			                   (int)dev->alt_servers[i].failures)
			          , size);
		else
			continue;
		size -= ret;
		buf += ret;
		if (size <= 0)
		{
			size = 0;
			break;
		}
	}
	return PAGE_SIZE - size;
}

ssize_t show_image_name(char *buf, dnbd3_device_t *dev)
{
	if (dev->imgname == NULL) return sprintf(buf, "(null)");
	return MIN(snprintf(buf, PAGE_SIZE, "%s\n", dev->imgname), PAGE_SIZE);
}

ssize_t show_rid(char *buf, dnbd3_device_t *dev)
{
	return MIN(snprintf(buf, PAGE_SIZE, "%d\n", dev->rid), PAGE_SIZE);
}

ssize_t show_update_available(char *buf, dnbd3_device_t *dev)
{
	return MIN(snprintf(buf, PAGE_SIZE, "%d\n", dev->update_available), PAGE_SIZE);
}

device_attr_t cur_server_addr =
{
	.attr = {.name = "cur_server_addr", .mode = 0444 },
	.show   = show_cur_server_addr,
	.store  = NULL,
};

device_attr_t cur_server_rtt =
{
	.attr = {.name = "cur_server_rtt", .mode = 0444 },
	.show   = show_cur_server_rtt,
	.store  = NULL,
};

device_attr_t alt_server_num =
{
	.attr = {.name = "alt_server_num", .mode = 0444 },
	.show   = show_alt_server_num,
	.store  = NULL,
};

device_attr_t alt_servers =
{
	.attr = {.name = "alt_servers", .mode = 0444 },
	.show   = show_alt_servers,
	.store  = NULL,
};

device_attr_t image_name =
{
	.attr = {.name = "image_name", .mode = 0444 },
	.show   = show_image_name,
	.store  = NULL,
};

device_attr_t rid =
{
	.attr = {.name = "rid", .mode = 0444 },
	.show   = show_rid,
	.store  = NULL,
};

device_attr_t update_available =
{
	.attr = {.name = "update_available", .mode = 0444 },
	.show   = show_update_available,
	.store  = NULL,
};

ssize_t device_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	device_attr_t *device_attr = container_of(attr, device_attr_t, attr);
	dnbd3_device_t *dev = container_of(kobj, dnbd3_device_t, kobj);
	return device_attr->show(buf, dev);
}

struct attribute *device_attrs[] =
{
	&cur_server_addr.attr,
	&cur_server_rtt.attr,
	&alt_server_num.attr,
	&alt_servers.attr,
	&image_name.attr,
	&rid.attr,
	&update_available.attr,
	NULL,
};


struct sysfs_ops device_ops =
{
	.show = device_show,
};

void release(struct kobject *kobj)
{
	kobj->state_initialized = 0;
}

struct kobj_type device_ktype =
{
	.default_attrs = device_attrs,
	.sysfs_ops = &device_ops,
	.release = release,
};


void dnbd3_sysfs_init(dnbd3_device_t *dev)
{
	struct kobject *kobj = &dev->kobj;
	struct kobj_type *ktype = &device_ktype;
	struct kobject *parent = &disk_to_dev(dev->disk)->kobj;

	kobject_init_and_add(kobj, ktype, parent, "net");
}

void dnbd3_sysfs_exit(dnbd3_device_t *dev)
{
	kobject_put(&dev->kobj);
}
