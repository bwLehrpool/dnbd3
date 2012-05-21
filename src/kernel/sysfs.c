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

ssize_t show_cur_server_ip(char *buf, dnbd3_device_t *dev)
{
    return sprintf(buf, "%s\n", dev->cur_server.host);
}

ssize_t show_cur_server_rtt(char *buf, dnbd3_device_t *dev)
{
    return sprintf(buf, "%llu\n", dev->cur_server.rtt);
}

ssize_t show_alt_server_num(char *buf, dnbd3_device_t *dev)
{
    return sprintf(buf, "%d\n", dev->alt_servers_num);
}

ssize_t show_vid(char *buf, dnbd3_device_t *dev)
{
    return sprintf(buf, "%d\n", dev->vid);
}

ssize_t show_rid(char *buf, dnbd3_device_t *dev)
{
    return sprintf(buf, "%d\n", dev->rid);
}

ssize_t show_update_available(char *buf, dnbd3_device_t *dev)
{
    return sprintf(buf, "%d\n", dev->update_available);
}

ssize_t show_alt_server_ip(char *buf, dnbd3_server_t *srv)
{
    return sprintf(buf, "%s\n", srv->host);
}

ssize_t show_alt_server_rtt(char *buf, dnbd3_server_t *srv)
{
    return sprintf(buf, "%llu\n", srv->rtt);
}

device_attr_t cur_server_ip =
{
    .attr = {.name = "cur_server_ip", .mode = 0444 },
    .show   = show_cur_server_ip,
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

device_attr_t vid =
{
    .attr = {.name = "vid", .mode = 0444 },
    .show   = show_vid,
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

server_attr_t alt_server_ip =
{
    .attr = {.name = "alt_server_ip", .mode = 0444 },
    .show   = show_alt_server_ip,
    .store  = NULL,
};

server_attr_t alt_server_rtt =
{
    .attr = {.name = "alt_server_rtt", .mode = 0444 },
    .show   = show_alt_server_rtt,
    .store  = NULL,
};

ssize_t device_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
    device_attr_t *device_attr = container_of(attr, device_attr_t, attr);
    dnbd3_device_t *dev = container_of(kobj, dnbd3_device_t, kobj);
    return device_attr->show(buf, dev);
}

ssize_t server_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
    server_attr_t *server_attr = container_of(attr, server_attr_t, attr);
    dnbd3_server_t *srv = container_of(kobj, dnbd3_server_t, kobj);
    return server_attr->show(buf, srv);
}

struct attribute *device_attrs[] =
{
    &cur_server_ip.attr,
    &cur_server_rtt.attr,
    &alt_server_num.attr,
    &vid.attr,
    &rid.attr,
    &update_available.attr,
    NULL,
};

struct attribute *server_attrs[] =
{
    &alt_server_ip.attr,
    &alt_server_rtt.attr,
    NULL,
};

struct sysfs_ops device_ops =
{
    .show = device_show,
};

struct sysfs_ops server_ops =
{
    .show = server_show,
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

struct kobj_type server_ktype =
{
    .default_attrs = server_attrs,
    .sysfs_ops = &server_ops,
    .release = release,
};

void dnbd3_sysfs_init(dnbd3_device_t *dev)
{
    int i;
    char name[] = "alt_server99";
    struct kobject *kobj = &dev->kobj;
    struct kobj_type *ktype = &device_ktype;
    struct kobject *parent = &disk_to_dev(dev->disk)->kobj;

    kobject_init_and_add(kobj, ktype, parent, "net");

    for (i = 0; i < NUMBER_SERVERS; i++)
    {
        sprintf(name, "alt_server%d", i);
        kobj = &dev->alt_servers[i].kobj;
        ktype = &server_ktype;
        parent = &dev->kobj;
        kobject_init_and_add(kobj, ktype, parent, name);
    }
}

void dnbd3_sysfs_exit(dnbd3_device_t *dev)
{
    int i;
    for (i = 0; i < NUMBER_SERVERS; i++)
    {
        kobject_put(&dev->alt_servers[i].kobj);
    }
    kobject_put(&dev->kobj);
}
