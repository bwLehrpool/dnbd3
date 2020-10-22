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

static int __init dnbd3_init(void)
{
	int i;

	dnbd3_devices = kcalloc(max_devs, sizeof(*dnbd3_devices), GFP_KERNEL);
	if (!dnbd3_devices)
		return -ENOMEM;

	// initialize block device
	if ((major = register_blkdev(0, "dnbd3")) == 0)
	{
		pr_err("register_blkdev failed\n");
		return -EIO;
	}

	pr_info("kernel module in version %s loaded\n", DNBD3_VERSION);
	pr_debug("machine type %s\n", DNBD3_ENDIAN_MODE);

	// add MAX_NUMBER_DEVICES devices
	for (i = 0; i < max_devs; i++)
	{
		if (dnbd3_blk_add_device(&dnbd3_devices[i], i) != 0)
		{
			pr_err("dnbd3_blk_add_device failed\n");
			return -EIO; // TODO: delete all devices added so far. it could happen that it's not the first one that fails. also call unregister_blkdev and free memory
		}
	}

	pr_info("init successful (%i devices)\n", max_devs);

	return 0;
}

static void __exit dnbd3_exit(void)
{
	int i;

	for (i = 0; i < max_devs; i++)
	{
		dnbd3_blk_del_device(&dnbd3_devices[i]);
	}

	unregister_blkdev(major, "dnbd3");
	kfree(dnbd3_devices);

	pr_info("exit kernel module\n");
}

module_init(dnbd3_init);
module_exit(dnbd3_exit);

MODULE_DESCRIPTION("Distributed Network Block Device 3");
MODULE_LICENSE("GPL");
MODULE_VERSION(DNBD3_VERSION);

module_param(max_devs, int, 0444);
MODULE_PARM_DESC(max_devs, "number of network block devices to initialize (default: 8)");
