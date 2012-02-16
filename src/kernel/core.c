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

#include "dnbd3.h"
#include "blk.h"

int major;
dnbd3_device_t dnbd3_device[NUMBER_DEVICES];

static int __init dnbd3_init(void)
{
    int i;

    // initialize block device
    if ((major = register_blkdev(0, "dnbd3")) == 0)
    {
        printk("ERROR: dnbd3 register_blkdev failed.\n");
        return -EIO;
    }

    // add MAX_NUMBER_DEVICES devices
    for (i = 0; i < NUMBER_DEVICES; i++)
    {
        if (dnbd3_blk_add_device(&dnbd3_device[i], i) != 0)
        {
            printk("ERROR: adding device failed.\n");
            return -EIO;
        }
    }

    printk("INFO: dnbd3 init successful.\n");
    return 0;
}

static void __exit dnbd3_exit(void)
{
    int i;

    for (i = 0; i < NUMBER_DEVICES; i++)
    {
        dnbd3_blk_del_device(&dnbd3_device[i]);
    }

    unregister_blkdev(major, "dnbd3");
    printk("INFO: dnbd3 exit.\n");
}

module_init( dnbd3_init);
module_exit( dnbd3_exit);

MODULE_DESCRIPTION("Distributed Network Block Device 3");
MODULE_LICENSE("GPL");
