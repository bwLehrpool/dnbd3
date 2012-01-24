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

// block
int major;
struct gendisk *disk;
struct request_queue *dnbd3_queue;
spinlock_t dnbd3_lock;

// network
char* _host = NULL;
char* _port = NULL;
char* _image_id = NULL;
struct socket *_sock;

// process
wait_queue_head_t _process_queue_send;
wait_queue_head_t _process_queue_receive;
struct list_head _request_queue_send;
struct list_head _request_queue_receive;

static int __init dnbd3_init(void)
{
	// initialize queues
	init_waitqueue_head(&_process_queue_send);
	init_waitqueue_head(&_process_queue_receive);
	INIT_LIST_HEAD(&_request_queue_send);
	INIT_LIST_HEAD(&_request_queue_receive);

	// initialize block device
	if ((major = register_blkdev(0, "dnbd")) == 0)
	{
		printk("ERROR: dnbd3 register_blkdev failed.\n");
		return -EIO;
	}
	if (!(disk = alloc_disk(1)))
	{
		printk("ERROR: dnbd3 alloc_disk failed.\n");
		return -EIO;
	}
	disk->major = major;
	disk->first_minor = 0;
	sprintf(disk->disk_name, "dnbd0");
	set_capacity(disk, 0);
	set_disk_ro(disk, 1);
	disk->fops = &dnbd3_blk_ops;
	spin_lock_init(&dnbd3_lock);
	if ((dnbd3_queue = blk_init_queue(&dnbd3_blk_request, &dnbd3_lock)) == NULL)
	{
		printk("ERROR: dnbd3 blk_init_queue failed.\n");
		return -EIO;
	}
	blk_queue_logical_block_size(dnbd3_queue, DNBD3_BLOCK_SIZE);
	disk->queue = dnbd3_queue;

	add_disk(disk); // must be last

	printk("INFO: dnbd3 init successful.\n");
	return 0;
}

static void __exit dnbd3_exit(void)
{
	if (_sock)
		sock_release(_sock);
	unregister_blkdev(major, "dnbd");
	del_gendisk(disk);
	put_disk(disk);
	blk_cleanup_queue(dnbd3_queue);
	printk("INFO: dnbd3 exit.\n");
}

module_init( dnbd3_init);
module_exit( dnbd3_exit);
MODULE_LICENSE("GPL");
