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

#include "blk.h"
#include "net.h"

int dnbd3_blk_add_device(struct dnbd3_device *dev, int minor)
{
	struct gendisk *disk;
	struct request_queue *blk_queue;

	init_waitqueue_head(&dev->process_queue_send);
	init_waitqueue_head(&dev->process_queue_receive);
	INIT_LIST_HEAD(&dev->request_queue_send);
	INIT_LIST_HEAD(&dev->request_queue_receive);

	if (!(disk = alloc_disk(1)))
	{
		printk("ERROR: dnbd3 alloc_disk failed.\n");
		return -EIO;
	}

	disk->major = major;
	disk->first_minor = minor;
	sprintf(disk->disk_name, "dnbd%d", minor);
	set_capacity(disk, 0);
	set_disk_ro(disk, 1);
	disk->fops = &dnbd3_blk_ops;

	spin_lock_init(&dev->blk_lock);
	if ((blk_queue = blk_init_queue(&dnbd3_blk_request, &dev->blk_lock)) == NULL)
	{
		printk("ERROR: dnbd3 blk_init_queue failed.\n");
		return -EIO;
	}

	blk_queue_logical_block_size(blk_queue, DNBD3_BLOCK_SIZE);
	disk->queue = blk_queue;
	disk->private_data = dev;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, disk->queue);
	dev->disk = disk;

	add_disk(disk); // must be last
	return 0;
}

int dnbd3_blk_del_device(struct dnbd3_device *dev)
{
	if (dev->sock)
	{
		sock_release(dev->sock);
		dev->sock = NULL;
	}

	del_gendisk(dev->disk);
	put_disk(dev->disk);
	blk_cleanup_queue(dev->disk->queue);
	return 0;
}

struct block_device_operations dnbd3_blk_ops =
{ .owner = THIS_MODULE, .ioctl = dnbd3_blk_ioctl, };

int dnbd3_blk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
		unsigned long arg)
{
	struct dnbd3_device *lo = bdev->bd_disk->private_data;

	switch (cmd)
	{
	case IOCTL_SET_HOST:
		strcpy(lo->host, (char *) arg);
		break;

	case IOCTL_SET_PORT:
		strcpy(lo->port, (char *) arg);
		break;
	case IOCTL_SET_IMAGE:
		strcpy(lo->image_id, (char *) arg);
		break;
	case IOCTL_CONNECT:
		if (lo->host && lo->port && lo->image_id)
			dnbd3_net_connect(lo);
		else
			return -1;
		break;
	case IOCTL_DISCONNECT:
		dnbd3_net_disconnect(lo);
		break;
	case BLKFLSBUF:
		break;

	default:
		return -1;

	}
	return 0;
}

void dnbd3_blk_request(struct request_queue *q)
{
	struct request *req;
	struct dnbd3_device *lo;

	while ((req = blk_fetch_request(q)) != NULL)
	{
		lo = req->rq_disk->private_data;

		if (req->cmd_type != REQ_TYPE_FS)
		{
			__blk_end_request_all(req, 0);
			continue;
		}

		if (rq_data_dir(req) == READ)
		{
			list_add_tail(&req->queuelist, &lo->request_queue_send);
			spin_unlock_irq(q->queue_lock);
			wake_up(&lo->process_queue_send);
			spin_lock_irq(q->queue_lock);
		}
	}
}
