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
#include "sysfs.h"

#include <linux/pagemap.h>

int dnbd3_blk_add_device(dnbd3_device_t *dev, int minor)
{
    struct gendisk *disk;
    struct request_queue *blk_queue;

    init_waitqueue_head(&dev->process_queue_send);
    init_waitqueue_head(&dev->process_queue_receive);
    init_waitqueue_head(&dev->process_queue_discover);
    INIT_LIST_HEAD(&dev->request_queue_send);
    INIT_LIST_HEAD(&dev->request_queue_receive);

    memset(&dev->cur_server, 0, sizeof(dev->cur_server));
    memset(&dev->initial_server, 0, sizeof(dev->initial_server));
    dev->better_sock = NULL;

    dev->imgname = NULL;
    dev->rid = 0;
    dev->update_available = 0;
    memset(dev->alt_servers, 0, sizeof(dev->alt_servers[0])*NUMBER_SERVERS);
    dev->thread_send = NULL;
    dev->thread_receive = NULL;
    dev->thread_discover = NULL;
    dev->discover = 0;
    dev->panic = 0;
    dev->panic_count = 0;
    dev->reported_size = 0;

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
    blk_queue_physical_block_size(blk_queue, DNBD3_BLOCK_SIZE);

    disk->queue = blk_queue;
    disk->private_data = dev;
    queue_flag_set_unlocked(QUEUE_FLAG_NONROT, disk->queue);
    dev->disk = disk;

    add_disk(disk);
    dnbd3_sysfs_init(dev);
    return 0;
}

int dnbd3_blk_del_device(dnbd3_device_t *dev)
{
	dnbd3_sysfs_exit(dev);
	dnbd3_net_disconnect(dev);
    del_gendisk(dev->disk);
    put_disk(dev->disk);
    blk_cleanup_queue(dev->disk->queue);
    return 0;
}

struct block_device_operations dnbd3_blk_ops =
{ .owner = THIS_MODULE, .ioctl = dnbd3_blk_ioctl, };

int dnbd3_blk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
    int result = 0;
    dnbd3_device_t *dev = bdev->bd_disk->private_data;
    struct request_queue *blk_queue = dev->disk->queue;
    char *imgname = NULL;
    dnbd3_ioctl_t *msg = kmalloc(sizeof(*msg), GFP_KERNEL);
    unsigned long irqflags;

    if (msg == NULL) return -ENOMEM;
    copy_from_user((char *)msg, (char *)arg, 2);
    if (msg->len != sizeof(*msg))
    {
    	result = -ENOEXEC;
    	goto cleanup_return;
    }
    copy_from_user((char *)msg, (char *)arg, sizeof(*msg));
    if (msg->imgname != NULL && msg->imgnamelen > 0)
    {
    	imgname = kmalloc(msg->imgnamelen + 1, GFP_KERNEL);
    	if (imgname == NULL)
    	{
    		result = -ENOMEM;
    		goto cleanup_return;
    	}
    	copy_from_user(imgname, msg->imgname, msg->imgnamelen);
    	imgname[msg->imgnamelen] = '\0';
    	//printk("IOCTL Image name of len %d is %s\n", (int)msg->imgnamelen, imgname);
    }

    switch (cmd)
    {
    case IOCTL_OPEN:
    	if (dev->imgname != NULL)
    	{
    		result = -EBUSY;
    	}
    	else if (imgname == NULL)
    	{
    		result = -EINVAL;
    	}
    	else
    	{
			memcpy(dev->cur_server.hostaddr, msg->addr, 16);
			dev->cur_server.port = msg->port;
			dev->cur_server.hostaddrtype = msg->addrtype;
			dev->cur_server.failures = 0;
			memcpy(&dev->initial_server, &dev->cur_server, sizeof(dev->initial_server));
			dev->imgname = imgname;
			dev->rid = msg->rid;
			dev->is_server = msg->is_server;
			blk_queue->backing_dev_info.ra_pages = (msg->read_ahead_kb * 1024) / PAGE_CACHE_SIZE;
			if (dnbd3_net_connect(dev) == 0)
			{
				result = 0;
				imgname = NULL; // Prevent kfree at the end
			}
			else
			{
				result = -ENOENT;
				dev->imgname = NULL;
			}
    	}
        break;

    case IOCTL_CLOSE:
    	dnbd3_blk_fail_all_requests(dev);
        result = dnbd3_net_disconnect(dev);
        dnbd3_blk_fail_all_requests(dev);
        set_capacity(dev->disk, 0);
        if (dev->imgname)
        {
        	kfree(dev->imgname);
        	dev->imgname = NULL;
        }
        break;

    case IOCTL_SWITCH:
        dnbd3_net_disconnect(dev);
		memcpy(dev->cur_server.hostaddr, msg->addr, 16);
		dev->cur_server.port = msg->port;
		dev->cur_server.hostaddrtype = msg->addrtype;
        result = dnbd3_net_connect(dev);
        break;

    case IOCTL_ADD_SRV:
    case IOCTL_REM_SRV:
    	if (dev->imgname == NULL)
    	{
    		result = -ENOENT;
    	}
    	else
    	{
    		spin_lock_irqsave(&dev->blk_lock, irqflags);
    		if (dev->new_servers_num >= NUMBER_SERVERS)
    			result = -EAGAIN;
    		else
    		{
				memcpy(dev->new_servers[dev->new_servers_num].hostaddr, msg->addr, 16);
				dev->new_servers[dev->new_servers_num].port = msg->port;
				dev->new_servers[dev->new_servers_num].hostaddrtype = msg->addrtype;
				dev->new_servers[dev->new_servers_num].failures = (cmd == IOCTL_ADD_SRV ? 0 : 1); // 0 = ADD, 1 = REM
				++dev->new_servers_num;
				result = 0;
    		}
    		spin_unlock_irqrestore(&dev->blk_lock, irqflags);
    	}
    	break;

    case BLKFLSBUF:
        break;

    default:
        result = -EIO;
        break;
    }

cleanup_return:
    if (msg) kfree(msg);
    if (imgname) kfree(imgname);
    return result;
}

void dnbd3_blk_request(struct request_queue *q)
{
    struct request *req;
    dnbd3_device_t *dev;

    while ((req = blk_fetch_request(q)) != NULL)
    {
        dev = req->rq_disk->private_data;

        if (dev->imgname == NULL)
        {
        	__blk_end_request_all(req, -EIO);
        	continue;
        }

        if (req->cmd_type != REQ_TYPE_FS)
        {
            __blk_end_request_all(req, 0);
            continue;
        }

        if (dev->panic_count >= PROBE_COUNT_TIMEOUT)
        {
        	__blk_end_request_all(req, -EIO);
        	continue;
        }

        if (rq_data_dir(req) != READ)
        {
        	__blk_end_request_all(req, -EACCES);
        	continue;
        }

		list_add_tail(&req->queuelist, &dev->request_queue_send);
		spin_unlock_irq(q->queue_lock);
		wake_up(&dev->process_queue_send);
		spin_lock_irq(q->queue_lock);
    }
}

void dnbd3_blk_fail_all_requests(dnbd3_device_t *dev)
{
	struct request *blk_request, *tmp_request;
	struct request *blk_request2, *tmp_request2;
	unsigned long flags;
	struct list_head local_copy;
	int dup;
	INIT_LIST_HEAD(&local_copy);
	spin_lock_irq(&dev->blk_lock);
	while (!list_empty(&dev->request_queue_receive))
	{
		list_for_each_entry_safe(blk_request, tmp_request, &dev->request_queue_receive, queuelist)
		{
			list_del_init(&blk_request->queuelist);
			dup = 0;
			list_for_each_entry_safe(blk_request2, tmp_request2, &local_copy, queuelist)
			{
				if (blk_request == blk_request2)
				{
					printk("WARNING: Request is in both lists!\n");
					dup = 1;
					break;
				}
			}
			if (!dup) list_add(&blk_request->queuelist, &local_copy);
		}
	}
	while (!list_empty(&dev->request_queue_send))
	{
		list_for_each_entry_safe(blk_request, tmp_request, &dev->request_queue_send, queuelist)
		{
			list_del_init(&blk_request->queuelist);
			dup = 0;
			list_for_each_entry_safe(blk_request2, tmp_request2, &local_copy, queuelist)
			{
				if (blk_request == blk_request2)
				{
					printk("WARNING: Request is in both lists!\n");
					dup = 1;
					break;
				}
			}
			if (!dup) list_add(&blk_request->queuelist, &local_copy);
		}
	}
	spin_unlock_irq(&dev->blk_lock);
	list_for_each_entry_safe(blk_request, tmp_request, &local_copy, queuelist)
	{
		list_del_init(&blk_request->queuelist);
		if (blk_request->cmd_type == REQ_TYPE_FS)
		{
			spin_lock_irqsave(&dev->blk_lock, flags);
			__blk_end_request_all(blk_request, -EIO);
			spin_unlock_irqrestore(&dev->blk_lock, flags);
		}
		else if (blk_request->cmd_type == REQ_TYPE_SPECIAL)
		{
			kfree(blk_request);
		}
	}
}
