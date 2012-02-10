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

int dnbd3_blk_add_device(dnbd3_device_t *dev, int minor)
{
    struct gendisk *disk;
    struct request_queue *blk_queue;

    init_waitqueue_head(&dev->process_queue_send);
    init_waitqueue_head(&dev->process_queue_receive);
    INIT_LIST_HEAD(&dev->request_queue_send);
    INIT_LIST_HEAD(&dev->request_queue_receive);

    dev->vid = 0;
    dev->rid = 0;
    dev->sock = NULL;
    dev->num_servers = 0;
    dev->thread_send = NULL;
    dev->thread_receive = NULL;

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

int dnbd3_blk_del_device(dnbd3_device_t *dev)
{
    if (dev->sock)
    {
        sock_release(dev->sock);
        dev->sock = NULL;
    }

    if (&dev->hb_timer)
        del_timer(&dev->hb_timer);

    del_gendisk(dev->disk);
    put_disk(dev->disk);
    blk_cleanup_queue(dev->disk->queue);
    return 0;
}

struct block_device_operations dnbd3_blk_ops =
{ .owner = THIS_MODULE, .ioctl = dnbd3_blk_ioctl, };

int dnbd3_blk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
    dnbd3_device_t *dev = bdev->bd_disk->private_data;
    int minor = dev->disk->first_minor;

    dnbd3_ioctl_t *msg = kmalloc(sizeof(dnbd3_ioctl_t), GFP_KERNEL);
    copy_from_user((char *)msg, (char *)arg, sizeof(*msg));

    switch (cmd)
    {
    case IOCTL_OPEN:
        strcpy(dev->host, msg->host);
        strcpy(dev->port, msg->port);
        dev->vid = msg->vid;
        dev->rid = msg->rid;
        dnbd3_net_connect(dev);
        break;

    case IOCTL_CLOSE:
        dnbd3_net_disconnect(dev);
        dnbd3_blk_del_device(dev);
        dnbd3_blk_add_device(dev, minor);
        break;

    case IOCTL_SWITCH:
        dnbd3_net_disconnect(dev);
        strcpy(dev->host, msg->host);
        dnbd3_net_connect(dev);
        break;

    case BLKFLSBUF:
        break;

    default:
        kfree(msg);
        return -1;

    }

    kfree(msg);
    return 0;
}

void dnbd3_blk_request(struct request_queue *q)
{
    struct request *req;
    dnbd3_device_t *dev;

    while ((req = blk_fetch_request(q)) != NULL)
    {
        dev = req->rq_disk->private_data;

        if (req->cmd_type != REQ_TYPE_FS)
        {
            __blk_end_request_all(req, 0);
            continue;
        }

        if (rq_data_dir(req) == READ)
        {
            list_add_tail(&req->queuelist, &dev->request_queue_send);
            spin_unlock_irq(q->queue_lock);
            wake_up(&dev->process_queue_send);
            spin_lock_irq(q->queue_lock);
        }
    }
}
