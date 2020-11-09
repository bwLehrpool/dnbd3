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

#include <dnbd3/config/client.h>
#include "blk.h"
#include "net.h"
#include "sysfs.h"

#include <linux/pagemap.h>

#define dnbd3_req_read(req) \
	req_op(req) == REQ_OP_READ
#define dnbd3_req_fs(req) \
	dnbd3_req_read(req) || req_op(req) == REQ_OP_WRITE
#define dnbd3_req_special(req) \
	blk_rq_is_private(req)

static int dnbd3_blk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	int result = -100;
	dnbd3_device_t *dev = bdev->bd_disk->private_data;
	struct request_queue *blk_queue = dev->disk->queue;
	char *imgname = NULL;
	dnbd3_ioctl_t *msg = NULL;
	unsigned long irqflags;
	int i = 0;

	while (dev->disconnecting) { /* do nothing */ }

	if (arg != 0)
	{
		msg = kmalloc(sizeof(*msg), GFP_KERNEL);
		if (msg == NULL) return -ENOMEM;
		if (copy_from_user((char *)msg, (char *)arg, 2) != 0 || msg->len != sizeof(*msg))
		{
			result = -ENOEXEC;
			goto cleanup_return;
		}
		if (copy_from_user((char *)msg, (char *)arg, sizeof(*msg)) != 0)
		{
			result = -ENOENT;
			goto cleanup_return;
		}
		if (msg->imgname != NULL && msg->imgnamelen > 0)
		{
			imgname = kmalloc(msg->imgnamelen + 1, GFP_KERNEL);
			if (imgname == NULL)
			{
				result = -ENOMEM;
				goto cleanup_return;
			}
			if (copy_from_user(imgname, msg->imgname, msg->imgnamelen) != 0)
			{
				result = -ENOENT;
				goto cleanup_return;
			}
			imgname[msg->imgnamelen] = '\0';
		}
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
		else if (msg == NULL)
		{
			result = -EINVAL;
		}
		else
		{
			if (sizeof(msg->hosts[0]) != sizeof(dev->cur_server.host))
				dev_warn(dnbd3_device_to_dev(dev), "odd size bug triggered in IOCTL\n");

			/* assert that at least one and not to many hosts are given */
			if (msg->hosts_num < 1 || msg->hosts_num > NUMBER_SERVERS) {
				result = -EINVAL;
				break;
			}

			dev->imgname = imgname;
			dev->rid = msg->rid;
			dev->use_server_provided_alts = msg->use_server_provided_alts;


			if (blk_queue->backing_dev_info != NULL) {
				blk_queue->backing_dev_info->ra_pages = (msg->read_ahead_kb * 1024) / PAGE_SIZE;
			}

			/* add specified servers to alt server list */
			for (i = 0; i < msg->hosts_num; i++) {
				/* copy provided host into corresponding alt server slot */
				memset(&dev->alt_servers[i], 0, sizeof(dev->alt_servers[i]));
				memcpy(&dev->alt_servers[i].host, &msg->hosts[i], sizeof(msg->hosts[i]));
				dev->alt_servers[i].failures = 0;

				if (dev->alt_servers[i].host.type == HOST_IP4)
					dev_dbg(dnbd3_device_to_dev(dev), "adding server %pI4\n",   dev->alt_servers[i].host.addr);
				else
					dev_dbg(dnbd3_device_to_dev(dev), "adding server [%pI6]\n", dev->alt_servers[i].host.addr);
			}

			/* probe added alt servers in specified order and choose first working server as initial server */
			for (i = 0; i < msg->hosts_num; i++) {
				/* probe added alt server */
				memcpy(&dev->cur_server, &dev->alt_servers[i], sizeof(dev->cur_server));

				if (dnbd3_net_connect(dev) != 0) {
					/* probing server failed, cleanup connection and proceed with next specified server */
					dnbd3_blk_fail_all_requests(dev);
					dnbd3_net_disconnect(dev);
					dnbd3_blk_fail_all_requests(dev);
					result = -ENOENT;
				} else {
					/* probing server succeeds, abort probing of other servers */
					result = 0;
					break;
				}
			}

			if (result == 0)
			{
				/* probing was successful */
				if (dev->cur_server.host.type == HOST_IP4)
					dev_dbg(dnbd3_device_to_dev(dev), "server %pI4 is initial server\n",   dev->cur_server.host.addr);
				else
					dev_dbg(dnbd3_device_to_dev(dev), "server [%pI6] is initial server\n", dev->cur_server.host.addr);

				imgname = NULL; // Prevent kfree at the end
			}
			else
			{
				/* probing failed */
				dev->imgname = NULL;
			}
		}
		break;

	case IOCTL_CLOSE:
		dnbd3_blk_fail_all_requests(dev);
		result = dnbd3_net_disconnect(dev);
		dnbd3_blk_fail_all_requests(dev);
		blk_mq_freeze_queue(dev->queue);
		set_capacity(dev->disk, 0);
		blk_mq_unfreeze_queue(dev->queue);
		if (dev->imgname)
		{
			kfree(dev->imgname);
			dev->imgname = NULL;
		}
		break;

	case IOCTL_SWITCH:
		result = -EINVAL;
		break;

	case IOCTL_ADD_SRV:
	case IOCTL_REM_SRV:
		if (dev->imgname == NULL)
		{
			result = -ENOENT;
		}
		else if (msg == NULL)
		{
			result = -EINVAL;
		}

		/* protect access to 'new_servers_num' and 'new_servers' */
		spin_lock_irqsave(&dev->blk_lock, irqflags);
		if (dev->new_servers_num >= NUMBER_SERVERS)
		{
			result = -EAGAIN;
		}
		else
		{
			/* add or remove specified server */
			memcpy(&dev->new_servers[dev->new_servers_num].host, &msg->hosts[0], sizeof(msg->hosts[0]));
			dev->new_servers[dev->new_servers_num].failures = (cmd == IOCTL_ADD_SRV ? 0 : 1); // 0 = ADD, 1 = REM
			++dev->new_servers_num;
			result = 0;
		}
		spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		break;

	case BLKFLSBUF:
		result = 0;
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

static const struct block_device_operations dnbd3_blk_ops = {
	.owner = THIS_MODULE,
	.ioctl = dnbd3_blk_ioctl,
};

static blk_status_t dnbd3_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	dnbd3_device_t *dev = rq->q->queuedata;
	unsigned long irqflags;

	blk_mq_start_request(rq);

	if (dev->imgname == NULL)
	{
		blk_mq_end_request(rq, BLK_STS_IOERR);
		goto out;
	}

	if (!(dnbd3_req_fs(rq)))
	{
		blk_mq_end_request(rq, BLK_STS_IOERR);
		goto out;
	}

	if (PROBE_COUNT_TIMEOUT > 0 && dev->panic_count >= PROBE_COUNT_TIMEOUT)
	{
		blk_mq_end_request(rq, BLK_STS_TIMEOUT);
		goto out;
	}

	if (!(dnbd3_req_read(rq)))
	{
		blk_mq_end_request(rq, BLK_STS_NOTSUPP);
		goto out;
	}

	spin_lock_irqsave(&dev->blk_lock, irqflags);
	list_add_tail(&rq->queuelist, &dev->request_queue_send);
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
	wake_up(&dev->process_queue_send);

out:
	return BLK_STS_OK;
}

static const struct blk_mq_ops dnbd3_mq_ops = {
	.queue_rq = dnbd3_queue_rq,
};

int dnbd3_blk_add_device(dnbd3_device_t *dev, int minor)
{
	int ret;

	init_waitqueue_head(&dev->process_queue_send);
	init_waitqueue_head(&dev->process_queue_discover);
	INIT_LIST_HEAD(&dev->request_queue_send);
	INIT_LIST_HEAD(&dev->request_queue_receive);

	memset(&dev->cur_server, 0, sizeof(dev->cur_server));
	dev->better_sock = NULL;

	dev->imgname = NULL;
	dev->rid = 0;
	dev->update_available = 0;
	memset(dev->alt_servers, 0, sizeof(dev->alt_servers[0])*NUMBER_SERVERS);
	dev->thread_send = NULL;
	dev->thread_receive = NULL;
	dev->thread_discover = NULL;
	dev->discover = 0;
	dev->disconnecting = 0;
	dev->panic = 0;
	dev->panic_count = 0;
	dev->reported_size = 0;

	// set up spin lock for request queues for send and receive
	spin_lock_init(&dev->blk_lock);

	// set up tag_set for blk-mq
	dev->tag_set.ops = &dnbd3_mq_ops;
	dev->tag_set.nr_hw_queues = 1;
	dev->tag_set.queue_depth = 128;
	dev->tag_set.numa_node = NUMA_NO_NODE;
	dev->tag_set.cmd_size = 0;
	dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	dev->tag_set.driver_data = dev;

	ret = blk_mq_alloc_tag_set(&dev->tag_set);
	if (ret)
	{
		dev_err(dnbd3_device_to_dev(dev), "blk_mq_alloc_tag_set failed\n");
		goto out;
	}

	// set up blk-mq
	dev->queue = blk_mq_init_queue(&dev->tag_set);
	if (IS_ERR(dev->queue)) {
		ret = PTR_ERR(dev->queue);
		dev_err(dnbd3_device_to_dev(dev), "blk_mq_init_queue failed\n");
		goto out_cleanup_tags;
	}
	dev->queue->queuedata = dev;

	blk_queue_logical_block_size(dev->queue, DNBD3_BLOCK_SIZE);
	blk_queue_physical_block_size(dev->queue, DNBD3_BLOCK_SIZE);
	blk_queue_flag_set(QUEUE_FLAG_NONROT, dev->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, dev->queue);
#define ONE_MEG (1048576)
	blk_queue_max_segment_size(dev->queue, ONE_MEG);
	blk_queue_max_segments(dev->queue, 0xffff);
	blk_queue_max_hw_sectors(dev->queue, ONE_MEG / DNBD3_BLOCK_SIZE);
	dev->queue->limits.max_sectors = 256;
#undef ONE_MEG

	// set up disk
	if (!(dev->disk = alloc_disk(1)))
	{
		dev_err(dnbd3_device_to_dev(dev), "alloc_disk failed\n");
		ret = -ENOMEM;
		goto out_cleanup_queue;
	}

	dev->disk->flags |= GENHD_FL_NO_PART_SCAN;
	dev->disk->major = major;
	dev->disk->first_minor = minor;
	dev->disk->fops = &dnbd3_blk_ops;
	dev->disk->private_data = dev;
	dev->disk->queue = dev->queue;
	sprintf(dev->disk->disk_name, "dnbd%d", minor);
	set_capacity(dev->disk, 0);
	set_disk_ro(dev->disk, 1);
	add_disk(dev->disk);

	// set up sysfs
	dnbd3_sysfs_init(dev);

	return 0;

out_cleanup_queue:
	blk_cleanup_queue(dev->queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&dev->tag_set);
out:
	return ret;
}

int dnbd3_blk_del_device(dnbd3_device_t *dev)
{
	dnbd3_sysfs_exit(dev);
	dnbd3_net_disconnect(dev);
	del_gendisk(dev->disk);
	blk_cleanup_queue(dev->queue);
	blk_mq_free_tag_set(&dev->tag_set);
	put_disk(dev->disk);
	return 0;
}

void dnbd3_blk_fail_all_requests(dnbd3_device_t *dev)
{
	struct request *blk_request, *tmp_request;
	struct request *blk_request2, *tmp_request2;
	unsigned long flags;
	struct list_head local_copy;
	int dup;
	INIT_LIST_HEAD(&local_copy);
	spin_lock_irqsave(&dev->blk_lock, flags);
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
					dev_warn(dnbd3_device_to_dev(dev), "request is in both lists\n");
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
					dev_warn(dnbd3_device_to_dev(dev), "request is in both lists\n");
					dup = 1;
					break;
				}
			}
			if (!dup) list_add(&blk_request->queuelist, &local_copy);
		}
	}
	spin_unlock_irqrestore(&dev->blk_lock, flags);
	list_for_each_entry_safe(blk_request, tmp_request, &local_copy, queuelist)
	{
		list_del_init(&blk_request->queuelist);
		if (dnbd3_req_fs(blk_request))
		{
			spin_lock_irqsave(&dev->blk_lock, flags);
			blk_mq_end_request(blk_request, BLK_STS_IOERR);
			spin_unlock_irqrestore(&dev->blk_lock, flags);
		}
		else if (dnbd3_req_special(blk_request))
		{
			kfree(blk_request);
		}
	}
}
