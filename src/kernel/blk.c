// SPDX-License-Identifier: GPL-2.0
/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
 *
 * This file may be licensed under the terms of the
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
#include "dnbd3_main.h"

#include <linux/pagemap.h>

static int dnbd3_close_device(dnbd3_device_t *dev)
{
	int result;
	unsigned int mf;

	if (dev->imgname)
		dev_info(dnbd3_device_to_dev(dev), "closing down device.\n");

	dev->panic = false;
	result = dnbd3_net_disconnect(dev);
	kfree(dev->imgname);
	dev->imgname = NULL;

	/* new requests might have been queued up, */
	/* but now that imgname is NULL no new ones can show up */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
	blk_mq_freeze_queue(dev->queue);
	set_capacity(dev->disk, 0);
	blk_mq_unfreeze_queue(dev->queue);
#else
	mf = blk_mq_freeze_queue(dev->queue);
	set_capacity(dev->disk, 0);
	blk_mq_unfreeze_queue(dev->queue, mf);
#endif
	return result;
}

static int dnbd3_blk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	int result = -100;
	dnbd3_device_t *dev = bdev->bd_disk->private_data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
	struct request_queue *blk_queue = dev->disk->queue;
#endif
	char *imgname = NULL;
	dnbd3_ioctl_t *msg = NULL;
	int i = 0, j;
	u8 locked = 0;

	if (arg != 0) {
		msg = kmalloc(sizeof(*msg), GFP_KERNEL);
		if (msg == NULL)
			return -ENOMEM;
		if (copy_from_user((char *)msg, (char *)arg, 2) != 0 || msg->len != sizeof(*msg)) {
			result = -ENOEXEC;
			goto cleanup_return;
		}
		if (copy_from_user((char *)msg, (char *)arg, sizeof(*msg)) != 0) {
			result = -ENOENT;
			goto cleanup_return;
		}
		if (msg->imgname != NULL && msg->imgnamelen > 0) {
			imgname = kmalloc(msg->imgnamelen + 1, GFP_KERNEL);
			if (imgname == NULL) {
				result = -ENOMEM;
				goto cleanup_return;
			}
			if (copy_from_user(imgname, msg->imgname, msg->imgnamelen) != 0) {
				result = -ENOENT;
				goto cleanup_return;
			}
			imgname[msg->imgnamelen] = '\0';
		}
	}

	switch (cmd) {
	case IOCTL_OPEN:
		if (!dnbd3_flag_get(dev->connection_lock)) {
			result = -EBUSY;
			break;
		}
		locked = 1;
		if (dev->imgname != NULL) {
			result = -EBUSY;
		} else if (imgname == NULL) {
			result = -EINVAL;
		} else if (msg == NULL) {
			result = -EINVAL;
		} else {
			/* assert that at least one and not to many hosts are given */
			if (msg->hosts_num < 1 || msg->hosts_num > NUMBER_SERVERS) {
				result = -EINVAL;
				break;
			}

			dev->imgname = imgname;
			dev->rid = msg->rid;
			dev->use_server_provided_alts = msg->use_server_provided_alts;

			dev_info(dnbd3_device_to_dev(dev), "opening device.\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0) \
				|| RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 6))
			/* nothing to do here, set at creation time */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
			// set optimal request size for the queue to half the read-ahead
			blk_queue_io_opt(dev->queue, (msg->read_ahead_kb * 512));
# if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) \
				&& !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
			// set readahead from optimal request size of the queue
			// ra_pages are calculated by following formula: queue_io_opt() * 2 / PAGE_SIZE
			blk_queue_update_readahead(dev->queue);
# endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
			if (blk_queue->backing_dev_info != NULL)
				blk_queue->backing_dev_info->ra_pages = (msg->read_ahead_kb * 1024) / PAGE_SIZE;
#else
			blk_queue->backing_dev_info.ra_pages = (msg->read_ahead_kb * 1024) / PAGE_SIZE;
#endif

			/* add specified servers to alt server list */
			for (i = 0; i < NUMBER_SERVERS; i++)
				dev->alt_servers[i].host.ss_family = 0;
			for (i = 0; i < msg->hosts_num; i++) {
				/* copy provided host into corresponding alt server slot */
				if (dnbd3_add_server(dev, &msg->hosts[i]) == 0)
					dev_dbg(dnbd3_device_to_dev(dev), "adding server %pISpc\n",
						&dev->alt_servers[i].host);
				else
					dev_warn(dnbd3_device_to_dev(dev), "could not add server %pISpc\n",
						&dev->alt_servers[i].host);
			}

			/*
			 * probe added alt servers in specified order and
			 * choose first working server as initial server
			 */
			result = -EPROTONOSUPPORT;
			for (i = 0; i < NUMBER_SERVERS; i++) {
				/* probe added alt server */
				if (dev->alt_servers[i].host.ss_family == 0)
					continue; // Empty slot

				result = dnbd3_new_connection(dev, &dev->alt_servers[i].host, true);
				if (result == 0) {
					/* connection established, store index of server and exit loop */
					result = i;
					break;
				}
			}

			if (result >= 0) {
				/* connection was successful */
				dev_dbg(dnbd3_device_to_dev(dev), "server %pISpc is initial server\n",
					&dev->cur_server.host);
				imgname = NULL; // Prevent kfree at the end
			} else {
				/* probing failed */
				dev->imgname = NULL;
			}
		}
		break;

	case IOCTL_CLOSE:
		if (!dnbd3_flag_get(dev->connection_lock)) {
			result = -EBUSY;
			break;
		}
		locked = 1;
		result = dnbd3_close_device(dev);
		break;

	case IOCTL_SWITCH:
		if (!dnbd3_flag_get(dev->connection_lock)) {
			result = -EBUSY;
			break;
		}
		locked = 1;
		if (dev->imgname == NULL) {
			result = -ENOTCONN;
		} else if (msg == NULL) {
			result = -EINVAL;
		} else {
			dnbd3_alt_server_t *alt_server;
			struct sockaddr_storage new_addr;

			mutex_lock(&dev->alt_servers_lock);
			alt_server = get_existing_alt_from_host(&msg->hosts[0], dev);
			if (alt_server == NULL) {
				mutex_unlock(&dev->alt_servers_lock);
				/* specified server is not known, so do not switch */
				result = -ENOENT;
			} else {
				/* specified server is known, so try to switch to it */
				new_addr = alt_server->host;
				mutex_unlock(&dev->alt_servers_lock);
				if (is_same_server(&dev->cur_server.host, &new_addr)) {
					/* specified server is current server, so do not switch */
					result = 0;
				} else {
					dev_info(dnbd3_device_to_dev(dev), "manual server switch to %pISpc\n",
						 &new_addr);
					result = dnbd3_new_connection(dev, &new_addr, false);
					if (result != 0) {
						/* switching didn't work */
						result = -EAGAIN;
					}
				}
				if (result == 0) {
					/* fake RTT so we don't switch away again soon */
					mutex_lock(&dev->alt_servers_lock);
					for (i = 0; i < NUMBER_SERVERS; ++i) {
						alt_server = &dev->alt_servers[i];
						if (is_same_server(&alt_server->host, &new_addr)) {
							for (j = 0; j < DISCOVER_HISTORY_SIZE; ++j)
								alt_server->rtts[j] = 1;
							alt_server->best_count = 100;
						} else {
							for (j = 0; j < DISCOVER_HISTORY_SIZE; ++j)
								if (alt_server->rtts[j] < 500000)
									alt_server->rtts[j] = 500000;
							alt_server->best_count = 0;
						}
					}
					mutex_unlock(&dev->alt_servers_lock);
				}
			}
		}
		break;

	case IOCTL_ADD_SRV:
	case IOCTL_REM_SRV: {
		struct sockaddr_storage addr;
		dnbd3_host_t *host;

		if (dev->imgname == NULL) {
			result = -ENOTCONN;
			break;
		}
		if (msg == NULL) {
			result = -EINVAL;
			break;
		}
		host = &msg->hosts[0];
		if (!dnbd3_host_to_sockaddr(host, &addr)) {
			result = -EINVAL;
			break;
		}

		if (cmd == IOCTL_ADD_SRV) {
			result = dnbd3_add_server(dev, host);
			if (result == -EEXIST)
				dev_info(dnbd3_device_to_dev(dev), "alt server %pISpc already exists\n", &addr);
			else if (result == -ENOSPC)
				dev_info(dnbd3_device_to_dev(dev), "cannot add %pISpc; no free slot\n", &addr);
			else
				dev_info(dnbd3_device_to_dev(dev), "added alt server %pISpc\n", &addr);
		} else { // IOCTL_REM_SRV
			result = dnbd3_rem_server(dev, host);
			if (result == -ENOENT)
				dev_info(dnbd3_device_to_dev(dev), "alt server %pISpc not found\n", &addr);
			else
				dev_info(dnbd3_device_to_dev(dev), "removed alt server %pISpc\n", &addr);
		}
		break;
	}
	case BLKFLSBUF:
		result = 0;
		break;

	default:
		result = -EIO;
		break;
	}

cleanup_return:
	kfree(msg);
	kfree(imgname);
	if (locked)
		dnbd3_flag_reset(dev->connection_lock);
	return result;
}

static const struct block_device_operations dnbd3_blk_ops = {
	.owner = THIS_MODULE,
	.ioctl = dnbd3_blk_ioctl,
};

static void dnbd3_add_queue(dnbd3_device_t *dev, struct request *rq)
{
	unsigned long irqflags;

	spin_lock_irqsave(&dev->send_queue_lock, irqflags);
	list_add_tail(&rq->queuelist, &dev->send_queue);
	spin_unlock_irqrestore(&dev->send_queue_lock, irqflags);
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	queue_work(dev->send_wq, &dev->send_work);
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
}

/*
 * Linux kernel blk-mq driver function (entry point) to handle block IO requests
 */
static blk_status_t dnbd3_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	dnbd3_device_t *dev = rq->q->queuedata;
	struct dnbd3_cmd *cmd;

	if (dev->imgname == NULL || !device_active(dev))
		return BLK_STS_IOERR;

	if (req_op(rq) != REQ_OP_READ)
		return BLK_STS_IOERR;

	if (PROBE_COUNT_TIMEOUT > 0 && dev->panic_count >= PROBE_COUNT_TIMEOUT)
		return BLK_STS_TIMEOUT;

	if (rq_data_dir(rq) != READ)
		return BLK_STS_NOTSUPP;

	cmd = blk_mq_rq_to_pdu(rq);
	cmd->handle = (u64)blk_mq_unique_tag(rq) | (((u64)jiffies) << 32);
	blk_mq_start_request(rq);
	dnbd3_add_queue(dev, rq);
	return BLK_STS_OK;
}

static enum blk_eh_timer_return dnbd3_rq_timeout(struct request *req
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0) \
	&& !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
		, bool reserved
#endif
		)
{
	unsigned long irqflags;
	struct request *rq_iter;
	bool found = false;
	dnbd3_device_t *dev = req->q->queuedata;

	spin_lock_irqsave(&dev->send_queue_lock, irqflags);
	list_for_each_entry(rq_iter, &dev->send_queue, queuelist) {
		if (rq_iter == req) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&dev->send_queue_lock, irqflags);
	// If still in send queue, do nothing
	if (found)
		return BLK_EH_RESET_TIMER;

	spin_lock_irqsave(&dev->recv_queue_lock, irqflags);
	list_for_each_entry(rq_iter, &dev->recv_queue, queuelist) {
		if (rq_iter == req) {
			found = true;
			list_del_init(&req->queuelist);
			break;
		}
	}
	spin_unlock_irqrestore(&dev->recv_queue_lock, irqflags);
	if (!found) {
		dev_err(dnbd3_device_to_dev(dev), "timeout request neither found in send nor recv queue, ignoring\n");
		// Assume it was fnished concurrently
		return BLK_EH_DONE;
	}
	// Add to send queue again and trigger work, reset timeout
	dnbd3_add_queue(dev, req);
	return BLK_EH_RESET_TIMER;
}

static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
const
#endif
struct blk_mq_ops dnbd3_mq_ops = {
	.queue_rq = dnbd3_queue_rq,
	.timeout  = dnbd3_rq_timeout,
};

#define ONE_MEG (1048576)
int dnbd3_blk_add_device(dnbd3_device_t *dev, int minor)
{
	int ret;

	memset(dev, 0, sizeof(*dev));
	dev->index = minor;
	// lock for imgname, cur_server etc.
	spin_lock_init(&dev->blk_lock);
	spin_lock_init(&dev->send_queue_lock);
	spin_lock_init(&dev->recv_queue_lock);
	INIT_LIST_HEAD(&dev->send_queue);
	INIT_LIST_HEAD(&dev->recv_queue);
	dnbd3_flag_reset(dev->connection_lock);
	dnbd3_flag_reset(dev->discover_running);
	mutex_init(&dev->alt_servers_lock);
	dnbd3_net_work_init(dev);

	// memset has done this already but I like initial values to be explicit
	dev->imgname = NULL;
	dev->rid = 0;
	dev->update_available = false;
	dev->panic = false;
	dev->panic_count = 0;
	dev->reported_size = 0;

	// set up tag_set for blk-mq
	dev->tag_set.ops = &dnbd3_mq_ops;
	dev->tag_set.nr_hw_queues = 1;
	dev->tag_set.queue_depth = 128;
	dev->tag_set.numa_node = NUMA_NO_NODE;
	dev->tag_set.cmd_size = sizeof(struct dnbd3_cmd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
	dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
#endif
	dev->tag_set.driver_data = dev;
	dev->tag_set.timeout = BLOCK_LAYER_TIMEOUT * HZ;

	ret = blk_mq_alloc_tag_set(&dev->tag_set);
	if (ret) {
		dev_err(dnbd3_device_to_dev(dev), "blk_mq_alloc_tag_set failed\n");
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	// set up blk-mq and disk
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0) \
		|| RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 6))
	do {
		struct queue_limits lim = {
			.logical_block_size = DNBD3_BLOCK_SIZE, // in bytes
			.physical_block_size = DNBD3_BLOCK_SIZE, // in bytes
			.io_opt = ONE_MEG >> 2, // 256kb
			.max_hw_sectors = ONE_MEG >> SECTOR_SHIFT, // in 512byte sectors
			.max_segments		= USHRT_MAX,
			.max_segment_size	= UINT_MAX,
		};
		dev->disk = blk_mq_alloc_disk(&dev->tag_set, &lim, dev);
	} while (0);
# else
	dev->disk = blk_mq_alloc_disk(&dev->tag_set, dev);
# endif
	if (IS_ERR(dev->disk)) {
		dev_err(dnbd3_device_to_dev(dev), "blk_mq_alloc_disk failed\n");
		ret = PTR_ERR(dev->disk);
		goto out_cleanup_tags;
	}
	dev->queue = dev->disk->queue;
#else
	// set up blk-mq
	dev->queue = blk_mq_init_queue(&dev->tag_set);
	if (IS_ERR(dev->queue)) {
		ret = PTR_ERR(dev->queue);
		dev_err(dnbd3_device_to_dev(dev), "blk_mq_init_queue failed\n");
		goto out_cleanup_tags;
	}
	dev->queue->queuedata = dev;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 11, 0) \
		&& !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 6))
	blk_queue_logical_block_size(dev->queue, DNBD3_BLOCK_SIZE);
	blk_queue_physical_block_size(dev->queue, DNBD3_BLOCK_SIZE);
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	blk_queue_flag_set(QUEUE_FLAG_NONROT, dev->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, dev->queue);
# else
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, dev->queue);
# endif
	blk_queue_max_segment_size(dev->queue, ONE_MEG);
	blk_queue_max_segments(dev->queue, 0xffff);
	blk_queue_max_hw_sectors(dev->queue, ONE_MEG / DNBD3_BLOCK_SIZE);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
	// set up disk
	dev->disk = alloc_disk(1);
	if (!dev->disk) {
		dev_err(dnbd3_device_to_dev(dev), "alloc_disk failed\n");
		ret = -ENOMEM;
		goto out_cleanup_queue;
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 132)) \
		|| RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
	dev->disk->flags |= GENHD_FL_NO_PART;
#else
	dev->disk->flags |= GENHD_FL_NO_PART_SCAN;
#endif
	dev->disk->major = major;
	dev->disk->first_minor = minor;
	dev->disk->minors = 1;
	dev->disk->fops = &dnbd3_blk_ops;
	dev->disk->private_data = dev;
	dev->disk->queue = dev->queue;
	sprintf(dev->disk->disk_name, "dnbd%d", minor);
	set_capacity(dev->disk, 0);
	set_disk_ro(dev->disk, 1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) \
		|| RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
	ret = add_disk(dev->disk);
	if (ret != 0)
		goto out_cleanup_queue;
#else
	add_disk(dev->disk);
#endif

	// set up sysfs
	dnbd3_sysfs_init(dev);

	return 0;

out_cleanup_queue:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
	blk_cleanup_queue(dev->queue);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0) \
		&& !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
	blk_cleanup_disk(dev->disk);
#else
	put_disk(dev->disk);
#endif
out_cleanup_tags:
	blk_mq_free_tag_set(&dev->tag_set);
out:
	mutex_destroy(&dev->alt_servers_lock);
	return ret;
}
#undef ONE_MEG

int dnbd3_blk_del_device(dnbd3_device_t *dev)
{
	while (!dnbd3_flag_get(dev->connection_lock))
		schedule();
	dnbd3_close_device(dev);
	dnbd3_sysfs_exit(dev);
	del_gendisk(dev->disk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
	blk_cleanup_queue(dev->queue);
	put_disk(dev->disk);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0) \
		&& !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
	blk_cleanup_disk(dev->disk);
#else
	put_disk(dev->disk);
#endif
	blk_mq_free_tag_set(&dev->tag_set);
	mutex_destroy(&dev->alt_servers_lock);
	return 0;
}

void dnbd3_blk_requeue_all_requests(dnbd3_device_t *dev)
{
	struct request *blk_request;
	unsigned long flags;
	struct list_head local_copy;
	int count = 0;

	INIT_LIST_HEAD(&local_copy);
	spin_lock_irqsave(&dev->recv_queue_lock, flags);
	while (!list_empty(&dev->recv_queue)) {
		blk_request = list_entry(dev->recv_queue.next, struct request, queuelist);
		list_del_init(&blk_request->queuelist);
		list_add(&blk_request->queuelist, &local_copy);
		count++;
	}
	spin_unlock_irqrestore(&dev->recv_queue_lock, flags);
	if (count)
		dev_info(dnbd3_device_to_dev(dev), "re-queueing %d requests\n", count);
	while (!list_empty(&local_copy)) {
		blk_request = list_entry(local_copy.next, struct request, queuelist);
		list_del_init(&blk_request->queuelist);
		spin_lock_irqsave(&dev->send_queue_lock, flags);
		list_add_tail(&blk_request->queuelist, &dev->send_queue);
		spin_unlock_irqrestore(&dev->send_queue_lock, flags);
	}
	// Do this even if we didn't move anything from the recv list to the send
	// list. It might have already contained something, which needs to be
	// re-requested anyways if this was called because of a server switch.
	spin_lock_irqsave(&dev->blk_lock, flags);
	queue_work(dev->send_wq, &dev->send_work);
	spin_unlock_irqrestore(&dev->blk_lock, flags);
}

void dnbd3_blk_fail_all_requests(dnbd3_device_t *dev)
{
	struct request *blk_request;
	unsigned long flags;
	struct list_head local_copy;
	int count = 0;

	INIT_LIST_HEAD(&local_copy);
	spin_lock_irqsave(&dev->recv_queue_lock, flags);
	while (!list_empty(&dev->recv_queue)) {
		blk_request = list_entry(dev->recv_queue.next, struct request, queuelist);
		list_del_init(&blk_request->queuelist);
		list_add(&blk_request->queuelist, &local_copy);
		count++;
	}
	spin_unlock_irqrestore(&dev->recv_queue_lock, flags);
	spin_lock_irqsave(&dev->send_queue_lock, flags);
	while (!list_empty(&dev->send_queue)) {
		blk_request = list_entry(dev->send_queue.next, struct request, queuelist);
		list_del_init(&blk_request->queuelist);
		list_add(&blk_request->queuelist, &local_copy);
		count++;
	}
	spin_unlock_irqrestore(&dev->send_queue_lock, flags);
	if (count)
		dev_info(dnbd3_device_to_dev(dev), "failing %d requests\n", count);
	while (!list_empty(&local_copy)) {
		blk_request = list_entry(local_copy.next, struct request, queuelist);
		list_del_init(&blk_request->queuelist);
		blk_mq_end_request(blk_request, BLK_STS_IOERR);
	}
}
