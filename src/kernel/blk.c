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

struct block_device_operations dnbd3_blk_ops =
{ .owner = THIS_MODULE, .ioctl = dnbd3_blk_ioctl, };

int dnbd3_blk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
		unsigned long arg)
{
	switch (cmd)
	{
	case IOCTL_SET_HOST:
		_host = (char *) arg;
		break;

	case IOCTL_SET_PORT:
		_port = (char *) arg;
		break;

	case IOCTL_CONNECT:
		dnbd3_net_connect();
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

	if (!_sock)
		return;

	while ((req = blk_fetch_request(q)) != NULL)
	{
		if (req->cmd_type != REQ_TYPE_FS)
		{
			__blk_end_request_all(req, 0);
			continue;
		}

		if (rq_data_dir(req) == READ)
		{
			list_add_tail(&req->queuelist, &_request_queue_send);
			spin_unlock_irq(q->queue_lock);
			wake_up(&_process_queue_send);
			spin_lock_irq(q->queue_lock);
		}
	}
}
