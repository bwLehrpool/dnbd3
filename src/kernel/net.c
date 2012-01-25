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

#include "net.h"
#include "utils.h"

void dnbd3_net_connect(struct dnbd3_device *lo)
{
	struct sockaddr_in sin;
	struct msghdr msg;
	struct kvec iov;
	struct dnbd3_request dnbd3_request;
	struct dnbd3_reply dnbd3_reply;
	struct task_struct *thread_send;
	struct task_struct *thread_receive;

	if (!lo->host || !lo->port || !lo->image_id)
	{
		printk("ERROR: Host or port not set.");
		return;
	}

	// initialize socket
	if (sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &lo->sock) < 0)
	{
		printk("ERROR: dnbd3 couldn't create socket.\n");
		return;
	}
	lo->sock->sk->sk_allocation = GFP_NOIO;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(lo->host);
	sin.sin_port = htons(simple_strtol(lo->port, NULL, 10));
	if (kernel_connect(lo->sock, (struct sockaddr *) &sin, sizeof(sin), 0) < 0)
	{
		printk("ERROR: dnbd3 couldn't connect to given host.\n");
		return;
	}

	// prepare message and send request
	dnbd3_request.cmd = CMD_GET_SIZE;
	strcpy(dnbd3_request.image_id, lo->image_id);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL; // No SIGPIPE

	iov.iov_base = &dnbd3_request;
	iov.iov_len = sizeof(dnbd3_request);
	kernel_sendmsg(lo->sock, &msg, &iov, 1, sizeof(dnbd3_request));

	// receive replay
	iov.iov_base = &dnbd3_reply;
	iov.iov_len = sizeof(dnbd3_reply);
	kernel_recvmsg(lo->sock, &msg, &iov, 1, sizeof(dnbd3_reply), msg.msg_flags);

	// set filesize
	if (dnbd3_reply.filesize <= 0)
	{
		printk("ERROR: File size returned by server is < 0.\n");
		return;
	}

	printk("INFO: dnbd3 filesize: %llu\n", dnbd3_reply.filesize);
	set_capacity(lo->disk, dnbd3_reply.filesize >> 9); /* 512 Byte blocks */

	// start sending thread
	thread_send = kthread_create(dnbd3_net_send, lo, lo->disk->disk_name);
	wake_up_process(thread_send);

	// start receiving thread
	thread_receive = kthread_create(dnbd3_net_receive, lo, lo->disk->disk_name);
	wake_up_process(thread_receive);
}

int dnbd3_net_send(void *data)
{
	struct dnbd3_device *lo = data;
	struct dnbd3_request dnbd3_request;
	struct request *blk_request;
	struct msghdr msg;
	struct kvec iov;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL; // No SIGPIPE

	set_user_nice(current, -20);

	while (!kthread_should_stop() || !list_empty(&lo->request_queue_send))
	{
		wait_event_interruptible(lo->process_queue_send,
				kthread_should_stop() || !list_empty(&lo->request_queue_send));

		if (list_empty(&lo->request_queue_send))
			continue;

		// extract block request
		spin_lock_irq(&lo->blk_lock);
		blk_request = list_entry(lo->request_queue_send.next, struct request, queuelist);
		list_del_init(&blk_request->queuelist);
		spin_unlock_irq(&lo->blk_lock);

		// prepare net request
		dnbd3_request.cmd = CMD_GET_BLOCK;
		dnbd3_request.offset = blk_rq_pos(blk_request) << 9; // *512
		dnbd3_request.size = blk_rq_bytes(blk_request); // blk_rq_bytes() Returns bytes left to complete in the entire request
		memcpy(dnbd3_request.handle, &blk_request, sizeof(blk_request));
		iov.iov_base = &dnbd3_request;
		iov.iov_len = sizeof(dnbd3_request);

		// send net request
		if (kernel_sendmsg(lo->sock, &msg, &iov, 1, sizeof(dnbd3_request)) <= 0)
			printk("ERROR: kernel_sendmsg\n");

		spin_lock_irq(&lo->blk_lock);
		list_add_tail(&blk_request->queuelist, &lo->request_queue_receive);
		spin_unlock_irq(&lo->blk_lock);
		wake_up(&lo->process_queue_receive);
	}
	return 0;
}

int dnbd3_net_receive(void *data)
{
	struct dnbd3_device *lo = data;
	struct dnbd3_reply dnbd3_reply;
	struct request *blk_request;
	struct msghdr msg;
	struct kvec iov;
	struct req_iterator iter;
	struct bio_vec *bvec;
	unsigned long flags;
	sigset_t blocked, oldset;
	struct request *tmp_request, *received_request;
	void *kaddr;
	unsigned int size;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL; // No SIGPIPE

	set_user_nice(current, -20);

	while (!kthread_should_stop() || !list_empty(&lo->request_queue_receive))
	{
		wait_event_interruptible(lo->process_queue_receive, kthread_should_stop() || !list_empty(&lo->request_queue_receive));

		// receive net replay
		iov.iov_base = &dnbd3_reply;
		iov.iov_len = sizeof(dnbd3_reply);
		kernel_recvmsg(lo->sock, &msg, &iov, 1, sizeof(dnbd3_reply),
				msg.msg_flags);

		// search for replied request in queue
		received_request = *(struct request **) dnbd3_reply.handle;
		spin_lock_irq(&lo->blk_lock);
		list_for_each_entry_safe(blk_request, tmp_request, &lo->request_queue_receive, queuelist)
		{
			if (blk_request != received_request)
				continue;

			list_del_init(&blk_request->queuelist);
			break;
		}
		spin_unlock_irq(&lo->blk_lock);

		// receive data and answer to block layer
		rq_for_each_segment(bvec, blk_request, iter)
			{
				siginitsetinv(&blocked, sigmask(SIGKILL));
				sigprocmask(SIG_SETMASK, &blocked, &oldset);

				kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
				size = bvec->bv_len;
				iov.iov_base = kaddr;
				iov.iov_len = size;
				kernel_recvmsg(lo->sock, &msg, &iov, 1, size, msg.msg_flags);
				kunmap(bvec->bv_page);

				sigprocmask(SIG_SETMASK, &oldset, NULL);
			}

		spin_lock_irqsave(&lo->blk_lock, flags);
		__blk_end_request_all(blk_request, 0);
		spin_unlock_irqrestore(&lo->blk_lock, flags);
	}

	return 0;
}
