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

void dnbd3_net_connect(dnbd3_device_t *lo)
{
    struct sockaddr_in sin;
    struct msghdr msg;
    struct kvec iov;
    dnbd3_request_t dnbd3_request;
    dnbd3_reply_t dnbd3_reply;

    if (!lo->host || !lo->port || !lo->image_id)
    {
        printk("ERROR: Host or port not set.");
        return;
    }

    // TODO: check if allready connected
    printk("INFO: Connecting device %s\n", lo->disk->disk_name);

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
        printk("ERROR: dnbd3 couldn't connect to host %s:%s\n", lo->host, lo->port);
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
    lo->thread_send = kthread_create(dnbd3_net_send, lo, lo->disk->disk_name);
    wake_up_process(lo->thread_send);

    // start receiving thread
    lo->thread_receive = kthread_create(dnbd3_net_receive, lo, lo->disk->disk_name);
    wake_up_process(lo->thread_receive);

    // Add heartbeat timer
    init_timer(&lo->hb_timer);
    lo->hb_timer.data = (unsigned long) lo;
    lo->hb_timer.function = dnbd3_net_heartbeat;
    lo->hb_timer.expires = jiffies + HB_INTERVAL;
    add_timer(&lo->hb_timer);
}

void dnbd3_net_disconnect(dnbd3_device_t *lo)
{
    struct request *blk_request, *tmp_request;
    printk("INFO: Disconnecting device %s\n", lo->disk->disk_name);

    // kill sending and receiving threads
    kthread_stop(lo->thread_send);
    kthread_stop(lo->thread_receive);

    // clear sock
    if (lo->sock)
    {
        sock_release(lo->sock);
        lo->sock = NULL;
    }
    // clear heartbeat timer
    if (&lo->hb_timer)
        del_timer(&lo->hb_timer);

    // move already send requests to request_queue_send
    if (!list_empty(&lo->request_queue_receive))
    {
        printk("WARN: Request queue was not empty on %s\n", lo->disk->disk_name);
        spin_lock_irq(&lo->blk_lock);
        list_for_each_entry_safe(blk_request, tmp_request, &lo->request_queue_receive, queuelist)
        {
            list_del_init(&blk_request->queuelist);
            list_add_tail(&blk_request->queuelist, &lo->request_queue_send);
        }
        spin_unlock_irq(&lo->blk_lock);
    }
}

int dnbd3_net_send(void *data)
{
    dnbd3_device_t *lo = data;
    dnbd3_request_t dnbd3_request;
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

        switch (blk_request->cmd_type)
        {
        case REQ_TYPE_SPECIAL:
            dnbd3_request.cmd = CMD_PING;
            break;

        case REQ_TYPE_FS:
            dnbd3_request.cmd = CMD_GET_BLOCK;
            dnbd3_request.offset = blk_rq_pos(blk_request) << 9; // *512
            dnbd3_request.size = blk_rq_bytes(blk_request); // bytes left to complete entire request
            break;

        default:
            printk("ERROR: Unknown command\n");
            break;
        }

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
    dnbd3_device_t *lo = data;
    dnbd3_reply_t dnbd3_reply;
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
        wait_event_interruptible(lo->process_queue_receive,
                kthread_should_stop() || !list_empty(&lo->request_queue_receive));

        if (list_empty(&lo->request_queue_receive))
            continue;

        // receive net replay
        iov.iov_base = &dnbd3_reply;
        iov.iov_len = sizeof(dnbd3_reply);
        kernel_recvmsg(lo->sock, &msg, &iov, 1, sizeof(dnbd3_reply), msg.msg_flags);

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

        switch (dnbd3_reply.cmd)
        {
        case CMD_PING:
            // TODO: use for rtt?
            break;

        case CMD_GET_BLOCK:
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
            break;

        default:
            printk("ERROR: Unknown command\n");
            break;
        }

    }
    return 0;
}

void dnbd3_net_heartbeat(unsigned long arg)
{
    dnbd3_device_t *lo = (dnbd3_device_t *) arg;
    list_add(&lo->hb_request.queuelist, &lo->request_queue_send);
    wake_up(&lo->process_queue_send);
    lo->hb_timer.expires = jiffies + HB_INTERVAL;
    add_timer(&lo->hb_timer);
}
