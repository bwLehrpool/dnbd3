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
#include "blk.h"
#include "utils.h"
#include "serialize.h"

#include <linux/time.h>

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

static inline int is_same_server(const dnbd3_server_t * const a, const dnbd3_server_t * const b)
{
	return (a->hostaddrtype == b->hostaddrtype)
		&& (a->port == b->port)
		&& (0 == memcmp(a->hostaddr, b->hostaddr, (a->hostaddrtype == AF_INET ? 4 : 16)));
}

int dnbd3_net_connect(dnbd3_device_t *dev)
{
    struct sockaddr_in sin;
    struct request *req1 = NULL;

    struct timeval timeout;

    timeout.tv_sec = SOCKET_TIMEOUT_CLIENT_DATA;
    timeout.tv_usec = 0;

    // do some checks before connecting
    if (is_same_server(&dev->cur_server, &dev->initial_server))
    {
    	req1 = kmalloc(sizeof(*req1), GFP_ATOMIC);
		if (!req1)
		{
			printk("FATAL: Kmalloc(1) failed.\n");
			goto error;
		}
    }
    if (dev->cur_server.port == 0 || dev->cur_server.hostaddrtype == 0 || dev->imgname == NULL)
    {
        printk("FATAL: Host, port or image name not set.\n");
        goto error;
    }
    if (dev->sock)
    {
    	if (dev->cur_server.hostaddrtype == AF_INET)
    		printk("ERROR: Device %s is already connected to %pI4 : %d.\n", dev->disk->disk_name, dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port));
    	else
    		printk("ERROR: Device %s is already connected to %pI6 : %d.\n", dev->disk->disk_name, dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port));
        goto error;
    }

    if (dev->cur_server.hostaddrtype == AF_INET)
    	printk("INFO: Connecting device %s to %pI4 : %d\n", dev->disk->disk_name, dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port));
    else
    {
    	printk("ERROR: Cannot connect to %pI6 - IPv6 not yet implemented.\n", dev->cur_server.hostaddr);
    	//printk("INFO: Connecting device %s to %pI6 : %d\n", dev->disk->disk_name, dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port));
    	goto error;
    }

    if (dev->better_sock == NULL)
    { //  no established connection yet from discovery thread, start new one
        dnbd3_request_t dnbd3_request;
        dnbd3_reply_t dnbd3_reply;
        struct msghdr msg;
        struct kvec iov[2];
        uint16_t rid;
        char *name;
        init_msghdr(msg);
		if (sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &dev->sock) < 0)
		{
			printk("ERROR: Couldn't create socket.\n");
			goto error;
		}
		kernel_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
		kernel_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
		dev->sock->sk->sk_allocation = GFP_NOIO;
		sin.sin_family = AF_INET;
		memcpy(&(sin.sin_addr.s_addr), dev->cur_server.hostaddr, 4);
		sin.sin_port = dev->cur_server.port;
		if (kernel_connect(dev->sock, (struct sockaddr *) &sin, sizeof(sin), 0) != 0)
		{
			printk("ERROR: Couldn't connect to host %pI4 : %d\n", dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port));
			goto error;
		}
        // Request filesize
		dnbd3_request.magic = dnbd3_packet_magic;
        dnbd3_request.cmd = CMD_GET_SIZE;
        dnbd3_request.size = strlen(dev->imgname) + 1 + 2 + 2; // str+\0, version, rid
        fixup_request(dnbd3_request);
        iov[0].iov_base = &dnbd3_request;
        iov[0].iov_len = sizeof(dnbd3_request);
        serializer_reset_write(&dev->payload_buffer);
        serializer_put_uint16(&dev->payload_buffer, PROTOCOL_VERSION);
        serializer_put_string(&dev->payload_buffer, dev->imgname);
        serializer_put_uint16(&dev->payload_buffer, dev->rid);
        iov[1].iov_base = &dev->payload_buffer;
        iov[1].iov_len = serializer_get_written_length(&dev->payload_buffer);
        if (kernel_sendmsg(dev->sock, &msg, iov, 2, sizeof(dnbd3_request) + iov[1].iov_len) != sizeof(dnbd3_request) + iov[1].iov_len)
        {
        	printk("ERROR: Couldn't send CMD_SIZE_REQUEST to %pI4 : %d\n", dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port));
            goto error;
        }
        // receive reply header
        iov[0].iov_base = &dnbd3_reply;
        iov[0].iov_len = sizeof(dnbd3_reply);
        if (kernel_recvmsg(dev->sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
        {
        	printk("FATAL: Received corrupted reply header after CMD_SIZE_REQUEST.\n");
            goto error;
        }
        fixup_reply(dnbd3_reply);
        if (dnbd3_reply.cmd != CMD_GET_SIZE || dnbd3_reply.size < 3 || dnbd3_reply.size > MAX_PAYLOAD || dnbd3_reply.magic != dnbd3_packet_magic)
        {
        	printk("FATAL: Received invalid reply to CMD_SIZE_REQUEST, image doesn't exist on server.\n");
            goto error;
        }
        // receive reply payload
        iov[0].iov_base = &dev->payload_buffer;
        iov[0].iov_len = dnbd3_reply.size;
        if (kernel_recvmsg(dev->sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size)
        {
        	printk("FATAL: Cold not read CMD_GET_SIZE payload on handshake.\n");
            goto error;
        }
        serializer_reset_read(&dev->payload_buffer, dnbd3_reply.size);
        // read reply payload
        dev->cur_server.protocol_version = serializer_get_uint16(&dev->payload_buffer);
        if (dev->cur_server.protocol_version < MIN_SUPPORTED_SERVER)
        {
        	printk("FATAL: Server version is lower than min supported version.\n");
        	goto error;
        }
        name = serializer_get_string(&dev->payload_buffer);
        if (dev->rid != 0 && strcmp(name, dev->imgname) != 0)
        {
        	printk("FATAL: Server provides different image than asked for.\n");
        	goto error;
        }
        if (strlen(dev->imgname) < strlen(name))
        {
        	dev->imgname = krealloc(dev->imgname, strlen(name) + 1, GFP_ATOMIC);
        	if (dev->imgname == NULL)
        	{
        		printk("FATAL: Reallocating buffer for new image name failed");
        		goto error;
        	}
        }
        strcpy(dev->imgname, name);
        rid = serializer_get_uint16(&dev->payload_buffer);
        if (dev->rid != 0 && dev->rid != rid)
        {
        	printk("FATAL: Server provides different rid of image than asked for.\n");
        	goto error;
        }
        dev->rid = rid;
        dev->reported_size = serializer_get_uint64(&dev->payload_buffer);
        // store image information
        set_capacity(dev->disk, dev->reported_size >> 9); /* 512 Byte blocks */
        printk("INFO: Filesize of %s: %llu\n", dev->disk->disk_name, dev->reported_size);
    }
    else // Switching server, connection is already established and size request was executed
    {
    	printk("INFO: On-the-fly server change\n");
    	dev->sock = dev->better_sock;
    	dev->better_sock = NULL;
        kernel_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
        kernel_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
    }

    dev->panic = 0;
    dev->panic_count = 0;
    dev->update_available = 0;

    if (req1) // This connection is established to the initial server (from the ioctl call)
    {
    	// Set number of known alt servers to 0
    	dev->alt_servers_num = 0;
		// And then enqueue request to request_queue_send for a fresh list of alt servers
		req1->cmd_type = REQ_TYPE_SPECIAL;
		req1->cmd_flags = CMD_GET_SERVERS;
		list_add(&req1->queuelist, &dev->request_queue_send);
    }

    // create required threads
    dev->thread_send = kthread_create(dnbd3_net_send, dev, dev->disk->disk_name);
    dev->thread_receive = kthread_create(dnbd3_net_receive, dev, dev->disk->disk_name);
    dev->thread_discover = kthread_create(dnbd3_net_discover, dev, dev->disk->disk_name);
    // start them up
    wake_up_process(dev->thread_send);
    wake_up_process(dev->thread_receive);
    wake_up_process(dev->thread_discover);

    wake_up(&dev->process_queue_send);

    // add heartbeat timer
    init_timer(&dev->hb_timer);
    dev->hb_timer.data = (unsigned long) dev;
    dev->hb_timer.function = dnbd3_net_heartbeat;
    dev->hb_timer.expires = jiffies + TIMER_INTERVAL_HEARTBEAT;
    add_timer(&dev->hb_timer);

    return 0;
error:
	if (dev->sock)
	{
		sock_release(dev->sock);
		dev->sock = NULL;
	}
	dev->cur_server.hostaddrtype = 0;
	dev->cur_server.port = 0;
	if (req1) kfree(req1);
	return -1;
}

int dnbd3_net_disconnect(dnbd3_device_t *dev)
{
    printk("INFO: Disconnecting device %s\n", dev->disk->disk_name);

    dev->disconnecting = 1;

    // clear heartbeat timer
    if (&dev->hb_timer)
    	del_timer(&dev->hb_timer);

    dev->discover = 0;

    if (dev->sock)
    	kernel_sock_shutdown(dev->sock, SHUT_RDWR);

    // kill sending and receiving threads
    if (dev->thread_send)
    {
        kthread_stop(dev->thread_send);
        dev->thread_send = NULL;
    }

    if (dev->thread_receive)
    {
        kthread_stop(dev->thread_receive);
        dev->thread_receive = NULL;
    }

    if (dev->thread_discover)
    {
        kthread_stop(dev->thread_discover);
        dev->thread_discover = NULL;
    }

    // clear socket
    if (dev->sock)
    {
        sock_release(dev->sock);
        dev->sock = NULL;
    }
	dev->cur_server.hostaddrtype = 0;
	dev->cur_server.port = 0;

	dev->disconnecting = 0;

    return 0;
}

void dnbd3_net_heartbeat(unsigned long arg)
{
    dnbd3_device_t *dev = (dnbd3_device_t *) arg;


    if (!dev->panic)
    {
		struct request *req = kmalloc(sizeof(struct request), GFP_ATOMIC);
		// send keepalive
		if (req)
		{
			req->cmd_type = REQ_TYPE_SPECIAL;
			req->cmd_flags = CMD_KEEPALIVE;
			list_add_tail(&req->queuelist, &dev->request_queue_send);
			wake_up(&dev->process_queue_send);
		}
		else
		{
			printk("ERROR: Couldn't create keepalive request\n");
		}
    }

    // start discover
    dev->discover = 1;
    wake_up(&dev->process_queue_discover);

    if (dev->panic)
        dev->hb_timer.expires = jiffies + TIMER_INTERVAL_PANIC;
    else
        dev->hb_timer.expires = jiffies + TIMER_INTERVAL_HEARTBEAT;

    add_timer(&dev->hb_timer);
}

int dnbd3_net_discover(void *data)
{
    dnbd3_device_t *dev = data;
    struct sockaddr_in sin;
    struct socket *sock, *best_sock = NULL;

    dnbd3_request_t dnbd3_request;
    dnbd3_reply_t dnbd3_reply;
    struct msghdr msg;
    struct kvec iov[2];

    char *buf, *name;
    serialized_buffer_t *payload;
    uint64_t filesize;
    uint16_t rid;

    struct timeval start, end;
    unsigned long rtt, best_rtt = 0;
    int i, best_server, current_server;
    int turn = 0;
    int ready = 0;

    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT_CLIENT_DISCOVERY;
    timeout.tv_usec = 0;

    init_msghdr(msg);

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf)
    {
        printk("FATAL: Kmalloc failed (discover)\n");
        return -1;
    }
    payload = (serialized_buffer_t*)buf;

    dnbd3_request.magic = dnbd3_packet_magic;

    for (;;)
    {
        wait_event_interruptible(dev->process_queue_discover,
        		kthread_should_stop() || dev->discover);

        if (kthread_should_stop() || dev->imgname == NULL)
        	break;

        if (!dev->discover)
            continue;
        dev->discover = 0;

        // Check if the list of alt servers needs to be updated and do so if neccessary
        spin_lock_irq(&dev->blk_lock);
        if (dev->new_servers_num)
        {
        	for (i = 0; i < dev->new_servers_num; ++i)
        	{
        		memcpy(dev->alt_servers[i].hostaddr, dev->new_servers[i].ipaddr, 16);
        		dev->alt_servers[i].hostaddrtype = dev->new_servers[i].addrtype;
        		dev->alt_servers[i].port = dev->new_servers[i].port;
        		dev->alt_servers[i].rtts[0] = dev->alt_servers[i].rtts[1]
					= dev->alt_servers[i].rtts[2] = dev->alt_servers[i].rtts[3]
					= RTT_UNREACHABLE;
        		dev->alt_servers[i].protocol_version = 0;
        		dev->alt_servers[i].skip_count = 0;
        	}
        	dev->alt_servers_num = dev->new_servers_num;
        	dev->new_servers_num = 0;
        }
        spin_unlock_irq(&dev->blk_lock);

        current_server = best_server = -1;
        best_rtt = 0xFFFFFFFul;

        for (i=0; i < dev->alt_servers_num; ++i)
        {
            if (dev->alt_servers[i].hostaddrtype != AF_INET) // add IPv6....
            	continue;

            if (!dev->panic && dev->alt_servers[i].skip_count) // If not in panic mode, skip server if indicated
            {
            	--dev->alt_servers[i].skip_count;
            	continue;
            }

            // Initialize socket and connect
            if (sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock) < 0)
            {
                printk("ERROR: Couldn't create socket (discover)\n");
                sock = NULL;
                continue;
            }
            kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
            kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
            sock->sk->sk_allocation = GFP_NOIO;
            sin.sin_family = AF_INET; // add IPv6.....
            memcpy(&sin.sin_addr.s_addr, dev->alt_servers[i].hostaddr, 4);
            sin.sin_port = dev->alt_servers[i].port;
            if (kernel_connect(sock, (struct sockaddr *) &sin, sizeof(sin), 0) < 0)
            {
                //printk("ERROR: Couldn't connect to host %s:%s (discover)\n", current_server, dev->cur_server.port);
                goto error;
            }

            // Request filesize
            dnbd3_request.cmd = CMD_GET_SIZE;
            fixup_request(dnbd3_request);
            iov[0].iov_base = &dnbd3_request;
            iov[0].iov_len = sizeof(dnbd3_request);
            serializer_reset_write(payload);
            serializer_put_uint16(payload, PROTOCOL_VERSION);
            serializer_put_string(payload, dev->imgname);
            serializer_put_uint16(payload, dev->rid);
            iov[1].iov_base = payload;
            dnbd3_request.size = iov[1].iov_len = serializer_get_written_length(payload);
            if (kernel_sendmsg(sock, &msg, iov, 2, sizeof(dnbd3_request) + iov[1].iov_len) != sizeof(dnbd3_request) + iov[1].iov_len)
            {
            	printk("ERROR: Requesting image size failed (%pI4 : %d, discover)\n", dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }

            // receive net reply
            iov[0].iov_base = &dnbd3_reply;
            iov[0].iov_len = sizeof(dnbd3_reply);
            if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
            {
            	printk("ERROR: Receiving image size packet (header) failed (%pI4 :%d, discover)\n", dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }
            fixup_reply(dnbd3_reply);
            if (dnbd3_reply.magic != dnbd3_packet_magic || dnbd3_reply.cmd != CMD_GET_SIZE || dnbd3_reply.size < 4)
            {
            	printk("ERROR: Content of image size packet (header) mismatched (%pI4 :%d, discover)\n", dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }

            // receive data
            iov[0].iov_base = payload;
            iov[0].iov_len = dnbd3_reply.size;
            if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size)
            {
            	printk("ERROR: Receiving image size packet (payload) failed (%pI4 : %d, discover)\n", dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }
            serializer_reset_read(payload, dnbd3_reply.size);

            dev->alt_servers[i].protocol_version = serializer_get_uint16(payload);
            if (dev->alt_servers[i].protocol_version < MIN_SUPPORTED_SERVER)
            {
            	printk("ERROR: Server version too old (client: %d, server: %d, min supported: %d) (%pI4 : %d, discover)\n", (int)PROTOCOL_VERSION, (int)dev->alt_servers[i].protocol_version, (int)MIN_SUPPORTED_SERVER, dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }

            name = serializer_get_string(payload);
            if (name == NULL)
            {
            	printk("ERROR: Server did not supply an image name (%pI4 : %d, discover)\n", dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }
            if (strcmp(name, dev->imgname) != 0)
            {
            	printk("ERROR: Image name does not match requested one (client: '%s', server: '%s') (%pI4 : %d, discover)\n", dev->imgname, name, dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }

            rid = serializer_get_uint16(payload);
            if (rid != dev->rid)
            {
            	printk("ERROR: Server supplied wrong rid (client: '%d', server: '%d') (%pI4 : %d, discover)\n", (int)dev->rid, (int)rid, dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }

            filesize = serializer_get_uint64(payload);
            if (filesize != dev->reported_size)
            {
            	printk("ERROR: Reported image size of %llu does not match expected value %llu. (%pI4 :%d, discover)\n", (unsigned long long)filesize, (unsigned long long)dev->reported_size, dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
            	goto error;
            }

            // panic mode, take first responding server
            if (dev->panic)
            {
                printk("WARN: Panic mode (%s), taking server %pI4 : %d\n", dev->disk->disk_name, dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                if (best_sock != NULL) sock_release(best_sock);
                dev->better_sock = sock; // Pass over socket to take a shortcut in *_connect();
                kfree(buf);
                dev->thread_discover = NULL;
                dnbd3_net_disconnect(dev);
                memcpy(&dev->cur_server, &dev->alt_servers[i], sizeof(dev->cur_server));
                dnbd3_net_connect(dev);
                return 0;
            }

            // Request block
            dnbd3_request.cmd = CMD_GET_BLOCK;
            // Pick random block
            if (sizeof(size_t) >= 8)
            {
				dnbd3_request.offset = ((((start.tv_usec << 12) ^ start.tv_usec) << 4) % dev->reported_size) & ~(uint64_t)(RTT_BLOCK_SIZE-1);
				//printk("Random offset 64bit: %lluMiB\n", (unsigned long long)(dnbd3_request.offset >> 20));
            }
            else // On 32bit, prevent modulo on a 64bit data type. This limits the random block picking to the first 4GB of the image
            {
				dnbd3_request.offset = ((((start.tv_usec << 12) ^ start.tv_usec) << 4) % (uint32_t)dev->reported_size) & ~(RTT_BLOCK_SIZE-1);
				//printk("Random offset 32bit: %lluMiB\n", (unsigned long long)(dnbd3_request.offset >> 20));
            }
            dnbd3_request.size = RTT_BLOCK_SIZE;
            fixup_request(dnbd3_request);
            iov[0].iov_base = &dnbd3_request;
            iov[0].iov_len = sizeof(dnbd3_request);

            // start rtt measurement
            do_gettimeofday(&start);

            if (kernel_sendmsg(sock, &msg, iov, 1, sizeof(dnbd3_request)) <= 0)
            {
            	printk("ERROR: Requesting test block failed (%pI4 : %d, discover)\n", dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }

            // receive net reply
            iov[0].iov_base = &dnbd3_reply;
            iov[0].iov_len = sizeof(dnbd3_reply);
            if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
            {
            	printk("ERROR: Receiving test block header packet failed (%pI4 : %d, discover)\n", dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }
            fixup_reply(dnbd3_reply);
            if (dnbd3_reply.magic != dnbd3_packet_magic || dnbd3_reply.cmd != CMD_GET_BLOCK || dnbd3_reply.size != RTT_BLOCK_SIZE)
            {
            	printk("ERROR: Unexpected reply to block request: cmd=%d, size=%d (%pI4 : %d, discover)\n", (int)dnbd3_reply.cmd, (int)dnbd3_reply.size, dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }

            // receive data
            iov[0].iov_base = buf;
            iov[0].iov_len = RTT_BLOCK_SIZE;
            if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != RTT_BLOCK_SIZE)
            {
            	printk("ERROR: Receiving test block payload failed (%pI4 : %d, discover)\n", dev->alt_servers[i].hostaddr, (int)ntohs(dev->alt_servers[i].port));
                goto error;
            }

            do_gettimeofday(&end); // end rtt measurement

            dev->alt_servers[i].rtts[turn] = (unsigned long)(
            		  (end.tv_sec - start.tv_sec) * 1000000ull
            		+ (end.tv_usec - start.tv_usec)
            );

            rtt = ( dev->alt_servers[i].rtts[0]
				  + dev->alt_servers[i].rtts[1]
				  + dev->alt_servers[i].rtts[2]
				  + dev->alt_servers[i].rtts[3] ) >> 2; // ">> 2" == "/ 4", needed to prevent 64bit division on 32bit
            printk("RTT: %luµs\n", rtt);


            if (best_rtt > rtt)
            { // This one is better, keep socket open in case we switch
            	best_rtt = rtt;
            	best_server = i;
            	if (best_sock != NULL) sock_release(best_sock);
            	best_sock = sock;
            	sock = NULL;
            }
            else
            { // Not better, discard connection
                sock_release(sock);
                sock = NULL;
            }

            // update cur servers rtt
            if (is_same_server(&dev->cur_server,  &dev->alt_servers[i]))
            {
                dev->cur_rtt = rtt;
                current_server = i;
            }

            continue;

            error:
                sock_release(sock);
                sock = NULL;
                dev->alt_servers[i].rtts[turn] = RTT_UNREACHABLE;
                if (is_same_server(&dev->cur_server,  &dev->alt_servers[i]))
                {
                    dev->cur_rtt = RTT_UNREACHABLE;
                    current_server = i;
                }
                continue;
        }

        if (dev->panic && ++dev->panic_count == 21)
		{ // After 21 retries, bail out by reporting errors to block layer
        	dnbd3_blk_fail_all_requests(dev);
		}

        if (best_server == -1 || kthread_should_stop()) // No alt server could be reached at all or thread should stop
        {
        	if (best_sock != NULL) // Should never happen actually
        	{
        		sock_release(best_sock);
        		best_sock = NULL;
        	}
            continue;
        }

        // take server with lowest rtt
        if (ready && best_server != current_server
        		&& RTT_THRESHOLD_FACTOR(dev->cur_rtt) > best_rtt)
        {
            printk("INFO: Server %d on %s is faster (%lluµs vs. %lluµs)\n", best_server, dev->disk->disk_name, (unsigned long long)best_rtt, (unsigned long long)dev->cur_rtt);
        	kfree(buf);
        	dev->better_sock = best_sock; // Take shortcut by continuing to use open connection
            dev->thread_discover = NULL;
            dnbd3_net_disconnect(dev);
            memcpy(&dev->cur_server, &dev->alt_servers[best_server], sizeof(dev->cur_server));
            dev->cur_rtt = best_rtt;
            dnbd3_net_connect(dev);
            return 0;
        }

        // Clean up connection that was held open for quicker server switch
        if (best_sock != NULL)
        {
			sock_release(best_sock);
			best_sock = NULL;
        }

        turn = (turn + 1) % 4;
        if (turn == 3)
            ready = 1;

    }
    kfree(buf);
    return 0;
}

int dnbd3_net_send(void *data)
{
    dnbd3_device_t *dev = data;
    struct request *blk_request;

    dnbd3_request_t dnbd3_request;
    struct msghdr msg;
    struct kvec iov;

    init_msghdr(msg);

    dnbd3_request.magic = dnbd3_packet_magic;

    set_user_nice(current, -20);

    for (;;)
    {
        wait_event_interruptible(dev->process_queue_send,
                kthread_should_stop() || !list_empty(&dev->request_queue_send));

        if (kthread_should_stop())
        	break;

        // extract block request
        spin_lock_irq(&dev->blk_lock); // TODO: http://www.linuxjournal.com/article/5833 says spin_lock_irq should not be used in general, but article is 10 years old
        if (list_empty(&dev->request_queue_send))
        {
        	spin_unlock_irq(&dev->blk_lock);
            continue;
        }
        blk_request = list_entry(dev->request_queue_send.next, struct request, queuelist);
        spin_unlock_irq(&dev->blk_lock);

        // what to do?
        switch (blk_request->cmd_type)
        {
        case REQ_TYPE_FS:
            dnbd3_request.cmd = CMD_GET_BLOCK;
            dnbd3_request.offset = blk_rq_pos(blk_request) << 9; // *512
            dnbd3_request.size = blk_rq_bytes(blk_request); // bytes left to complete entire request
            // enqueue request to request_queue_receive
            spin_lock_irq(&dev->blk_lock);
            list_del_init(&blk_request->queuelist);
            list_add_tail(&blk_request->queuelist, &dev->request_queue_receive);
            spin_unlock_irq(&dev->blk_lock);
            break;

        case REQ_TYPE_SPECIAL:
            dnbd3_request.cmd = blk_request->cmd_flags;
            dnbd3_request.size = 0;
            spin_lock_irq(&dev->blk_lock);
            list_del_init(&blk_request->queuelist);
            spin_unlock_irq(&dev->blk_lock);
            break;

        default:
            printk("ERROR: Unknown command (send)\n");
            spin_lock_irq(&dev->blk_lock);
            list_del_init(&blk_request->queuelist);
            spin_unlock_irq(&dev->blk_lock);
            continue;
        }

        // send net request
        dnbd3_request.handle = (uint64_t)(uintptr_t)blk_request; // Double cast to prevent warning on 32bit
        fixup_request(dnbd3_request);
        iov.iov_base = &dnbd3_request;
        iov.iov_len = sizeof(dnbd3_request);
        if (kernel_sendmsg(dev->sock, &msg, &iov, 1, sizeof(dnbd3_request)) != sizeof(dnbd3_request))
        {
        	printk("Couldn't properly send a request header.\n");
            goto error;
        }
        wake_up(&dev->process_queue_receive);
    }

    return 0;

error:
	printk("ERROR: Connection to server %pI4 : %d lost (send)\n", dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port));
	if (dev->sock)
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);
	dev->thread_send = NULL;
	if (!dev->disconnecting)
	{
		dev->panic = 1;
		// start discover
		dev->discover = 1;
		wake_up(&dev->process_queue_discover);
	}
	return -1;
}

int dnbd3_net_receive(void *data)
{
    dnbd3_device_t *dev = data;
    struct request *blk_request, *tmp_request, *received_request;

    dnbd3_reply_t dnbd3_reply;
    struct msghdr msg;
    struct kvec iov;
    struct req_iterator iter;
    struct bio_vec *bvec;
    void *kaddr;
    unsigned long flags;
    sigset_t blocked, oldset;

    int count, remaining, ret;

    init_msghdr(msg);
    set_user_nice(current, -20);

    while (!kthread_should_stop())
    {
        // receive net reply
        iov.iov_base = &dnbd3_reply;
        iov.iov_len = sizeof(dnbd3_reply);
        ret = kernel_recvmsg(dev->sock, &msg, &iov, 1, sizeof(dnbd3_reply), msg.msg_flags);
        if (ret == -EAGAIN)
        {
        	// Sleep at most 2 seconds, then check if we can receive something
        	interruptible_sleep_on_timeout(&dev->process_queue_receive, 2*HZ);
            // If a request for a block was sent, the thread is waken up immediately, so that we don't wait 2 seconds for the reply
            // This change was made to allow unrequested information from the server to be received (push)
        	continue;
        }
        if (ret <= 0)
        {
        	printk("Connection closed (%d).\n", ret);
        	goto error;
        }
        if (ret != sizeof(dnbd3_reply))
        {
        	printk("ERROR: Recv msg header\n");
            goto error;
        }
        fixup_reply(dnbd3_reply);

        // check error
        if (dnbd3_reply.magic != dnbd3_packet_magic)
        {
         printk("ERROR: Wrong packet magic (Receive)\n");
         goto error;
        }
        if (dnbd3_reply.cmd == 0)
        {
         printk("ERROR: Command was 0 (Receive)\n");
         goto error;
        }


        // what to do?
        switch (dnbd3_reply.cmd)
        {
        case CMD_GET_BLOCK:
            // search for replied request in queue
            blk_request = NULL;
            spin_lock_irq(&dev->blk_lock);
            list_for_each_entry_safe(received_request, tmp_request, &dev->request_queue_receive, queuelist)
            {
                if ((uint64_t)(uintptr_t)received_request == dnbd3_reply.handle) // Double cast to prevent warning on 32bit
                {
                	blk_request = received_request;
                    break;
                }
            }
            spin_unlock_irq(&dev->blk_lock);
            if (blk_request == NULL)
            {
            	printk("ERROR: Received block data for unrequested handle (%llu: %llu).\n",
            			(unsigned long long)dnbd3_reply.handle, (unsigned long long)dnbd3_reply.size);
            	goto error;
            }
            // receive data and answer to block layer
            rq_for_each_segment(bvec, blk_request, iter)
            {
                siginitsetinv(&blocked, sigmask(SIGKILL));
                sigprocmask(SIG_SETMASK, &blocked, &oldset);

                kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
                iov.iov_base = kaddr;
                iov.iov_len = bvec->bv_len;
                if (kernel_recvmsg(dev->sock, &msg, &iov, 1, bvec->bv_len, msg.msg_flags) != bvec->bv_len)
                {
                	printk("ERROR: Receiving from net to block layer\n");
                    kunmap(bvec->bv_page);
                    goto error;
                }
                kunmap(bvec->bv_page);

                sigprocmask(SIG_SETMASK, &oldset, NULL);
            }
            spin_lock_irqsave(&dev->blk_lock, flags);
            list_del_init(&blk_request->queuelist);
            __blk_end_request_all(blk_request, 0);
            spin_unlock_irqrestore(&dev->blk_lock, flags);
            continue;

        case CMD_GET_SERVERS:
        	if (!is_same_server(&dev->cur_server, &dev->initial_server))
        	{
        		remaining = dnbd3_reply.size;
        		goto clear_remaining_payload;
        	}
        	spin_lock_irq(&dev->blk_lock);
        	dev->new_servers_num = 0;
        	spin_unlock_irq(&dev->blk_lock);
            count = MIN(NUMBER_SERVERS, dnbd3_reply.size / sizeof(dnbd3_server_entry_t));

            if (count != 0)
            {
				iov.iov_base = dev->new_servers;
				iov.iov_len = count * sizeof(dnbd3_server_entry_t);
				if (kernel_recvmsg(dev->sock, &msg, &iov, 1, (count * sizeof(dnbd3_server_entry_t)), msg.msg_flags) != (count * sizeof(dnbd3_server_entry_t)))
				{
					printk("ERROR: Recv CMD_GET_SERVERS payload.\n");
					goto error;
				}
				for (remaining = 0; remaining < count; ++remaining)
				{
					if (dev->new_servers[remaining].addrtype == AF_INET)
						printk("New Server: %pI4 : %d\n", dev->new_servers[remaining].ipaddr, (int)ntohs(dev->new_servers[remaining].port));
					else if (dev->new_servers[remaining].addrtype == AF_INET6)
						printk("New Server: %pI6 : %d\n", dev->new_servers[remaining].ipaddr, (int)ntohs(dev->new_servers[remaining].port));
					else
						printk("New Server of unknown address type (%d)\n", (int)dev->new_servers[remaining].addrtype);
				}
	        	spin_lock_irq(&dev->blk_lock);
	        	dev->new_servers_num = count;
	        	spin_unlock_irq(&dev->blk_lock);
				// TODO: Re-Add update check
            }
            // If there were more servers than accepted, remove the remaining data from the socket buffer
            remaining = dnbd3_reply.size - (count * sizeof(dnbd3_server_entry_t));
clear_remaining_payload:
            while (remaining > 0)
            {
            	count = MIN(sizeof(dnbd3_reply), remaining); // Abuse the reply struct as the receive buffer
            	iov.iov_base = &dnbd3_reply;
            	iov.iov_len = count;
            	ret = kernel_recvmsg(dev->sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
            	if (ret <= 0)
            	{
            		printk("ERROR: Recv additional payload from CMD_GET_SERVERS.\n");
            		goto error;
            	}
            	remaining -= ret;
            }
            continue;

        case CMD_KEEPALIVE:
        	if (dnbd3_reply.size != 0)
        		printk("Error: keep alive packet with payload.\n");
        	continue;

        default:
            printk("ERROR: Unknown command (Receive)\n");
            continue;

        }
    }

    printk("dnbd3_net_receive terminated normally.\n");
    return 0;

error:
    printk("ERROR: Connection to server %pI4 : %d lost (receive)\n", dev->cur_server.hostaddr, (int)ntohs(dev->cur_server.port));
	// move already sent requests to request_queue_send again
	while (!list_empty(&dev->request_queue_receive))
	{
		printk("WARN: Request queue was not empty on %s\n", dev->disk->disk_name);
		spin_lock_irq(&dev->blk_lock);
		list_for_each_entry_safe(blk_request, tmp_request, &dev->request_queue_receive, queuelist)
		{
			list_del_init(&blk_request->queuelist);
			list_add(&blk_request->queuelist, &dev->request_queue_send);
		}
		spin_unlock_irq(&dev->blk_lock);
	}
	if (dev->sock)
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);
	dev->thread_receive = NULL;
	if (!dev->disconnecting)
	{
		dev->panic = 1;
		// start discover
		dev->discover = 1;
		wake_up(&dev->process_queue_discover);
	}
	return -1;
}
