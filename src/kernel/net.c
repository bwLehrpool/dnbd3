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

/**
 * Some macros for easier debug output. Location in source-code
 * as well as server IP:port info will be printed.
 * The error_* macros include a "goto error;" at the end
 */
#if 1 // Change to 0 to disable debug messages
#define debug_print_va_host(_host, _fmt, ...) do { \
	if (dev->cur_server.hostaddrtype == AF_INET) \
		printk("%s:%d " _fmt " (%s, %pI4:%d)\n", __FILE__, __LINE__, __VA_ARGS__, dev->disk->disk_name, (_host).hostaddr, (int)ntohs((_host).port)); \
	else \
		printk("%s:%d " _fmt " (%s, [%pI6]:%d)\n", __FILE__, __LINE__, __VA_ARGS__, dev->disk->disk_name, (_host).hostaddr, (int)ntohs((_host).port)); \
} while(0)
#define debug_error_va_host(_host, _fmt, ...) do { \
	debug_print_va_host(_host, _fmt, __VA_ARGS__); \
	goto error; \
} while(0)
#define debug_dev_va(_fmt, ...) debug_print_va_host(dev->cur_server, _fmt, __VA_ARGS__)
#define error_dev_va(_fmt, ...) debug_error_va_host(dev->cur_server, _fmt, __VA_ARGS__)
#define debug_alt_va(_fmt, ...) debug_print_va_host(dev->alt_servers[i], _fmt, __VA_ARGS__)
#define error_alt_va(_fmt, ...) debug_error_va_host(dev->alt_servers[i], _fmt, __VA_ARGS__)

#define debug_print_host(_host, txt) do { \
	if (dev->cur_server.hostaddrtype == AF_INET) \
		printk("%s:%d " txt " (%s, %pI4:%d)\n", __FILE__, __LINE__, dev->disk->disk_name, (_host).hostaddr, (int)ntohs((_host).port)); \
	else \
		printk("%s:%d " txt " (%s, [%pI6]:%d)\n", __FILE__, __LINE__, dev->disk->disk_name, (_host).hostaddr, (int)ntohs((_host).port)); \
} while(0)
#define debug_error_host(_host, txt) do { \
	debug_print_host(_host, txt); \
	goto error; \
} while(0)
#define debug_dev(txt) debug_print_host(dev->cur_server, txt)
#define error_dev(txt) debug_error_host(dev->cur_server, txt)
#define debug_alt(txt) debug_print_host(dev->alt_servers[i], txt)
#define error_alt(txt) debug_error_host(dev->alt_servers[i], txt)

#else // Silent

#define debug_dev(x) while(0)
#define error_dev(x) goto error
#define debug_dev_va(x, ...) while(0)
#define error_dev_va(x, ...) goto error
#define debug_alt(x) while(0)
#define error_alt(x) goto error
#define debug_alt_va(x, ...) while(0)
#define error_alt_va(x, ...) goto error
#endif

static inline int is_same_server(const dnbd3_server_t * const a, const dnbd3_server_t * const b)
{
	return (a->hostaddrtype == b->hostaddrtype)
		&& (a->port == b->port)
		&& (0 == memcmp(a->hostaddr, b->hostaddr, (a->hostaddrtype == AF_INET ? 4 : 16)));
}

static inline dnbd3_server_t* get_existing_server(const dnbd3_server_entry_t * const newserver, dnbd3_device_t * const dev)
{
	int i;
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if ((newserver->hostaddrtype == dev->alt_servers[i].hostaddrtype)
			&& (newserver->port == dev->alt_servers[i].port)
			&& (0 == memcmp(newserver->hostaddr, dev->alt_servers[i].hostaddr, (newserver->hostaddrtype == AF_INET ? 4 : 16))))
		{
			return &dev->alt_servers[i];
			break;
		}
	}
	return NULL;
}

static inline dnbd3_server_t* get_free_alt_server(dnbd3_device_t * const dev)
{
	int i;
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if (dev->alt_servers[i].hostaddrtype == 0)
			return &dev->alt_servers[i];
	}
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if (dev->alt_servers[i].failures > 10)
			return &dev->alt_servers[i];
	}
	return NULL;
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
    	// Forget all known alt servers
    	memset(dev->alt_servers, 0, sizeof(dev->alt_servers[0])*NUMBER_SERVERS);
    	memcpy(dev->alt_servers, &dev->initial_server, sizeof(dev->alt_servers[0]));
    	if (dev->mode == DEVICE_MODE_CLIENT)
    	{
			req1 = kmalloc(sizeof(*req1), GFP_ATOMIC);
			if (!req1)
				error_dev("FATAL: Kmalloc(1) failed.");
    	}
    }
    if (dev->cur_server.port == 0 || dev->cur_server.hostaddrtype == 0 || dev->imgname == NULL)
    	error_dev("FATAL: Host, port or image name not set.");
    if (dev->sock)
    	error_dev("ERROR: Already connected.");

    if (dev->cur_server.hostaddrtype != AF_INET)
    	error_dev("ERROR: IPv6 not implemented.");
    else
    	debug_dev("INFO: Connecting...");

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
			error_dev("ERROR: Couldn't create socket.");
		kernel_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
		kernel_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
		dev->sock->sk->sk_allocation = GFP_NOIO;
		sin.sin_family = AF_INET;
		memcpy(&(sin.sin_addr.s_addr), dev->cur_server.hostaddr, 4);
		sin.sin_port = dev->cur_server.port;
		if (kernel_connect(dev->sock, (struct sockaddr *) &sin, sizeof(sin), 0) != 0)
			error_dev("FATAL: Connection to host failed.");
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
        	error_dev("ERROR: Couldn't send CMD_SIZE_REQUEST.");
        // receive reply header
        iov[0].iov_base = &dnbd3_reply;
        iov[0].iov_len = sizeof(dnbd3_reply);
        if (kernel_recvmsg(dev->sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
        	error_dev("FATAL: Received corrupted reply header after CMD_SIZE_REQUEST.");
        // check reply header
        fixup_reply(dnbd3_reply);
        if (dnbd3_reply.cmd != CMD_GET_SIZE || dnbd3_reply.size < 3 || dnbd3_reply.size > MAX_PAYLOAD || dnbd3_reply.magic != dnbd3_packet_magic)
        	error_dev("FATAL: Received invalid reply to CMD_SIZE_REQUEST, image doesn't exist on server.");
        // receive reply payload
        iov[0].iov_base = &dev->payload_buffer;
        iov[0].iov_len = dnbd3_reply.size;
        if (kernel_recvmsg(dev->sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size)
        	error_dev("FATAL: Cold not read CMD_GET_SIZE payload on handshake.");
        // handle/check reply payload
        serializer_reset_read(&dev->payload_buffer, dnbd3_reply.size);
        dev->cur_server.protocol_version = serializer_get_uint16(&dev->payload_buffer);
        if (dev->cur_server.protocol_version < MIN_SUPPORTED_SERVER)
        	error_dev("FATAL: Server version is lower than min supported version.");
        name = serializer_get_string(&dev->payload_buffer);
        if (dev->rid != 0 && strcmp(name, dev->imgname) != 0)
        	error_dev_va("FATAL: Server offers image '%s', requested '%s'", name, dev->imgname);
        if (strlen(dev->imgname) < strlen(name))
        {
        	dev->imgname = krealloc(dev->imgname, strlen(name) + 1, GFP_ATOMIC);
        	if (dev->imgname == NULL)
        		error_dev("FATAL: Reallocating buffer for new image name failed");
        }
        strcpy(dev->imgname, name);
        rid = serializer_get_uint16(&dev->payload_buffer);
        if (dev->rid != 0 && dev->rid != rid)
        	error_dev_va("FATAL: Server provides rid %d, requested was %d.", (int)rid, (int)dev->rid);
        dev->rid = rid;
        dev->reported_size = serializer_get_uint64(&dev->payload_buffer);
        // store image information
        set_capacity(dev->disk, dev->reported_size >> 9); /* 512 Byte blocks */
        debug_dev_va("INFO: Filesize: %llu.", dev->reported_size);
    }
    else // Switching server, connection is already established and size request was executed
    {
    	debug_dev("INFO: On-the-fly server change.");
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
		// Enqueue request to request_queue_send for a fresh list of alt servers
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
    dev->heartbeat_count = 0;
    init_timer(&dev->hb_timer);
    dev->hb_timer.data = (unsigned long) dev;
    dev->hb_timer.function = dnbd3_net_heartbeat;
    dev->hb_timer.expires = jiffies + HZ;
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
    debug_dev("INFO: Disconnecting device.");

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
	// Because different events need different intervals, the timer is called once a second.
	// Other intervals can be derived using dev->heartbeat_count.
#define timeout_seconds(x) (dev->heartbeat_count % (x) == 0)
    dnbd3_device_t *dev = (dnbd3_device_t *) arg;


    if (!dev->panic)
    {
    	if (timeout_seconds(TIMER_INTERVAL_KEEPALIVE_PACKET))
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
				debug_dev("ERROR: Couldn't create keepalive request.");
			}
    	}
    	if (timeout_seconds(TIMER_INTERVAL_PROBE_NORMAL))
    	{
			// Normal discovery
			dev->discover = 1;
			wake_up(&dev->process_queue_discover);
    	}
    }
    else if (timeout_seconds(TIMER_INTERVAL_PROBE_PANIC))
    {
		// Panic discovery
		dev->discover = 1;
		wake_up(&dev->process_queue_discover);
    }

    dev->hb_timer.expires = jiffies + HZ;

    ++dev->heartbeat_count;
    add_timer(&dev->hb_timer);
#undef timeout_seconds
}

int dnbd3_net_discover(void *data)
{
    dnbd3_device_t *dev = data;
    struct sockaddr_in sin;
    struct socket *sock, *best_sock = NULL;

    dnbd3_request_t dnbd3_request;
    dnbd3_reply_t dnbd3_reply;
    dnbd3_server_t *alt_server;
    struct msghdr msg;
    struct kvec iov[2];

    char *buf, *name;
    serialized_buffer_t *payload;
    uint64_t filesize;
    uint16_t rid;

    struct timeval start, end;
    unsigned long rtt, best_rtt = 0;
    unsigned long irqflags;
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
        debug_dev("FATAL: Kmalloc failed (discover)");
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
        if (dev->new_servers_num)
        {
        	spin_lock_irqsave(&dev->blk_lock, irqflags);
        	for (i = 0; i < dev->new_servers_num; ++i)
        	{
        		if (dev->new_servers[i].hostaddrtype != AF_INET) // Invalid entry.. (Add IPv6)
        			continue;
        		alt_server = get_existing_server(&dev->new_servers[i], dev);
        		if (alt_server != NULL) // Server already known
        		{
        			if (dev->new_servers[i].failures == 1)
        			{	// REMOVE request
        				alt_server->hostaddrtype = 0;
        				continue;
        			}
        			// ADD, so just reset fail counter
        			alt_server->failures = 0;
        			continue;
        		}
        		if (dev->new_servers[i].failures == 1) // REMOVE, but server is not in list anyways
        			continue;
        		alt_server = get_free_alt_server(dev);
        		if (alt_server == NULL) // All NUMBER_SERVERS slots are taken, ignore entry
        			continue;
        		// Add new server entry
        		memcpy(alt_server->hostaddr, dev->new_servers[i].hostaddr, 16);
        		alt_server->hostaddrtype = dev->new_servers[i].hostaddrtype;
        		alt_server->port = dev->new_servers[i].port;
        		alt_server->rtts[0] = alt_server->rtts[1]
					= alt_server->rtts[2] = alt_server->rtts[3]
					= RTT_UNREACHABLE;
        		alt_server->protocol_version = 0;
        		alt_server->failures = 0;
        	}
        	dev->new_servers_num = 0;
        	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
        }

        current_server = best_server = -1;
        best_rtt = 0xFFFFFFFul;

        for (i=0; i < NUMBER_SERVERS; ++i)
        {
        	if (dev->alt_servers[i].hostaddrtype == 0) // Empty slot
        		continue;
            if (!dev->panic && dev->alt_servers[i].failures > 50) // If not in panic mode, skip server if it failed too many times
            	continue;

            // Initialize socket and connect
            if (sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock) < 0)
            {
                debug_alt("ERROR: Couldn't create socket (discover).");
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
            	goto error;

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
            	error_alt("ERROR: Requesting image size failed.");

            // receive net reply
            iov[0].iov_base = &dnbd3_reply;
            iov[0].iov_len = sizeof(dnbd3_reply);
            if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
            	error_alt("ERROR: Receiving image size packet (header) failed (discover).");
            fixup_reply(dnbd3_reply);
            if (dnbd3_reply.magic != dnbd3_packet_magic || dnbd3_reply.cmd != CMD_GET_SIZE || dnbd3_reply.size < 4)
            	error_alt("ERROR: Content of image size packet (header) mismatched (discover).");

            // receive data
            iov[0].iov_base = payload;
            iov[0].iov_len = dnbd3_reply.size;
            if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size)
            	error_alt("ERROR: Receiving image size packet (payload) failed (discover).");
            serializer_reset_read(payload, dnbd3_reply.size);

            dev->alt_servers[i].protocol_version = serializer_get_uint16(payload);
            if (dev->alt_servers[i].protocol_version < MIN_SUPPORTED_SERVER)
            	error_alt_va("ERROR: Server version too old (client: %d, server: %d, min supported: %d).", (int)PROTOCOL_VERSION, (int)dev->alt_servers[i].protocol_version, (int)MIN_SUPPORTED_SERVER);

            name = serializer_get_string(payload);
            if (name == NULL)
            	error_alt("ERROR: Server did not supply an image name (discover).");

            if (strcmp(name, dev->imgname) != 0)
            	error_alt_va("ERROR: Image name does not match requested one (client: '%s', server: '%s') (discover).", dev->imgname, name);

            rid = serializer_get_uint16(payload);
            if (rid != dev->rid)
            	error_alt_va("ERROR: Server supplied wrong rid (client: '%d', server: '%d') (discover).", (int)dev->rid, (int)rid);

            filesize = serializer_get_uint64(payload);
            if (filesize != dev->reported_size)
            	error_alt_va("ERROR: Reported image size of %llu does not match expected value %llu.(discover).", (unsigned long long)filesize, (unsigned long long)dev->reported_size);

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
            	error_alt("ERROR: Requesting test block failed (discover).");

            // receive net reply
            iov[0].iov_base = &dnbd3_reply;
            iov[0].iov_len = sizeof(dnbd3_reply);
            if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
            	error_alt("ERROR: Receiving test block header packet failed (discover).");
            fixup_reply(dnbd3_reply);
            if (dnbd3_reply.magic != dnbd3_packet_magic || dnbd3_reply.cmd != CMD_GET_BLOCK || dnbd3_reply.size != RTT_BLOCK_SIZE)
            	error_alt_va("ERROR: Unexpected reply to block request: cmd=%d, size=%d (discover).", (int)dnbd3_reply.cmd, (int)dnbd3_reply.size);

            // receive data
            iov[0].iov_base = buf;
            iov[0].iov_len = RTT_BLOCK_SIZE;
            if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != RTT_BLOCK_SIZE)
            	error_alt("ERROR: Receiving test block payload failed (discover).");

            do_gettimeofday(&end); // end rtt measurement

            dev->alt_servers[i].rtts[turn] = (unsigned long)(
            		  (end.tv_sec - start.tv_sec) * 1000000ull
            		+ (end.tv_usec - start.tv_usec)
            );

            rtt = ( dev->alt_servers[i].rtts[0]
				  + dev->alt_servers[i].rtts[1]
				  + dev->alt_servers[i].rtts[2]
				  + dev->alt_servers[i].rtts[3] ) / 4;

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

            dev->alt_servers[i].failures = 0;

            continue;

		error:
			++dev->alt_servers[i].failures;
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

        if (dev->panic)
		{ // After 21 retries, bail out by reporting errors to block layer
        	if (dev->panic_count < 255 && ++dev->panic_count == PROBE_COUNT_TIMEOUT+1)
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

    unsigned long irqflags;

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
        spin_lock_irqsave(&dev->blk_lock, irqflags);
        if (list_empty(&dev->request_queue_send))
        {
        	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
            continue;
        }
        blk_request = list_entry(dev->request_queue_send.next, struct request, queuelist);
        spin_unlock_irqrestore(&dev->blk_lock, irqflags);

        // what to do?
        switch (blk_request->cmd_type)
        {
        case REQ_TYPE_FS:
            dnbd3_request.cmd = CMD_GET_BLOCK;
            dnbd3_request.offset = blk_rq_pos(blk_request) << 9; // *512
            dnbd3_request.size = blk_rq_bytes(blk_request); // bytes left to complete entire request
            // enqueue request to request_queue_receive
            spin_lock_irqsave(&dev->blk_lock, irqflags);
            list_del_init(&blk_request->queuelist);
            list_add_tail(&blk_request->queuelist, &dev->request_queue_receive);
            spin_unlock_irqrestore(&dev->blk_lock, irqflags);
            break;

        case REQ_TYPE_SPECIAL:
            dnbd3_request.cmd = blk_request->cmd_flags;
            dnbd3_request.size = 0;
            spin_lock_irqsave(&dev->blk_lock, irqflags);
            list_del_init(&blk_request->queuelist);
            spin_unlock_irqrestore(&dev->blk_lock, irqflags);
            break;

        default:
            printk("ERROR: Unknown command (send)\n");
            spin_lock_irqsave(&dev->blk_lock, irqflags);
            list_del_init(&blk_request->queuelist);
            spin_unlock_irqrestore(&dev->blk_lock, irqflags);
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
    unsigned long irqflags;
    sigset_t blocked, oldset;
    uint16_t rid;

    int count, remaining, ret, recv_timeout = 0;

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
        	if ((recv_timeout += SOCKET_TIMEOUT_CLIENT_DATA) > SOCKET_KEEPALIVE_TIMEOUT)
        		error_dev("ERROR: Receive timeout reached.");
        	continue;
        }
        if (ret <= 0)
        	error_dev_va("Connection closed (%d).", ret);
        if (ret != sizeof(dnbd3_reply))
        	error_dev("ERROR: Recv msg header.");
        fixup_reply(dnbd3_reply);

        // check error
        if (dnbd3_reply.magic != dnbd3_packet_magic)
        	error_dev("ERROR: Wrong packet magic (Receive).");
        if (dnbd3_reply.cmd == 0)
        	error_dev("ERROR: Command was 0 (Receive).");

        recv_timeout = 0;

        // what to do?
        switch (dnbd3_reply.cmd)
        {
        case CMD_GET_BLOCK:
            // search for replied request in queue
            blk_request = NULL;
            spin_lock_irqsave(&dev->blk_lock, irqflags);
            list_for_each_entry_safe(received_request, tmp_request, &dev->request_queue_receive, queuelist)
            {
                if ((uint64_t)(uintptr_t)received_request == dnbd3_reply.handle) // Double cast to prevent warning on 32bit
                {
                	blk_request = received_request;
                    break;
                }
            }
            spin_unlock_irqrestore(&dev->blk_lock, irqflags);
            if (blk_request == NULL)
            	error_dev_va("ERROR: Received block data for unrequested handle (%llu: %llu).\n",
            			(unsigned long long)dnbd3_reply.handle, (unsigned long long)dnbd3_reply.size);
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
                	kunmap(bvec->bv_page);
                	sigprocmask(SIG_SETMASK, &oldset, NULL);
                	error_dev("ERROR: Receiving from net to block layer.");
                }
                kunmap(bvec->bv_page);

                sigprocmask(SIG_SETMASK, &oldset, NULL);
            }
            spin_lock_irqsave(&dev->blk_lock, irqflags);
            list_del_init(&blk_request->queuelist);
            __blk_end_request_all(blk_request, 0);
            spin_unlock_irqrestore(&dev->blk_lock, irqflags);
            continue;

        case CMD_GET_SERVERS:
        	if (dev->mode == DEVICE_MODE_PROXY || !is_same_server(&dev->cur_server, &dev->initial_server))
        	{	// If not connected to initial server, or device is in proxy mode, ignore this message
        		remaining = dnbd3_reply.size;
        		goto clear_remaining_payload;
        	}
        	spin_lock_irqsave(&dev->blk_lock, irqflags);
        	dev->new_servers_num = 0;
        	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
            count = MIN(NUMBER_SERVERS, dnbd3_reply.size / sizeof(dnbd3_server_entry_t));

            if (count != 0)
            {
				iov.iov_base = dev->new_servers;
				iov.iov_len = count * sizeof(dnbd3_server_entry_t);
				if (kernel_recvmsg(dev->sock, &msg, &iov, 1, (count * sizeof(dnbd3_server_entry_t)), msg.msg_flags) != (count * sizeof(dnbd3_server_entry_t)))
					error_dev("ERROR: Recv CMD_GET_SERVERS payload.");
	        	spin_lock_irqsave(&dev->blk_lock, irqflags);
	        	dev->new_servers_num = count;
	        	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
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
            		error_dev("ERROR: Recv additional payload from CMD_GET_SERVERS.");
            	remaining -= ret;
            }
            continue;

        case CMD_LATEST_RID:
        	if (dnbd3_reply.size != 2)
        	{
        		printk("ERROR: CMD_LATEST_RID.size != 2.\n");
        		continue;
        	}
        	iov.iov_base = &rid;
        	iov.iov_len = sizeof(rid);
        	if (kernel_recvmsg(dev->sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags) <= 0)
        	{
        		printk("ERROR: Could not receive CMD_LATEST_RID payload.\n");
        	}
        	else
        	{
        		rid = net_order_16(rid);
        		printk("Latest rid of %s is %d (currently using %d)\n", dev->imgname, (int)rid, (int)dev->rid);
        		dev->update_available = (rid > dev->rid ? 1 : 0);
        	}
        	continue;

        case CMD_KEEPALIVE:
        	if (dnbd3_reply.size != 0)
        		printk("ERROR: keep alive packet with payload.\n");
        	continue;

        default:
            printk("ERROR: Unknown command (Receive)\n");
            continue;

        }
    }

    printk("dnbd3_net_receive terminated normally.\n");
    return 0;

error:
	// move already sent requests to request_queue_send again
	while (!list_empty(&dev->request_queue_receive))
	{
		printk("WARN: Request queue was not empty on %s\n", dev->disk->disk_name);
		spin_lock_irqsave(&dev->blk_lock, irqflags);
		list_for_each_entry_safe(blk_request, tmp_request, &dev->request_queue_receive, queuelist)
		{
			list_del_init(&blk_request->queuelist);
			list_add(&blk_request->queuelist, &dev->request_queue_send);
		}
		spin_unlock_irqrestore(&dev->blk_lock, irqflags);
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
