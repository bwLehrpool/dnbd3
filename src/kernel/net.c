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
	if ((_host).type == AF_INET) \
		printk("%s:%d " _fmt " (%s, %pI4:%d)\n", __FILE__, __LINE__, __VA_ARGS__, dev->disk->disk_name, (_host).addr, (int)ntohs((_host).port)); \
	else \
		printk("%s:%d " _fmt " (%s, [%pI6]:%d)\n", __FILE__, __LINE__, __VA_ARGS__, dev->disk->disk_name, (_host).addr, (int)ntohs((_host).port)); \
} while(0)
#define debug_error_va_host(_host, _fmt, ...) do { \
	debug_print_va_host(_host, _fmt, __VA_ARGS__); \
	goto error; \
} while(0)
#define debug_dev_va(_fmt, ...) debug_print_va_host(dev->cur_server.host, _fmt, __VA_ARGS__)
#define error_dev_va(_fmt, ...) debug_error_va_host(dev->cur_server.host, _fmt, __VA_ARGS__)
#define debug_alt_va(_fmt, ...) debug_print_va_host(dev->alt_servers[i].host, _fmt, __VA_ARGS__)
#define error_alt_va(_fmt, ...) debug_error_va_host(dev->alt_servers[i].host, _fmt, __VA_ARGS__)

#define debug_print_host(_host, txt) do { \
	if ((_host).type == AF_INET) \
		printk("%s:%d " txt " (%s, %pI4:%d)\n", __FILE__, __LINE__, dev->disk->disk_name, (_host).addr, (int)ntohs((_host).port)); \
	else \
		printk("%s:%d " txt " (%s, [%pI6]:%d)\n", __FILE__, __LINE__, dev->disk->disk_name, (_host).addr, (int)ntohs((_host).port)); \
} while(0)
#define debug_error_host(_host, txt) do { \
	debug_print_host(_host, txt); \
	goto error; \
} while(0)
#define debug_dev(txt) debug_print_host(dev->cur_server.host, txt)
#define error_dev(txt) debug_error_host(dev->cur_server.host, txt)
#define debug_alt(txt) debug_print_host(dev->alt_servers[i].host, txt)
#define error_alt(txt) debug_error_host(dev->alt_servers[i].host, txt)

#else // Silent
#define debug_dev(x) do { } while(0)
#define error_dev(x) goto error
#define debug_dev_va(x, ...) do { } while(0)
#define error_dev_va(x, ...) goto error
#define debug_alt(x) do { } while(0)
#define error_alt(x) goto error
#define debug_alt_va(x, ...) do { } while(0)
#define error_alt_va(x, ...) goto error
#endif

static inline int is_same_server(const dnbd3_server_t * const a, const dnbd3_server_t * const b)
{
	return (a->host.type == b->host.type) && (a->host.port == b->host.port)
	   && (0 == memcmp(a->host.addr, b->host.addr, (a->host.type == AF_INET ? 4 : 16)));
}

static inline dnbd3_server_t *get_existing_server(const dnbd3_server_entry_t * const newserver,
   dnbd3_device_t * const dev)
{
	int i;
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if ((newserver->host.type == dev->alt_servers[i].host.type)
		   && (newserver->host.port == dev->alt_servers[i].host.port)
		   && (0
		      == memcmp(newserver->host.addr, dev->alt_servers[i].host.addr, (newserver->host.type == AF_INET ? 4 : 16))))
		{
			return &dev->alt_servers[i];
			break;
		}
	}
	return NULL ;
}

static inline dnbd3_server_t *get_free_alt_server(dnbd3_device_t * const dev)
{
	int i;
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if (dev->alt_servers[i].host.type == 0)
			return &dev->alt_servers[i];
	}
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if (dev->alt_servers[i].failures > 10)
			return &dev->alt_servers[i];
	}
	return NULL ;
}

int dnbd3_net_connect(dnbd3_device_t *dev)
{
	struct request *req1 = NULL;
	struct timeval timeout;

	if (dev->disconnecting) {
		debug_dev("CONNECT: Still disconnecting!!!\n");
		while (dev->disconnecting)
			schedule();
	}
	if (dev->thread_receive != NULL) {
		debug_dev("CONNECT: Still receiving!!!\n");
		while (dev->thread_receive != NULL)
			schedule();
	}
	if (dev->thread_send != NULL) {
		debug_dev("CONNECT: Still sending!!!\n");
		while (dev->thread_send != NULL)
			schedule();
	}

	timeout.tv_sec = SOCKET_TIMEOUT_CLIENT_DATA;
	timeout.tv_usec = 0;

	// do some checks before connecting

	req1 = kmalloc(sizeof(*req1), GFP_ATOMIC );
	if (!req1)
		error_dev("FATAL: Kmalloc(1) failed.");

	if (dev->cur_server.host.port == 0 || dev->cur_server.host.type == 0 || dev->imgname == NULL )
		error_dev("FATAL: Host, port or image name not set.");
	if (dev->sock)
		error_dev("ERROR: Already connected.");

	if (dev->cur_server.host.type != AF_INET && dev->cur_server.host.type != AF_INET6)
		error_dev_va("ERROR: Unknown address type %d", (int)dev->cur_server.host.type);

	debug_dev("INFO: Connecting...");

	if (dev->better_sock == NULL )
	{
		//  no established connection yet from discovery thread, start new one
		dnbd3_request_t dnbd3_request;
		dnbd3_reply_t dnbd3_reply;
		struct msghdr msg;
		struct kvec iov[2];
		uint16_t rid;
		char *name;
		int mlen;
		init_msghdr(msg);

		if (sock_create_kern(dev->cur_server.host.type, SOCK_STREAM, IPPROTO_TCP, &dev->sock) < 0)
			error_dev("ERROR: Couldn't create socket (v6).");

		kernel_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
		kernel_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		dev->sock->sk->sk_allocation = GFP_NOIO;
		if (dev->cur_server.host.type == AF_INET)
		{
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			memcpy(&(sin.sin_addr), dev->cur_server.host.addr, 4);
			sin.sin_port = dev->cur_server.host.port;
			if (kernel_connect(dev->sock, (struct sockaddr *)&sin, sizeof(sin), 0) != 0)
				error_dev("FATAL: Connection to host failed. (v4)");
		}
		else
		{
			struct sockaddr_in6 sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin6_family = AF_INET6;
			memcpy(&(sin.sin6_addr), dev->cur_server.host.addr, 16);
			sin.sin6_port = dev->cur_server.host.port;
			if (kernel_connect(dev->sock, (struct sockaddr *)&sin, sizeof(sin), 0) != 0)
				error_dev("FATAL: Connection to host failed. (v6)");
		}
		// Request filesize
		dnbd3_request.magic = dnbd3_packet_magic;
		dnbd3_request.cmd = CMD_SELECT_IMAGE;
		iov[0].iov_base = &dnbd3_request;
		iov[0].iov_len = sizeof(dnbd3_request);
		serializer_reset_write(&dev->payload_buffer);
		serializer_put_uint16(&dev->payload_buffer, PROTOCOL_VERSION);
		serializer_put_string(&dev->payload_buffer, dev->imgname);
		serializer_put_uint16(&dev->payload_buffer, dev->rid);
		serializer_put_uint8(&dev->payload_buffer, dev->is_server);
		iov[1].iov_base = &dev->payload_buffer;
		dnbd3_request.size = iov[1].iov_len = serializer_get_written_length(&dev->payload_buffer);
		fixup_request(dnbd3_request);
		mlen = sizeof(dnbd3_request) + iov[1].iov_len;
		if (kernel_sendmsg(dev->sock, &msg, iov, 2, mlen) != mlen)
			error_dev("ERROR: Couldn't send CMD_SIZE_REQUEST.");
		// receive reply header
		iov[0].iov_base = &dnbd3_reply;
		iov[0].iov_len = sizeof(dnbd3_reply);
		if (kernel_recvmsg(dev->sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
			error_dev("FATAL: Received corrupted reply header after CMD_SIZE_REQUEST.");
		// check reply header
		fixup_reply(dnbd3_reply);
		if (dnbd3_reply.cmd != CMD_SELECT_IMAGE || dnbd3_reply.size < 3 || dnbd3_reply.size > MAX_PAYLOAD
		   || dnbd3_reply.magic != dnbd3_packet_magic)
			error_dev("FATAL: Received invalid reply to CMD_SIZE_REQUEST, image doesn't exist on server.");
		// receive reply payload
		iov[0].iov_base = &dev->payload_buffer;
		iov[0].iov_len = dnbd3_reply.size;
		if (kernel_recvmsg(dev->sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size)
			error_dev("FATAL: Cold not read CMD_SELECT_IMAGE payload on handshake.");
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
			dev->imgname = krealloc(dev->imgname, strlen(name) + 1, GFP_ATOMIC );
			if (dev->imgname == NULL )
				error_dev("FATAL: Reallocating buffer for new image name failed");
		}
		strcpy(dev->imgname, name);
		rid = serializer_get_uint16(&dev->payload_buffer);
		if (dev->rid != 0 && dev->rid != rid)
			error_dev_va("FATAL: Server provides rid %d, requested was %d.", (int)rid, (int)dev->rid);
		dev->rid = rid;
		dev->reported_size = serializer_get_uint64(&dev->payload_buffer);
		if (dev->reported_size < 4096)
			error_dev("ERROR: Reported size by server is < 4096");
		// store image information
		set_capacity(dev->disk, dev->reported_size >> 9); /* 512 Byte blocks */
		debug_dev_va("INFO: Filesize: %llu.", dev->reported_size);
		dev->update_available = 0;
	}
	else // Switching server, connection is already established and size request was executed
	{
		debug_dev("INFO: On-the-fly server change.");
		dev->sock = dev->better_sock;
		dev->better_sock = NULL;
		kernel_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
		kernel_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	}

	dev->panic = 0;
	dev->panic_count = 0;

	// Enqueue request to request_queue_send for a fresh list of alt servers
	req1->cmd_type = REQ_TYPE_SPECIAL;
	req1->cmd_flags = CMD_GET_SERVERS;
	list_add(&req1->queuelist, &dev->request_queue_send);

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
	dev->hb_timer.data = (unsigned long)dev;
	dev->hb_timer.function = dnbd3_net_heartbeat;
	dev->hb_timer.expires = jiffies + HZ;
	add_timer(&dev->hb_timer);

	return 0;
	error: ;
	if (dev->sock)
	{
		sock_release(dev->sock);
		dev->sock = NULL;
	}
	dev->cur_server.host.type = 0;
	dev->cur_server.host.port = 0;
	if (req1)
		kfree(req1);
	return -1;
}

int dnbd3_net_disconnect(dnbd3_device_t *dev)
{
	if (dev->disconnecting)
		return 0;

	if (dev->cur_server.host.port)
		debug_dev("INFO: Disconnecting device.");

	dev->disconnecting = 1;

	// clear heartbeat timer
	del_timer(&dev->hb_timer);

	dev->discover = 0;

	if (dev->sock)
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);

	// kill sending and receiving threads
	if (dev->thread_send)
	{
		kthread_stop(dev->thread_send);
	}

	if (dev->thread_receive)
	{
		kthread_stop(dev->thread_receive);
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
	dev->cur_server.host.type = 0;
	dev->cur_server.host.port = 0;

	dev->disconnecting = 0;

	return 0;
}

void dnbd3_net_heartbeat(unsigned long arg)
{
	// Because different events need different intervals, the timer is called once a second.
	// Other intervals can be derived using dev->heartbeat_count.
#define timeout_seconds(x) (dev->heartbeat_count % (x) == 0)
	dnbd3_device_t *dev = (dnbd3_device_t *)arg;

	if (!dev->panic)
	{
		if (timeout_seconds(TIMER_INTERVAL_KEEPALIVE_PACKET))
		{
			struct request *req = kmalloc(sizeof(struct request), GFP_ATOMIC );
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
		if ((dev->heartbeat_count > STARTUP_MODE_DURATION && timeout_seconds(TIMER_INTERVAL_PROBE_NORMAL))
				|| (dev->heartbeat_count <= STARTUP_MODE_DURATION && timeout_seconds(TIMER_INTERVAL_PROBE_STARTUP)))
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
	struct sockaddr_in sin4;
	struct sockaddr_in6 sin6;
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
	int i, j, isize, best_server, current_server;
	int turn = 0;
	int ready = 0, do_change = 0;
	char check_order[NUMBER_SERVERS];
	int mlen;

	struct request *last_request = (struct request *)123, *cur_request = (struct request *)456;

	struct timeval timeout;
	timeout.tv_sec = SOCKET_TIMEOUT_CLIENT_DISCOVERY;
	timeout.tv_usec = 0;

	memset(&sin4, 0, sizeof(sin4));
	memset(&sin6, 0, sizeof(sin6));

	init_msghdr(msg);

	buf = kmalloc(4096, GFP_KERNEL);
	if (!buf)
	{
		debug_dev("FATAL: Kmalloc failed (discover)");
		return -1;
	}
	payload = (serialized_buffer_t *)buf; // Reuse this buffer to save kernel mem

	dnbd3_request.magic = dnbd3_packet_magic;

	for (i = 0; i < NUMBER_SERVERS; ++i) {
		check_order[i] = i;
	}

	for (;;)
	{
		wait_event_interruptible(dev->process_queue_discover,
		   kthread_should_stop() || dev->discover || dev->thread_discover == NULL);

		if (kthread_should_stop() || dev->imgname == NULL || dev->thread_discover == NULL )
			break;

		if (!dev->discover)
			continue;
		dev->discover = 0;

		if (dev->reported_size < 4096)
			continue;

		// Check if the list of alt servers needs to be updated and do so if necessary
		if (dev->new_servers_num)
		{
			spin_lock_irqsave(&dev->blk_lock, irqflags);
			for (i = 0; i < dev->new_servers_num; ++i)
			{
				if (dev->new_servers[i].host.type != AF_INET && dev->new_servers[i].host.type != AF_INET6) // Invalid entry?
					continue;
				alt_server = get_existing_server(&dev->new_servers[i], dev);
				if (alt_server != NULL ) // Server already known
				{
					if (dev->new_servers[i].failures == 1)
					{
						// REMOVE request
						if (alt_server->host.type == AF_INET)
							debug_dev_va("Removing alt server %pI4", alt_server->host.addr);
						else
							debug_dev_va("Removing alt server %pI6", alt_server->host.addr);
						alt_server->host.type = 0;
						continue;
					}
					// ADD, so just reset fail counter
					alt_server->failures = 0;
					continue;
				}
				if (dev->new_servers[i].failures == 1) // REMOVE, but server is not in list anyways
					continue;
				alt_server = get_free_alt_server(dev);
				if (alt_server == NULL ) // All NUMBER_SERVERS slots are taken, ignore entry
					continue;
				// Add new server entry
				alt_server->host = dev->new_servers[i].host;
				if (alt_server->host.type == AF_INET)
					debug_dev_va("Adding alt server %pI4", alt_server->host.addr);
				else
					debug_dev_va("Adding alt server %pI6", alt_server->host.addr);
				alt_server->rtts[0] = alt_server->rtts[1] = alt_server->rtts[2] = alt_server->rtts[3] = RTT_UNREACHABLE;
				alt_server->protocol_version = 0;
				alt_server->failures = 0;
			}
			dev->new_servers_num = 0;
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		}

		current_server = best_server = -1;
		best_rtt = 0xFFFFFFFul;

		if (dev->heartbeat_count < STARTUP_MODE_DURATION || dev->panic)
		{
			isize = NUMBER_SERVERS;
		}
		else
		{
			isize = 3;
		}
		if (NUMBER_SERVERS > isize) {
			for (i = 0; i < isize; ++i) {
				j = ((start.tv_sec >> i) ^ (start.tv_usec >> j)) % NUMBER_SERVERS;
				if (j != i) {
					mlen = check_order[i];
					check_order[i] = check_order[j];
					check_order[j] = mlen;
				}
			}
		}

		for (j = 0; j < NUMBER_SERVERS; ++j)
		{
			i = check_order[j];
			if (dev->alt_servers[i].host.type == 0) // Empty slot
				continue;
			if (!dev->panic && dev->alt_servers[i].failures > 50 && (start.tv_usec & 7) != 0) // If not in panic mode, skip server if it failed too many times
				continue;
			if (isize-- <= 0 && !is_same_server(&dev->cur_server, &dev->alt_servers[i]))
				continue;

			// Initialize socket and connect
			if (sock_create_kern(dev->alt_servers[i].host.type, SOCK_STREAM, IPPROTO_TCP, &sock) < 0)
			{
				debug_alt("ERROR: Couldn't create socket (discover).");
				sock = NULL;
				continue;
			}
			kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
			kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
			sock->sk->sk_allocation = GFP_NOIO;
			if (dev->alt_servers[i].host.type == AF_INET)
			{
				sin4.sin_family = AF_INET;
				memcpy(&sin4.sin_addr, dev->alt_servers[i].host.addr, 4);
				sin4.sin_port = dev->alt_servers[i].host.port;
				if (kernel_connect(sock, (struct sockaddr *)&sin4, sizeof(sin4), 0) < 0)
					goto error;
			}
			else
			{
				sin6.sin6_family = AF_INET6;
				memcpy(&sin6.sin6_addr, dev->alt_servers[i].host.addr, 16);
				sin6.sin6_port = dev->alt_servers[i].host.port;
				if (kernel_connect(sock, (struct sockaddr *)&sin6, sizeof(sin6), 0) < 0)
					goto error;
			}

			// Request filesize
			dnbd3_request.cmd = CMD_SELECT_IMAGE;
			iov[0].iov_base = &dnbd3_request;
			iov[0].iov_len = sizeof(dnbd3_request);
			serializer_reset_write(payload);
			serializer_put_uint16(payload, PROTOCOL_VERSION); // DNBD3 protocol version
			serializer_put_string(payload, dev->imgname); // image name
			serializer_put_uint16(payload, dev->rid); // revision id
			serializer_put_uint8(payload, 0); // are we a server? (no!)
			iov[1].iov_base = payload;
			dnbd3_request.size = iov[1].iov_len = serializer_get_written_length(payload);
			fixup_request(dnbd3_request);
			mlen = iov[1].iov_len + sizeof(dnbd3_request);
			if (kernel_sendmsg(sock, &msg, iov, 2, mlen) != mlen)
				error_alt("ERROR: Requesting image size failed.");

			// receive net reply
			iov[0].iov_base = &dnbd3_reply;
			iov[0].iov_len = sizeof(dnbd3_reply);
			if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
				error_alt("ERROR: Receiving image size packet (header) failed (discover).");
			fixup_reply(dnbd3_reply);
			if (dnbd3_reply.magic != dnbd3_packet_magic || dnbd3_reply.cmd != CMD_SELECT_IMAGE || dnbd3_reply.size < 4)
				error_alt("ERROR: Content of image size packet (header) mismatched (discover).");

			// receive data
			iov[0].iov_base = payload;
			iov[0].iov_len = dnbd3_reply.size;
			if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size)
				error_alt("ERROR: Receiving image size packet (payload) failed (discover).");
			serializer_reset_read(payload, dnbd3_reply.size);

			dev->alt_servers[i].protocol_version = serializer_get_uint16(payload);
			if (dev->alt_servers[i].protocol_version < MIN_SUPPORTED_SERVER)
				error_alt_va("ERROR: Server version too old (client: %d, server: %d, min supported: %d).",
				   (int)PROTOCOL_VERSION, (int)dev->alt_servers[i].protocol_version, (int)MIN_SUPPORTED_SERVER);

			name = serializer_get_string(payload);
			if (name == NULL )
				error_alt("ERROR: Server did not supply an image name (discover).");

			if (strcmp(name, dev->imgname) != 0)
				error_alt_va("ERROR: Image name does not match requested one (client: '%s', server: '%s') (discover).",
				   dev->imgname, name);

			rid = serializer_get_uint16(payload);
			if (rid != dev->rid)
				error_alt_va("ERROR: Server supplied wrong rid (client: '%d', server: '%d') (discover).",
				   (int)dev->rid, (int)rid);

			filesize = serializer_get_uint64(payload);
			if (filesize != dev->reported_size)
				error_alt_va("ERROR: Reported image size of %llu does not match expected value %llu.(discover).",
				   (unsigned long long)filesize, (unsigned long long)dev->reported_size);

			// panic mode, take first responding server
			if (dev->panic)
			{
				dev->panic = 0;
				debug_alt("WARN: Panic mode, changing server:");
				if (best_sock != NULL )
					sock_release(best_sock);
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
			if (dev->reported_size == 0)
			{
				dnbd3_request.offset = 0;
			}
			else if (sizeof(size_t) >= 8)
			{
				dnbd3_request.offset = ((((start.tv_sec << 12) ^ start.tv_usec) << 4) % dev->reported_size)
				   & ~(uint64_t)(RTT_BLOCK_SIZE - 1);
				//printk("Random offset 64bit: %lluMiB\n", (unsigned long long)(dnbd3_request.offset >> 20));
			}
			else // On 32bit, prevent modulo on a 64bit data type. This limits the random block picking to the first 4GB of the image
			{
				dnbd3_request.offset = ((((start.tv_sec << 12) ^ start.tv_usec) << 4) % (uint32_t)dev->reported_size)
				   & ~(RTT_BLOCK_SIZE - 1);
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
			if (dnbd3_reply.magic
			   != dnbd3_packet_magic|| dnbd3_reply.cmd != CMD_GET_BLOCK || dnbd3_reply.size != RTT_BLOCK_SIZE)
				error_alt_va("ERROR: Unexpected reply to block request: cmd=%d, size=%d (discover).",
				   (int)dnbd3_reply.cmd, (int)dnbd3_reply.size);

			// receive data
			iov[0].iov_base = buf;
			iov[0].iov_len = RTT_BLOCK_SIZE;
			if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != RTT_BLOCK_SIZE)
				error_alt("ERROR: Receiving test block payload failed (discover).");

			do_gettimeofday(&end); // end rtt measurement

			dev->alt_servers[i].rtts[turn] = (unsigned long)((end.tv_sec - start.tv_sec) * 1000000ull
			   + (end.tv_usec - start.tv_usec));

			rtt = (dev->alt_servers[i].rtts[0] + dev->alt_servers[i].rtts[1] + dev->alt_servers[i].rtts[2]
			   + dev->alt_servers[i].rtts[3]) / 4;

			if (best_rtt > rtt)
			{
				// This one is better, keep socket open in case we switch
				best_rtt = rtt;
				best_server = i;
				if (best_sock != NULL )
					sock_release(best_sock);
				best_sock = sock;
				sock = NULL;
			}
			else
			{
				// Not better, discard connection
				sock_release(sock);
				sock = NULL;
			}

			// update cur servers rtt
			if (is_same_server(&dev->cur_server, &dev->alt_servers[i]))
			{
				dev->cur_rtt = rtt;
				current_server = i;
			}

			dev->alt_servers[i].failures = 0;

			continue;

			error: ;
			++dev->alt_servers[i].failures;
			sock_release(sock);
			sock = NULL;
			dev->alt_servers[i].rtts[turn] = RTT_UNREACHABLE;
			if (is_same_server(&dev->cur_server, &dev->alt_servers[i]))
			{
				dev->cur_rtt = RTT_UNREACHABLE;
				current_server = i;
			}
			continue;
		}

		if (dev->panic)
		{
			// After 21 retries, bail out by reporting errors to block layer
			if (dev->panic_count < 255 && ++dev->panic_count == PROBE_COUNT_TIMEOUT + 1)
				dnbd3_blk_fail_all_requests(dev);
		}

		if (best_server == -1 || kthread_should_stop() || dev->thread_discover == NULL ) // No alt server could be reached at all or thread should stop
		{
			if (best_sock != NULL ) // Should never happen actually
			{
				sock_release(best_sock);
				best_sock = NULL;
			}
			continue;
		}

		do_change = !dev->is_server && ready && best_server != current_server && (start.tv_usec & 3) != 0
				   && RTT_THRESHOLD_FACTOR(dev->cur_rtt) > best_rtt + 1500;

		if (ready && !do_change) {
			spin_lock_irqsave(&dev->blk_lock, irqflags);
			if (!list_empty(&dev->request_queue_send))
			{
				cur_request = list_entry(dev->request_queue_send.next, struct request, queuelist);
				do_change = (cur_request == last_request);
				if (do_change)
					printk("WARNING: Hung request on %s\n", dev->disk->disk_name);
			}
			else
			{
				cur_request = (struct request *)123;
			}
			last_request = cur_request;
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		}

		// take server with lowest rtt (only if in client mode)
		if (do_change)
		{
			printk("INFO: Server %d on %s is faster (%lluµs vs. %lluµs)\n", best_server, dev->disk->disk_name,
			   (unsigned long long)best_rtt, (unsigned long long)dev->cur_rtt);
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
		if (best_sock != NULL )
		{
			sock_release(best_sock);
			best_sock = NULL;
		}

		if (!ready || (start.tv_usec & 7) != 0)
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
	struct request *blk_request, *tmp_request;

	dnbd3_request_t dnbd3_request;
	struct msghdr msg;
	struct kvec iov;

	unsigned long irqflags;

	init_msghdr(msg);

	dnbd3_request.magic = dnbd3_packet_magic;

	set_user_nice(current, -20);

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

	for (;;)
	{
		wait_event_interruptible(dev->process_queue_send, kthread_should_stop() || !list_empty(&dev->request_queue_send));

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
			debug_dev("ERROR: Connection to server lost (send)");
			goto error;
		}
		wake_up(&dev->process_queue_receive);
	}

	dev->thread_send = NULL;
	return 0;

	error: ;
	if (dev->sock)
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);
	if (!dev->disconnecting)
	{
		dev->panic = 1;
		dev->discover = 1;
		wake_up(&dev->process_queue_discover);
	}
	dev->thread_send = NULL;
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
			error_dev_va("ERROR: Connection to server lost (receive)", ret);
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
			if (blk_request == NULL )
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
					sigprocmask(SIG_SETMASK, &oldset, NULL );
					error_dev("ERROR: Receiving from net to block layer.");
				}
				kunmap(bvec->bv_page);

				sigprocmask(SIG_SETMASK, &oldset, NULL );
			}
			spin_lock_irqsave(&dev->blk_lock, irqflags);
			list_del_init(&blk_request->queuelist);
			__blk_end_request_all(blk_request, 0);
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			continue;

		case CMD_GET_SERVERS:
			if (dev->is_server || !is_same_server(&dev->cur_server, &dev->initial_server))
			{
				// If not connected to initial server, or device is in proxy mode, ignore this message
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
				if (kernel_recvmsg(dev->sock, &msg, &iov, 1, (count * sizeof(dnbd3_server_entry_t)), msg.msg_flags)
				   != (count * sizeof(dnbd3_server_entry_t)))
					error_dev("ERROR: Recv CMD_GET_SERVERS payload.");
				spin_lock_irqsave(&dev->blk_lock, irqflags);
				dev->new_servers_num = count;
				spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			}
			// If there were more servers than accepted, remove the remaining data from the socket buffer
			remaining = dnbd3_reply.size - (count * sizeof(dnbd3_server_entry_t));
			clear_remaining_payload: while (remaining > 0)
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
	dev->thread_receive = NULL;
	return 0;

	error:
	if (dev->sock)
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);
	if (!dev->disconnecting)
	{
		dev->panic = 1;
		dev->discover = 1;
		wake_up(&dev->process_queue_discover);
	}
	dev->thread_receive = NULL;
	return -1;
}

