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
#include "net.h"
#include "blk.h"
#include "utils.h"

#include <dnbd3/shared/serialize.h>

#include <linux/time.h>
#include <linux/ktime.h>

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ktime_to_s
#define ktime_to_s(kt) ktime_divns(kt, NSEC_PER_SEC)
#endif

#define dnbd3_sock_create(af,type,proto,sock) sock_create_kern(&init_net, (af) == HOST_IP4 ? AF_INET : AF_INET6, type, proto, sock)

// cmd_flags and cmd_type are merged into cmd_flags now
#if REQ_FLAG_BITS > 24
#error "Fix CMD bitshift"
#endif
// Pack into cmd_flags field by shifting CMD_* into unused bits of cmd_flags
#define dnbd3_cmd_to_priv(req, cmd)   (req)->cmd_flags = REQ_OP_DRV_IN | ((cmd) << REQ_FLAG_BITS)
#define dnbd3_priv_to_cmd(req)        ((req)->cmd_flags >> REQ_FLAG_BITS)
#define dnbd3_req_op(req)             req_op(req)
#define DNBD3_DEV_READ REQ_OP_READ
#define DNBD3_REQ_OP_SPECIAL REQ_OP_DRV_IN

/**
 * Some macros for easier debug output.
 * Server IP:port info will be printed.
 */
#define __dnbd3_dev_dbg_host(dev, host, fmt, ...) do { \
	if ((host).type == HOST_IP4) { \
		dev_dbg(dnbd3_device_to_dev((dev)), "(%pI4:%d): "   fmt, (host).addr, (int)ntohs((host).port) __VA_OPT__(,) __VA_ARGS__); \
	} else { \
		dev_dbg(dnbd3_device_to_dev((dev)), "([%pI6]:%d): " fmt, (host).addr, (int)ntohs((host).port) __VA_OPT__(,) __VA_ARGS__); \
	} \
} while (0)

#define __dnbd3_dev_err_host(dev, host, fmt, ...) do { \
	if ((host).type == HOST_IP4) { \
		dev_err(dnbd3_device_to_dev((dev)), "(%pI4:%d): "   fmt, (host).addr, (int)ntohs((host).port) __VA_OPT__(,) __VA_ARGS__); \
	} else { \
		dev_err(dnbd3_device_to_dev((dev)), "([%pI6]:%d): " fmt, (host).addr, (int)ntohs((host).port) __VA_OPT__(,) __VA_ARGS__); \
	} \
} while (0)

#define dnbd3_dev_dbg_host_cur(dev, fmt, ...) __dnbd3_dev_dbg_host((dev), (dev)->cur_server.host,     fmt __VA_OPT__(,) __VA_ARGS__)
#define dnbd3_dev_err_host_cur(dev, fmt, ...) __dnbd3_dev_err_host((dev), (dev)->cur_server.host,     fmt __VA_OPT__(,) __VA_ARGS__)
#define dnbd3_dev_dbg_host_alt(dev, fmt, ...) __dnbd3_dev_dbg_host((dev), (dev)->alt_servers[i].host, fmt __VA_OPT__(,) __VA_ARGS__)
#define dnbd3_dev_err_host_alt(dev, fmt, ...) __dnbd3_dev_err_host((dev), (dev)->alt_servers[i].host, fmt __VA_OPT__(,) __VA_ARGS__)

static inline int is_same_server(const dnbd3_server_t * const a, const dnbd3_server_t * const b)
{
	return (a->host.type == b->host.type) && (a->host.port == b->host.port)
	   && (0 == memcmp(a->host.addr, b->host.addr, (a->host.type == HOST_IP4 ? 4 : 16)));
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
		      == memcmp(newserver->host.addr, dev->alt_servers[i].host.addr, (newserver->host.type == HOST_IP4 ? 4 : 16))))
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

static void dnbd3_net_heartbeat(struct timer_list *arg)
{
	dnbd3_device_t *dev = (dnbd3_device_t *)container_of(arg, dnbd3_device_t, hb_timer);

	// Because different events need different intervals, the timer is called once a second.
	// Other intervals can be derived using dev->heartbeat_count.
#define timeout_seconds(x) (dev->heartbeat_count % (x) == 0)

	if (!dev->panic)
	{
		if (timeout_seconds(TIMER_INTERVAL_KEEPALIVE_PACKET))
		{
			struct request *req = kmalloc(sizeof(struct request), GFP_ATOMIC );
			// send keepalive
			if (req)
			{
				dnbd3_cmd_to_priv(req, CMD_KEEPALIVE);
				list_add_tail(&req->queuelist, &dev->request_queue_send);
				wake_up(&dev->process_queue_send);
			}
			else
			{
				dev_err(dnbd3_device_to_dev(dev), "couldn't create keepalive request\n");
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

static int dnbd3_net_discover(void *data)
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

	ktime_t start = 0, end = 0;
	unsigned long rtt, best_rtt = 0;
	unsigned long irqflags;
	int i, j, isize, best_server, current_server;
	int turn = 0;
	int ready = 0, do_change = 0;
	char check_order[NUMBER_SERVERS];
	int mlen;

	struct request *last_request = (struct request *)123, *cur_request = (struct request *)456;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
	struct __kernel_sock_timeval timeout;
#else
	struct timeval timeout;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
	sockptr_t timeout_ptr;
#else
	char *timeout_ptr;
#endif

	timeout.tv_sec = SOCKET_TIMEOUT_CLIENT_DISCOVERY;
	timeout.tv_usec = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
	timeout_ptr = KERNEL_SOCKPTR(&timeout);
#else
	timeout_ptr = (char *)&timeout;
#endif

	memset(&sin4, 0, sizeof(sin4));
	memset(&sin6, 0, sizeof(sin6));

	init_msghdr(msg);

	buf = kmalloc(4096, GFP_KERNEL);
	if (!buf)
	{
		dev_err(dnbd3_device_to_dev(dev), "kmalloc failed for payload buf (discover)\n");
		return -1;
	}
	payload = (serialized_buffer_t *)buf; // Reuse this buffer to save kernel mem

	dnbd3_request.magic = dnbd3_packet_magic;

	for (i = 0; i < NUMBER_SERVERS; ++i) {
		check_order[i] = i;
	}

	while (!kthread_should_stop())
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
		spin_lock_irqsave(&dev->blk_lock, irqflags);
		if (dev->new_servers_num)
		{
			for (i = 0; i < dev->new_servers_num; ++i)
			{
				if (dev->new_servers[i].host.type != HOST_IP4 && dev->new_servers[i].host.type != HOST_IP6) // Invalid entry?
					continue;
				alt_server = get_existing_server(&dev->new_servers[i], dev);
				if (alt_server != NULL ) // Server already known
				{
					if (dev->new_servers[i].failures == 1)
					{
						// REMOVE request
						if (alt_server->host.type == HOST_IP4)
							dnbd3_dev_dbg_host_cur(dev, "removing alt server %pI4\n",   alt_server->host.addr);
						else
							dnbd3_dev_dbg_host_cur(dev, "removing alt server [%pI6]\n", alt_server->host.addr);
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
				if (alt_server->host.type == HOST_IP4)
					dnbd3_dev_dbg_host_cur(dev, "adding alt server %pI4\n",   alt_server->host.addr);
				else
					dnbd3_dev_dbg_host_cur(dev, "adding alt server [%pI6]\n", alt_server->host.addr);
				alt_server->rtts[0] = alt_server->rtts[1] = alt_server->rtts[2] = alt_server->rtts[3] = RTT_UNREACHABLE;
				alt_server->protocol_version = 0;
				alt_server->failures = 0;
			}
			dev->new_servers_num = 0;
		}
		spin_unlock_irqrestore(&dev->blk_lock, irqflags);

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
				j = ((ktime_to_s(start) >> i) ^ (ktime_to_us(start) >> j)) % NUMBER_SERVERS;
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
			if (!dev->panic && dev->alt_servers[i].failures > 50 && (ktime_to_us(start) & 7) != 0) // If not in panic mode, skip server if it failed too many times
				continue;
			if (isize-- <= 0 && !is_same_server(&dev->cur_server, &dev->alt_servers[i]))
				continue;

			// Initialize socket and connect
			if (dnbd3_sock_create(dev->alt_servers[i].host.type, SOCK_STREAM, IPPROTO_TCP, &sock) < 0)
			{
				dnbd3_dev_err_host_alt(dev, "couldn't create socket (discover)\n");
				sock = NULL;
				continue;
			}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
			sock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO_NEW, timeout_ptr, sizeof(timeout));
			sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_NEW, timeout_ptr, sizeof(timeout));
#else
			sock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, timeout_ptr, sizeof(timeout));
			sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, timeout_ptr, sizeof(timeout));
#endif
			sock->sk->sk_allocation = GFP_NOIO;
			if (dev->alt_servers[i].host.type == HOST_IP4)
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
			{
				dnbd3_dev_err_host_alt(dev, "requesting image size failed\n");
				goto error;
			}

			// receive net reply
			iov[0].iov_base = &dnbd3_reply;
			iov[0].iov_len = sizeof(dnbd3_reply);
			if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
			{
				dnbd3_dev_err_host_alt(dev, "receiving image size packet (header) failed (discover)\n");
				goto error;
			}
			fixup_reply(dnbd3_reply);
			if (dnbd3_reply.magic != dnbd3_packet_magic || dnbd3_reply.cmd != CMD_SELECT_IMAGE || dnbd3_reply.size < 4)
			{
				dnbd3_dev_err_host_alt(dev, "content of image size packet (header) mismatched (discover)\n");
				goto error;
			}

			// receive data
			iov[0].iov_base = payload;
			iov[0].iov_len = dnbd3_reply.size;
			if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size)
			{
				dnbd3_dev_err_host_alt(dev, "receiving image size packet (payload) failed (discover)\n");
				goto error;
			}
			serializer_reset_read(payload, dnbd3_reply.size);

			dev->alt_servers[i].protocol_version = serializer_get_uint16(payload);
			if (dev->alt_servers[i].protocol_version < MIN_SUPPORTED_SERVER)
			{
				dnbd3_dev_err_host_alt(dev, "server version too old (client: %d, server: %d, min supported: %d)\n",
				   (int)PROTOCOL_VERSION, (int)dev->alt_servers[i].protocol_version, (int)MIN_SUPPORTED_SERVER);
				goto error;
			}

			name = serializer_get_string(payload);
			if (name == NULL )
			{
				dnbd3_dev_err_host_alt(dev, "server did not supply an image name (discover)\n");
				goto error;
			}

			if (strcmp(name, dev->imgname) != 0)
			{
				dnbd3_dev_err_host_alt(dev, "image name does not match requested one (client: '%s', server: '%s') (discover)\n",
				   dev->imgname, name);
				goto error;
			}

			rid = serializer_get_uint16(payload);
			if (rid != dev->rid)
			{
				dnbd3_dev_err_host_alt(dev, "server supplied wrong rid (client: '%d', server: '%d') (discover)\n",
				   (int)dev->rid, (int)rid);
				goto error;
			}

			filesize = serializer_get_uint64(payload);
			if (filesize != dev->reported_size)
			{
				dnbd3_dev_err_host_alt(dev, "reported image size of %llu does not match expected value %llu (discover)\n",
				   (unsigned long long)filesize, (unsigned long long)dev->reported_size);
				goto error;
			}

			// panic mode, take first responding server
			if (dev->panic)
			{
				dev->panic = 0;
				dnbd3_dev_dbg_host_alt(dev, "panic mode, changing server ...\n");
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
			// Do *NOT* pick a random block as it has proven to cause severe
			// cache thrashing on the server
			dnbd3_request.offset = 0;
			dnbd3_request.size = RTT_BLOCK_SIZE;
			fixup_request(dnbd3_request);
			iov[0].iov_base = &dnbd3_request;
			iov[0].iov_len = sizeof(dnbd3_request);

			// start rtt measurement
			start = ktime_get_real();

			if (kernel_sendmsg(sock, &msg, iov, 1, sizeof(dnbd3_request)) <= 0)
			{
				dnbd3_dev_err_host_alt(dev, "requesting test block failed (discover)\n");
				goto error;
			}

			// receive net reply
			iov[0].iov_base = &dnbd3_reply;
			iov[0].iov_len = sizeof(dnbd3_reply);
			if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
			{
				dnbd3_dev_err_host_alt(dev, "receiving test block header packet failed (discover)\n");
				goto error;
			}
			fixup_reply(dnbd3_reply);
			if (dnbd3_reply.magic
			   != dnbd3_packet_magic|| dnbd3_reply.cmd != CMD_GET_BLOCK || dnbd3_reply.size != RTT_BLOCK_SIZE)
			{
				dnbd3_dev_err_host_alt(dev, "unexpected reply to block request: cmd=%d, size=%d (discover)\n",
				   (int)dnbd3_reply.cmd, (int)dnbd3_reply.size);
				goto error;
			}

			// receive data
			iov[0].iov_base = buf;
			iov[0].iov_len = RTT_BLOCK_SIZE;
			if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != RTT_BLOCK_SIZE)
			{
				dnbd3_dev_err_host_alt(dev, "receiving test block payload failed (discover)\n");
				goto error;
			}

			end = ktime_get_real(); // end rtt measurement

			dev->alt_servers[i].rtts[turn] = (unsigned long) ktime_us_delta(end, start);

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
			if (PROBE_COUNT_TIMEOUT > 0 && dev->panic_count < 255 && ++dev->panic_count == PROBE_COUNT_TIMEOUT + 1)
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

		do_change = ready && best_server != current_server && (ktime_to_us(start) & 3) != 0
				   && RTT_THRESHOLD_FACTOR(dev->cur_rtt) > best_rtt + 1500;

		if (ready && !do_change) {
			spin_lock_irqsave(&dev->blk_lock, irqflags);
			if (!list_empty(&dev->request_queue_send))
			{
				cur_request = list_entry(dev->request_queue_send.next, struct request, queuelist);
				do_change = (cur_request == last_request);
				if (do_change)
					dev_warn(dnbd3_device_to_dev(dev), "hung request\n");
			}
			else
			{
				cur_request = (struct request *)123;
			}
			last_request = cur_request;
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		}

		// take server with lowest rtt
		if (do_change)
		{
			dev_info(dnbd3_device_to_dev(dev), "server %d is faster (%lluµs vs. %lluµs)\n", best_server,
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

		if (!ready || (ktime_to_us(start) & 15) != 0)
			turn = (turn + 1) % 4;
		if (turn == 2) // Set ready when we only have 2 of 4 measurements for quicker load balancing
			ready = 1;

	}

	kfree(buf);
	dev_dbg(dnbd3_device_to_dev(dev), "kthread dnbd3_net_discover terminated normally\n");
	dev->thread_discover = NULL;
	return 0;
}

static int dnbd3_net_send(void *data)
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
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	if (!list_empty(&dev->request_queue_receive))
	{
		dev_warn(dnbd3_device_to_dev(dev), "request queue was not empty");
		list_for_each_entry_safe(blk_request, tmp_request, &dev->request_queue_receive, queuelist)
		{
			list_del_init(&blk_request->queuelist);
			list_add(&blk_request->queuelist, &dev->request_queue_send);
		}
	}
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);

	while (!kthread_should_stop())
	{
		wait_event_interruptible(dev->process_queue_send, kthread_should_stop() || !list_empty(&dev->request_queue_send));

		if (kthread_should_stop())
			break;

		// extract block request
		/* lock since we aquire a blk request from the request_queue_send */
		spin_lock_irqsave(&dev->blk_lock, irqflags);
		if (list_empty(&dev->request_queue_send))
		{
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			continue;
		}
		blk_request = list_entry(dev->request_queue_send.next, struct request, queuelist);

		// what to do?
		switch (dnbd3_req_op(blk_request))
		{
		case DNBD3_DEV_READ:
			dnbd3_request.cmd = CMD_GET_BLOCK;
			dnbd3_request.offset = blk_rq_pos(blk_request) << 9; // *512
			dnbd3_request.size = blk_rq_bytes(blk_request); // bytes left to complete entire request
			// enqueue request to request_queue_receive
			list_del_init(&blk_request->queuelist);
			list_add_tail(&blk_request->queuelist, &dev->request_queue_receive);
			break;
		case DNBD3_REQ_OP_SPECIAL:
			dnbd3_request.cmd = dnbd3_priv_to_cmd(blk_request);
			dnbd3_request.size = 0;
			list_del_init(&blk_request->queuelist);
			break;

		default:
			dev_err(dnbd3_device_to_dev(dev), "unknown command (send %u %u)\n", (int)blk_request->cmd_flags, (int)dnbd3_req_op(blk_request));
			list_del_init(&blk_request->queuelist);
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			continue;
		}

		// send net request
		dnbd3_request.handle = (uint64_t)(uintptr_t)blk_request; // Double cast to prevent warning on 32bit
		spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		fixup_request(dnbd3_request);
		iov.iov_base = &dnbd3_request;
		iov.iov_len = sizeof(dnbd3_request);
		if (kernel_sendmsg(dev->sock, &msg, &iov, 1, sizeof(dnbd3_request)) != sizeof(dnbd3_request))
		{
			dnbd3_dev_err_host_cur(dev, "connection to server lost (send)\n");
			goto error;
		}
	}

	dev_dbg(dnbd3_device_to_dev(dev), "kthread dnbd3_net_send terminated normally\n");
	dev->thread_send = NULL;
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
	dev_err(dnbd3_device_to_dev(dev), "kthread dnbd3_net_send terminated abnormally\n");
	dev->thread_send = NULL;
	return -1;
}

static int dnbd3_net_receive(void *data)
{
	dnbd3_device_t *dev = data;
	struct request *blk_request, *tmp_request, *received_request;

	dnbd3_reply_t dnbd3_reply;
	struct msghdr msg;
	struct kvec iov;
	struct req_iterator iter;
	struct bio_vec bvec_inst;
	struct bio_vec *bvec = &bvec_inst;
	void *kaddr;
	unsigned long irqflags;
	uint16_t rid;
	unsigned long int recv_timeout = jiffies;

	int count, remaining, ret = 0;

	init_msghdr(msg);
	set_user_nice(current, -20);

	while (!kthread_should_stop())
	{
		// receive net reply
		iov.iov_base = &dnbd3_reply;
		iov.iov_len = sizeof(dnbd3_reply);
		ret = kernel_recvmsg(dev->sock, &msg, &iov, 1, sizeof(dnbd3_reply), msg.msg_flags);

		/* end thread after socket timeout or reception of data */
		if (kthread_should_stop())
			break;

		/* check return value of kernel_recvmsg() */
		if (ret == 0)
		{
			/* have not received any data, but remote peer is shutdown properly */
			dnbd3_dev_dbg_host_cur(dev, "remote peer has performed an orderly shutdown\n");
			goto cleanup;
		}
		else if (ret < 0)
		{
			if (ret == -EAGAIN)
			{
				if (jiffies < recv_timeout) recv_timeout = jiffies; // Handle overflow
				if ((jiffies - recv_timeout) / HZ > SOCKET_KEEPALIVE_TIMEOUT)
				{
					dnbd3_dev_err_host_cur(dev, "receive timeout reached (%d of %d secs)\n", (int)((jiffies - recv_timeout) / HZ), (int)SOCKET_KEEPALIVE_TIMEOUT);
					ret = -ETIMEDOUT;
					goto cleanup;
				}
				continue;
			} else {
				/* for all errors other than -EAGAIN, print message and abort thread */
				dnbd3_dev_err_host_cur(dev, "connection to server lost (receive)\n");
				ret = -ESHUTDOWN;
				goto cleanup;
			}
		}

		/* check if arrived data is valid */
		if (ret != sizeof(dnbd3_reply))
		{
			dnbd3_dev_err_host_cur(dev, "recv msg header\n");
			ret = -EINVAL;
			goto cleanup;
		}
		fixup_reply(dnbd3_reply);

		// check error
		if (dnbd3_reply.magic != dnbd3_packet_magic)
		{
			dnbd3_dev_err_host_cur(dev, "wrong packet magic (receive)\n");
			ret = -EINVAL;
			goto cleanup;
		}
		if (dnbd3_reply.cmd == 0)
		{
			dnbd3_dev_err_host_cur(dev, "command was 0 (Receive)\n");
			ret = -EINVAL;
			goto cleanup;
		}

		// Update timeout
		recv_timeout = jiffies;

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
			{
				dnbd3_dev_err_host_cur(dev, "received block data for unrequested handle (%llu: %llu)\n",
				   (unsigned long long)dnbd3_reply.handle, (unsigned long long)dnbd3_reply.size);
				ret = -EINVAL;
				goto cleanup;
			}
			// receive data and answer to block layer
			rq_for_each_segment(bvec_inst, blk_request, iter)
			{
				kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
				iov.iov_base = kaddr;
				iov.iov_len = bvec->bv_len;
				if (kernel_recvmsg(dev->sock, &msg, &iov, 1, bvec->bv_len, msg.msg_flags) != bvec->bv_len)
				{
					kunmap(bvec->bv_page);
					dnbd3_dev_err_host_cur(dev, "receiving from net to block layer\n");
					ret = -EINVAL;
					goto cleanup;
				}
				kunmap(bvec->bv_page);
			}
			spin_lock_irqsave(&dev->blk_lock, irqflags);
			list_del_init(&blk_request->queuelist);
			blk_mq_end_request(blk_request, BLK_STS_OK);
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			continue;

		case CMD_GET_SERVERS:
			if (!dev->use_server_provided_alts)
			{
				remaining = dnbd3_reply.size;
				goto consume_payload;
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
				{
					dnbd3_dev_err_host_cur(dev, "recv CMD_GET_SERVERS payload\n");
					ret = -EINVAL;
					goto cleanup;
				}
				spin_lock_irqsave(&dev->blk_lock, irqflags);
				dev->new_servers_num = count;
				spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			}
			// If there were more servers than accepted, remove the remaining data from the socket buffer
			remaining = dnbd3_reply.size - (count * sizeof(dnbd3_server_entry_t));
			consume_payload: while (remaining > 0)
			{
				count = MIN(sizeof(dnbd3_reply), remaining); // Abuse the reply struct as the receive buffer
				iov.iov_base = &dnbd3_reply;
				iov.iov_len = count;
				ret = kernel_recvmsg(dev->sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
				if (ret <= 0)
				{
					dnbd3_dev_err_host_cur(dev, "recv additional payload from CMD_GET_SERVERS\n");
					ret = -EINVAL;
					goto cleanup;
				}
				remaining -= ret;
			}
			continue;

		case CMD_LATEST_RID:
			if (dnbd3_reply.size != 2)
			{
				dev_err(dnbd3_device_to_dev(dev), "CMD_LATEST_RID.size != 2\n");
				continue;
			}
			iov.iov_base = &rid;
			iov.iov_len = sizeof(rid);
			if (kernel_recvmsg(dev->sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags) <= 0)
			{
				dev_err(dnbd3_device_to_dev(dev), "could not receive CMD_LATEST_RID payload\n");
			}
			else
			{
				rid = net_order_16(rid);
				dev_info(dnbd3_device_to_dev(dev), "latest rid of %s is %d (currently using %d)\n", dev->imgname, (int)rid, (int)dev->rid);
				dev->update_available = (rid > dev->rid ? 1 : 0);
			}
			continue;

		case CMD_KEEPALIVE:
			if (dnbd3_reply.size != 0)
				dev_err(dnbd3_device_to_dev(dev), "keep alive packet with payload\n");
			continue;

		default:
			dev_err(dnbd3_device_to_dev(dev), "unknown command (receive)\n");
			continue;

		}
	}

	goto out;

cleanup:
	if (dev->sock)
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);
	if (!dev->disconnecting)
	{
		dev->panic = 1;
		dev->discover = 1;
		wake_up(&dev->process_queue_discover);
	}

out:
	if (!ret)
		dev_dbg(dnbd3_device_to_dev(dev), "kthread dnbd3_net_receive terminated normally\n");
	else
		dev_err(dnbd3_device_to_dev(dev), "kthread dnbd3_net_receive terminated abnormally\n");
	dev->thread_receive = NULL;
	return ret;
}

int dnbd3_net_connect(dnbd3_device_t *dev)
{
	struct request *req1 = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
	struct __kernel_sock_timeval timeout;
#else
	struct timeval timeout;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
	sockptr_t timeout_ptr;
#else
	char *timeout_ptr;
#endif

	if (dev->disconnecting)
	{
		dnbd3_dev_dbg_host_cur(dev, "connect: wait for disconnect has finished ...\n");
		set_current_state(TASK_INTERRUPTIBLE);
		while (dev->disconnecting)
			schedule();
		dnbd3_dev_dbg_host_cur(dev, "connect: disconnect is done\n");
	}

	timeout.tv_sec = SOCKET_TIMEOUT_CLIENT_DATA;
	timeout.tv_usec = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
	timeout_ptr = KERNEL_SOCKPTR(&timeout);
#else
	timeout_ptr = (char *)&timeout;
#endif

	// do some checks before connecting
	req1 = kmalloc(sizeof(*req1), GFP_ATOMIC);
	if (!req1)
	{
		dnbd3_dev_err_host_cur(dev, "kmalloc failed\n");
		goto error;
	}

	if (dev->cur_server.host.port == 0 || dev->cur_server.host.type == 0 || dev->imgname == NULL )
	{
		dnbd3_dev_err_host_cur(dev, "host, port or image name not set\n");
		goto error;
	}

	if (dev->sock)
	{
		dnbd3_dev_err_host_cur(dev, "socket already connected\n");
		goto error;
	}

	if (dev->cur_server.host.type != HOST_IP4 && dev->cur_server.host.type != HOST_IP6)
	{
		dnbd3_dev_err_host_cur(dev, "unknown address type %d\n", (int)dev->cur_server.host.type);
		goto error;
	}

	dnbd3_dev_dbg_host_cur(dev, "connecting ...\n");

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

		if (dnbd3_sock_create(dev->cur_server.host.type, SOCK_STREAM, IPPROTO_TCP, &dev->sock) < 0)
		{
			dnbd3_dev_err_host_cur(dev, "couldn't create socket (v6)\n");
			goto error;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
		sock_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO_NEW, timeout_ptr, sizeof(timeout));
		sock_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO_NEW, timeout_ptr, sizeof(timeout));
#else
		sock_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO, timeout_ptr, sizeof(timeout));
		sock_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO, timeout_ptr, sizeof(timeout));
#endif
		dev->sock->sk->sk_allocation = GFP_NOIO;
		if (dev->cur_server.host.type == HOST_IP4)
		{
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			memcpy(&(sin.sin_addr), dev->cur_server.host.addr, 4);
			sin.sin_port = dev->cur_server.host.port;
			if (kernel_connect(dev->sock, (struct sockaddr *)&sin, sizeof(sin), 0) != 0)
			{
				dnbd3_dev_err_host_cur(dev, "connection to host failed (v4)\n");
				goto error;
			}
		}
		else
		{
			struct sockaddr_in6 sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin6_family = AF_INET6;
			memcpy(&(sin.sin6_addr), dev->cur_server.host.addr, 16);
			sin.sin6_port = dev->cur_server.host.port;
			if (kernel_connect(dev->sock, (struct sockaddr *)&sin, sizeof(sin), 0) != 0)
			{
				dnbd3_dev_err_host_cur(dev, "connection to host failed (v6)\n");
			}
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
		serializer_put_uint8(&dev->payload_buffer, 0); // is_server = false
		iov[1].iov_base = &dev->payload_buffer;
		dnbd3_request.size = iov[1].iov_len = serializer_get_written_length(&dev->payload_buffer);
		fixup_request(dnbd3_request);
		mlen = sizeof(dnbd3_request) + iov[1].iov_len;
		if (kernel_sendmsg(dev->sock, &msg, iov, 2, mlen) != mlen)
		{
			dnbd3_dev_err_host_cur(dev, "couldn't send CMD_SIZE_REQUEST\n");
			goto error;
		}
		// receive reply header
		iov[0].iov_base = &dnbd3_reply;
		iov[0].iov_len = sizeof(dnbd3_reply);
		if (kernel_recvmsg(dev->sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) != sizeof(dnbd3_reply))
		{
			dnbd3_dev_err_host_cur(dev, "received corrupted reply header after CMD_SIZE_REQUEST\n");
			goto error;
		}
		// check reply header
		fixup_reply(dnbd3_reply);
		if (dnbd3_reply.cmd != CMD_SELECT_IMAGE || dnbd3_reply.size < 3 || dnbd3_reply.size > MAX_PAYLOAD
		   || dnbd3_reply.magic != dnbd3_packet_magic)
		{
			dnbd3_dev_err_host_cur(dev, "received invalid reply to CMD_SIZE_REQUEST, image doesn't exist on server\n");
			goto error;
		}
		// receive reply payload
		iov[0].iov_base = &dev->payload_buffer;
		iov[0].iov_len = dnbd3_reply.size;
		if (kernel_recvmsg(dev->sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size)
		{
			dnbd3_dev_err_host_cur(dev, "cold not read CMD_SELECT_IMAGE payload on handshake\n");
			goto error;
		}
		// handle/check reply payload
		serializer_reset_read(&dev->payload_buffer, dnbd3_reply.size);
		dev->cur_server.protocol_version = serializer_get_uint16(&dev->payload_buffer);
		if (dev->cur_server.protocol_version < MIN_SUPPORTED_SERVER)
		{
			dnbd3_dev_err_host_cur(dev, "server version is lower than min supported version\n");
			goto error;
		}
		name = serializer_get_string(&dev->payload_buffer);
		if (dev->rid != 0 && strcmp(name, dev->imgname) != 0)
		{
			dnbd3_dev_err_host_cur(dev, "server offers image '%s', requested '%s'\n", name, dev->imgname);
			goto error;
		}
		if (strlen(dev->imgname) < strlen(name))
		{
			dev->imgname = krealloc(dev->imgname, strlen(name) + 1, GFP_ATOMIC );
			if (dev->imgname == NULL)
			{
				dnbd3_dev_err_host_cur(dev, "reallocating buffer for new image name failed\n");
				goto error;
			}
		}
		strcpy(dev->imgname, name);
		rid = serializer_get_uint16(&dev->payload_buffer);
		if (dev->rid != 0 && dev->rid != rid)
		{
			dnbd3_dev_err_host_cur(dev, "server provides rid %d, requested was %d\n", (int)rid, (int)dev->rid);
			goto error;
		}
		dev->rid = rid;
		dev->reported_size = serializer_get_uint64(&dev->payload_buffer);
		if (dev->reported_size < 4096)
		{
			dnbd3_dev_err_host_cur(dev, "reported size by server is < 4096\n");
			goto error;
		}
		// store image information
		set_capacity(dev->disk, dev->reported_size >> 9); /* 512 Byte blocks */
		dnbd3_dev_dbg_host_cur(dev, "filesize: %llu\n", dev->reported_size);
		dev->update_available = 0;
	}
	else // Switching server, connection is already established and size request was executed
	{
		dnbd3_dev_dbg_host_cur(dev, "on-the-fly server change ...\n");
		dev->sock = dev->better_sock;
		dev->better_sock = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
		sock_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO_NEW, timeout_ptr, sizeof(timeout));
		sock_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO_NEW, timeout_ptr, sizeof(timeout));
#else
		sock_setsockopt(dev->sock, SOL_SOCKET, SO_SNDTIMEO, timeout_ptr, sizeof(timeout));
		sock_setsockopt(dev->sock, SOL_SOCKET, SO_RCVTIMEO, timeout_ptr, sizeof(timeout));
#endif
	}

	dev->panic = 0;
	dev->panic_count = 0;

	// Enqueue request to request_queue_send for a fresh list of alt servers
	dnbd3_cmd_to_priv(req1, CMD_GET_SERVERS);
	list_add(&req1->queuelist, &dev->request_queue_send);

	// create required threads
	dev->thread_send = kthread_create(dnbd3_net_send, dev, "%s-send", dev->disk->disk_name);
	dev->thread_receive = kthread_create(dnbd3_net_receive, dev, "%s-receive", dev->disk->disk_name);
	dev->thread_discover = kthread_create(dnbd3_net_discover, dev, "%s-discover", dev->disk->disk_name);

	// start them up
	if (!IS_ERR(dev->thread_send)) {
		get_task_struct(dev->thread_send);
		wake_up_process(dev->thread_send);
	} else {
		dev_err(dnbd3_device_to_dev(dev), "failed to create send thread\n");
		/* reset error to cleanup thread */
		dev->thread_send = NULL;
		goto cleanup_thread;
	}

	if (!IS_ERR(dev->thread_receive)) {
		get_task_struct(dev->thread_receive);
		wake_up_process(dev->thread_receive);
	} else {
		dev_err(dnbd3_device_to_dev(dev), "failed to create receive thread\n");
		/* reset error to cleanup thread */
		dev->thread_receive = NULL;
		goto cleanup_thread;
	}

	if (!IS_ERR(dev->thread_discover)) {
		get_task_struct(dev->thread_discover);
		wake_up_process(dev->thread_discover);
	} else {
		dev_err(dnbd3_device_to_dev(dev), "failed to create discover thread\n");
		/* reset error to cleanup thread */
		dev->thread_discover = NULL;
		goto cleanup_thread;
	}

	wake_up(&dev->process_queue_send);

	// add heartbeat timer
	dev->heartbeat_count = 0;
	timer_setup(&dev->hb_timer, dnbd3_net_heartbeat, 0);
	dev->hb_timer.expires = jiffies + HZ;
	add_timer(&dev->hb_timer);

	return 0;

cleanup_thread:
	dnbd3_net_disconnect(dev);

error:
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
	struct task_struct* thread = NULL;
	bool thread_not_terminated = false;
	int ret = 0;

	if (dev->disconnecting) {
		ret = -EBUSY;
		goto out;
	}

	dev->disconnecting = 1;

	dev_dbg(dnbd3_device_to_dev(dev), "disconnecting device ...\n");

	// clear heartbeat timer
	del_timer(&dev->hb_timer);

	dev->discover = 0;

	if (dev->sock)
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);

	// kill sending and receiving threads
	if (dev->thread_send)
	{
		dnbd3_dev_dbg_host_cur(dev, "stop send thread\n");
		thread = dev->thread_send;
		ret = kthread_stop(thread);
		put_task_struct(thread);
		if (ret == -EINTR) {
			/* thread has never been scheduled and run */
			dev_dbg(dnbd3_device_to_dev(dev), "send thread has never run\n");
		} else {
			/* thread has run, check if it has terminated successfully */
			if (dev->thread_send != NULL) {
				dev_err(dnbd3_device_to_dev(dev), "send thread was not terminated correctly\n");
				thread_not_terminated = true;
			}
		}
	}

	if (dev->thread_receive)
	{
		dnbd3_dev_dbg_host_cur(dev, "stop receive thread\n");
		thread = dev->thread_receive;
		ret = kthread_stop(thread);
		put_task_struct(thread);
		if (ret == -EINTR) {
			/* thread has never been scheduled and run */
			dev_dbg(dnbd3_device_to_dev(dev), "receive thread has never run\n");
		} else {
			/* thread has run, check if it has terminated successfully */
			if (dev->thread_receive != NULL) {
				dev_err(dnbd3_device_to_dev(dev), "receive thread was not terminated correctly\n");
				thread_not_terminated = true;
			}
		}
	}

	if (dev->thread_discover)
	{
		dnbd3_dev_dbg_host_cur(dev, "stop discover thread\n");
		thread = dev->thread_discover;
		ret = kthread_stop(thread);
		put_task_struct(thread);
		if (ret == -EINTR) {
			/* thread has never been scheduled and run */
			dev_dbg(dnbd3_device_to_dev(dev), "discover thread has never run\n");
		} else {
			/* thread has run, check if it has terminated successfully */
			if (dev->thread_discover != NULL) {
				dev_err(dnbd3_device_to_dev(dev), "discover thread was not terminated correctly\n");
				thread_not_terminated = true;
			}
		}
	}

	if (dev->sock)
	{
		sock_release(dev->sock);
		dev->sock = NULL;
	}
	dev->cur_server.host.type = 0;
	dev->cur_server.host.port = 0;

	if (thread_not_terminated) {
		dev_err(dnbd3_device_to_dev(dev), "failed to disconnect device\n");
		ret = -ENODEV;
	} else {
		dev_dbg(dnbd3_device_to_dev(dev), "device is disconnected\n");
		ret = 0;
	}

	dev->disconnecting = 0;

out:
	return ret;
}
