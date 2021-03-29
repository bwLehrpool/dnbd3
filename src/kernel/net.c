// SPDX-License-Identifier: GPL-2.0
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
#include <linux/tcp.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ktime_to_s
#define ktime_to_s(kt) ktime_divns(kt, NSEC_PER_SEC)
#endif

#ifdef CONFIG_DEBUG_DRIVER
#define ASSERT(x)                                                                                                      \
	do {                                                                                                           \
		if (!(x)) {                                                                                            \
			printk(KERN_EMERG "assertion failed %s: %d: %s\n", __FILE__, __LINE__, #x);                    \
			BUG();                                                                                         \
		}                                                                                                      \
	} while (0)
#else
#define ASSERT(x)                                                                                                      \
	do {                                                                                                           \
	} while (0)
#endif

// cmd_flags and cmd_type are merged into cmd_flags now
#if REQ_FLAG_BITS > 24
#error "Fix CMD bitshift"
#endif
// Pack into cmd_flags field by shifting CMD_* into unused bits of cmd_flags
#define dnbd3_cmd_to_priv(req, cmd) ((req)->cmd_flags = REQ_OP_DRV_IN | ((cmd) << REQ_FLAG_BITS))
#define dnbd3_priv_to_cmd(req) ((req)->cmd_flags >> REQ_FLAG_BITS)
#define dnbd3_req_op(req) req_op(req)
#define DNBD3_DEV_READ REQ_OP_READ
#define DNBD3_REQ_OP_SPECIAL REQ_OP_DRV_IN

#define dnbd3_dev_dbg_host_cur(dev, fmt, ...) \
	dev_dbg(dnbd3_device_to_dev(dev), "(%pISpc): " fmt, &(dev)->cur_server.host, ##__VA_ARGS__)
#define dnbd3_dev_err_host_cur(dev, fmt, ...) \
	dev_err(dnbd3_device_to_dev(dev), "(%pISpc): " fmt, &(dev)->cur_server.host, ##__VA_ARGS__)

#define dnbd3_dev_dbg_host_alt(dev, fmt, ...) \
	dev_dbg(dnbd3_device_to_dev(dev), "(%pISpc): " fmt, &(dev)->alt_servers[i].host, ##__VA_ARGS__)
#define dnbd3_dev_err_host_alt(dev, fmt, ...) \
	dev_err(dnbd3_device_to_dev(dev), "(%pISpc): " fmt, &(dev)->alt_servers[i].host, ##__VA_ARGS__)

static struct socket *dnbd3_connect(dnbd3_device_t *dev, struct sockaddr_storage *addr);

static void dnbd3_net_heartbeat(struct timer_list *arg)
{
	dnbd3_device_t *dev = (dnbd3_device_t *)container_of(arg, dnbd3_device_t, hb_timer);

	// Because different events need different intervals, the timer is called once a second.
	// Other intervals can be derived using dev->heartbeat_count.
#define timeout_seconds(x) (dev->heartbeat_count % (x) == 0)

	if (!dev->panic) {
		if (timeout_seconds(TIMER_INTERVAL_KEEPALIVE_PACKET)) {
			struct request *req = kmalloc(sizeof(struct request), GFP_ATOMIC);
			// send keepalive
			if (req) {
				unsigned long irqflags;

				dnbd3_cmd_to_priv(req, CMD_KEEPALIVE);
				spin_lock_irqsave(&dev->blk_lock, irqflags);
				list_add_tail(&req->queuelist, &dev->request_queue_send);
				spin_unlock_irqrestore(&dev->blk_lock, irqflags);
				wake_up(&dev->process_queue_send);
			} else {
				dev_err(dnbd3_device_to_dev(dev), "couldn't create keepalive request\n");
			}
		}
		if ((dev->heartbeat_count > STARTUP_MODE_DURATION && timeout_seconds(TIMER_INTERVAL_PROBE_NORMAL)) ||
		    (dev->heartbeat_count <= STARTUP_MODE_DURATION && timeout_seconds(TIMER_INTERVAL_PROBE_STARTUP))) {
			// Normal discovery
			dev->discover = 1;
			wake_up(&dev->process_queue_discover);
		}
	} else if (timeout_seconds(TIMER_INTERVAL_PROBE_PANIC)) {
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
	dnbd3_alt_server_t *alt;
	struct sockaddr_storage host_compare, best_server;
	struct msghdr msg;
	struct kvec iov[2];

	char *buf, *name;
	serialized_buffer_t *payload;
	uint64_t filesize;
	uint16_t rid;
	uint16_t remote_version;

	ktime_t start = 0, end = 0;
	unsigned long rtt, best_rtt = 0;
	unsigned long irqflags;
	int i, j, isize, fails, rtt_threshold;
	int turn = 0;
	int ready = 0, do_change = 0;
	char check_order[NUMBER_SERVERS];
	int mlen;

	struct request *last_request = (struct request *)123, *cur_request = (struct request *)456;

	memset(&sin4, 0, sizeof(sin4));
	memset(&sin6, 0, sizeof(sin6));

	init_msghdr(msg);

	BUILD_BUG_ON(sizeof(serialized_buffer_t) > DNBD3_BLOCK_SIZE);

	buf = kmalloc(DNBD3_BLOCK_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	payload = (serialized_buffer_t *)buf; // Reuse this buffer to save kernel mem

	dnbd3_request.magic = dnbd3_packet_magic;

	for (i = 0; i < NUMBER_SERVERS; ++i)
		check_order[i] = i;

	while (!kthread_should_stop()) {
		wait_event_interruptible(dev->process_queue_discover,
					 kthread_should_stop() || dev->discover || dev->thread_discover == NULL);

		if (kthread_should_stop() || dev->imgname == NULL || dev->thread_discover == NULL)
			break;

		if (!dev->discover)
			continue;
		dev->discover = 0;

		if (dev->reported_size < 4096)
			continue;

		best_server.ss_family = 0;
		best_rtt = 0xFFFFFFFul;

		if (dev->heartbeat_count < STARTUP_MODE_DURATION || dev->panic)
			isize = NUMBER_SERVERS;
		else
			isize = 3;

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

		for (j = 0; j < NUMBER_SERVERS; ++j) {
			i = check_order[j];
			mutex_lock(&dev->alt_servers_lock);
			host_compare = dev->alt_servers[i].host;
			fails = dev->alt_servers[i].failures;
			mutex_unlock(&dev->alt_servers_lock);
			if (host_compare.ss_family == 0)
				continue; // Empty slot
			if (!dev->panic && fails > 50
				&& (ktime_to_us(start) & 7) != 0)
				continue; // If not in panic mode, skip server if it failed too many times
			if (isize-- <= 0 && !is_same_server(&dev->cur_server.host, &host_compare))
				continue; // Only test isize servers plus current server

			// Initialize socket and connect
			sock = dnbd3_connect(dev, &host_compare);
			if (sock == NULL)
				goto error;

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
			if (kernel_sendmsg(sock, &msg, iov, 2, mlen) != mlen) {
				dnbd3_dev_err_host_alt(dev, "requesting image size failed\n");
				goto error;
			}

			// receive net reply
			iov[0].iov_base = &dnbd3_reply;
			iov[0].iov_len = sizeof(dnbd3_reply);
			if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) !=
			    sizeof(dnbd3_reply)) {
				dnbd3_dev_err_host_alt(dev, "receiving image size packet (header) failed (discover)\n");
				goto error;
			}
			fixup_reply(dnbd3_reply);
			if (dnbd3_reply.magic != dnbd3_packet_magic || dnbd3_reply.cmd != CMD_SELECT_IMAGE ||
			    dnbd3_reply.size < 4) {
				dnbd3_dev_err_host_alt(dev,
						       "content of image size packet (header) mismatched (discover)\n");
				goto error;
			}

			// receive data
			iov[0].iov_base = payload;
			iov[0].iov_len = dnbd3_reply.size;
			if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size) {
				dnbd3_dev_err_host_alt(dev,
						       "receiving image size packet (payload) failed (discover)\n");
				goto error;
			}
			serializer_reset_read(payload, dnbd3_reply.size);

			remote_version = serializer_get_uint16(payload);
			if (remote_version < MIN_SUPPORTED_SERVER) {
				dnbd3_dev_err_host_alt(
					dev, "server version too old (client: %d, server: %d, min supported: %d)\n",
					(int)PROTOCOL_VERSION, (int)remote_version,
					(int)MIN_SUPPORTED_SERVER);
				goto error;
			}

			name = serializer_get_string(payload);
			if (name == NULL) {
				dnbd3_dev_err_host_alt(dev, "server did not supply an image name (discover)\n");
				goto error;
			}

			if (strcmp(name, dev->imgname) != 0) {
				dnbd3_dev_err_host_alt(
					dev,
					"image name does not match requested one (client: '%s', server: '%s') (discover)\n",
					dev->imgname, name);
				goto error;
			}

			rid = serializer_get_uint16(payload);
			if (rid != dev->rid) {
				dnbd3_dev_err_host_alt(
					dev, "server supplied wrong rid (client: '%d', server: '%d') (discover)\n",
					(int)dev->rid, (int)rid);
				goto error;
			}

			filesize = serializer_get_uint64(payload);
			if (filesize != dev->reported_size) {
				dnbd3_dev_err_host_alt(
					dev,
					"reported image size of %llu does not match expected value %llu (discover)\n",
					(unsigned long long)filesize, (unsigned long long)dev->reported_size);
				goto error;
			}

			// panic mode, take first responding server
			if (dev->panic) {
				dnbd3_dev_dbg_host_alt(dev, "panic mode, changing server ...\n");
				while (atomic_cmpxchg(&dev->connection_lock, 0, 1) != 0)
					schedule();

				if (dev->panic) {
					// Re-check, a connect might have been in progress
					dev->panic = 0;
					if (best_sock != NULL)
						sock_release(best_sock);

					dev->better_sock = sock; // Pass over socket to take a shortcut in *_connect();
					kfree(buf);
					put_task_struct(dev->thread_discover);
					dev->thread_discover = NULL;
					dnbd3_net_disconnect(dev);
					spin_lock_irqsave(&dev->blk_lock, irqflags);
					dev->cur_server.host = host_compare;
					spin_unlock_irqrestore(&dev->blk_lock, irqflags);
					dnbd3_net_connect(dev);
					atomic_set(&dev->connection_lock, 0);
					return 0;
				}
				atomic_set(&dev->connection_lock, 0);
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

			if (kernel_sendmsg(sock, &msg, iov, 1, sizeof(dnbd3_request)) <= 0) {
				dnbd3_dev_err_host_alt(dev, "requesting test block failed (discover)\n");
				goto error;
			}

			// receive net reply
			iov[0].iov_base = &dnbd3_reply;
			iov[0].iov_len = sizeof(dnbd3_reply);
			if (kernel_recvmsg(sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) !=
			    sizeof(dnbd3_reply)) {
				dnbd3_dev_err_host_alt(dev, "receiving test block header packet failed (discover)\n");
				goto error;
			}
			fixup_reply(dnbd3_reply);
			if (dnbd3_reply.magic != dnbd3_packet_magic || dnbd3_reply.cmd != CMD_GET_BLOCK ||
			    dnbd3_reply.size != RTT_BLOCK_SIZE) {
				dnbd3_dev_err_host_alt(
					dev, "unexpected reply to block request: cmd=%d, size=%d (discover)\n",
					(int)dnbd3_reply.cmd, (int)dnbd3_reply.size);
				goto error;
			}

			// receive data
			iov[0].iov_base = buf;
			iov[0].iov_len = RTT_BLOCK_SIZE;
			if (kernel_recvmsg(sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != RTT_BLOCK_SIZE) {
				dnbd3_dev_err_host_alt(dev, "receiving test block payload failed (discover)\n");
				goto error;
			}

			end = ktime_get_real(); // end rtt measurement

			mutex_lock(&dev->alt_servers_lock);
			if (is_same_server(&dev->alt_servers[i].host, &host_compare)) {
				dev->alt_servers[i].protocol_version = remote_version;
				dev->alt_servers[i].rtts[turn] = (unsigned long)ktime_us_delta(end, start);

				rtt = (dev->alt_servers[i].rtts[0] + dev->alt_servers[i].rtts[1]
						+ dev->alt_servers[i].rtts[2] + dev->alt_servers[i].rtts[3])
						/ 4;
				dev->alt_servers[i].failures = 0;
				if (dev->alt_servers[i].best_count > 1)
					dev->alt_servers[i].best_count -= 2;
			}
			mutex_unlock(&dev->alt_servers_lock);

			if (best_rtt > rtt) {
				// This one is better, keep socket open in case we switch
				best_rtt = rtt;
				best_server = host_compare;
				if (best_sock != NULL)
					sock_release(best_sock);
				best_sock = sock;
				sock = NULL;
			} else {
				// Not better, discard connection
				sock_release(sock);
				sock = NULL;
			}

			// update cur servers rtt
			if (is_same_server(&dev->cur_server.host, &host_compare))
				dev->cur_server.rtt = rtt;

			continue;

error:
			if (sock != NULL) {
				sock_release(sock);
				sock = NULL;
			}
			mutex_lock(&dev->alt_servers_lock);
			if (is_same_server(&dev->alt_servers[i].host, &host_compare)) {
				++dev->alt_servers[i].failures;
				dev->alt_servers[i].rtts[turn] = RTT_UNREACHABLE;
				if (dev->alt_servers[i].best_count > 2)
					dev->alt_servers[i].best_count -= 3;
			}
			mutex_unlock(&dev->alt_servers_lock);
			if (is_same_server(&dev->cur_server.host, &host_compare))
				dev->cur_server.rtt = RTT_UNREACHABLE;
		} // for loop over alt_servers

		if (dev->panic) {
			if (dev->panic_count < 255)
				dev->panic_count++;
			// If probe timeout is set, report error to block layer
			if (PROBE_COUNT_TIMEOUT > 0 && dev->panic_count == PROBE_COUNT_TIMEOUT + 1)
				dnbd3_blk_fail_all_requests(dev);
		}

		if (best_server.ss_family == 0 || kthread_should_stop() || dev->thread_discover == NULL) {
			// No alt server could be reached at all or thread should stop
			if (best_sock != NULL) {
				// Should never happen actually
				sock_release(best_sock);
				best_sock = NULL;
			}
			continue;
		}

		// If best server was repeatedly measured best, lower the switching threshold more
		mutex_lock(&dev->alt_servers_lock);
		alt = get_existing_alt_from_addr(&best_server, dev);
		if (alt != NULL) {
			if (alt->best_count < 148)
				alt->best_count += 3;
			rtt_threshold = 1500 - (alt->best_count * 10);
		} else {
			rtt_threshold = 1500;
		}
		mutex_unlock(&dev->alt_servers_lock);

		do_change = ready && !is_same_server(&best_server, &dev->cur_server.host)
			&& (ktime_to_us(start) & 3) != 0
			&& RTT_THRESHOLD_FACTOR(dev->cur_server.rtt) > best_rtt + rtt_threshold;

		if (ready && !do_change && best_sock != NULL) {
			spin_lock_irqsave(&dev->blk_lock, irqflags);
			if (!list_empty(&dev->request_queue_send)) {
				cur_request = list_entry(dev->request_queue_send.next, struct request, queuelist);
				do_change = (cur_request == last_request);
				if (do_change)
					dev_warn(dnbd3_device_to_dev(dev), "hung request, triggering change\n");
			} else {
				cur_request = (struct request *)123;
			}
			last_request = cur_request;
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		}

		// take server with lowest rtt
		// if a (dis)connect is already in progress, we do nothing, this is not panic mode
		if (do_change && atomic_cmpxchg(&dev->connection_lock, 0, 1) == 0) {
			dev_info(dnbd3_device_to_dev(dev), "server %pISpc is faster (%lluµs vs. %lluµs)\n",
					&best_server,
					(unsigned long long)best_rtt, (unsigned long long)dev->cur_server.rtt);
			kfree(buf);
			dev->better_sock = best_sock; // Take shortcut by continuing to use open connection
			put_task_struct(dev->thread_discover);
			dev->thread_discover = NULL;
			dnbd3_net_disconnect(dev);
			spin_lock_irqsave(&dev->blk_lock, irqflags);
			dev->cur_server.host = best_server;
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			dev->cur_server.rtt = best_rtt;
			dnbd3_net_connect(dev);
			atomic_set(&dev->connection_lock, 0);
			return 0;
		}

		// Clean up connection that was held open for quicker server switch
		if (best_sock != NULL) {
			sock_release(best_sock);
			best_sock = NULL;
		}

		// Increase rtt array index pointer, low probability that it doesn't advance
		if (!ready || (ktime_to_us(start) & 15) != 0)
			turn = (turn + 1) % 4;
		if (turn == 2) // Set ready when we only have 2 of 4 measurements for quicker load balancing
			ready = 1;
	}

	kfree(buf);
	if (kthread_should_stop())
		dev_dbg(dnbd3_device_to_dev(dev), "kthread %s terminated normally\n", __func__);
	else
		dev_dbg(dnbd3_device_to_dev(dev), "kthread %s exited unexpectedly\n", __func__);

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
	int ret = 0;

	init_msghdr(msg);

	dnbd3_request.magic = dnbd3_packet_magic;

	set_user_nice(current, -20);

	// move already sent requests to request_queue_send again
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	if (!list_empty(&dev->request_queue_receive)) {
		dev_dbg(dnbd3_device_to_dev(dev), "request queue was not empty");
		list_for_each_entry_safe(blk_request, tmp_request, &dev->request_queue_receive, queuelist) {
			list_del_init(&blk_request->queuelist);
			list_add(&blk_request->queuelist, &dev->request_queue_send);
		}
	}
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);

	while (!kthread_should_stop()) {
		wait_event_interruptible(dev->process_queue_send,
					 kthread_should_stop() || !list_empty(&dev->request_queue_send));

		if (kthread_should_stop())
			break;

		// extract block request
		/* lock since we aquire a blk request from the request_queue_send */
		spin_lock_irqsave(&dev->blk_lock, irqflags);
		if (list_empty(&dev->request_queue_send)) {
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			continue;
		}
		blk_request = list_entry(dev->request_queue_send.next, struct request, queuelist);

		// what to do?
		switch (dnbd3_req_op(blk_request)) {
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
			if (!atomic_read(&dev->connection_lock))
				dev_err(dnbd3_device_to_dev(dev), "unknown command (send %u %u)\n",
					(int)blk_request->cmd_flags, (int)dnbd3_req_op(blk_request));
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
		if (kernel_sendmsg(dev->sock, &msg, &iov, 1, sizeof(dnbd3_request)) != sizeof(dnbd3_request)) {
			if (!atomic_read(&dev->connection_lock))
				dnbd3_dev_err_host_cur(dev, "connection to server lost (send)\n");
			ret = -ESHUTDOWN;
			goto cleanup;
		}
	}

	dev_dbg(dnbd3_device_to_dev(dev), "kthread %s terminated normally\n", __func__);
	return 0;

cleanup:
	if (!atomic_read(&dev->connection_lock)) {
		if (dev->sock)
			kernel_sock_shutdown(dev->sock, SHUT_RDWR);
		dev->panic = 1;
		dev->discover = 1;
		wake_up(&dev->process_queue_discover);
	}

	if (kthread_should_stop() || ret == 0 || atomic_read(&dev->connection_lock))
		dev_dbg(dnbd3_device_to_dev(dev), "kthread %s terminated normally (cleanup)\n", __func__);
	else
		dev_err(dnbd3_device_to_dev(dev), "kthread %s terminated abnormally (%d)\n", __func__, ret);

	return 0;
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
	unsigned long recv_timeout = jiffies;

	int count, remaining, ret = 0;

	init_msghdr(msg);
	set_user_nice(current, -20);

	while (!kthread_should_stop()) {
		// receive net reply
		iov.iov_base = &dnbd3_reply;
		iov.iov_len = sizeof(dnbd3_reply);
		ret = kernel_recvmsg(dev->sock, &msg, &iov, 1, sizeof(dnbd3_reply), msg.msg_flags);

		/* end thread after socket timeout or reception of data */
		if (kthread_should_stop())
			break;

		/* check return value of kernel_recvmsg() */
		if (ret == 0) {
			/* have not received any data, but remote peer is shutdown properly */
			dnbd3_dev_dbg_host_cur(dev, "remote peer has performed an orderly shutdown\n");
			goto cleanup;
		} else if (ret < 0) {
			if (ret == -EAGAIN) {
				if (jiffies < recv_timeout)
					recv_timeout = jiffies; // Handle overflow
				if ((jiffies - recv_timeout) / HZ > SOCKET_KEEPALIVE_TIMEOUT) {
					if (!atomic_read(&dev->connection_lock))
						dnbd3_dev_err_host_cur(dev, "receive timeout reached (%d of %d secs)\n",
								       (int)((jiffies - recv_timeout) / HZ),
								       (int)SOCKET_KEEPALIVE_TIMEOUT);
					ret = -ETIMEDOUT;
					goto cleanup;
				}
				continue;
			} else {
				/* for all errors other than -EAGAIN, print message and abort thread */
				if (!atomic_read(&dev->connection_lock))
					dnbd3_dev_err_host_cur(dev, "connection to server lost (receive)\n");
				ret = -ESHUTDOWN;
				goto cleanup;
			}
		}

		/* check if arrived data is valid */
		if (ret != sizeof(dnbd3_reply)) {
			if (!atomic_read(&dev->connection_lock))
				dnbd3_dev_err_host_cur(dev, "recv msg header\n");
			ret = -EINVAL;
			goto cleanup;
		}
		fixup_reply(dnbd3_reply);

		// check error
		if (dnbd3_reply.magic != dnbd3_packet_magic) {
			dnbd3_dev_err_host_cur(dev, "wrong packet magic (receive)\n");
			ret = -EINVAL;
			goto cleanup;
		}
		if (dnbd3_reply.cmd == 0) {
			dnbd3_dev_err_host_cur(dev, "command was 0 (Receive)\n");
			ret = -EINVAL;
			goto cleanup;
		}

		// Update timeout
		recv_timeout = jiffies;

		// what to do?
		switch (dnbd3_reply.cmd) {
		case CMD_GET_BLOCK:
			// search for replied request in queue
			blk_request = NULL;
			spin_lock_irqsave(&dev->blk_lock, irqflags);
			list_for_each_entry_safe(received_request, tmp_request, &dev->request_queue_receive,
						  queuelist) {
				if ((uint64_t)(uintptr_t)received_request == dnbd3_reply.handle) {
					// Double cast to prevent warning on 32bit
					blk_request = received_request;
					list_del_init(&blk_request->queuelist);
					break;
				}
			}
			spin_unlock_irqrestore(&dev->blk_lock, irqflags);
			if (blk_request == NULL) {
				dnbd3_dev_err_host_cur(dev, "received block data for unrequested handle (%llu: %llu)\n",
						       (unsigned long long)dnbd3_reply.handle,
						       (unsigned long long)dnbd3_reply.size);
				ret = -EINVAL;
				goto cleanup;
			}
			// receive data and answer to block layer
			rq_for_each_segment(bvec_inst, blk_request, iter) {
				kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
				iov.iov_base = kaddr;
				iov.iov_len = bvec->bv_len;
				ret = kernel_recvmsg(dev->sock, &msg, &iov, 1, bvec->bv_len, msg.msg_flags);
				kunmap(bvec->bv_page);
				if (ret != bvec->bv_len) {
					if (ret == 0) {
						/* have not received any data, but remote peer is shutdown properly */
						dnbd3_dev_dbg_host_cur(
							dev, "remote peer has performed an orderly shutdown\n");
						ret = 0;
					} else {
						if (!atomic_read(&dev->connection_lock))
							dnbd3_dev_err_host_cur(dev,
									       "receiving from net to block layer\n");
						ret = -EINVAL;
					}
					// Requeue request
					spin_lock_irqsave(&dev->blk_lock, irqflags);
					list_add(&blk_request->queuelist, &dev->request_queue_send);
					spin_unlock_irqrestore(&dev->blk_lock, irqflags);
					goto cleanup;
				}
			}
			blk_mq_end_request(blk_request, BLK_STS_OK);
			continue;

		case CMD_GET_SERVERS:
			remaining = dnbd3_reply.size;
			if (dev->use_server_provided_alts) {
				dnbd3_server_entry_t new_server;

				while (remaining >= sizeof(dnbd3_server_entry_t)) {
					iov.iov_base = &new_server;
					iov.iov_len = sizeof(dnbd3_server_entry_t);
					if (kernel_recvmsg(dev->sock, &msg, &iov, 1, iov.iov_len,
								msg.msg_flags) != sizeof(dnbd3_server_entry_t)) {
						if (!atomic_read(&dev->connection_lock))
							dnbd3_dev_err_host_cur(dev, "recv CMD_GET_SERVERS payload\n");
						ret = -EINVAL;
						goto cleanup;
					}
					// TODO: Log
					if (new_server.failures == 0) { // ADD
						dnbd3_add_server(dev, &new_server.host);
					} else { // REM
						dnbd3_rem_server(dev, &new_server.host);
					}
					remaining -= sizeof(dnbd3_server_entry_t);
				}
			}
			// Drain any payload still on the wire
			while (remaining > 0) {
				count = MIN(sizeof(dnbd3_reply),
					    remaining); // Abuse the reply struct as the receive buffer
				iov.iov_base = &dnbd3_reply;
				iov.iov_len = count;
				ret = kernel_recvmsg(dev->sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
				if (ret <= 0) {
					if (!atomic_read(&dev->connection_lock))
						dnbd3_dev_err_host_cur(
							dev, "recv additional payload from CMD_GET_SERVERS\n");
					ret = -EINVAL;
					goto cleanup;
				}
				remaining -= ret;
			}
			continue;

		case CMD_LATEST_RID:
			if (dnbd3_reply.size != 2) {
				dev_err(dnbd3_device_to_dev(dev), "CMD_LATEST_RID.size != 2\n");
				continue;
			}
			iov.iov_base = &rid;
			iov.iov_len = sizeof(rid);
			if (kernel_recvmsg(dev->sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags) <= 0) {
				if (!atomic_read(&dev->connection_lock))
					dev_err(dnbd3_device_to_dev(dev), "could not receive CMD_LATEST_RID payload\n");
			} else {
				rid = net_order_16(rid);
				dev_info(dnbd3_device_to_dev(dev), "latest rid of %s is %d (currently using %d)\n",
					 dev->imgname, (int)rid, (int)dev->rid);
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

	dev_dbg(dnbd3_device_to_dev(dev), "kthread thread_receive terminated normally\n");
	return 0;

cleanup:
	if (!atomic_read(&dev->connection_lock)) {
		if (dev->sock)
			kernel_sock_shutdown(dev->sock, SHUT_RDWR);
		dev->panic = 1;
		dev->discover = 1;
		wake_up(&dev->process_queue_discover);
	}

	if (kthread_should_stop() || ret == 0 || atomic_read(&dev->connection_lock))
		dev_dbg(dnbd3_device_to_dev(dev), "kthread %s terminated normally (cleanup)\n", __func__);
	else
		dev_err(dnbd3_device_to_dev(dev), "kthread %s terminated abnormally (%d)\n", __func__, ret);

	return 0;
}

static void set_socket_timeouts(struct socket *sock, int timeout_ms)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	struct __kernel_sock_timeval timeout;
#else
	struct timeval timeout;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	sockptr_t timeout_ptr;

	timeout_ptr = KERNEL_SOCKPTR(&timeout);
#else
	char *timeout_ptr;

	timeout_ptr = (char *)&timeout;
#endif

	timeout.tv_sec = timeout_ms / 1000;
	timeout.tv_usec = (timeout_ms % 1000) * 1000;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	sock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO_NEW, timeout_ptr, sizeof(timeout));
	sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_NEW, timeout_ptr, sizeof(timeout));
#else
	sock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, timeout_ptr, sizeof(timeout));
	sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, timeout_ptr, sizeof(timeout));
#endif
}

static struct socket *dnbd3_connect(dnbd3_device_t *dev, struct sockaddr_storage *addr)
{
	ktime_t start;
	int ret, connect_time_ms;
	struct socket *sock;

	if (sock_create_kern(&init_net, addr->ss_family, SOCK_STREAM, IPPROTO_TCP, &sock) < 0) {
		dev_err(dnbd3_device_to_dev(dev), "couldn't create socket\n");
		return NULL;
	}

	/* Only one retry, TCP no delay */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	tcp_sock_set_syncnt(sock->sk, 1);
	tcp_sock_set_nodelay(sock->sk);
	/* because of our aggressive timeouts, this is pointless */
	sock_no_linger(sock->sk);
#else
	/* add legacy version of this, but ignore others as they're not that important */
	ret = 1;
	kernel_setsockopt(sock, IPPROTO_TCP, TCP_SYNCNT,
			(char *)&ret, sizeof(ret));
#endif
	/* allow this socket to use reserved mem (vm.mem_free_kbytes) */
	sk_set_memalloc(sock->sk);
	sock->sk->sk_allocation = GFP_NOIO;

	if (dev->panic && dev->panic_count > 1) {
		/* in panic mode for some time, start increasing timeouts */
		connect_time_ms = dev->panic_count * 1000;
	} else {
		/* otherwise, use 2*RTT of current server */
		connect_time_ms = dev->cur_server.rtt * 2 / 1000;
	}
	/* but obey a minimal configurable value */
	if (connect_time_ms < SOCKET_TIMEOUT_CLIENT_DATA * 1000)
		connect_time_ms = SOCKET_TIMEOUT_CLIENT_DATA * 1000;
	set_socket_timeouts(sock, connect_time_ms);
	start = ktime_get_real();
	ret = kernel_connect(sock, (struct sockaddr *)addr, sizeof(*addr), 0);
	connect_time_ms = (int)ktime_ms_delta(ktime_get_real(), start);
	if (connect_time_ms > 2 * SOCKET_TIMEOUT_CLIENT_DATA * 1000) {
		/* Either I'm losing my mind or there was a specific build of kernel
		 * 5.x where SO_RCVTIMEO didn't affect the connect call above, so
		 * this function would hang for over a minute for unreachable hosts.
		 * Leave in this debug check for twice the configured timeout
		 */
		dev_dbg(dnbd3_device_to_dev(dev), "%pISpc connect call took %dms\n",
				addr, connect_time_ms);
	}
	if (ret != 0) {
		dev_dbg(dnbd3_device_to_dev(dev), "%pISpc connect failed (%d, blocked %dms)\n",
				addr, ret, connect_time_ms);
		goto error;
	}
	return sock;
error:
	sock_release(sock);
	return NULL;
}

int dnbd3_net_connect(dnbd3_device_t *dev)
{
	struct request *req1 = NULL;
	unsigned long irqflags;

	ASSERT(atomic_read(&dev->connection_lock));

	// do some checks before connecting
	req1 = kmalloc(sizeof(*req1), GFP_ATOMIC);
	if (!req1) {
		dnbd3_dev_err_host_cur(dev, "kmalloc failed\n");
		goto error;
	}

	if (dev->cur_server.host.ss_family == 0 || dev->imgname == NULL) {
		dnbd3_dev_err_host_cur(dev, "connect: host or image name not set\n");
		goto error;
	}

	if (dev->sock) {
		dnbd3_dev_err_host_cur(dev, "socket already connected\n");
		goto error;
	}

	ASSERT(dev->thread_send == NULL);
	ASSERT(dev->thread_receive == NULL);
	ASSERT(dev->thread_discover == NULL);

	dnbd3_dev_dbg_host_cur(dev, "connecting ...\n");

	if (dev->better_sock != NULL) {
		// Switching server, connection is already established and size request was executed
		dnbd3_dev_dbg_host_cur(dev, "on-the-fly server change ...\n");
		dev->sock = dev->better_sock;
		dev->better_sock = NULL;
	} else {
		//  no established connection yet from discovery thread, start new one
		uint64_t reported_size;
		dnbd3_request_t dnbd3_request;
		dnbd3_reply_t dnbd3_reply;
		struct msghdr msg;
		struct kvec iov[2];
		uint16_t rid, proto_version;
		char *name;
		int mlen;

		init_msghdr(msg);

		dev->sock = dnbd3_connect(dev, &dev->cur_server.host);
		if (dev->sock == NULL) {
			dnbd3_dev_err_host_cur(dev, "%s: Failed\n", __func__);
			goto error;
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
		if (kernel_sendmsg(dev->sock, &msg, iov, 2, mlen) != mlen) {
			dnbd3_dev_err_host_cur(dev, "couldn't send CMD_SELECT_IMAGE\n");
			goto error;
		}
		// receive reply header
		iov[0].iov_base = &dnbd3_reply;
		iov[0].iov_len = sizeof(dnbd3_reply);
		if (kernel_recvmsg(dev->sock, &msg, iov, 1, sizeof(dnbd3_reply), msg.msg_flags) !=
		    sizeof(dnbd3_reply)) {
			dnbd3_dev_err_host_cur(dev, "received corrupted reply header after CMD_SELECT_IMAGE\n");
			goto error;
		}
		// check reply header
		fixup_reply(dnbd3_reply);
		if (dnbd3_reply.cmd != CMD_SELECT_IMAGE || dnbd3_reply.size < 3 || dnbd3_reply.size > MAX_PAYLOAD ||
		    dnbd3_reply.magic != dnbd3_packet_magic) {
			dnbd3_dev_err_host_cur(
				dev, "received invalid reply to CMD_SELECT_IMAGE, image doesn't exist on server\n");
			goto error;
		}
		// receive reply payload
		iov[0].iov_base = &dev->payload_buffer;
		iov[0].iov_len = dnbd3_reply.size;
		if (kernel_recvmsg(dev->sock, &msg, iov, 1, dnbd3_reply.size, msg.msg_flags) != dnbd3_reply.size) {
			dnbd3_dev_err_host_cur(dev, "cold not read CMD_SELECT_IMAGE payload on handshake\n");
			goto error;
		}
		// handle/check reply payload
		serializer_reset_read(&dev->payload_buffer, dnbd3_reply.size);
		proto_version = serializer_get_uint16(&dev->payload_buffer);
		spin_lock_irqsave(&dev->blk_lock, irqflags);
		dev->cur_server.protocol_version = proto_version;
		spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		if (proto_version < MIN_SUPPORTED_SERVER) {
			dnbd3_dev_err_host_cur(dev, "server version is lower than min supported version\n");
			goto error;
		}
		name = serializer_get_string(&dev->payload_buffer);
		if (dev->rid != 0 && strcmp(name, dev->imgname) != 0) {
			dnbd3_dev_err_host_cur(dev, "server offers image '%s', requested '%s'\n", name, dev->imgname);
			goto error;
		}
		if (strlen(dev->imgname) < strlen(name)) {
			dev->imgname = krealloc(dev->imgname, strlen(name) + 1, GFP_ATOMIC);
			if (dev->imgname == NULL) {
				dnbd3_dev_err_host_cur(dev, "reallocating buffer for new image name failed\n");
				goto error;
			}
		}
		strcpy(dev->imgname, name);
		rid = serializer_get_uint16(&dev->payload_buffer);
		if (dev->rid != 0 && dev->rid != rid) {
			dnbd3_dev_err_host_cur(dev, "server provides rid %d, requested was %d\n", (int)rid,
					       (int)dev->rid);
			goto error;
		}
		dev->rid = rid;
		reported_size = serializer_get_uint64(&dev->payload_buffer);
		if (reported_size < 4096) {
			dnbd3_dev_err_host_cur(dev, "reported size by server is < 4096\n");
			goto error;
		}
		if (dev->reported_size != 0 && dev->reported_size != reported_size) {
			dnbd3_dev_err_host_cur(dev, "newly connected server reports size %llu, but expected is %llu\n",
					       reported_size, dev->reported_size);
			goto error;
		} else if (dev->reported_size == 0) {
			// store image information
			dev->reported_size = reported_size;
			set_capacity(dev->disk, dev->reported_size >> 9); /* 512 Byte blocks */
			dnbd3_dev_dbg_host_cur(dev, "image size: %llu\n", dev->reported_size);
			dev->update_available = 0;
		}
	}

	// create required threads
	dev->thread_send = kthread_create(dnbd3_net_send, dev, "%s-send", dev->disk->disk_name);
	if (!IS_ERR(dev->thread_send)) {
		get_task_struct(dev->thread_send);
		wake_up_process(dev->thread_send);
	} else {
		dev_err(dnbd3_device_to_dev(dev), "failed to create send thread\n");
		/* reset error to cleanup thread */
		dev->thread_send = NULL;
		goto error;
	}

	dev->thread_receive = kthread_create(dnbd3_net_receive, dev, "%s-receive", dev->disk->disk_name);
	if (!IS_ERR(dev->thread_receive)) {
		get_task_struct(dev->thread_receive);
		wake_up_process(dev->thread_receive);
	} else {
		dev_err(dnbd3_device_to_dev(dev), "failed to create receive thread\n");
		/* reset error to cleanup thread */
		dev->thread_receive = NULL;
		goto error;
	}

	dev->thread_discover = kthread_create(dnbd3_net_discover, dev, "%s-discover", dev->disk->disk_name);
	if (!IS_ERR(dev->thread_discover)) {
		get_task_struct(dev->thread_discover);
		wake_up_process(dev->thread_discover);
	} else {
		dev_err(dnbd3_device_to_dev(dev), "failed to create discover thread\n");
		/* reset error to cleanup thread */
		dev->thread_discover = NULL;
		goto error;
	}

	dev->panic = 0;
	dev->panic_count = 0;

	// Enqueue request to request_queue_send for a fresh list of alt servers
	dnbd3_cmd_to_priv(req1, CMD_GET_SERVERS);
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	list_add(&req1->queuelist, &dev->request_queue_send);
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);

	wake_up(&dev->process_queue_send);

	// add heartbeat timer
	// Do not goto error after creating the timer - we require that the timer exists
	// if dev->sock != NULL -- see dnbd3_net_disconnect
	dev->heartbeat_count = 0;
	timer_setup(&dev->hb_timer, dnbd3_net_heartbeat, 0);
	dev->hb_timer.expires = jiffies + HZ;
	add_timer(&dev->hb_timer);

	return 0;

error:
	if (dev->thread_send) {
		kthread_stop(dev->thread_send);
		put_task_struct(dev->thread_send);
		dev->thread_send = NULL;
	}
	if (dev->thread_receive) {
		kthread_stop(dev->thread_receive);
		put_task_struct(dev->thread_receive);
		dev->thread_receive = NULL;
	}
	if (dev->thread_discover) {
		kthread_stop(dev->thread_discover);
		put_task_struct(dev->thread_discover);
		dev->thread_discover = NULL;
	}
	if (dev->sock) {
		sock_release(dev->sock);
		dev->sock = NULL;
	}
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	dev->cur_server.host.ss_family = 0;
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
	kfree(req1);

	return -1;
}

int dnbd3_net_disconnect(dnbd3_device_t *dev)
{
	struct task_struct *thread = NULL;
	unsigned long irqflags;
	int ret;

	dev_dbg(dnbd3_device_to_dev(dev), "disconnecting device ...\n");
	ASSERT(atomic_read(&dev->connection_lock));

	dev->discover = 0;

	if (dev->sock) {
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);
		// clear heartbeat timer
		del_timer(&dev->hb_timer);
	}

	// kill sending and receiving threads
	if (dev->thread_send) {
		dnbd3_dev_dbg_host_cur(dev, "stop send thread\n");
		thread = dev->thread_send;
		ret = kthread_stop(thread);
		put_task_struct(thread);
		if (ret == -EINTR) {
			/* thread has never been scheduled and run */
			dev_dbg(dnbd3_device_to_dev(dev), "send thread has never run\n");
		} else {
			/* thread has run, check if it has terminated successfully */
			if (ret < 0)
				dev_err(dnbd3_device_to_dev(dev), "send thread was not terminated correctly\n");
		}
		dev->thread_send = NULL;
	}

	if (dev->thread_receive) {
		dnbd3_dev_dbg_host_cur(dev, "stop receive thread\n");
		thread = dev->thread_receive;
		ret = kthread_stop(thread);
		put_task_struct(thread);
		if (ret == -EINTR) {
			/* thread has never been scheduled and run */
			dev_dbg(dnbd3_device_to_dev(dev), "receive thread has never run\n");
		} else {
			/* thread has run, check if it has terminated successfully */
			if (ret < 0)
				dev_err(dnbd3_device_to_dev(dev), "receive thread was not terminated correctly\n");
		}
		dev->thread_receive = NULL;
	}

	if (dev->thread_discover) {
		dnbd3_dev_dbg_host_cur(dev, "stop discover thread\n");
		thread = dev->thread_discover;
		ret = kthread_stop(thread);
		put_task_struct(thread);
		if (ret == -EINTR) {
			/* thread has never been scheduled and run */
			dev_dbg(dnbd3_device_to_dev(dev), "discover thread has never run\n");
		} else {
			/* thread has run, check if it has terminated successfully */
			if (ret < 0) {
				dev_err(dnbd3_device_to_dev(dev), "discover thread was not terminated correctly (%d)\n",
					ret);
			}
		}
		dev->thread_discover = NULL;
	}

	if (dev->sock) {
		sock_release(dev->sock);
		dev->sock = NULL;
	}
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	dev->cur_server.host.ss_family = 0;
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);

	return 0;
}
