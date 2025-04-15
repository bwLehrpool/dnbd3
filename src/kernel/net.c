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
#include "net.h"
#include "blk.h"
#include "dnbd3_main.h"

#include <dnbd3/shared/serialize.h>

#include <linux/random.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#define get_random_u32 prandom_u32
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
// Old
#define dnbd3_kmap kmap
#define dnbd3_kunmap(page, addr) kunmap(page)
#else
// New
#define dnbd3_kmap kmap_local_page
#define dnbd3_kunmap(page, addr) kunmap_local(addr)
#endif

#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/tcp.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ktime_to_s
#define ktime_to_s(kt) ktime_divns(kt, NSEC_PER_SEC)
#endif

#ifdef DEBUG
#define ASSERT(x) \
	do { \
		if (!(x)) { \
			printk(KERN_EMERG "assertion failed %s: %d: %s\n", __FILE__, __LINE__, #x); \
			BUG(); \
		} \
	} while (0)
#else
#define ASSERT(x) \
	do { \
	} while (0)
#endif

#define dnbd3_dev_dbg_host(dev, host, fmt, ...) \
	dev_dbg(dnbd3_device_to_dev(dev), "(%pISpc): " fmt, (host), ##__VA_ARGS__)
#define dnbd3_dev_info_host(dev, host, fmt, ...) \
	dev_info(dnbd3_device_to_dev(dev), "(%pISpc): " fmt, (host), ##__VA_ARGS__)
#define dnbd3_dev_err_host(dev, host, fmt, ...) \
	dev_err(dnbd3_device_to_dev(dev), "(%pISpc): " fmt, (host), ##__VA_ARGS__)

#define dnbd3_dev_dbg_cur(dev, fmt, ...) \
	dnbd3_dev_dbg_host(dev, &(dev)->cur_server.host, fmt, ##__VA_ARGS__)
#define dnbd3_dev_info_cur(dev, fmt, ...) \
	dnbd3_dev_info_host(dev, &(dev)->cur_server.host, fmt, ##__VA_ARGS__)
#define dnbd3_dev_err_cur(dev, fmt, ...) \
	dnbd3_dev_err_host(dev, &(dev)->cur_server.host, fmt, ##__VA_ARGS__)

static bool dnbd3_drain_socket(dnbd3_device_t *dev, struct socket *sock, int bytes);
static int dnbd3_recv_bytes(struct socket *sock, void *buffer, size_t count);
static int dnbd3_recv_reply(struct socket *sock, dnbd3_reply_t *reply_hdr);
static bool dnbd3_send_request(struct socket *sock, u16 cmd, u64 handle, u64 offset, u32 size);

static int dnbd3_set_primary_connection(dnbd3_device_t *dev, struct socket *sock,
		struct sockaddr_storage *addr, u16 protocol_version);

static int dnbd3_connect(dnbd3_device_t *dev, struct sockaddr_storage *addr,
		struct socket **sock_out);

static bool dnbd3_execute_handshake(dnbd3_device_t *dev, struct socket *sock,
		struct sockaddr_storage *addr, uint16_t *remote_version, bool copy_image_info);

static bool dnbd3_request_test_block(dnbd3_device_t *dev, struct sockaddr_storage *addr,
		struct socket *sock, u64 test_start, u32 test_size);

static bool dnbd3_send_empty_request(dnbd3_device_t *dev, u16 cmd);

static void dnbd3_start_discover(dnbd3_device_t *dev, bool panic);

static void dnbd3_discover(dnbd3_device_t *dev);

static void dnbd3_internal_discover(dnbd3_device_t *dev);

static void set_socket_timeout(struct socket *sock, bool set_send, int timeout_ms);

// Use as write-only dump, don't care about race conditions etc.
static u8 __garbage_mem[PAGE_SIZE];

/**
 * Delayed work triggering sending of keepalive packet.
 */
static void dnbd3_keepalive_workfn(struct work_struct *work)
{
	unsigned long irqflags;
	dnbd3_device_t *dev = container_of(work, dnbd3_device_t, keepalive_work.work);

	dnbd3_send_empty_request(dev, CMD_KEEPALIVE);
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	if (device_active(dev)) {
		mod_delayed_work(system_freezable_power_efficient_wq,
				&dev->keepalive_work, KEEPALIVE_INTERVAL * HZ);
	}
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
}

/**
 * Delayed work triggering discovery (alt server check)
 */
static void dnbd3_discover_workfn(struct work_struct *work)
{
	dnbd3_device_t *dev = container_of(work, dnbd3_device_t, discover_work.work);

	dnbd3_discover(dev);
}

/**
 * For manually triggering an immediate discovery
 */
static void dnbd3_start_discover(dnbd3_device_t *dev, bool panic)
{
	unsigned long irqflags;

	if (!device_active(dev))
		return;
	if (panic && dnbd3_flag_get(dev->connection_lock)) {
		spin_lock_irqsave(&dev->blk_lock, irqflags);
		if (!dev->panic) {
			// Panic freshly turned on
			dev->panic = true;
			dev->discover_interval = TIMER_INTERVAL_PROBE_PANIC;
			dev->discover_count = 0;
		}
		spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		dnbd3_flag_reset(dev->connection_lock);
	}
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	mod_delayed_work(system_freezable_power_efficient_wq,
			&dev->discover_work, 1);
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
}

/**
 * Wrapper for the actual discover function below. Check run conditions
 * here and re-schedule delayed task here.
 */
static void dnbd3_discover(dnbd3_device_t *dev)
{
	unsigned long irqflags;

	if (!device_active(dev) || dnbd3_flag_taken(dev->connection_lock))
		return; // device not active anymore, or just about to switch
	if (!dnbd3_flag_get(dev->discover_running))
		return; // Already busy
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	cancel_delayed_work(&dev->discover_work);
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
	dnbd3_internal_discover(dev);
	dev->discover_count++;
	// Re-queueing logic
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	if (device_active(dev)) {
		mod_delayed_work(system_freezable_power_efficient_wq,
				&dev->discover_work, dev->discover_interval * HZ);
		if (dev->discover_interval < TIMER_INTERVAL_PROBE_MAX
				&& dev->discover_count > DISCOVER_STARTUP_PHASE_COUNT) {
			dev->discover_interval += 2;
		}
	}
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
	dnbd3_flag_reset(dev->discover_running);
}

/**
 * Discovery. Probe all (or some) known alt servers,
 * and initiate connection switch if appropriate
 */
static void dnbd3_internal_discover(dnbd3_device_t *dev)
{
	struct socket *sock, *best_sock = NULL;
	dnbd3_alt_server_t *alt;
	struct request *blk_request;
	struct sockaddr_storage host_compare, best_server;
	uint16_t remote_version;
	ktime_t start, end;
	unsigned long rtt = 0, best_rtt = 0;
	u64 test_start = 0;
	u32 test_size = RTT_BLOCK_SIZE;
	unsigned long irqflags;
	int i, j, k, isize, fails, rtt_threshold;
	int do_change = 0;
	u8 check_order[NUMBER_SERVERS];
	const bool ready = dev->discover_count > DISCOVER_STARTUP_PHASE_COUNT;
	const u32 turn = dev->discover_count % DISCOVER_HISTORY_SIZE;

	// Shuffle alt_servers
	for (i = 0; i < NUMBER_SERVERS; ++i)
		check_order[i] = i;

	for (i = 0; i < NUMBER_SERVERS; ++i) {
		j = get_random_u32() % NUMBER_SERVERS;
		if (j != i) {
			int tmp = check_order[i];

			check_order[i] = check_order[j];
			check_order[j] = tmp;
		}
	}

	best_server.ss_family = 0;
	best_rtt = RTT_UNREACHABLE;

	if (dev->panic)
		dnbd3_dev_dbg_host(dev, &host_compare, "Discover in panic mode\n");

	if (!ready || dev->panic)
		isize = NUMBER_SERVERS;
	else
		isize = 3;

	for (j = 0; j < NUMBER_SERVERS; ++j) {
		if (!device_active(dev))
			break;
		i = check_order[j];
		mutex_lock(&dev->alt_servers_lock);
		host_compare = dev->alt_servers[i].host;
		fails = dev->alt_servers[i].failures;
		mutex_unlock(&dev->alt_servers_lock);
		if (host_compare.ss_family == 0)
			continue; // Empty slot
		// Reduced probability for hosts that have been unreachable
		if (!dev->panic && fails > 50 && (get_random_u32() % 4) != 0)
			continue; // If not in panic mode, skip server if it failed too many times
		if (isize-- <= 0 && !is_same_server(&dev->cur_server.host, &host_compare))
			continue; // Only test isize servers plus current server

		// Initialize socket and connect
		sock = NULL;
		if (dnbd3_connect(dev, &host_compare, &sock) != 0)
			goto error;

		remote_version = 0;
		if (!dnbd3_execute_handshake(dev, sock, &host_compare, &remote_version, false))
			goto error;

		if (dev->panic) {
			// In panic mode, use next pending request for testing, this has a higher chance of
			// filtering out a server which can't actually handle our requests, instead of just
			// requesting the very first block which should be cached by every server.
			spin_lock_irqsave(&dev->send_queue_lock, irqflags);
			if (!list_empty(&dev->send_queue)) {
				blk_request = list_entry(dev->send_queue.next, struct request, queuelist);
				test_start = blk_rq_pos(blk_request) << 9; /* sectors to bytes */
				test_size = blk_rq_bytes(blk_request);
			}
			spin_unlock_irqrestore(&dev->send_queue_lock, irqflags);
		}

		// actual rtt measurement is just the first block request and reply
		start = ktime_get_real();
		if (!dnbd3_request_test_block(dev, &host_compare, sock, test_start, test_size))
			goto error;
		end = ktime_get_real();

		// panic mode, take first responding server
		if (dev->panic) {
			dnbd3_dev_info_host(dev, &host_compare, "panic mode, changing to new server\n");
			if (!dnbd3_flag_get(dev->connection_lock)) {
				dnbd3_dev_info_host(dev, &host_compare, "...raced, ignoring\n");
			} else {
				// Check global flag, a connect might have been in progress
				if (best_sock != NULL)
					sock_release(best_sock);
				set_socket_timeout(sock, false, MAX(
							SOCKET_TIMEOUT_RECV * 1000,
							(int)ktime_ms_delta(end, start)
						) + 1000);
				if (dnbd3_set_primary_connection(dev, sock, &host_compare, remote_version) != 0)
					sock_release(sock);
				dnbd3_flag_reset(dev->connection_lock);
				return;
			}
		}

		mutex_lock(&dev->alt_servers_lock);
		if (is_same_server(&dev->alt_servers[i].host, &host_compare)) {
			dev->alt_servers[i].protocol_version = remote_version;
			dev->alt_servers[i].rtts[turn] =
				(unsigned long)ktime_us_delta(end, start);

			rtt = 0;

			for (k = 0; k < DISCOVER_HISTORY_SIZE; ++k)
				rtt += dev->alt_servers[i].rtts[k];

			rtt /= DISCOVER_HISTORY_SIZE;
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
			if (remote_version)
				dev->alt_servers[i].protocol_version = remote_version;
			++dev->alt_servers[i].failures;
			dev->alt_servers[i].rtts[turn] = RTT_UNREACHABLE;
			if (dev->alt_servers[i].best_count > 2)
				dev->alt_servers[i].best_count -= 3;
		}
		mutex_unlock(&dev->alt_servers_lock);
		if (is_same_server(&dev->cur_server.host, &host_compare))
			dev->cur_server.rtt = RTT_UNREACHABLE;
	} // END - for loop over alt_servers

	if (best_server.ss_family == 0) {
		// No alt server could be reached
		ASSERT(!best_sock);
		if (dev->panic) {
			if (dev->panic_count < 255)
				dev->panic_count++;
			// If probe timeout is set, report error to block layer
			if (PROBE_COUNT_TIMEOUT > 0 && dev->panic_count == PROBE_COUNT_TIMEOUT + 1)
				dnbd3_blk_fail_all_requests(dev);
		}
		return;
	}

	// If best server was repeatedly measured best, lower the switching threshold more
	mutex_lock(&dev->alt_servers_lock);
	alt = get_existing_alt_from_addr(&best_server, dev);
	if (alt != NULL) {
		if (alt->best_count < 178)
			alt->best_count += 3;
		rtt_threshold = 1800 - (alt->best_count * 10);
		remote_version = alt->protocol_version;
	} else {
		rtt_threshold = 1800;
		remote_version = 0;
	}
	mutex_unlock(&dev->alt_servers_lock);

	do_change = ready && !is_same_server(&best_server, &dev->cur_server.host)
		&& RTT_THRESHOLD_FACTOR(dev->cur_server.rtt) > best_rtt + rtt_threshold;

	// take server with lowest rtt
	// if a (dis)connect is already in progress, we do nothing, this is not panic mode
	if (do_change && device_active(dev) && dnbd3_flag_get(dev->connection_lock)) {
		dnbd3_dev_info_cur(dev, "server %pISpc is faster (%lluµs vs. %lluµs)\n",
				&best_server,
				(unsigned long long)best_rtt, (unsigned long long)dev->cur_server.rtt);
		set_socket_timeout(best_sock, false, // recv
				MAX(best_rtt / 1000, SOCKET_TIMEOUT_RECV * 1000) + 500);
		set_socket_timeout(best_sock, true, // send
				MAX(best_rtt / 1000, SOCKET_TIMEOUT_SEND * 1000) + 500);
		if (dnbd3_set_primary_connection(dev, best_sock, &best_server, remote_version) != 0)
			sock_release(best_sock);
		dnbd3_flag_reset(dev->connection_lock);
		return;
	}

	// Clean up connection that was held open for quicker server switch
	if (best_sock != NULL)
		sock_release(best_sock);
}

/**
 * Worker for sending pending requests. This will be triggered whenever
 * we get a new request from the block layer. The worker will then
 * work through all the requests in the send queue, request them from
 * the server, and return again.
 */
static void dnbd3_send_workfn(struct work_struct *work)
{
	dnbd3_device_t *dev = container_of(work, dnbd3_device_t, send_work);
	struct request *blk_request;
	struct dnbd3_cmd *cmd;
	unsigned long irqflags;

	mutex_lock(&dev->send_mutex);
	while (dev->sock && device_active(dev)) {
		// extract next block request
		spin_lock_irqsave(&dev->send_queue_lock, irqflags);
		if (list_empty(&dev->send_queue)) {
			spin_unlock_irqrestore(&dev->send_queue_lock, irqflags);
			break;
		}

		blk_request = list_entry(dev->send_queue.next, struct request, queuelist);
		list_del_init(&blk_request->queuelist);
		spin_unlock_irqrestore(&dev->send_queue_lock, irqflags);
		// append to receive queue
		spin_lock_irqsave(&dev->recv_queue_lock, irqflags);
		list_add_tail(&blk_request->queuelist, &dev->recv_queue);
		spin_unlock_irqrestore(&dev->recv_queue_lock, irqflags);

		cmd = blk_mq_rq_to_pdu(blk_request);
		if (!dnbd3_send_request(dev->sock, CMD_GET_BLOCK, cmd->handle,
					blk_rq_pos(blk_request) << 9 /* sectors */, blk_rq_bytes(blk_request))) {
			if (!dnbd3_flag_taken(dev->connection_lock)) {
				dnbd3_dev_err_cur(dev, "connection to server lost (send)\n");
				dnbd3_start_discover(dev, true);
			}
			break;
		}
	}
	mutex_unlock(&dev->send_mutex);
}

/**
 * The receive workfn stays active for as long as the connection to a server
 * lasts, i.e. it only gets restarted when we switch to a new server.
 */
static void dnbd3_recv_workfn(struct work_struct *work)
{
	dnbd3_device_t *dev = container_of(work, dnbd3_device_t, recv_work);
	struct request *blk_request;
	struct request *rq_iter;
	struct dnbd3_cmd *cmd;
	dnbd3_reply_t reply_hdr;
	struct req_iterator iter;
	struct bio_vec bvec_inst;
	struct bio_vec *bvec = &bvec_inst;
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL | MSG_WAITALL };
	struct kvec iov;
	void *kaddr;
	unsigned long irqflags;
	uint16_t rid;
	u32 remaining;
	int ret;

	dnbd3_dev_dbg_cur(dev, "starting receive worker...\n");
	mutex_lock(&dev->recv_mutex);
	dnbd3_dev_dbg_cur(dev, "receive worker started\n");
	while (dev->sock) {
		// receive net reply
		ret = dnbd3_recv_reply(dev->sock, &reply_hdr);
		if (ret == 0) {
			/* have not received any data, but remote peer is shutdown properly */
			dnbd3_dev_dbg_cur(dev, "remote peer has performed an orderly shutdown\n");
			goto out_unlock;
		} else if (ret < 0) {
			if (ret == -EAGAIN) {
				if (!dnbd3_flag_taken(dev->connection_lock))
					dnbd3_dev_err_cur(dev, "receive timeout reached\n");
			} else {
				/* for all errors other than -EAGAIN, print errno */
				if (!dnbd3_flag_taken(dev->connection_lock))
					dnbd3_dev_err_cur(dev, "connection to server lost (receive, errno=%d)\n", ret);
			}
			goto out_unlock;
		}

		/* check if arrived data is valid */
		if (ret != sizeof(reply_hdr)) {
			if (!dnbd3_flag_taken(dev->connection_lock))
				dnbd3_dev_err_cur(dev, "recv partial msg header (%d/%d bytes)\n",
						ret, (int)sizeof(reply_hdr));
			goto out_unlock;
		}

		// check error
		if (reply_hdr.magic != dnbd3_packet_magic) {
			dnbd3_dev_err_cur(dev, "wrong packet magic (receive)\n");
			goto out_unlock;
		}

		// what to do?
		switch (reply_hdr.cmd) {
		case CMD_GET_BLOCK:
			// search for replied request in queue
			blk_request = NULL;
			spin_lock_irqsave(&dev->recv_queue_lock, irqflags);
			list_for_each_entry(rq_iter, &dev->recv_queue, queuelist) {
				cmd = blk_mq_rq_to_pdu(rq_iter);
				if (cmd->handle == reply_hdr.handle) {
					blk_request = rq_iter;
					list_del_init(&blk_request->queuelist);
					break;
				}
			}
			spin_unlock_irqrestore(&dev->recv_queue_lock, irqflags);
			if (blk_request == NULL) {
				dnbd3_dev_err_cur(dev, "received block data for unrequested handle (%llx: len=%llu)\n",
						       reply_hdr.handle,
						       (u64)reply_hdr.size);
				goto out_unlock;
			}
			// receive data and answer to block layer
			remaining = reply_hdr.size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			rq_for_each_segment(bvec_inst, blk_request, iter) {
#else
			rq_for_each_segment(bvec, blk_request, iter) {
#endif
				if (bvec->bv_len > remaining) {
					dnbd3_dev_dbg_cur(
						dev, "request has more data remaining than is left in reply (want: %u, have: %u)\n",
						bvec->bv_len, remaining);
					ret = -1;
				} else {
					kaddr = dnbd3_kmap(bvec->bv_page) + bvec->bv_offset;
					iov.iov_base = kaddr;
					iov.iov_len = bvec->bv_len;
					ret = kernel_recvmsg(dev->sock, &msg, &iov, 1, bvec->bv_len, msg.msg_flags);
					dnbd3_kunmap(bvec->bv_page, kaddr);
				}
				if (ret != bvec->bv_len) {
					if (ret == 0) {
						/* have not received any data, but remote peer is shutdown properly */
						dnbd3_dev_dbg_cur(
							dev, "remote peer has performed an orderly shutdown\n");
					} else if (ret < 0) {
						if (!dnbd3_flag_taken(dev->connection_lock))
							dnbd3_dev_err_cur(dev,
								"receiving from net to block layer failed (ret=%d)\n", ret);
					} else {
						if (!dnbd3_flag_taken(dev->connection_lock))
							dnbd3_dev_err_cur(dev,
								"receiving from net to block layer (%d bytes)\n", ret);
					}
					goto segment_loop_end;
				}
				remaining -= ret;
			}
segment_loop_end: /* Make this a goto as rq_for_each_segment is opaque and can be any number of nested loops */
			if (remaining != 0) {
				if (ret > 0) {
					/* No previous error, the reply must've had more payload than the according request */
					dnbd3_dev_err_cur(dev,
						"reply has payload left, but block request already satisfied (len: %u, remaining: %u)\n",
						reply_hdr.size, remaining);
				}
				// Requeue request
				spin_lock_irqsave(&dev->send_queue_lock, irqflags);
				list_add(&blk_request->queuelist, &dev->send_queue);
				spin_unlock_irqrestore(&dev->send_queue_lock, irqflags);
				goto out_unlock;
			}
			blk_mq_end_request(blk_request, BLK_STS_OK);
			break;

		case CMD_GET_SERVERS:
			remaining = reply_hdr.size;
			if (dev->use_server_provided_alts) {
				dnbd3_server_entry_t new_server;

				while (remaining >= sizeof(new_server)) {
					if (dnbd3_recv_bytes(dev->sock, &new_server, sizeof(new_server))
							!= sizeof(new_server)) {
						if (!dnbd3_flag_taken(dev->connection_lock))
							dnbd3_dev_err_cur(dev, "recv CMD_GET_SERVERS payload\n");
						goto out_unlock;
					}
					// TODO: Log
					if (new_server.failures == 0) { // ADD
						dnbd3_add_server(dev, &new_server.host);
					} else { // REM
						dnbd3_rem_server(dev, &new_server.host);
					}
					remaining -= sizeof(new_server);
				}
			}
			if (!dnbd3_drain_socket(dev, dev->sock, remaining))
				goto out_unlock;
			break;

		case CMD_LATEST_RID:
			if (reply_hdr.size < 2) {
				dev_err(dnbd3_device_to_dev(dev), "CMD_LATEST_RID.size < 2\n");
				continue;
			}
			if (dnbd3_recv_bytes(dev->sock, &rid, 2) != 2) {
				if (!dnbd3_flag_taken(dev->connection_lock))
					dev_err(dnbd3_device_to_dev(dev), "could not receive CMD_LATEST_RID payload\n");
			} else {
				rid = net_order_16(rid);
				dnbd3_dev_info_cur(dev, "latest rid of %s is %d (currently using %d)\n",
					 dev->imgname, (int)rid, (int)dev->rid);
				dev->update_available = (rid > dev->rid ? 1 : 0);
			}
			if (reply_hdr.size > 2)
				dnbd3_drain_socket(dev, dev->sock, reply_hdr.size - 2);
			continue;

		case CMD_KEEPALIVE:
			if (reply_hdr.size != 0) {
				dev_dbg(dnbd3_device_to_dev(dev), "keep alive packet with payload\n");
				dnbd3_drain_socket(dev, dev->sock, reply_hdr.size);
			}
			continue;

		default:
			dev_err(dnbd3_device_to_dev(dev), "unknown command: %d (receive), aborting connection\n", (int)reply_hdr.cmd);
			goto out_unlock;
		}
	}
out_unlock:
	// This will check if we actually still need a new connection
	dnbd3_start_discover(dev, true);
	dnbd3_dev_dbg_cur(dev, "Receive worker exited\n");
	mutex_unlock(&dev->recv_mutex);
}

/**
 * Set send or receive timeout of given socket
 */
static void set_socket_timeout(struct socket *sock, bool set_send, int timeout_ms)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	int opt = set_send ? SO_SNDTIMEO_NEW : SO_RCVTIMEO_NEW;
	struct __kernel_sock_timeval timeout;
#else
	int opt = set_send ? SO_SNDTIMEO : SO_RCVTIMEO;
	struct timeval timeout;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	sockptr_t timeout_ptr = KERNEL_SOCKPTR(&timeout);
#else
	char *timeout_ptr = (char *)&timeout;
#endif

	timeout.tv_sec = timeout_ms / 1000;
	timeout.tv_usec = (timeout_ms % 1000) * 1000;
	sock_setsockopt(sock, SOL_SOCKET, opt, timeout_ptr, sizeof(timeout));
}

static int dnbd3_connect(dnbd3_device_t *dev, struct sockaddr_storage *addr, struct socket **sock_out)
{
	ktime_t start;
	int ret, connect_time_ms, diff;
	struct socket *sock;
	int retries = 4;
	const int addrlen = addr->ss_family == AF_INET ? sizeof(struct sockaddr_in)
		: sizeof(struct sockaddr_in6);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	ret = sock_create_kern(&init_net, addr->ss_family, SOCK_STREAM,
			IPPROTO_TCP, &sock);
#else
	ret = sock_create_kern(addr->ss_family, SOCK_STREAM,
			IPPROTO_TCP, &sock);
#endif
	if (ret < 0) {
		dev_err(dnbd3_device_to_dev(dev), "couldn't create socket: %d\n", ret);
		return ret;
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
		connect_time_ms = dev->panic_count * 333;
	} else {
		/* otherwise, use 2*RTT of current server */
		connect_time_ms = dev->cur_server.rtt * 2 / 1000;
	}
	/* but obey a minimal configurable value, and maximum sanity check */
	if (connect_time_ms < SOCKET_TIMEOUT_SEND * 1000)
		connect_time_ms = SOCKET_TIMEOUT_SEND * 1000;
	else if (connect_time_ms > 15000)
		connect_time_ms = 15000;
	set_socket_timeout(sock, false, connect_time_ms); // recv
	set_socket_timeout(sock, true, connect_time_ms); // send
	start = ktime_get_real();
	while (--retries > 0) {
		ret = kernel_connect(sock, (struct sockaddr *)addr, addrlen, 0);
		diff = (int)ktime_ms_delta(ktime_get_real(), start);
		if (diff > 2 * connect_time_ms) {
			/* Either I'm losing my mind or there was a specific build of kernel
			 * 5.x where SO_RCVTIMEO didn't affect the connect call above, so
			 * this function would hang for over a minute for unreachable hosts.
			 * Leave in this debug check for twice the configured timeout.
			 */
			dnbd3_dev_err_host(dev, addr, "connect: call took %dms (timeout: %dms)\n",
					diff, connect_time_ms);
		}
		if (ret != 0) {
			if (ret == -EINTR)
				dnbd3_dev_dbg_host(dev, addr, "connect: interrupted system call, blocked %dms (timeout: %dms)\n",
						diff, connect_time_ms);
			else
				dnbd3_dev_dbg_host(dev, addr, "connect: failed (%d, blocked %dms, timeout %dms)\n",
						ret, diff, connect_time_ms);
			goto error;
		}
		*sock_out = sock;
		return 0;
	}
error:
	sock_release(sock);
	return ret < 0 ? ret : -EIO;
}

#define dnbd3_err_dbg_host(...) do { \
		if (dev->panic || dev->sock == NULL) \
			dnbd3_dev_err_host(__VA_ARGS__); \
		else \
			dnbd3_dev_dbg_host(__VA_ARGS__); \
} while (0)

/**
 * Execute protocol handshake on a newly connected socket.
 * If this is the initial connection to any server, ie. we're being called
 * through the initial ioctl() to open a device, we'll store the rid, filesize
 * etc. in the dev struct., otherwise, this is a potential switch to another
 * server, so we validate the filesize, rid, name against what we expect.
 * The server's protocol version is returned in 'remote_version'
 */
static bool dnbd3_execute_handshake(dnbd3_device_t *dev, struct socket *sock,
		struct sockaddr_storage *addr, uint16_t *remote_version, bool copy_data)
{
	unsigned long irqflags;
	const char *name;
	uint64_t filesize;
	int mlen;
	uint16_t rid;
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL | MSG_WAITALL };
	struct kvec iov[2];
	serialized_buffer_t *payload;
	dnbd3_reply_t reply_hdr;
	dnbd3_request_t request_hdr = { .magic = dnbd3_packet_magic };

	payload = kmalloc(sizeof(*payload), GFP_KERNEL);
	if (payload == NULL)
		goto error;

	if (copy_data && device_active(dev))
		dev_warn(dnbd3_device_to_dev(dev), "Called handshake function with copy_data enabled when reported_size is not zero\n");

	// Request filesize
	request_hdr.cmd = CMD_SELECT_IMAGE;
	iov[0].iov_base = &request_hdr;
	iov[0].iov_len = sizeof(request_hdr);
	serializer_reset_write(payload);
	serializer_put_uint16(payload, PROTOCOL_VERSION); // DNBD3 protocol version
	serializer_put_string(payload, dev->imgname); // image name
	serializer_put_uint16(payload, dev->rid); // revision id
	serializer_put_uint8(payload, 0); // are we a server? (no!)
	iov[1].iov_base = payload;
	request_hdr.size = iov[1].iov_len = serializer_get_written_length(payload);
	fixup_request(request_hdr);
	mlen = iov[0].iov_len + iov[1].iov_len;
	if (kernel_sendmsg(sock, &msg, iov, 2, mlen) != mlen) {
		dnbd3_err_dbg_host(dev, addr, "requesting image size failed\n");
		goto error;
	}

	// receive net reply
	if (dnbd3_recv_reply(sock, &reply_hdr) != sizeof(reply_hdr)) {
		dnbd3_err_dbg_host(dev, addr, "receiving image size packet (header) failed\n");
		goto error;
	}
	if (reply_hdr.magic != dnbd3_packet_magic
			|| reply_hdr.cmd != CMD_SELECT_IMAGE || reply_hdr.size < 4
			|| reply_hdr.size > sizeof(*payload)) {
		dnbd3_err_dbg_host(dev, addr,
				"corrupt CMD_SELECT_IMAGE reply\n");
		goto error;
	}

	// receive data
	iov[0].iov_base = payload;
	iov[0].iov_len = reply_hdr.size;
	if (kernel_recvmsg(sock, &msg, iov, 1, reply_hdr.size, msg.msg_flags)
			!= reply_hdr.size) {
		dnbd3_err_dbg_host(dev, addr,
				"receiving payload of CMD_SELECT_IMAGE reply failed\n");
		goto error;
	}
	serializer_reset_read(payload, reply_hdr.size);

	*remote_version = serializer_get_uint16(payload);
	name = serializer_get_string(payload);
	rid = serializer_get_uint16(payload);
	filesize = serializer_get_uint64(payload);

	if (*remote_version < MIN_SUPPORTED_SERVER) {
		dnbd3_err_dbg_host(dev, addr,
				"server version too old (client: %d, server: %d, min supported: %d)\n",
				(int)PROTOCOL_VERSION, (int)*remote_version,
				(int)MIN_SUPPORTED_SERVER);
		goto error;
	}
	if (name == NULL || *name == '\0') {
		dnbd3_err_dbg_host(dev, addr, "server did not supply an image name\n");
		goto error;
	}
	if (rid == 0) {
		dnbd3_err_dbg_host(dev, addr, "server did not supply a revision id\n");
		goto error;
	}

	if (copy_data) {
		const size_t namelen = strlen(name);

		if (filesize < DNBD3_BLOCK_SIZE) {
			dnbd3_err_dbg_host(dev, addr, "reported size by server is < 4096\n");
			goto error;
		}
		spin_lock_irqsave(&dev->blk_lock, irqflags);
		if (strlen(dev->imgname) < namelen) {
			dev->imgname = krealloc(dev->imgname, namelen + 1, GFP_KERNEL);
			if (dev->imgname == NULL) {
				spin_unlock_irqrestore(&dev->blk_lock, irqflags);
				dnbd3_err_dbg_host(dev, addr, "reallocating buffer for new image name failed\n");
				goto error;
			}
		}
		strscpy(dev->imgname, name, namelen + 1);
		dev->rid = rid;
		// store image information
		dev->reported_size = filesize;
		dev->update_available = 0;
		spin_unlock_irqrestore(&dev->blk_lock, irqflags);
		set_capacity(dev->disk, dev->reported_size >> 9); /* 512 Byte blocks */
		dnbd3_dev_dbg_host(dev, addr, "image size: %llu\n", dev->reported_size);
	} else {
		/* switching connection, sanity checks */
		if (rid != dev->rid) {
			dnbd3_err_dbg_host(dev, addr,
					"server supplied wrong rid (client: '%d', server: '%d')\n",
					(int)dev->rid, (int)rid);
			goto error;
		}

		if (strcmp(name, dev->imgname) != 0) {
			dnbd3_err_dbg_host(dev, addr, "server offers image '%s', requested '%s'\n", name, dev->imgname);
			goto error;
		}

		if (filesize != dev->reported_size) {
			dnbd3_err_dbg_host(dev, addr,
					"reported image size of %llu does not match expected value %llu\n",
					(unsigned long long)filesize, (unsigned long long)dev->reported_size);
			goto error;
		}
	}
	kfree(payload);
	return true;

error:
	kfree(payload);
	return false;
}

static bool dnbd3_send_request(struct socket *sock, u16 cmd, u64 handle, u64 offset, u32 size)
{
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
	dnbd3_request_t request_hdr = {
		.magic = dnbd3_packet_magic,
		.cmd = cmd,
		.size = size,
		.offset = offset,
		.handle = handle,
	};
	struct kvec iov = { .iov_base = &request_hdr, .iov_len = sizeof(request_hdr) };

	fixup_request(request_hdr);
	return kernel_sendmsg(sock, &msg, &iov, 1, sizeof(request_hdr)) == sizeof(request_hdr);
}

/**
 * Send a request with given cmd type and empty payload.
 */
static bool dnbd3_send_empty_request(dnbd3_device_t *dev, u16 cmd)
{
	int ret;

	mutex_lock(&dev->send_mutex);
	ret = dev->sock
		&& dnbd3_send_request(dev->sock, cmd, 0, 0, 0);
	mutex_unlock(&dev->send_mutex);
	return ret;
}

static int dnbd3_recv_bytes(struct socket *sock, void *buffer, size_t count)
{
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL | MSG_WAITALL };
	struct kvec iov = { .iov_base = buffer, .iov_len = count };

	return kernel_recvmsg(sock, &msg, &iov, 1, count, msg.msg_flags);
}

static int dnbd3_recv_reply(struct socket *sock, dnbd3_reply_t *reply_hdr)
{
	int ret = dnbd3_recv_bytes(sock, reply_hdr, sizeof(*reply_hdr));

	fixup_reply(*reply_hdr);
	return ret;
}

static bool dnbd3_drain_socket(dnbd3_device_t *dev, struct socket *sock, int bytes)
{
	int ret;
	struct kvec iov;
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };

	while (bytes > 0) {
		iov.iov_base = __garbage_mem;
		iov.iov_len = sizeof(__garbage_mem);
		ret = kernel_recvmsg(sock, &msg, &iov, 1, MIN(bytes, iov.iov_len), msg.msg_flags);
		if (ret <= 0) {
			dnbd3_dev_err_cur(dev, "draining payload failed (ret=%d)\n", ret);
			return false;
		}
		bytes -= ret;
	}
	return true;
}

static bool dnbd3_request_test_block(dnbd3_device_t *dev, struct sockaddr_storage *addr,
		struct socket *sock, u64 test_start, u32 test_size)
{
	dnbd3_reply_t reply_hdr;

	// Request block
	if (!dnbd3_send_request(sock, CMD_GET_BLOCK, 0, test_start, test_size)) {
		dnbd3_err_dbg_host(dev, addr, "requesting test block failed\n");
		return false;
	}

	// receive reply header
	if (dnbd3_recv_reply(sock, &reply_hdr) != sizeof(reply_hdr)) {
		dnbd3_err_dbg_host(dev, addr, "receiving test block header packet failed\n");
		return false;
	}
	if (reply_hdr.magic != dnbd3_packet_magic || reply_hdr.cmd != CMD_GET_BLOCK
			|| reply_hdr.size != test_size || reply_hdr.handle != 0) {
		dnbd3_err_dbg_host(dev, addr,
				"unexpected reply to block request: cmd=%d, size=%d, handle=%llu (discover)\n",
				(int)reply_hdr.cmd, (int)reply_hdr.size, reply_hdr.handle);
		return false;
	}

	// receive data
	return dnbd3_drain_socket(dev, sock, test_size);
}
#undef dnbd3_err_dbg_host

static void replace_main_socket(dnbd3_device_t *dev, struct socket *sock, struct sockaddr_storage *addr, u16 protocol_version)
{
	unsigned long irqflags;

	mutex_lock(&dev->send_mutex);
	// First, shutdown connection, so receive worker will leave its mainloop
	if (dev->sock)
		kernel_sock_shutdown(dev->sock, SHUT_RDWR);
	mutex_lock(&dev->recv_mutex);
	// Receive worker is done, get rid of socket and replace
	if (dev->sock)
		sock_release(dev->sock);
	dev->sock = sock;
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	if (addr == NULL) {
		memset(&dev->cur_server, 0, sizeof(dev->cur_server));
	} else {
		dev->cur_server.host = *addr;
		dev->cur_server.rtt = 0;
		dev->cur_server.protocol_version = protocol_version;
	}
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
	mutex_unlock(&dev->recv_mutex);
	mutex_unlock(&dev->send_mutex);
}

static void dnbd3_release_resources(dnbd3_device_t *dev)
{
	if (dev->send_wq)
		destroy_workqueue(dev->send_wq);
	dev->send_wq = NULL;
	if (dev->recv_wq)
		destroy_workqueue(dev->recv_wq);
	dev->recv_wq = NULL;
	mutex_destroy(&dev->send_mutex);
	mutex_destroy(&dev->recv_mutex);
}

/**
 * Establish new connection on a dnbd3 device.
 * Return 0 on success, errno otherwise
 */
int dnbd3_new_connection(dnbd3_device_t *dev, struct sockaddr_storage *addr, bool init)
{
	unsigned long irqflags;
	struct socket *sock = NULL;
	uint16_t proto_version;
	int ret;

	ASSERT(dnbd3_flag_taken(dev->connection_lock));
	if (init && device_active(dev)) {
		dnbd3_dev_err_cur(dev, "device already configured/connected\n");
		return -EBUSY;
	}
	if (!init && !device_active(dev)) {
		dev_warn(dnbd3_device_to_dev(dev), "connection switch called on unconfigured device\n");
		return -ENOTCONN;
	}

	dnbd3_dev_dbg_host(dev, addr, "connecting...\n");
	ret = dnbd3_connect(dev, addr, &sock);
	if (ret != 0 || sock == NULL)
		goto error;

	/* execute the "select image" handshake */
	// if init is true, reported_size will be set
	if (!dnbd3_execute_handshake(dev, sock, addr, &proto_version, init)) {
		ret = -EINVAL;
		goto error;
	}

	if (init) {
		// We're setting up the device for use - allocate resources
		// Do not goto error before this
		ASSERT(!dev->send_wq);
		ASSERT(!dev->recv_wq);
		mutex_init(&dev->send_mutex);
		mutex_init(&dev->recv_mutex);
		// a designated queue for sending, that allows one active task only
		dev->send_wq = alloc_workqueue("dnbd%d-send",
				WQ_UNBOUND | WQ_FREEZABLE | WQ_MEM_RECLAIM | WQ_HIGHPRI,
				1, dev->index);
		dev->recv_wq = alloc_workqueue("dnbd%d-recv",
				WQ_UNBOUND | WQ_FREEZABLE | WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_CPU_INTENSIVE,
				1, dev->index);
		if (!dev->send_wq || !dev->recv_wq) {
			ret = -ENOMEM;
			goto error_dealloc;
		}
	}

	set_socket_timeout(sock, false, SOCKET_TIMEOUT_RECV * 1000); // recv
	dnbd3_set_primary_connection(dev, sock, addr, proto_version);
	sock = NULL; // In case we ever goto error* after this point

	spin_lock_irqsave(&dev->blk_lock, irqflags);
	if (init) {
		dev->discover_count = 0;
		dev->discover_interval = TIMER_INTERVAL_PROBE_STARTUP;
		// discovery and keepalive are not critical, use the power efficient queue
		queue_delayed_work(system_power_efficient_wq, &dev->discover_work,
				dev->discover_interval * HZ);
		queue_delayed_work(system_power_efficient_wq, &dev->keepalive_work,
				KEEPALIVE_INTERVAL * HZ);
		// but the receiver is performance critical AND runs indefinitely, use the
		// the cpu intensive queue, as jobs submitted there will not cound towards
		// the concurrency limit of per-cpu worker threads. It still feels a little
		// dirty to avoid managing our own thread, but nbd does it too.
	}
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);
	return 0;

error_dealloc:
	if (init) {
		// If anything fails during initialization, free resources again
		dnbd3_release_resources(dev);
	}
error:
	if (init)
		dev->reported_size = 0;
	if (sock)
		sock_release(sock);
	return ret < 0 ? ret : -EIO;
}

void dnbd3_net_work_init(dnbd3_device_t *dev)
{
	INIT_WORK(&dev->send_work, dnbd3_send_workfn);
	INIT_WORK(&dev->recv_work, dnbd3_recv_workfn);
	INIT_DELAYED_WORK(&dev->discover_work, dnbd3_discover_workfn);
	INIT_DELAYED_WORK(&dev->keepalive_work, dnbd3_keepalive_workfn);
}

static int dnbd3_set_primary_connection(dnbd3_device_t *dev, struct socket *sock, struct sockaddr_storage *addr, u16 protocol_version)
{
	unsigned long irqflags;

	ASSERT(dnbd3_flag_taken(dev->connection_lock));
	if (addr->ss_family == 0 || dev->imgname == NULL || sock == NULL) {
		dnbd3_dev_err_cur(dev, "connect: host, image name or sock not set\n");
		return -EINVAL;
	}

	replace_main_socket(dev, sock, addr, protocol_version);
	spin_lock_irqsave(&dev->blk_lock, irqflags);
	dev->panic = false;
	dev->panic_count = 0;
	dev->discover_interval = TIMER_INTERVAL_PROBE_SWITCH;
	queue_work(dev->recv_wq, &dev->recv_work);
	spin_unlock_irqrestore(&dev->blk_lock, irqflags);

	if (dev->use_server_provided_alts)
		dnbd3_send_empty_request(dev, CMD_GET_SERVERS);

	dnbd3_dev_info_cur(dev, "connection switched\n");
	dnbd3_blk_requeue_all_requests(dev);
	return 0;
}

/**
 * Disconnect the device, shutting it down.
 */
int dnbd3_net_disconnect(dnbd3_device_t *dev)
{
	ASSERT(dnbd3_flag_taken(dev->connection_lock));
	if (!device_active(dev))
		return -ENOTCONN;
	dev_dbg(dnbd3_device_to_dev(dev), "disconnecting device ...\n");

	dev->reported_size = 0;
	/* quickly fail all requests */
	dnbd3_blk_fail_all_requests(dev);
	replace_main_socket(dev, NULL, NULL, 0);

	cancel_delayed_work_sync(&dev->keepalive_work);
	cancel_delayed_work_sync(&dev->discover_work);
	cancel_work_sync(&dev->send_work);
	cancel_work_sync(&dev->recv_work);

	dnbd3_blk_fail_all_requests(dev);
	dnbd3_release_resources(dev);
	dev_dbg(dnbd3_device_to_dev(dev), "all workers shut down\n");
	return 0;
}
