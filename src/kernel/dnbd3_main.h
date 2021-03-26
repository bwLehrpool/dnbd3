/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef DNBD_H_
#define DNBD_H_

#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/mutex.h>
#include <net/sock.h>

#include <dnbd3/config.h>
#include <dnbd3/types.h>
#include <dnbd3/shared/serialize.h>

extern int major;

typedef struct {
	unsigned long rtts[4];     // Last four round trip time measurements in µs
	uint16_t protocol_version; // dnbd3 protocol version of this server
	uint8_t failures;          // How many times the server was unreachable
	uint8_t best_count;        // Number of times server measured best
	struct sockaddr_storage host; // Address of server
} dnbd3_alt_server_t;

typedef struct {
	// block
	struct gendisk *disk;
	struct blk_mq_tag_set tag_set;
	struct request_queue *queue;
	spinlock_t blk_lock;

	// sysfs
	struct kobject kobj;

	// network
	struct mutex alt_servers_lock;
	char *imgname;
	struct socket *sock;
	struct {
		unsigned long rtt;
		struct sockaddr_storage host;
		uint16_t protocol_version;
	} cur_server;
	serialized_buffer_t payload_buffer;
	dnbd3_alt_server_t alt_servers[NUMBER_SERVERS]; // array of alt servers, protected by alt_servers_lock
	uint8_t discover, panic, update_available, panic_count;
	atomic_t connection_lock;
	uint8_t use_server_provided_alts;
	uint16_t rid;
	uint32_t heartbeat_count;
	uint64_t reported_size;
	// server switch
	struct socket *better_sock;

	// process
	struct task_struct *thread_send;
	struct task_struct *thread_receive;
	struct task_struct *thread_discover;
	struct timer_list hb_timer;
	wait_queue_head_t process_queue_send;
	wait_queue_head_t process_queue_discover;
	struct list_head request_queue_send;
	struct list_head request_queue_receive;

} dnbd3_device_t;

extern inline struct device *dnbd3_device_to_dev(dnbd3_device_t *dev);

extern inline int is_same_server(const struct sockaddr_storage *const x, const struct sockaddr_storage *const y);

extern int dnbd3_host_to_sockaddr(const dnbd3_host_t *host, struct sockaddr_storage *dest);

extern dnbd3_alt_server_t *get_existing_alt_from_host(const dnbd3_host_t *const host, dnbd3_device_t *const dev);

extern dnbd3_alt_server_t *get_existing_alt_from_addr(const struct sockaddr_storage *const addr,
		dnbd3_device_t *const dev);

extern int dnbd3_add_server(dnbd3_device_t *dev, dnbd3_host_t *host);

extern int dnbd3_rem_server(dnbd3_device_t *dev, dnbd3_host_t *host);

#endif /* DNBD_H_ */
