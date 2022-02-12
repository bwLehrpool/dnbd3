/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef DNBD_H_
#define DNBD_H_

#include <dnbd3/config/client.h>

#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include <net/sock.h>

#include <dnbd3/config.h>
#include <dnbd3/types.h>
#include <dnbd3/shared/serialize.h>

#include <linux/blk-mq.h>

extern int major;

typedef struct {
	unsigned long rtts[DISCOVER_HISTORY_SIZE]; // Last X round trip time measurements in µs
	uint16_t protocol_version; // dnbd3 protocol version of this server
	uint8_t failures;          // How many times the server was unreachable
	uint8_t best_count;        // Number of times server measured best
	struct sockaddr_storage host; // Address of server
} dnbd3_alt_server_t;

typedef struct {
	// block
	int                        index;
	struct gendisk            *disk;
	struct blk_mq_tag_set      tag_set;
	struct request_queue      *queue;
	spinlock_t                 blk_lock;

	// sysfs
	struct kobject             kobj;

	char                      *imgname;
	uint16_t                   rid;
	struct socket             *sock;
	struct { // use blk_lock
		unsigned long           rtt;
		struct sockaddr_storage host;
		uint16_t                protocol_version;
	}              cur_server;
	serialized_buffer_t        payload_buffer;
	struct mutex               alt_servers_lock;
	dnbd3_alt_server_t         alt_servers[NUMBER_SERVERS];
	bool                       use_server_provided_alts;
	bool                       panic;
	u8                         panic_count;
	bool                       update_available;
	atomic_t                   connection_lock;
	// Size if image/device - this is 0 if the device is not in use,
	// otherwise this is also the value we expect from alt servers.
	uint64_t                   reported_size;
	struct delayed_work        keepalive_work;

	// sending
	struct workqueue_struct   *send_wq;
	spinlock_t                 send_queue_lock;
	struct list_head           send_queue;
	struct mutex               send_mutex;
	struct work_struct         send_work;
	// receiving
	struct workqueue_struct   *recv_wq;
	spinlock_t                 recv_queue_lock;
	struct list_head           recv_queue;
	struct mutex               recv_mutex;
	struct work_struct         recv_work;
	// discover
	atomic_t                   discover_running;
	struct delayed_work        discover_work;
	u32                        discover_interval;
	u32                        discover_count;

} dnbd3_device_t;

struct dnbd3_cmd {
	u64        handle;
};

extern inline struct device *dnbd3_device_to_dev(dnbd3_device_t *dev);

extern inline int is_same_server(const struct sockaddr_storage *const x, const struct sockaddr_storage *const y);

extern int dnbd3_host_to_sockaddr(const dnbd3_host_t *host, struct sockaddr_storage *dest);

extern dnbd3_alt_server_t *get_existing_alt_from_host(const dnbd3_host_t *const host, dnbd3_device_t *const dev);

extern dnbd3_alt_server_t *get_existing_alt_from_addr(const struct sockaddr_storage *const addr,
		dnbd3_device_t *const dev);

extern int dnbd3_add_server(dnbd3_device_t *dev, dnbd3_host_t *host);

extern int dnbd3_rem_server(dnbd3_device_t *dev, dnbd3_host_t *host);

#define dnbd3_flag_get(x) (atomic_cmpxchg(&(x), 0, 1) == 0)
#define dnbd3_flag_reset(x) atomic_set(&(x), 0)
#define dnbd3_flag_taken(x) (atomic_read(&(x)) != 0)

/* shims for making older kernels look like the current one, if possible, to avoid too
 * much inline #ifdef which makes code harder to read. */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#define BLK_EH_DONE BLK_EH_NOT_HANDLED
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define blk_status_t int
#define	BLK_STS_OK 0
#define	BLK_STS_IOERR (-EIO)
#define	BLK_STS_TIMEOUT (-ETIME)
#define	BLK_STS_NOTSUPP (-ENOTSUPP)
#endif

#endif /* DNBD_H_ */
