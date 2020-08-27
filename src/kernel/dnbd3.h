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
#include <net/sock.h>

#define KERNEL_MODULE
#include "config.h"
#include "types.h"
#include "serialize.h"

extern int major;

typedef struct
{
	dnbd3_host_t host;
	unsigned long rtts[4];		// Last four round trip time measurements in µs
	uint16_t protocol_version;	// dnbd3 protocol version of this server
	uint8_t failures;			// How many times the server was unreachable
} dnbd3_server_t;

typedef struct
{
	// block
	struct gendisk *disk;
	struct blk_mq_tag_set tag_set;
	struct request_queue *queue;
	spinlock_t blk_lock;

	// sysfs
	struct kobject kobj;

	// network
	char *imgname;
	struct socket *sock;
	dnbd3_server_t cur_server, initial_server;
	unsigned long cur_rtt;
	serialized_buffer_t payload_buffer;
	dnbd3_server_t alt_servers[NUMBER_SERVERS]; // array of alt servers
	int new_servers_num;	// number of new alt servers that are waiting to be copied to above array
	dnbd3_server_entry_t new_servers[NUMBER_SERVERS]; // pending new alt servers
	uint8_t discover, panic, disconnecting, update_available, panic_count;
	uint8_t use_server_provided_alts;
	uint16_t rid;
	uint32_t heartbeat_count;
	uint64_t reported_size;
	// server switch
	struct socket *better_sock;

	// process
	struct task_struct * thread_send;
	struct task_struct * thread_receive;
	struct task_struct *thread_discover;
	struct timer_list hb_timer;
	wait_queue_head_t process_queue_send;
	wait_queue_head_t process_queue_receive;
	wait_queue_head_t process_queue_discover;
	struct list_head request_queue_send;
	struct list_head request_queue_receive;

} dnbd3_device_t;

#endif /* DNBD_H_ */
