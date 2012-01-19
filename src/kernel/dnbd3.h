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

#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <net/sock.h>

#include "config.h"
#include "types.h"

// block
extern struct gendisk *disk;
extern spinlock_t dnbd3_lock;

// network
extern char* _host;
extern char* _port;
extern struct socket *_sock;

// process
extern wait_queue_head_t _process_queue_send;
extern wait_queue_head_t _process_queue_receive;
extern struct list_head _request_queue_send;
extern struct list_head _request_queue_receive;

#endif /* DNBD_H_ */
