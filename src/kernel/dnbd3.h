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

extern int major;

typedef struct
{
    // block
    struct gendisk *disk;
    spinlock_t blk_lock;

    // network
    char host[16];
    char port[6];
    int vid;
    int rid;
    struct socket *sock;
    struct timer_list hb_timer;
    struct request hb_request;

    // process
    struct task_struct *thread_send;
    struct task_struct *thread_receive;
    wait_queue_head_t process_queue_send;
    wait_queue_head_t process_queue_receive;
    struct list_head request_queue_send;
    struct list_head request_queue_receive;

} dnbd3_device_t;

#endif /* DNBD_H_ */
