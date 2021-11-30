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

#ifndef BLK_H_
#define BLK_H_

#include "dnbd3_main.h"

/* define blkdev file system operation type */
#define DNBD3_REQ_OP_FS           REQ_TYPE_FS

/* define blkdev special operation type */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define DNBD3_REQ_OP_SPECIAL      REQ_OP_DRV_IN
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) || \
	RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 3))
#define DNBD3_REQ_OP_SPECIAL      REQ_TYPE_DRV_PRIV
#else
#define DNBD3_REQ_OP_SPECIAL      REQ_TYPE_SPECIAL
#endif

/* define blkdev read operation type */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define DNBD3_DEV_READ            REQ_OP_READ
#else
#define DNBD3_DEV_READ            DNBD3_REQ_OP_FS
#endif

/* define blkdev write operation type */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define DNBD3_DEV_WRITE           REQ_OP_WRITE
#else
#define DNBD3_DEV_WRITE           DNBD3_REQ_OP_FS
#endif

/* define command and blkdev operation access macros */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define DNBD3_REQ_FLAG_BITS       REQ_FLAG_BITS
/* cmd_flags and cmd_type are merged into cmd_flags now */
/* sanity check to avoid overriding of request bits */
#if DNBD3_REQ_FLAG_BITS > 24
#error "Fix CMD bitshift"
#endif
/* pack command into cmd_flags field by shifting CMD_* into unused bits of cmd_flags */
#define dnbd3_cmd_to_priv(req, cmd) \
	((req)->cmd_flags = DNBD3_REQ_OP_SPECIAL | ((cmd) << DNBD3_REQ_FLAG_BITS))
#define dnbd3_priv_to_cmd(req) \
	((req)->cmd_flags >> DNBD3_REQ_FLAG_BITS)
#define dnbd3_req_op(req) \
	req_op(req)
#else
/* pack command into cmd_type and cmd_flags field separated */
#define dnbd3_cmd_to_priv(req, cmd) \
	do { \
		(req)->cmd_type = DNBD3_REQ_OP_SPECIAL; \
		(req)->cmd_flags = (cmd); \
	} while (0)
#define dnbd3_priv_to_cmd(req) \
	((req)->cmd_flags)
#define dnbd3_req_op(req) \
	((req)->cmd_type)
#endif

/* define dnbd3_req_read(req) boolean expression */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define dnbd3_req_read(req) \
	(req_op(req) == DNBD3_DEV_READ)
#else
#define dnbd3_req_read(req) \
	(rq_data_dir(req) == READ)
#endif

/* define dnbd3_req_write(req) boolean expression */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define dnbd3_req_write(req) \
	(req_op(req) == DNBD3_DEV_WRITE)
#else
#define dnbd3_req_write(req) \
	(rq_data_dir(req) == WRITE)
#endif

/* define dnbd3_req_fs(req) boolean expression */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define dnbd3_req_fs(req) \
	(dnbd3_req_read(req) || dnbd3_req_write(req))
#else
#define dnbd3_req_fs(req) \
	(dnbd3_req_op(req) == DNBD3_REQ_OP_FS)
#endif

/* define dnbd3_req_special(req) boolean expression */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#define dnbd3_req_special(req) \
	(dnbd3_req_op(req) == DNBD3_REQ_OP_SPECIAL)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define dnbd3_req_special(req) \
	blk_rq_is_private(req)
#else
#define dnbd3_req_special(req) \
	(dnbd3_req_op(req) == DNBD3_REQ_OP_SPECIAL)
#endif

int dnbd3_blk_add_device(dnbd3_device_t *dev, int minor);

int dnbd3_blk_del_device(dnbd3_device_t *dev);

void dnbd3_blk_fail_all_requests(dnbd3_device_t *dev);

#endif /* BLK_H_ */
