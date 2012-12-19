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

#ifndef RPC_H_
#define RPC_H_

#include <stdint.h>

#define RPC_EXIT           0
#define RPC_RELOAD         1
#define RPC_IMG_LIST       2
#define RPC_ADD_IMG        3
#define RPC_DEL_IMG        4
#define RPC_ADD_NS         5
#define RPC_DEL_NS         6
#define RPC_CLIENT_LIST    7
#define RPC_TRUSTED_LIST   8
#define RPC_GET_LOG        9
#define RPC_FIX_IMAGE     10
#define RPC_ERROR         11

void *dnbd3_rpc_mainloop();

void dnbd3_rpc_shutdown();

void dnbd3_rpc_send(int cmd);


#pragma pack(1)
typedef struct
{
	uint32_t handle;// 4byte
	uint32_t cmd;	// 4byte
	uint32_t size;	// 4byte
} dnbd3_rpc_t;
#pragma pack(0)

#endif /* RPC_H_ */
