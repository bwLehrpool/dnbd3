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

#ifndef IPC_H_
#define IPC_H_

#define IPC_EXIT 0
#define IPC_RELOAD 1
#define IPC_INFO 2
#define IPC_ADDIMG 3
#define IPC_DELIMG 4

void* dnbd3_ipc_receive();

void dnbd3_ipc_send(int cmd);


#pragma pack(1)
typedef struct
{
    uint32_t cmd;	// 4byte
    uint32_t size;	// 4byte
    uint32_t error;	// 4byte
} dnbd3_ipc_t;
#pragma pack(0)

#endif /* IPC_H_ */
