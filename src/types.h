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

#ifndef TYPES_H_
#define TYPES_H_

#include "config.h"
#ifndef KERNEL_MODULE
#include <stdint.h>
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

// ioctl
#define DNBD3_MAGIC     'd'
#define IOCTL_OPEN      _IO(0xab, 1)
#define IOCTL_CLOSE     _IO(0xab, 2)
#define IOCTL_SWITCH    _IO(0xab, 3)
#define IOCTL_ADD_SRV	_IO(0xab, 4)
#define IOCTL_REM_SRV	_IO(0xab, 5)

#if defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER) && defined(__BIG_ENDIAN) && __BYTE_ORDER == __BIG_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
static const uint16_t dnbd3_packet_magic = (0x73 << 8) | (0x72);
// Flip bytes around on big endian when putting stuff on the net
#define net_order_64(a) ((uint64_t)((((a) & 0xFFull) << 56) | (((a) & 0xFF00ull) << 40) | (((a) & 0xFF0000ull) << 24) | (((a) & 0xFF000000ull) << 8) | (((a) & 0xFF00000000ull) >> 8) | (((a) & 0xFF0000000000ull) >> 24) | (((a) & 0xFF000000000000ull) >> 40) | (((a) & 0xFF00000000000000ull) >> 56)))
#define net_order_32(a) ((uint32_t)((((a) & (uint32_t)0xFF) << 24) | (((a) & (uint32_t)0xFF00) << 8) | (((a) & (uint32_t)0xFF0000) >> 8) | (((a) & (uint32_t)0xFF000000) >> 24)))
#define net_order_16(a) ((uint16_t)((((a) & (uint16_t)0xFF) << 8) | (((a) & (uint16_t)0xFF00) >> 8)))
#define fixup_request(a) do { \
	(a).cmd = net_order_16((a).cmd); \
	(a).size = net_order_32((a).size); \
	(a).offset = net_order_64((a).offset); \
} while (0)
#define fixup_reply(a) do { \
	(a).cmd = net_order_16((a).cmd); \
	(a).size = net_order_32((a).size); \
} while (0)
#define ENDIAN_MODE "Big Endian"
#elif defined(__LITTLE_ENDIAN__) || (defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(__i386__) || defined(__i386)
static const uint16_t dnbd3_packet_magic = (0x73) | (0x72 << 8);
// Make little endian our network byte order as probably 99.999% of machines this will be used on are LE
#define net_order_64(a) (a)
#define net_order_32(a) (a)
#define net_order_16(a) (a)
#define fixup_request(a) while(0)
#define fixup_reply(a)   while(0)
#define ENDIAN_MODE "Little Endian"
#else
#error "Unknown Endianness"
#endif

#pragma pack(1)
typedef struct
{
	uint8_t addr[16];	   // 16byte (network representation, so it can be directly passed to socket functions)
	uint16_t port;		   // 2byte (network representation, so it can be directly passed to socket functions)
	uint8_t type;        // 1byte (ip version. AF_INET or AF_INET6. 0 means this struct is empty and should be ignored)
} dnbd3_host_t;
#pragma pack(0)

typedef struct
{
	uint16_t len;
	dnbd3_host_t host;
	uint16_t imgnamelen;
	char *imgname;
	int rid;
	int read_ahead_kb;
	uint8_t is_server;     // FALSE = automatic (real client), TRUE = manual control (proxy)
} dnbd3_ioctl_t;

// network
#define CMD_GET_BLOCK           1
#define CMD_SELECT_IMAGE        2
#define CMD_GET_SERVERS         3
#define CMD_ERROR               4
#define CMD_KEEPALIVE           5
#define CMD_LATEST_RID          6
#define CMD_SET_CLIENT_MODE     7
#define CMD_GET_CRC32           8

#pragma pack(1)
typedef struct
{
	uint16_t magic;		// 2byte
	uint16_t cmd;       // 2byte
	uint32_t size;      // 4byte
	uint64_t offset;	// 8byte
	uint64_t handle;    // 8byte
} dnbd3_request_t;
#pragma pack(0)

#pragma pack(1)
typedef struct
{
	uint16_t magic;		// 2byte
	uint16_t cmd;		// 2byte
	uint32_t size;		// 4byte
	uint64_t handle;	// 8byte
} dnbd3_reply_t;
#pragma pack(0)

#pragma pack(1)
typedef struct
{
	dnbd3_host_t host;
	uint8_t  failures;		// 1byte (number of times server has been consecutively unreachable)
} dnbd3_server_entry_t;
#pragma pack(0)

#endif /* TYPES_H_ */
