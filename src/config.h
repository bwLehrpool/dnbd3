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

#ifndef CONFIG_H_
#define CONFIG_H_

// ##############################
// ########### SERVER ###########

// +++++ Performance related
#define SERVER_MAX_CLIENTS 2000
#define SERVER_MAX_IMAGES  5000
#define SERVER_MAX_ALTS    250
#define SERVER_MAX_UPLINK_QUEUE  1500
#define SERVER_MAX_UPLINK_FAILS  8 // How many times may a server fail until it is considered bad
#define SERVER_BAD_UPLINK_IGNORE 120 // How many seconds is a server considered bad?
#define SERVER_UPLINK_QUEUELEN_THRES  900
#define SERVER_MAX_PENDING_ALT_CHECKS 50
#define SERVER_CACHE_MAP_SAVE_INTERVAL 90

// +++++ Other magic constants
#define SERVER_RTT_PROBES 5
#define SERVER_RTT_DELAY_INIT 5
#define SERVER_RTT_DELAY_MAX 45
#define SERVER_RTT_DELAY_FAILED 180

#define SERVER_REMOTE_IMAGE_CHECK_CACHETIME 600 // 10 minutes
#define SERVER_MAX_PROXY_IMAGE_SIZE 100000000000LL // 100GB
// +++++ Network +++++
// Default port
#define PORT 5003
#define RPC_PORT (PORT+1)

// No serialized payload allowed exceeding this many bytes (so actual data from client->server is not affected by this limit!)
#define MAX_PAYLOAD 1000

// Protocol version should be increased whenever new features/messages are added,
// so either the client or server can run in compatibility mode, or they can
// cancel the connection right away if the protocol has changed too much
#define PROTOCOL_VERSION 2
// Which is the minimum protocol version the server expects from the client
#define MIN_SUPPORTED_CLIENT 2
// Which is the minimum protocol version the client expects from the server
#define MIN_SUPPORTED_SERVER 2
// Length of comment fields (for alt server etc.)
#define COMMENT_LENGTH 120

// in seconds if not stated otherwise (MS = milliseconds)
#define SOCKET_TIMEOUT_SERVER_MS 15000
#define SOCKET_TIMEOUT_SERVER_RETRIES 3 // When waiting for next header, max reties * above timeout is the actual total timeout (ping timeout)
#define SOCKET_TIMEOUT_CLIENT_DATA 2
#define SOCKET_TIMEOUT_CLIENT_DISCOVERY 1

#define NUMBER_SERVERS 8 // Number of alt servers per image/device
#define RTT_THRESHOLD_FACTOR(us) (((us) * 2) / 3) // 2/3 = current to best must be 33% worse
#define RTT_UNREACHABLE 0x7FFFFFFul // Use this value for timeout/unreachable as RTT. Don't set too high or you might get overflows. 0x7FFFFFF = 134 seconds
// This must be a power of two:
#define RTT_BLOCK_SIZE 4096

#define STARTUP_MODE_DURATION 30
// Interval of several repeating tasks (in seconds)
#define TIMER_INTERVAL_PROBE_STARTUP 4
#define TIMER_INTERVAL_PROBE_NORMAL 22
#define TIMER_INTERVAL_PROBE_PANIC 2
#define TIMER_INTERVAL_KEEPALIVE_PACKET 6

// Expect a keepalive response every X seconds
#define SOCKET_KEEPALIVE_TIMEOUT 7

// Number of unsuccessful alt_server probes before read errors are reported to the block layer
// (ALL servers will be probed this many times)
#define PROBE_COUNT_TIMEOUT 20

// +++++ Block Device +++++
#define KERNEL_SECTOR_SIZE 512
#define DNBD3_BLOCK_SIZE ((uint64_t)4096) // NEVER CHANGE THIS OR THE WORLD WILL END!
#define NUMBER_DEVICES 8
#define DEFAULT_READ_AHEAD_KB 512

#endif /* CONFIG_H_ */
