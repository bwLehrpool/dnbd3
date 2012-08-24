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

// +++++ Network +++++
// Default port
#define PORT 5003
#define PORTSTR "5003"

// Protocol version should be increased whenever new features/messages are added,
// so either the client or server can run in compatibility mode, or they can
// cancel the connection right away if the protocol has changed too much
#define PROTOCOL_VERSION 1
// Which is the minimum protocol version the server expects from the client
#define MIN_SUPPORTED_CLIENT 1
// Which is the minimum protocol version the client expects from the server
#define MIN_SUPPORTED_SERVER 1

// No payload allowed exceeding this many bytes:
#define MAX_PAYLOAD 1000

#define SOCKET_TIMEOUT_SERVER 30
#define SOCKET_TIMEOUT_CLIENT_DATA 2
#define SOCKET_TIMEOUT_CLIENT_DISCOVERY 1

#define NUMBER_SERVERS 8
#define RTT_THRESHOLD 1000
// This must be a power of two:
#define RTT_BLOCK_SIZE 4096

#define TIMER_INTERVAL_HEARTBEAT 10*HZ
#define TIMER_INTERVAL_PANIC 2*HZ

// +++++ Block Device +++++
#define KERNEL_SECTOR_SIZE 512
#define DNBD3_BLOCK_SIZE 4096
#define NUMBER_DEVICES 8
#define DEFAULT_READ_AHEAD_KB 256

// +++++ Misc +++++
#define DEFAULT_SERVER_CONFIG_FILE "/etc/dnbd3/server.conf"
#define DEFAULT_CLIENT_CONFIG_FILE "/etc/dnbd3/client.conf"
#define UNIX_SOCKET "/run/dnbd3-server.sock"
#define UNIX_SOCKET_GROUP "dnbd"
#define IPC_PORT 5004

#endif /* CONFIG_H_ */
