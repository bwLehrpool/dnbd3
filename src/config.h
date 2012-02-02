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

// network
#define PORT 5003
#define SERVER_SOCKET_TIMEOUT 30
#define HB_INTERVAL 20*HZ

// block device
#define KERNEL_SECTOR_SIZE 512
#define DNBD3_BLOCK_SIZE 4096
#define MAX_NUMBER_DEVICES 8

// misc
#define DEFAULT_CONFIG_FILE "/etc/dnbd3-server.conf"
#define SERVER_PID_FILE "/tmp/dnbd3-server.pid"

#endif /* CONFIG_H_ */
