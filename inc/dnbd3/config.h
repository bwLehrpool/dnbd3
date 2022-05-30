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

#ifndef CONFIG_H_
#define CONFIG_H_

// +++++ Network +++++
// Default port
#define PORT 5003
#define RPC_PORT (PORT+1)

// No serialized payload allowed exceeding this many bytes (so actual data from client->server is not affected by this limit!)
#define MAX_PAYLOAD 1000

// Protocol version should be increased whenever new features/messages are added,
// so either the client or server can run in compatibility mode, or they can
// cancel the connection right away if the protocol has changed too much
#define PROTOCOL_VERSION 3
// 2017-10-16: Update to v3: Change header to support request hop-counting

#define NUMBER_SERVERS 8 // Number of alt servers per image/device

// +++++ Block Device +++++
#define DNBD3_BLOCK_SIZE ((uint64_t)4096) // NEVER CHANGE THIS OR THE WORLD WILL END!

// +++++ COW +++++
#define COW_BITFIELD_SIZE 40 // NEVER CHANGE THIS OR THE WORLD WILL ALSO END!
#define COW_FILE_META_MAGIC_VALUE ((uint64_t)0xEBE44D6E72F7825E) // Magic Value to recognize a Cow .meta file
#define COW_FILE_DATA_MAGIC_VALUE ((uint64_t)0xEBE44D6E72F7825F) // Magic Value to recognize a Cow .data file
#define COW_MIN_UPLOAD_DELAY 60 // in seconds
#define COW_STATS_UPDATE_TIME 5 // time in seconds the cow status files gets updated (while uploading blocks)
// +++++ COW API Endpoints +++++
#define COW_API_CREATE "%s/api/File/Create"
#define COW_API_UPDATE "%s/api/File/Update?guid=%s&BlockNumber=%u"
#define COW_API_START_MERGE "%s/api/File/StartMerge?guid=%s&fileSize=%lld"

#endif /* CONFIG_H_ */
