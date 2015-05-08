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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>

#include "sockhelper.h"
#include "helper.h"
#include "server.h"
#include "image.h"
#include "uplink.h"
#include "altservers.h"
#include "log.h"
#include "helper.h"
#include "../serialize.h"
#include "../config.h"
#include "../types.h"
#include "locks.h"
#include "rpc.h"


static uint64_t totalBytesSent = 0;
static pthread_spinlock_t statisticsSentLock;

static inline bool recv_request_header(int sock, dnbd3_request_t *request)
{
	int ret, fails = 0;
	// Read request header from socket
	while ( (ret = recv( sock, request, sizeof(*request), MSG_WAITALL )) != sizeof(*request) ) {
		if ( errno == EINTR && ++fails < 10 ) continue;
		if ( ret >= 0 || ++fails > SOCKET_TIMEOUT_SERVER_RETRIES ) return false;
		if ( errno == EAGAIN ) continue;
		logadd( LOG_DEBUG1, "Error receiving request: Could not read message header (%d/%d, e=%d)\n", ret, (int)sizeof(*request), errno );
		return false;
	}
	// Make sure all bytes are in the right order (endianness)
	fixup_request( *request );
	if ( request->magic != dnbd3_packet_magic ) {
		logadd( LOG_DEBUG2, "Magic in client request incorrect (cmd: %d, len: %d)\n", (int)request->cmd, (int)request->size );
		return false;
	}
	// Payload sanity check
	if ( request->cmd != CMD_GET_BLOCK && request->size > MAX_PAYLOAD ) {
		logadd( LOG_WARNING, "Client tries to send a packet of type %d with %d bytes payload. Dropping client.", (int)request->cmd, (int)request->size );
		return false;
	}
	return true;
}

static inline bool recv_request_payload(int sock, uint32_t size, serialized_buffer_t *payload)
{
	if ( size == 0 ) {
		logadd( LOG_ERROR, "Called recv_request_payload() to receive 0 bytes" );
		return false;
	}
	if ( size > MAX_PAYLOAD ) {
		logadd( LOG_ERROR, "Called recv_request_payload() for more bytes than the passed buffer could hold!" );
		return false;
	}
	if ( recv( sock, payload->buffer, size, MSG_WAITALL ) != size ) {
		logadd( LOG_DEBUG1, "Could not receive request payload of length %d\n", (int)size );
		return false;
	}
	// Prepare payload buffer for reading
	serializer_reset_read( payload, size );
	return true;
}

static inline bool send_reply(int sock, dnbd3_reply_t *reply, void *payload)
{
	const unsigned int size = reply->size;
	fixup_reply( *reply );
	if ( !payload || size == 0 ) {
		if ( send( sock, reply, sizeof(dnbd3_reply_t), 0 ) != sizeof(dnbd3_reply_t) ) {
			logadd( LOG_DEBUG1, "Send failed (header-only)\n" );
			return false;
		}
	} else {
		struct iovec iov[2];
		iov[0].iov_base = reply;
		iov[0].iov_len = sizeof(dnbd3_reply_t);
		iov[1].iov_base = payload;
		iov[1].iov_len = (size_t)size;
		if ( (size_t)writev( sock, iov, 2 ) != sizeof(dnbd3_reply_t) + size ) {
			logadd( LOG_DEBUG1, "Send failed (reply with payload of %u bytes)\n", size );
			return false;
		}
	}
	return true;
}

uint64_t net_getTotalBytesSent()
{
	spin_lock( &statisticsSentLock );
	uint64_t tmp = totalBytesSent;
	spin_unlock( &statisticsSentLock );
	return tmp;
}

void net_init()
{
	spin_init( &statisticsSentLock, PTHREAD_PROCESS_PRIVATE );
}

void *net_client_handler(void *dnbd3_client)
{
	dnbd3_client_t *client = (dnbd3_client_t *)dnbd3_client;
	dnbd3_request_t request;
	dnbd3_reply_t reply;

	dnbd3_image_t *image = NULL;
	int image_file = -1;

	int num;
	bool bOk = false;
	bool hasName = false;

	serialized_buffer_t payload;
	char *image_name;
	uint16_t rid, client_version;
	uint64_t start, end;
	char buffer[100];

	dnbd3_server_entry_t server_list[NUMBER_SERVERS];

	// Set to zero to make valgrind happy
	memset( &reply, 0, sizeof(reply) );
	memset( &payload, 0, sizeof(payload) );
	reply.magic = dnbd3_packet_magic;

	sock_setTimeout( client->sock, _clientTimeout );

	// Receive first packet. This must be CMD_SELECT_IMAGE by protocol specification
	if ( recv_request_header( client->sock, &request ) ) {
		if ( request.cmd != CMD_SELECT_IMAGE ) {
			logadd( LOG_DEBUG1, "Client sent invalid handshake (%d). Dropping Client\n", (int)request.cmd );
		} else {
			if ( recv_request_payload( client->sock, request.size, &payload ) ) {
				client_version = serializer_get_uint16( &payload );
				image_name = serializer_get_string( &payload );
				rid = serializer_get_uint16( &payload );
				client->isServer = serializer_get_uint8( &payload );
				if ( request.size < 3 || !image_name || client_version < MIN_SUPPORTED_CLIENT ) {
					if ( client_version < MIN_SUPPORTED_CLIENT ) {
						logadd( LOG_DEBUG1, "Client too old\n" );
					} else {
						logadd( LOG_DEBUG1, "Incomplete handshake received\n" );
					}
				} else {
					client->image = image = image_getOrClone( image_name, rid );
					if ( image == NULL ) {
						//logadd( LOG_DEBUG1, "Client requested non-existent image '%s' (rid:%d), rejected\n", image_name, (int)rid );
					} else if ( !image->working ) {
						logadd( LOG_DEBUG1, "Client requested non-working image '%s' (rid:%d), rejected\n", image_name, (int)rid );
					} else {
						image_file = image->readFd;
						serializer_reset_write( &payload );
						serializer_put_uint16( &payload, PROTOCOL_VERSION );
						serializer_put_string( &payload, image->lower_name );
						serializer_put_uint16( &payload, image->rid );
						serializer_put_uint64( &payload, image->filesize );
						reply.cmd = CMD_SELECT_IMAGE;
						reply.size = serializer_get_written_length( &payload );
						if ( send_reply( client->sock, &reply, &payload ) ) {
							if ( !client->isServer ) image->atime = time( NULL );
							bOk = true;
						}
					}
				}
			}
		}
	} else if ( strncmp( (char*)&request, "GET ", 4 ) == 0 || strncmp( (char*)&request, "POST ", 5 ) == 0 ) {
		rpc_sendStatsJson( client->sock );
	}

	if ( bOk ) {
		// add artificial delay if applicable
		if ( client->isServer && _serverPenalty != 0 ) {
			usleep( _serverPenalty );
		} else if ( !client->isServer && _clientPenalty != 0 ) {
			usleep( _clientPenalty );
		}
		// client handling mainloop
		while ( recv_request_header( client->sock, &request ) ) {
			if ( _shutdown ) break;
			switch ( request.cmd ) {

			case CMD_GET_BLOCK:
				if ( request.offset >= image->filesize ) {
					// Sanity check
					logadd( LOG_WARNING, "Client requested non-existent block" );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}
				if ( request.offset + request.size > image->filesize ) {
					// Sanity check
					logadd( LOG_WARNING, "Client requested data block that extends beyond image size" );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}
				if ( request.size > image->filesize ) {
					// Sanity check
					logadd( LOG_WARNING, "Client requested data block that is bigger than the image size" );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}
				//printf( "Request - size: %" PRIu32 ", offset: %" PRIu64 "\n", request.size, request.offset );

				if ( request.size != 0 && image->cache_map != NULL ) {
					// This is a proxyed image, check if we need to relay the request...
					start = request.offset & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					end = (request.offset + request.size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					bool isCached = true;
					spin_lock( &image->lock );
					// Check again as we only aquired the lock just now
					if ( image->cache_map != NULL ) {
						const uint64_t firstByte = start >> 15;
						const uint64_t lastByte = (end - 1) >> 15;
						// First byte
						uint64_t pos = start;
						do {
							const int map_x = (pos >> 12) & 7; // mod 8
							const uint8_t bit_mask = 1 << map_x;
							if ( (image->cache_map[firstByte] & bit_mask) == 0 ) {
								isCached = false;
								break;
							}
							pos += DNBD3_BLOCK_SIZE;
						} while ( firstByte == (pos >> 15) && pos < end );
						// Middle - quick checking
						if ( isCached ) {
							pos = firstByte + 1;
							while ( pos < lastByte ) {
								if ( image->cache_map[pos] != 0xff ) {
									isCached = false;
									break;
								}
								++pos;
							}
						}
						// Last byte
						if ( isCached && firstByte != lastByte ) {
							pos = lastByte << 15;
							while ( pos < end ) {
								assert( lastByte == (pos >> 15) );
								const int map_x = (pos >> 12) & 7; // mod 8
								const uint8_t bit_mask = 1 << map_x;
								if ( (image->cache_map[lastByte] & bit_mask) == 0 ) {
									isCached = false;
									break;
								}
								pos += DNBD3_BLOCK_SIZE;
							}
						}
					}
					spin_unlock( &image->lock );
					if ( !isCached ) {
						if ( !uplink_request( client, request.handle, request.offset, request.size ) ) {
							logadd( LOG_DEBUG1, "Could not relay uncached request to upstream proxy\n" );
							goto exit_client_cleanup;
						}
						break; // DONE
					}
				}

				reply.cmd = CMD_GET_BLOCK;
				reply.size = request.size;
				reply.handle = request.handle;

				fixup_reply( reply );
				const bool lock = image->uplink != NULL;
				if ( lock ) pthread_mutex_lock( &client->sendMutex );
				// Send reply header
				if ( send( client->sock, &reply, sizeof(dnbd3_reply_t), (request.size == 0 ? 0 : MSG_MORE) ) != sizeof(dnbd3_reply_t) ) {
					if ( lock ) pthread_mutex_unlock( &client->sendMutex );
					logadd( LOG_DEBUG1, "Sending CMD_GET_BLOCK header failed\n" );
					goto exit_client_cleanup;
				}

				if ( request.size != 0 ) {
					// Send payload if request length > 0
					size_t done = 0;
					off_t offset = (off_t)request.offset;
					while ( done < request.size ) {
						const ssize_t ret = sendfile( client->sock, image_file, &offset, request.size - done );
						if ( ret <= 0 ) {
							if ( lock ) pthread_mutex_unlock( &client->sendMutex );
							if ( ret < 0 && errno != 32 && errno != 104 )
								logadd( LOG_DEBUG1, "sendfile failed (image to net. sent %d/%d, errno=%d)\n",
										(int)done, (int)request.size, (int)errno );
							if ( errno == EBADF || errno == EINVAL || errno == EIO ) image->working = false;
							goto exit_client_cleanup;
						}
						done += ret;
					}
					client->bytesSent += request.size; // Increase counter for statistics.
				}
				if ( lock ) pthread_mutex_unlock( &client->sendMutex );
				break;

			case CMD_GET_SERVERS:
				// Build list of known working alt servers
				num = altservers_getMatching( &client->host, server_list, NUMBER_SERVERS );
				reply.cmd = CMD_GET_SERVERS;
				reply.size = num * sizeof(dnbd3_server_entry_t);
				send_reply( client->sock, &reply, server_list );
				client->isServer = false; // Only clients request list of servers
				goto set_name;
				break;

			case CMD_KEEPALIVE:
				reply.cmd = CMD_KEEPALIVE;
				reply.size = 0;
				send_reply( client->sock, &reply, NULL );
set_name: ;
				if ( !hasName && host_to_string( &client->host, buffer, sizeof buffer ) ) {
					hasName = true;
					setThreadName( buffer );
				}
				break;

			case CMD_SET_CLIENT_MODE:
				image->atime = time( NULL );
				client->isServer = false;
				break;

			case CMD_GET_CRC32:
				reply.cmd = CMD_GET_CRC32;
				if ( image->crc32 == NULL ) {
					reply.size = 0;
					send_reply( client->sock, &reply, NULL );
				} else {
					const int size = reply.size = (IMGSIZE_TO_HASHBLOCKS(image->filesize) + 1) * sizeof(uint32_t);
					send_reply( client->sock, &reply, NULL );
					send( client->sock, &image->masterCrc32, sizeof(uint32_t), 0 );
					send( client->sock, image->crc32, size - sizeof(uint32_t), 0 );
				}
				break;

			default:
				logadd( LOG_ERROR, "Unknown command: %d", (int)request.cmd );
				break;

			}
		}
	}
exit_client_cleanup: ;
	dnbd3_removeClient( client );
	spin_lock( &statisticsSentLock );
	totalBytesSent += client->bytesSent;// Add the amount of bytes sent by the client to the statistics of the server.
	spin_unlock( &statisticsSentLock );
	client = dnbd3_freeClient( client );
	return NULL ;
}

