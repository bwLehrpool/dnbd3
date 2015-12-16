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

#include "../shared/sockhelper.h"
#include "helper.h"
#include "server.h"
#include "image.h"
#include "uplink.h"
#include "altservers.h"
#include "../shared/log.h"
#include "helper.h"
#include "../serialize.h"
#include "../config.h"
#include "../types.h"
#include "locks.h"
#include "rpc.h"

static char nullbytes[500];

static uint64_t totalBytesSent = 0;
static pthread_spinlock_t statisticsSentLock;

/**
 * Update global sent stats. Hold client's statsLock when calling.
 */
void net_updateGlobalSentStatsFromClient(dnbd3_client_t * const client)
{
	spin_lock( &statisticsSentLock );
	totalBytesSent += client->tmpBytesSent;
	spin_unlock( &statisticsSentLock );
	client->tmpBytesSent = 0;
}

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
	if ( sock_recv( sock, payload->buffer, size ) != size ) {
		logadd( LOG_DEBUG1, "Could not receive request payload of length %d\n", (int)size );
		return false;
	}
	// Prepare payload buffer for reading
	serializer_reset_read( payload, size );
	return true;
}

/**
 * Send reply with optional payload. payload can be null. The caller has to
 * acquire the sendMutex first.
 */
static inline bool send_reply(int sock, dnbd3_reply_t *reply, void *payload)
{
	const size_t size = reply->size;
	fixup_reply( *reply );
	if ( sock_sendAll( sock, reply, sizeof(dnbd3_reply_t), 1 ) != sizeof(dnbd3_reply_t) ) {
		logadd( LOG_DEBUG1, "Sending reply header to client failed" );
		return false;
	}
	if ( size != 0 && payload != NULL ) {
		if ( sock_sendAll( sock, payload, size, 1 ) != (ssize_t)size ) {
			logadd( LOG_DEBUG1, "Sending payload of %u bytes to client failed", size );
			return false;
		}
	}
	return true;
}

/**
 * Send given amount of null bytes. The caller has to acquire the sendMutex first.
 */
static inline bool sendPadding( const int fd, uint32_t bytes )
{
	ssize_t ret;
	while ( bytes >= sizeof(nullbytes) ) {
		ret = sock_sendAll( fd, nullbytes, sizeof(nullbytes), 2 );
		if ( ret <= 0 )
			return false;
		bytes -= (uint32_t)ret;
	}
	return sock_sendAll( fd, nullbytes, bytes, 2 ) == bytes;
}

uint64_t net_getTotalBytesSent()
{
	// reads and writes to 64bit ints are not atomic on x86, so let's be safe and use locking
	spin_lock( &statisticsSentLock );
	const uint64_t tmp = totalBytesSent;
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
	uint16_t rid, client_version;
	uint64_t start, end;

	dnbd3_server_entry_t server_list[NUMBER_SERVERS];

	// Set to zero to make valgrind happy
	memset( &reply, 0, sizeof(reply) );
	memset( &payload, 0, sizeof(payload) );
	reply.magic = dnbd3_packet_magic;

	sock_setTimeout( client->sock, _clientTimeout );
	if ( !host_to_string( &client->host, client->hostName, HOSTNAMELEN ) ) {
		client->hostName[HOSTNAMELEN-1] = '\0';
	}

	// Receive first packet. This must be CMD_SELECT_IMAGE by protocol specification
	if ( recv_request_header( client->sock, &request ) ) {
		if ( request.cmd != CMD_SELECT_IMAGE ) {
			logadd( LOG_DEBUG1, "Client %s sent invalid handshake (%d). Dropping Client\n", client->hostName, (int)request.cmd );
		} else if ( recv_request_payload( client->sock, request.size, &payload ) ) {
			char *image_name;
			client_version = serializer_get_uint16( &payload );
			image_name = serializer_get_string( &payload );
			rid = serializer_get_uint16( &payload );
			client->isServer = serializer_get_uint8( &payload );
			if ( request.size < 3 || !image_name || client_version < MIN_SUPPORTED_CLIENT ) {
				if ( client_version < MIN_SUPPORTED_CLIENT ) {
					logadd( LOG_DEBUG1, "Client %s too old", client->hostName );
				} else {
					logadd( LOG_DEBUG1, "Incomplete handshake received from %s", client->hostName );
				}
			} else {
				client->image = image = image_getOrLoad( image_name, rid );
				if ( image == NULL ) {
					//logadd( LOG_DEBUG1, "Client requested non-existent image '%s' (rid:%d), rejected\n", image_name, (int)rid );
				} else if ( !image->working ) {
					logadd( LOG_DEBUG1, "Client %s requested non-working image '%s' (rid:%d), rejected\n",
							client->hostName, image_name, (int)rid );
				} else {
					// Image is fine so far, but occasionally drop a client if the uplink for the image is clogged or unavailable
					bOk = true;
					if ( image->cache_map != NULL ) {
						spin_lock( &image->lock );
						if ( image->uplink == NULL || image->uplink->queueLen > SERVER_UPLINK_QUEUELEN_THRES ) {
							bOk = ( rand() % 4 ) == 1;
						}
						spin_unlock( &image->lock );
						if ( image->cacheFd == -1 ) { // Wait 100ms if local caching is not working so this
							usleep( 100000 ); // server gets a penalty and is less likely to be selected
						}
					}
					if ( bOk ) {
						image_file = image->readFd;
						serializer_reset_write( &payload );
						serializer_put_uint16( &payload, PROTOCOL_VERSION );
						serializer_put_string( &payload, image->lower_name );
						serializer_put_uint16( &payload, image->rid );
						serializer_put_uint64( &payload, image->virtualFilesize );
						reply.cmd = CMD_SELECT_IMAGE;
						reply.size = serializer_get_written_length( &payload );
						if ( !send_reply( client->sock, &reply, &payload ) ) {
							bOk = false;
						}
					}
				}
			}
		}
	} else if ( strncmp( (char*)&request, "GET ", 4 ) == 0 || strncmp( (char*)&request, "POST ", 5 ) == 0 ) {
		rpc_sendStatsJson( client->sock );
	} else {
		// Unknown request
		logadd( LOG_DEBUG1, "Client %s sent invalid handshake", client->hostName );
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
				if ( request.offset >= image->virtualFilesize ) {
					// Sanity check
					logadd( LOG_WARNING, "Client %s requested non-existent block", client->hostName );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}
				if ( request.offset + request.size > image->virtualFilesize ) {
					// Sanity check
					logadd( LOG_WARNING, "Client %s requested data block that extends beyond image size", client->hostName );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}

				if ( request.size != 0 && image->cache_map != NULL ) {
					// This is a proxyed image, check if we need to relay the request...
					start = request.offset & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					end = (request.offset + request.size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					bool isCached = true;
					spin_lock( &image->lock );
					// Check again as we only aquired the lock just now
					if ( image->cache_map != NULL ) {
						const uint64_t firstByteInMap = start >> 15;
						const uint64_t lastByteInMap = (end - 1) >> 15;
						uint64_t pos;
						// Middle - quick checking
						if ( isCached ) {
							pos = firstByteInMap + 1;
							while ( pos < lastByteInMap ) {
								if ( image->cache_map[pos] != 0xff ) {
									isCached = false;
									break;
								}
								++pos;
							}
						}
						// First byte
						if ( isCached ) {
							pos = start;
							do {
								const int map_x = (pos >> 12) & 7; // mod 8
								const uint8_t bit_mask = 1 << map_x;
								if ( (image->cache_map[firstByteInMap] & bit_mask) == 0 ) {
									isCached = false;
									break;
								}
								pos += DNBD3_BLOCK_SIZE;
							} while ( firstByteInMap == (pos >> 15) && pos < end );
						}
						// Last byte - only check if request spans multiple bytes in cache map
						if ( isCached && firstByteInMap != lastByteInMap ) {
							pos = lastByteInMap << 15;
							while ( pos < end ) {
								assert( lastByteInMap == (pos >> 15) );
								const int map_x = (pos >> 12) & 7; // mod 8
								const uint8_t bit_mask = 1 << map_x;
								if ( (image->cache_map[lastByteInMap] & bit_mask) == 0 ) {
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
							logadd( LOG_DEBUG1, "Could not relay un-cached request from %s to upstream proxy, disabling image %s:%d",
									client->hostName, image->lower_name, (int)image->rid );
							image->working = false;
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
					logadd( LOG_DEBUG1, "Sending CMD_GET_BLOCK reply header to %s failed", client->hostName );
					goto exit_client_cleanup;
				}

				if ( request.size != 0 ) {
					// Send payload if request length > 0
					size_t done = 0;
					off_t offset = (off_t)request.offset;
					size_t realBytes;
					if ( request.offset + request.size <= image->realFilesize ) {
						realBytes = request.size;
					} else {
						realBytes = image->realFilesize - request.offset;
					}
					while ( done < realBytes ) {
						const ssize_t ret = sendfile( client->sock, image_file, &offset, realBytes - done );
						if ( ret <= 0 ) {
							const int err = errno;
							if ( lock ) pthread_mutex_unlock( &client->sendMutex );
							if ( ret == -1 ) {
								if ( err != EPIPE && err != ECONNRESET && err != ESHUTDOWN ) {
									logadd( LOG_DEBUG1, "sendfile to %s failed (image to net. sent %d/%d, errno=%d)",
											client->hostName, (int)done, (int)realBytes, err );
								}
								if ( err != EAGAIN && err != EWOULDBLOCK ) image->working = false;
							}
							goto exit_client_cleanup;
						}
						done += ret;
					}
					if ( request.size > (uint32_t)realBytes ) {
						if ( !sendPadding( client->sock, request.size - (uint32_t)realBytes ) ) {
							if ( lock ) pthread_mutex_unlock( &client->sendMutex );
							goto exit_client_cleanup;
						}
					}
				}
				if ( lock ) pthread_mutex_unlock( &client->sendMutex );
				spin_lock( &client->statsLock );
				// Global per-client counter
				client->bytesSent += request.size; // Increase counter for statistics.
				// Local counter that gets added to the global total bytes sent counter periodically
				client->tmpBytesSent += request.size;
				if ( client->tmpBytesSent > 100000000 ) {
					net_updateGlobalSentStatsFromClient( client );
				}
				spin_unlock( &client->statsLock );
				break;

			case CMD_GET_SERVERS:
				// Build list of known working alt servers
				num = altservers_getMatching( &client->host, server_list, NUMBER_SERVERS );
				reply.cmd = CMD_GET_SERVERS;
				reply.size = num * sizeof(dnbd3_server_entry_t);
				pthread_mutex_lock( &client->sendMutex );
				send_reply( client->sock, &reply, server_list );
				pthread_mutex_unlock( &client->sendMutex );
				goto set_name;
				break;

			case CMD_KEEPALIVE:
				reply.cmd = CMD_KEEPALIVE;
				reply.size = 0;
				pthread_mutex_lock( &client->sendMutex );
				send_reply( client->sock, &reply, NULL );
				pthread_mutex_unlock( &client->sendMutex );
				image->atime = time( NULL );
set_name: ;
				if ( !hasName ) {
					hasName = true;
					setThreadName( client->hostName );
				}
				break;

			case CMD_SET_CLIENT_MODE:
				image->atime = time( NULL );
				client->isServer = false;
				break;

			case CMD_GET_CRC32:
				reply.cmd = CMD_GET_CRC32;
				pthread_mutex_lock( &client->sendMutex );
				if ( image->crc32 == NULL ) {
					reply.size = 0;
					send_reply( client->sock, &reply, NULL );
				} else {
					const int size = reply.size = (IMGSIZE_TO_HASHBLOCKS(image->realFilesize) + 1) * sizeof(uint32_t);
					send_reply( client->sock, &reply, NULL );
					send( client->sock, &image->masterCrc32, sizeof(uint32_t), MSG_MORE );
					send( client->sock, image->crc32, size - sizeof(uint32_t), 0 );
				}
				pthread_mutex_unlock( &client->sendMutex );
				break;

			default:
				logadd( LOG_ERROR, "Unknown command from client %s: %d", client->hostName, (int)request.cmd );
				break;

			}
		}
	}
exit_client_cleanup: ;
	dnbd3_removeClient( client );
	net_updateGlobalSentStatsFromClient( client ); // Don't need client's lock here as it's not active anymore
	client = dnbd3_freeClient( client ); // This will also call image_release on client->image
	return NULL ;
}

