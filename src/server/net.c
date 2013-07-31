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
#include <pthread.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <assert.h>

#include "sockhelper.h"
#include "helper.h"
#include "server.h"
#include "image.h"
#include "uplink.h"
#include "altservers.h"
#include "memlog.h"
#include "../serialize.h"
#include "../config.h"
#include "../types.h"
#include "locks.h"

static inline char recv_request_header(int sock, dnbd3_request_t *request)
{
	int ret;
	// Read request header from socket
	if ( (ret = recv( sock, request, sizeof(*request), MSG_WAITALL )) != sizeof(*request) ) {
		if ( ret == 0 ) return 0;
		printf( "[DEBUG] Error receiving request: Could not read message header (%d/%d)\n", ret, (int)sizeof(*request) );
		return FALSE;
	}
	// Make sure all bytes are in the right order (endianness)
	fixup_request( *request );
	if ( request->magic != dnbd3_packet_magic ) {
		printf( "[DEBUG] Magic in client request incorrect (cmd: %d, len: %d)\n", (int)request->cmd, (int)request->size );
		return FALSE;
	}
	// Payload sanity check
	if ( request->cmd != CMD_GET_BLOCK && request->size > MAX_PAYLOAD ) {
		memlogf( "[WARNING] Client tries to send a packet of type %d with %d bytes payload. Dropping client.", (int)request->cmd,
		        (int)request->size );
		return FALSE;
	}
#ifdef _DEBUG
	if ( _fake_delay ) usleep( _fake_delay );
#endif
	return TRUE;
}

static inline char recv_request_payload(int sock, uint32_t size, serialized_buffer_t *payload)
{
	if ( size == 0 ) {
		memlogf( "[BUG] Called recv_request_payload() to receive 0 bytes" );
		return FALSE;
	}
	if ( size > MAX_PAYLOAD ) {
		memlogf( "[BUG] Called recv_request_payload() for more bytes than the passed buffer could hold!" );
		return FALSE;
	}
	if ( recv( sock, payload->buffer, size, MSG_WAITALL ) != size ) {
		printf( "[ERROR] Could not receive request payload of length %d\n", (int)size );
		return FALSE;
	}
	// Prepare payload buffer for reading
	serializer_reset_read( payload, size );
	return TRUE;
}

static inline char send_reply(int sock, dnbd3_reply_t *reply, void *payload)
{
	const unsigned int size = reply->size;
	fixup_reply( *reply );
	if ( !payload || size == 0 ) {
		if ( send( sock, reply, sizeof(dnbd3_reply_t), MSG_WAITALL ) != sizeof(dnbd3_reply_t) ) {
			printf( "[DEBUG] Send failed (header-only)\n" );
			return FALSE;
		}
	} else {
		struct iovec iov[2];
		iov[0].iov_base = reply;
		iov[0].iov_len = sizeof(dnbd3_reply_t);
		iov[1].iov_base = payload;
		iov[1].iov_len = size;
		if ( writev( sock, iov, 2 ) != sizeof(dnbd3_reply_t) + size ) {
			printf( "[DEBUG] Send failed (reply with payload of %u bytes)\n", size );
			return FALSE;
		}
	}
	return TRUE;
}

void *net_client_handler(void *dnbd3_client)
{
	dnbd3_client_t *client = (dnbd3_client_t *)(uintptr_t)dnbd3_client;
	dnbd3_request_t request;
	dnbd3_reply_t reply;

	dnbd3_image_t *image = NULL;
	int image_file = -1;

	int num;
	int bOk = FALSE;

	serialized_buffer_t payload;
	char *image_name;
	uint16_t rid, client_version;
	uint64_t start, end;

	dnbd3_server_entry_t server_list[NUMBER_SERVERS];

	// Set to zero to make valgrind happy
	memset( &reply, 0, sizeof(reply) );
	memset( &payload, 0, sizeof(payload) );
	reply.magic = dnbd3_packet_magic;

	// Receive first packet. This must be CMD_SELECT_IMAGE by protocol specification
	if ( recv_request_header( client->sock, &request ) ) {
		if ( request.cmd != CMD_SELECT_IMAGE ) {
			printf( "[DEBUG] Client sent invalid handshake (%d). Dropping Client\n", (int)request.cmd );
		} else {
			if ( recv_request_payload( client->sock, request.size, &payload ) ) {
				client_version = serializer_get_uint16( &payload );
				image_name = serializer_get_string( &payload );
				rid = serializer_get_uint16( &payload );
				client->is_server = serializer_get_uint8( &payload );
				if ( request.size < 3 || !image_name || client_version < MIN_SUPPORTED_CLIENT ) {
					if ( client_version < MIN_SUPPORTED_CLIENT ) {
						printf( "[DEBUG] Client too old\n" );
					} else {
						printf( "[DEBUG] Incomplete handshake received\n" );
					}
				} else {
					image = image_get( image_name, rid );
					if ( image == NULL ) {
						printf( "[DEBUG] Client requested non-existent image '%s' (rid:%d), rejected\n", image_name, (int)rid );
					} else if ( !image->working ) {
						printf( "[DEBUG] Client requested non-working image '%s' (rid:%d), rejected\n", image_name, (int)rid );
					} else {
						image_file = open( image->path, O_RDONLY );
						if ( image_file >= 0 ) {
							serializer_reset_write( &payload );
							serializer_put_uint16( &payload, PROTOCOL_VERSION );
							serializer_put_string( &payload, image->lower_name );
							serializer_put_uint16( &payload, image->rid );
							serializer_put_uint64( &payload, image->filesize );
							reply.cmd = CMD_SELECT_IMAGE;
							reply.size = serializer_get_written_length( &payload );
							if ( send_reply( client->sock, &reply, &payload ) ) {
								client->image = image;
								if ( !client->is_server ) image->atime = time( NULL );
								bOk = TRUE;
							}
						}
					}
				}
			}
		}
	}

	// client handling mainloop
	if ( bOk ) {
		while ( recv_request_header( client->sock, &request ) ) {
			switch ( request.cmd ) {

			case CMD_GET_BLOCK:
				if ( request.offset >= image->filesize ) {
					// Sanity check
					memlogf( "[WARNING] Client requested non-existent block" );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}
				if ( request.offset + request.size > image->filesize ) {
					// Sanity check
					memlogf( "[WARNING] Client requested data block that extends beyond image size" );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}
				if ( request.size > image->filesize ) {
					// Sanity check
					memlogf( "[WARNING] Client requested data block that is bigger than the image size" );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}

				if ( request.size != 0 && image->cache_map != NULL ) {
					// This is a proxyed image, check if we need to relay the request...
					start = request.offset & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					end = (request.offset + request.size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					int isCached = TRUE;
					spin_lock( &image->lock );
					// Check again as we only aquired the lock just now
					if ( image->cache_map != NULL ) {
						// First byte
						uint64_t pos = start;
						const uint64_t firstByte = start >> 15;
						const uint64_t lastByte = (end - 1) >> 15;
						do {
							const int map_x = (pos >> 12) & 7; // mod 8
							const uint8_t bit_mask = 0b00000001 << map_x;
							if ( (image->cache_map[firstByte] & bit_mask) == 0 ) {
								isCached = FALSE;
								break;
							}
							pos += DNBD3_BLOCK_SIZE;
						} while ( firstByte == (pos >> 15) );
						// Middle - quick checking
						if ( isCached ) {
							pos = firstByte + 1;
							while ( pos < lastByte ) {
								if ( image->cache_map[pos] != 0xff ) {
									isCached = FALSE;
									break;
								}
							}
						}
						// Last byte
						if ( isCached ) {
							pos = lastByte << 15;
							while ( pos < end ) {
								assert( lastByte == (pos >> 15) );
								const int map_x = (pos >> 12) & 7; // mod 8
								const uint8_t bit_mask = 0b00000001 << map_x;
								if ( (image->cache_map[lastByte] & bit_mask) == 0 ) {
									isCached = FALSE;
									break;
								}
								pos += DNBD3_BLOCK_SIZE;
							}
						}
					}
					spin_unlock( &image->lock );
					if ( !isCached ) {
						if ( !uplink_request( client, request.handle, request.offset, request.size ) ) {
							printf( "[DEBUG] Could not relay uncached request to upstream proxy\n" );
							goto exit_client_cleanup;
						}
						break; // DONE
					}
				}

				reply.cmd = CMD_GET_BLOCK;
				reply.size = request.size;
				reply.handle = request.handle;

				fixup_reply( reply );
				pthread_mutex_lock( &client->sendMutex );
				// Send reply header
				if ( send( client->sock, &reply, sizeof(dnbd3_reply_t), (request.size == 0 ? 0 : MSG_MORE) ) != sizeof(dnbd3_reply_t) ) {
					pthread_mutex_unlock( &client->sendMutex );
					printf( "[DEBUG] Sending CMD_GET_BLOCK header failed\n" );
					goto exit_client_cleanup;
				}

				if ( request.size != 0 ) {
					// Send payload if request length > 0
					const ssize_t ret = sendfile( client->sock, image_file, (off_t *)&request.offset, request.size );
					if ( ret != request.size ) {
						pthread_mutex_unlock( &client->sendMutex );
						printf( "[ERROR] sendfile failed (image to net %d/%d)\n", (int)ret, (int)request.size );
						goto exit_client_cleanup;
					}
				}
				pthread_mutex_unlock( &client->sendMutex );
				break;

			case CMD_GET_SERVERS:
				client->is_server = FALSE; // Only clients request list of servers
				// Build list of known working alt servers
				num = altservers_get_matching( &client->host, server_list, NUMBER_SERVERS );
				reply.cmd = CMD_GET_SERVERS;
				reply.size = num * sizeof(dnbd3_server_entry_t);
				send_reply( client->sock, &reply, server_list );
				break;

			case CMD_KEEPALIVE:
				reply.cmd = CMD_KEEPALIVE;
				reply.size = 0;
				send_reply( client->sock, &reply, NULL );
				break;

			case CMD_SET_CLIENT_MODE:
				image->atime = time( NULL );
				break;

			case CMD_GET_CRC32:
				reply.cmd = CMD_GET_CRC32;
				if ( image->crc32 == NULL ) {
					reply.size = 0;
				} else {
					reply.size = IMGSIZE_TO_HASHBLOCKS(image->filesize) * 4;
				}
				send_reply( client->sock, &reply, image->crc32 );
				break;

			default:
				memlogf( "[ERROR] Unknown command: %d", (int)request.cmd );
				break;

			}

			/*
			 // Check for messages that have been queued from another thread
			 while ( client->sendqueue != NULL ) {
			 dnbd3_binstring_t *message = NULL;
			 spin_lock( &client->lock );
			 if ( client->sendqueue != NULL ) {
			 message = client->sendqueue->data;
			 client->sendqueue = g_slist_remove( client->sendqueue, message );
			 }
			 spin_unlock( &client->lock );
			 send_data( client->sock, message->data, message->len );
			 free( message );
			 }
			 */

		}
	}
	exit_client_cleanup: ;
	if ( image_file != -1 ) close( image_file );
	dnbd3_remove_client( client );
	client = dnbd3_free_client( client );
	return NULL ;
}
