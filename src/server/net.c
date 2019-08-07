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

#include "helper.h"
#include "image.h"
#include "uplink.h"
#include "locks.h"
#include "rpc.h"
#include "altservers.h"

#include "../shared/sockhelper.h"
#include "../shared/timing.h"
#include "../shared/protocol.h"
#include "../serialize.h"

#include <assert.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif
#include <jansson.h>
#include <inttypes.h>
#include <stdatomic.h>

static dnbd3_client_t *_clients[SERVER_MAX_CLIENTS];
static int _num_clients = 0;
static pthread_mutex_t _clients_lock;

static char nullbytes[500];

static atomic_uint_fast64_t totalBytesSent = 0;

// Adding and removing clients -- list management
static bool addToList(dnbd3_client_t *client);
static void removeFromList(dnbd3_client_t *client);
static dnbd3_client_t* freeClientStruct(dnbd3_client_t *client);

static inline bool recv_request_header(int sock, dnbd3_request_t *request)
{
	ssize_t ret, fails = 0;
#ifdef AFL_MODE
	sock = 0;
#endif
	// Read request header from socket
	while ( ( ret = recv( sock, request, sizeof(*request), MSG_WAITALL ) ) != sizeof(*request) ) {
		if ( errno == EINTR && ++fails < 10 ) continue;
		if ( ret >= 0 || ++fails > SOCKET_TIMEOUT_CLIENT_RETRIES ) return false;
		if ( errno == EAGAIN ) continue;
		logadd( LOG_DEBUG2, "Error receiving request: Could not read message header (%d/%d, e=%d)\n", (int)ret, (int)sizeof(*request), errno );
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
#ifdef AFL_MODE
	sock = 0;
#endif
	if ( size == 0 ) {
		logadd( LOG_ERROR, "Called recv_request_payload() to receive 0 bytes" );
		return false;
	}
	if ( size > MAX_PAYLOAD ) {
		logadd( LOG_ERROR, "Called recv_request_payload() for more bytes than the passed buffer could hold!" );
		return false;
	}
	if ( sock_recv( sock, payload->buffer, size ) != (ssize_t)size ) {
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
	const uint32_t size = reply->size;
	fixup_reply( *reply );
	if ( sock_sendAll( sock, reply, sizeof(dnbd3_reply_t), 1 ) != sizeof(dnbd3_reply_t) ) {
		logadd( LOG_DEBUG1, "Sending reply header to client failed" );
		return false;
	}
	if ( size != 0 && payload != NULL ) {
		if ( sock_sendAll( sock, payload, size, 1 ) != (ssize_t)size ) {
			logadd( LOG_DEBUG1, "Sending payload of %"PRIu32" bytes to client failed", size );
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
	return sock_sendAll( fd, nullbytes, bytes, 2 ) == (ssize_t)bytes;
}

void net_init()
{
	mutex_init( &_clients_lock, LOCK_CLIENT_LIST );
}

void* net_handleNewConnection(void *clientPtr)
{
	dnbd3_client_t * const client = (dnbd3_client_t *)clientPtr;
	dnbd3_request_t request;

	// Await data from client. Since this is a fresh connection, we expect data right away
	sock_setTimeout( client->sock, _clientTimeout );
	do {
#ifdef AFL_MODE
		const int ret = (int)recv( 0, &request, sizeof(request), MSG_WAITALL );
#else
		const int ret = (int)recv( client->sock, &request, sizeof(request), MSG_WAITALL );
#endif
		// It's expected to be a real dnbd3 client
		// Check request for validity. This implicitly dictates that all HTTP requests are more than 24 bytes...
		if ( ret != (int)sizeof(request) ) {
			logadd( LOG_DEBUG2, "Error receiving request: Could not read message header (%d/%d, e=%d)", (int)ret, (int)sizeof(request), errno );
			goto fail_preadd;
		}

		if ( request.magic != dnbd3_packet_magic ) {
			// Let's see if this looks like an HTTP request
			if ( ((char*)&request)[0] == 'G' || ((char*)&request)[0] == 'P' ) {
				// Close enough...
				rpc_sendStatsJson( client->sock, &client->host, &request, ret );
			} else {
				logadd( LOG_DEBUG1, "Magic in client handshake incorrect" );
			}
			goto fail_preadd;
		}
		// Magic OK, untangle byte order if required
		fixup_request( request );
		if ( request.cmd != CMD_SELECT_IMAGE ) {
			logadd( LOG_WARNING, "Client sent != CMD_SELECT_IMAGE in handshake (got cmd=%d, size=%d), dropping client.", (int)request.cmd, (int)request.size );
			goto fail_preadd;
		}
	} while (0);
	// Fully init client struct
	mutex_init( &client->lock, LOCK_CLIENT );
	mutex_init( &client->sendMutex, LOCK_CLIENT_SEND );

	mutex_lock( &client->lock );
	host_to_string( &client->host, client->hostName, HOSTNAMELEN );
	client->hostName[HOSTNAMELEN-1] = '\0';
	mutex_unlock( &client->lock );
	client->bytesSent = 0;

	if ( !addToList( client ) ) {
		freeClientStruct( client );
		logadd( LOG_WARNING, "Could not add new client to list when connecting" );
		return NULL;
	}

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

	// Receive first packet's payload
	if ( recv_request_payload( client->sock, request.size, &payload ) ) {
		char *image_name;
		client_version = serializer_get_uint16( &payload );
		image_name = serializer_get_string( &payload );
		rid = serializer_get_uint16( &payload );
		const uint8_t flags = serializer_get_uint8( &payload );
		client->isServer = ( flags & FLAGS8_SERVER );
		if ( request.size < 3 || !image_name || client_version < MIN_SUPPORTED_CLIENT ) {
			if ( client_version < MIN_SUPPORTED_CLIENT ) {
				logadd( LOG_DEBUG1, "Client %s too old", client->hostName );
			} else {
				logadd( LOG_DEBUG1, "Incomplete handshake received from %s", client->hostName );
			}
		} else {
			if ( !client->isServer || !_isProxy ) {
				// Is a normal client, or we're not proxy
				image = image_getOrLoad( image_name, rid );
			} else if ( _backgroundReplication != BGR_FULL && ( flags & FLAGS8_BG_REP ) ) {
				// We're a proxy, client is another proxy, we don't do BGR, but connecting proxy does...
				// Reject, as this would basically force this proxy to do BGR too.
				image = image_get( image_name, rid, true );
				if ( image != NULL && image->cache_map != NULL ) {
					// Only exception is if the image is complete locally
					image = image_release( image );
				}
			} else if ( _lookupMissingForProxy ) {
				// No BGR mismatch and we're told to lookup missing images on a known uplink server
				// if the requesting client is a proxy
				image = image_getOrLoad( image_name, rid );
			} else {
				// No BGR mismatch, but don't lookup if image is unknown locally
				image = image_get( image_name, rid, true );
			}
			client->image = image;
			atomic_thread_fence( memory_order_release );
			if ( image == NULL ) {
				//logadd( LOG_DEBUG1, "Client requested non-existent image '%s' (rid:%d), rejected\n", image_name, (int)rid );
			} else if ( !image->working ) {
				logadd( LOG_DEBUG1, "Client %s requested non-working image '%s' (rid:%d), rejected\n",
						client->hostName, image_name, (int)rid );
			} else {
				bool penalty;
				// Image is fine so far, but occasionally drop a client if the uplink for the image is clogged or unavailable
				bOk = true;
				if ( image->cache_map != NULL ) {
					mutex_lock( &image->lock );
					if ( image->uplink == NULL || image->uplink->cacheFd == -1 || image->uplink->queueLen > SERVER_UPLINK_QUEUELEN_THRES ) {
						bOk = ( rand() % 4 ) == 1;
					}
					penalty = bOk && image->uplink != NULL && image->uplink->cacheFd == -1;
					mutex_unlock( &image->lock );
					if ( penalty ) { // Wait 100ms if local caching is not working so this
						usleep( 100000 ); // server gets a penalty and is less likely to be selected
					}
				}
				if ( bOk ) {
					mutex_lock( &image->lock );
					image_file = image->readFd;
					if ( !client->isServer ) {
						// Only update immediately if this is a client. Servers are handled on disconnect.
						timing_get( &image->atime );
					}
					mutex_unlock( &image->lock );
					serializer_reset_write( &payload );
					serializer_put_uint16( &payload, client_version < 3 ? client_version : PROTOCOL_VERSION ); // XXX: Since messed up fuse client was messed up before :(
					serializer_put_string( &payload, image->name );
					serializer_put_uint16( &payload, (uint16_t)image->rid );
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

			case CMD_GET_BLOCK:;
				const uint64_t offset = request.offset_small; // Copy to full uint64 to prevent repeated masking
				if ( offset >= image->virtualFilesize ) {
					// Sanity check
					logadd( LOG_WARNING, "Client %s requested non-existent block", client->hostName );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}
				if ( offset + request.size > image->virtualFilesize ) {
					// Sanity check
					logadd( LOG_WARNING, "Client %s requested data block that extends beyond image size", client->hostName );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					break;
				}

				if ( request.size != 0 && image->cache_map != NULL ) {
					// This is a proxyed image, check if we need to relay the request...
					start = offset & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					end = (offset + request.size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					bool isCached = true;
					mutex_lock( &image->lock );
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
								const uint8_t bit_mask = (uint8_t)( 1 << map_x );
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
								const uint8_t bit_mask = (uint8_t)( 1 << map_x );
								if ( (image->cache_map[lastByteInMap] & bit_mask) == 0 ) {
									isCached = false;
									break;
								}
								pos += DNBD3_BLOCK_SIZE;
							}
						}
					}
					mutex_unlock( &image->lock );
					if ( !isCached ) {
						if ( !uplink_request( client, request.handle, offset, request.size, request.hops ) ) {
							logadd( LOG_DEBUG1, "Could not relay uncached request from %s to upstream proxy, disabling image %s:%d",
									client->hostName, image->name, image->rid );
							image->working = false;
							goto exit_client_cleanup;
						}
						break; // DONE, exit request.cmd switch
					}
				}

				reply.cmd = CMD_GET_BLOCK;
				reply.size = request.size;
				reply.handle = request.handle;

				fixup_reply( reply );
				const bool lock = image->uplink != NULL;
				if ( lock ) mutex_lock( &client->sendMutex );
				// Send reply header
				if ( send( client->sock, &reply, sizeof(dnbd3_reply_t), (request.size == 0 ? 0 : MSG_MORE) ) != sizeof(dnbd3_reply_t) ) {
					if ( lock ) mutex_unlock( &client->sendMutex );
					logadd( LOG_DEBUG1, "Sending CMD_GET_BLOCK reply header to %s failed", client->hostName );
					goto exit_client_cleanup;
				}

				if ( request.size != 0 ) {
					// Send payload if request length > 0
					size_t done = 0;
					off_t foffset = (off_t)offset;
					size_t realBytes;
					if ( offset + request.size <= image->realFilesize ) {
						realBytes = request.size;
					} else {
						realBytes = (size_t)(image->realFilesize - offset);
					}
					while ( done < realBytes ) {
						// TODO: Should we consider EOPNOTSUPP on BSD for sendfile and fallback to read/write?
						// Linux would set EINVAL or ENOSYS instead, which it unfortunately also does for a couple of other failures :/
						// read/write would kill performance anyways so a fallback would probably be of little use either way.
#ifdef AFL_MODE
						char buf[1000];
						size_t cnt = realBytes - done;
						if ( cnt > 1000 ) {
							cnt = 1000;
						}
						const ssize_t sent = pread( image_file, buf, cnt, foffset );
						if ( sent > 0 ) {
							//write( client->sock, buf, sent ); // This is not verified in any way, so why even do it...
						} else {
							const int err = errno;
#elif defined(__linux__)
						const ssize_t sent = sendfile( client->sock, image_file, &foffset, realBytes - done );
						if ( sent <= 0 ) {
							const int err = errno;
#elif defined(__FreeBSD__)
						off_t sent;
						const int ret = sendfile( image_file, client->sock, foffset, realBytes - done, NULL, &sent, 0 );
						if ( ret == -1 || sent == 0 ) {
							const int err = errno;
							if ( ret == -1 ) {
								if ( err == EAGAIN || err == EINTR ) { // EBUSY? manpage doesn't explicitly mention *sent here.. But then again we dont set the according flag anyways
									done += sent;
									continue;
								}
								sent = -1;
							}
#endif
							if ( lock ) mutex_unlock( &client->sendMutex );
							if ( sent == -1 ) {
								if ( err != EPIPE && err != ECONNRESET && err != ESHUTDOWN
										&& err != EAGAIN && err != EWOULDBLOCK ) {
									logadd( LOG_DEBUG1, "sendfile to %s failed (image to net. sent %d/%d, errno=%d)",
											client->hostName, (int)done, (int)realBytes, err );
								}
								if ( err == EBADF || err == EFAULT || err == EINVAL || err == EIO ) {
									logadd( LOG_INFO, "Disabling %s:%d", image->name, image->rid );
									image->working = false;
								}
							}
							goto exit_client_cleanup;
						}
						done += sent;
					}
					if ( request.size > (uint32_t)realBytes ) {
						if ( !sendPadding( client->sock, request.size - (uint32_t)realBytes ) ) {
							if ( lock ) mutex_unlock( &client->sendMutex );
							goto exit_client_cleanup;
						}
					}
				}
				if ( lock ) mutex_unlock( &client->sendMutex );
				// Global per-client counter
				client->bytesSent += request.size; // Increase counter for statistics.
				break;

			case CMD_GET_SERVERS:
				// Build list of known working alt servers
				num = altservers_getListForClient( &client->host, server_list, NUMBER_SERVERS );
				reply.cmd = CMD_GET_SERVERS;
				reply.size = (uint32_t)( num * sizeof(dnbd3_server_entry_t) );
				mutex_lock( &client->sendMutex );
				send_reply( client->sock, &reply, server_list );
				mutex_unlock( &client->sendMutex );
				goto set_name;
				break;

			case CMD_KEEPALIVE:
				reply.cmd = CMD_KEEPALIVE;
				reply.size = 0;
				mutex_lock( &client->sendMutex );
				send_reply( client->sock, &reply, NULL );
				mutex_unlock( &client->sendMutex );
set_name: ;
				if ( !hasName ) {
					hasName = true;
					setThreadName( client->hostName );
				}
				break;

			case CMD_SET_CLIENT_MODE:
				client->isServer = false;
				break;

			case CMD_GET_CRC32:
				reply.cmd = CMD_GET_CRC32;
				mutex_lock( &client->sendMutex );
				if ( image->crc32 == NULL ) {
					reply.size = 0;
					send_reply( client->sock, &reply, NULL );
				} else {
					const uint32_t size = reply.size = (uint32_t)( (IMGSIZE_TO_HASHBLOCKS(image->realFilesize) + 1) * sizeof(uint32_t) );
					send_reply( client->sock, &reply, NULL );
					send( client->sock, &image->masterCrc32, sizeof(uint32_t), MSG_MORE );
					send( client->sock, image->crc32, size - sizeof(uint32_t), 0 );
				}
				mutex_unlock( &client->sendMutex );
				break;

			default:
				logadd( LOG_ERROR, "Unknown command from client %s: %d", client->hostName, (int)request.cmd );
				break;

			}
		}
	}
exit_client_cleanup: ;
	// First remove from list, then add to counter to prevent race condition
	removeFromList( client );
	totalBytesSent += client->bytesSent;
	// Access time, but only if client didn't just probe
	if ( image != NULL ) {
		mutex_lock( &image->lock );
		if ( client->bytesSent > DNBD3_BLOCK_SIZE * 10 ) {
			timing_get( &image->atime );
		}
		mutex_unlock( &image->lock );
	}
	freeClientStruct( client ); // This will also call image_release on client->image
	return NULL ;
fail_preadd: ;
	close( client->sock );
	free( client );
	return NULL;
}

/**
 * Get list of all clients.
 */
struct json_t* net_getListAsJson()
{
	json_t *jsonClients = json_array();
	json_t *clientStats;
	int imgId, isServer;
	uint64_t bytesSent;
	char host[HOSTNAMELEN];
	host[HOSTNAMELEN-1] = '\0';

	mutex_lock( &_clients_lock );
	for ( int i = 0; i < _num_clients; ++i ) {
		dnbd3_client_t * const client = _clients[i];
		if ( client == NULL || client->image == NULL )
			continue;
		mutex_lock( &client->lock );
		// Unlock so we give other threads a chance to access the client list.
		// We might not get an atomic snapshot of the currently connected clients,
		// but that doesn't really make a difference anyways.
		mutex_unlock( &_clients_lock );
		strncpy( host, client->hostName, HOSTNAMELEN - 1 );
		imgId = client->image->id;
		isServer = (int)client->isServer;
		bytesSent = client->bytesSent;
		mutex_unlock( &client->lock );
		clientStats = json_pack( "{sssisisI}",
				"address", host,
				"imageId", imgId,
				"isServer", isServer,
				"bytesSent", (json_int_t)bytesSent );
		json_array_append_new( jsonClients, clientStats );
		mutex_lock( &_clients_lock );
	}
	mutex_unlock( &_clients_lock );
	return jsonClients;
}

/**
 * Get number of clients connected, total bytes sent, or both.
 * we don't unlock the list while iterating or we might get an
 * incorrect result if a client is disconnecting while iterating.
 */
void net_getStats(int *clientCount, int *serverCount, uint64_t *bytesSent)
{
	int cc = 0, sc = 0;
	uint64_t bs = 0;

	mutex_lock( &_clients_lock );
	for ( int i = 0; i < _num_clients; ++i ) {
		const dnbd3_client_t * const client = _clients[i];
		if ( client == NULL || client->image == NULL )
			continue;
		if ( client->isServer ) {
			sc += 1;
		} else {
			cc += 1;
		}
		bs += client->bytesSent;
	}
	// Do this before unlocking the list, otherwise we might
	// account for a client twice if it would disconnect after
	// unlocking but before we add the count here.
	if ( bytesSent != NULL ) {
		*bytesSent = totalBytesSent + bs;
	}
	mutex_unlock( &_clients_lock );
	if ( clientCount != NULL ) {
		*clientCount = cc;
	}
	if ( serverCount != NULL ) {
		*serverCount = sc;
	}
}

void net_disconnectAll()
{
	int i;
	mutex_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] == NULL ) continue;
		dnbd3_client_t * const client = _clients[i];
		mutex_lock( &client->lock );
		if ( client->sock >= 0 ) shutdown( client->sock, SHUT_RDWR );
		mutex_unlock( &client->lock );
	}
	mutex_unlock( &_clients_lock );
}

void net_waitForAllDisconnected()
{
	int retries = 10, count, i;
	do {
		count = 0;
		mutex_lock( &_clients_lock );
		for (i = 0; i < _num_clients; ++i) {
			if ( _clients[i] == NULL ) continue;
			count++;
		}
		mutex_unlock( &_clients_lock );
		if ( count != 0 ) {
			logadd( LOG_INFO, "%d clients still active...\n", count );
			sleep( 1 );
		}
	} while ( count != 0 && --retries > 0 );
	_num_clients = 0;
}

/* +++
 * Client list.
 *
 * Adding and removing clients.
 */

/**
 * Remove a client from the clients array
 * Locks on: _clients_lock
 */
static void removeFromList(dnbd3_client_t *client)
{
	int i;
	mutex_lock( &_clients_lock );
	for ( i = _num_clients - 1; i >= 0; --i ) {
		if ( _clients[i] == client ) {
			_clients[i] = NULL;
		}
		if ( _clients[i] == NULL && i + 1 == _num_clients ) --_num_clients;
	}
	mutex_unlock( &_clients_lock );
}

/**
 * Free the client struct recursively.
 * !! Make sure to call this function after removing the client from _dnbd3_clients !!
 * Locks on: _clients[].lock, _images[].lock
 * might call functions that lock on _images, _image[], uplink.queueLock, client.sendMutex
 */
static dnbd3_client_t* freeClientStruct(dnbd3_client_t *client)
{
	mutex_lock( &client->lock );
	mutex_lock( &client->sendMutex );
	if ( client->sock != -1 ) close( client->sock );
	client->sock = -1;
	mutex_unlock( &client->sendMutex );
	if ( client->image != NULL ) {
		mutex_lock( &client->image->lock );
		if ( client->image->uplink != NULL ) uplink_removeClient( client->image->uplink, client );
		mutex_unlock( &client->image->lock );
	}
	mutex_unlock( &client->lock );
	client->image = image_release( client->image );
	mutex_destroy( &client->lock );
	mutex_destroy( &client->sendMutex );
	free( client );
	return NULL ;
}

//###//

/**
 * Add client to the clients array.
 * Locks on: _clients_lock
 */
static bool addToList(dnbd3_client_t *client)
{
	int i;
	mutex_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] != NULL ) continue;
		_clients[i] = client;
		mutex_unlock( &_clients_lock );
		return true;
	}
	if ( _num_clients >= _maxClients ) {
		mutex_unlock( &_clients_lock );
		logadd( LOG_ERROR, "Maximum number of clients reached!" );
		return false;
	}
	_clients[_num_clients++] = client;
	mutex_unlock( &_clients_lock );
	return true;
}

