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

#include "helper.h"
#include "image.h"
#include "iscsi.h"
#include "uplink.h"
#include "locks.h"
#include "rpc.h"
#include "altservers.h"
#include "reference.h"

#include <dnbd3/shared/sockhelper.h>
#include <dnbd3/shared/timing.h>
#include <dnbd3/shared/protocol.h>
#include <dnbd3/shared/serialize.h>

#include <assert.h>
#include <netinet/tcp.h>

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
#include <signal.h>

static dnbd3_client_t *_clients[SERVER_MAX_CLIENTS];
static int _num_clients = 0;
static pthread_mutex_t _clients_lock;

static char nullbytes[500];

static atomic_uint_fast64_t totalBytesSent = 0;

// Adding and removing clients -- list management
static bool addToList(dnbd3_client_t *client);
static void removeFromList(dnbd3_client_t *client);
static dnbd3_client_t* freeClientStruct(dnbd3_client_t *client);
static void uplinkCallback(void *data, uint64_t handle, uint64_t start, uint32_t length, const char *buffer);

static inline bool recv_request_header(int sock, dnbd3_request_t *request)
{
	ssize_t ret, fails = 0;
#ifdef DNBD3_SERVER_AFL
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
#ifdef DNBD3_SERVER_AFL
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
static inline bool send_reply(int sock, dnbd3_reply_t *reply, const void *payload)
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

void initClientStruct(dnbd3_client_t *client)
{
	mutex_init( &client->lock, LOCK_CLIENT );
	mutex_init( &client->sendMutex, LOCK_CLIENT_SEND );

	mutex_lock( &client->lock );
	host_to_string( &client->host, client->hostName, HOSTNAMELEN );
	client->hostName[HOSTNAMELEN-1] = '\0';
	mutex_unlock( &client->lock );
	client->bytesSent = 0;
	client->relayedCount = 0;
}

void* net_handleNewConnection(void *clientPtr)
{
	dnbd3_client_t * const client = (dnbd3_client_t *)clientPtr;
	dnbd3_request_t request;
	dnbd3_cache_map_t *cache = NULL;
	client->thread = pthread_self();

	// Await data from client. Since this is a fresh connection, we expect data right away
	sock_setTimeout( client->sock, _clientTimeout );
	// NODELAY makes sense since we're sending a lot of data
	int e2 = 1;
	socklen_t optlen = sizeof(e2);
	setsockopt( client->sock, IPPROTO_TCP, TCP_NODELAY, (void *)&e2, optlen );
	// Also increase send buffer
	if ( getsockopt( client->sock, SOL_SOCKET, SO_SNDBUF, (void *)&e2, &optlen ) == 0 ) {
#ifdef __linux__
		// Linux doubles the value to account for overhead, get "real" value
		e2 /= 2;
#endif
		if ( e2 < SERVER_TCP_BUFFER_MIN_SIZE_PAYLOAD ) {
			e2 = SERVER_TCP_BUFFER_MIN_SIZE_PAYLOAD;
			setsockopt( client->sock, SOL_SOCKET, SO_SNDBUF, &e2, sizeof(e2) );
		}
	}
	do {
#ifdef DNBD3_SERVER_AFL
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
			} else if ( true /* check opcode ... */ ) {
				initClientStruct( client );
				if ( !addToList( client ) ) {
					freeClientStruct( client );
					logadd( LOG_WARNING, "Could not add new iSCSI client to list when connecting" );
				} else {
					iscsi_connection_handle( client, &request, ret );
					goto exit_client_cleanup;
				}
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
	initClientStruct( client );

	if ( !addToList( client ) ) {
		freeClientStruct( client );
		logadd( LOG_WARNING, "Could not add new DNBD3 client to list when connecting" );
		goto fail_preadd;
	}

	dnbd3_reply_t reply;

	dnbd3_image_t *image = NULL;
	int image_file = -1;

	int num;
	bool bOk = false;
	bool hasName = false;

	serialized_buffer_t payload;
	uint16_t rid, client_version;

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
		if ( unlikely( request.size < 3 || !image_name || client_version < MIN_SUPPORTED_CLIENT ) ) {
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
				if ( image != NULL && image->ref_cacheMap != NULL ) {
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
			if ( unlikely( image == NULL ) ) {
				//logadd( LOG_DEBUG1, "Client requested non-existent image '%s' (rid:%d), rejected\n", image_name, (int)rid );
			} else if ( unlikely( image->problem.read || image->problem.changed ) ) {
				logadd( LOG_DEBUG1, "Client %s requested non-working image '%s' (rid:%d), rejected\n",
						client->hostName, image_name, (int)rid );
			} else {
				// Image is fine so far, but occasionally drop a client if the uplink for the image is clogged or unavailable
				bOk = true;
				if ( image->ref_cacheMap != NULL ) {
					if ( image->problem.queue || image->problem.write ) {
						bOk = ( rand() % 4 ) == 1;
					}
					if ( bOk ) {
						if ( image->problem.write ) { // Wait 100ms if local caching is not working so this
							usleep( 100000 ); // server gets a penalty and is less likely to be selected
						}
						if ( image->problem.uplink ) {
							// Penaltize depending on completeness, if no uplink is available
							usleep( ( 100 - image->completenessEstimate ) * 100 );
						}
					}
				}
				if ( bOk ) {
					mutex_lock( &image->lock );
					image_file = image->readFd;
					if ( !client->isServer ) {
						// Only update immediately if this is a client. Servers are handled on disconnect.
						timing_get( &image->atime );
						image->accessed = true;
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

	if ( likely( bOk ) ) {
		// add artificial delay if applicable
		if ( client->isServer && _serverPenalty != 0 ) {
			usleep( _serverPenalty );
		} else if ( !client->isServer && _clientPenalty != 0 ) {
			usleep( _clientPenalty );
		}
		// client handling mainloop
		while ( recv_request_header( client->sock, &request ) ) {
			if ( _shutdown ) break;
			if ( likely ( request.cmd == CMD_GET_BLOCK ) ) {

				const uint64_t offset = request.offset_small; // Copy to full uint64 to prevent repeated masking
				reply.handle = request.handle;
				if ( unlikely( offset >= image->virtualFilesize ) ) {
					// Sanity check
					logadd( LOG_WARNING, "Client %s requested non-existent block", client->hostName );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					continue;
				}
				if ( unlikely( offset + request.size > image->virtualFilesize ) ) {
					// Sanity check
					logadd( LOG_WARNING, "Client %s requested data block that extends beyond image size", client->hostName );
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply( client->sock, &reply, NULL );
					continue;
				}

				if ( cache == NULL ) {
					cache = ref_get_cachemap( image );
				}

				if ( request.size != 0 && cache != NULL ) {
					// This is a proxyed image, check if we need to relay the request...
					const uint64_t start = offset & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					const uint64_t end = (offset + request.size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
					if ( !image_isRangeCachedUnsafe( cache, start, end ) ) {
						if ( unlikely( client->relayedCount > 250 ) ) {
							logadd( LOG_DEBUG1, "Client is overloading uplink; throttling" );
							for ( int i = 0; i < 100 && client->relayedCount > 200; ++i ) {
								usleep( 10000 );
							}
							if ( client->relayedCount > 250 ) {
								logadd( LOG_WARNING, "Could not lower client's uplink backlog; dropping client" );
								goto exit_client_cleanup;
							}
						}
						client->relayedCount++;
						if ( !uplink_requestClient( client, &uplinkCallback, request.handle, offset, request.size, request.hops ) ) {
							client->relayedCount--;
							logadd( LOG_DEBUG1, "Could not relay uncached request from %s to upstream proxy for image %s:%d",
									client->hostName, image->name, image->rid );
							goto exit_client_cleanup;
						}
						continue; // Reply arrives on uplink some time later, handle next request now
					}
				}

				reply.cmd = CMD_GET_BLOCK;
				reply.size = request.size;

				fixup_reply( reply );
				const bool lock = image->uplinkref != NULL;
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
#ifdef DNBD3_SERVER_AFL
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
									image->problem.read = true;
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
				continue;
			}
			// Any other command
			// Release cache map every now and then, in case the image was replicated
			// entirely. Will be re-grabbed on next CMD_GET_BLOCK otherwise.
			if ( cache != NULL ) {
				ref_put( &cache->reference );
				cache = NULL;
			}
			switch ( request.cmd ) {

			case CMD_GET_SERVERS:
				// Build list of known working alt servers
				num = altservers_getListForClient( client, server_list, NUMBER_SERVERS );
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

			} // end switch
		} // end loop
	} // end bOk
exit_client_cleanup: ;
	// First remove from list, then add to counter to prevent race condition
	removeFromList( client );
	totalBytesSent += client->bytesSent;
	// Access time, but only if client didn't just probe
	if ( client->image != NULL && client->bytesSent > DNBD3_BLOCK_SIZE * 10 ) {
		mutex_lock( &client->image->lock );
		timing_get( &client->image->atime );
		client->image->accessed = true;
		mutex_unlock( &client->image->lock );
	}
	if ( cache != NULL ) {
		ref_put( &cache->reference );
	}
	freeClientStruct( client ); // This will also call image_release on client->image
	return NULL ;
fail_preadd: ;
	// This is before we even initialized any mutex
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
		if ( _clients[i] == NULL )
			continue;
		shutdown( _clients[i]->sock, SHUT_RDWR );
		pthread_kill( _clients[i]->thread, SIGINT );
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
	if ( _num_clients != 0 ) {
		for ( i = _num_clients - 1; i >= 0; --i ) {
			if ( _clients[i] == client ) {
				_clients[i] = NULL;
				break;
			}
		}
		if ( i != 0 && i + 1 == _num_clients ) {
			do {
				i--;
			} while ( _clients[i] == NULL && i > 0 );
			_num_clients = i + 1;
		}
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
	if ( client->image != NULL ) {
		dnbd3_uplink_t *uplink = ref_get_uplink( &client->image->uplinkref );
		if ( uplink != NULL ) {
			if ( client->relayedCount != 0 ) {
				uplink_removeEntry( uplink, client );
			}
			ref_put( &uplink->reference );
		}
		if ( client->relayedCount != 0 ) {
			logadd( LOG_DEBUG1, "Client has relayedCount == %"PRIu8" on disconnect..", client->relayedCount );
			int i;
			for ( i = 0; i < 1000 && client->relayedCount != 0; ++i ) {
				usleep( 10000 );
			}
			if ( client->relayedCount != 0 ) {
				logadd( LOG_WARNING, "Client relayedCount still %"PRIu8" after sleeping!", client->relayedCount );
			}
		}
	}
	mutex_lock( &client->sendMutex );
	if ( client->sock != -1 ) {
		close( client->sock );
	}
	client->sock = -1;
	mutex_unlock( &client->sendMutex );
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

static void uplinkCallback(void *data, uint64_t handle, uint64_t start UNUSED, uint32_t length, const char *buffer)
{
	dnbd3_client_t *client = (dnbd3_client_t*)data;
	dnbd3_reply_t reply = {
		.magic = dnbd3_packet_magic,
		.cmd = buffer == NULL ? CMD_ERROR : CMD_GET_BLOCK,
		.handle = handle,
		.size = length,
	};
	mutex_lock( &client->sendMutex );
	send_reply( client->sock, &reply, buffer );
	if ( buffer == NULL ) {
		shutdown( client->sock, SHUT_RDWR );
	}
	client->relayedCount--;
	mutex_unlock( &client->sendMutex );
}

