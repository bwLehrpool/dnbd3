#include "uplink.h"
#include "locks.h"
#include "memlog.h"
#include "sockhelper.h"
#include "image.h"
#include "helper.h"
#include "altservers.h"
#include "helper.h"
#include "protocol.h"

#include <pthread.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/errno.h>
#include <sys/eventfd.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <zlib.h>
#include <fcntl.h>

static void* uplink_mainloop(void *data);
static void uplink_send_requests(dnbd3_connection_t *link, int newOnly);
static void uplink_handle_receive(dnbd3_connection_t *link);
static int uplink_send_keepalive(const int fd);
static void uplink_addCrc32(dnbd3_connection_t *uplink);

// ############ uplink connection handling

/**
 * Create and initialize an uplink instance for the given
 * image. Uplinks run in their own thread.
 * Locks on: _images[].lock
 */
int uplink_init(dnbd3_image_t *image, int sock, dnbd3_host_t *host)
{
	if ( !_isProxy ) return FALSE;
	dnbd3_connection_t *link = NULL;
	assert( image != NULL );
	spin_lock( &image->lock );
	if ( image->uplink != NULL ) {
		spin_unlock( &image->lock );
		return TRUE;
	}
	if ( image->cache_map == NULL ) {
		memlogf( "[WARNING] Uplink was requested for image %s, but it is already complete", image->lower_name );
		goto failure;
	}
	link = image->uplink = calloc( 1, sizeof(dnbd3_connection_t) );
	link->image = image;
	link->queueLen = 0;
	link->fd = -1;
	link->signal = -1;
	if ( sock >= 0 ) {
		link->betterFd = sock;
		link->betterServer = *host;
		link->rttTestResult = RTT_DOCHANGE;
	} else {
		link->betterFd = -1;
		link->rttTestResult = RTT_IDLE;
	}
	link->recvBufferLen = 0;
	link->shutdown = FALSE;
	spin_init( &link->queueLock, PTHREAD_PROCESS_PRIVATE );
	if ( 0 != pthread_create( &(link->thread), NULL, &uplink_mainloop, (void *)(uintptr_t)link ) ) {
		memlogf( "[ERROR] Could not start thread for new client." );
		goto failure;
	}
	spin_unlock( &image->lock );
	return TRUE;
	failure: ;
	if ( link != NULL ) free( link );
	link = image->uplink = NULL;
	spin_unlock( &image->lock );
	return FALSE;
}

void uplink_shutdown(dnbd3_image_t *image)
{
	assert( image != NULL );
	if ( image->uplink == NULL || image->uplink->shutdown ) return;
	dnbd3_connection_t * const uplink = image->uplink;
	spin_lock( &uplink->queueLock );
	image->uplink = NULL;
	uplink->shutdown = TRUE;
	spin_unlock( &uplink->queueLock );
	spin_destroy( &uplink->queueLock );
	if ( uplink->signal != -1 ) write( uplink->signal, "", 1 );
	if ( uplink->image != NULL ) {
		pthread_join( uplink->thread, NULL );
	}
	free( uplink->recvBuffer );
	free( uplink );
}

/**
 * Remove given client from uplink request queue
 * Locks on: uplink.queueLock, client.sendMutex
 */
void uplink_removeClient(dnbd3_connection_t *uplink, dnbd3_client_t *client)
{
	spin_lock( &uplink->queueLock );
	for (int i = uplink->queueLen - 1; i >= 0; --i) {
		if ( uplink->queue[i].client == client ) {
			uplink->queue[i].client = NULL;
			uplink->queue[i].status = ULR_FREE;
			if ( i > 20 && uplink->queueLen == i + 1 ) uplink->queueLen--;
		}
	}
	spin_unlock( &uplink->queueLock );
}

/**
 * Request a chunk of data through an uplink server
 */
int uplink_request(dnbd3_client_t *client, uint64_t handle, uint64_t start, uint32_t length)
{
	if ( client == NULL || client->image == NULL ) return FALSE;
	spin_lock( &client->image->lock );
	if ( client->image->uplink == NULL ) {
		spin_unlock( &client->image->lock );
		return FALSE;
	}
	dnbd3_connection_t * const uplink = client->image->uplink;
	int foundExisting = -1; // Index of a pending request that is a superset of our range, -1 otherwise
	int existingType = -1; // ULR_* type of existing request
	int i;
	int freeSlot = -1;
	const uint64_t end = start + length;

	spin_lock( &uplink->queueLock );
	spin_unlock( &client->image->lock );
	for (i = 0; i < uplink->queueLen; ++i) {
		if ( freeSlot == -1 && uplink->queue[i].status == ULR_FREE ) freeSlot = i;
		if ( uplink->queue[i].status != ULR_PENDING && uplink->queue[i].status != ULR_NEW ) continue;
		if ( (foundExisting == -1 || existingType == ULR_PENDING) && uplink->queue[i].from <= start && uplink->queue[i].to >= end ) {
			foundExisting = i;
			existingType = uplink->queue[i].status;
			break;
		}
	}
	if ( freeSlot == -1 ) {
		if ( uplink->queueLen >= SERVER_MAX_UPLINK_QUEUE ) {
			spin_unlock( &uplink->queueLock );
			memlogf( "[WARNING] Uplink queue is full, consider increasing SERVER_MAX_UPLINK_QUEUE. Dropping client..." );
			return FALSE;
		}
		freeSlot = uplink->queueLen++;
	}
	// Do not send request to uplink server if we have a matching pending request AND the request either has the
	// status ULR_NEW OR we found a free slot with LOWER index than the one we attach to. Otherwise
	// explicitly send this request to the uplink server. The second condition mentioned here is to prevent
	// a race condition where the reply for the outstanding request already arrived and the uplink thread
	// is currently traversing the request queue. As it is processing the queue from highest to lowest index, it might
	// already have passed the index of the free slot we determined, but not reached the existing request we just found above.
	if ( foundExisting != -1 && existingType != ULR_NEW && freeSlot > foundExisting ) foundExisting = -1;
	// Fill structure
	uplink->queue[freeSlot].from = start;
	uplink->queue[freeSlot].to = end;
	uplink->queue[freeSlot].handle = handle;
	uplink->queue[freeSlot].client = client;
	uplink->queue[freeSlot].status = (foundExisting == -1 ? ULR_NEW : ULR_PENDING);
#ifdef _DEBUG
	uplink->queue[freeSlot].entered = time( NULL );
#endif
	spin_unlock( &uplink->queueLock );

	if ( foundExisting == -1 ) { // Only wake up uplink thread if the request needs to be relayed
		static uint64_t counter = 1;
		write( uplink->signal, &counter, sizeof(uint64_t) );
	}
	return TRUE;
}

/**
 * Uplink thread.
 * Locks are irrelevant as this is never called from another function
 */
static void* uplink_mainloop(void *data)
{
	const int MAXEVENTS = 3;
	struct epoll_event ev, events[MAXEVENTS];
	dnbd3_connection_t *link = (dnbd3_connection_t*)data;
	int fdEpoll = -1;
	int numSocks, i, waitTime;
	int altCheckInterval = SERVER_RTT_DELAY_INIT;
	int bFree = FALSE;
	time_t nextAltCheck = 0;
	char buffer[100];
	//
	assert( link != NULL );
	assert( link->queueLen == 0 );
	setThreadName( "idle-uplink" );
	blockNoncriticalSignals();
	//
	fdEpoll = epoll_create( 2 );
	if ( fdEpoll == -1 ) {
		memlogf( "[WARNING] epoll_create failed. Uplink unavailable." );
		goto cleanup;
	}
	link->signal = eventfd( 0, EFD_NONBLOCK );
	if ( link->signal < 0 ) {
		memlogf( "[WARNING] error creating pipe. Uplink unavailable." );
		goto cleanup;
	}
	memset( &ev, 0, sizeof(ev) );
	ev.events = EPOLLIN;
	ev.data.fd = link->signal;
	if ( epoll_ctl( fdEpoll, EPOLL_CTL_ADD, link->signal, &ev ) < 0 ) {
		memlogf( "[WARNING] adding eventfd to epoll set failed" );
		goto cleanup;
	}
	while ( !_shutdown && !link->shutdown ) {
		// Check if server switch is in order
		if ( link->rttTestResult == RTT_DOCHANGE ) {
			link->rttTestResult = RTT_IDLE;
			// The rttTest worker thread has finished our request.
			// And says it's better to switch to another server
			const int fd = link->fd;
			link->fd = link->betterFd;
			if ( fd != -1 ) close( fd );
			// If we don't have a crc32 list yet, see if the new server has one
			if ( link->image->crc32 == NULL ) {
				uplink_addCrc32( link );
			}
			// Re-send all pending requests
			uplink_send_requests( link, FALSE );
			link->betterFd = -1;
			link->currentServer = link->betterServer;
			link->image->working = TRUE;
			buffer[0] = '@';
			if ( host_to_string( &link->currentServer, buffer + 1, sizeof(buffer) - 1 ) ) {
				printf( "[DEBUG] Now connected to %s\n", buffer + 1 );
				setThreadName( buffer );
			}
			memset( &ev, 0, sizeof(ev) );
			ev.events = EPOLLIN;
			ev.data.fd = link->fd;
			if ( epoll_ctl( fdEpoll, EPOLL_CTL_ADD, link->fd, &ev ) < 0 ) {
				memlogf( "[WARNING] adding uplink to epoll set failed" );
				goto cleanup;
			}
			nextAltCheck = time( NULL ) + altCheckInterval;
			// The rtt worker already did the handshake for our image, so there's nothing
			// more to do here
		}
		// epoll()
		if ( link->fd == -1 ) {
			waitTime = 2000;
			nextAltCheck = 0;
		} else {
			waitTime = (time( NULL ) - nextAltCheck) * 1000;
			if ( waitTime < 1500 ) waitTime = 1500;
		}
		numSocks = epoll_wait( fdEpoll, events, MAXEVENTS, waitTime );
		if ( _shutdown || link->shutdown ) goto cleanup;
		if ( numSocks < 0 ) { // Error?
			memlogf( "[DEBUG] epoll_wait() error %d", (int)errno);
			usleep( 10000 );
			continue;
		}
		// Check all events
		for (i = 0; i < numSocks; ++i) {
			if ( (events[i].events & (EPOLLERR | EPOLLHUP)) || !(events[i].events & EPOLLIN) ) {
				if ( events[i].data.fd == link->signal ) {
					memlogf( "[WARNING] epoll error on signal-pipe!" );
					goto cleanup;
				}
				if ( events[i].data.fd == link->fd ) {
					link->fd = -1;
					close( events[i].data.fd );
					printf( "[DEBUG] Uplink gone away, panic!\n" );
					nextAltCheck = 0;
				} else {
					printf( "[DEBUG] Error on unknown FD in uplink epoll\n" );
					close( events[i].data.fd );
				}
				continue;
			}
			// No error, handle normally
			if ( events[i].data.fd == link->signal ) {
				int ret;
				do {
					ret = read( link->signal, buffer, sizeof buffer );
				} while ( ret == sizeof buffer ); // Throw data away, this is just used for waking this thread up
				if ( ret == 0 ) {
					memlogf( "[WARNING] Eventfd of uplink for %s closed! Things will break!", link->image->lower_name );
				}
				if ( ret < 0 ) {
					ret = errno;
					if ( ret != EAGAIN && ret != EWOULDBLOCK && ret != EBUSY && ret != EINTR ) {
						memlogf( "[WARNING] Errno %d on eventfd on uplink for %s! Things will break!", ret, link->image->lower_name );
					}
				}
				if ( link->fd != -1 ) {
					uplink_send_requests( link, TRUE );
				}
			} else if ( events[i].data.fd == link->fd ) {
				uplink_handle_receive( link );
				if ( link->fd == -1 ) nextAltCheck = 0;
				if ( _shutdown || link->shutdown ) goto cleanup;
			} else {
				printf( "[DEBUG] Sanity check: unknown FD ready on epoll! Closing...\n" );
				close( events[i].data.fd );
			}
		}
		// Done handling epoll sockets
		// See if we should trigger an RTT measurement
		if ( link->rttTestResult == RTT_IDLE || link->rttTestResult == RTT_DONTCHANGE ) {
			const time_t now = time( NULL );
			if ( nextAltCheck - now > SERVER_RTT_DELAY_MAX ) {
				// This probably means the system time was changed - handle this case properly by capping the timeout
				nextAltCheck = now + SERVER_RTT_DELAY_MAX;
			} else if ( now >= nextAltCheck ) {
				// It seems it's time for a check
				if ( image_isComplete( link->image ) ) {
					// Quit work if image is complete
					memlogf( "[INFO] Replication of %s complete.", link->image->lower_name );
					if ( spin_trylock( &link->image->lock ) == 0 ) {
						image_markComplete( link->image );
						link->image->uplink = NULL;
						link->shutdown = TRUE;
						free( link->recvBuffer );
						link->recvBuffer = NULL;
						bFree = TRUE;
						spin_lock( &link->queueLock );
						spin_unlock( &link->queueLock );
						spin_destroy( &link->queueLock );
						spin_unlock( &link->image->lock );
						pthread_detach( link->thread );
						goto cleanup;
					}
				} else {
					// Not complete - do measurement
					altservers_findUplink( link ); // This will set RTT_INPROGRESS (synchronous)
					// Also send a keepalive packet to the currently connected server
					if ( link->fd != -1 ) {
						if ( !uplink_send_keepalive( link->fd ) ) {
							printf( "[DEBUG] Error sending keep-alive to uplink\n" );
							altservers_serverFailed( &link->currentServer );
							const int fd = link->fd;
							link->fd = -1;
							close( fd );
						}
					}
				}
				altCheckInterval = MIN(altCheckInterval + 1, SERVER_RTT_DELAY_MAX);
				nextAltCheck = now + altCheckInterval;
			}
		}
#ifdef _DEBUG
		if ( link->fd != -1 ) {
			time_t deadline = time( NULL ) - 10;
			spin_lock( &link->queueLock );
			for (i = 0; i < link->queueLen; ++i) {
				if ( link->queue[i].status != ULR_FREE && link->queue[i].entered < deadline ) {
					printf( "[DEBUG WARNING] Starving request detected:\n"
							"%s\n(from %" PRIu64 " to %" PRIu64 ", status: %d)\n", link->queue[i].client->image->lower_name,
					        link->queue[i].from, link->queue[i].to, link->queue[i].status );
				}
			}
			spin_unlock( &link->queueLock );
		}
#endif
	}
	cleanup: ;
	const int fd = link->fd;
	const int signal = link->signal;
	link->fd = -1;
	link->signal = -1;
	if ( fd != -1 ) close( fd );
	if ( signal != -1 ) close( signal );
	if ( fdEpoll != -1 ) close( fdEpoll );
	// Wait for the RTT check to finish/fail if it's in progress
	while ( link->rttTestResult == RTT_INPROGRESS )
		usleep( 10000 );
	if ( link->betterFd != -1 ) close( link->betterFd );
	if ( bFree ) free( link );
	return NULL ;
}

static void uplink_send_requests(dnbd3_connection_t *link, int newOnly)
{
	// Scan for new requests
	int j;
	dnbd3_request_t request;
	request.magic = dnbd3_packet_magic;
	spin_lock( &link->queueLock );
	for (j = 0; j < link->queueLen; ++j) {
		if ( link->queue[j].status != ULR_NEW && (newOnly || link->queue[j].status != ULR_PENDING) ) continue;
		link->queue[j].status = ULR_PENDING;
		request.handle = link->queue[j].from; // HACK: Store offset in handle too, as it won't be included in the reply
		request.cmd = CMD_GET_BLOCK;
		request.offset = link->queue[j].from;
		request.size = link->queue[j].to - link->queue[j].from;
		spin_unlock( &link->queueLock );
		fixup_request( request );
		const int ret = send( link->fd, &request, sizeof request, MSG_NOSIGNAL );
		if ( ret != sizeof(request) ) {
			// Non-critical - if the connection dropped or the server was changed
			// the thread will re-send this request as soon as the connection
			// is reestablished.
			printf( "[DEBUG] Error sending request to uplink server!\n" );
			altservers_serverFailed( &link->currentServer );
			break;
		}
		spin_lock( &link->queueLock );
	}
	spin_unlock( &link->queueLock );
}

/**
 * Receive data from uplink server and process/dispatch
 * Locks on: link.lock, indirectly on images[].lock
 */
static void uplink_handle_receive(dnbd3_connection_t *link)
{
	dnbd3_reply_t inReply, outReply;
	int ret, i;
	for (;;) {
		ret = recv( link->fd, &inReply, sizeof inReply, MSG_DONTWAIT | MSG_NOSIGNAL );
		if ( ret < 0 ) {
			const int err = errno;
			if ( err == EAGAIN || err == EWOULDBLOCK || err == EINTR ) return; // OK cases
			goto error_cleanup;
		}
		if ( ret == 0 ) {
			memlogf( "[INFO] Uplink: Remote host hung up (%s)", link->image->path );
			goto error_cleanup;
		}
		if ( ret != sizeof inReply ) ret += recv( link->fd, &inReply + ret, sizeof(inReply) - ret, MSG_WAITALL | MSG_NOSIGNAL );
		if ( ret != sizeof inReply ) {
			const int err = errno;
			memlogf( "[INFO] Lost connection to uplink server for %s (header %d/%d, e=%d)", link->image->path, ret, (int)sizeof(inReply),
			        err );
			goto error_cleanup;
		}
		fixup_reply( inReply );
		if ( inReply.magic != dnbd3_packet_magic ) {
			memlogf( "[WARNING] Uplink server's packet did not start with dnbd3_packet_magic (%s)", link->image->path );
			goto error_cleanup;
		}
		if ( inReply.size > 9000000 ) {
			memlogf( "[WARNING] Pure evil: Uplink server sent too much payload for %s", link->image->path );
			goto error_cleanup;
		}
		if ( link->recvBufferLen < inReply.size ) {
			if ( link->recvBuffer != NULL ) free( link->recvBuffer );
			link->recvBufferLen = MIN(9000000, inReply.size + 8192);
			link->recvBuffer = malloc( link->recvBufferLen );
		}
		uint32_t done = 0;
		while ( done < inReply.size ) {
			ret = recv( link->fd, link->recvBuffer + done, inReply.size - done, MSG_NOSIGNAL );
			if ( ret <= 0 ) {
				memlogf( "[INFO] Lost connection to uplink server of %s (payload)", link->image->path );
				goto error_cleanup;
			}
			done += ret;
		}
		// Payload read completely
		// Bail out if we're not interested
		if ( inReply.cmd != CMD_GET_BLOCK ) return;
		// Is a legit block reply
		const uint64_t start = inReply.handle;
		const uint64_t end = inReply.handle + inReply.size;
		// 1) Write to cache file
		assert( link->image->cacheFd != -1 );
		if ( lseek( link->image->cacheFd, start, SEEK_SET ) != start ) {
			memlogf( "[ERROR] lseek() failed when writing to cache for %s", link->image->path );
		} else {
			ret = (int)write( link->image->cacheFd, link->recvBuffer, inReply.size );
			if ( ret > 0 ) image_updateCachemap( link->image, start, start + ret, TRUE );
		}
		// 2) Figure out which clients are interested in it
		struct iovec iov[2];
		spin_lock( &link->queueLock );
		for (i = 0; i < link->queueLen; ++i) {
			dnbd3_queued_request_t * const req = &link->queue[i];
			assert( req->status != ULR_PROCESSING || req->status != ULR_NEW );
			if ( req->status != ULR_PENDING ) continue;
			if ( req->from >= start && req->to <= end ) { // Match :-)
				req->status = ULR_PROCESSING;
			}
		}
		// 3) Send to interested clients - iterate backwards so request collaboration works, and
		// so we can decrease queueLen on the fly while iterating. Should you ever change this to start
		// from 0, you also need to change the "attach to existing request"-logic in uplink_request()
		outReply.magic = dnbd3_packet_magic;
		for (i = link->queueLen - 1; i >= 0; --i) {
			dnbd3_queued_request_t * const req = &link->queue[i];
			if ( req->status != ULR_PROCESSING ) continue;
			assert( req->from >= start && req->to <= end );
			dnbd3_client_t * const client = req->client;
			outReply.cmd = CMD_GET_BLOCK;
			outReply.handle = req->handle;
			outReply.size = req->to - req->from;
			iov[0].iov_base = &outReply;
			iov[0].iov_len = sizeof outReply;
			iov[1].iov_base = link->recvBuffer + (req->from - start);
			iov[1].iov_len = outReply.size;
			fixup_reply( outReply );
			req->status = ULR_FREE;
			pthread_mutex_lock( &client->sendMutex );
			spin_unlock( &link->queueLock );
			writev( client->sock, iov, 2 );
			pthread_mutex_unlock( &client->sendMutex );
			spin_lock( &link->queueLock );
			if ( i > 20 && i == link->queueLen - 1 ) link->queueLen--;
		}
		spin_unlock( &link->queueLock );
	}
	error_cleanup: ;
	altservers_serverFailed( &link->currentServer );
	const int fd = link->fd;
	link->fd = -1;
	if ( fd != -1 ) close( fd );
}

/**
 * Send keep alive request to server
 */
static int uplink_send_keepalive(const int fd)
{
	static dnbd3_request_t request = { 0, 0, 0, 0, 0 };
	if ( request.magic == 0 ) {
		request.magic = dnbd3_packet_magic;
		request.cmd = CMD_KEEPALIVE;
		fixup_request( request );
	}
	return send( fd, &request, sizeof(request), MSG_NOSIGNAL ) == sizeof(request);
}

static void uplink_addCrc32(dnbd3_connection_t *uplink)
{
	dnbd3_image_t *image = uplink->image;
	if ( image == NULL || image->filesize == 0 ) return;
	size_t bytes = IMGSIZE_TO_HASHBLOCKS(image->filesize) * sizeof(uint32_t);
	uint32_t masterCrc;
	uint32_t *buffer = malloc( bytes );
	if ( !dnbd3_get_crc32( uplink->fd, &masterCrc, buffer, &bytes ) || bytes == 0 ) {
		free( buffer );
		return;
	}
	uint32_t lists_crc = crc32( 0L, Z_NULL, 0 );
	lists_crc = crc32( lists_crc, (Bytef*)buffer, bytes );
	if ( lists_crc != masterCrc ) {
		memlogf( "[WARNING] Received corrupted crc32 list from uplink server (%s)!", uplink->image->lower_name );
		free( buffer );
		return;
	}
	uplink->image->masterCrc32 = masterCrc;
	uplink->image->crc32 = buffer;
	const size_t len = strlen( uplink->image->path ) + 30;
	char path[len];
	snprintf( path, len, "%s.crc", uplink->image->path );
	const int fd = open( path, O_WRONLY | O_CREAT, 0640 );
	if ( fd >= 0 ) {
		write( fd, &masterCrc, sizeof(uint32_t) );
		write( fd, buffer, bytes );
		close( fd );
	}
}
