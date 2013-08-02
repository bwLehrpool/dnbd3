#include "uplink.h"
#include "locks.h"
#include "memlog.h"
#include "sockhelper.h"
#include "image.h"
#include "altservers.h"
#include <pthread.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

static void* uplink_mainloop(void *data);
static void uplink_send_requests(dnbd3_connection_t *link, int newOnly);
static void uplink_handle_receive(dnbd3_connection_t *link);

// ############ uplink connection handling

/**
 * Create and initialize an uplink instance for the given
 * image. Uplinks run in their own thread.
 * Locks on: _images[].lock
 */
int uplink_init(dnbd3_image_t *image)
{
	dnbd3_connection_t *link = NULL;
	assert( image != NULL );
	spin_lock( &image->lock );
	assert( image->uplink == NULL );
	if ( image->cache_map == NULL ) {
		memlogf( "[WARNING] Uplink was requested for image %s, but it is already complete", image->lower_name );
		goto failure;
	}
	link = image->uplink = calloc( 1, sizeof(dnbd3_connection_t) );
	link->image = image;
	link->queueLen = 0;
	link->fd = -1;
	link->signal = -1;
	link->betterFd = -1;
	link->rttTestResult = RTT_IDLE;
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
	image->uplink = NULL;
	uplink->shutdown = TRUE;
	if ( uplink->signal != -1 ) write( uplink->signal, "", 1 );
	pthread_join( uplink->thread, NULL );
	spin_lock( &uplink->queueLock );
	spin_unlock( &uplink->queueLock );
	spin_destroy( &uplink->queueLock );
	free( uplink );
}

/**
 * Request a chunk of data through an uplink server
 */
int uplink_request(dnbd3_client_t *client, uint64_t handle, uint64_t start, uint32_t length)
{
	if ( client == NULL || client->image == NULL || client->image->uplink == NULL ) return FALSE;
	dnbd3_connection_t * const uplink = client->image->uplink;
	int foundExisting = FALSE; // Is there a pending request that is a superset of our range?
	int i;
	int freeSlot = -1;
	const uint64_t end = start + length;

	spin_lock( &uplink->queueLock );
	for (i = 0; i < uplink->queueLen; ++i) {
		if ( freeSlot == -1 && uplink->queue[i].status == ULR_FREE ) freeSlot = i;
		if ( uplink->queue[i].status != ULR_PENDING && uplink->queue[i].status != ULR_NEW ) continue;
		if ( uplink->queue[i].from <= start && uplink->queue[i].to >= end ) {
			foundExisting = TRUE;
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
	uplink->queue[freeSlot].from = start;
	uplink->queue[freeSlot].to = end;
	uplink->queue[freeSlot].handle = handle;
	uplink->queue[freeSlot].client = client;
	uplink->queue[freeSlot].status = (foundExisting ? ULR_PENDING : ULR_NEW);
	spin_unlock( &uplink->queueLock );

	if ( !foundExisting ) {
		write( uplink->signal, "", 1 );
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
	int fdEpoll = -1, fdPipe = -1;
	int numSocks, i, waitTime;
	int altCheckInterval = SERVER_RTT_DELAY_INIT;
	time_t nextAltCheck = 0;
	char buffer[100];
	//
	assert( link != NULL );
	assert( link->queueLen == 0 );
	//
	fdEpoll = epoll_create( 2 );
	if ( fdEpoll == -1 ) {
		memlogf( "[WARNING] epoll_create failed. Uplink unavailable." );
		goto cleanup;
	}
	{
		int pipes[2];
		if ( pipe( pipes ) < 0 ) {
			memlogf( "[WARNING] error creating pipe. Uplink unavailable." );
			goto cleanup;
		}
		sock_set_nonblock( pipes[0] );
		sock_set_nonblock( pipes[1] );
		fdPipe = pipes[0];
		link->signal = pipes[1];
		memset( &ev, 0, sizeof(ev) );
		ev.events = EPOLLIN;
		ev.data.fd = fdPipe;
		if ( epoll_ctl( fdEpoll, EPOLL_CTL_ADD, fdPipe, &ev ) < 0 ) {
			memlogf( "[WARNING] adding signal-pipe to epoll set failed" );
			goto cleanup;
		}
	}
	while ( !_shutdown && !link->shutdown ) {
		// epoll()
		if ( link->fd == -1 ) {
			waitTime = 1500;
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
		for (i = 0; i < numSocks; ++i) { // Check all events
			if ( (events[i].events & (EPOLLERR | EPOLLHUP)) || !(events[i].events & EPOLLIN) ) {
				if ( events[i].data.fd == fdPipe ) {
					memlogf( "[WARNING] epoll error on signal-pipe!" );
					goto cleanup;
				}
				if ( events[i].data.fd == link->fd ) {
					link->fd = -1;
					close( events[i].data.fd );
					printf( "[DEBUG] Uplink gone away, panic!\n" );
					nextAltCheck = 0;
				} else {
					printf( "[DEBUG] Error on unknown FD in uplink epoll" );
					close( events[i].data.fd );
				}
				continue;
			}
			// No error, handle normally
			if ( events[i].data.fd == fdPipe ) {
				int ret;
				do {
					ret = read( fdPipe, buffer, sizeof buffer );
				} while ( ret > 0 ); // Throw data away, this is just used for waking this thread up
				if ( ret == 0 ) {
					memlogf( "[WARNING] Signal pipe of uplink for %s closed! Things will break!", link->image->lower_name );
				}
				ret = errno;
				if ( ret != EAGAIN && ret != EWOULDBLOCK && ret != EBUSY && ret != EINTR ) {
					memlogf( "[WARNING] Errno %d on pipe-read on uplink for %s! Things will break!", ret, link->image->lower_name );
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
		// Check if server switch is in order
		if ( link->rttTestResult == RTT_DOCHANGE ) {
			link->rttTestResult = RTT_IDLE;
			// The rttTest worker thread has finished our request.
			// And says it's better to switch to another server
			const int fd = link->fd;
			link->fd = link->betterFd;
			if ( fd != -1 ) close( fd );
			// Re-send all pending requests
			uplink_send_requests( link, FALSE );
			link->betterFd = -1;
			link->currentServer = link->betterServer;
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
		// See if we should trigger a RTT measurement
		if ( link->rttTestResult == RTT_IDLE || link->rttTestResult == RTT_DONTCHANGE ) {
			const time_t now = time( NULL );
			if ( nextAltCheck - now > SERVER_RTT_DELAY_MAX ) {
				nextAltCheck = now + SERVER_RTT_DELAY_MAX;
			} else if ( now >= nextAltCheck ) {
				altCheckInterval = MIN(altCheckInterval + 1, SERVER_RTT_DELAY_MAX);
				nextAltCheck = now + altCheckInterval;
				altserver_find_uplink( link ); // This will set RTT_INPROGRESS (synchronous)
			}
		}
	}
	cleanup: ;
	const int fd = link->fd;
	const int signal = link->signal;
	link->fd = -1;
	link->signal = -1;
	if ( fd != -1 ) close( fd );
	if ( signal != -1 ) close( signal );
	if ( fdPipe != -1 ) close( fdPipe );
	if ( fdEpoll != -1 ) close( fdEpoll );
	// Wait for the RTT check to finish/fail if it's in progress
	while ( link->rttTestResult == RTT_INPROGRESS )
		usleep( 10000 );
	if ( link->betterFd != -1 ) close( link->betterFd );
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
		request.handle = link->queue[j].handle;
		request.cmd = CMD_GET_BLOCK;
		request.offset = link->queue[j].from;
		request.size = link->queue[j].to - link->queue[j].from;
		spin_unlock( &link->queueLock );
		fixup_request( request );
		const int ret = write( link->fd, &request, sizeof request );
		if ( ret != sizeof(request) ) {
			// Non-critical - if the connection dropped or the server was changed
			// the thread will re-send this request as soon as the connection
			// is reestablished.
			printf( "[DEBUG] Error sending request to uplink server!" );
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
	dnbd3_reply_t reply;
	int ret, i;
	ret = recv( link->fd, &reply, sizeof reply, MSG_WAITALL );
	if ( ret != sizeof reply ) {
		memlogf( "[INFO] Lost connection to uplink server for %s", link->image->path );
		goto error_cleanup;
	}
	fixup_reply( reply );
	if ( reply.size > 9000000 ) {
		memlogf( "[WARNING] Pure evil: Uplink server sent too much payload for %s", link->image->path );
		goto error_cleanup;
	}
	if ( link->recvBufferLen < reply.size ) {
		if ( link->recvBuffer != NULL ) free( link->recvBuffer );
		link->recvBufferLen = MIN(9000000, reply.size + 8192);
		link->recvBuffer = malloc( link->recvBufferLen );
	}
	uint32_t done = 0;
	while ( done < reply.size ) {
		ret = recv( link->fd, link->recvBuffer + done, reply.size - done, 0 );
		if ( ret <= 0 ) {
			memlogf( "[INFO] Lost connection to uplink server of", link->image->path );
			goto error_cleanup;
		}
		done += ret;
	}
	// Payload read completely
	const uint64_t start = reply.handle;
	const uint64_t end = reply.handle + reply.size;
	// 1) Write to cache file
	assert( link->image->cacheFd != -1 );
	if ( lseek( link->image->cacheFd, start, SEEK_SET ) != start ) {
		memlogf( "[ERROR] lseek() failed when writing to cache for %s", link->image->path );
	} else {
		ret = (int)write( link->image->cacheFd, link->recvBuffer, reply.size );
		if ( ret > 0 ) image_update_cachemap( link->image, start, start + ret, TRUE );
	}
	// 2) Figure out which clients are interested in it
	struct iovec iov[2];
	spin_lock( &link->queueLock );
	for (i = 0; i < link->queueLen; ++i) {
		dnbd3_queued_request_t * const req = &link->queue[i];
		assert( req->status != ULR_PROCESSING );
		if ( req->status != ULR_PENDING ) continue;
		if ( req->from >= start && req->to <= end ) { // Match :-)
			req->status = ULR_PROCESSING;
		}
	}
	// 3) Send to interested clients
	reply.magic = dnbd3_packet_magic; // !! re-using reply struct - do not read from it after here
	for (i = link->queueLen - 1; i >= 0; --i) {
		dnbd3_queued_request_t * const req = &link->queue[i];
		if ( req->status != ULR_PROCESSING ) continue;
		assert( req->from >= start && req->to <= end );
		reply.cmd = CMD_GET_BLOCK;
		reply.handle = req->handle;
		reply.size = req->to - req->from;
		iov[0].iov_base = &reply;
		iov[0].iov_len = sizeof reply;
		iov[1].iov_base = link->recvBuffer + (req->from - start);
		iov[1].iov_len = reply.size;
		fixup_reply( reply );
		spin_unlock( &link->queueLock );
		// send: Don't care about errors here, let the client
		// connection thread deal with it if something goes wrong
		pthread_mutex_lock( &req->client->sendMutex );
		writev( req->client->sock, iov, 2 );
		pthread_mutex_unlock( &req->client->sendMutex );
		spin_lock( &link->queueLock );
		req->status = ULR_FREE;
		if ( i > 20 && i == link->queueLen - 1 ) link->queueLen--;
	}
	spin_unlock( &link->queueLock );
	return;
	error_cleanup: ;
	const int fd = link->fd;
	link->fd = -1;
	if ( fd != -1 ) close( fd );
	return;
}
