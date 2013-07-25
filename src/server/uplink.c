#include "uplink.h"
#include "locks.h"
#include "memlog.h"
#include "sockhelper.h"
#include <pthread.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

dnbd3_alt_server_t *_alt_servers[SERVER_MAX_ALTS];
int _num_alts = 0;
pthread_spinlock_t _alts_lock;

static void* uplink_mainloop(void *data);
static void uplink_handle_receive(dnbd3_connection_t *link);

/**
 * Get <size> known (working) alt servers, ordered by network closeness
 * (by finding the smallest possible subnet)
 */
int uplink_get_matching_alt_servers(dnbd3_host_t *host, dnbd3_server_entry_t *output, int size)
{
	if ( host == NULL || host->type == 0 || _num_alts == 0 ) return 0;
	int i, j;
	int count = 0;
	int distance[size];
	spin_lock( &_alts_lock );
	for (i = 0; i < _num_alts; ++i) {
		if ( host->type != _alt_servers[i]->host.type ) continue; // Wrong address family
		if ( count == 0 ) {
			// Trivial - this is the first entry
			memcpy( &output[0].host, &_alt_servers[i]->host, sizeof(dnbd3_host_t) );
			output[0].failures = 0;
			distance[0] = uplink_net_closeness( host, &output[0].host );
			count++;
		} else {
			// Other entries already exist, insert in proper position
			const int dist = uplink_net_closeness( host, &_alt_servers[i]->host );
			for (j = 0; j < size; ++j) {
				if ( j < count && dist <= distance[j] ) continue;
				if ( j > count ) break; // Should never happen but just in case...
				if ( j < count ) {
					// Check if we're in the middle and need to move other entries...
					if ( j + 1 < size ) {
						memmove( &output[j + 1], &output[j], sizeof(dnbd3_server_entry_t) * (size - j - 1) );
						memmove( &distance[j + 1], &distance[j], sizeof(int) * (size - j - 1) );
					}
				} else {
					count++;
				}
				memcpy( &output[j].host, &_alt_servers[i]->host, sizeof(dnbd3_host_t) );
				output[j].failures = 0;
				distance[j] = dist;
				break;
			}
		}
	}
	spin_unlock( &_alts_lock );
	return count;
}

/**
 * Determine how close two addresses are to each other by comparing the number of
 * matching bits from the left of the address. Does not count individual bits but
 * groups of 4 for speed.
 */
int uplink_net_closeness(dnbd3_host_t *host1, dnbd3_host_t *host2)
{
	if ( host1 == NULL || host2 == NULL || host1->type != host2->type ) return -1;
	int retval = 0;
	const int max = host1->type == AF_INET ? 4 : 16;
	for (int i = 0; i < max; ++i) {
		if ( (host1->addr[i] & 0xf0) != (host2->addr[i] & 0xf0) ) return retval;
		++retval;
		if ( (host1->addr[i] & 0x0f) != (host2->addr[i] & 0x0f) ) return retval;
		++retval;
	}
	return retval;
}

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
	link->queuelen = 0;
	link->fd = -1;
	link->signal = -1;
	link->betterFd = -1;
	link->rttTestResult = RTT_IDLE;
	link->recvBufferLen = 0;
	spin_init( &link->lock, PTHREAD_PROCESS_PRIVATE );
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

void uplink_shutdown(dnbd3_connection_t *uplink)
{
	assert( uplink != NULL );
	if ( uplink->fd != -1 ) close( uplink->fd );
	pthread_join( uplink->thread, NULL );
}

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
	assert( link->queuelen == 0 );
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
	while ( !_shutdown ) {
		if ( link->rttTestResult == RTT_DOCHANGE ) {
			link->rttTestResult = RTT_IDLE;
			// The rttTest worker thread has finished our request.
			// And says it's better to switch to another server
			if ( link->fd != -1 ) close( link->fd );
			link->fd = link->betterFd;
			link->betterFd = -1;
			link->currentServer = link->betterServer;
			memset( &ev, 0, sizeof(ev) );
			ev.events = EPOLLIN;
			ev.data.fd = link->fd;
			if ( epoll_ctl( fdEpoll, EPOLL_CTL_ADD, link->fd, &ev ) < 0 ) {
				memlogf( "[WARNING] adding uplink to epoll set failed" );
				goto cleanup;
			}
			// The rtt worker already did the handshake for our image, so there's nothing
			// more to do here
		}
		// epoll()
		if ( link->fd == -1 ) {
			waitTime = 1500;
		} else {
			waitTime = (time( NULL ) - nextAltCheck) * 1000;
			if ( waitTime < 1500 ) waitTime = 1500;
		}
		numSocks = epoll_wait( fdEpoll, events, MAXEVENTS, waitTime );
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
				close( events[i].data.fd );
				if ( events[i].data.fd == link->fd ) {
					link->fd = -1;
					printf( "[DEBUG] Uplink gone away, panic!\n" );
					nextAltCheck = 0;
				}
				continue;
			}
			// No error, handle normally
			if ( events[i].data.fd == fdPipe ) {
				while ( read( fdPipe, buffer, sizeof buffer ) > 0 ) {
				} // Throw data away, this is just used for waking this thread up
			} else if ( events[i].data.fd == link->fd ) {
				uplink_handle_receive( link );
				if ( link->fd == -1 ) nextAltCheck = 0;
			} else {
				printf( "[DEBUG] Sanity check: unknown FD ready on epoll! Closing...\n" );
				close( events[i].data.fd );
			}
		}
	}
	cleanup: ;
	if ( link->fd != -1 ) close( link->fd );
	link->fd = -1;
	if ( link->signal != -1 ) close( link->signal );
	link->signal = -1;
	if ( fdPipe != -1 ) close( fdPipe );
	if ( fdEpoll != -1 ) close( fdEpoll );
	return NULL ;
}

static void uplink_handle_receive(dnbd3_connection_t *link)
{
	dnbd3_reply_t reply;
	int ret, i;
	ret = recv( link->fd, &reply, sizeof reply, MSG_WAITALL );
	if ( ret != sizeof reply ) {
		memlogf( "[INFO] Lost connection to uplink server." );
		goto error_cleanup;
	}
	fixup_reply( reply );
	if ( reply.size > 9000000 ) {
		memlogf( "[WARNING] Pure evil: Uplink server sent too much payload!" );
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
			memlogf( "[INFO] Lost connection to uplink server" );
			goto error_cleanup;
		}
		done += ret;
	}
	// Payload read completely
	// 1) Write to cache file
	assert( link->image->cacheFd != -1 );
	// 2) Figure out which clients are interested in it
	const uint64_t start = reply.handle;
	const uint64_t end = reply.handle + reply.size;
	struct iovec iov[2];
	reply.magic = dnbd3_packet_magic;
	spin_lock( &link->lock );
	for (i = 0; i < link->queuelen; ++i) {
		dnbd3_queued_request_t * const req = &link->queue[i];
		assert( req->status != ULR_PROCESSING );
		if ( req->status != ULR_PENDING ) continue;
		if ( req->from >= start && req->to <= end ) { // Match :-)
			req->status = ULR_PROCESSING;
		}
	}
	for (i = link->queuelen - 1; i >= 0; --i) {
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
		spin_unlock( &link->lock );
		// send: Don't care about errors here, let the client
		// connection thread deal with it if something goes wrong here
		writev( req->socket, iov, 2 );
		spin_lock( &link->lock );
		req->status = ULR_FREE;
		if ( i > 20 && i == link->queuelen - 1 ) link->queuelen--;
	}
	spin_unlock( &link->lock );
	return;
	error_cleanup: ;
	close( link->fd );
	link->fd = -1;
	return;
}
