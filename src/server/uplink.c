#include "uplink.h"
#include "helper.h"
#include "locks.h"
#include "image.h"
#include "altservers.h"
#include "../shared/sockhelper.h"
#include "../shared/protocol.h"

#include <assert.h>
#include <inttypes.h>
#include <zlib.h>
#include <fcntl.h>
#include <poll.h>


static uint64_t totalBytesReceived = 0;
static pthread_spinlock_t statisticsReceivedLock;

static void* uplink_mainloop(void *data);
static void uplink_sendRequests(dnbd3_connection_t *link, bool newOnly);
static void uplink_handleReceive(dnbd3_connection_t *link);
static int uplink_sendKeepalive(const int fd);
static void uplink_addCrc32(dnbd3_connection_t *uplink);
static void uplink_sendReplicationRequest(dnbd3_connection_t *link);

// ############ uplink connection handling

void uplink_globalsInit()
{
	spin_init( &statisticsReceivedLock, PTHREAD_PROCESS_PRIVATE );
}

uint64_t uplink_getTotalBytesReceived()
{
	spin_lock( &statisticsReceivedLock );
	uint64_t tmp = totalBytesReceived;
	spin_unlock( &statisticsReceivedLock );
	return tmp;
}

/**
 * Create and initialize an uplink instance for the given
 * image. Uplinks run in their own thread.
 * Locks on: _images[].lock
 */
bool uplink_init(dnbd3_image_t *image, int sock, dnbd3_host_t *host, int version)
{
	if ( !_isProxy ) return false;
	dnbd3_connection_t *link = NULL;
	assert( image != NULL );
	spin_lock( &image->lock );
	if ( image->uplink != NULL ) {
		spin_unlock( &image->lock );
		if ( sock >= 0 ) close( sock );
		return true; // There's already an uplink, so should we consider this success or failure?
	}
	if ( image->cache_map == NULL ) {
		logadd( LOG_WARNING, "Uplink was requested for image %s, but it is already complete", image->name );
		goto failure;
	}
	link = image->uplink = calloc( 1, sizeof(dnbd3_connection_t) );
	spin_init( &link->queueLock, PTHREAD_PROCESS_PRIVATE );
	spin_init( &link->rttLock, PTHREAD_PROCESS_PRIVATE );
	link->image = image;
	link->bytesReceived = 0;
	link->queueLen = 0;
	link->fd = -1;
	link->signal = NULL;
	link->replicationHandle = 0;
	spin_lock( &link->rttLock );
	link->cycleDetected = false;
	if ( sock >= 0 ) {
		link->betterFd = sock;
		link->betterServer = *host;
		link->rttTestResult = RTT_DOCHANGE;
		link->betterVersion = version;
	} else {
		link->betterFd = -1;
		link->rttTestResult = RTT_IDLE;
	}
	spin_unlock( &link->rttLock );
	link->recvBufferLen = 0;
	link->shutdown = false;
	if ( 0 != thread_create( &(link->thread), NULL, &uplink_mainloop, (void *)link ) ) {
		logadd( LOG_ERROR, "Could not start thread for new uplink." );
		goto failure;
	}
	spin_unlock( &image->lock );
	return true;
failure: ;
	if ( link != NULL ) {
		free( link );
		link = image->uplink = NULL;
	}
	spin_unlock( &image->lock );
	return false;
}

/**
 * Locks on image.lock, uplink.lock
 * Calling it multiple times, even concurrently, will
 * not break anything.
 */
void uplink_shutdown(dnbd3_image_t *image)
{
	bool join = false;
	pthread_t thread;
	assert( image != NULL );
	spin_lock( &image->lock );
	if ( image->uplink == NULL ) {
		spin_unlock( &image->lock );
		return;
	}
	dnbd3_connection_t * const uplink = image->uplink;
	spin_lock( &uplink->queueLock );
	if ( !uplink->shutdown ) {
		uplink->shutdown = true;
		signal_call( uplink->signal );
		thread = uplink->thread;
		join = true;
	}
	spin_unlock( &uplink->queueLock );
	spin_unlock( &image->lock );
	if ( join ) thread_join( thread, NULL );
	while ( image->uplink != NULL )
		usleep( 10000 );
}

/**
 * Remove given client from uplink request queue
 * Locks on: uplink.queueLock
 */
void uplink_removeClient(dnbd3_connection_t *uplink, dnbd3_client_t *client)
{
	spin_lock( &uplink->queueLock );
	for (int i = uplink->queueLen - 1; i >= 0; --i) {
		if ( uplink->queue[i].client == client ) {
			uplink->queue[i].client = NULL;
			uplink->queue[i].status = ULR_FREE;
		}
		if ( uplink->queue[i].client == NULL && uplink->queueLen == i + 1 ) uplink->queueLen--;
	}
	spin_unlock( &uplink->queueLock );
}

/**
 * Request a chunk of data through an uplink server
 * Locks on: image.lock, uplink.queueLock
 */
bool uplink_request(dnbd3_client_t *client, uint64_t handle, uint64_t start, uint32_t length, uint8_t hops)
{
	if ( client == NULL || client->image == NULL ) return false;
	spin_lock( &client->image->lock );
	if ( client->image->uplink == NULL ) {
		spin_unlock( &client->image->lock );
		logadd( LOG_DEBUG1, "Uplink request for image with no uplink" );
		return false;
	}
	dnbd3_connection_t * const uplink = client->image->uplink;
	if ( uplink->shutdown ) {
		spin_unlock( &client->image->lock );
		logadd( LOG_DEBUG1, "Uplink request for image with uplink shutting down" );
		return false;
	}
	// Check if the client is the same host as the uplink. If so assume this is a circular proxy chain
	// This might be a false positive if there are multiple instances running on the same host (IP)
	if ( hops != 0 && isSameAddress( &uplink->currentServer, &client->host ) ) {
		spin_unlock( &client->image->lock );
		logadd( LOG_WARNING, "Proxy cycle detected (same host)." );
		spin_lock( &uplink->rttLock );
		uplink->cycleDetected = true;
		spin_unlock( &uplink->rttLock );
		signal_call( uplink->signal );
		return false;
	}

	int foundExisting = -1; // Index of a pending request that is a superset of our range, -1 otherwise
	int existingType = -1; // ULR_* type of existing request
	int i;
	int freeSlot = -1;
	bool requestLoop = false;
	const uint64_t end = start + length;

	spin_lock( &uplink->queueLock );
	spin_unlock( &client->image->lock );
	for (i = 0; i < uplink->queueLen; ++i) {
		if ( freeSlot == -1 && uplink->queue[i].status == ULR_FREE ) {
			freeSlot = i;
			continue;
		}
		if ( uplink->queue[i].status != ULR_PENDING && uplink->queue[i].status != ULR_NEW ) continue;
		if ( uplink->queue[i].from <= start && uplink->queue[i].to >= end ) {
			if ( hops > uplink->queue[i].hopCount ) {
				requestLoop = true;
				break;
			}
			if ( foundExisting == -1 || existingType == ULR_PENDING ) {
				foundExisting = i;
				existingType = uplink->queue[i].status;
				if ( freeSlot != -1 ) break;
			}
		}
	}
	if ( requestLoop ) {
		spin_unlock( &uplink->queueLock );
		logadd( LOG_WARNING, "Rejecting relay of request to upstream proxy because of possible cyclic proxy chain. Incoming hop-count is %" PRIu8 ".", hops );
		spin_lock( &uplink->rttLock );
		uplink->cycleDetected = true;
		spin_unlock( &uplink->rttLock );
		signal_call( uplink->signal );
		return false;
	}
	if ( freeSlot == -1 ) {
		if ( uplink->queueLen >= SERVER_MAX_UPLINK_QUEUE ) {
			spin_unlock( &uplink->queueLock );
			logadd( LOG_WARNING, "Uplink queue is full, consider increasing SERVER_MAX_UPLINK_QUEUE. Dropping client..." );
			return false;
		}
		freeSlot = uplink->queueLen++;
	}
	// Do not send request to uplink server if we have a matching pending request AND the request either has the
	// status ULR_NEW OR we found a free slot with LOWER index than the one we attach to. Otherwise
	// explicitly send this request to the uplink server. The second condition mentioned here is to prevent
	// a race condition where the reply for the outstanding request already arrived and the uplink thread
	// is currently traversing the request queue. As it is processing the queue from highest to lowest index, it might
	// already have passed the index of the free slot we determined, but not reached the existing request we just found above.
	if ( foundExisting != -1 && existingType != ULR_NEW && freeSlot > foundExisting ) foundExisting = -1; // -1 means "send request"
#ifdef _DEBUG
	if ( foundExisting != -1 ) {
		logadd( LOG_DEBUG2, "%p (%s) Found existing request of type %s at slot %d, attaching in slot %d.\n", (void*)uplink, uplink->image->name, existingType == ULR_NEW ? "ULR_NEW" : "ULR_PENDING", foundExisting, freeSlot );
		logadd( LOG_DEBUG2, "Original %" PRIu64 "-%" PRIu64 " (%p)\n"
				"New      %" PRIu64 "-%" PRIu64 " (%p)\n",
				uplink->queue[foundExisting].from, uplink->queue[foundExisting].to, (void*)uplink->queue[foundExisting].client,
				start, end, (void*)client );
	}
#endif
	// Fill structure
	uplink->queue[freeSlot].from = start;
	uplink->queue[freeSlot].to = end;
	uplink->queue[freeSlot].handle = handle;
	uplink->queue[freeSlot].client = client;
	//int old = uplink->queue[freeSlot].status;
	uplink->queue[freeSlot].status = (foundExisting == -1 ? ULR_NEW : ULR_PENDING);
	uplink->queue[freeSlot].hopCount = hops;
#ifdef _DEBUG
	uplink->queue[freeSlot].entered = time( NULL );
	//logadd( LOG_DEBUG2 %p] Inserting request at slot %d, was %d, now %d, handle %" PRIu64 ", Range: %" PRIu64 "-%" PRIu64 "\n", (void*)uplink, freeSlot, old, uplink->queue[freeSlot].status, uplink->queue[freeSlot, ".handle, start, end );
#endif
	spin_unlock( &uplink->queueLock );

	if ( foundExisting == -1 ) { // Only wake up uplink thread if the request needs to be relayed
		if ( signal_call( uplink->signal ) == SIGNAL_ERROR ) {
			logadd( LOG_WARNING, "Cannot wake up uplink thread; errno=%d", (int)errno );
		}
	}
	return true;
}

/**
 * Uplink thread.
 * Locks are irrelevant as this is never called from another function
 */
static void* uplink_mainloop(void *data)
{
#define EV_SIGNAL (0)
#define EV_SOCKET (1)
#define EV_COUNT  (2)
	struct pollfd events[EV_COUNT];
	dnbd3_connection_t *link = (dnbd3_connection_t*)data;
	int numSocks, i, waitTime;
	int altCheckInterval = SERVER_RTT_DELAY_INIT;
	int discoverFailCount = 0;
	time_t nextAltCheck = 0, nextKeepalive = 0;
	char buffer[200];
	memset( events, 0, sizeof(events) );
	//
	assert( link != NULL );
	setThreadName( "idle-uplink" );
	blockNoncriticalSignals();
	//
	link->signal = signal_new();
	if ( link->signal == NULL ) {
		logadd( LOG_WARNING, "error creating signal. Uplink unavailable." );
		goto cleanup;
	}
	events[EV_SIGNAL].events = POLLIN;
	events[EV_SIGNAL].fd = signal_getWaitFd( link->signal );
	events[EV_SOCKET].fd = -1;
	while ( !_shutdown && !link->shutdown ) {
		// Check if server switch is in order
		spin_lock( &link->rttLock );
		if ( link->rttTestResult != RTT_DOCHANGE ) {
			spin_unlock( &link->rttLock );
		} else {
			link->rttTestResult = RTT_IDLE;
			// The rttTest worker thread has finished our request.
			// And says it's better to switch to another server
			const int fd = link->fd;
			link->fd = link->betterFd;
			link->betterFd = -1;
			link->currentServer = link->betterServer;
			link->version = link->betterVersion;
			link->cycleDetected = false;
			spin_unlock( &link->rttLock );
			discoverFailCount = 0;
			if ( fd != -1 ) close( fd );
			link->replicationHandle = 0;
			link->image->working = true;
			link->replicatedLastBlock = false; // Reset this to be safe - request could've been sent but reply was never received
			buffer[0] = '@';
			if ( host_to_string( &link->currentServer, buffer + 1, sizeof(buffer) - 1 ) ) {
				logadd( LOG_DEBUG1, "(Uplink %s) Now connected to %s\n", link->image->name, buffer + 1 );
				setThreadName( buffer );
			}
			// If we don't have a crc32 list yet, see if the new server has one
			if ( link->image->crc32 == NULL ) {
				uplink_addCrc32( link );
			}
			// Re-send all pending requests
			uplink_sendRequests( link, false );
			uplink_sendReplicationRequest( link );
			events[EV_SOCKET].events = POLLIN | POLLRDHUP;
			events[EV_SOCKET].fd = link->fd;
			nextAltCheck = time( NULL ) + altCheckInterval;
			// The rtt worker already did the handshake for our image, so there's nothing
			// more to do here
		}
		// poll()
		waitTime = (time( NULL ) - nextAltCheck) * 1000;
		if ( waitTime < 1500 ) waitTime = 1500;
		if ( waitTime > 5000 ) waitTime = 5000;
		numSocks = poll( events, EV_COUNT, waitTime );
		if ( _shutdown || link->shutdown ) goto cleanup;
		if ( numSocks == -1 ) { // Error?
			if ( errno == EINTR ) continue;
			logadd( LOG_DEBUG1, "poll() error %d", (int)errno );
			usleep( 10000 );
			continue;
		}
		// Check events
		// Signal
		if ( (events[EV_SIGNAL].revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) ) {
			logadd( LOG_WARNING, "poll error on signal in uplink_mainloop!" );
			goto cleanup;
		} else if ( (events[EV_SIGNAL].revents & POLLIN) ) {
			// signal triggered -> pending requests
			if ( signal_clear( link->signal ) == SIGNAL_ERROR ) {
				logadd( LOG_WARNING, "Errno on signal on uplink for %s! Things will break!", link->image->name );
			}
			if ( link->fd != -1 ) {
				// Uplink seems fine, relay requests to it...
				uplink_sendRequests( link, true );
			}
		}
		// Uplink socket
		if ( (events[EV_SOCKET].revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) ) {
			link->fd = -1;
			close( events[EV_SOCKET].fd );
			events[EV_SOCKET].fd = -1;
			logadd( LOG_DEBUG1, "Uplink gone away, panic!\n" );
		} else if ( (events[EV_SOCKET].revents & POLLIN) ) {
			uplink_handleReceive( link );
			if ( link->fd == -1 ) nextAltCheck = 0;
			if ( _shutdown || link->shutdown ) goto cleanup;
		}
		// Send keep alive if nothing is happening
		const time_t now = time( NULL );
		if ( link->fd != -1 && link->replicationHandle == 0 && now > nextKeepalive ) {
			nextKeepalive = now + 20;
			if ( !uplink_sendKeepalive( link->fd ) ) {
				const int fd = link->fd;
				link->fd = -1;
				close( fd );
			}
		}
		// See if we should trigger an RTT measurement
		spin_lock( &link->rttLock );
		const int rttTestResult = link->rttTestResult;
		spin_unlock( &link->rttLock );
		if ( rttTestResult == RTT_IDLE || rttTestResult == RTT_DONTCHANGE ) {
			if ( now + SERVER_RTT_DELAY_FAILED < nextAltCheck ) {
				// This probably means the system time was changed - handle this case properly by capping the timeout
				nextAltCheck = now + SERVER_RTT_DELAY_FAILED / 2;
			} else if ( now >= nextAltCheck || link->fd == -1 || link->cycleDetected ) {
				// It seems it's time for a check
				if ( image_isComplete( link->image ) ) {
					// Quit work if image is complete
					logadd( LOG_INFO, "Replication of %s complete.", link->image->name );
					image_markComplete( link->image );
					goto cleanup;
				} else {
					// Not complete - do measurement
					altservers_findUplink( link ); // This will set RTT_INPROGRESS (synchronous)
				}
				altCheckInterval = MIN(altCheckInterval + 1, SERVER_RTT_DELAY_MAX);
				nextAltCheck = now + altCheckInterval;
			}
		} else if ( rttTestResult == RTT_NOT_REACHABLE ) {
			spin_lock( &link->rttLock );
			link->rttTestResult = RTT_IDLE;
			spin_unlock( &link->rttLock );
			discoverFailCount++;
			nextAltCheck = now + (discoverFailCount < 5 ? altCheckInterval : SERVER_RTT_DELAY_FAILED);
		}
#ifdef _DEBUG
		if ( link->fd != -1 && !link->shutdown ) {
			bool resend = false;
			const time_t deadline = now - 10;
			spin_lock( &link->queueLock );
			for (i = 0; i < link->queueLen; ++i) {
				if ( link->queue[i].status != ULR_FREE && link->queue[i].entered < deadline ) {
					snprintf( buffer, sizeof(buffer), "[DEBUG %p] Starving request slot %d detected:\n"
							"%s\n(from %" PRIu64 " to %" PRIu64 ", status: %d)\n", (void*)link, i, link->queue[i].client->image->name,
							link->queue[i].from, link->queue[i].to, link->queue[i].status );
					link->queue[i].entered = now;
#ifdef _DEBUG_RESEND_STARVING
					link->queue[i].status = ULR_NEW;
					resend = true;
#endif
					spin_unlock( &link->queueLock );
					logadd( LOG_WARNING, "%s", buffer );
					spin_lock( &link->queueLock );
				}
			}
			spin_unlock( &link->queueLock );
			if ( resend )
				uplink_sendRequests( link, true );
		}
#endif
	}
	cleanup: ;
	altservers_removeUplink( link );
	spin_lock( &link->image->lock );
	spin_lock( &link->queueLock );
	link->image->uplink = NULL;
	const int fd = link->fd;
	const dnbd3_signal_t* signal = link->signal;
	link->fd = -1;
	link->signal = NULL;
	if ( !link->shutdown ) {
		link->shutdown = true;
		thread_detach( link->thread );
	}
	spin_unlock( &link->image->lock );
	spin_unlock( &link->queueLock );
	if ( fd != -1 ) close( fd );
	if ( signal != NULL ) signal_close( signal );
	// Wait for the RTT check to finish/fail if it's in progress
	while ( link->rttTestResult == RTT_INPROGRESS )
		usleep( 10000 );
	if ( link->betterFd != -1 ) close( link->betterFd );
	spin_destroy( &link->queueLock );
	spin_destroy( &link->rttLock );
	free( link->recvBuffer );
	link->recvBuffer = NULL;
	spin_lock( &statisticsReceivedLock );
	totalBytesReceived += link->bytesReceived;
	spin_unlock( &statisticsReceivedLock );
	free( link );
	return NULL ;
}

static void uplink_sendRequests(dnbd3_connection_t *link, bool newOnly)
{
	// Scan for new requests
	int j;
	spin_lock( &link->queueLock );
	for (j = 0; j < link->queueLen; ++j) {
		if ( link->queue[j].status != ULR_NEW && (newOnly || link->queue[j].status != ULR_PENDING) ) continue;
		//logadd( LOG_DEBUG2 %p] Sending slot %d, now %d, handle %" PRIu64 ", Range: %" PRIu64 "-%" PRIu64 "\n", (void*)link, j, link->queue[j].status, link->queue[j].handle, link->queue[j].from, link->queue[j, ".to );
		link->queue[j].status = ULR_PENDING;
		const uint64_t offset = link->queue[j].from;
		const uint32_t size = link->queue[j].to - link->queue[j].from;
		uint8_t hops = link->queue[j].hopCount;
		spin_unlock( &link->queueLock );
		if ( hops < 200 ) hops += 1;
		const int ret = dnbd3_get_block( link->fd, offset, size, offset, COND_HOPCOUNT( link->version, hops ) );
		if ( !ret ) {
			// Non-critical - if the connection dropped or the server was changed
			// the thread will re-send this request as soon as the connection
			// is reestablished.
			logadd( LOG_DEBUG1, "Error forwarding request to uplink server!\n" );
			altservers_serverFailed( &link->currentServer );
			return;
		}
		spin_lock( &link->queueLock );
	}
	spin_unlock( &link->queueLock );
}

/**
 * Send a block request to an uplink server without really having
 * any client that needs that data. This will be used for background replication.
 *
 * We'll go through the cache map of the image and look for bytes that don't have
 * all bits set. We then request the corresponding 8 blocks of 4kb from the uplink
 * server. This means we might request data we already have, but it makes
 * the code simpler. Worst case would be only one bit is zero, which means
 * 4kb are missing, but we will request 32kb.
 */
static void uplink_sendReplicationRequest(dnbd3_connection_t *link)
{
	if ( !_backgroundReplication ) return; // Don't do background replication
	if ( link == NULL || link->fd == -1 ) return;
	dnbd3_image_t * const image = link->image;
	if ( image->realFilesize < DNBD3_BLOCK_SIZE ) return;
	spin_lock( &image->lock );
	if ( image == NULL || image->cache_map == NULL || link->replicationHandle != 0 ) {
		// No cache map (=image complete), or replication pending, do nothing
		spin_unlock( &image->lock );
		return;
	}
	const int len = IMGSIZE_TO_MAPBYTES( image->realFilesize ) - 1;
	// Needs to be 8 (bit->byte, bitmap)
	const uint32_t requestBlockSize = DNBD3_BLOCK_SIZE * 8;
	for ( int j = 0; j <= len; ++j ) {
		const int i = ( j + link->nextReplicationIndex ) % ( len + 1 );
		if ( image->cache_map == NULL || link->fd == -1 ) break;
		if ( image->cache_map[i] == 0xff || (i == len && link->replicatedLastBlock) ) continue;
		link->replicationHandle = 1; // Prevent race condition
		spin_unlock( &image->lock );
		// Unlocked - do not break or continue here...
		const uint64_t offset = link->replicationHandle = (uint64_t)i * (uint64_t)requestBlockSize;
		const uint32_t size = MIN( image->realFilesize - offset, requestBlockSize );
		if ( !dnbd3_get_block( link->fd, offset, size, link->replicationHandle, COND_HOPCOUNT( link->version, 1 ) ) ) {
			logadd( LOG_DEBUG1, "Error sending background replication request to uplink server!\n" );
			return;
		}
		link->nextReplicationIndex = i + 1; // Remember last incomplete offset for next time so we don't play Schlemiel the painter
		if ( i == len ) link->replicatedLastBlock = true; // Special treatment, last byte in map could represent less than 8 blocks
		return; // Request was sent, bail out, nothing is locked
	}
	spin_unlock( &image->lock );
	// Replication might be complete, uplink_mainloop should take care....
}

/**
 * Receive data from uplink server and process/dispatch
 * Locks on: link.lock, images[].lock
 */
static void uplink_handleReceive(dnbd3_connection_t *link)
{
	dnbd3_reply_t inReply, outReply;
	int ret, i;
	for (;;) {
		ret = dnbd3_read_reply( link->fd, &inReply, false );
		if ( ret == REPLY_INTR && !_shutdown && !link->shutdown ) continue;
		if ( ret == REPLY_AGAIN ) break;
		if ( ret == REPLY_CLOSED ) {
			logadd( LOG_INFO, "Uplink: Remote host hung up (%s)", link->image->path );
			goto error_cleanup;
		}
		if ( ret == REPLY_WRONGMAGIC ) {
			logadd( LOG_WARNING, "Uplink server's packet did not start with dnbd3_packet_magic (%s)", link->image->path );
			goto error_cleanup;
		}
		if ( ret != REPLY_OK ) {
			logadd( LOG_INFO, "Uplink: Connection error %d (%s)", ret, link->image->path );
			goto error_cleanup;
		}
		if ( inReply.size > 9000000 ) { // TODO: Configurable
			logadd( LOG_WARNING, "Pure evil: Uplink server sent too much payload for %s", link->image->path );
			goto error_cleanup;
		}

		if ( link->recvBufferLen < inReply.size ) {
			link->recvBufferLen = MIN(9000000, inReply.size + 65536); // XXX dont miss occurrence
			link->recvBuffer = realloc( link->recvBuffer, link->recvBufferLen );
		}
		if ( (uint32_t)sock_recv( link->fd, link->recvBuffer, inReply.size ) != inReply.size ) {
			logadd( LOG_INFO, "Lost connection to uplink server of %s (payload)", link->image->path );
			goto error_cleanup;
		}
		// Payload read completely
		// Bail out if we're not interested
		if ( inReply.cmd != CMD_GET_BLOCK ) continue;
		// Is a legit block reply
		struct iovec iov[2];
		const uint64_t start = inReply.handle;
		const uint64_t end = inReply.handle + inReply.size;
		spin_lock( &link->image->lock );
		link->bytesReceived += inReply.size;
		spin_unlock( &link->image->lock );
		// 1) Write to cache file
		if ( link->image->cacheFd != -1 ) {
			uint32_t done = 0;
			while ( done < inReply.size ) {
				ret = (int)pwrite( link->image->cacheFd, link->recvBuffer + done, inReply.size - done, start + done );
				if ( ret == -1 && errno == EINTR ) continue;
				if ( ret <= 0 ) break;
				done += (uint32_t)ret;
			}
			if ( done > 0 ) image_updateCachemap( link->image, start, start + done, true );
			if ( ret == -1 && ( errno == EBADF || errno == EINVAL || errno == EIO ) ) {
				logadd( LOG_WARNING, "Error writing received data for %s:%d; disabling caching.",
						link->image->name, (int)link->image->rid );
				const int fd = link->image->cacheFd;
				link->image->cacheFd = -1;
				close( fd );
			}
		}
		// 2) Figure out which clients are interested in it
		spin_lock( &link->queueLock );
		for (i = 0; i < link->queueLen; ++i) {
			dnbd3_queued_request_t * const req = &link->queue[i];
			assert( req->status != ULR_PROCESSING );
			if ( req->status != ULR_PENDING && req->status != ULR_NEW ) continue;
			assert( req->client != NULL );
			if ( req->from >= start && req->to <= end ) { // Match :-)
				req->status = ULR_PROCESSING;
			}
		}
		// 3) Send to interested clients - iterate backwards so request collaboration works, and
		// so we can decrease queueLen on the fly while iterating. Should you ever change this to start
		// from 0, you also need to change the "attach to existing request"-logic in uplink_request()
		outReply.magic = dnbd3_packet_magic;
		bool served = false;
		for ( i = link->queueLen - 1; i >= 0; --i ) {
			dnbd3_queued_request_t * const req = &link->queue[i];
			if ( req->status == ULR_PROCESSING ) {
				size_t bytesSent = 0;
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
				req->client = NULL;
				served = true;
				pthread_mutex_lock( &client->sendMutex );
				spin_unlock( &link->queueLock );
				if ( client->sock != -1 ) {
					ssize_t sent = writev( client->sock, iov, 2 );
					if ( sent > (ssize_t)sizeof outReply ) {
						bytesSent = (size_t)sent - sizeof outReply;
					}
				}
				spin_lock( &client->statsLock );
				pthread_mutex_unlock( &client->sendMutex );
				if ( bytesSent != 0 ) {
					client->bytesSent += bytesSent;
					client->tmpBytesSent += bytesSent;
				}
				spin_unlock( &client->statsLock );
				spin_lock( &link->queueLock );
			}
			if ( req->status == ULR_FREE && i == link->queueLen - 1 ) link->queueLen--;
		}
		spin_unlock( &link->queueLock );
#ifdef _DEBUG
		if ( !served && start != link->replicationHandle )
			logadd( LOG_DEBUG2, "%p, %s -- Unmatched reply: %" PRIu64 " to %" PRIu64, (void*)link, link->image->name, start, end );
#endif
		if ( start == link->replicationHandle ) link->replicationHandle = 0;
	}
	spin_lock( &link->queueLock );
	const bool rep = ( link->queueLen == 0 );
	spin_unlock( &link->queueLock );
	if ( rep ) uplink_sendReplicationRequest( link );
	return;
	// Error handling from failed receive or message parsing
	error_cleanup: ;
	altservers_serverFailed( &link->currentServer );
	const int fd = link->fd;
	link->fd = -1;
	link->replicationHandle = 0;
	if ( fd != -1 ) close( fd );
	altservers_findUplink( link ); // Can we just call it here?
}

/**
 * Send keep alive request to server
 */
static int uplink_sendKeepalive(const int fd)
{
	static dnbd3_request_t request = { 0 };
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
	if ( image == NULL || image->realFilesize == 0 ) return;
	size_t bytes = IMGSIZE_TO_HASHBLOCKS( image->realFilesize ) * sizeof(uint32_t);
	uint32_t masterCrc;
	uint32_t *buffer = malloc( bytes );
	if ( !dnbd3_get_crc32( uplink->fd, &masterCrc, buffer, &bytes ) || bytes == 0 ) {
		free( buffer );
		return;
	}
	uint32_t lists_crc = crc32( 0L, Z_NULL, 0 );
	lists_crc = crc32( lists_crc, (Bytef*)buffer, bytes );
	lists_crc = net_order_32( lists_crc );
	if ( lists_crc != masterCrc ) {
		logadd( LOG_WARNING, "Received corrupted crc32 list from uplink server (%s)!", uplink->image->name );
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
