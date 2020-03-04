#include "uplink.h"
#include "helper.h"
#include "locks.h"
#include "image.h"
#include "altservers.h"
#include "net.h"
#include "../shared/sockhelper.h"
#include "../shared/protocol.h"
#include "../shared/timing.h"
#include "../shared/crc32.h"
#include "reference.h"

#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <stdatomic.h>

#define FILE_BYTES_PER_MAP_BYTE ( DNBD3_BLOCK_SIZE * 8 )
#define MAP_BYTES_PER_HASH_BLOCK (int)( HASH_BLOCK_SIZE / FILE_BYTES_PER_MAP_BYTE )
#define MAP_INDEX_HASH_START_MASK ( ~(int)( MAP_BYTES_PER_HASH_BLOCK - 1 ) )

#define REP_NONE ( (uint64_t)0xffffffffffffffff )

// Status of request in queue

// Slot is free, can be used.
// Must only be set in uplink_handle_receive() or uplink_remove_client()
#define ULR_FREE 0
// Slot has been filled with a request that hasn't been sent to the upstream server yet, matching request can safely rely on reuse.
// Must only be set in uplink_request()
#define ULR_NEW 1
// Slot is occupied, reply has not yet been received, matching request can safely rely on reuse.
// Must only be set in uplink_mainloop() or uplink_request()
#define ULR_PENDING 2
// Slot is being processed, do not consider for hop on.
// Must only be set in uplink_handle_receive()
#define ULR_PROCESSING 3

static const char *const NAMES_ULR[4] = {
	[ULR_FREE] = "ULR_FREE",
	[ULR_NEW] = "ULR_NEW",
	[ULR_PENDING] = "ULR_PENDING",
	[ULR_PROCESSING] = "ULR_PROCESSING",
};

static atomic_uint_fast64_t totalBytesReceived = 0;

static void cancelAllRequests(dnbd3_uplink_t *uplink);
static void uplink_free(ref *ref);
static void* uplink_mainloop(void *data);
static void uplink_sendRequests(dnbd3_uplink_t *uplink, bool newOnly);
static int uplink_findNextIncompleteHashBlock(dnbd3_uplink_t *uplink, const int lastBlockIndex);
static void uplink_handleReceive(dnbd3_uplink_t *uplink);
static bool uplink_sendKeepalive(dnbd3_uplink_t *uplink);
static void uplink_addCrc32(dnbd3_uplink_t *uplink);
static bool uplink_sendReplicationRequest(dnbd3_uplink_t *uplink);
static bool uplink_reopenCacheFd(dnbd3_uplink_t *uplink, const bool force);
static bool uplink_connectionShouldShutdown(dnbd3_uplink_t *uplink);
static void uplink_connectionFailed(dnbd3_uplink_t *uplink, bool findNew);

// ############ uplink connection handling

void uplink_globalsInit()
{
}

uint64_t uplink_getTotalBytesReceived()
{
	return (uint64_t)totalBytesReceived;
}

/**
 * Create and initialize an uplink instance for the given
 * image. Uplinks run in their own thread.
 * Locks on: _images[].lock
 */
bool uplink_init(dnbd3_image_t *image, int sock, dnbd3_host_t *host, int version)
{
	if ( !_isProxy || _shutdown ) return false;
	assert( image != NULL );
	mutex_lock( &image->lock );
	dnbd3_uplink_t *uplink = ref_get_uplink( &image->uplinkref );
	if ( uplink != NULL ) {
		mutex_unlock( &image->lock );
		if ( sock != -1 ) {
			close( sock );
		}
		ref_put( &uplink->reference );
		return true; // There's already an uplink
	}
	if ( image->ref_cacheMap == NULL ) {
		logadd( LOG_WARNING, "Uplink was requested for image %s, but it is already complete", image->name );
		goto failure;
	}
	uplink = calloc( 1, sizeof(dnbd3_uplink_t) );
	// Start with one reference for the uplink thread. We'll return it when the thread finishes
	ref_init( &uplink->reference, uplink_free, 1 );
	mutex_init( &uplink->queueLock, LOCK_UPLINK_QUEUE );
	mutex_init( &uplink->rttLock, LOCK_UPLINK_RTT );
	mutex_init( &uplink->sendMutex, LOCK_UPLINK_SEND );
	uplink->image = image;
	uplink->bytesReceived = 0;
	uplink->bytesReceivedLastSave = 0;
	uplink->idleTime = 0;
	uplink->queueLen = 0;
	uplink->cacheFd = -1;
	uplink->signal = signal_new();
	if ( uplink->signal == NULL ) {
		logadd( LOG_WARNING, "Error creating signal. Uplink unavailable." );
		goto failure;
	}
	uplink->replicationHandle = REP_NONE;
	mutex_lock( &uplink->rttLock );
	mutex_lock( &uplink->sendMutex );
	uplink->current.fd = -1;
	mutex_unlock( &uplink->sendMutex );
	uplink->cycleDetected = false;
	image->problem.uplink = true;
	image->problem.write = true;
	image->problem.queue = false;
	if ( sock != -1 ) {
		uplink->better.fd = sock;
		int index = altservers_hostToIndex( host );
		uplink->better.index = index == -1 ? 0 : index; // Prevent invalid array access
		uplink->rttTestResult = RTT_DOCHANGE;
		uplink->better.version = version;
	} else {
		uplink->better.fd = -1;
		uplink->rttTestResult = RTT_IDLE;
	}
	mutex_unlock( &uplink->rttLock );
	uplink->recvBufferLen = 0;
	uplink->shutdown = false;
	if ( 0 != thread_create( &(uplink->thread), NULL, &uplink_mainloop, (void *)uplink ) ) {
		logadd( LOG_ERROR, "Could not start thread for new uplink." );
		goto failure;
	}
	ref_setref( &image->uplinkref, &uplink->reference );
	mutex_unlock( &image->lock );
	return true;
failure: ;
	if ( uplink != NULL ) {
		image->users++; // Expected by uplink_free()
		ref_put( &uplink->reference ); // The ref for the uplink thread that never was
	}
	mutex_unlock( &image->lock );
	return false;
}

/**
 * Locks on image.lock, uplink.lock
 * Calling it multiple times, even concurrently, will
 * not break anything.
 */
bool uplink_shutdown(dnbd3_image_t *image)
{
	assert( image != NULL );
	mutex_lock( &image->lock );
	dnbd3_uplink_t *uplink = ref_get_uplink( &image->uplinkref );
	if ( uplink == NULL ) {
		mutex_unlock( &image->lock );
		return true;
	}
	mutex_lock( &uplink->queueLock );
	bool exp = false;
	if ( atomic_compare_exchange_strong( &uplink->shutdown, &exp, true ) ) {
		image->users++; // Prevent free while uplink shuts down
		signal_call( uplink->signal );
	} else {
		logadd( LOG_ERROR, "This will never happen. '%s:%d'", image->name, (int)image->rid );
	}
	cancelAllRequests( uplink );
	ref_setref( &image->uplinkref, NULL );
	ref_put( &uplink->reference );
	mutex_unlock( &uplink->queueLock );
	bool retval = ( exp && image->users == 0 );
	mutex_unlock( &image->lock );
	return retval;
}

/**
 * Cancel all requests of this uplink.
 * HOLD QUEUE LOCK WHILE CALLING
 */
static void cancelAllRequests(dnbd3_uplink_t *uplink)
{
	for ( int i = 0; i < uplink->queueLen; ++i ) {
		if ( uplink->queue[i].status != ULR_FREE ) {
			net_sendReply( uplink->queue[i].client, CMD_ERROR, uplink->queue[i].handle );
			uplink->queue[i].status = ULR_FREE;
		}
	}
	uplink->queueLen = 0;
	uplink->image->problem.queue = false;
}

static void uplink_free(ref *ref)
{
	dnbd3_uplink_t *uplink = container_of(ref, dnbd3_uplink_t, reference);
	logadd( LOG_DEBUG1, "Freeing uplink for '%s:%d'", uplink->image->name, (int)uplink->image->rid );
	assert( uplink->queueLen == 0 );
	if ( uplink->signal != NULL ) {
		signal_close( uplink->signal );
	}
	if ( uplink->current.fd != -1 ) {
		close( uplink->current.fd );
		uplink->current.fd = -1;
	}
	if ( uplink->better.fd != -1 ) {
		close( uplink->better.fd );
		uplink->better.fd = -1;
	}
	mutex_destroy( &uplink->queueLock );
	mutex_destroy( &uplink->rttLock );
	mutex_destroy( &uplink->sendMutex );
	free( uplink->recvBuffer );
	uplink->recvBuffer = NULL;
	if ( uplink->cacheFd != -1 ) {
		close( uplink->cacheFd );
	}
	// Finally let go of image. It was acquired either in uplink_shutdown or in the cleanup code
	// of the uplink thread, depending on who set the uplink->shutdown flag. (Or uplink_init if that failed)
	image_release( uplink->image );
	free( uplink ); // !!!
}

/**
 * Remove given client from uplink request queue
 * Locks on: uplink.queueLock
 */
void uplink_removeClient(dnbd3_uplink_t *uplink, dnbd3_client_t *client)
{
	mutex_lock( &uplink->queueLock );
	for (int i = uplink->queueLen - 1; i >= 0; --i) {
		if ( uplink->queue[i].client == client ) {
			// Make sure client doesn't get destroyed while we're sending it data
			mutex_lock( &client->sendMutex );
			mutex_unlock( &client->sendMutex );
			uplink->queue[i].client = NULL;
			uplink->queue[i].status = ULR_FREE;
		}
		if ( uplink->queue[i].client == NULL && uplink->queueLen == i + 1 ) uplink->queueLen--;
	}
	mutex_unlock( &uplink->queueLock );
}

/**
 * Request a chunk of data through an uplink server
 * Locks on: image.lock, uplink.queueLock
 */
bool uplink_request(dnbd3_client_t *client, uint64_t handle, uint64_t start, uint32_t length, uint8_t hops)
{
	if ( client == NULL || client->image == NULL )
		return false;
	if ( length > (uint32_t)_maxPayload ) {
		logadd( LOG_WARNING, "Cannot relay request by client; length of %" PRIu32 " exceeds maximum payload", length );
		return false;
	}
	dnbd3_uplink_t * uplink = ref_get_uplink( &client->image->uplinkref );
	if ( unlikely( uplink == NULL ) ) {
		uplink_init( client->image, -1, NULL, -1 );
		uplink = ref_get_uplink( &client->image->uplinkref );
		if ( uplink == NULL ) {
			logadd( LOG_DEBUG1, "Uplink request for image with no uplink" );
			return false;
		}
	}
	if ( uplink->shutdown ) {
		logadd( LOG_DEBUG1, "Uplink request for image with uplink shutting down" );
		goto fail_ref;
	}
	// Check if the client is the same host as the uplink. If so assume this is a circular proxy chain
	// This might be a false positive if there are multiple instances running on the same host (IP)
	if ( hops != 0 && isSameAddress( altservers_indexToHost( uplink->current.index ), &client->host ) ) {
		uplink->cycleDetected = true;
		signal_call( uplink->signal );
		logadd( LOG_WARNING, "Proxy cycle detected (same host)." );
		goto fail_ref;
	}

	int foundExisting = -1; // Index of a pending request that is a superset of our range, -1 otherwise
	int existingType = -1; // ULR_* type of existing request
	int i;
	int freeSlot = -1;
	int firstUsedSlot = -1;
	bool requestLoop = false;
	const uint64_t end = start + length;

	mutex_lock( &uplink->queueLock );
	if ( uplink->shutdown ) { // Check again after locking to prevent lost requests
		goto fail_lock;
	}
	for (i = 0; i < uplink->queueLen; ++i) {
		// find free slot to place this request into
		if ( uplink->queue[i].status == ULR_FREE ) {
			if ( freeSlot == -1 || existingType != ULR_PROCESSING ) {
				freeSlot = i;
			}
			continue;
		}
		if ( firstUsedSlot == -1 ) {
			firstUsedSlot = i;
		}
		// find existing request to attach to
		if ( uplink->queue[i].from > start || uplink->queue[i].to < end )
			continue; // Range not suitable
		// Detect potential proxy cycle. New request hopcount is greater, range is same, old request has already been sent -> suspicious
		if ( hops > uplink->queue[i].hopCount && uplink->queue[i].from == start && uplink->queue[i].to == end && uplink->queue[i].status == ULR_PENDING ) {
			requestLoop = true;
			break;
		}
		if ( foundExisting == -1 || existingType == ULR_PROCESSING ) {
			foundExisting = i;
			existingType = uplink->queue[i].status;
		}
	}
	if ( unlikely( requestLoop ) ) {
		uplink->cycleDetected = true;
		signal_call( uplink->signal );
		logadd( LOG_WARNING, "Rejecting relay of request to upstream proxy because of possible cyclic proxy chain. Incoming hop-count is %" PRIu8 ".", hops );
		goto fail_lock;
	}
	if ( freeSlot < firstUsedSlot && firstUsedSlot < 10 && existingType != ULR_PROCESSING ) {
		freeSlot = -1; // Not attaching to existing request, make it use a higher slot
	}
	if ( freeSlot == -1 ) {
		if ( uplink->queueLen >= SERVER_MAX_UPLINK_QUEUE ) {
			logadd( LOG_WARNING, "Uplink queue is full, consider increasing SERVER_MAX_UPLINK_QUEUE. Dropping client..." );
			goto fail_lock;
		}
		freeSlot = uplink->queueLen++;
		if ( freeSlot > SERVER_UPLINK_QUEUELEN_THRES ) {
			uplink->image->problem.queue = true;
		}
	}
	// Do not send request to uplink server if we have a matching pending request AND the request either has the
	// status ULR_NEW/PENDING OR we found a free slot with LOWER index than the one we attach to. Otherwise
	// explicitly send this request to the uplink server. The second condition mentioned here is to prevent
	// a race condition where the reply for the outstanding request already arrived and the uplink thread
	// is currently traversing the request queue. As it is processing the queue from highest to lowest index, it might
	// already have passed the index of the free slot we determined, but not reached the existing request we just found above.
	if ( foundExisting != -1 && existingType == ULR_PROCESSING && freeSlot > foundExisting ) {
		foundExisting = -1; // -1 means "send request"
	}
#ifdef _DEBUG
	if ( foundExisting != -1 ) {
		logadd( LOG_DEBUG2, "%p (%s) Found existing request of type %s at slot %d, attaching in slot %d.\n", (void*)uplink, uplink->image->name, NAMES_ULR[existingType], foundExisting, freeSlot );
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
	uplink->queue[freeSlot].status = ( foundExisting == -1 ? ULR_NEW :
			( existingType == ULR_NEW ? ULR_PENDING : existingType ) );
	uplink->queue[freeSlot].hopCount = hops;
#ifdef _DEBUG
	timing_get( &uplink->queue[freeSlot].entered );
	//logadd( LOG_DEBUG2 %p] Inserting request at slot %d, was %d, now %d, handle %" PRIu64 ", Range: %" PRIu64 "-%" PRIu64 "\n", (void*)uplink, freeSlot, old, uplink->queue[freeSlot].status, uplink->queue[freeSlot, ".handle, start, end );
#endif
	mutex_unlock( &uplink->queueLock );

	if ( foundExisting != -1 ) {
		ref_put( &uplink->reference );
		return true; // Attached to pending request, do nothing
	}

	// See if we can fire away the request
	if ( unlikely( mutex_trylock( &uplink->sendMutex ) != 0 ) ) {
		logadd( LOG_DEBUG2, "Could not trylock send mutex, queueing uplink request" );
	} else {
		if ( unlikely( uplink->current.fd == -1 ) ) {
			uplink->image->problem.uplink = true;
			mutex_unlock( &uplink->sendMutex );
			logadd( LOG_DEBUG2, "Cannot do direct uplink request: No socket open" );
		} else {
			const uint64_t reqStart = uplink->queue[freeSlot].from & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
			const uint32_t reqSize = (uint32_t)(((uplink->queue[freeSlot].to + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1)) - reqStart);
			if ( hops < 200 ) ++hops;
			const bool ret = dnbd3_get_block( uplink->current.fd, reqStart, reqSize, reqStart, COND_HOPCOUNT( uplink->current.version, hops ) );
			if ( unlikely( !ret ) ) {
				uplink->image->problem.uplink = true;
				mutex_unlock( &uplink->sendMutex );
				logadd( LOG_DEBUG2, "Could not send out direct uplink request, queueing" );
			} else {
				// Direct send succeeded, update queue entry from NEW to PENDING, so the request won't be sent again
				int state;
				mutex_unlock( &uplink->sendMutex );
				mutex_lock( &uplink->queueLock );
				if ( !uplink->shutdown && uplink->queue[freeSlot].handle == handle && uplink->queue[freeSlot].client == client ) {
					state = uplink->queue[freeSlot].status;
					if ( uplink->queue[freeSlot].status == ULR_NEW ) {
						uplink->queue[freeSlot].status = ULR_PENDING;
					}
				} else {
					state = -1;
				}
				mutex_unlock( &uplink->queueLock );
				if ( state == -1 ) {
					logadd( LOG_DEBUG2, "Direct uplink request queue entry gone after sending and re-locking queue. *shrug*" );
				} else if ( state == ULR_NEW ) {
					//logadd( LOG_DEBUG2, "Direct uplink request" );
				} else {
					logadd( LOG_DEBUG2, "Direct uplink request queue entry changed to %s afte sending (expected ULR_NEW).", NAMES_ULR[uplink->queue[freeSlot].status] );
				}
				ref_put( &uplink->reference );
				return true;
			}
			// Fall through to waking up sender thread
		}
	}

	if ( signal_call( uplink->signal ) == SIGNAL_ERROR ) {
		logadd( LOG_WARNING, "Cannot wake up uplink thread; errno=%d", (int)errno );
	}
	ref_put( &uplink->reference );
	return true;
fail_lock:
	mutex_unlock( &uplink->queueLock );
fail_ref:
	ref_put( &uplink->reference );
	return false;
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
	dnbd3_uplink_t * const uplink = (dnbd3_uplink_t*)data;
	int numSocks, i, waitTime;
	int altCheckInterval = SERVER_RTT_INTERVAL_INIT;
	int rttTestResult;
	uint32_t discoverFailCount = 0;
	ticks nextAltCheck, lastKeepalive;
	char buffer[200];
	memset( events, 0, sizeof(events) );
	timing_get( &nextAltCheck );
	lastKeepalive = nextAltCheck;
	//
	assert( uplink != NULL );
	setThreadName( "idle-uplink" );
	thread_detach( uplink->thread );
	blockNoncriticalSignals();
	// Make sure file is open for writing
	if ( !uplink_reopenCacheFd( uplink, false ) ) {
		// It might have failed - still offer proxy mode, we just can't cache
		logadd( LOG_WARNING, "Cannot open cache file %s for writing (errno=%d); will just proxy traffic without caching!", uplink->image->path, errno );
	}
	//
	events[EV_SIGNAL].events = POLLIN;
	events[EV_SIGNAL].fd = signal_getWaitFd( uplink->signal );
	events[EV_SOCKET].fd = -1;
	if ( uplink->rttTestResult != RTT_DOCHANGE ) {
		altservers_findUplink( uplink ); // In case we didn't kickstart
	}
	while ( !_shutdown && !uplink->shutdown ) {
		// poll()
		if ( uplink->rttTestResult == RTT_DOCHANGE ) {
			// 0 means poll, since we're about to change the server
			waitTime = 0;
		} else {
			declare_now;
			waitTime = (int)timing_diffMs( &now, &nextAltCheck );
			if ( waitTime < 100 ) waitTime = 100;
			if ( waitTime > 10000 ) waitTime = 10000;
		}
		events[EV_SOCKET].fd = uplink->current.fd;
		numSocks = poll( events, EV_COUNT, waitTime );
		if ( _shutdown || uplink->shutdown ) goto cleanup;
		if ( numSocks == -1 ) { // Error?
			if ( errno == EINTR ) continue;
			logadd( LOG_DEBUG1, "poll() error %d", (int)errno );
			usleep( 10000 );
			continue;
		}
		// Check if server switch is in order
		if ( unlikely( uplink->rttTestResult == RTT_DOCHANGE ) ) {
			mutex_lock( &uplink->rttLock );
			assert( uplink->rttTestResult == RTT_DOCHANGE );
			uplink->rttTestResult = RTT_IDLE;
			// The rttTest worker thread has finished our request.
			// And says it's better to switch to another server
			const int fd = uplink->current.fd;
			mutex_lock( &uplink->sendMutex );
			uplink->current = uplink->better;
			mutex_unlock( &uplink->sendMutex );
			uplink->better.fd = -1;
			uplink->cycleDetected = false;
			mutex_unlock( &uplink->rttLock );
			discoverFailCount = 0;
			if ( fd != -1 ) close( fd );
			uplink->replicationHandle = REP_NONE;
			uplink->image->problem.uplink = false;
			uplink->replicatedLastBlock = false; // Reset this to be safe - request could've been sent but reply was never received
			buffer[0] = '@';
			if ( altservers_toString( uplink->current.index, buffer + 1, sizeof(buffer) - 1 ) ) {
				logadd( LOG_DEBUG1, "(Uplink %s) Now connected to %s\n", uplink->image->name, buffer + 1 );
				setThreadName( buffer );
			}
			// If we don't have a crc32 list yet, see if the new server has one
			if ( uplink->image->crc32 == NULL ) {
				uplink_addCrc32( uplink );
			}
			// Re-send all pending requests
			uplink_sendRequests( uplink, false );
			uplink_sendReplicationRequest( uplink );
			events[EV_SOCKET].events = POLLIN | POLLRDHUP;
			if ( uplink->image->problem.uplink ) {
				// Some of the requests above must have failed again already :-(
				logadd( LOG_DEBUG1, "Newly established uplink connection failed during getCRC or sendRequests" );
				uplink_connectionFailed( uplink, true );
			}
			timing_gets( &nextAltCheck, altCheckInterval );
			// The rtt worker already did the handshake for our image, so there's nothing
			// more to do here
		}
		// Check events
		// Signal
		if ( (events[EV_SIGNAL].revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) ) {
			uplink->image->problem.uplink = true;
			logadd( LOG_WARNING, "poll error on signal in uplink_mainloop!" );
			goto cleanup;
		} else if ( (events[EV_SIGNAL].revents & POLLIN) ) {
			// signal triggered -> pending requests
			if ( signal_clear( uplink->signal ) == SIGNAL_ERROR ) {
				logadd( LOG_WARNING, "Errno on signal on uplink for %s! Things will break!", uplink->image->name );
			}
			if ( uplink->current.fd != -1 ) {
				// Uplink seems fine, relay requests to it...
				uplink_sendRequests( uplink, true );
			} else if ( uplink->queueLen != 0 ) { // No uplink; maybe it was shutdown since it was idle for too long
				uplink->idleTime = 0;
			}
		}
		// Uplink socket
		if ( (events[EV_SOCKET].revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) ) {
			uplink_connectionFailed( uplink, true );
			logadd( LOG_DEBUG1, "Uplink gone away, panic! (revents=%d)\n", (int)events[EV_SOCKET].revents );
			setThreadName( "panic-uplink" );
		} else if ( (events[EV_SOCKET].revents & POLLIN) ) {
			uplink_handleReceive( uplink );
			if ( _shutdown || uplink->shutdown ) goto cleanup;
		}
		declare_now;
		uint32_t timepassed = timing_diff( &lastKeepalive, &now );
		if ( timepassed >= SERVER_UPLINK_KEEPALIVE_INTERVAL ) {
			lastKeepalive = now;
			uplink->idleTime += timepassed;
			// Keep-alive
			if ( uplink->current.fd != -1 && uplink->replicationHandle == REP_NONE ) {
				// Send keep-alive if nothing is happening, and try to trigger background rep.
				if ( !uplink_sendKeepalive( uplink ) || !uplink_sendReplicationRequest( uplink ) ) {
					uplink_connectionFailed( uplink, true );
					logadd( LOG_DEBUG1, "Error sending keep-alive/BGR, panic!\n" );
				}
			}
			// Don't keep uplink established if we're idle for too much
			if ( uplink_connectionShouldShutdown( uplink ) ) {
				logadd( LOG_DEBUG1, "Closing idle uplink for image %s:%d", uplink->image->name, (int)uplink->image->rid );
				goto cleanup;
			}
		}
		// See if we should trigger an RTT measurement
		rttTestResult = uplink->rttTestResult;
		if ( rttTestResult == RTT_IDLE || rttTestResult == RTT_DONTCHANGE ) {
			if ( timing_reached( &nextAltCheck, &now ) || ( uplink->current.fd == -1 && discoverFailCount == 0 ) || uplink->cycleDetected ) {
				// It seems it's time for a check
				if ( image_isComplete( uplink->image ) ) {
					// Quit work if image is complete
					logadd( LOG_INFO, "Replication of %s complete.", uplink->image->name );
					setThreadName( "finished-uplink" );
					uplink->image->problem.uplink = false;
					goto cleanup;
				} else {
					// Not complete - do measurement
					altservers_findUplinkAsync( uplink ); // This will set RTT_INPROGRESS (synchronous)
					if ( _backgroundReplication == BGR_FULL && uplink->nextReplicationIndex == -1 ) {
						uplink->nextReplicationIndex = 0;
					}
				}
				altCheckInterval = MIN(altCheckInterval + 1, SERVER_RTT_INTERVAL_MAX);
				timing_set( &nextAltCheck, &now, altCheckInterval );
			}
		} else if ( rttTestResult == RTT_NOT_REACHABLE ) {
			if ( atomic_compare_exchange_strong( &uplink->rttTestResult, &rttTestResult, RTT_IDLE ) ) {
				discoverFailCount++;
				if ( uplink->current.fd == -1 ) {
					uplink->cycleDetected = false;
				}
			}
			timing_set( &nextAltCheck, &now, (discoverFailCount < SERVER_RTT_MAX_UNREACH) ? altCheckInterval : SERVER_RTT_INTERVAL_FAILED );
		}
#ifdef _DEBUG
		if ( uplink->current.fd != -1 && !uplink->shutdown ) {
			bool resend = false;
			ticks deadline;
			timing_set( &deadline, &now, -10 );
			mutex_lock( &uplink->queueLock );
			for (i = 0; i < uplink->queueLen; ++i) {
				if ( uplink->queue[i].status != ULR_FREE && timing_reached( &uplink->queue[i].entered, &deadline ) ) {
					snprintf( buffer, sizeof(buffer), "[DEBUG %p] Starving request slot %d detected:\n"
							"%s\n(from %" PRIu64 " to %" PRIu64 ", status: %d)\n", (void*)uplink, i, uplink->queue[i].client->image->name,
							uplink->queue[i].from, uplink->queue[i].to, uplink->queue[i].status );
					uplink->queue[i].entered = now;
#ifdef _DEBUG_RESEND_STARVING
					uplink->queue[i].status = ULR_NEW;
					resend = true;
#endif
					mutex_unlock( &uplink->queueLock );
					logadd( LOG_WARNING, "%s", buffer );
					mutex_lock( &uplink->queueLock );
				}
			}
			mutex_unlock( &uplink->queueLock );
			if ( resend ) {
				uplink_sendRequests( uplink, true );
			}
		}
#endif
	}
cleanup: ;
	dnbd3_image_t *image = uplink->image;
	image->mapDirty = true; // Force writeout of cache map
	mutex_lock( &image->lock );
	bool exp = false;
	if ( atomic_compare_exchange_strong( &uplink->shutdown, &exp, true ) ) {
		image->users++; // We set the flag - hold onto image
	}
	dnbd3_uplink_t *current = ref_get_uplink( &image->uplinkref );
	if ( current == uplink ) { // Set NULL if it's still us...
		mutex_lock( &uplink->queueLock );
		cancelAllRequests( uplink );
		mutex_unlock( &uplink->queueLock );
		ref_setref( &image->uplinkref, NULL );
	}
	if ( current != NULL ) { // Decrease ref in any case
		ref_put( &current->reference );
	}
	mutex_unlock( &image->lock );
	// Finally as the thread is done, decrease our own ref that we initialized with
	ref_put( &uplink->reference );
	return NULL ;
}

/**
 * Only called from uplink thread.
 */
static void uplink_sendRequests(dnbd3_uplink_t *uplink, bool newOnly)
{
	// Scan for new requests
	int j;
	mutex_lock( &uplink->queueLock );
	for (j = 0; j < uplink->queueLen; ++j) {
		if ( uplink->queue[j].status != ULR_NEW && (newOnly || uplink->queue[j].status != ULR_PENDING) ) continue;
		uplink->queue[j].status = ULR_PENDING;
		uint8_t hops = uplink->queue[j].hopCount;
		const uint64_t reqStart = uplink->queue[j].from & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
		const uint32_t reqSize = (uint32_t)(((uplink->queue[j].to + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1)) - reqStart);
		/*
		logadd( LOG_DEBUG2, "[%p] Sending slot %d, now %d, handle %" PRIu64 ", Range: %" PRIu64 "-%" PRIu64 " (%" PRIu64 "-%" PRIu64 ")",
				(void*)uplink, j, uplink->queue[j].status, uplink->queue[j].handle, uplink->queue[j].from, uplink->queue[j].to, reqStart, reqStart+reqSize );
		*/
		mutex_unlock( &uplink->queueLock );
		if ( hops < 200 ) ++hops;
		mutex_lock( &uplink->sendMutex );
		const bool ret = dnbd3_get_block( uplink->current.fd, reqStart, reqSize, reqStart, COND_HOPCOUNT( uplink->current.version, hops ) );
		if ( likely( ret ) ) {
			mutex_unlock( &uplink->sendMutex );
		} else {
			// Non-critical - if the connection dropped or the server was changed
			// the thread will re-send this request as soon as the connection
			// is reestablished.
			uplink->image->problem.uplink = true;
			mutex_unlock( &uplink->sendMutex );
			logadd( LOG_DEBUG1, "Error forwarding request to uplink server!\n" );
			return;
		}
		mutex_lock( &uplink->queueLock );
	}
	mutex_unlock( &uplink->queueLock );
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
 *
 * Only called form uplink thread, so current.fd is assumed to be valid.
 *
 * @return false if sending request failed, true otherwise (i.e. not necessary/disabled)
 */
static bool uplink_sendReplicationRequest(dnbd3_uplink_t *uplink)
{
	if ( uplink->current.fd == -1 )
		return false; // Should never be called in this state, consider send error
	if ( _backgroundReplication == BGR_DISABLED || uplink->cacheFd == -1 )
		return true; // Don't do background replication
	if ( uplink->nextReplicationIndex == -1 || uplink->replicationHandle != REP_NONE )
		return true; // Already a replication request on the wire, or no more blocks to replicate
	dnbd3_image_t * const image = uplink->image;
	if ( image->users < _bgrMinClients )
		return true; // Not enough active users
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	if ( cache == NULL || image->users ) {
		// No cache map (=image complete)
		ref_put( &cache->reference );
		return true;
	}
	const int mapBytes = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
	const int lastBlockIndex = mapBytes - 1;
	int endByte;
	if ( _backgroundReplication == BGR_FULL ) { // Full mode: consider all blocks
		endByte = uplink->nextReplicationIndex + mapBytes;
	} else { // Hashblock based: Only look for match in current hash block
		endByte = ( uplink->nextReplicationIndex + MAP_BYTES_PER_HASH_BLOCK ) & MAP_INDEX_HASH_START_MASK;
		if ( endByte > mapBytes ) {
			endByte = mapBytes;
		}
	}
	atomic_thread_fence( memory_order_acquire );
	int replicationIndex = -1;
	for ( int j = uplink->nextReplicationIndex; j < endByte; ++j ) {
		const int i = j % ( mapBytes ); // Wrap around for BGR_FULL
		if ( atomic_load_explicit( &cache->map[i], memory_order_relaxed ) != 0xff
				&& ( i != lastBlockIndex || !uplink->replicatedLastBlock ) ) {
			// Found incomplete one
			replicationIndex = i;
			break;
		}
	}
	ref_put( &cache->reference );
	if ( replicationIndex == -1 && _backgroundReplication == BGR_HASHBLOCK ) {
		// Nothing left in current block, find next one
		replicationIndex = uplink_findNextIncompleteHashBlock( uplink, endByte );
	}
	if ( replicationIndex == -1 ) {
		// Replication might be complete, uplink_mainloop should take care....
		uplink->nextReplicationIndex = -1;
		return true;
	}
	const uint64_t offset = (uint64_t)replicationIndex * FILE_BYTES_PER_MAP_BYTE;
	uplink->replicationHandle = offset;
	const uint32_t size = (uint32_t)MIN( image->virtualFilesize - offset, FILE_BYTES_PER_MAP_BYTE );
	mutex_lock( &uplink->sendMutex );
	bool sendOk = dnbd3_get_block( uplink->current.fd, offset, size, uplink->replicationHandle, COND_HOPCOUNT( uplink->current.version, 1 ) );
	if ( likely( sendOk ) ) {
		mutex_unlock( &uplink->sendMutex );
	} else {
		uplink->image->problem.uplink = true;
		mutex_unlock( &uplink->sendMutex );
		logadd( LOG_DEBUG1, "Error sending background replication request to uplink server!\n" );
		return false;
	}
	if ( replicationIndex == lastBlockIndex ) {
		uplink->replicatedLastBlock = true; // Special treatment, last byte in map could represent less than 8 blocks
	}
	uplink->nextReplicationIndex = replicationIndex + 1; // Remember last incomplete offset for next time so we don't play Schlemiel the painter
	if ( _backgroundReplication == BGR_HASHBLOCK
			&& uplink->nextReplicationIndex % MAP_BYTES_PER_HASH_BLOCK == 0 ) {
		// Just crossed a hash block boundary, look for new candidate starting at this very index
		uplink->nextReplicationIndex = uplink_findNextIncompleteHashBlock( uplink, uplink->nextReplicationIndex );
	}
	return true;
}

/**
 * find next index into cache map that corresponds to the beginning
 * of a hash block which is neither completely empty nor completely
 * replicated yet. Returns -1 if no match.
 */
static int uplink_findNextIncompleteHashBlock(dnbd3_uplink_t *uplink, const int startMapIndex)
{
	int retval = -1;
	dnbd3_cache_map_t *cache = ref_get_cachemap( uplink->image );
	if ( cache != NULL ) {
		const int mapBytes = IMGSIZE_TO_MAPBYTES( uplink->image->virtualFilesize );
		const int start = ( startMapIndex & MAP_INDEX_HASH_START_MASK );
		atomic_thread_fence( memory_order_acquire );
		int j;
		for (j = 0; j < mapBytes; ++j) {
			const int i = ( start + j ) % mapBytes;
			const uint8_t b = atomic_load_explicit( &cache->map[i], memory_order_relaxed );
			const bool isFull = b == 0xff || ( i + 1 == mapBytes && uplink->replicatedLastBlock );
			const bool isEmpty = b == 0;
			if ( !isEmpty && !isFull ) {
				// Neither full nor empty, replicate
				if ( retval == -1 ) {
					retval = i;
				}
				break;
			}
			if ( ( i & MAP_INDEX_HASH_START_MASK ) == i ) {
				// Reset state if we just crossed into the next hash chunk
				retval = ( isEmpty ) ? ( i ) : ( -1 );
			} else if ( isFull ) {
				if ( retval != -1 ) {
					// It's a full one, previous one was empty -> replicate
					break;
				}
			} else if ( isEmpty ) {
				if ( retval == -1 ) { // Previous one was full -> replicate
					retval = i;
					break;
				}
			}
		}
		if ( j == mapBytes ) { // Nothing found, loop ran until end
			retval = -1;
		}
	}
	ref_put( &cache->reference );
	return retval;
}

/**
 * Receive data from uplink server and process/dispatch
 * Locks on: uplink.lock, images[].lock
 * Only called from uplink thread, so current.fd is assumed to be valid.
 */
static void uplink_handleReceive(dnbd3_uplink_t *uplink)
{
	dnbd3_reply_t inReply, outReply;
	int ret, i;
	for (;;) {
		ret = dnbd3_read_reply( uplink->current.fd, &inReply, false );
		if ( unlikely( ret == REPLY_INTR ) && likely( !_shutdown && !uplink->shutdown ) ) continue;
		if ( ret == REPLY_AGAIN ) break;
		if ( unlikely( ret == REPLY_CLOSED ) ) {
			logadd( LOG_INFO, "Uplink: Remote host hung up (%s)", uplink->image->path );
			goto error_cleanup;
		}
		if ( unlikely( ret == REPLY_WRONGMAGIC ) ) {
			logadd( LOG_WARNING, "Uplink server's packet did not start with dnbd3_packet_magic (%s)", uplink->image->path );
			goto error_cleanup;
		}
		if ( unlikely( ret != REPLY_OK ) ) {
			logadd( LOG_INFO, "Uplink: Connection error %d (%s)", ret, uplink->image->path );
			goto error_cleanup;
		}
		if ( unlikely( inReply.size > (uint32_t)_maxPayload ) ) {
			logadd( LOG_WARNING, "Pure evil: Uplink server sent too much payload (%" PRIu32 ") for %s", inReply.size, uplink->image->path );
			goto error_cleanup;
		}

		if ( unlikely( uplink->recvBufferLen < inReply.size ) ) {
			uplink->recvBufferLen = MIN((uint32_t)_maxPayload, inReply.size + 65536);
			uplink->recvBuffer = realloc( uplink->recvBuffer, uplink->recvBufferLen );
			if ( uplink->recvBuffer == NULL ) {
				logadd( LOG_ERROR, "Out of memory when trying to allocate receive buffer for uplink" );
				exit( 1 );
			}
		}
		if ( unlikely( (uint32_t)sock_recv( uplink->current.fd, uplink->recvBuffer, inReply.size ) != inReply.size ) ) {
			logadd( LOG_INFO, "Lost connection to uplink server of %s (payload)", uplink->image->path );
			goto error_cleanup;
		}
		// Payload read completely
		// Bail out if we're not interested
		if ( unlikely( inReply.cmd != CMD_GET_BLOCK ) ) continue;
		// Is a legit block reply
		struct iovec iov[2];
		const uint64_t start = inReply.handle;
		const uint64_t end = inReply.handle + inReply.size;
		totalBytesReceived += inReply.size;
		uplink->bytesReceived += inReply.size;
		// 1) Write to cache file
		if ( unlikely( uplink->cacheFd == -1 ) ) {
			uplink_reopenCacheFd( uplink, false );
		}
		if ( likely( uplink->cacheFd != -1 ) ) {
			int err = 0;
			bool tryAgain = true; // Allow one retry in case we run out of space or the write fd became invalid
			uint32_t done = 0;
			ret = 0;
			while ( done < inReply.size ) {
				ret = (int)pwrite( uplink->cacheFd, uplink->recvBuffer + done, inReply.size - done, start + done );
				if ( unlikely( ret == -1 ) ) {
					err = errno;
					if ( err == EINTR && !_shutdown ) continue;
					if ( err == ENOSPC || err == EDQUOT ) {
						// try to free 256MiB
						if ( !tryAgain || !image_ensureDiskSpaceLocked( 256ull * 1024 * 1024, true ) ) break;
						tryAgain = false;
						continue; // Success, retry write
					}
					if ( err == EBADF || err == EINVAL || err == EIO ) {
						uplink->image->problem.write = true;
						if ( !tryAgain || !uplink_reopenCacheFd( uplink, true ) )
							break;
						tryAgain = false;
						continue; // Write handle to image successfully re-opened, try again
					}
					logadd( LOG_DEBUG1, "Error trying to cache data for %s:%d -- errno=%d", uplink->image->name, (int)uplink->image->rid, err );
					break;
				}
				if ( unlikely( ret <= 0 || (uint32_t)ret > inReply.size - done ) ) {
					logadd( LOG_WARNING, "Unexpected return value %d from pwrite to %s:%d", ret, uplink->image->name, (int)uplink->image->rid );
					break;
				}
				done += (uint32_t)ret;
			}
			if ( likely( done > 0 ) ) {
				image_updateCachemap( uplink->image, start, start + done, true );
			}
			if ( unlikely( ret == -1 && ( err == EBADF || err == EINVAL || err == EIO ) ) ) {
				logadd( LOG_WARNING, "Error writing received data for %s:%d (errno=%d); disabling caching.",
						uplink->image->name, (int)uplink->image->rid, err );
			}
		}
		// 2) Figure out which clients are interested in it
		// Mark as ULR_PROCESSING, since we unlock repeatedly in the second loop
		// below; this prevents uplink_request() from attaching to this request
		// by populating a slot with index greater than the highest matching
		// request with ULR_PROCESSING (assuming there is no ULR_PENDING or ULR_NEW
		// where it's fine if the index is greater)
		mutex_lock( &uplink->queueLock );
		for (i = 0; i < uplink->queueLen; ++i) {
			dnbd3_queued_request_t * const req = &uplink->queue[i];
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
		for ( i = uplink->queueLen - 1; i >= 0; --i ) {
			dnbd3_queued_request_t * const req = &uplink->queue[i];
			if ( req->status == ULR_PROCESSING ) {
				size_t bytesSent = 0;
				assert( req->from >= start && req->to <= end );
				dnbd3_client_t * const client = req->client;
				outReply.cmd = CMD_GET_BLOCK;
				outReply.handle = req->handle;
				outReply.size = (uint32_t)( req->to - req->from );
				iov[0].iov_base = &outReply;
				iov[0].iov_len = sizeof outReply;
				iov[1].iov_base = uplink->recvBuffer + (req->from - start);
				iov[1].iov_len = outReply.size;
				fixup_reply( outReply );
				req->status = ULR_FREE;
				req->client = NULL;
				served = true;
				mutex_lock( &client->sendMutex );
				mutex_unlock( &uplink->queueLock );
				if ( client->sock != -1 ) {
					ssize_t sent = writev( client->sock, iov, 2 );
					if ( sent > (ssize_t)sizeof outReply ) {
						bytesSent = (size_t)sent - sizeof outReply;
					}
				}
				if ( bytesSent != 0 ) {
					client->bytesSent += bytesSent;
				}
				mutex_unlock( &client->sendMutex );
				mutex_lock( &uplink->queueLock );
				if ( i > uplink->queueLen ) {
					i = uplink->queueLen; // Might have been set to 0 by cancelAllRequests
				}
			}
			if ( req->status == ULR_FREE && i == uplink->queueLen - 1 ) uplink->queueLen--;
		}
		if ( uplink->queueLen < SERVER_UPLINK_QUEUELEN_THRES ) {
			uplink->image->problem.queue = false;
		}
		mutex_unlock( &uplink->queueLock );
#ifdef _DEBUG
		if ( !served && start != uplink->replicationHandle ) {
			logadd( LOG_DEBUG2, "%p, %s -- Unmatched reply: %" PRIu64 " to %" PRIu64, (void*)uplink, uplink->image->name, start, end );
		}
#endif
		if ( start == uplink->replicationHandle ) {
			// Was our background replication
			uplink->replicationHandle = REP_NONE;
			// Try to remove from fs cache if no client was interested in this data
			if ( !served && uplink->cacheFd != -1 ) {
				posix_fadvise( uplink->cacheFd, start, inReply.size, POSIX_FADV_DONTNEED );
			}
		}
		if ( served ) {
			// Was some client -- reset idle counter
			uplink->idleTime = 0;
			// Re-enable replication if disabled
			if ( uplink->nextReplicationIndex == -1 ) {
				uplink->nextReplicationIndex = (int)( start / FILE_BYTES_PER_MAP_BYTE ) & MAP_INDEX_HASH_START_MASK;
			}
		}
	}
	if ( uplink->replicationHandle == REP_NONE ) {
		mutex_lock( &uplink->queueLock );
		const bool rep = ( uplink->queueLen == 0 );
		mutex_unlock( &uplink->queueLock );
		if ( rep ) {
			if ( !uplink_sendReplicationRequest( uplink ) )
				goto error_cleanup;
		}
	}
	return;
	// Error handling from failed receive or message parsing
error_cleanup: ;
	uplink_connectionFailed( uplink, true );
}

/**
 * Only call from uplink thread
 */
static void uplink_connectionFailed(dnbd3_uplink_t *uplink, bool findNew)
{
	if ( uplink->current.fd == -1 )
		return;
	setThreadName( "panic-uplink" );
	altservers_serverFailed( uplink->current.index );
	mutex_lock( &uplink->sendMutex );
	uplink->image->problem.uplink = true;
	close( uplink->current.fd );
	uplink->current.fd = -1;
	mutex_unlock( &uplink->sendMutex );
	uplink->replicationHandle = REP_NONE;
	if ( _backgroundReplication == BGR_FULL && uplink->nextReplicationIndex == -1 ) {
		uplink->nextReplicationIndex = 0;
	}
	if ( !findNew )
		return;
	mutex_lock( &uplink->rttLock );
	bool bail = uplink->rttTestResult == RTT_INPROGRESS || uplink->better.fd != -1;
	mutex_unlock( &uplink->rttLock );
	if ( bail )
		return;
	altservers_findUplinkAsync( uplink );
}

/**
 * Send keep alive request to server.
 * Called from uplink thread, current.fd must be valid.
 */
static bool uplink_sendKeepalive(dnbd3_uplink_t *uplink)
{
	static const dnbd3_request_t request = { .magic = dnbd3_packet_magic, .cmd = net_order_16( CMD_KEEPALIVE ) };
	mutex_lock( &uplink->sendMutex );
	bool sendOk = send( uplink->current.fd, &request, sizeof(request), MSG_NOSIGNAL ) == sizeof(request);
	mutex_unlock( &uplink->sendMutex );
	return sendOk;
}

/**
 * Request crclist from uplink.
 * Called from uplink thread, current.fd must be valid.
 * FIXME This is broken as it could happen that another message arrives after sending
 * the request. Refactor, split and move receive into general receive handler.
 */
static void uplink_addCrc32(dnbd3_uplink_t *uplink)
{
	dnbd3_image_t *image = uplink->image;
	if ( image == NULL || image->virtualFilesize == 0 ) return;
	size_t bytes = IMGSIZE_TO_HASHBLOCKS( image->virtualFilesize ) * sizeof(uint32_t);
	uint32_t masterCrc;
	uint32_t *buffer = malloc( bytes );
	mutex_lock( &uplink->sendMutex );
	bool sendOk = dnbd3_get_crc32( uplink->current.fd, &masterCrc, buffer, &bytes );
	if ( !sendOk ) {
		uplink->image->problem.uplink = true;
	}
	mutex_unlock( &uplink->sendMutex );
	if ( !sendOk || bytes == 0 ) {
		free( buffer );
		return;
	}
	uint32_t lists_crc = crc32( 0, NULL, 0 );
	lists_crc = crc32( lists_crc, (uint8_t*)buffer, bytes );
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
	const int fd = open( path, O_WRONLY | O_CREAT, 0644 );
	if ( fd >= 0 ) {
		write( fd, &masterCrc, sizeof(uint32_t) );
		write( fd, buffer, bytes );
		close( fd );
	}
}

/**
 * Open the given image's main image file in
 * rw mode, assigning it to the cacheFd struct member.
 *
 * @param force If cacheFd was previously assigned a file descriptor (not == -1),
 * it will be closed first. Otherwise, nothing will happen and true will be returned
 * immediately.
 */
static bool uplink_reopenCacheFd(dnbd3_uplink_t *uplink, const bool force)
{
	if ( uplink->cacheFd != -1 ) {
		if ( !force ) return true;
		close( uplink->cacheFd );
	}
	uplink->cacheFd = open( uplink->image->path, O_WRONLY | O_CREAT, 0644 );
	uplink->image->problem.write = uplink->cacheFd == -1;
	return uplink->cacheFd != -1;
}

static bool uplink_connectionShouldShutdown(dnbd3_uplink_t *uplink)
{
	return ( uplink->idleTime > SERVER_UPLINK_IDLE_TIMEOUT
			&& ( _backgroundReplication != BGR_FULL || _bgrMinClients > uplink->image->users ) );
}

bool uplink_getHostString(dnbd3_uplink_t *uplink, char *buffer, size_t len)
{
	int current;
	mutex_lock( &uplink->rttLock );
	current = uplink->current.fd == -1 ? -1 : uplink->current.index;
	mutex_unlock( &uplink->rttLock );
	if ( current == -1 )
		return false;
	return altservers_toString( current, buffer, len );
}
