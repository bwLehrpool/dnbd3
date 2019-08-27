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
static int uplink_sendKeepalive(const int fd);
static void uplink_addCrc32(dnbd3_uplink_t *uplink);
static void uplink_sendReplicationRequest(dnbd3_uplink_t *uplink);
static bool uplink_reopenCacheFd(dnbd3_uplink_t *uplink, const bool force);
static bool uplink_saveCacheMap(dnbd3_uplink_t *uplink);
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
		return true; // There's already an uplink, so should we consider this success or failure?
	}
	if ( image->cache_map == NULL ) {
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
	uplink->idleTime = 0;
	uplink->queueLen = 0;
	uplink->cacheFd = -1;
	uplink->signal = NULL;
	uplink->replicationHandle = REP_NONE;
	mutex_lock( &uplink->rttLock );
	mutex_lock( &uplink->sendMutex );
	uplink->current.fd = -1;
	mutex_unlock( &uplink->sendMutex );
	uplink->cycleDetected = false;
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
		free( uplink );
		uplink = NULL;
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
	return exp;
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
}

static void uplink_free(ref *ref)
{
	dnbd3_uplink_t *uplink = container_of(ref, dnbd3_uplink_t, reference);
	logadd( LOG_DEBUG1, "Freeing uplink for '%s:%d'", uplink->image->name, (int)uplink->image->rid );
	assert( uplink->queueLen == 0 );
	signal_close( uplink->signal );
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
	// TODO Requeue any requests
	dnbd3_image_t *image = image_lock( uplink->image );
	if ( image != NULL ) {
		// != NULL means image is still in list...
		if ( !_shutdown && image->cache_map != NULL ) {
			// Ingegrity checker must have found something in the meantime
			uplink_init( image, -1, NULL, 0 );
		}
		image_release( image );
	}
	// Finally let go of image. It was acquired either in uplink_shutdown or in the cleanup code
	// of the uplink thread, depending on who set the uplink->shutdown flag.
	image_release( image );
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
	dnbd3_uplink_t * const uplink = ref_get_uplink( &client->image->uplinkref );
	if ( uplink == NULL ) {
		logadd( LOG_DEBUG1, "Uplink request for image with no uplink" );
		return false;
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
			mutex_unlock( &uplink->sendMutex );
			logadd( LOG_DEBUG2, "Cannot do direct uplink request: No socket open" );
		} else {
			const uint64_t reqStart = uplink->queue[freeSlot].from & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
			const uint32_t reqSize = (uint32_t)(((uplink->queue[freeSlot].to + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1)) - reqStart);
			if ( hops < 200 ) ++hops;
			const bool ret = dnbd3_get_block( uplink->current.fd, reqStart, reqSize, reqStart, COND_HOPCOUNT( uplink->current.version, hops ) );
			mutex_unlock( &uplink->sendMutex );
			if ( unlikely( !ret ) ) {
				logadd( LOG_DEBUG2, "Could not send out direct uplink request, queueing" );
			} else {
				// Direct send succeeded, update queue entry from NEW to PENDING, so the request won't be sent again
				int state;
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
	uint32_t unsavedSeconds = 0;
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
	uplink->signal = signal_new();
	if ( uplink->signal == NULL ) {
		logadd( LOG_WARNING, "error creating signal. Uplink unavailable." );
		goto cleanup;
	}
	events[EV_SIGNAL].events = POLLIN;
	events[EV_SIGNAL].fd = signal_getWaitFd( uplink->signal );
	events[EV_SOCKET].fd = -1;
	while ( !_shutdown && !uplink->shutdown ) {
		// poll()
		waitTime = uplink->rttTestResult == RTT_DOCHANGE ? 0 : -1;
		if ( waitTime == 0 ) {
			// 0 means poll, since we're about to change the server
		} else if ( uplink->current.fd == -1 && !uplink_connectionShouldShutdown( uplink ) ) {
			waitTime = 1000;
		} else {
			declare_now;
			waitTime = (int)timing_diffMs( &now, &nextAltCheck );
			if ( waitTime < 100 ) waitTime = 100;
			if ( waitTime > 5000 ) waitTime = 5000;
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
			uplink->image->working = true;
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
			timing_gets( &nextAltCheck, altCheckInterval );
			// The rtt worker already did the handshake for our image, so there's nothing
			// more to do here
		}
		// Check events
		// Signal
		if ( (events[EV_SIGNAL].revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) ) {
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
			} else { // No uplink; maybe it was shutdown since it was idle for too long
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
			unsavedSeconds += timepassed;
			if ( unsavedSeconds > 240 || ( unsavedSeconds > 60 && uplink->idleTime >= 20 && uplink->idleTime <= 70 ) ) {
				// fsync/save every 4 minutes, or every 60 seconds if uplink is idle
				unsavedSeconds = 0;
				uplink_saveCacheMap( uplink );
			}
			// Keep-alive
			if ( uplink->current.fd != -1 && uplink->replicationHandle == REP_NONE ) {
				// Send keep-alive if nothing is happening
				if ( uplink_sendKeepalive( uplink->current.fd ) ) {
					// Re-trigger periodically, in case it requires a minimum user count
					uplink_sendReplicationRequest( uplink );
				} else {
					uplink_connectionFailed( uplink, true );
					logadd( LOG_DEBUG1, "Error sending keep-alive, panic!\n" );
					setThreadName( "panic-uplink" );
				}
			}
			// Don't keep uplink established if we're idle for too much
			if ( uplink->current.fd != -1 && uplink_connectionShouldShutdown( uplink ) ) {
				mutex_lock( &uplink->sendMutex );
				close( uplink->current.fd );
				uplink->current.fd = -1;
				mutex_unlock( &uplink->sendMutex );
				uplink->cycleDetected = false;
				if ( uplink->recvBufferLen != 0 ) {
					uplink->recvBufferLen = 0;
					free( uplink->recvBuffer );
					uplink->recvBuffer = NULL;
				}
				logadd( LOG_DEBUG1, "Closing idle uplink for image %s:%d", uplink->image->name, (int)uplink->image->rid );
				setThreadName( "idle-uplink" );
			}
		}
		// See if we should trigger an RTT measurement
		rttTestResult = uplink->rttTestResult;
		if ( rttTestResult == RTT_IDLE || rttTestResult == RTT_DONTCHANGE ) {
			if ( timing_reached( &nextAltCheck, &now ) || ( uplink->current.fd == -1 && !uplink_connectionShouldShutdown( uplink ) ) || uplink->cycleDetected ) {
				// It seems it's time for a check
				if ( image_isComplete( uplink->image ) ) {
					// Quit work if image is complete
					logadd( LOG_INFO, "Replication of %s complete.", uplink->image->name );
					setThreadName( "finished-uplink" );
					goto cleanup;
				} else if ( !uplink_connectionShouldShutdown( uplink ) ) {
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
			atomic_compare_exchange_strong( &uplink->rttTestResult, &rttTestResult, RTT_IDLE );
			discoverFailCount++;
			timing_set( &nextAltCheck, &now, (discoverFailCount < SERVER_RTT_MAX_UNREACH ? altCheckInterval : SERVER_RTT_INTERVAL_FAILED) );
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
			if ( resend )
				uplink_sendRequests( uplink, true );
		}
#endif
	}
	cleanup: ;
	uplink_saveCacheMap( uplink );
	dnbd3_image_t *image = uplink->image;
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
		mutex_unlock( &uplink->sendMutex );
		if ( !ret ) {
			// Non-critical - if the connection dropped or the server was changed
			// the thread will re-send this request as soon as the connection
			// is reestablished.
			logadd( LOG_DEBUG1, "Error forwarding request to uplink server!\n" );
			altservers_serverFailed( uplink->current.index );
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
 */
static void uplink_sendReplicationRequest(dnbd3_uplink_t *uplink)
{
	if ( uplink == NULL || uplink->current.fd == -1 ) return;
	if ( _backgroundReplication == BGR_DISABLED || uplink->cacheFd == -1 ) return; // Don't do background replication
	if ( uplink->nextReplicationIndex == -1 || uplink->replicationHandle != REP_NONE )
		return;
	dnbd3_image_t * const image = uplink->image;
	if ( image->virtualFilesize < DNBD3_BLOCK_SIZE ) return;
	mutex_lock( &image->lock );
	if ( image == NULL || image->cache_map == NULL || image->users < _bgrMinClients ) {
		// No cache map (=image complete), or replication pending, or not enough users, do nothing
		mutex_unlock( &image->lock );
		return;
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
	int replicationIndex = -1;
	for ( int j = uplink->nextReplicationIndex; j < endByte; ++j ) {
		const int i = j % ( mapBytes ); // Wrap around for BGR_FULL
		if ( image->cache_map[i] != 0xff && ( i != lastBlockIndex || !uplink->replicatedLastBlock ) ) {
			// Found incomplete one
			replicationIndex = i;
			break;
		}
	}
	mutex_unlock( &image->lock );
	if ( replicationIndex == -1 && _backgroundReplication == BGR_HASHBLOCK ) {
		// Nothing left in current block, find next one
		replicationIndex = uplink_findNextIncompleteHashBlock( uplink, endByte );
	}
	if ( replicationIndex == -1 ) {
		// Replication might be complete, uplink_mainloop should take care....
		uplink->nextReplicationIndex = -1;
		return;
	}
	const uint64_t offset = (uint64_t)replicationIndex * FILE_BYTES_PER_MAP_BYTE;
	uplink->replicationHandle = offset;
	const uint32_t size = (uint32_t)MIN( image->virtualFilesize - offset, FILE_BYTES_PER_MAP_BYTE );
	mutex_lock( &uplink->sendMutex );
	bool sendOk = dnbd3_get_block( uplink->current.fd, offset, size, uplink->replicationHandle, COND_HOPCOUNT( uplink->current.version, 1 ) );
	mutex_unlock( &uplink->sendMutex );
	if ( !sendOk ) {
		logadd( LOG_DEBUG1, "Error sending background replication request to uplink server!\n" );
		return;
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
}

/**
 * find next index into cache_map that corresponds to the beginning
 * of a hash block which is neither completely empty nor completely
 * replicated yet. Returns -1 if no match.
 */
static int uplink_findNextIncompleteHashBlock(dnbd3_uplink_t *uplink, const int startMapIndex)
{
	int retval = -1;
	mutex_lock( &uplink->image->lock );
	const int mapBytes = IMGSIZE_TO_MAPBYTES( uplink->image->virtualFilesize );
	const uint8_t *cache_map = uplink->image->cache_map;
	if ( cache_map != NULL ) {
		int j;
		const int start = ( startMapIndex & MAP_INDEX_HASH_START_MASK );
		for (j = 0; j < mapBytes; ++j) {
			const int i = ( start + j ) % mapBytes;
			const bool isFull = cache_map[i] == 0xff || ( i + 1 == mapBytes && uplink->replicatedLastBlock );
			const bool isEmpty = cache_map[i] == 0;
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
	mutex_unlock( &uplink->image->lock );
	return retval;
}

/**
 * Receive data from uplink server and process/dispatch
 * Locks on: uplink.lock, images[].lock
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
					if ( err == EINTR ) continue;
					if ( err == ENOSPC || err == EDQUOT ) {
						// try to free 256MiB
						if ( !tryAgain || !image_ensureDiskSpaceLocked( 256ull * 1024 * 1024, true ) ) break;
						tryAgain = false;
						continue; // Success, retry write
					}
					if ( err == EBADF || err == EINVAL || err == EIO ) {
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
		if ( rep ) uplink_sendReplicationRequest( uplink );
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
	altservers_serverFailed( uplink->current.index );
	mutex_lock( &uplink->sendMutex );
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

static void uplink_addCrc32(dnbd3_uplink_t *uplink)
{
	dnbd3_image_t *image = uplink->image;
	if ( image == NULL || image->virtualFilesize == 0 ) return;
	size_t bytes = IMGSIZE_TO_HASHBLOCKS( image->virtualFilesize ) * sizeof(uint32_t);
	uint32_t masterCrc;
	uint32_t *buffer = malloc( bytes );
	mutex_lock( &uplink->sendMutex );
	bool sendOk = dnbd3_get_crc32( uplink->current.fd, &masterCrc, buffer, &bytes );
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
	return uplink->cacheFd != -1;
}

/**
 * Saves the cache map of the given image.
 * Return true on success.
 * Locks on: imageListLock, image.lock
 */
static bool uplink_saveCacheMap(dnbd3_uplink_t *uplink)
{
	dnbd3_image_t *image = uplink->image;
	assert( image != NULL );

	if ( uplink->cacheFd != -1 ) {
		if ( fsync( uplink->cacheFd ) == -1 ) {
			// A failing fsync means we have no guarantee that any data
			// since the last fsync (or open if none) has been saved. Apart
			// from keeping the cache_map from the last successful fsync
			// around and restoring it there isn't much we can do to recover
			// a consistent state. Bail out.
			logadd( LOG_ERROR, "fsync() on image file %s failed with errno %d", image->path, errno );
			logadd( LOG_ERROR, "Bailing out immediately" );
			exit( 1 );
		}
	}

	if ( image->cache_map == NULL ) return true;
	logadd( LOG_DEBUG2, "Saving cache map of %s:%d", image->name, (int)image->rid );
	mutex_lock( &image->lock );
	// Lock and get a copy of the cache map, as it could be freed by another thread that is just about to
	// figure out that this image's cache copy is complete
	if ( image->cache_map == NULL || image->virtualFilesize < DNBD3_BLOCK_SIZE ) {
		mutex_unlock( &image->lock );
		return true;
	}
	const size_t size = IMGSIZE_TO_MAPBYTES(image->virtualFilesize);
	uint8_t *map = malloc( size );
	memcpy( map, image->cache_map, size );
	// Unlock. Use path and cacheFd without locking. path should never change after initialization of the image,
	// cacheFd is owned by the uplink thread and we don't want to hold a spinlock during I/O
	mutex_unlock( &image->lock );
	assert( image->path != NULL );
	char mapfile[strlen( image->path ) + 4 + 1];
	strcpy( mapfile, image->path );
	strcat( mapfile, ".map" );

	int fd = open( mapfile, O_WRONLY | O_CREAT, 0644 );
	if ( fd == -1 ) {
		const int err = errno;
		free( map );
		logadd( LOG_WARNING, "Could not open file to write cache map to disk (errno=%d) file %s", err, mapfile );
		return false;
	}

	size_t done = 0;
	while ( done < size ) {
		const ssize_t ret = write( fd, map, size - done );
		if ( ret == -1 ) {
			if ( errno == EINTR ) continue;
			logadd( LOG_WARNING, "Could not write cache map (errno=%d) file %s", errno, mapfile );
			break;
		}
		if ( ret <= 0 ) {
			logadd( LOG_WARNING, "Unexpected return value %d for write() to %s", (int)ret, mapfile );
			break;
		}
		done += (size_t)ret;
	}
	if ( fsync( fd ) == -1 ) {
		logadd( LOG_WARNING, "fsync() on image map %s failed with errno %d", mapfile, errno );
	}
	close( fd );
	free( map );
	return true;
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
