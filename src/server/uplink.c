#include "uplink.h"
#include "helper.h"
#include "locks.h"
#include "image.h"
#include "altservers.h"
#include "../shared/sockhelper.h"
#include "../shared/protocol.h"
#include "../shared/timing.h"
#include "../shared/crc32.h"

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

static atomic_uint_fast64_t totalBytesReceived = 0;

static void* uplink_mainloop(void *data);
static void uplink_sendRequests(dnbd3_connection_t *link, bool newOnly);
static int uplink_findNextIncompleteHashBlock(dnbd3_connection_t *link, const int lastBlockIndex);
static void uplink_handleReceive(dnbd3_connection_t *link);
static int uplink_sendKeepalive(const int fd);
static void uplink_addCrc32(dnbd3_connection_t *uplink);
static void uplink_sendReplicationRequest(dnbd3_connection_t *link);
static bool uplink_reopenCacheFd(dnbd3_connection_t *link, const bool force);
static bool uplink_saveCacheMap(dnbd3_connection_t *link);
static bool uplink_connectionShouldShutdown(dnbd3_connection_t *link);
static void uplink_connectionFailed(dnbd3_connection_t *link, bool findNew);

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
	dnbd3_connection_t *link = NULL;
	assert( image != NULL );
	mutex_lock( &image->lock );
	if ( image->uplink != NULL && !image->uplink->shutdown ) {
		mutex_unlock( &image->lock );
		if ( sock >= 0 ) close( sock );
		return true; // There's already an uplink, so should we consider this success or failure?
	}
	if ( image->cache_map == NULL ) {
		logadd( LOG_WARNING, "Uplink was requested for image %s, but it is already complete", image->name );
		goto failure;
	}
	link = image->uplink = calloc( 1, sizeof(dnbd3_connection_t) );
	mutex_init( &link->queueLock );
	mutex_init( &link->rttLock );
	mutex_init( &link->sendMutex );
	link->image = image;
	link->bytesReceived = 0;
	link->idleTime = 0;
	link->queueLen = 0;
	mutex_lock( &link->sendMutex );
	link->fd = -1;
	mutex_unlock( &link->sendMutex );
	link->cacheFd = -1;
	link->signal = NULL;
	link->replicationHandle = REP_NONE;
	mutex_lock( &link->rttLock );
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
	mutex_unlock( &link->rttLock );
	link->recvBufferLen = 0;
	link->shutdown = false;
	if ( 0 != thread_create( &(link->thread), NULL, &uplink_mainloop, (void *)link ) ) {
		logadd( LOG_ERROR, "Could not start thread for new uplink." );
		goto failure;
	}
	mutex_unlock( &image->lock );
	return true;
failure: ;
	if ( link != NULL ) {
		free( link );
		link = image->uplink = NULL;
	}
	mutex_unlock( &image->lock );
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
	mutex_lock( &image->lock );
	if ( image->uplink == NULL ) {
		mutex_unlock( &image->lock );
		return;
	}
	dnbd3_connection_t * const uplink = image->uplink;
	mutex_lock( &uplink->queueLock );
	if ( !uplink->shutdown ) {
		uplink->shutdown = true;
		signal_call( uplink->signal );
		thread = uplink->thread;
		join = true;
	}
	mutex_unlock( &uplink->queueLock );
	bool wait = image->uplink != NULL;
	mutex_unlock( &image->lock );
	if ( join ) thread_join( thread, NULL );
	while ( wait ) {
		usleep( 5000 );
		mutex_lock( &image->lock );
		wait = image->uplink != NULL && image->uplink->shutdown;
		mutex_unlock( &image->lock );
	}
}

/**
 * Remove given client from uplink request queue
 * Locks on: uplink.queueLock
 */
void uplink_removeClient(dnbd3_connection_t *uplink, dnbd3_client_t *client)
{
	mutex_lock( &uplink->queueLock );
	for (int i = uplink->queueLen - 1; i >= 0; --i) {
		if ( uplink->queue[i].client == client ) {
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
	if ( client == NULL || client->image == NULL ) return false;
	if ( length > (uint32_t)_maxPayload ) {
		logadd( LOG_WARNING, "Cannot relay request by client; length of %" PRIu32 " exceeds maximum payload", length );
		return false;
	}
	mutex_lock( &client->image->lock );
	if ( client->image->uplink == NULL ) {
		mutex_unlock( &client->image->lock );
		logadd( LOG_DEBUG1, "Uplink request for image with no uplink" );
		return false;
	}
	dnbd3_connection_t * const uplink = client->image->uplink;
	if ( uplink->shutdown ) {
		mutex_unlock( &client->image->lock );
		logadd( LOG_DEBUG1, "Uplink request for image with uplink shutting down" );
		return false;
	}
	// Check if the client is the same host as the uplink. If so assume this is a circular proxy chain
	// This might be a false positive if there are multiple instances running on the same host (IP)
	if ( hops != 0 && isSameAddress( &uplink->currentServer, &client->host ) ) {
		mutex_unlock( &client->image->lock );
		logadd( LOG_WARNING, "Proxy cycle detected (same host)." );
		mutex_lock( &uplink->rttLock );
		uplink->cycleDetected = true;
		mutex_unlock( &uplink->rttLock );
		signal_call( uplink->signal );
		return false;
	}

	int foundExisting = -1; // Index of a pending request that is a superset of our range, -1 otherwise
	int existingType = -1; // ULR_* type of existing request
	int i;
	int freeSlot = -1;
	bool requestLoop = false;
	const uint64_t end = start + length;

	mutex_lock( &uplink->queueLock );
	mutex_unlock( &client->image->lock );
	for (i = 0; i < uplink->queueLen; ++i) {
		if ( freeSlot == -1 && uplink->queue[i].status == ULR_FREE ) {
			freeSlot = i;
			continue;
		}
		if ( uplink->queue[i].status != ULR_PENDING && uplink->queue[i].status != ULR_NEW ) continue;
		if ( uplink->queue[i].from <= start && uplink->queue[i].to >= end ) {
			if ( hops > uplink->queue[i].hopCount && uplink->queue[i].from == start && uplink->queue[i].to == end ) {
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
		mutex_unlock( &uplink->queueLock );
		logadd( LOG_WARNING, "Rejecting relay of request to upstream proxy because of possible cyclic proxy chain. Incoming hop-count is %" PRIu8 ".", hops );
		mutex_lock( &uplink->rttLock );
		uplink->cycleDetected = true;
		mutex_unlock( &uplink->rttLock );
		signal_call( uplink->signal );
		return false;
	}
	if ( freeSlot == -1 ) {
		if ( uplink->queueLen >= SERVER_MAX_UPLINK_QUEUE ) {
			mutex_unlock( &uplink->queueLock );
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
	timing_get( &uplink->queue[freeSlot].entered );
	//logadd( LOG_DEBUG2 %p] Inserting request at slot %d, was %d, now %d, handle %" PRIu64 ", Range: %" PRIu64 "-%" PRIu64 "\n", (void*)uplink, freeSlot, old, uplink->queue[freeSlot].status, uplink->queue[freeSlot, ".handle, start, end );
#endif
	mutex_unlock( &uplink->queueLock );

	if ( foundExisting != -1 )
		return true; // Attached to pending request, do nothing

	// See if we can fire away the request
	if ( mutex_trylock( &uplink->sendMutex ) != 0 ) {
		logadd( LOG_DEBUG2, "Could not trylock send mutex, queueing uplink request" );
	} else {
		if ( uplink->fd == -1 ) {
			mutex_unlock( &uplink->sendMutex );
			logadd( LOG_DEBUG2, "Cannot do direct uplink request: No socket open" );
		} else {
			const uint64_t reqStart = uplink->queue[freeSlot].from & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
			const uint32_t reqSize = (uint32_t)(((uplink->queue[freeSlot].to + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1)) - reqStart);
			if ( hops < 200 ) ++hops;
			const bool ret = dnbd3_get_block( uplink->fd, reqStart, reqSize, reqStart, COND_HOPCOUNT( uplink->version, hops ) );
			mutex_unlock( &uplink->sendMutex );
			if ( !ret ) {
				logadd( LOG_DEBUG2, "Could not send out direct uplink request, queueing" );
			} else {
				mutex_lock( &uplink->queueLock );
				if ( uplink->queue[freeSlot].handle == handle && uplink->queue[freeSlot].client == client && uplink->queue[freeSlot].status == ULR_NEW ) {
					uplink->queue[freeSlot].status = ULR_PENDING;
					logadd( LOG_DEBUG2, "Succesful direct uplink request" );
				} else {
					logadd( LOG_DEBUG2, "Weird queue update fail for direct uplink request" );
				}
				mutex_unlock( &uplink->queueLock );
				return true;
			}
			// Fall through to waking up sender thread
		}
	}

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
	dnbd3_connection_t * const link = (dnbd3_connection_t*)data;
	int numSocks, i, waitTime;
	int altCheckInterval = SERVER_RTT_INTERVAL_INIT;
	uint32_t discoverFailCount = 0;
	uint32_t unsavedSeconds = 0;
	ticks nextAltCheck, lastKeepalive;
	char buffer[200];
	memset( events, 0, sizeof(events) );
	timing_get( &nextAltCheck );
	lastKeepalive = nextAltCheck;
	//
	assert( link != NULL );
	setThreadName( "idle-uplink" );
	blockNoncriticalSignals();
	// Make sure file is open for writing
	if ( !uplink_reopenCacheFd( link, false ) ) {
		// It might have failed - still offer proxy mode, we just can't cache
		logadd( LOG_WARNING, "Cannot open cache file %s for writing (errno=%d); will just proxy traffic without caching!", link->image->path, errno );
	}
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
		// poll()
		mutex_lock( &link->rttLock );
		waitTime = link->rttTestResult == RTT_DOCHANGE ? 0 : -1;
		mutex_unlock( &link->rttLock );
		if ( waitTime == 0 ) {
			// Nothing
		} else if ( link->fd == -1 && !uplink_connectionShouldShutdown( link ) ) {
			waitTime = 1000;
		} else {
			declare_now;
			waitTime = (int)timing_diffMs( &now, &nextAltCheck );
			if ( waitTime < 100 ) waitTime = 100;
			if ( waitTime > 5000 ) waitTime = 5000;
		}
		events[EV_SOCKET].fd = link->fd;
		numSocks = poll( events, EV_COUNT, waitTime );
		if ( _shutdown || link->shutdown ) goto cleanup;
		if ( numSocks == -1 ) { // Error?
			if ( errno == EINTR ) continue;
			logadd( LOG_DEBUG1, "poll() error %d", (int)errno );
			usleep( 10000 );
			continue;
		}
		// Check if server switch is in order
		mutex_lock( &link->rttLock );
		if ( link->rttTestResult != RTT_DOCHANGE ) {
			mutex_unlock( &link->rttLock );
		} else {
			link->rttTestResult = RTT_IDLE;
			// The rttTest worker thread has finished our request.
			// And says it's better to switch to another server
			const int fd = link->fd;
			mutex_lock( &link->sendMutex );
			link->fd = link->betterFd;
			mutex_unlock( &link->sendMutex );
			link->betterFd = -1;
			link->currentServer = link->betterServer;
			link->version = link->betterVersion;
			link->cycleDetected = false;
			mutex_unlock( &link->rttLock );
			discoverFailCount = 0;
			if ( fd != -1 ) close( fd );
			link->replicationHandle = REP_NONE;
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
			if ( signal_clear( link->signal ) == SIGNAL_ERROR ) {
				logadd( LOG_WARNING, "Errno on signal on uplink for %s! Things will break!", link->image->name );
			}
			if ( link->fd != -1 ) {
				// Uplink seems fine, relay requests to it...
				uplink_sendRequests( link, true );
			} else { // No uplink; maybe it was shutdown since it was idle for too long
				link->idleTime = 0;
			}
		}
		// Uplink socket
		if ( (events[EV_SOCKET].revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) ) {
			uplink_connectionFailed( link, true );
			logadd( LOG_DEBUG1, "Uplink gone away, panic!\n" );
			setThreadName( "panic-uplink" );
		} else if ( (events[EV_SOCKET].revents & POLLIN) ) {
			uplink_handleReceive( link );
			if ( _shutdown || link->shutdown ) goto cleanup;
		}
		declare_now;
		uint32_t timepassed = timing_diff( &lastKeepalive, &now );
		if ( timepassed >= SERVER_UPLINK_KEEPALIVE_INTERVAL ) {
			lastKeepalive = now;
			link->idleTime += timepassed;
			unsavedSeconds += timepassed;
			if ( unsavedSeconds > 240 || ( unsavedSeconds > 60 && link->idleTime >= 20 && link->idleTime <= 70 ) ) {
				// fsync/save every 4 minutes, or every 60 seconds if link is idle
				unsavedSeconds = 0;
				uplink_saveCacheMap( link );
			}
			// Keep-alive
			if ( link->fd != -1 && link->replicationHandle == REP_NONE ) {
				// Send keep-alive if nothing is happening
				if ( uplink_sendKeepalive( link->fd ) ) {
					// Re-trigger periodically, in case it requires a minimum user count
					uplink_sendReplicationRequest( link );
				} else {
					uplink_connectionFailed( link, true );
					logadd( LOG_DEBUG1, "Error sending keep-alive, panic!\n" );
					setThreadName( "panic-uplink" );
				}
			}
			// Don't keep link established if we're idle for too much
			if ( link->fd != -1 && uplink_connectionShouldShutdown( link ) ) {
				mutex_lock( &link->sendMutex );
				close( link->fd );
				link->fd = events[EV_SOCKET].fd = -1;
				mutex_unlock( &link->sendMutex );
				link->cycleDetected = false;
				if ( link->recvBufferLen != 0 ) {
					link->recvBufferLen = 0;
					free( link->recvBuffer );
					link->recvBuffer = NULL;
				}
				logadd( LOG_DEBUG1, "Closing idle uplink for image %s:%d", link->image->name, (int)link->image->rid );
				setThreadName( "idle-uplink" );
			}
		}
		// See if we should trigger an RTT measurement
		mutex_lock( &link->rttLock );
		const int rttTestResult = link->rttTestResult;
		mutex_unlock( &link->rttLock );
		if ( rttTestResult == RTT_IDLE || rttTestResult == RTT_DONTCHANGE ) {
			if ( timing_reached( &nextAltCheck, &now ) || ( link->fd == -1 && !uplink_connectionShouldShutdown( link ) ) || link->cycleDetected ) {
				// It seems it's time for a check
				if ( image_isComplete( link->image ) ) {
					// Quit work if image is complete
					logadd( LOG_INFO, "Replication of %s complete.", link->image->name );
					setThreadName( "finished-uplink" );
					goto cleanup;
				} else if ( !uplink_connectionShouldShutdown( link ) ) {
					// Not complete - do measurement
					altservers_findUplink( link ); // This will set RTT_INPROGRESS (synchronous)
					if ( _backgroundReplication == BGR_FULL && link->nextReplicationIndex == -1 ) {
						link->nextReplicationIndex = 0;
					}
				}
				altCheckInterval = MIN(altCheckInterval + 1, SERVER_RTT_INTERVAL_MAX);
				timing_set( &nextAltCheck, &now, altCheckInterval );
			}
		} else if ( rttTestResult == RTT_NOT_REACHABLE ) {
			mutex_lock( &link->rttLock );
			link->rttTestResult = RTT_IDLE;
			mutex_unlock( &link->rttLock );
			discoverFailCount++;
			timing_set( &nextAltCheck, &now, (discoverFailCount < SERVER_RTT_BACKOFF_COUNT ? altCheckInterval : SERVER_RTT_INTERVAL_FAILED) );
		}
#ifdef _DEBUG
		if ( link->fd != -1 && !link->shutdown ) {
			bool resend = false;
			ticks deadline;
			timing_set( &deadline, &now, -10 );
			mutex_lock( &link->queueLock );
			for (i = 0; i < link->queueLen; ++i) {
				if ( link->queue[i].status != ULR_FREE && timing_reached( &link->queue[i].entered, &deadline ) ) {
					snprintf( buffer, sizeof(buffer), "[DEBUG %p] Starving request slot %d detected:\n"
							"%s\n(from %" PRIu64 " to %" PRIu64 ", status: %d)\n", (void*)link, i, link->queue[i].client->image->name,
							link->queue[i].from, link->queue[i].to, link->queue[i].status );
					link->queue[i].entered = now;
#ifdef _DEBUG_RESEND_STARVING
					link->queue[i].status = ULR_NEW;
					resend = true;
#endif
					mutex_unlock( &link->queueLock );
					logadd( LOG_WARNING, "%s", buffer );
					mutex_lock( &link->queueLock );
				}
			}
			mutex_unlock( &link->queueLock );
			if ( resend )
				uplink_sendRequests( link, true );
		}
#endif
	}
	cleanup: ;
	altservers_removeUplink( link );
	uplink_saveCacheMap( link );
	mutex_lock( &link->image->lock );
	if ( link->image->uplink == link ) {
		link->image->uplink = NULL;
	}
	mutex_lock( &link->queueLock );
	const int fd = link->fd;
	const dnbd3_signal_t* signal = link->signal;
	mutex_lock( &link->sendMutex );
	link->fd = -1;
	mutex_unlock( &link->sendMutex );
	link->signal = NULL;
	if ( !link->shutdown ) {
		link->shutdown = true;
		thread_detach( link->thread );
	}
	// Do not access link->image after unlocking, since we set
	// image->uplink to NULL. Acquire with image_lock first,
	// like done below when checking whether to re-init uplink
	mutex_unlock( &link->image->lock );
	mutex_unlock( &link->queueLock );
	if ( fd != -1 ) close( fd );
	if ( signal != NULL ) signal_close( signal );
	// Wait for the RTT check to finish/fail if it's in progress
	while ( link->rttTestResult == RTT_INPROGRESS )
		usleep( 10000 );
	if ( link->betterFd != -1 ) {
		close( link->betterFd );
	}
	mutex_destroy( &link->queueLock );
	mutex_destroy( &link->rttLock );
	mutex_destroy( &link->sendMutex );
	free( link->recvBuffer );
	link->recvBuffer = NULL;
	if ( link->cacheFd != -1 ) {
		close( link->cacheFd );
	}
	dnbd3_image_t *image = image_lock( link->image );
	free( link ); // !!!
	if ( image != NULL ) {
		if ( !_shutdown && image->cache_map != NULL ) {
			// Ingegrity checker must have found something in the meantime
			uplink_init( image, -1, NULL, 0 );
		}
		image_release( image );
	}
	return NULL ;
}

static void uplink_sendRequests(dnbd3_connection_t *link, bool newOnly)
{
	// Scan for new requests
	int j;
	mutex_lock( &link->queueLock );
	for (j = 0; j < link->queueLen; ++j) {
		if ( link->queue[j].status != ULR_NEW && (newOnly || link->queue[j].status != ULR_PENDING) ) continue;
		link->queue[j].status = ULR_PENDING;
		uint8_t hops = link->queue[j].hopCount;
		const uint64_t reqStart = link->queue[j].from & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
		const uint32_t reqSize = (uint32_t)(((link->queue[j].to + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1)) - reqStart);
		/*
		logadd( LOG_DEBUG2, "[%p] Sending slot %d, now %d, handle %" PRIu64 ", Range: %" PRIu64 "-%" PRIu64 " (%" PRIu64 "-%" PRIu64 ")",
				(void*)link, j, link->queue[j].status, link->queue[j].handle, link->queue[j].from, link->queue[j].to, reqStart, reqStart+reqSize );
		*/
		mutex_unlock( &link->queueLock );
		if ( hops < 200 ) ++hops;
		mutex_lock( &link->sendMutex );
		const bool ret = dnbd3_get_block( link->fd, reqStart, reqSize, reqStart, COND_HOPCOUNT( link->version, hops ) );
		mutex_unlock( &link->sendMutex );
		if ( !ret ) {
			// Non-critical - if the connection dropped or the server was changed
			// the thread will re-send this request as soon as the connection
			// is reestablished.
			logadd( LOG_DEBUG1, "Error forwarding request to uplink server!\n" );
			altservers_serverFailed( &link->currentServer );
			return;
		}
		mutex_lock( &link->queueLock );
	}
	mutex_unlock( &link->queueLock );
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
	if ( link == NULL || link->fd == -1 ) return;
	if ( _backgroundReplication == BGR_DISABLED || link->cacheFd == -1 ) return; // Don't do background replication
	if ( link->nextReplicationIndex == -1 || link->replicationHandle != REP_NONE )
		return;
	dnbd3_image_t * const image = link->image;
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
		endByte = link->nextReplicationIndex + mapBytes;
	} else { // Hashblock based: Only look for match in current hash block
		endByte = ( link->nextReplicationIndex + MAP_BYTES_PER_HASH_BLOCK ) & MAP_INDEX_HASH_START_MASK;
		if ( endByte > mapBytes ) {
			endByte = mapBytes;
		}
	}
	int replicationIndex = -1;
	for ( int j = link->nextReplicationIndex; j < endByte; ++j ) {
		const int i = j % ( mapBytes ); // Wrap around for BGR_FULL
		if ( image->cache_map[i] != 0xff && ( i != lastBlockIndex || !link->replicatedLastBlock ) ) {
			// Found incomplete one
			replicationIndex = i;
			break;
		}
	}
	mutex_unlock( &image->lock );
	if ( replicationIndex == -1 && _backgroundReplication == BGR_HASHBLOCK ) {
		// Nothing left in current block, find next one
		replicationIndex = uplink_findNextIncompleteHashBlock( link, endByte );
	}
	if ( replicationIndex == -1 ) {
		// Replication might be complete, uplink_mainloop should take care....
		link->nextReplicationIndex = -1;
		return;
	}
	const uint64_t offset = (uint64_t)replicationIndex * FILE_BYTES_PER_MAP_BYTE;
	link->replicationHandle = offset;
	const uint32_t size = (uint32_t)MIN( image->virtualFilesize - offset, FILE_BYTES_PER_MAP_BYTE );
	mutex_lock( &link->sendMutex );
	bool sendOk = dnbd3_get_block( link->fd, offset, size, link->replicationHandle, COND_HOPCOUNT( link->version, 1 ) );
	mutex_unlock( &link->sendMutex );
	if ( !sendOk ) {
		logadd( LOG_DEBUG1, "Error sending background replication request to uplink server!\n" );
		return;
	}
	if ( replicationIndex == lastBlockIndex ) {
		link->replicatedLastBlock = true; // Special treatment, last byte in map could represent less than 8 blocks
	}
	link->nextReplicationIndex = replicationIndex + 1; // Remember last incomplete offset for next time so we don't play Schlemiel the painter
	if ( _backgroundReplication == BGR_HASHBLOCK
			&& link->nextReplicationIndex % MAP_BYTES_PER_HASH_BLOCK == 0 ) {
		// Just crossed a hash block boundary, look for new candidate starting at this very index
		link->nextReplicationIndex = uplink_findNextIncompleteHashBlock( link, link->nextReplicationIndex );
	}
}

/**
 * find next index into cache_map that corresponds to the beginning
 * of a hash block which is neither completely empty nor completely
 * replicated yet. Returns -1 if no match.
 */
static int uplink_findNextIncompleteHashBlock(dnbd3_connection_t *link, const int startMapIndex)
{
	int retval = -1;
	mutex_lock( &link->image->lock );
	const int mapBytes = IMGSIZE_TO_MAPBYTES( link->image->virtualFilesize );
	const uint8_t *cache_map = link->image->cache_map;
	if ( cache_map != NULL ) {
		int j;
		const int start = ( startMapIndex & MAP_INDEX_HASH_START_MASK );
		for (j = 0; j < mapBytes; ++j) {
			const int i = ( start + j ) % mapBytes;
			const bool isFull = cache_map[i] == 0xff || ( i + 1 == mapBytes && link->replicatedLastBlock );
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
	mutex_unlock( &link->image->lock );
	return retval;
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
		if ( unlikely( ret == REPLY_INTR ) && likely( !_shutdown && !link->shutdown ) ) continue;
		if ( ret == REPLY_AGAIN ) break;
		if ( unlikely( ret == REPLY_CLOSED ) ) {
			logadd( LOG_INFO, "Uplink: Remote host hung up (%s)", link->image->path );
			goto error_cleanup;
		}
		if ( unlikely( ret == REPLY_WRONGMAGIC ) ) {
			logadd( LOG_WARNING, "Uplink server's packet did not start with dnbd3_packet_magic (%s)", link->image->path );
			goto error_cleanup;
		}
		if ( unlikely( ret != REPLY_OK ) ) {
			logadd( LOG_INFO, "Uplink: Connection error %d (%s)", ret, link->image->path );
			goto error_cleanup;
		}
		if ( unlikely( inReply.size > (uint32_t)_maxPayload ) ) {
			logadd( LOG_WARNING, "Pure evil: Uplink server sent too much payload (%" PRIu32 ") for %s", inReply.size, link->image->path );
			goto error_cleanup;
		}

		if ( unlikely( link->recvBufferLen < inReply.size ) ) {
			link->recvBufferLen = MIN((uint32_t)_maxPayload, inReply.size + 65536);
			link->recvBuffer = realloc( link->recvBuffer, link->recvBufferLen );
			if ( link->recvBuffer == NULL ) {
				logadd( LOG_ERROR, "Out of memory when trying to allocate receive buffer for uplink" );
				exit( 1 );
			}
		}
		if ( unlikely( (uint32_t)sock_recv( link->fd, link->recvBuffer, inReply.size ) != inReply.size ) ) {
			logadd( LOG_INFO, "Lost connection to uplink server of %s (payload)", link->image->path );
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
		link->bytesReceived += inReply.size;
		// 1) Write to cache file
		if ( unlikely( link->cacheFd == -1 ) ) {
			uplink_reopenCacheFd( link, false );
		}
		if ( likely( link->cacheFd != -1 ) ) {
			int err = 0;
			bool tryAgain = true; // Allow one retry in case we run out of space or the write fd became invalid
			uint32_t done = 0;
			ret = 0;
			while ( done < inReply.size ) {
				ret = (int)pwrite( link->cacheFd, link->recvBuffer + done, inReply.size - done, start + done );
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
						if ( !tryAgain || !uplink_reopenCacheFd( link, true ) )
							break;
						tryAgain = false;
						continue; // Write handle to image successfully re-opened, try again
					}
					logadd( LOG_DEBUG1, "Error trying to cache data for %s:%d -- errno=%d", link->image->name, (int)link->image->rid, err );
					break;
				}
				if ( unlikely( ret <= 0 || (uint32_t)ret > inReply.size - done ) ) {
					logadd( LOG_WARNING, "Unexpected return value %d from pwrite to %s:%d", ret, link->image->name, (int)link->image->rid );
					break;
				}
				done += (uint32_t)ret;
			}
			if ( likely( done > 0 ) ) {
				image_updateCachemap( link->image, start, start + done, true );
			}
			if ( unlikely( ret == -1 && ( err == EBADF || err == EINVAL || err == EIO ) ) ) {
				logadd( LOG_WARNING, "Error writing received data for %s:%d (errno=%d); disabling caching.",
						link->image->name, (int)link->image->rid, err );
			}
		}
		// 2) Figure out which clients are interested in it
		mutex_lock( &link->queueLock );
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
				outReply.size = (uint32_t)( req->to - req->from );
				iov[0].iov_base = &outReply;
				iov[0].iov_len = sizeof outReply;
				iov[1].iov_base = link->recvBuffer + (req->from - start);
				iov[1].iov_len = outReply.size;
				fixup_reply( outReply );
				req->status = ULR_FREE;
				req->client = NULL;
				served = true;
				mutex_lock( &client->sendMutex );
				mutex_unlock( &link->queueLock );
				if ( client->sock != -1 ) {
					ssize_t sent = writev( client->sock, iov, 2 );
					if ( sent > (ssize_t)sizeof outReply ) {
						bytesSent = (size_t)sent - sizeof outReply;
					}
				}
				mutex_unlock( &client->sendMutex );
				if ( bytesSent != 0 ) {
					client->bytesSent += bytesSent;
				}
				mutex_lock( &link->queueLock );
			}
			if ( req->status == ULR_FREE && i == link->queueLen - 1 ) link->queueLen--;
		}
		mutex_unlock( &link->queueLock );
#ifdef _DEBUG
		if ( !served && start != link->replicationHandle ) {
			logadd( LOG_DEBUG2, "%p, %s -- Unmatched reply: %" PRIu64 " to %" PRIu64, (void*)link, link->image->name, start, end );
		}
#endif
		if ( start == link->replicationHandle ) {
			// Was our background replication
			link->replicationHandle = REP_NONE;
			// Try to remove from fs cache if no client was interested in this data
			if ( !served && link->cacheFd != -1 ) {
				posix_fadvise( link->cacheFd, start, inReply.size, POSIX_FADV_DONTNEED );
			}
		}
		if ( served ) {
			// Was some client -- reset idle counter
			link->idleTime = 0;
			// Re-enable replication if disabled
			if ( link->nextReplicationIndex == -1 ) {
				link->nextReplicationIndex = (int)( start / FILE_BYTES_PER_MAP_BYTE ) & MAP_INDEX_HASH_START_MASK;
			}
		}
	}
	if ( link->replicationHandle == REP_NONE ) {
		mutex_lock( &link->queueLock );
		const bool rep = ( link->queueLen == 0 );
		mutex_unlock( &link->queueLock );
		if ( rep ) uplink_sendReplicationRequest( link );
	}
	return;
	// Error handling from failed receive or message parsing
	error_cleanup: ;
	uplink_connectionFailed( link, true );
}

static void uplink_connectionFailed(dnbd3_connection_t *link, bool findNew)
{
	if ( link->fd == -1 )
		return;
	altservers_serverFailed( &link->currentServer );
	mutex_lock( &link->sendMutex );
	close( link->fd );
	link->fd = -1;
	mutex_unlock( &link->sendMutex );
	link->replicationHandle = REP_NONE;
	if ( _backgroundReplication == BGR_FULL && link->nextReplicationIndex == -1 ) {
		link->nextReplicationIndex = 0;
	}
	if ( !findNew )
		return;
	mutex_lock( &link->rttLock );
	bool bail = link->rttTestResult == RTT_INPROGRESS || link->betterFd != -1;
	mutex_unlock( &link->rttLock );
	if ( bail )
		return;
	altservers_findUplink( link );
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
	if ( image == NULL || image->virtualFilesize == 0 ) return;
	size_t bytes = IMGSIZE_TO_HASHBLOCKS( image->virtualFilesize ) * sizeof(uint32_t);
	uint32_t masterCrc;
	uint32_t *buffer = malloc( bytes );
	mutex_lock( &uplink->sendMutex );
	bool sendOk = dnbd3_get_crc32( uplink->fd, &masterCrc, buffer, &bytes );
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
static bool uplink_reopenCacheFd(dnbd3_connection_t *link, const bool force)
{
	if ( link->cacheFd != -1 ) {
		if ( !force ) return true;
		close( link->cacheFd );
	}
	link->cacheFd = open( link->image->path, O_WRONLY | O_CREAT, 0644 );
	return link->cacheFd != -1;
}

/**
 * Saves the cache map of the given image.
 * Return true on success.
 * Locks on: imageListLock, image.lock
 */
static bool uplink_saveCacheMap(dnbd3_connection_t *link)
{
	dnbd3_image_t *image = link->image;
	assert( image != NULL );

	if ( link->cacheFd != -1 ) {
		if ( fsync( link->cacheFd ) == -1 ) {
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

static bool uplink_connectionShouldShutdown(dnbd3_connection_t *link)
{
	return ( link->idleTime > SERVER_UPLINK_IDLE_TIMEOUT
			&& ( _backgroundReplication != BGR_FULL || _bgrMinClients > link->image->users ) );
}

