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
#include "threadpool.h"
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

static atomic_uint_fast64_t totalBytesReceived = 0;

static void cancelAllRequests(dnbd3_uplink_t *uplink);
static void freeUplinkStruct(ref *ref);
static void* uplink_mainloop(void *data);
static void sendQueuedRequests(dnbd3_uplink_t *uplink, bool newOnly);
static int findNextIncompleteHashBlock(dnbd3_uplink_t *uplink, const int lastBlockIndex);
static void handleReceive(dnbd3_uplink_t *uplink);
static bool sendKeepalive(dnbd3_uplink_t *uplink);
static void requestCrc32List(dnbd3_uplink_t *uplink);
static bool sendReplicationRequest(dnbd3_uplink_t *uplink);
static bool reopenCacheFd(dnbd3_uplink_t *uplink, const bool force);
static bool connectionShouldShutdown(dnbd3_uplink_t *uplink);
static void connectionFailed(dnbd3_uplink_t *uplink, bool findNew);
static int numWantedReplicationRequests(dnbd3_uplink_t *uplink);
static void markRequestUnsent(dnbd3_uplink_t *uplink, uint64_t handle);
static void *prefetchForClient(void *data);

typedef struct {
	dnbd3_uplink_t *uplink;
	uint64_t start;
	uint32_t length;
} prefetch_job_t;

#define assert_uplink_thread() assert( pthread_equal( uplink->thread, pthread_self() ) )

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
	if ( sock == -1 && !altservers_imageHasAltServers( image->name ) )
		return false; // Nothing to do
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
	ref_init( &uplink->reference, freeUplinkStruct, 1 );
	mutex_init( &uplink->queueLock, LOCK_UPLINK_QUEUE );
	mutex_init( &uplink->rttLock, LOCK_UPLINK_RTT );
	mutex_init( &uplink->sendMutex, LOCK_UPLINK_SEND );
	uplink->image = image;
	uplink->bytesReceived = 0;
	uplink->bytesReceivedLastSave = 0;
	uplink->idleTime = SERVER_UPLINK_IDLE_TIMEOUT - 90;
	uplink->queue = NULL;
	uplink->queueLen = 0;
	uplink->cacheFd = -1;
	uplink->signal = signal_new();
	if ( uplink->signal == NULL ) {
		logadd( LOG_WARNING, "Error creating signal. Uplink unavailable." );
		goto failure;
	}
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
		image->users++; // Expected by freeUplinkStruct()
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
		logadd( LOG_ERROR, "This will never happen. '%s:%d'", PIMG(image) );
	}
	cancelAllRequests( uplink );
	ref_setref( &image->uplinkref, NULL );
	mutex_unlock( &uplink->queueLock );
	bool retval = ( exp && image->users == 0 );
	ref_put( &uplink->reference );
	mutex_unlock( &image->lock );
	return retval;
}

/**
 * Cancel all requests of this uplink.
 * HOLD QUEUE LOCK WHILE CALLING
 */
static void cancelAllRequests(dnbd3_uplink_t *uplink)
{
	dnbd3_queue_entry_t *it = uplink->queue;
	while ( it != NULL ) {
		dnbd3_queue_client_t *cit = it->clients;
		while ( cit != NULL ) {
			net_sendReply( cit->client, CMD_ERROR, cit->handle );
			cit->client->relayedCount--;
			dnbd3_queue_client_t *next = cit->next;
			free( cit );
			cit = next;
		}
		dnbd3_queue_entry_t *next = it->next;
		free( it );
		it = next;
	}
	uplink->queue = NULL;
	uplink->queueLen = 0;
	uplink->image->problem.queue = false;
}

static void freeUplinkStruct(ref *ref)
{
	dnbd3_uplink_t *uplink = container_of(ref, dnbd3_uplink_t, reference);
	logadd( LOG_DEBUG1, "Freeing uplink for '%s:%d'", PIMG(uplink->image) );
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
	if ( client->relayedCount == 0 )
		return;
	mutex_lock( &uplink->queueLock );
	for ( dnbd3_queue_entry_t *it = uplink->queue; it != NULL; it = it->next ) {
		for ( dnbd3_queue_client_t **cit = &it->clients; *cit != NULL; ) {
			if ( (**cit).client == client ) {
				--client->relayedCount;
				dnbd3_queue_client_t *entry = *cit;
				*cit = (**cit).next;
				free( entry );
			} else {
				cit = &(**cit).next;
			}
		}
	}
	mutex_unlock( &uplink->queueLock );
	if ( unlikely( client->relayedCount != 0 ) ) {
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

/**
 * Request a chunk of data through an uplink server. Either uplink or client has to be non-NULL.
 * If client is NULL, this is assumed to be a background replication request.
 * Locks on: uplink.queueLock, uplink.sendMutex
 */
bool uplink_request(dnbd3_uplink_t *uplink, dnbd3_client_t *client, uint64_t handle, uint64_t start, uint32_t length, uint8_t hops)
{
	bool getUplink = ( uplink == NULL );
	assert( client != NULL || uplink != NULL );
	if ( hops++ > 200 ) { // This is just silly
		logadd( LOG_WARNING, "Refusing to relay a request that has > 200 hops" );
		return false;
	}
	if ( length > (uint32_t)_maxPayload ) {
		logadd( LOG_WARNING, "Cannot relay request by client; length of %" PRIu32 " exceeds maximum payload", length );
		return false;
	}
	if ( getUplink ) {
		uplink = ref_get_uplink( &client->image->uplinkref );
		if ( unlikely( uplink == NULL ) ) {
			uplink_init( client->image, -1, NULL, -1 );
			uplink = ref_get_uplink( &client->image->uplinkref );
			if ( uplink == NULL ) {
				logadd( LOG_DEBUG1, "Uplink request for image with no uplink" );
				return false;
			}
		}
	}
	if ( uplink->shutdown ) {
		logadd( LOG_DEBUG1, "Uplink request for image with uplink shutting down" );
		goto fail_ref;
	}
	// Check if the client is the same host as the uplink. If so assume this is a circular proxy chain
	// This might be a false positive if there are multiple instances running on the same host (IP)
	if ( client != NULL && hops > 1
			&& isSameAddress( altservers_indexToHost( uplink->current.index ), &client->host ) ) {
		uplink->cycleDetected = true;
		signal_call( uplink->signal );
		logadd( LOG_WARNING, "Proxy cycle detected (same host)." );
		goto fail_ref;
	}

	struct {
		uint64_t handle, start, end;
	} req;
	do {
		const uint64_t end = start + length;
		dnbd3_queue_entry_t *request = NULL, *last = NULL;
		bool isNew;
		mutex_lock( &uplink->queueLock );
		if ( uplink->shutdown ) { // Check again after locking to prevent lost requests
			goto fail_lock;
		}
		for ( dnbd3_queue_entry_t *it = uplink->queue; it != NULL; it = it->next ) {
			if ( it->from <= start && it->to >= end ) {
				// Matching range, attach
				request = it;
				break;
			}
			if ( it->next == NULL ) {
				// Not matching, last in list, remember
				last = it;
				break;
			}
		}
		dnbd3_queue_client_t **c;
		if ( request == NULL ) {
			// No existing request to attach to
			if ( uplink->queueLen >= UPLINK_MAX_QUEUE ) {
				logadd( LOG_WARNING, "Uplink queue is full, consider increasing UPLINK_MAX_QUEUE. Dropping client..." );
				goto fail_lock;
			}
			uplink->queueLen++;
			if ( uplink->queueLen > SERVER_UPLINK_QUEUELEN_THRES ) {
				uplink->image->problem.queue = true;
			}
			request = malloc( sizeof(*request) );
			if ( last == NULL ) {
				uplink->queue = request;
			} else {
				last->next = request;
			}
			request->next = NULL;
			request->handle = ++uplink->queueId;
			request->from = start & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
			request->to = (end + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
#ifdef _DEBUG
			timing_get( &request->entered );
#endif
			request->hopCount = hops;
			request->sent = true; // Optimistic; would be set to false on failure
			if ( client == NULL ) {
				// BGR
				request->clients = NULL;
			} else {
				c = &request->clients;
			}
			isNew = true;
		} else if ( client == NULL ) {
			// Replication request that maches existing request. Do nothing
			isNew = false;
		} else {
			// Existing request. Check if potential cycle
			if ( hops > request->hopCount && request->from == start && request->to == end ) {
				logadd( LOG_DEBUG1, "Request cycle detected on uplink for %s:%d", PIMG(uplink->image) );
				goto fail_lock;
			}
			// Count number if clients, get tail of list
			int count = 0;
			c = &request->clients;
			while ( *c != NULL ) {
				c = &(**c).next;
				if ( ++count >= UPLINK_MAX_CLIENTS_PER_REQUEST ) {
					logadd( LOG_DEBUG2, "Won't accept more than %d clients per request, dropping client", count );
					goto fail_lock;
				}
			}
			isNew = false;
		}
		req.handle = request->handle;
		req.start = request->from;
		req.end = request->to;
		if ( client != NULL ) {
			*c = malloc( sizeof( *request->clients ) );
			(**c).next = NULL;
			(**c).handle = handle;
			(**c).from = start;
			(**c).to = end;
			(**c).client = client;
			client->relayedCount++;
		}
		mutex_unlock( &uplink->queueLock );

		if ( !isNew ) {
			goto success_ref; // Attached to pending request, do nothing
		}
	} while (0);

	// Fire away the request
	mutex_lock( &uplink->sendMutex );
	if ( unlikely( uplink->current.fd == -1 ) ) {
		uplink->image->problem.uplink = true;
		markRequestUnsent( uplink, req.handle );
		mutex_unlock( &uplink->sendMutex );
		logadd( LOG_DEBUG2, "Cannot do direct uplink request: No socket open" );
	} else {
		const bool ret = dnbd3_get_block( uplink->current.fd, req.start,
				(uint32_t)( req.end - req.start ), req.handle,
				COND_HOPCOUNT( uplink->current.version, hops ) );
		if ( unlikely( !ret ) ) {
			markRequestUnsent( uplink, req.handle );
			uplink->image->problem.uplink = true;
			mutex_unlock( &uplink->sendMutex );
			logadd( LOG_DEBUG2, "Could not send out direct uplink request, queueing (%"PRIu64")", req.handle );
		} else {
			// OK
			mutex_unlock( &uplink->sendMutex );
			goto success_ref;
		}
		// Fall through to waking up sender thread
	}

	if ( signal_call( uplink->signal ) == SIGNAL_ERROR ) {
		logadd( LOG_WARNING, "Cannot wake up uplink thread; errno=%d", (int)errno );
	}

success_ref:
	if ( client != NULL ) {
		// Was from client -- potential prefetch
		// Same size as this request, but consider end of image...
		uint32_t len = (uint32_t)MIN( uplink->image->virtualFilesize - req.end,
				req.end - req.start );
		// Also don't prefetch if we cross a hash block border and BGR mode == hashblock
		if ( len > 0 && ( _backgroundReplication != BGR_HASHBLOCK
					|| req.start % HASH_BLOCK_SIZE == (req.end-1) % HASH_BLOCK_SIZE ) ) {
			prefetch_job_t *job = malloc( sizeof( *job ) );
			job->start = req.end;
			job->length = len;
			job->uplink = uplink;
			ref_inc( &uplink->reference ); // Hold one for the thread, thread will return it
			threadpool_run( &prefetchForClient, (void*)job, "PREFETCH" );
		}
	}
	if ( getUplink ) {
		ref_put( &uplink->reference );
	}
	return true;
fail_lock:
	mutex_unlock( &uplink->queueLock );
fail_ref:
	if ( getUplink ) {
		ref_put( &uplink->reference );
	}
	return false;
}

static void *prefetchForClient(void *data)
{
	prefetch_job_t *job = (prefetch_job_t*)data;
	dnbd3_cache_map_t *cache = ref_get_cachemap( job->uplink->image );
	if ( cache != NULL ) {
		if ( !image_isRangeCachedUnsafe( cache, job->start, job->start + job->length ) ) {
			uplink_request( job->uplink, NULL, ++job->uplink->queueId, job->start, job->length, 0 );
		}
		ref_put( &cache->reference );
	}
	ref_put( &job->uplink->reference ); // Acquired in uplink_request
	free( job );
	return NULL;
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
	int numSocks, waitTime;
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
	if ( !reopenCacheFd( uplink, false ) ) {
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
			else if ( waitTime > 10000 ) waitTime = 10000;
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
			uplink->image->problem.uplink = false;
			uplink->replicatedLastBlock = false; // Reset this to be safe - request could've been sent but reply was never received
			buffer[0] = '@';
			if ( altservers_toString( uplink->current.index, buffer + 1, sizeof(buffer) - 1 ) ) {
				logadd( LOG_DEBUG1, "(Uplink %s) Now connected to %s\n", uplink->image->name, buffer + 1 );
				setThreadName( buffer );
			}
			// If we don't have a crc32 list yet, see if the new server has one
			if ( uplink->image->crc32 == NULL ) {
				requestCrc32List( uplink );
			}
			// Re-send all pending requests
			sendQueuedRequests( uplink, false );
			sendReplicationRequest( uplink );
			events[EV_SOCKET].events = POLLIN | POLLRDHUP;
			if ( uplink->image->problem.uplink ) {
				// Some of the requests above must have failed again already :-(
				logadd( LOG_DEBUG1, "Newly established uplink connection failed during getCRC or sendRequests" );
				connectionFailed( uplink, true );
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
				sendQueuedRequests( uplink, true );
			} else if ( uplink->queueLen != 0 ) { // No uplink; maybe it was shutdown since it was idle for too long
				uplink->idleTime = 0;
			}
		}
		// Uplink socket
		if ( (events[EV_SOCKET].revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) ) {
			connectionFailed( uplink, true );
			logadd( LOG_DEBUG1, "Uplink gone away, panic! (revents=%d)\n", (int)events[EV_SOCKET].revents );
			setThreadName( "panic-uplink" );
		} else if ( (events[EV_SOCKET].revents & POLLIN) ) {
			handleReceive( uplink );
			if ( _shutdown || uplink->shutdown ) goto cleanup;
		}
		declare_now;
		uint32_t timepassed = timing_diff( &lastKeepalive, &now );
		if ( timepassed >= SERVER_UPLINK_KEEPALIVE_INTERVAL
				|| ( timepassed >= 2 && uplink->idleTime < _bgrWindowSize ) ) {
			lastKeepalive = now;
			uplink->idleTime += timepassed;
			// Keep-alive
			if ( uplink->current.fd != -1 && uplink->queueLen < _bgrWindowSize ) {
				// Send keep-alive if nothing is happening, and try to trigger background rep.
				if ( !sendKeepalive( uplink ) || !sendReplicationRequest( uplink ) ) {
					connectionFailed( uplink, true );
					logadd( LOG_DEBUG1, "Error sending keep-alive/BGR, panic!\n" );
				}
			}
			// Don't keep uplink established if we're idle for too much
			if ( connectionShouldShutdown( uplink ) ) {
				logadd( LOG_DEBUG1, "Closing idle uplink for image %s:%d", PIMG(uplink->image) );
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
			for ( dnbd3_queue_entry_t *it = uplink->queue; it != NULL; it = it->next ) {
				if ( timing_reached( &it->entered, &deadline ) ) {
					logadd( LOG_WARNING, "Starving request detected:"
							" (from %" PRIu64 " to %" PRIu64 ", sent: %d) %s:%d",
							it->from, it->to, (int)it->sent, PIMG(uplink->image) );
					it->entered = now;
#ifdef _DEBUG_RESEND_STARVING
					it->sent = false;
					resend = true;
#endif
				}
			}
			mutex_unlock( &uplink->queueLock );
			if ( resend ) {
				sendQueuedRequests( uplink, true );
			}
		}
#endif
	}
cleanup: ;
	dnbd3_image_t *image = uplink->image;
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	if ( cache != NULL ) {
		cache->dirty = true; // Force writeout of cache map
		ref_put( &cache->reference );
	}
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
static void sendQueuedRequests(dnbd3_uplink_t *uplink, bool newOnly)
{
	assert_uplink_thread();
	// Scan for new requests, or optionally, (re)send all
	// Build a buffer, so if there aren't too many requests, we can send them after
	// unlocking the queue again. Otherwise we need flushes during iteration, which
	// is no ideal, but in that case the uplink is probably overwhelmed anyways.
	// Try 125 as that's exactly 300bytes, usually 2*MTU.
#define MAX_RESEND_BATCH 125
	dnbd3_request_t reqs[MAX_RESEND_BATCH];
	int count = 0;
	mutex_lock( &uplink->queueLock );
	for ( dnbd3_queue_entry_t *it = uplink->queue; it != NULL; it = it->next ) {
		if ( newOnly && it->sent )
			continue;
		it->sent = true;
		dnbd3_request_t *hdr = &reqs[count++];
		hdr->magic = dnbd3_packet_magic;
		hdr->cmd = CMD_GET_BLOCK;
		hdr->size = (uint32_t)( it->to - it->from );
		hdr->offset = it->from; // Offset first, then hops! (union)
		hdr->hops = COND_HOPCOUNT( uplink->current.version, it->hopCount );
		hdr->handle = it->handle;
		fixup_request( *hdr );
		if ( count == MAX_RESEND_BATCH ) {
			bool ok = false;
			logadd( LOG_DEBUG2, "BLOCKING resend of %d", count );
			count = 0;
			mutex_lock( &uplink->sendMutex );
			if ( uplink->current.fd != -1 ) {
				ok = ( sock_sendAll( uplink->current.fd, reqs, DNBD3_REQUEST_SIZE * MAX_RESEND_BATCH, 3 )
						== DNBD3_REQUEST_SIZE * MAX_RESEND_BATCH );
			}
			mutex_unlock( &uplink->sendMutex );
			if ( !ok ) {
				uplink->image->problem.uplink = true;
				break;
			}
		}
	}
	mutex_unlock( &uplink->queueLock );
	if ( count != 0 ) {
		mutex_lock( &uplink->sendMutex );
		if ( uplink->current.fd != -1 ) {
			uplink->image->problem.uplink =
				( sock_sendAll( uplink->current.fd, reqs, DNBD3_REQUEST_SIZE * count, 3 )
					!= DNBD3_REQUEST_SIZE * count );
		}
		mutex_unlock( &uplink->sendMutex );
	}
#undef MAX_RESEND_BATCH
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
static bool sendReplicationRequest(dnbd3_uplink_t *uplink)
{
	assert_uplink_thread();
	if ( uplink->current.fd == -1 )
		return false; // Should never be called in this state, consider send error
	if ( _backgroundReplication == BGR_DISABLED || uplink->cacheFd == -1 )
		return true; // Don't do background replication
	if ( uplink->nextReplicationIndex == -1 )
		return true; // No more blocks to replicate
	dnbd3_image_t * const image = uplink->image;
	if ( image->users < _bgrMinClients )
		return true; // Not enough active users
	const int numNewRequests = numWantedReplicationRequests( uplink );
	if ( numNewRequests <= 0 )
		return true; // Already sufficient amount of requests on the wire
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	if ( cache == NULL ) {
		// No cache map (=image complete)
		return true;
	}
	const int mapBytes = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
	const int lastBlockIndex = mapBytes - 1;
	for ( int bc = 0; bc < numNewRequests; ++bc ) {
		int endByte;
		if ( UPLINK_MAX_QUEUE - uplink->queueLen < 10 )
			break; // Don't overload queue
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
		if ( replicationIndex == -1 && _backgroundReplication == BGR_HASHBLOCK ) {
			// Nothing left in current block, find next one
			replicationIndex = findNextIncompleteHashBlock( uplink, endByte );
		}
		if ( replicationIndex == -1 ) {
			// Replication might be complete, uplink_mainloop should take care....
			uplink->nextReplicationIndex = -1;
			break;
		}
		const uint64_t offset = (uint64_t)replicationIndex * FILE_BYTES_PER_MAP_BYTE;
		const uint32_t size = (uint32_t)MIN( image->virtualFilesize - offset, FILE_BYTES_PER_MAP_BYTE );
		const uint64_t handle = ++uplink->queueId;
		if ( !uplink_request( uplink, NULL, handle, offset, size, 0 ) ) {
			logadd( LOG_DEBUG1, "Error sending background replication request to uplink server (%s:%d)",
					PIMG(uplink->image) );
			ref_put( &cache->reference );
			return false;
		}
		if ( replicationIndex == lastBlockIndex ) {
			uplink->replicatedLastBlock = true; // Special treatment, last byte in map could represent less than 8 blocks
		}
		uplink->nextReplicationIndex = replicationIndex + 1; // Remember last incomplete offset for next time so we don't play Schlemiel the painter
		if ( _backgroundReplication == BGR_HASHBLOCK
				&& uplink->nextReplicationIndex % MAP_BYTES_PER_HASH_BLOCK == 0 ) {
			// Just crossed a hash block boundary, look for new candidate starting at this very index
			uplink->nextReplicationIndex = findNextIncompleteHashBlock( uplink, uplink->nextReplicationIndex );
			if ( uplink->nextReplicationIndex == -1 )
				break;
		}
	}
	ref_put( &cache->reference );
	return true;
}

/**
 * find next index into cache map that corresponds to the beginning
 * of a hash block which is neither completely empty nor completely
 * replicated yet. Returns -1 if no match.
 */
static int findNextIncompleteHashBlock(dnbd3_uplink_t *uplink, const int startMapIndex)
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
static void handleReceive(dnbd3_uplink_t *uplink)
{
	dnbd3_reply_t inReply, outReply;
	int ret;
	assert_uplink_thread();
	for (;;) {
		ret = dnbd3_read_reply( uplink->current.fd, &inReply, false );
		if ( unlikely( ret == REPLY_INTR ) && likely( !_shutdown && !uplink->shutdown ) ) continue;
		if ( ret == REPLY_AGAIN ) break;
		if ( unlikely( ret == REPLY_CLOSED ) ) {
			logadd( LOG_INFO, "Uplink: Remote host hung up (%s:%d)", PIMG(uplink->image) );
			goto error_cleanup;
		}
		if ( unlikely( ret == REPLY_WRONGMAGIC ) ) {
			logadd( LOG_WARNING, "Uplink server's packet did not start with dnbd3_packet_magic (%s:%d)", PIMG(uplink->image) );
			goto error_cleanup;
		}
		if ( unlikely( ret != REPLY_OK ) ) {
			logadd( LOG_INFO, "Uplink: Connection error %d (%s:%d)", ret, PIMG(uplink->image) );
			goto error_cleanup;
		}
		if ( unlikely( inReply.size > (uint32_t)_maxPayload ) ) {
			logadd( LOG_WARNING, "Pure evil: Uplink server sent too much payload (%" PRIu32 ") for %s:%d", inReply.size, PIMG(uplink->image) );
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
			logadd( LOG_INFO, "Lost connection to uplink server of %s:%d (payload)", PIMG(uplink->image) );
			goto error_cleanup;
		}
		// Payload read completely
		// Bail out if we're not interested
		if ( unlikely( inReply.cmd != CMD_GET_BLOCK ) )
			continue;
		// Is a legit block reply
		totalBytesReceived += inReply.size;
		uplink->bytesReceived += inReply.size;
		// Get entry from queue
		dnbd3_queue_entry_t *entry;
		mutex_lock( &uplink->queueLock );
		for ( entry = uplink->queue; entry != NULL; entry = entry->next ) {
			if ( entry->handle == inReply.handle )
				break;
		}
		if ( entry == NULL ) {
			mutex_unlock( &uplink->queueLock ); // Do not dereference pointer after unlock!
			logadd( LOG_DEBUG1, "Received block reply on uplink, but handle %"PRIu64" is unknown (%s:%d)",
					inReply.handle, PIMG(uplink->image) );
			continue;
		}
		const uint64_t start = entry->from;
		const uint64_t end = entry->to;
		mutex_unlock( &uplink->queueLock ); // Do not dereference pointer after unlock!
		// We don't remove the entry from the list here yet, to slightly increase the chance of other
		// clients attaching to this request while we write the data to disk
		if ( end - start != inReply.size ) {
			logadd( LOG_WARNING, "Received payload length does not match! (is: %"PRIu32", expect: %u, %s:%d)",
					inReply.size, (unsigned int)( end - start ), PIMG(uplink->image) );
		}
		struct iovec iov[2];
		// 1) Write to cache file
		if ( unlikely( uplink->cacheFd == -1 ) ) {
			reopenCacheFd( uplink, false );
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
						if ( !tryAgain || !reopenCacheFd( uplink, true ) )
							break;
						tryAgain = false;
						continue; // Write handle to image successfully re-opened, try again
					}
					logadd( LOG_DEBUG1, "Error trying to cache data for %s:%d -- errno=%d",
							PIMG(uplink->image), err );
					break;
				}
				if ( unlikely( ret <= 0 || (uint32_t)ret > inReply.size - done ) ) {
					logadd( LOG_WARNING, "Unexpected return value %d from pwrite to %s:%d",
							ret, PIMG(uplink->image) );
					break;
				}
				done += (uint32_t)ret;
			}
			if ( likely( done > 0 ) ) {
				image_updateCachemap( uplink->image, start, start + done, true );
			}
			if ( unlikely( ret == -1 && ( err == EBADF || err == EINVAL || err == EIO ) ) ) {
				logadd( LOG_WARNING, "Error writing received data for %s:%d (errno=%d); disabling caching.",
						PIMG(uplink->image), err );
			}
		}
		bool found = false;
		dnbd3_queue_entry_t **it;
		mutex_lock( &uplink->queueLock );
		for ( it = &uplink->queue; *it != NULL; it = &(**it).next ) {
			if ( *it == entry && entry->handle == inReply.handle ) { // ABA check
				assert( found == false );
				*it = (**it).next;
				found = true;
				uplink->queueLen--;
				break;
			}
		}
		if ( uplink->queueLen < SERVER_UPLINK_QUEUELEN_THRES ) {
			uplink->image->problem.queue = false;
		}
		mutex_unlock( &uplink->queueLock );
		if ( !found ) {
			logadd( LOG_DEBUG1, "Replication request vanished from queue after writing to disk (%s:%d)",
					PIMG(uplink->image) );
			continue;
		}
		outReply.magic = dnbd3_packet_magic;
		dnbd3_queue_client_t *next;
		for ( dnbd3_queue_client_t *c = entry->clients; c != NULL; c = next ) {
			assert( c->from >= start && c->to <= end );
			dnbd3_client_t * const client = c->client;
			outReply.cmd = CMD_GET_BLOCK;
			outReply.handle = c->handle;
			outReply.size = (uint32_t)( c->to - c->from );
			iov[0].iov_base = &outReply;
			iov[0].iov_len = sizeof outReply;
			iov[1].iov_base = uplink->recvBuffer + (c->from - start);
			iov[1].iov_len = outReply.size;
			fixup_reply( outReply );
			mutex_lock( &client->sendMutex );
			if ( client->sock != -1 ) {
				ssize_t sent = writev( client->sock, iov, 2 );
				if ( sent > (ssize_t)sizeof outReply ) {
					client->bytesSent += (size_t)sent - sizeof outReply;
				}
			}
			mutex_unlock( &client->sendMutex );
			client->relayedCount--;
			next = c->next;
			free( c );
		}
		if ( entry->clients != NULL ) {
			// Was some client -- reset idle counter
			uplink->idleTime = 0;
			// Re-enable replication if disabled
			if ( uplink->nextReplicationIndex == -1 ) {
				uplink->nextReplicationIndex = (int)( start / FILE_BYTES_PER_MAP_BYTE ) & MAP_INDEX_HASH_START_MASK;
			}
		} else {
			if ( uplink->cacheFd != -1 ) {
				// Try to remove from fs cache if no client was interested in this data
				posix_fadvise( uplink->cacheFd, start, inReply.size, POSIX_FADV_DONTNEED );
			}
		}
		free( entry );
	} // main receive loop
	// Trigger background replication if applicable
	if ( !sendReplicationRequest( uplink ) ) {
		goto error_cleanup;
	}
	// Normal end
	return;
	// Error handling from failed receive or message parsing
error_cleanup: ;
	connectionFailed( uplink, true );
}

/**
 * Only call from uplink thread
 */
static void connectionFailed(dnbd3_uplink_t *uplink, bool findNew)
{
	assert_uplink_thread();
	if ( uplink->current.fd == -1 )
		return;
	setThreadName( "panic-uplink" );
	altservers_serverFailed( uplink->current.index );
	mutex_lock( &uplink->sendMutex );
	uplink->image->problem.uplink = true;
	close( uplink->current.fd );
	uplink->current.fd = -1;
	mutex_unlock( &uplink->sendMutex );
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
static bool sendKeepalive(dnbd3_uplink_t *uplink)
{
	static const dnbd3_request_t request = { .magic = dnbd3_packet_magic, .cmd = net_order_16( CMD_KEEPALIVE ) };
	assert_uplink_thread();
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
static void requestCrc32List(dnbd3_uplink_t *uplink)
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
		logadd( LOG_WARNING, "Received corrupted crc32 list from uplink server (%s:%d)!", PIMG(uplink->image) );
		free( buffer );
		return;
	}
	uplink->image->masterCrc32 = masterCrc;
	uplink->image->crc32 = buffer;
	const size_t len = strlen( uplink->image->path ) + 30;
	char path[len];
	snprintf( path, len, "%s.crc", uplink->image->path );
	const int fd = open( path, O_WRONLY | O_CREAT, 0644 );
	if ( fd != -1 ) {
		ssize_t ret = write( fd, &masterCrc, sizeof(masterCrc) );
		ret += write( fd, buffer, bytes );
		close( fd );
		if ( (size_t)ret != sizeof(masterCrc) + bytes ) {
			unlink( path );
			logadd( LOG_WARNING, "Could not write crc32 file for %s:%d", PIMG(uplink->image) );
		}
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
static bool reopenCacheFd(dnbd3_uplink_t *uplink, const bool force)
{
	if ( uplink->cacheFd != -1 ) {
		if ( !force ) return true;
		close( uplink->cacheFd );
	}
	uplink->cacheFd = open( uplink->image->path, O_WRONLY | O_CREAT, 0644 );
	uplink->image->problem.write = uplink->cacheFd == -1;
	return uplink->cacheFd != -1;
}

/**
 * Returns true if the uplink has been idle for some time (apart from
 * background replication, if it is set to hashblock, or if it has
 * a minimum number of active clients configured that is not currently
 * reached)
 */
static bool connectionShouldShutdown(dnbd3_uplink_t *uplink)
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

/**
 * Get number of replication requests that should be sent right now to
 * meet the configured bgrWindowSize. Returns 0 if any client requests
 * are pending.
 * This applies a sort of "slow start" in case the uplink was recently
 * dealing with actual client requests, in that the uplink's idle time
 * (in seconds) is an upper bound for the number returned, so we don't
 * saturate the uplink with loads of requests right away, in case that
 * client triggers more requests to the uplink server.
 */
static int numWantedReplicationRequests(dnbd3_uplink_t *uplink)
{
	int ret = MIN( _bgrWindowSize, uplink->idleTime + 1 );
	if ( uplink->queueLen == 0 )
		return ret;
	mutex_lock( &uplink->queueLock );
	for ( dnbd3_queue_entry_t *it = uplink->queue; it != NULL; it = it->next ) {
		if ( it->clients == NULL ) {
			ret--;
		} else {
			ret = 0; // Do not allow BGR if client requests are being handled
			break;
		}
	}
	mutex_unlock( &uplink->queueLock );
	return ret;
}

static void markRequestUnsent(dnbd3_uplink_t *uplink, uint64_t handle)
{
	mutex_lock( &uplink->queueLock );
	for ( dnbd3_queue_entry_t *it = uplink->queue; it != NULL; it = it->next ) {
		if ( it->handle == handle ) {
			it->sent = false;
			break;
		}
	}
	mutex_unlock( &uplink->queueLock );
}

