#include "altservers.h"
#include "uplink.h"
#include "locks.h"
#include "../shared/sockhelper.h"
#include "../shared/log.h"
#include "helper.h"
#include "globals.h"
#include "image.h"
#include "../shared/signal.h"
#include "../shared/log.h"
#include "../shared/protocol.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <math.h>
#include <assert.h>
#include <inttypes.h>
#include <time.h>
#include <stdio.h>

static dnbd3_connection_t *pending[SERVER_MAX_PENDING_ALT_CHECKS];
static pthread_spinlock_t pendingLockWrite; // Lock for adding something to pending. (NULL -> nonNULL)
static pthread_mutex_t pendingLockConsume = PTHREAD_MUTEX_INITIALIZER; // Lock for removing something (nonNULL -> NULL)
static int signalFd = -1;

static dnbd3_alt_server_t altServers[SERVER_MAX_ALTS];
static int numAltServers = 0;
static pthread_spinlock_t altServersLock;
static bool initDone = false;

static pthread_t altThread;

static void *altservers_main(void *data);
static unsigned int altservers_updateRtt(const dnbd3_host_t * const host, const unsigned int rtt);

int altservers_getCount()
{
	return numAltServers;
}

void altservers_init()
{
	spin_init( &pendingLockWrite, PTHREAD_PROCESS_PRIVATE );
	spin_init( &altServersLock, PTHREAD_PROCESS_PRIVATE );
	memset( altServers, 0, SERVER_MAX_ALTS * sizeof(dnbd3_alt_server_t) );
	if ( 0 != thread_create( &altThread, NULL, &altservers_main, (void *)NULL ) ) {
		logadd( LOG_ERROR, "Could not start altservers connector thread" );
		exit( EXIT_FAILURE );
	}
	initDone = true;
}

void altservers_shutdown()
{
	if ( !initDone ) return;
	signal_call( signalFd ); // Wake altservers thread up
	thread_join( altThread, NULL );
}

int altservers_load()
{
	int count = 0;
	char *name = NULL, *space;
	char buffer[1000], *line;
	dnbd3_host_t host;
	asprintf( &name, "%s/%s", _configDir, "alt-servers" );
	if ( name == NULL ) return -1;
	FILE *fp = fopen( name, "r" );
	free( name );
	if ( fp == NULL ) return -1;
	while ( fgets( buffer, 1000, fp ) != NULL ) {
		bool isPrivate = false;
		bool isClientOnly = false;
		for (line = buffer; *line != '\0'; ) { // Trim left and scan for "-" prefix
			if ( *line == '-' ) isPrivate = true;
			else if ( *line == '+' ) isClientOnly = true;
			else if ( *line != ' ' && *line != '\t' ) break;
			line++;
		}
		if ( *line == '\r' || *line == '\n' || *line == '\0' ) continue; // Ignore empty lines
		trim_right( line );
		space = line;
		while ( *space != '\0' ) {
			if ( *space == ' ' || *space == '\t' ) break;
			space++;
		}
		if ( *space == '\0' ) space = NULL;
		else *space++ = '\0';
		if ( !parse_address( line, &host ) ) {
			if ( space != NULL ) *--space = ' ';
			logadd( LOG_WARNING, "Invalid entry in alt-servers file ignored: '%s'", line );
			continue;
		}
		if ( altservers_add( &host, space, isPrivate, isClientOnly ) ) ++count;
	}
	fclose( fp );
	logadd( LOG_DEBUG1, "Added %d alt servers\n", count );
	return count;
}

bool altservers_add(dnbd3_host_t *host, const char *comment, const int isPrivate, const int isClientOnly)
{
	int i, freeSlot = -1;
	spin_lock( &altServersLock );
	for (i = 0; i < numAltServers; ++i) {
		if ( isSameAddressPort( &altServers[i].host, host ) ) {
			spin_unlock( &altServersLock );
			return false;
		} else if ( freeSlot == -1 && altServers[i].host.type == 0 ) {
			freeSlot = i;
		}
	}
	if ( freeSlot == -1 ) {
		if ( numAltServers >= SERVER_MAX_ALTS ) {
			logadd( LOG_WARNING, "Cannot add another alt server, maximum of %d already reached.", (int)SERVER_MAX_ALTS );
			spin_unlock( &altServersLock );
			return false;
		}
		freeSlot = numAltServers++;
	}
	altServers[freeSlot].host = *host;
	altServers[freeSlot].isPrivate = isPrivate;
	altServers[freeSlot].isClientOnly = isClientOnly;
	if ( comment != NULL ) snprintf( altServers[freeSlot].comment, COMMENT_LENGTH, "%s", comment );
	spin_unlock( &altServersLock );
	return true;
}

/**
 * ONLY called from the passed uplink's main thread
 */
void altservers_findUplink(dnbd3_connection_t *uplink)
{
	int i;
	// if betterFd != -1 it means the uplink is supposed to switch to another
	// server. As this function here is called by the uplink thread, it can
	// never be that the uplink is supposed to switch, but instead calls
	// this function.
	assert( uplink->betterFd == -1 );
	spin_lock( &pendingLockWrite );
	// it is however possible that an RTT measurement is currently in progress,
	// so check for that case and do nothing if one is in progress
	if ( uplink->rttTestResult == RTT_INPROGRESS ) {
		for (i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i) {
			if ( pending[i] != uplink ) continue;
			// Yep, measuring right now
			spin_unlock( &pendingLockWrite );
			return;
		}
	}
	// Find free slot for measurement
	for (i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i) {
		if ( pending[i] != NULL ) continue;
		pending[i] = uplink;
		uplink->rttTestResult = RTT_INPROGRESS;
		spin_unlock( &pendingLockWrite );
		signal_call( signalFd ); // Wake altservers thread up
		return;
	}
	// End of loop - no free slot
	spin_unlock( &pendingLockWrite );
	logadd( LOG_WARNING, "No more free RTT measurement slots, ignoring a request..." );
}

/**
 * The given uplink is about to disappear, so remove it from any queues
 */
void altservers_removeUplink(dnbd3_connection_t *uplink)
{
	pthread_mutex_lock( &pendingLockConsume );
	spin_lock( &pendingLockWrite );
	for (int i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i) {
		if ( pending[i] == uplink ) {
			uplink->rttTestResult = RTT_NOT_REACHABLE;
			pending[i] = NULL;
		}
	}
	spin_unlock( &pendingLockWrite );
	pthread_mutex_unlock( &pendingLockConsume );
}

/**
 * Get <size> known (working) alt servers, ordered by network closeness
 * (by finding the smallest possible subnet)
 * Private servers are excluded, so this is what you want to call to
 * get a list of servers you can tell a client about
 */
int altservers_getMatching(dnbd3_host_t *host, dnbd3_server_entry_t *output, int size)
{
	if ( host == NULL || host->type == 0 || numAltServers == 0 || output == NULL || size <= 0 ) return 0;
	int i, j;
	int count = 0;
	int distance[size];
	spin_lock( &altServersLock );
	for (i = 0; i < numAltServers; ++i) {
		if ( host->type != altServers[i].host.type ) continue; // Wrong address family
		if ( altServers[i].isPrivate ) continue; // Do not tell clients about private servers
		// TODO: Prefer same AF here, but if in the end we got less servers than requested, add
		// servers of other AF too (after this loop)
		if ( count == 0 ) {
			// Trivial - this is the first entry
			output[0].host = altServers[i].host;
			output[0].failures = 0;
			distance[0] = altservers_netCloseness( host, &output[0].host );
			count++;
		} else {
			// Other entries already exist, insert in proper position
			const int dist = altservers_netCloseness( host, &altServers[i].host );
			for (j = 0; j < size; ++j) {
				if ( j < count && dist <= distance[j] ) continue;
				if ( j > count ) break; // Should never happen but just in case...
				if ( j < count && j + 1 < size ) {
					// Check if we're in the middle and need to move other entries...
					memmove( &output[j + 1], &output[j], sizeof(dnbd3_server_entry_t) * (size - j - 1) );
					memmove( &distance[j + 1], &distance[j], sizeof(int) * (size - j - 1) );
				}
				if ( count < size ) {
					count++;
				}
				output[j].host = altServers[i].host;
				output[j].failures = 0;
				distance[j] = dist;
				break;
			}
		}
	}
	// TODO: "if count < size then add servers of other address families"
	spin_unlock( &altServersLock );
	return count;
}

/**
 * Get <size> alt servers. If there are more alt servers than
 * requested, random servers will be picked.
 * This function is suited for finding uplink servers as
 * it includes private servers and ignores any "client only" servers
 */
int altservers_get(dnbd3_host_t *output, int size, int emergency)
{
	if ( size <= 0 ) return 0;
	int count = 0, i;
	const time_t now = time( NULL );
	spin_lock( &altServersLock );
	// Flip first server in list with a random one every time this is called
	if ( numAltServers > 1 ) {
		const dnbd3_alt_server_t tmp = altServers[0];
		do {
			i = rand() % numAltServers;
		} while ( i == 0 );
		altServers[0] = altServers[i];
		altServers[i] = tmp;
	}
	for (i = 0; i < numAltServers; ++i) {
		if ( altServers[i].host.type == 0 ) continue; // Slot is empty
		if ( _proxyPrivateOnly && !altServers[i].isPrivate ) continue; // Config says to consider private alt-servers only? ignore!
		if ( altServers[i].isClientOnly ) continue;
		if ( !emergency && altServers[i].numFails > SERVER_MAX_UPLINK_FAILS // server failed X times in a row
			&& now - altServers[i].lastFail > SERVER_BAD_UPLINK_IGNORE ) continue; // and last fail was not too long ago? ignore!
		// server seems ok, include in output and reset its fail counter
		if ( !emergency ) altServers[i].numFails = 0;
		output[count++] = altServers[i].host;
		if ( count >= size ) break;
	}
	spin_unlock( &altServersLock );
	return count;
}

/**
 * Update rtt history of given server - returns the new average for that server
 */
static unsigned int altservers_updateRtt(const dnbd3_host_t * const host, const unsigned int rtt)
{
	unsigned int avg = rtt;
	int i;
	spin_lock( &altServersLock );
	for (i = 0; i < numAltServers; ++i) {
		if ( !isSameAddressPort( host, &altServers[i].host ) ) continue;
		altServers[i].rtt[++altServers[i].rttIndex % SERVER_RTT_PROBES] = rtt;
#if SERVER_RTT_PROBES == 5
		avg = (altServers[i].rtt[0] + altServers[i].rtt[1] + altServers[i].rtt[2] + altServers[i].rtt[3] + altServers[i].rtt[4])
		        / SERVER_RTT_PROBES;
#else
#warning You might want to change the code in altservers_update_rtt if you changed SERVER_RTT_PROBES
		avg = 0;
		for (int j = 0; j < SERVER_RTT_PROBES; ++j) {
			avg += altServers[i].rtt[j];
		}
		avg /= SERVER_RTT_PROBES;
#endif
		break;
	}
	spin_unlock( &altServersLock );
	return avg;
}

/**
 * Determine how close two addresses are to each other by comparing the number of
 * matching bits from the left of the address. Does not count individual bits but
 * groups of 4 for speed.
 * Return: Closeness - higher number means closer
 */
int altservers_netCloseness(dnbd3_host_t *host1, dnbd3_host_t *host2)
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

/**
 * Called if an uplink server failed during normal uplink operation. This unit keeps
 * track of how often servers fail, and consider them disabled for some time if they
 * fail too many times.
 */
void altservers_serverFailed(const dnbd3_host_t * const host)
{
	int i;
	const time_t now = time( NULL );
	spin_lock( &altServersLock );
	for (i = 0; i < numAltServers; ++i) {
		if ( !isSameAddressPort( host, &altServers[i].host ) ) continue;
		// Do only increase counter if last fail was not too recent. This is
		// to prevent the counter from increasing rapidly if many images use the
		// same uplink. If there's a network hickup, all uplinks will call this
		// function and would increase the counter too quickly, disabling the server.
		if ( now - altServers[i].lastFail > SERVER_RTT_DELAY_INIT ) {
			altServers[i].numFails++;
			altServers[i].lastFail = now;
		}
		break;
	}
	spin_unlock( &altServersLock );
}
/**
 * Mainloop of this module. It will wait for requests by uplinks to find a
 * suitable uplink server for them. If found, it will tell the uplink about
 * the best server found. Currently the RTT history is kept per server and
 * not per uplink, so if many images use the same uplink server, the history
 * will update quite quickly. Needs to be improved some time, ie. by only
 * updating the rtt if the last update was at least X seconds ago.
 */
static void *altservers_main(void *data UNUSED)
{
	const int ALTS = 4;
	int ret, itLink, itAlt, numAlts;
	bool found;
	char buffer[DNBD3_BLOCK_SIZE ];
	dnbd3_reply_t reply;
	dnbd3_host_t servers[ALTS + 1];
	serialized_buffer_t serialized;
	struct timespec start, end;
	time_t nextCacheMapSave = time( NULL ) + 90;

	setThreadName( "altserver-check" );
	blockNoncriticalSignals();
	// Init spinlock
	// Init waiting links queue
	spin_lock( &pendingLockWrite );
	for (int i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i)
		pending[i] = NULL;
	spin_unlock( &pendingLockWrite );
	// Init signal-pipe
	signalFd = signal_new();
	if ( signalFd < 0 ) {
		logadd( LOG_WARNING, "error creating signal object. Uplink feature unavailable." );
		goto cleanup;
	}
	// LOOP
	while ( !_shutdown ) {
		// Wait 5 seconds max.
		ret = signal_wait( signalFd, 5000 );
		if ( _shutdown ) goto cleanup;
		if ( ret == SIGNAL_ERROR ) {
			if ( errno == EAGAIN || errno == EINTR ) continue;
			logadd( LOG_WARNING, "Error on signal_clear on alservers_main! Things will break!" );
			usleep( 100000 );
		}
		// Work your way through the queue
		for (itLink = 0; itLink < SERVER_MAX_PENDING_ALT_CHECKS; ++itLink) {
			spin_lock( &pendingLockWrite );
			if ( pending[itLink] == NULL ) {
				spin_unlock( &pendingLockWrite );
				continue; // Check once before locking, as a mutex is expensive
			}
			spin_unlock( &pendingLockWrite );
			pthread_mutex_lock( &pendingLockConsume );
			spin_lock( &pendingLockWrite );
			dnbd3_connection_t * const uplink = pending[itLink];
			spin_unlock( &pendingLockWrite );
			if ( uplink == NULL ) { // Check again after locking
				pthread_mutex_unlock( &pendingLockConsume );
				continue;
			}
			dnbd3_image_t * const image = image_lock( uplink->image );
			if ( image == NULL ) { // Check again after locking
				uplink->rttTestResult = RTT_NOT_REACHABLE;
				spin_lock( &pendingLockWrite );
				pending[itLink] = NULL;
				spin_unlock( &pendingLockWrite );
				pthread_mutex_unlock( &pendingLockConsume );
				logadd( LOG_DEBUG1, "Image has gone away that was queued for RTT measurement\n" );
				continue;
			}
			assert( uplink->rttTestResult == RTT_INPROGRESS );
			// Now get 4 alt servers
			numAlts = altservers_get( servers, ALTS, uplink->fd == -1 );
			if ( uplink->fd != -1 ) {
				// Add current server if not already in list
				found = false;
				for (itAlt = 0; itAlt < numAlts; ++itAlt) {
					if ( !isSameAddressPort( &uplink->currentServer, &servers[itAlt] ) ) continue;
					found = true;
					break;
				}
				if ( !found ) servers[numAlts++] = uplink->currentServer;
			}
			// Test them all
			int bestSock = -1;
			int bestIndex = -1;
			unsigned int bestRtt = 0xfffffff;
			unsigned int currentRtt = 0xfffffff;
			for (itAlt = 0; itAlt < numAlts; ++itAlt) {
				usleep( 1000 ); // Wait a very short moment for the network to recover (we might be doing lots of measurements...)
				// Connect
				clock_gettime( CLOCK_MONOTONIC_RAW, &start );
				int sock = sock_connect( &servers[itAlt], 750, _uplinkTimeout );
				if ( sock < 0 ) continue;
				// Select image ++++++++++++++++++++++++++++++
				if ( !dnbd3_select_image( sock, image->name, image->rid, FLAGS8_SERVER ) ) {
					goto server_failed;
				}
				// See if selecting the image succeeded ++++++++++++++++++++++++++++++
				uint16_t protocolVersion, rid;
				uint64_t imageSize;
				char *name;
				if ( !dnbd3_select_image_reply( &serialized, sock, &protocolVersion, &name, &rid, &imageSize ) ) {
					goto server_image_not_available;
				}
				if ( protocolVersion < MIN_SUPPORTED_SERVER ) goto server_failed;
				if ( name == NULL || strcmp( name, image->name ) != 0 ) {
					ERROR_GOTO( server_failed, "[RTT] Server offers image '%s', requested '%s'", name, image->name );
				}
				if ( rid != image->rid ) {
					ERROR_GOTO( server_failed, "[RTT] Server provides rid %d, requested was %d (%s)",
					        (int)rid, (int)image->rid, image->name );
				}
				if ( imageSize != image->virtualFilesize ) {
					ERROR_GOTO( server_failed, "[RTT] Remote size: %" PRIu64 ", expected: %" PRIu64 " (%s)",
					        imageSize, image->virtualFilesize, image->name );
				}
				// Request first block (NOT random!) ++++++++++++++++++++++++++++++
				fixup_request( request );
				if ( !dnbd3_get_block( sock, 0, DNBD3_BLOCK_SIZE, 0 ) ) {
					ERROR_GOTO( server_failed, "[RTT] Could not request first block for %s", image->name );
				}
				// See if requesting the block succeeded ++++++++++++++++++++++
				if ( !dnbd3_get_reply( sock, &reply ) ) {
					char buf[100] = { 0 };
					host_to_string( &servers[itAlt], buf, 100 );
					ERROR_GOTO( server_failed, "[RTT] Received corrupted reply header (%s) after CMD_GET_BLOCK (%s)",
					        buf, image->name );
				}
				// check reply header
				if ( reply.cmd != CMD_GET_BLOCK || reply.size != DNBD3_BLOCK_SIZE ) {
					ERROR_GOTO( server_failed, "[RTT] Reply to first block request is %d bytes for %s",
					        reply.size, image->name );
				}
				if ( recv( sock, buffer, DNBD3_BLOCK_SIZE, MSG_WAITALL ) != DNBD3_BLOCK_SIZE ) {
					ERROR_GOTO( server_failed, "[RTT] Could not read first block payload for %s", image->name );
				}
				clock_gettime( CLOCK_MONOTONIC_RAW, &end );
				// Measurement done - everything fine so far
				const unsigned int rtt = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000; // µs
				const unsigned int avg = altservers_updateRtt( &servers[itAlt], rtt );
				if ( uplink->fd != -1 && isSameAddressPort( &servers[itAlt], &uplink->currentServer ) ) {
					// Was measuring current server
					currentRtt = avg;
					close( sock );
				} else if ( avg < bestRtt ) {
					// Was another server, update "best"
					if ( bestSock != -1 ) close( bestSock );
					bestSock = sock;
					bestRtt = avg;
					bestIndex = itAlt;
				} else {
					// Was too slow, ignore
					close( sock );
				}
				// We're done, call continue
				continue;
				// Jump here if anything went wrong
				// This will cleanup and continue
				server_failed: ;
				altservers_serverFailed( &servers[itAlt] );
				server_image_not_available: ;
				close( sock );
			}
			image_release( image );
			// Done testing all servers. See if we should switch
			if ( bestSock != -1 && (uplink->fd == -1 || (bestRtt < 10000000 && RTT_THRESHOLD_FACTOR(currentRtt) > bestRtt)) ) {
				// yep
				logadd( LOG_DEBUG1, "Change @ %s - best: %uµs, current: %uµs\n", image->name, bestRtt, currentRtt );
				spin_lock( &uplink->rttLock );
				uplink->betterFd = bestSock;
				uplink->betterServer = servers[bestIndex];
				uplink->rttTestResult = RTT_DOCHANGE;
				spin_unlock( &uplink->rttLock );
				static uint64_t counter = 1;
				write( uplink->signal, &counter, sizeof(counter) );
			} else if (bestSock == -1) {
				// No server was reachable
				spin_lock( &uplink->rttLock );
				uplink->rttTestResult = RTT_NOT_REACHABLE;
				spin_unlock( &uplink->rttLock );
			} else {
				// nope
				if ( bestSock != -1 ) close( bestSock );
				spin_lock( &uplink->rttLock );
				uplink->rttTestResult = RTT_DONTCHANGE;
				spin_unlock( &uplink->rttLock );
			}
			// end of loop over all pending uplinks
			spin_lock( &pendingLockWrite );
			pending[itLink] = NULL;
			spin_unlock( &pendingLockWrite );
			pthread_mutex_unlock( &pendingLockConsume );
		}
		// Save cache maps of all images if applicable
		// TODO: Has nothing to do with alt servers really, maybe move somewhere else?
		const time_t now = time( NULL );
		if ( now > nextCacheMapSave ) {
			nextCacheMapSave = now + SERVER_CACHE_MAP_SAVE_INTERVAL;
			image_saveAllCacheMaps();
		}
	}
	cleanup: ;
	if ( signalFd != -1 ) signal_close( signalFd );
	signalFd = -1;
	return NULL ;
}

