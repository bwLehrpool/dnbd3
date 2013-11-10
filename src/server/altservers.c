#include "altservers.h"
#include "uplink.h"
#include "locks.h"
#include "sockhelper.h"
#include "memlog.h"
#include "helper.h"
#include "globals.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/errno.h>
#include <math.h>
#include <assert.h>
#include <inttypes.h>
#include <time.h>
#include <stdio.h>
#include "protocol.h"

static dnbd3_connection_t *pending[SERVER_MAX_PENDING_ALT_CHECKS];
static pthread_spinlock_t pendingLockProduce; // Lock for adding something to pending. (NULL -> nonNULL)
static pthread_mutex_t pendingLockConsume = PTHREAD_MUTEX_INITIALIZER; // Lock for removegin something (nunNULL -> NULL)
static int signalPipe = -1;

static dnbd3_alt_server_t altServers[SERVER_MAX_ALTS];
static int numAltServers = 0;
static pthread_spinlock_t altServersLock;
static int initDone = FALSE;

static pthread_t altThread;

static void *altservers_main(void *data);
static unsigned int altservers_updateRtt(const dnbd3_host_t * const host, const unsigned int rtt);

int altservers_getCount()
{
	return numAltServers;
}

void altservers_init()
{
	spin_init( &altServersLock, PTHREAD_PROCESS_PRIVATE );
	memset( altServers, 0, SERVER_MAX_ALTS * sizeof(dnbd3_alt_server_t) );
	if ( 0 != pthread_create( &altThread, NULL, &altservers_main, (void *)NULL ) ) {
		memlogf( "[ERROR] Could not start altservers connector thread" );
		exit( EXIT_FAILURE );
	}
	initDone = TRUE;
}

void altservers_shutdown()
{
	if ( !initDone ) return;
	pthread_join( altThread, NULL );
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
	while ( !feof( fp ) ) {
		if ( fgets( buffer, 1000, fp ) == NULL ) break;
		int isPrivate = FALSE;
		for (line = buffer;;) { // Trim left and scan for "-" prefix
			if ( *line == '-' ) isPrivate = TRUE;
			else if ( *line != ' ' || *line != '\t' ) break;
			line++;
		}
		trim_right( line );
		space = strchr( line, ' ' );
		if ( space != NULL ) *space++ = '\0';
		if ( !parse_address( line, &host ) ) {
			if ( space != NULL ) *--space = ' ';
			memlogf( "[WARNING] Invalid entry in alt-servers file ignored: '%s'", line );
			continue;
		}
		if ( altservers_add( &host, space, isPrivate ) ) ++count;
	}
	fclose( fp );
	printf( "[DEBUG] Added %d alt servers\n", count );
	return count;
}

int altservers_add(dnbd3_host_t *host, const char *comment, const int isPrivate)
{
	int i, freeSlot = -1;
	spin_lock( &altServersLock );
	for (i = 0; i < numAltServers; ++i) {
		if ( isSameAddressPort( &altServers[i].host, host ) ) {
			spin_unlock( &altServersLock );
			return FALSE;
		} else if ( freeSlot == -1 && altServers[i].host.type == 0 ) {
			freeSlot = i;
		}
	}
	if ( freeSlot == -1 ) {
		if ( numAltServers >= SERVER_MAX_ALTS ) {
			memlogf( "[WARNING] Cannot add another alt server, maximum of %d already reached.", (int)SERVER_MAX_ALTS );
			spin_unlock( &altServersLock );
			return FALSE;
		}
		freeSlot = numAltServers++;
	}
	altServers[freeSlot].host = *host;
	altServers[freeSlot].isPrivate = isPrivate;
	if ( comment != NULL ) snprintf( altServers[freeSlot].comment, COMMENT_LENGTH, "%s", comment );
	spin_unlock( &altServersLock );
	return TRUE;
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
	spin_lock( &pendingLockProduce );
	// it is however possible that an RTT measurement is currently in progress,
	// so check for that case and do nothing if one is in progress
	if ( uplink->rttTestResult == RTT_INPROGRESS ) {
		for (i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i) {
			if ( pending[i] != uplink ) continue;
			// Yep, measuring right now
			spin_unlock( &pendingLockProduce );
			return;
		}
	}
	// Find free slot for measurement
	for (i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i) {
		if ( pending[i] != NULL ) continue;
		pending[i] = uplink;
		uplink->rttTestResult = RTT_INPROGRESS;
		spin_unlock( &pendingLockProduce );
		write( signalPipe, "", 1 ); // Wake altservers thread up
		return;
	}
	// End of loop - no free slot
	spin_unlock( &pendingLockProduce );
	memlogf( "[WARNING] No more free RTT measurement slots, ignoring a request..." );
}

/**
 * The given uplink is about to disappear, so remove it from any queues
 */
void altservers_removeUplink(dnbd3_connection_t *uplink)
{
	pthread_mutex_lock( &pendingLockConsume );
	for (int i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i) {
		if ( pending[i] == uplink ) pending[i] = NULL;
	}
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
int altservers_get(dnbd3_host_t *output, int size)
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
		if ( altServers[i].numFails > SERVER_MAX_UPLINK_FAILS // server failed X times in a row
			&& now - altServers[i].lastFail > SERVER_BAD_UPLINK_IGNORE ) continue; // and last fail was not too long ago? ignore!
		// server seems ok, include in output and reset its fail counter
		altServers[i].numFails = 0;
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
static void *altservers_main(void *data)
{
	const int MAXEVENTS = 3;
	const int ALTS = 4;
	struct epoll_event ev, events[MAXEVENTS];
	int readPipe = -1, fdEpoll = -1;
	int numSocks, ret, itLink, itAlt, numAlts;
	int found;
	char buffer[DNBD3_BLOCK_SIZE ];
	dnbd3_reply_t reply;
	dnbd3_host_t servers[ALTS + 1];
	serialized_buffer_t serialized;
	struct timespec start, end;

	setThreadName( "altserver-check" );
	blockNoncriticalSignals();
	// Init spinlock
	spin_init( &pendingLockProduce, PTHREAD_PROCESS_PRIVATE );
	// Init waiting links queue
	for (int i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i)
		pending[i] = NULL;
	// Init signal-pipe
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
		readPipe = pipes[0];
		signalPipe = pipes[1];
		memset( &ev, 0, sizeof(ev) );
		ev.events = EPOLLIN;
		ev.data.fd = readPipe;
		if ( epoll_ctl( fdEpoll, EPOLL_CTL_ADD, readPipe, &ev ) < 0 ) {
			memlogf( "[WARNING] adding read-signal-pipe to epoll set failed" );
			goto cleanup;
		}
	}
	// LOOP
	while ( !_shutdown ) {
		// Wait 5 seconds max.
		numSocks = epoll_wait( fdEpoll, events, MAXEVENTS, 5000 );
		if ( numSocks < 0 ) {
			memlogf( "[WARNING] epoll_wait() error in uplink_connector" );
			usleep( 100000 );
		}
		// Empty pipe
		do {
			ret = read( readPipe, buffer, sizeof buffer );
		} while ( ret == sizeof buffer ); // Throw data away, this is just used for waking this thread up
		if ( ret == 0 ) {
			memlogf( "[WARNING] Signal pipe of alservers_main closed! Things will break!" );
		}
		if ( ret < 0 ) {
			ret = errno;
			if ( ret != EAGAIN && ret != EWOULDBLOCK && ret != EBUSY && ret != EINTR ) {
				memlogf( "[WARNING] Errno %d on pipe-read on alservers_main! Things will break!", ret );
			}
		}
		// Work your way through the queue
		for (itLink = 0; itLink < SERVER_MAX_PENDING_ALT_CHECKS; ++itLink) {
			if ( pending[itLink] == NULL ) continue; // Check once before locking, as a mutex is expensive
			pthread_mutex_lock( &pendingLockConsume );
			if ( pending[itLink] == NULL ) { // Check again after locking
				continue;
				pthread_mutex_unlock( &pendingLockConsume );
			}
			dnbd3_connection_t * const uplink = pending[itLink];
			assert( uplink->rttTestResult == RTT_INPROGRESS );
			// Now get 4 alt servers
			numAlts = altservers_get( servers, ALTS );
			if ( uplink->fd != -1 ) {
				// Add current server if not already in list
				found = FALSE;
				for (itAlt = 0; itAlt < numAlts; ++itAlt) {
					if ( !isSameAddressPort( &uplink->currentServer, &servers[itAlt] ) ) continue;
					found = TRUE;
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
				int sock = sock_connect( &servers[itAlt], 750, 1250 );
				if ( sock < 0 ) continue;
				// Select image ++++++++++++++++++++++++++++++
				if ( !dnbd3_select_image( sock, uplink->image->lower_name, uplink->image->rid, FLAGS8_SERVER ) ) {
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
				if ( name == NULL || strcmp( name, uplink->image->lower_name ) != 0 ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Server offers image '%s', requested '%s'", name, uplink->image->lower_name );
				}
				if ( rid != uplink->image->rid ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Server provides rid %d, requested was %d (%s)",
					        (int)rid, (int)uplink->image->rid, uplink->image->lower_name );
				}
				if ( imageSize != uplink->image->filesize ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Remote size: %" PRIu64 ", expected: %" PRIu64 " (%s)",
					        imageSize, uplink->image->filesize, uplink->image->lower_name );
				}
				// Request random block ++++++++++++++++++++++++++++++
				fixup_request( request );
				if ( !dnbd3_get_block( sock,
				        (((uint64_t)start.tv_nsec ^ (uint64_t)rand()) * DNBD3_BLOCK_SIZE )% uplink->image->filesize,
				        DNBD3_BLOCK_SIZE) ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Could not request random block for %s", uplink->image->lower_name );
				}
				// See if requesting the block succeeded ++++++++++++++++++++++
				if ( !dnbd3_get_reply( sock, &reply ) ) {
					char buf[100] = { 0 };
					host_to_string( &servers[itAlt], buf, 100 );
					ERROR_GOTO_VA( server_failed, "[ERROR] Received corrupted reply header (%s) after CMD_GET_BLOCK (%s)",
					        buf, uplink->image->lower_name );
				}
				// check reply header
				if ( reply.cmd != CMD_GET_BLOCK || reply.size != DNBD3_BLOCK_SIZE ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Reply to random block request is %d bytes for %s",
					        reply.size, uplink->image->lower_name );
				}
				if ( recv( sock, buffer, DNBD3_BLOCK_SIZE, MSG_WAITALL ) != DNBD3_BLOCK_SIZE ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Could not read random block payload for %s", uplink->image->lower_name );
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
			// Done testing all servers. See if we should switch
			if ( bestSock != -1 && (uplink->fd == -1 || (bestRtt < 10000000 && RTT_THRESHOLD_FACTOR(currentRtt) > bestRtt)) ) {
				// yep
				printf( "DO CHANGE: best: %uµs, current: %uµs\n", bestRtt, currentRtt );
				uplink->betterFd = bestSock;
				uplink->betterServer = servers[bestIndex];
				uplink->rttTestResult = RTT_DOCHANGE;
			} else {
				// nope
				if ( bestSock != -1 ) close( bestSock );
				uplink->rttTestResult = RTT_DONTCHANGE;
			}
			// end of loop over all pending uplinks
			pending[itLink] = NULL;
			pthread_mutex_unlock( &pendingLockConsume );
		}
	}
	cleanup: ;
	if ( fdEpoll != -1 ) close( fdEpoll );
	if ( readPipe != -1 ) close( readPipe );
	if ( signalPipe != -1 ) close( signalPipe );
	signalPipe = -1;
	return NULL ;
}
