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
#include "../serialize.h"

static dnbd3_connection_t *pending[SERVER_MAX_PENDING_ALT_CHECKS];
static pthread_spinlock_t pendingLock;
static int signalPipe = -1;

static dnbd3_alt_server_t _alt_servers[SERVER_MAX_ALTS];
static int _num_alts = 0;
static pthread_spinlock_t _alts_lock;
static int initDone = FALSE;

static pthread_t altThread;

static void *altserver_main(void *data);
static unsigned int altservers_update_rtt(const dnbd3_host_t * const host, const unsigned int rtt);

void altserver_init()
{
	spin_init( &_alts_lock, PTHREAD_PROCESS_PRIVATE );
	memset( _alt_servers, 0, SERVER_MAX_ALTS * sizeof(dnbd3_alt_server_t) );
	if ( 0 != pthread_create( &altThread, NULL, &altserver_main, (void *)NULL ) ) {
		memlogf( "[ERROR] Could not start altservers connector thread" );
		exit( EXIT_FAILURE );
	}
	initDone = TRUE;
}

void altservers_shutdown()
{
	if ( !initDone ) return;
	spin_destroy( &_alts_lock );
	pthread_join( altThread, NULL );
}

int altservers_load()
{
	int count = 0;
	char *name = NULL, *space;
	char line[1000];
	dnbd3_host_t host;
	asprintf( &name, "%s/%s", _configDir, "alt-servers" );
	if ( name == NULL ) return -1;
	FILE *fp = fopen( name, "r" );
	free( name );
	if ( fp == NULL ) return -1;
	while ( !feof( fp ) ) {
		if ( fgets( line, 1000, fp ) == NULL ) break;
		trim_right( line );
		space = strchr( line, ' ' );
		if ( space != NULL ) *space++ = '\0';
		if ( !parse_address( line, &host ) ) {
			if ( space != NULL ) *--space = ' ';
			memlogf( "[WARNING] Invalid entry in alt-servers file ignored: '%s'", line );
			continue;
		}
		if ( altservers_add( &host, space ) ) ++count;
	}
	fclose( fp );
	printf( "[DEBUG] Added %d alt servers\n", count );
	return count;
}

int altservers_add(dnbd3_host_t *host, const char *comment)
{
	int i, freeSlot = -1;
	spin_lock( &_alts_lock );
	for (i = 0; i < _num_alts; ++i) {
		if ( is_same_server( &_alt_servers[i].host, host ) ) {
			spin_unlock( &_alts_lock );
			return FALSE;
		} else if ( freeSlot == -1 && _alt_servers[i].host.type == 0 ) {
			freeSlot = i;
		}
	}
	if ( freeSlot == -1 ) {
		if ( _num_alts >= SERVER_MAX_ALTS ) {
			memlogf( "[WARNING] Cannot add another alt server, maximum of %d already reached.", (int)SERVER_MAX_ALTS );
			spin_unlock( &_alts_lock );
			return FALSE;
		}
		freeSlot = _num_alts++;
	}
	_alt_servers[freeSlot].host = *host;
	if ( comment != NULL ) snprintf( _alt_servers[freeSlot].comment, COMMENT_LENGTH, "%s", comment );
	spin_unlock( &_alts_lock );
	return TRUE;
}

/**
 * ONLY called from the passed uplink's main thread
 */
void altserver_find_uplink(dnbd3_connection_t *uplink)
{
	if ( uplink->rttTestResult == RTT_INPROGRESS ) return;
	spin_lock( &pendingLock );
	for (int i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i) {
		if ( pending[i] != NULL ) continue;
		pending[i] = uplink;
		uplink->rttTestResult = RTT_INPROGRESS;
		spin_unlock( &pendingLock );
		write( signalPipe, "", 1 );
		return;
	}
	// End of loop - no free slot
	spin_unlock( &pendingLock );
	memlogf( "[WARNING] No more free RTT measurement slots, ignoring a request..." );
}

/**
 * The given uplink is about to disappear, so remove it from any queues
 */
void altservers_remove_uplink(dnbd3_connection_t *uplink)
{
	spin_lock( &pendingLock );
	for (int i = 0; i < SERVER_MAX_PENDING_ALT_CHECKS; ++i) {
		if ( pending[i] == uplink ) pending[i] = NULL;
	}
	spin_unlock( &pendingLock );
}

/**
 * Get <size> known (working) alt servers, ordered by network closeness
 * (by finding the smallest possible subnet)
 */
int altservers_get_matching(dnbd3_host_t *host, dnbd3_server_entry_t *output, int size)
{
	if ( host == NULL || host->type == 0 || _num_alts == 0 || output == NULL || size <= 0 ) return 0;
	int i, j;
	int count = 0;
	int distance[size];
	spin_lock( &_alts_lock );
	for (i = 0; i < _num_alts; ++i) {
		if ( host->type != _alt_servers[i].host.type ) continue; // Wrong address family
		// TODO: Prefer same AF here, but if in the end we got less servers than requested, add
		// servers of other AF too (after this loop)
		if ( count == 0 ) {
			// Trivial - this is the first entry
			output[0].host = _alt_servers[i].host;
			output[0].failures = 0;
			distance[0] = altservers_net_closeness( host, &output[0].host );
			count++;
		} else {
			// Other entries already exist, insert in proper position
			const int dist = altservers_net_closeness( host, &_alt_servers[i].host );
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
				output[j].host = _alt_servers[i].host;
				output[j].failures = 0;
				distance[j] = dist;
				break;
			}
		}
	}
	// "if count < size then add servers of other address families"
	spin_unlock( &_alts_lock );
	return count;
}

/**
 * Get <size> alt servers. If there are more alt servers than
 * requested, random servers will be picked
 */
int altservers_get(dnbd3_host_t *output, int size)
{
	int count = 0, i, j, num;
	spin_lock( &_alts_lock );
	if ( size <= _num_alts ) {
		for (i = 0; i < size; ++i) {
			if ( _alt_servers[i].host.type == 0 ) continue;
			output[count++] = _alt_servers[i].host;
		}
	} else {
		int which[_num_alts]; // Generate random order over _num_alts
		for (i = 0; i < _num_alts; ++i) {
			again: ;
			num = rand() % _num_alts;
			for (j = 0; j < i; ++j) {
				if ( which[j] == num ) goto again;
			}
			which[i] = num;
		} // Now pick <size> working alt servers in that generated order
		for (i = 0; i < size; ++i) {
			if ( _alt_servers[which[i]].host.type == 0 ) continue;
			output[count++] = _alt_servers[which[i]].host;
			if ( count >= size ) break;
		}
	}
	spin_unlock( &_alts_lock );
	return count;
}

/**
 * Update rtt history of given server - returns the new average for that server
 */
static unsigned int altservers_update_rtt(const dnbd3_host_t * const host, const unsigned int rtt)
{
	unsigned int avg = rtt;
	int i;
	spin_lock( &_alts_lock );
	for (i = 0; i < _num_alts; ++i) {
		if ( !is_same_server( host, &_alt_servers[i].host ) ) continue;
		_alt_servers[i].rtt[++_alt_servers[i].rttIndex % SERVER_RTT_PROBES] = rtt;
#if SERVER_RTT_PROBES == 5
		avg = (_alt_servers[i].rtt[0] + _alt_servers[i].rtt[1] + _alt_servers[i].rtt[2] + _alt_servers[i].rtt[3] + _alt_servers[i].rtt[4])
		        / SERVER_RTT_PROBES;
#else
#warning You might want to change the code in altservers_update_rtt if you changed SERVER_RTT_PROBES
		avg = 0;
		for (int j = 0; j < SERVER_RTT_PROBES; ++j) {
			avg += _alt_servers[i].rtt[j];
		}
		avg /= SERVER_RTT_PROBES;
#endif
		break;
	}
	spin_unlock( &_alts_lock );
	return avg;
}

/**
 * Determine how close two addresses are to each other by comparing the number of
 * matching bits from the left of the address. Does not count individual bits but
 * groups of 4 for speed.
 */
int altservers_net_closeness(dnbd3_host_t *host1, dnbd3_host_t *host2)
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

static void *altserver_main(void *data)
{
	const int MAXEVENTS = 3;
	const int ALTS = 4;
	struct epoll_event ev, events[MAXEVENTS];
	int readPipe = -1, fdEpoll = -1;
	int numSocks, ret, itLink, itAlt, numAlts;
	int found, len;
	char buffer[DNBD3_BLOCK_SIZE ];
	dnbd3_host_t servers[ALTS + 1];
	dnbd3_request_t request;
	dnbd3_reply_t reply;
	serialized_buffer_t serialized;
	struct iovec iov[2];
	struct timespec start, end;

	// Make valgrind happy
	memset( &reply, 0, sizeof(reply) );
	memset( &request, 0, sizeof(request) );
	request.magic = dnbd3_packet_magic;
	// Init spinlock
	spin_init( &pendingLock, PTHREAD_PROCESS_PRIVATE );
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
		} while ( ret > 0 ); // Throw data away, this is just used for waking this thread up
		if ( ret == 0 ) {
			memlogf( "[WARNING] Signal pipe of uplink_connector for %s closed! Things will break!" );
		}
		ret = errno;
		if ( ret != EAGAIN && ret != EWOULDBLOCK && ret != EBUSY && ret != EINTR ) {
			memlogf( "[WARNING] Errno %d on pipe-read on uplink_connector for %s! Things will break!", ret );
		}
		// Work your way through the queue
		spin_lock( &pendingLock );
		for (itLink = 0; itLink < SERVER_MAX_PENDING_ALT_CHECKS; ++itLink) {
			if ( pending[itLink] == NULL ) continue;
			spin_unlock( &pendingLock );
			dnbd3_connection_t * const uplink = pending[itLink];
			assert( uplink->rttTestResult == RTT_INPROGRESS );
			// Now get 4 alt servers
			numAlts = altservers_get( servers, ALTS );
			if ( uplink->fd != -1 ) {
				// Add current server if not already in list
				found = FALSE;
				for (itAlt = 0; itAlt < numAlts; ++itAlt) {
					if ( !is_same_server( &uplink->currentServer, &servers[itAlt] ) ) continue;
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
				usleep( 1000 );
				// Connect
				clock_gettime( CLOCK_MONOTONIC_RAW, &start );
				int sock = sock_connect( &servers[itAlt], 750, 1250 );
				if ( sock < 0 ) continue;
				// Select image ++++++++++++++++++++++++++++++
				serializer_reset_write( &serialized );
				serializer_put_uint16( &serialized, PROTOCOL_VERSION );
				serializer_put_string( &serialized, uplink->image->lower_name );
				serializer_put_uint16( &serialized, uplink->image->rid );
				serializer_put_uint8( &serialized, 1 ); // isServer = TRUE
				len = serializer_get_written_length( &serialized );
				request.cmd = CMD_SELECT_IMAGE;
				request.size = len;
				fixup_request( request );
				iov[0].iov_base = &request;
				iov[0].iov_len = sizeof(request);
				iov[1].iov_base = &serialized;
				iov[1].iov_len = len;
				if ( writev( sock, iov, 2 ) != len + sizeof(request) ) goto server_failed;
				// See if selecting the image succeeded ++++++++++++++++++++++++++++++
				if ( recv( sock, &reply, sizeof(reply), MSG_WAITALL ) != sizeof(reply) ) {
					//ERROR_GOTO_VA( server_failed, "[ERROR] Received corrupted reply header after CMD_SELECT_IMAGE (%s)",
					//        uplink->image->lower_name );
					goto server_failed;
				}
				// check reply header
				fixup_reply( reply );
				if ( reply.cmd != CMD_SELECT_IMAGE || reply.size < 3 || reply.size > MAX_PAYLOAD || reply.magic != dnbd3_packet_magic ) goto server_failed;
				// Not found
				// receive reply payload
				if ( recv( sock, &serialized, reply.size, MSG_WAITALL ) != reply.size ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Cold not read CMD_SELECT_IMAGE payload (%s)", uplink->image->lower_name );
				}
				// handle/check reply payload
				serializer_reset_read( &serialized, reply.size );
				const uint16_t protocol_version = serializer_get_uint16( &serialized );
				if ( protocol_version < MIN_SUPPORTED_SERVER ) goto server_failed;
				const char *name = serializer_get_string( &serialized );
				if ( strcmp( name, uplink->image->lower_name ) != 0 ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Server offers image '%s', requested '%s'", name, uplink->image->lower_name );
				}
				const uint16_t rid = serializer_get_uint16( &serialized );
				if ( rid != uplink->image->rid ) ERROR_GOTO_VA( server_failed, "[ERROR] Server provides rid %d, requested was %d (%s)",
				        (int)rid, (int)uplink->image->rid, uplink->image->lower_name );
				const uint64_t image_size = serializer_get_uint64( &serialized );
				if ( image_size != uplink->image->filesize ) ERROR_GOTO_VA( server_failed,
				        "[ERROR] Remote size: %" PRIu64 ", expected: %" PRIu64 " (%s)",
				        image_size, uplink->image->filesize, uplink->image->lower_name );
				// Request random block ++++++++++++++++++++++++++++++
				request.cmd = CMD_GET_BLOCK;
				request.offset = (uplink->image->filesize - 1) & ~(DNBD3_BLOCK_SIZE - 1);
				request.size = DNBD3_BLOCK_SIZE;
				fixup_request( request );
				if ( send( sock, &request, sizeof(request), 0 ) != sizeof(request) ) ERROR_GOTO_VA( server_failed,
				        "[ERROR] Could not request random block for %s", uplink->image->lower_name );
				// See if requesting the block succeeded ++++++++++++++++++++++
				if ( recv( sock, &reply, sizeof(reply), MSG_WAITALL ) != sizeof(reply) ) {
					ERROR_GOTO_VA( server_failed, "[ERROR] Received corrupted reply header after CMD_GET_BLOCK (%s)",
					        uplink->image->lower_name );
				}
				// check reply header
				fixup_reply( reply );
				if ( reply.cmd != CMD_GET_BLOCK || reply.size != DNBD3_BLOCK_SIZE ) ERROR_GOTO_VA( server_failed,
				        "[ERROR] Reply to random block request is %d bytes for %s", reply.size, uplink->image->lower_name );
				if ( recv( sock, buffer, DNBD3_BLOCK_SIZE, MSG_WAITALL ) != DNBD3_BLOCK_SIZE ) ERROR_GOTO_VA( server_failed,
				        "[ERROR] Could not read random block from socket for %s", uplink->image->lower_name );
				clock_gettime( CLOCK_MONOTONIC_RAW, &end );
				// Measurement done - everything fine so far
				const unsigned int rtt = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000; // µs
				const unsigned int avg = altservers_update_rtt( &servers[itAlt], rtt );
				if ( is_same_server( &servers[itAlt], &uplink->currentServer ) ) {
					currentRtt = avg;
					close( sock );
				} else if ( avg < bestRtt ) {
					if ( bestSock != -1 ) close( bestSock );
					bestSock = sock;
					bestRtt = avg;
					bestIndex = itAlt;
				} else {
					close( sock );
				}
				continue;
				// Jump here if anything went wrong
				server_failed: ;
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
			spin_lock( &pendingLock );
		}
		spin_unlock( &pendingLock );
	}
	cleanup: ;
	spin_destroy( &pendingLock );
	if ( fdEpoll != -1 ) close( fdEpoll );
	if ( readPipe != -1 ) close( readPipe );
	if ( signalPipe != -1 ) close( signalPipe );
	signalPipe = -1;
	return NULL ;
}
