#include "connection.h"
#include "helper.h"
#include "../config.h"
#include "../shared/protocol.h"
#include "../shared/signal.h"
#include "../shared/sockhelper.h"
#include "../shared/log.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

/* Constants */
static const size_t SHORTBUF = 100;
#define MAX_ALTS (8)
#define MAX_HOSTS_PER_ADDRESS (2)
static const int MAX_CONSECUTIVE_FAILURES = 16;
#define RTT_COUNT (4)

/* Module variables */

// Init guard
static bool connectionInitDone = false;
static bool threadInitDone = false;
static pthread_mutex_t mutexInit = PTHREAD_MUTEX_INITIALIZER;
static bool keepRunning = true;

// List of pending requests
static struct {
	dnbd3_async_t *head;
	dnbd3_async_t *tail;
	pthread_spinlock_t lock;
} requests;

// Connection for the image
static struct {
	char *name;
	uint16_t rid;
	uint64_t size;
} image;

static struct {
	int sockFd;
	pthread_mutex_t sendMutex;
	int panicSignalFd;
	dnbd3_host_t currentServer;
	uint64_t startupTime;
} connection;

// Known alt servers
typedef struct _alt_server {
	dnbd3_host_t host;
	int consecutiveFails;
	int rtt;
	int rtts[RTT_COUNT];
	int rttIndex;
} alt_server_t;
alt_server_t altservers[MAX_ALTS];
dnbd3_server_entry_t newservers[MAX_ALTS];
pthread_spinlock_t altLock;

/* Static methods */


static void* connection_receiveThreadMain(void *sock);
static void* connection_backgroundThread(void *something);

static void addAltServers();
static void probeAltServers();
static void switchConnection(int sockFd, alt_server_t *srv);
static void requestAltServers();
static bool throwDataAway(int sockFd, uint32_t amount);

static void enqueueRequest(dnbd3_async_t *request);
static dnbd3_async_t* removeRequest(dnbd3_async_t *request);

static uint64_t nowMilli();
static uint64_t nowMicro();

bool connection_init(const char *hosts, const char *lowerImage, const uint16_t rid)
{
	int sock = -1;
	char host[SHORTBUF];
	serialized_buffer_t buffer;
	uint16_t remoteVersion, remoteRid;
	char *remoteName;
	uint64_t remoteSize;

	pthread_mutex_lock( &mutexInit );
	if ( !connectionInitDone && keepRunning ) {
		dnbd3_host_t tempHosts[MAX_HOSTS_PER_ADDRESS];
		const char *current, *end;
		int altIndex = 0;
		memset( altservers, 0, sizeof altservers );
		connection.sockFd = -1;
		current = hosts;
		do {
			// Get next host from string
			while ( *current == ' ' ) current++;
			end = strchr( current, ' ' );
			size_t len = (end == NULL ? SHORTBUF : (size_t)( end - current ) + 1);
			if ( len > SHORTBUF ) len = SHORTBUF;
			snprintf( host, len, "%s", current );
			int newHosts = sock_resolveToDnbd3Host( host, tempHosts, MAX_HOSTS_PER_ADDRESS );
			for ( int i = 0; i < newHosts; ++i ) {
				if ( altIndex >= MAX_ALTS )
					break;
				altservers[altIndex].host = tempHosts[i];
				altIndex += 1;
			}
			current = end + 1;
		} while ( end != NULL && altIndex < MAX_ALTS );
		logadd( LOG_INFO, "Got %d servers from init call", altIndex );
		// Connect
		for ( int i = 0; i < altIndex; ++i ) {
			if ( altservers[i].host.type == 0 )
				continue;
			// Try to connect
			sock = sock_connect( &altservers[i].host, 500, SOCKET_KEEPALIVE_TIMEOUT * 1000 );
			if ( sock == -1 ) {
				logadd( LOG_ERROR, "Could not connect to host" );
			} else if ( !dnbd3_select_image( sock, lowerImage, rid, 0 ) ) {
				logadd( LOG_ERROR, "Could not send select image" );
			} else if ( !dnbd3_select_image_reply( &buffer, sock, &remoteVersion, &remoteName, &remoteRid, &remoteSize ) ) {
				logadd( LOG_ERROR, "Could not read select image reply (%d)", errno );
			} else if ( rid != 0 && rid != remoteRid ) {
				logadd( LOG_ERROR, "rid mismatch" );
			} else {
				image.name = strdup( remoteName );
				image.rid = remoteRid;
				image.size = remoteSize;
				connection.currentServer = altservers[i].host;
				connection.panicSignalFd = signal_new();
				connection.startupTime = nowMilli();
				connection.sockFd = sock;
				requests.head = NULL;
				requests.tail = NULL;
				requestAltServers();
				break;
			}
			// Failed
			logadd( LOG_DEBUG1, "Server does not offer requested image... " );
			if ( sock != -1 ) {
				close( sock );
				sock = -1;
			}
		}
		if ( sock != -1 ) {
			connectionInitDone = true;
		}
	}
	pthread_mutex_unlock( &mutexInit );
	return sock != -1;
}

bool connection_initThreads()
{
	pthread_mutex_lock( &mutexInit );
	if ( !keepRunning || !connectionInitDone || threadInitDone || connection.sockFd == -1 ) {
		pthread_mutex_unlock( &mutexInit );
		return false;
	}
	bool success = true;
	pthread_t thread;
	threadInitDone = true;
	logadd( LOG_DEBUG1, "Initializing stuff" );
	if ( pthread_mutex_init( &connection.sendMutex, NULL ) != 0
			|| pthread_spin_init( &requests.lock, PTHREAD_PROCESS_PRIVATE ) != 0
			|| pthread_spin_init( &altLock, PTHREAD_PROCESS_PRIVATE ) != 0 ) {
		logadd( LOG_ERROR, "Mutex or spinlock init failure" );
		success = false;
	} else {
		if ( pthread_create( &thread, NULL, &connection_receiveThreadMain, (void*)(size_t)connection.sockFd ) != 0 ) {
			logadd( LOG_ERROR, "Could not create receive thread" );
			success = false;
		} else if ( pthread_create( &thread, NULL, &connection_backgroundThread, NULL ) != 0 ) {
			logadd( LOG_ERROR, "Could not create background thread" );
			success = false;
		}
	}
	if ( !success ) {
		close( connection.sockFd );
		connection.sockFd = -1;
	}
	pthread_mutex_unlock( &mutexInit );
	return success;
}

uint64_t connection_getImageSize()
{
	return image.size;
}

bool connection_read(dnbd3_async_t *request)
{
	if (!connectionInitDone) return false;
	pthread_mutex_lock( &connection.sendMutex );
	enqueueRequest( request );
	if ( connection.sockFd != -1 ) {
		if ( !dnbd3_get_block( connection.sockFd, request->offset, request->length, (uint64_t)request ) ) {
			shutdown( connection.sockFd, SHUT_RDWR );
			connection.sockFd = -1;
			pthread_mutex_unlock( &connection.sendMutex );
			signal_call( connection.panicSignalFd );
			return true;
		}
	}
	pthread_mutex_unlock( &connection.sendMutex );
	return true;
}

void connection_close()
{
	if ( keepRunning ) {
		logadd( LOG_INFO, "Tearing down dnbd3 connections and workers" );
	}
	pthread_mutex_lock( &mutexInit );
	keepRunning = false;
	if ( !connectionInitDone ) {
		pthread_mutex_unlock( &mutexInit );
		return;
	}
	pthread_mutex_unlock( &mutexInit );
	pthread_mutex_lock( &connection.sendMutex );
	if ( connection.sockFd != -1 ) {
		shutdown( connection.sockFd, SHUT_RDWR );
	}
	pthread_mutex_unlock( &connection.sendMutex );
}

int connection_printStats(char *buffer, const int len)
{
	int ret;
	int remaining = len;
	if ( remaining > 0 ) {
		ret = snprintf( buffer, remaining, "Image:    %s\nRevision: %d\n\nCurrent connection time: %ds\n\n",
				image.name, (int)image.rid, (int)( (nowMilli() - connection.startupTime) / 1000 ) );
		if ( ret > 0 ) {
			remaining -= ret;
			buffer += ret;
		}
	}
	int i = -1;
	pthread_spin_lock( &altLock );
	while ( remaining > 3 && ++i < MAX_ALTS ) {
		if ( altservers[i].host.type == 0 )
			continue;
		if ( isSameAddressPort( &connection.currentServer, &altservers[i].host ) ) {
			*buffer++ = '*';
		} else {
			*buffer++ = ' ';
		}
		ret = sock_printHost( &altservers[i].host, buffer, remaining );
		remaining -= (ret + 1); // For space or * above
		buffer += ret;
		if ( remaining < 3 )
			break;
		int width = MAX( 35 - ret, 0 );
		char *unit;
		int value;
		if ( altservers[i].rtt > 5000 ) {
			unit = "ms   ";
			value = altservers[i].rtt / 1000;
		} else {
			unit = "µs";
			value = altservers[i].rtt;
			width += 3;
		}
		ret = snprintf( buffer, remaining, "% *d %s   Unreachable: % 3d\n",
				width, value, unit, altservers[i].consecutiveFails );
		remaining -= ret;
		buffer += ret;
	}
	pthread_spin_unlock( &altLock );
	return len - remaining;
}

static void* connection_receiveThreadMain(void *sockPtr)
{
	int sockFd = (int)(size_t)sockPtr;
	dnbd3_reply_t reply;
	pthread_detach(pthread_self());

	while ( keepRunning ) {
		int ret;
		do {
			ret = dnbd3_read_reply( sockFd, &reply, true );
			if ( ret == REPLY_OK ) break;
		} while ( ret == REPLY_INTR || ret == REPLY_AGAIN );
		if ( ret != REPLY_OK ) {
			logadd( LOG_DEBUG1, "Error receiving reply on receiveThread (%d)", ret );
			goto fail;
		}

		if ( reply.cmd == CMD_GET_BLOCK ) {
			// Get block reply. find matching request
			dnbd3_async_t *request = removeRequest( (dnbd3_async_t*)reply.handle );
			if ( request == NULL ) {
				logadd( LOG_WARNING, "WARNING BUG ALERT SOMETHING: Got block reply with no matching request" );
				if ( reply.size != 0 && !throwDataAway( sockFd, reply.size ) ) {
					logadd( LOG_DEBUG1, "....and choked on reply payload" );
					goto fail;
				}
			} else {
				// Found a match
				const ssize_t ret = sock_recv( sockFd, request->buffer, request->length );
				if ( ret != (ssize_t)request->length ) {
					logadd( LOG_DEBUG1, "receiving payload for a block reply failed" );
					connection_read( request );
					goto fail;
				}
				// Success, wake up caller
				request->success = true;
				request->finished = true;
				signal_call( request->signalFd );
			}
		} else if ( reply.cmd == CMD_GET_SERVERS ) {
			// List of known alt servers
			dnbd3_server_entry_t entries[MAX_ALTS];
			const int count = MIN( reply.size / sizeof(dnbd3_server_entry_t), MAX_ALTS );
			const size_t relevantSize = sizeof(dnbd3_server_entry_t) * count;
			if ( sock_recv( sockFd, entries, relevantSize ) != (ssize_t)relevantSize
					|| !throwDataAway( sockFd, reply.size - (uint32_t)relevantSize ) ) {
				logadd( LOG_DEBUG1, "Error receiving list of alt servers." );
				goto fail;
			}
			pthread_spin_lock( &altLock );
			memcpy( newservers, entries, relevantSize );
			pthread_spin_unlock( &altLock );
		} else {
			// TODO: Handle the others?
			if ( reply.size != 0 && !throwDataAway( sockFd, reply.size ) ) {
				logadd( LOG_DEBUG1, "Could not throw %d bytes away on CMD %d", (int)reply.size, (int)reply.cmd );
				goto fail;
			}
		}
	}
	logadd( LOG_DEBUG1, "Aus der Schleife rausgeflogen! ARRRRRRRRRR" );
fail:;
	// Make sure noone is trying to use the socket for sending by locking,
	pthread_mutex_lock( &connection.sendMutex );
	// then just set the fd to -1, but only if it's the same fd as ours,
	// as someone could have established a new connection already
	logadd( LOG_DEBUG1, "RT: Local sock: %d, global: %d", sockFd, connection.sockFd );
	if ( connection.sockFd == sockFd ) {
		connection.sockFd = -1;
		signal_call( connection.panicSignalFd );
	}
	pthread_mutex_unlock( &connection.sendMutex );
	// As we're the only reader, it's safe to close the socket now
	close( sockFd );
	return NULL;
}

static void* connection_backgroundThread(void *something UNUSED)
{
	uint64_t nextKeepalive = 0;
	uint64_t nextRttCheck = 0;

	while ( keepRunning ) {
		const uint64_t now = nowMilli();
		if ( now < nextKeepalive && now < nextRttCheck ) {
			int waitTime = (int)( MIN( nextKeepalive, nextRttCheck ) - now );
			int waitRes = signal_wait( connection.panicSignalFd, waitTime );
			if ( waitRes == SIGNAL_ERROR ) {
				logadd( LOG_WARNING, "Error waiting on signal in background thread! Errno = %d", errno );
			}
		}
		// Woken up, see what we have to do
		const bool panic = connection.sockFd == -1;
		// Check alt servers
		if ( panic || now >= nextRttCheck ) {
			addAltServers();
			probeAltServers();
			if ( panic || connection.startupTime + ( STARTUP_MODE_DURATION * 1000ull ) > now ) {
				nextRttCheck = now + TIMER_INTERVAL_PROBE_STARTUP * 1000ull;
			} else {
				nextRttCheck = now + TIMER_INTERVAL_PROBE_NORMAL * 1000ull;
			}
		}
		// Send keepalive packet
		if ( now >= nextKeepalive ) {
			pthread_mutex_lock( &connection.sendMutex );
			if ( connection.sockFd != -1 ) {
				dnbd3_request_t request;
				request.magic = dnbd3_packet_magic;
				request.cmd = CMD_KEEPALIVE;
				request.handle = request.offset = request.size = 0;
				fixup_request( request );
				ssize_t ret = sock_sendAll( connection.sockFd, &request, sizeof request, 2 );
				if ( (size_t)ret != sizeof request ) {
					shutdown( connection.sockFd, SHUT_RDWR );
					connection.sockFd = -1;
					nextRttCheck = now;
				}
			}
			pthread_mutex_unlock( &connection.sendMutex );
			nextKeepalive = now + TIMER_INTERVAL_KEEPALIVE_PACKET * 1000ull;
		}
	}
	return NULL;
}

// Private quick helpers

static void addAltServers()
{
	pthread_spin_lock( &altLock );
	for ( int nIdx = 0; nIdx < MAX_ALTS; ++nIdx ) {
		if ( newservers[nIdx].host.type == 0 )
			continue;
		// Got a new alt server, see if it's already known
		for ( int eIdx = 0; eIdx < MAX_ALTS; ++eIdx ) {
			if ( isSameAddress( &newservers[nIdx].host, &altservers[eIdx].host ) ) {
				goto skip_server;
			}
		}
		// Not known yet, add
		int slot = -1;
		for ( int eIdx = 0; eIdx < MAX_ALTS; ++eIdx ) {
			if ( altservers[eIdx].host.type == 0 ) {
				slot = eIdx;
				break;
			}
			if ( altservers[eIdx].consecutiveFails > MAX_CONSECUTIVE_FAILURES
					&& slot != -1 && altservers[slot].consecutiveFails < altservers[eIdx].consecutiveFails ) {
				slot = eIdx;
			}
		}
		if ( slot != -1 ) {
			char txt[200];
			sock_printHost( &newservers[nIdx].host, txt, 200 );
			logadd( LOG_DEBUG1, "new server %s in slot %d", txt, slot );
			altservers[slot].consecutiveFails = 0;
			altservers[slot].rtts[0] = RTT_UNREACHABLE;
			altservers[slot].rttIndex = 1;
			altservers[slot].host = newservers[nIdx].host;
		}
skip_server:;
	}
	memset( newservers, 0, sizeof(newservers) );
	pthread_spin_unlock( &altLock );
}

static void probeAltServers()
{
	serialized_buffer_t buffer;
	dnbd3_reply_t reply;
	int bestIndex = -1;
	int bestSock = -1;
	int currentRtt = RTT_UNREACHABLE;
	uint16_t remoteRid, remoteProto;
	uint64_t remoteSize;
	char *remoteName;
	const bool panic = connection.sockFd == -1;

	for ( int altIndex = 0; altIndex < MAX_ALTS; ++altIndex ) {
		alt_server_t * const srv = &altservers[altIndex];
		if ( srv->host.type == 0 )
			continue;
		if ( !panic && srv->consecutiveFails > MAX_CONSECUTIVE_FAILURES
				&& srv->consecutiveFails % ( srv->consecutiveFails / 8 ) != 0 ) {
			continue;
		}
		if (srv->rttIndex >= RTT_COUNT) {
			srv->rttIndex = 0;
		} else {
			srv->rttIndex += 1;
		}
		// Probe
		const uint64_t start = nowMicro();
		int sock = sock_connect( &srv->host, panic ? 1000 : 333, 1000 );
		if ( sock == -1 ) {
			logadd( LOG_WARNING, "Could not crrate socket for probing. errno = %d", errno );
			continue;
		}
		if ( !dnbd3_select_image( sock, image.name, image.rid, 0 ) ) {
			logadd( LOG_DEBUG1, "-> select fail" );
			goto fail;
		}
		if ( !dnbd3_select_image_reply( &buffer, sock, &remoteProto, &remoteName, &remoteRid, &remoteSize )) {
			logadd( LOG_DEBUG1, "<- select fail" );
			goto fail;
		}
		if ( remoteProto < MIN_SUPPORTED_SERVER || remoteProto > PROTOCOL_VERSION ) {
			logadd( LOG_WARNING, "Unsupported remote version (local: %d, remote: %d)", (int)PROTOCOL_VERSION, (int)remoteProto );
			srv->consecutiveFails += 10;
			goto fail;
		}
		if ( remoteRid != image.rid || strcmp( remoteName, image.name ) != 0 ) {
			logadd( LOG_WARNING, "Remote rid or name mismatch (got '%s')", remoteName );
			srv->consecutiveFails += 10;
			goto fail;
		}
		if ( !dnbd3_get_block( sock, 0, RTT_BLOCK_SIZE, 0 ) ) {
			logadd( LOG_DEBUG1, "-> block request fail" );
			goto fail;
		}
		int a = 111, b = 111;
		if ( !(a = dnbd3_get_reply( sock, &reply )) || reply.size != RTT_BLOCK_SIZE
				|| !(b = throwDataAway( sock, RTT_BLOCK_SIZE )) ) {
			logadd( LOG_DEBUG1, "<- block paxload fail %d %d %d", a, (int)reply.size, b );
			goto fail;
		}
		// Yay, success
		// Panic mode? Just switch to server
		if ( panic ) {
			switchConnection( sock, srv );
			return;
		}
		// Non-panic mode:
		// Update stats of server
		const uint64_t end = nowMicro();
		srv->consecutiveFails = 0;
		srv->rtts[srv->rttIndex] = (int)(end - start);
		srv->rtt = 0;
		for ( int i = 0; i < RTT_COUNT; ++i ) {
			srv->rtt += srv->rtts[i];
		}
		srv->rtt /= RTT_COUNT;
		// Remember rtt if this server matches the current one
		if ( isSameAddressPort( &srv->host, &connection.currentServer ) ) {
			currentRtt = srv->rtt;
		}
		// Keep socket open if this is currently the best one
		if ( bestIndex == -1 || altservers[bestIndex].rtt > srv->rtt ) {
			bestIndex = altIndex;
			if ( bestSock != -1 ) {
				close( bestSock );
			}
			bestSock = sock;
		} else {
			close( sock );
		}
		continue;
fail:;
		close( sock );
		srv->rtts[srv->rttIndex] = RTT_UNREACHABLE;
		srv->consecutiveFails += 1;
	}
	// Switch if a better server was found
	if ( bestIndex != -1
			&& ( currentRtt > altservers[bestIndex].rtt + RTT_ABSOLUTE_THRESHOLD
					|| RTT_THRESHOLD_FACTOR(currentRtt) > altservers[bestIndex].rtt + 1500 ) ) {
		logadd( LOG_INFO, "Current: %dµs, best: %dµs. Will switch!", currentRtt, altservers[bestIndex].rtt );
		switchConnection( bestSock, &altservers[bestIndex] );
	} else if ( bestIndex != -1 ) {
		// No switch
		logadd( LOG_DEBUG1, "Current: %dµs, best: %dµs. Will not switch.", currentRtt, altservers[bestIndex].rtt );
		close( bestSock );
	}
}

static void switchConnection(int sockFd, alt_server_t *srv)
{
	pthread_t thread;
	struct sockaddr_storage addr;
	socklen_t addrLen = sizeof(addr);
	char message[200] = "Connection switched to ";
	size_t len = strlen(message);
	int ret;
	dnbd3_async_t *queue, *it;

	pthread_mutex_lock( &connection.sendMutex );
	if ( connection.sockFd != -1 ) {
		shutdown( connection.sockFd, SHUT_RDWR );
	}
	ret = getpeername( sockFd, (struct sockaddr*)&addr, &addrLen );
	if ( ret == 0 ) {
		connection.currentServer = srv->host;
		connection.sockFd = sockFd;
		pthread_spin_lock( &requests.lock );
		queue = requests.head;
		requests.head = requests.tail = NULL;
		pthread_spin_unlock( &requests.lock );
	} else {
		connection.sockFd = -1;
	}
	requestAltServers();
	pthread_mutex_unlock( &connection.sendMutex );
	if ( ret != 0 ) {
		close( sockFd );
		logadd( LOG_WARNING, "Could not getpeername after connection switch, assuming connection already dead again. (Errno=%d)", errno );
		signal_call( connection.panicSignalFd );
		return;
	}
	connection.startupTime = nowMilli();
	pthread_create( &thread, NULL, &connection_receiveThreadMain, (void*)(size_t)sockFd );
	sock_printable( (struct sockaddr*)&addr, sizeof(addr), message + len, sizeof(message) - len );
	logadd( LOG_INFO, message );
	// resend queue
	if ( queue != NULL ) {
		pthread_mutex_lock( &connection.sendMutex );
		dnbd3_async_t *next = NULL;
		for ( it = queue; it != NULL; it = next ) {
			logadd( LOG_DEBUG1, "Requeue after server change" );
			next = it->next;
			enqueueRequest( it );
			if ( connection.sockFd != -1 && !dnbd3_get_block( connection.sockFd, it->offset, it->length, (uint64_t)it ) ) {
				logadd( LOG_WARNING, "Resending pending request failed, re-entering panic mode" );
				shutdown( connection.sockFd, SHUT_RDWR );
				connection.sockFd = -1;
				signal_call( connection.panicSignalFd );
			}
		}
		pthread_mutex_unlock( &connection.sendMutex );
	}
}

/**
 * Does not lock, so get the sendMutex first!
 */
static void requestAltServers()
{
	if ( connection.sockFd == -1 )
		return;
	dnbd3_request_t request = { 0 };
	request.magic = dnbd3_packet_magic;
	request.cmd = CMD_GET_SERVERS;
	fixup_request( request );
	if ( sock_sendAll( connection.sockFd, &request, sizeof(request), 2 ) != (ssize_t)sizeof(request) ) {
		logadd( LOG_WARNING, "Connection failed while requesting alt server list" );
		shutdown( connection.sockFd, SHUT_RDWR );
		connection.sockFd = -1;
	}
}

static bool throwDataAway(int sockFd, uint32_t amount)
{
	size_t done = 0;
	char tempBuffer[SHORTBUF];
	while ( done < amount ) {
		const ssize_t ret = sock_recv( sockFd, tempBuffer, MIN( amount - done, SHORTBUF ) );
		if ( ret <= 0 )
			return false;
		done += (size_t)ret;
	}
	return true;
}

static void enqueueRequest(dnbd3_async_t *request)
{
	request->next = NULL;
	request->finished = false;
	request->success = false;
	pthread_spin_lock( &requests.lock );
	//logadd( LOG_DEBUG2, "Queue: %p @ %s : %d", request, file, line );
	if ( requests.head == NULL ) {
		requests.head = requests.tail = request;
	} else {
		requests.tail->next = request;
		requests.tail = request;
	}
	pthread_spin_unlock( &requests.lock );
}

static dnbd3_async_t* removeRequest(dnbd3_async_t *request)
{
	pthread_spin_lock( &requests.lock );
	//logadd( LOG_DEBUG2, "Remov: %p @ %s : %d", request, file, line );
	dnbd3_async_t *iterator, *prev = NULL;
	for ( iterator = requests.head; iterator != NULL; iterator = iterator->next ) {
		if ( iterator == request ) {
			// Found it, break!
			if ( prev != NULL ) {
				prev->next = iterator->next;
			} else {
				requests.head = iterator->next;
			}
			if ( requests.tail == iterator ) {
				requests.tail = prev;
			}
			break;
		}
		prev = iterator;
	}
	pthread_spin_unlock( &requests.lock );
	return iterator;
}

static uint64_t nowMilli()
{
	struct timespec ts;
	if ( clock_gettime( CLOCK_MONOTONIC_RAW, &ts ) != 0 ) {
		printf( "clock_gettime() failed. Errno: %d\n", errno );
		return 0;
	}
	return ( ts.tv_sec * 1000ull ) + ( ts.tv_nsec / 1000000ull );
}

static uint64_t nowMicro()
{
	struct timespec ts;
	if ( clock_gettime( CLOCK_MONOTONIC_RAW, &ts ) != 0 ) {
		printf( "clock_gettime() failed. Errno: %d\n", errno );
		return 0;
	}
	return ( ts.tv_sec * 1000000ull ) + ( ts.tv_nsec / 1000ull );
}

