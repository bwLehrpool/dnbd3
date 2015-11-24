#include "connection.h"
#include "helper.h"
#include "../config.h"
#include "../shared/protocol.h"
#include "../shared/signal.h"
#include "../shared/sockhelper.h"

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
static bool initDone = false;
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
	pthread_t receiveThread;
	int panicSignalFd;
	bool panicMode;
} connection;

// Known alt servers
static struct _alt_server {
	dnbd3_host_t host;
	int consecutiveFails;
	int rtt;
	int rtts[RTT_COUNT];
	int rttIndex;
} altservers[MAX_ALTS];
typedef struct _alt_server alt_server_t;

/* Static methods */


static void* connection_receiveThreadMain(void *sock);

static void probeAltServers();
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
	if ( !initDone && keepRunning ) {
		dnbd3_host_t tempHosts[MAX_HOSTS_PER_ADDRESS];
		const char *current, *end;
		int altIndex = 0;
		memset( altservers, 0, sizeof altservers );
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
		printf( "Got %d servers from init call\n", altIndex );
		// Connect
		for ( int i = 0; i < altIndex; ++i ) {
			if ( altservers[i].host.type == 0 )
				continue;
			// Try to connect
			sock = sock_connect( &altservers[i].host, 500, SOCKET_KEEPALIVE_TIMEOUT * 2000 ); // TODO timeout...
			printf( "Got socket %d\n", sock );
			if ( sock != -1 && dnbd3_select_image( sock, lowerImage, rid, 0 )
					&& dnbd3_select_image_reply( &buffer, sock, &remoteVersion, &remoteName, &remoteRid, &remoteSize )
					&& ( rid == 0 || rid == remoteRid ) ) {
				image.name = strdup(remoteName);
				image.rid = remoteRid;
				image.size = remoteSize;
				break;
			}
			// Failed
			if ( sock != -1 ) {
				close( sock );
				sock = -1;
			}
		}
		if ( sock != -1 ) {
			printf( "Initializing stuff\n" );
			if ( pthread_mutex_init( &connection.sendMutex, NULL ) != 0
					|| pthread_spin_init( &requests.lock, PTHREAD_PROCESS_PRIVATE ) != 0
					|| pthread_create( &connection.receiveThread, NULL, &connection_receiveThreadMain, (void*)(size_t)sock ) != 0 ) {
				close( sock );
				sock = -1;
			} else {
				connection.sockFd = sock;
				connection.panicMode = false;
				connection.panicSignalFd = signal_new();
				requests.head = NULL;
				requests.tail = NULL;
			}
			initDone = true;
		}
	}
	pthread_mutex_unlock( &mutexInit );
	return sock != -1;
}

bool connection_read(dnbd3_async_t *request)
{
	if (!initDone) return false;
	enqueueRequest( request );
	pthread_mutex_lock( &connection.sendMutex );
	if ( connection.sockFd != -1 ) {
		while ( !dnbd3_get_block( connection.sockFd, request->offset, request->length, (uint64_t)request ) ) {
			shutdown( connection.sockFd, SHUT_RDWR );
			connection.sockFd = -1;
			// TODO reconnect!
			pthread_mutex_unlock( &connection.sendMutex );
			return false;
		}
	}
	pthread_mutex_unlock( &connection.sendMutex );
	return true;
}

void connection_close()
{
	pthread_mutex_lock( &mutexInit );
	keepRunning = false;
	if ( !initDone ) {
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

static void* connection_receiveThreadMain(void *sockPtr)
{
	int sockFd = (int)(size_t)sockPtr;
	dnbd3_reply_t reply;
	while ( keepRunning ) {
		if ( !dnbd3_get_reply( connection.sockFd, &reply ) )
			goto fail;
		// TODO: Ignoring anything but block replies for now; handle the others
		if ( reply.cmd != CMD_GET_BLOCK ) {
			if ( reply.size != 0 && !throwDataAway( sockFd, reply.size ) )
				goto fail;
		} else {
			// get block reply. find matching request
			dnbd3_async_t *request = removeRequest( (dnbd3_async_t*)reply.handle );
			if ( request == NULL ) {
				printf("WARNING BUG ALERT SOMETHING: Got block reply with no matching request\n");
				if ( reply.size != 0 && !throwDataAway( sockFd, reply.size ) )
					goto fail;
			} else {
				// Found a match
				request->finished = true;
				uint32_t done = 0;
				while ( done < request->length ) {
					if ( recv( sockFd, request->buffer + done, request->length - done, 0 ) <= 0 ) {
						request->success = false;
						signal_call( request->signalFd );
						goto fail;
					}
				}
				// Success, wake up caller
				request->success = true;
				signal_call( request->signalFd );
			}
		}
	}
fail:;
	// Make sure noone is trying to use the socket for sending by locking,
	pthread_mutex_lock( &connection.sendMutex );
	// then just set the fd to -1, but only if it's the same fd as ours,
	// as someone could have established a new connection already
	if ( connection.sockFd == sockFd ) {
		connection.sockFd = -1;
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
	const uint64_t startupTime = nowMilli();

	while ( keepRunning ) {
		const uint64_t now = nowMilli();
		if ( now < nextKeepalive && now < nextRttCheck ) {
			int waitTime = (int)( MIN( nextKeepalive, nextRttCheck ) - now );
			int waitRes = signal_wait( connection.panicSignalFd, waitTime );
			if ( waitRes == SIGNAL_ERROR ) {
				printf( "Error waiting on signal in background thread! Errno = %d\n", errno );
			}
		}
		// Woken up, see what we have to do
		// Check alt servers
		if ( connection.panicMode || now < nextRttCheck ) {
			probeAltServers();
			if ( connection.panicMode || startupTime + ( STARTUP_MODE_DURATION * 1000ull ) > now ) {
				nextRttCheck = now + TIMER_INTERVAL_PROBE_STARTUP * 1000ull;
			} else {
				nextRttCheck = now + TIMER_INTERVAL_PROBE_NORMAL * 1000ull;
			}
		}
		// Send keepalive packet
		if ( now < nextKeepalive ) {
			pthread_mutex_lock( &connection.sendMutex );
			if ( connection.sockFd != -1 ) {
				printf( "Sending keepalive...\n" );
				dnbd3_request_t request;
				request.magic = dnbd3_packet_magic;
				request.cmd = CMD_KEEPALIVE;
				request.size = 0;
				fixup_request( request );
				ssize_t ret = sock_sendAll( connection.sockFd, &request, sizeof request, 2 );
				if ( (size_t)ret != sizeof request ) {
					shutdown( connection.sockFd, SHUT_RDWR );
					connection.sockFd = -1;
					connection.panicMode = true;
				}
			}
			pthread_mutex_unlock( &connection.sendMutex );
			nextKeepalive = now + TIMER_INTERVAL_KEEPALIVE_PACKET * 1000ull;
		}
	}
	return NULL;
}

// Private quick helpers

static void probeAltServers()
{
	serialized_buffer_t buffer;
	dnbd3_request_t request;
	dnbd3_reply_t reply;
	int bestIndex = -1;
	int bestSock = -1;
	uint16_t remoteRid, remoteProto;
	uint64_t remoteSize;
	char *remoteName;

	for ( int altIndex = 0; altIndex < MAX_ALTS; ++altIndex ) {
		alt_server_t * const srv = &altservers[altIndex];
		if ( srv->host.type == 0 )
			continue;
		if ( !connection.panicMode && srv->consecutiveFails > MAX_CONSECUTIVE_FAILURES
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
		int sock = sock_connect( &srv->host, connection.panicMode ? 1000 : 333, 1000 );
		if ( sock == -1 ) {
			printf( "Could not crrate socket for probing. errno = %d\n", errno );
			continue;
		}
		if ( !dnbd3_select_image( sock, image.name, image.rid, 0 ) ) {
			goto fail;
		}
		if ( !dnbd3_select_image_reply( &buffer, sock, &remoteProto, &remoteName, &remoteRid, &remoteSize )) {
			goto fail;
		}
		if ( remoteProto < MIN_SUPPORTED_SERVER || remoteProto > PROTOCOL_VERSION ) {
			printf( "Unsupported remote version\n" );
			goto fail;
		}
		if ( remoteRid != image.rid || strcmp( remoteName, image.name ) != 0 ) {
			printf( "Remote rid or name mismatch\n" );
			goto fail;
		}
		if ( !dnbd3_get_block( sock, 0, RTT_BLOCK_SIZE, 0 ) ) {
			goto fail;
		}
		if ( !dnbd3_get_reply( sock, &reply ) || reply.size != RTT_BLOCK_SIZE
				|| !throwDataAway( sock, RTT_BLOCK_SIZE ) ) {
			goto fail;
		}
		// Yay, success
		const uint64_t end = nowMicro();
		srv->consecutiveFails = 0;
		srv->rtts[srv->rttIndex] = (int)(end - start);
		srv->rtt = 0;
		for ( int i = 0; i < RTT_COUNT; ++i ) {
			srv->rtt += srv->rtts[i];
		}
		srv->rtt /= RTT_COUNT;
		if ( bestIndex == -1 || altservers[bestIndex].rtt > srv->rtt ) {
			bestIndex = altIndex;
			close( bestSock );
			bestSock = sock;
		} else {
			close( sock );
		}
		continue; // XXX: Remember current server, compare to it, update value on change,
fail:;
		close( sock );
		srv->rtts[srv->rttIndex] = RTT_UNREACHABLE;
		srv->consecutiveFails += 1;
	}
}

static bool throwDataAway(int sockFd, uint32_t amount)
{
	uint32_t done = 0;
	char tempBuffer[SHORTBUF];
	while ( done < amount ) {
		const ssize_t ret = recv( sockFd, tempBuffer, MIN( amount - done, SHORTBUF ), MSG_NOSIGNAL );
		if ( ret == 0 || ( ret < 0 && ret != EINTR ) )
			return false;
	}
	return true;
}

static void enqueueRequest(dnbd3_async_t *request)
{
	request->next = NULL;
	request->finished = false;
	request->success = false;
	pthread_spin_lock( &requests.lock );
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
	dnbd3_async_t *iterator, *prev = NULL;
	for ( iterator = requests.head; iterator != NULL; iterator = iterator->next ) {
		if ( iterator == request ) {
			// Found it, break!
			if ( prev != NULL ) {
				prev->next = iterator->next;
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
