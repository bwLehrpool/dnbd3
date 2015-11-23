#include "connection.h"
#include "helper.h"
#include "../config.h"
#include "../shared/protocol.h"
#include "../shared/signal.h"

#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* Constants */
static const size_t SHORTBUF = 100;
#define MAX_ALTS (8)

/* Module variables */

// Init guard
static bool initDone = false;
static pthread_mutex_t mutexInit = PTHREAD_MUTEX_INITIALIZER;

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
	int sockFd;
	pthread_mutex_t sendMutex;
	pthread_t receiveThread;
} image;

// Known alt servers
static struct _alt_server {

} altservers[MAX_ALTS];
typedef struct _alt_server alt_server_t;

/* Static methods */


static void* connection_receiveThreadMain(void *sock);

static bool throwDataAway(int sockFd, uint32_t amount);
static void enqueueRequest(dnbd3_async_t *request);
static dnbd3_async_t* removeRequest(dnbd3_async_t *request);

bool connection_init(const char *hosts, const char *lowerImage, const uint16_t rid)
{
	int sock = -1;
	char host[SHORTBUF];
	const char *current, *end;
	serialized_buffer_t buffer;
	uint16_t remoteVersion, remoteRid;
	char *remoteName;
	uint64_t remoteSize;

	pthread_mutex_lock( &mutexInit );
	if ( !initDone ) {
		current = hosts;
		do {
			// Get next host from string
			while ( *current == ' ' ) current++;
			end = strchr( current, ' ' );
			size_t len = (end == NULL ? SHORTBUF : (size_t)( end - current ) + 1);
			if ( len > SHORTBUF ) len = SHORTBUF;
			snprintf( host, len, "%s", current );
			current = end + 1;
			// Try to connect
			sock = connect_to_server( host, PORT ); // TODO: Parse port from host
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
			// TODO: Add to alt list
		} while ( end != NULL );
		if ( sock != -1 ) {
			if ( pthread_mutex_init( &image.sendMutex, NULL ) != 0
					|| pthread_spin_init( &requests.lock, PTHREAD_PROCESS_PRIVATE ) != 0
					|| pthread_create( &image.receiveThread, NULL, &connection_receiveThreadMain, (void*)(size_t)sock ) != 0 ) {
				close( sock );
				sock = -1;
			} else {
				image.sockFd = sock;
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
	pthread_mutex_lock( &image.sendMutex );
	if ( image.sockFd != -1 ) {
		while ( !dnbd3_get_block( image.sockFd, request->offset, request->length, (uint64_t)request ) ) {
			shutdown( image.sockFd, SHUT_RDWR );
			image.sockFd = -1;
			// TODO reconnect!
			pthread_mutex_unlock( &image.sendMutex );
			return false;
		}
	}
	pthread_mutex_unlock( &image.sendMutex );
	return true;
}

void connection_close()
{
	//
}

static void* connection_receiveThreadMain(void *sockPtr)
{
	int sockFd = (int)(size_t)sockPtr;
	dnbd3_reply_t reply;
	for ( ;; ) {
		if ( !dnbd3_get_reply( image.sockFd, &reply ) )
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
	pthread_mutex_lock( &image.sendMutex );
	// then just set the fd to -1, but only if it's the same fd as ours,
	// as someone could have established a new connection already
	if ( image.sockFd == sockFd ) {
		image.sockFd = -1;
	}
	pthread_mutex_unlock( &image.sendMutex );
	// As we're the only reader, it's safe to close the socket now
	close( sockFd );
	return NULL;
}

// Private quick helpers

static bool throwDataAway(int sockFd, uint32_t amount)
{
	uint32_t done = 0;
	char tempBuffer[SHORTBUF];
	while ( done < amount ) {
		if ( recv( sockFd, tempBuffer, MIN( amount - done, SHORTBUF ), 0 ) <= 0 )
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
