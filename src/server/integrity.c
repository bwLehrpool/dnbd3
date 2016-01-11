#include "integrity.h"

#include "locks.h"
#include "image.h"
#include "globals.h"
#include "../shared/log.h"
#include "helper.h"

#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>

#define CHECK_QUEUE_SIZE 100

typedef struct
{
	dnbd3_image_t *image;
	int block;
} queue_entry;

static pthread_t thread;
static queue_entry checkQueue[CHECK_QUEUE_SIZE];
static pthread_mutex_t integrityQueueLock;
static pthread_cond_t queueSignal;
static int queueLen = -1;
static volatile bool bRunning = false;

static void* integrity_main(void *data);

/**
 * Initialize the integrity check thread
 */
void integrity_init()
{
	assert( queueLen == -1 );
	pthread_mutex_init( &integrityQueueLock, NULL );
	pthread_cond_init( &queueSignal, NULL );
	pthread_mutex_lock( &integrityQueueLock );
	queueLen = 0;
	pthread_mutex_unlock( &integrityQueueLock );
	bRunning = true;
	if ( 0 != thread_create( &thread, NULL, &integrity_main, (void *)NULL ) ) {
		bRunning = false;
		logadd( LOG_WARNING, "Could not start integrity check thread. Corrupted images will not be detected." );
		return;
	}
}

void integrity_shutdown()
{
	assert( queueLen != -1 );
	logadd( LOG_DEBUG1, "Shutting down integrity checker...\n" );
	pthread_mutex_lock( &integrityQueueLock );
	pthread_cond_signal( &queueSignal );
	pthread_mutex_unlock( &integrityQueueLock );
	thread_join( thread, NULL );
	while ( bRunning )
		usleep( 10000 );
	pthread_mutex_destroy( &integrityQueueLock );
	pthread_cond_destroy( &queueSignal );
	logadd( LOG_DEBUG1, "Integrity checker exited normally.\n" );
}

/**
 * Schedule an integrity check on the given image for the given hash block.
 * It is not checked whether the block is completely cached locally, so
 * make sure it is before calling, otherwise it will result in falsely
 * detected corruption.
 */
void integrity_check(dnbd3_image_t *image, int block)
{
	int i, freeSlot = -1;
	pthread_mutex_lock( &integrityQueueLock );
	for (i = 0; i < queueLen; ++i) {
		if ( freeSlot == -1 && checkQueue[i].image == NULL ) {
			freeSlot = i;
		} else if ( checkQueue[i].image == image && checkQueue[i].block == block ) {
			pthread_mutex_unlock( &integrityQueueLock );
			return;
		}
	}
	if ( freeSlot == -1 ) {
		if ( queueLen >= CHECK_QUEUE_SIZE ) {
			pthread_mutex_unlock( &integrityQueueLock );
			logadd( LOG_DEBUG1, "Check queue full, discarding check request...\n" );
			return;
		}
		freeSlot = queueLen++;
	}
	checkQueue[freeSlot].image = image;
	checkQueue[freeSlot].block = block;
	pthread_cond_signal( &queueSignal );
	pthread_mutex_unlock( &integrityQueueLock );
}

static void* integrity_main(void * data UNUSED)
{
	int i;
	uint8_t *buffer = NULL;
	size_t bufferSize = 0;
	setThreadName( "image-check" );
	blockNoncriticalSignals();
#if defined(linux) || defined(__linux)
	// Setting nice of this thread - this is not POSIX conforming, so check if other platforms support this.
	// POSIX says that setpriority() should set the nice value of all threads belonging to the current process,
	// but on linux you can do this per thread.
	pid_t tid = syscall( SYS_gettid );
	setpriority( PRIO_PROCESS, tid, 10 );
#endif
	pthread_mutex_lock( &integrityQueueLock );
	while ( !_shutdown ) {
		if ( queueLen == 0 ) {
			pthread_cond_wait( &queueSignal, &integrityQueueLock );
		}
		for (i = queueLen - 1; i >= 0; --i) {
			if ( _shutdown ) break;
			dnbd3_image_t * const image = image_lock( checkQueue[i].image );
			checkQueue[i].image = NULL;
			if ( i + 1 == queueLen ) queueLen--;
			if ( image == NULL ) continue;
			// We have the image. Call image_release() some time
			spin_lock( &image->lock );
			if ( image->crc32 != NULL && image->realFilesize != 0 ) {
				int const blocks[2] = { checkQueue[i].block, -1 };
				pthread_mutex_unlock( &integrityQueueLock );
				const uint64_t fileSize = image->realFilesize;
				const size_t required = IMGSIZE_TO_HASHBLOCKS(fileSize) * sizeof(uint32_t);
				if ( required > bufferSize ) {
					bufferSize = required;
					if ( buffer != NULL ) free( buffer );
					buffer = malloc( bufferSize );
				}
				memcpy( buffer, image->crc32, required );
				spin_unlock( &image->lock );
				if ( !image_checkBlocksCrc32( image->readFd, (uint32_t*)buffer, blocks, fileSize ) ) {
					logadd( LOG_WARNING, "Hash check for block %d of %s failed!", blocks[0], image->lower_name );
					image_updateCachemap( image, blocks[0] * HASH_BLOCK_SIZE, (blocks[0] + 1) * HASH_BLOCK_SIZE, false );
				}
				pthread_mutex_lock( &integrityQueueLock );
			} else {
				spin_unlock( &image->lock );
			}
			// Release :-)
			image_release( image );
		}
	}
	pthread_mutex_unlock( &integrityQueueLock );
	if ( buffer != NULL ) free( buffer );
	bRunning = false;
	return NULL ;
}
