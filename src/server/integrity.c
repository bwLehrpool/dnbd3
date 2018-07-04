#include "integrity.h"

#include "helper.h"
#include "locks.h"
#include "image.h"
#include "uplink.h"

#include <assert.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define CHECK_QUEUE_SIZE 500

typedef struct
{
	dnbd3_image_t *image; // Image to check
	int block;            // Block to check
	bool full;            // Check all blocks in image; .block will be increased
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
		} else if ( checkQueue[i].image == image
				&& ( checkQueue[i].block == block || checkQueue[i].full ) ) {
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
	if ( block == -1 ) {
		checkQueue[freeSlot].block = 0;
		checkQueue[freeSlot].full = true;
	} else {
		checkQueue[freeSlot].block = block;
		checkQueue[freeSlot].full = false;
	}
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
	pid_t tid = (pid_t)syscall( SYS_gettid );
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
			if ( !checkQueue[i].full || image == NULL ) {
				checkQueue[i].image = NULL;
				if ( i + 1 == queueLen ) queueLen--;
			}
			if ( image == NULL ) continue;
			// We have the image. Call image_release() some time
			bool full = checkQueue[i].full;
			bool foundCorrupted = false;
			spin_lock( &image->lock );
			if ( image->crc32 != NULL && image->realFilesize != 0 ) {
				int blocks[2] = { checkQueue[i].block, -1 };
				pthread_mutex_unlock( &integrityQueueLock );
				// Make copy of crc32 list as it might go away
				const uint64_t fileSize = image->realFilesize;
				const int numHashBlocks = IMGSIZE_TO_HASHBLOCKS(fileSize);
				const size_t required = numHashBlocks * sizeof(uint32_t);
				if ( buffer == NULL || required > bufferSize ) {
					bufferSize = required;
					if ( buffer != NULL ) free( buffer );
					buffer = malloc( bufferSize );
				}
				memcpy( buffer, image->crc32, required );
				spin_unlock( &image->lock );
				// Open for direct I/O if possible; this prevents polluting the fs cache
				int fd = open( image->path, O_RDONLY | O_DIRECT );
				bool direct = fd != -1;
				if ( unlikely( !direct ) ) {
					// Try unbuffered; flush to disk for that
					logadd( LOG_DEBUG1, "O_DIRECT failed for %s", image->path );
					image_ensureOpen( image );
					fd = image->readFd;
				}
				int checkCount = full ? 5 : 1;
				if ( fd != -1 ) {
					while ( blocks[0] < numHashBlocks && !_shutdown ) {
						const uint64_t start = blocks[0] * HASH_BLOCK_SIZE;
						const uint64_t end = MIN( (uint64_t)(blocks[0] + 1) * HASH_BLOCK_SIZE, image->virtualFilesize );
						bool complete = true;
						if ( full ) {
							// When checking full image, skip incomplete blocks, otherwise assume block is complete
							spin_lock( &image->lock );
							complete = image_isHashBlockComplete( image->cache_map, blocks[0], fileSize );
							spin_unlock( &image->lock );
						}
						if ( fsync( fd ) == -1 ) {
							logadd( LOG_ERROR, "Cannot flush %s for integrity check", image->path );
							exit( 1 );
						}
						// Use direct I/O only if read length is multiple of 4096 to be on the safe side
						int tfd;
						if ( direct && ( end % DNBD3_BLOCK_SIZE ) == 0 ) {
							// Suitable for direct io
							tfd = fd;
						} else if ( !image_ensureOpen( image ) ) {
							logadd( LOG_WARNING, "Cannot open %s for reading", image->path );
							break;
						} else {
							tfd = image->readFd;
							// Evict from cache so we have to re-read, making sure data was properly stored
							posix_fadvise( fd, start, end - start, POSIX_FADV_DONTNEED );
						}
						if ( complete && !image_checkBlocksCrc32( tfd, (uint32_t*)buffer, blocks, fileSize ) ) {
							logadd( LOG_WARNING, "Hash check for block %d of %s failed!", blocks[0], image->name );
							image_updateCachemap( image, start, end, false );
							// If this is not a full check, queue one
							if ( !full ) {
								logadd( LOG_INFO, "Queueing full check for %s", image->name );
								integrity_check( image, -1 );
							}
							foundCorrupted = true;
						}
						if ( complete && --checkCount == 0 ) break;
						blocks[0]++;
					}
					if ( direct ) {
						close( fd );
					}
				}
				pthread_mutex_lock( &integrityQueueLock );
				if ( full ) {
					assert( checkQueue[i].image == image );
					assert( checkQueue[i].full );
					if ( checkCount == 0 ) {
						// Not done yet, keep going
						checkQueue[i].block = blocks[0] + 1;
					} else {
						// Didn't check as many blocks as requested, so we must be done
						checkQueue[i].image = NULL;
						if ( i + 1 == queueLen ) queueLen--;
						spin_lock( &image->lock );
						if ( image->uplink != NULL ) { // TODO: image_determineWorkingState() helper?
							image->working = image->uplink->fd != -1 && image->readFd != -1;
						}
						spin_unlock( &image->lock );
					}
				}
			} else {
				spin_unlock( &image->lock );
			}
			if ( foundCorrupted ) {
				// Something was fishy, make sure uplink exists
				spin_lock( &image->lock );
				image->working = false;
				bool restart = image->uplink == NULL || image->uplink->shutdown;
				spin_unlock( &image->lock );
				if ( restart ) {
					uplink_shutdown( image );
					uplink_init( image, -1, NULL, -1 );
				}
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

