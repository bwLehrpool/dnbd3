#include "integrity.h"

#include "helper.h"
#include "locks.h"
#include "image.h"
#include "uplink.h"
#include "reference.h"

#include <assert.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>

#define CHECK_QUEUE_SIZE 200

#define CHECK_ALL (0x7fffffff)

typedef struct
{
	dnbd3_image_t *image; // Image to check
	int block;            // Block to check
	int count;            // How many blocks to check starting at .block (CHECK_ALL for entire image)
} queue_entry;

static pthread_t thread;
static queue_entry checkQueue[CHECK_QUEUE_SIZE];
static pthread_mutex_t integrityQueueLock;
static pthread_cond_t queueSignal;
static int queueLen = -1;
static atomic_bool bRunning = false;

static void* integrity_main(void *data);
static void flushFileRange(dnbd3_image_t *image, uint64_t start, uint64_t end);

/**
 * Initialize the integrity check thread
 */
void integrity_init()
{
	assert( queueLen == -1 );
	mutex_init( &integrityQueueLock, LOCK_INTEGRITY_QUEUE );
	pthread_cond_init( &queueSignal, NULL );
	mutex_lock( &integrityQueueLock );
	queueLen = 0;
	mutex_unlock( &integrityQueueLock );
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
	if ( !bRunning )
		return;
	logadd( LOG_DEBUG1, "Shutting down integrity checker...\n" );
	pthread_kill( thread, SIGINT );
	mutex_lock( &integrityQueueLock );
	pthread_cond_signal( &queueSignal );
	mutex_unlock( &integrityQueueLock );
	thread_join( thread, NULL );
	mutex_destroy( &integrityQueueLock );
	pthread_cond_destroy( &queueSignal );
	logadd( LOG_DEBUG1, "Integrity checker exited normally.\n" );
}

/**
 * Schedule an integrity check on the given image for the given hash block.
 * It is not checked whether the block is completely cached locally, so
 * make sure it is before calling, otherwise it will result in falsely
 * detected corruption.
 */
void integrity_check(dnbd3_image_t *image, int block, bool blocking)
{
	int freeSlot;
	if ( !bRunning ) {
		logadd( LOG_MINOR, "Ignoring check request; thread not running..." );
		return;
	}
start_over:
	freeSlot = -1;
	mutex_lock( &integrityQueueLock );
	for (int i = 0; i < queueLen; ++i) {
		if ( freeSlot == -1 && checkQueue[i].image == NULL ) {
			freeSlot = i;
			continue;
		}
		if ( checkQueue[i].image != image ) {
			continue;
		}
		// There is an existing check request for the given image, see if we can merge
		if ( block == -1 ) {
			// New request is supposed to check entire image, reset existing queue item
			checkQueue[i].block = 0;
			checkQueue[i].count = CHECK_ALL;
			mutex_unlock( &integrityQueueLock );
			return;
		}
		if ( checkQueue[i].block <= block ) {
			// The block to check is after the block to check in queue
			if ( checkQueue[i].count == CHECK_ALL ) {
				logadd( LOG_DEBUG2, "Dominated by full image scan request (%d/%d) (at %d)",
						i, queueLen, checkQueue[i].block );
			} else if ( checkQueue[i].block + checkQueue[i].count == block ) {
				checkQueue[i].count += 1;
				logadd( LOG_DEBUG2, "Attaching to existing check request (%d/%d) (at %d, %d to go)",
						i, queueLen, checkQueue[i].block, checkQueue[i].count );
			} else if ( checkQueue[i].block + checkQueue[i].count > block ) {
				logadd( LOG_DEBUG2, "Dominated by existing check request (%d/%d) (at %d, %d to go)",
						i, queueLen, checkQueue[i].block, checkQueue[i].count );
			} else {
				continue; // Keep looking
			}
			mutex_unlock( &integrityQueueLock );
			return; // Nothing to do for one of the reasons above
		}
	}
	if ( freeSlot == -1 ) {
		if ( unlikely( queueLen >= CHECK_QUEUE_SIZE ) ) {
			mutex_unlock( &integrityQueueLock );
			if ( blocking ) {
				logadd( LOG_INFO, "Check queue full, waiting a couple seconds...\n" );
				sleep( 3 );
				goto start_over;
			}
			logadd( LOG_INFO, "Check queue full, discarding check request...\n" );
			return;
		}
		freeSlot = queueLen++;
	}
	checkQueue[freeSlot].image = image;
	if ( block == -1 ) {
		checkQueue[freeSlot].block = 0;
		checkQueue[freeSlot].count = CHECK_ALL;
	} else {
		checkQueue[freeSlot].block = block;
		checkQueue[freeSlot].count = 1;
	}
	pthread_cond_signal( &queueSignal );
	mutex_unlock( &integrityQueueLock );
}

static void* integrity_main(void * data UNUSED)
{
	int i;
	setThreadName( "image-check" );
	blockNoncriticalSignals();
#if defined(__linux__)
	// Setting nice of this thread - this is not POSIX conforming, so check if other platforms support this.
	// POSIX says that setpriority() should set the nice value of all threads belonging to the current process,
	// but on linux you can do this per thread.
	pid_t tid = (pid_t)syscall( SYS_gettid );
	setpriority( PRIO_PROCESS, tid, 10 );
#endif
	mutex_lock( &integrityQueueLock );
	while ( !_shutdown ) {
		if ( queueLen == 0 ) {
			mutex_cond_wait( &queueSignal, &integrityQueueLock );
		}
		for (i = queueLen - 1; i >= 0; --i) {
			if ( _shutdown ) break;
			dnbd3_image_t * const image = image_lock( checkQueue[i].image );
			if ( checkQueue[i].count == 0 || image == NULL ) {
				checkQueue[i].image = image_release( image );
				if ( i + 1 == queueLen ) queueLen--;
				continue;
			}
			// We have the image. Call image_release() some time
			const int qCount = checkQueue[i].count;
			bool foundCorrupted = false;
			if ( image->crc32 != NULL && image->realFilesize != 0 ) {
				int blocks[2] = { checkQueue[i].block, -1 };
				mutex_unlock( &integrityQueueLock );
				const uint64_t fileSize = image->realFilesize;
				const int numHashBlocks = IMGSIZE_TO_HASHBLOCKS(fileSize);
				int checkCount = MIN( qCount, 5 );
				int readFd = -1, directFd = -1;
				while ( blocks[0] < numHashBlocks && !_shutdown ) {
					const uint64_t start = blocks[0] * HASH_BLOCK_SIZE;
					const uint64_t end = MIN( (uint64_t)(blocks[0] + 1) * HASH_BLOCK_SIZE, image->virtualFilesize );
					bool complete = true;
					if ( qCount == CHECK_ALL ) {
						dnbd3_cache_map_t *cache = ref_get_cachemap( image );
						if ( cache != NULL ) {
							// When checking full image, skip incomplete blocks, otherwise assume block is complete
							complete = image_isHashBlockComplete( cache, blocks[0], fileSize );
							ref_put( &cache->reference );
						}
					}
					// Flush to disk if there's an uplink, as that means the block might have been written recently
					if ( image->uplinkref != NULL ) {
						flushFileRange( image, start, end );
					}
					if ( _shutdown )
						break;
					// Open for direct I/O if possible; this prevents polluting the fs cache
					if ( directFd == -1 && ( end % DNBD3_BLOCK_SIZE ) == 0 ) {
						// Use direct I/O only if read length is multiple of 4096 to be on the safe side
						directFd = open( image->path, O_RDONLY | O_DIRECT );
						if ( directFd == -1 ) {
							logadd( LOG_DEBUG2, "O_DIRECT failed for %s (errno=%d)", image->path, errno );
							directFd = -2;
						} else {
							readFd = directFd;
						}
					}
					if ( readFd == -1 ) { // Try buffered as fallback
						if ( image_ensureOpen( image ) && !image->problem.read ) {
							readFd = image->readFd;
						}
					}
					if ( readFd == -1 ) {
						logadd( LOG_MINOR, "Couldn't get any valid fd for integrity check of %s... ignoring...", image->path );
					} else if ( complete && !image_checkBlocksCrc32( readFd, image->crc32, blocks, fileSize ) ) {
						bool iscomplete = true;
						dnbd3_cache_map_t *cache = ref_get_cachemap( image );
						if ( cache != NULL ) {
							iscomplete = image_isHashBlockComplete( cache, blocks[0], fileSize );
							ref_put( &cache->reference );
						}
						logadd( LOG_WARNING, "Hash check for block %d of %s failed (complete: was: %d, is: %d)", blocks[0], image->name, (int)complete, (int)iscomplete );
						image_updateCachemap( image, start, end, false );
						// If this is not a full check, queue one
						if ( qCount != CHECK_ALL ) {
							logadd( LOG_INFO, "Queueing full check for %s", image->name );
							integrity_check( image, -1, false );
						}
						foundCorrupted = true;
					}
					blocks[0]++; // Increase before break, so it always points to the next block to check after loop
					if ( complete && --checkCount == 0 )
						break;
				}
				if ( directFd != -1 && directFd != -2 ) {
					close( directFd );
				}
				mutex_lock( &integrityQueueLock );
				assert( checkQueue[i].image == image );
				if ( qCount != CHECK_ALL ) {
					// Not a full check; update the counter
					checkQueue[i].count -= ( blocks[0] - checkQueue[i].block );
					if ( checkQueue[i].count < 0 ) {
						logadd( LOG_WARNING, "BUG! checkQueue counter ran negative" );
					}
				}
				if ( checkCount > 0 || checkQueue[i].count <= 0 ) {
					// Done with this task as nothing left
					checkQueue[i].image = NULL;
					if ( i + 1 == queueLen ) queueLen--;
				} else {
					// Still more blocks to go...
					checkQueue[i].block = blocks[0];
				}
			}
			if ( foundCorrupted && !_shutdown ) {
				// Something was fishy, make sure uplink exists
				uplink_init( image, -1, NULL, -1 );
			}
			// Release :-)
			image_release( image );
		}
	}
	mutex_unlock( &integrityQueueLock );
	bRunning = false;
	return NULL;
}

static void flushFileRange(dnbd3_image_t *image, uint64_t start, uint64_t end)
{
	int flushFd;
	int writableFd = -1;
	dnbd3_uplink_t *uplink = ref_get_uplink( &image->uplinkref );
	if ( uplink != NULL ) { // Try to steal uplink's writable fd
		if ( uplink->cacheFd != -1 ) {
			writableFd = dup( uplink->cacheFd );
		}
		ref_put( &uplink->reference );
	}
	if ( writableFd == -1 ) { // Open file as writable
		writableFd = open( image->path, O_WRONLY );
	}
	if ( writableFd == -1 ) { // Fallback to readFd (should work on Linux and BSD...)
		logadd( LOG_WARNING, "flushFileRange: Cannot open %s for writing. Trying readFd.", image->path );
		image_ensureOpen( image );
		flushFd = image->readFd;
	} else {
		flushFd = writableFd;
	}
	if ( flushFd == -1 )
		return;
#if defined(__linux__)
	while ( sync_file_range( flushFd, start, end - start, SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER ) == -1 )
#else
	while ( fsync( flushFd ) == -1 ) // TODO: fdatasync() should be available since FreeBSD 12.0 ... Might be a tad bit faster
#endif
	{
		if ( _shutdown )
			break;
		int e = errno;
		if ( e == EINTR )
			continue;
		logadd( LOG_ERROR, "Cannot flush %s for integrity check (errno=%d)", image->path, e );
		if ( e == EIO ) {
			exit( 1 );
		}
	}
	// Evict from cache too so we have to re-read, making sure data was properly stored
	posix_fadvise( flushFd, start, end - start, POSIX_FADV_DONTNEED );
	if ( writableFd != -1 ) {
		close( writableFd );
	}
}
