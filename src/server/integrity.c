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
	int count;            // How many blocks to check starting at .block
} queue_entry;

static pthread_t thread;
static queue_entry checkQueue[CHECK_QUEUE_SIZE];
static pthread_mutex_t integrityQueueLock;
static pthread_cond_t queueSignal;
static int queueLen = -1;
static atomic_bool bRunning = false;

static void* integrity_main(void *data);

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
void integrity_check(dnbd3_image_t *image, int block)
{
	if ( !bRunning ) {
		logadd( LOG_MINOR, "Ignoring check request; thread not running..." );
		return;
	}
	int i, freeSlot = -1;
	mutex_lock( &integrityQueueLock );
	for (i = 0; i < queueLen; ++i) {
		if ( freeSlot == -1 && checkQueue[i].image == NULL ) {
			freeSlot = i;
		} else if ( checkQueue[i].image == image
				&& checkQueue[i].block <= block && checkQueue[i].block + checkQueue[i].count >= block ) {
			// Already queued check dominates this one, or at least lies directly before this block
			if ( checkQueue[i].block + checkQueue[i].count == block ) {
				// It's directly before this one; expand range
				checkQueue[i].count += 1;
			}
			logadd( LOG_DEBUG2, "Attaching to existing check request (%d/%d) (%d +%d)", i, queueLen, checkQueue[i].block, checkQueue[i].count );
			mutex_unlock( &integrityQueueLock );
			return;
		}
	}
	if ( freeSlot == -1 ) {
		if ( queueLen >= CHECK_QUEUE_SIZE ) {
			mutex_unlock( &integrityQueueLock );
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
			mutex_lock( &image->lock );
			if ( image->crc32 != NULL && image->realFilesize != 0 ) {
				int blocks[2] = { checkQueue[i].block, -1 };
				mutex_unlock( &integrityQueueLock );
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
				mutex_unlock( &image->lock );
				// Open for direct I/O if possible; this prevents polluting the fs cache
				int fd = open( image->path, O_RDONLY | O_DIRECT );
				bool direct = fd != -1;
				if ( unlikely( !direct ) ) {
					// Try unbuffered; flush to disk for that
					logadd( LOG_DEBUG1, "O_DIRECT failed for %s", image->path );
					image_ensureOpen( image );
					fd = image->readFd;
				}
				int checkCount = MIN( qCount, 5 );
				if ( fd != -1 ) {
					while ( blocks[0] < numHashBlocks && !_shutdown ) {
						const uint64_t start = blocks[0] * HASH_BLOCK_SIZE;
						const uint64_t end = MIN( (uint64_t)(blocks[0] + 1) * HASH_BLOCK_SIZE, image->virtualFilesize );
						bool complete = true;
						if ( qCount == CHECK_ALL ) {
							dnbd3_cache_map_t *cache = ref_get_cachemap( image );
							if ( cache != NULL ) {
								// When checking full image, skip incomplete blocks, otherwise assume block is complete
								complete = image_isHashBlockComplete( cache->map, blocks[0], fileSize );
								ref_put( &cache->reference );
							}
						}
#if defined(linux) || defined(__linux)
						while ( sync_file_range( fd, start, end - start, SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER ) == -1 )
#else
						while ( fsync( fd ) == -1 )
#endif
						{
							if ( _shutdown )
								break;
							if ( errno == EINTR )
								continue;
							logadd( LOG_ERROR, "Cannot flush %s for integrity check (errno=%d)", image->path, errno );
							exit( 1 );
						}
						if ( _shutdown )
							break;
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
							if ( qCount != CHECK_ALL ) {
								logadd( LOG_INFO, "Queueing full check for %s", image->name );
								integrity_check( image, -1 );
							}
							foundCorrupted = true;
						}
						blocks[0]++; // Increase before break, so it always points to the next block to check after loop
						if ( complete && --checkCount == 0 ) break;
					}
					if ( direct ) {
						close( fd );
					}
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
				if ( checkCount > 0 || checkQueue[i].count <= 0 || fd == -1 ) {
					// Done with this task as nothing left, OR we don't have an fd to read from
					if ( fd == -1 ) {
						logadd( LOG_WARNING, "Cannot hash check %s: bad fd", image->path );
					}
					checkQueue[i].image = NULL;
					if ( i + 1 == queueLen ) queueLen--;
					// Mark as working again if applicable
					if ( !foundCorrupted ) {
						dnbd3_uplink_t *uplink = ref_get_uplink( &image->uplinkref );
						if ( uplink != NULL ) { // TODO: image_determineWorkingState() helper?
							mutex_lock( &image->lock );
							image->working = uplink->current.fd != -1 && image->readFd != -1;
							mutex_unlock( &image->lock );
							ref_put( &uplink->reference );
						}
					}
				} else {
					// Still more blocks to go...
					checkQueue[i].block = blocks[0];
				}
			} else {
				mutex_unlock( &image->lock );
			}
			if ( foundCorrupted ) {
				// Something was fishy, make sure uplink exists
				mutex_lock( &image->lock );
				image->working = false;
				mutex_unlock( &image->lock );
				uplink_init( image, -1, NULL, -1 );
			}
			// Release :-)
			image_release( image );
		}
	}
	mutex_unlock( &integrityQueueLock );
	if ( buffer != NULL ) {
		free( buffer );
	}
	bRunning = false;
	return NULL;
}

