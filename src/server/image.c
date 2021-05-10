#include "image.h"
#include "helper.h"
#include "fileutil.h"
#include "uplink.h"
#include "locks.h"
#include "integrity.h"
#include "altservers.h"
#include <dnbd3/shared/protocol.h>
#include <dnbd3/shared/timing.h>
#include <dnbd3/shared/crc32.h>
#include "reference.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <inttypes.h>
#include <glob.h>
#include <jansson.h>

#define PATHLEN (2000)
#define NONWORKING_RECHECK_INTERVAL_SECONDS (60)

// ##########################################

static dnbd3_image_t *_images[SERVER_MAX_IMAGES];
static int _num_images = 0;

static pthread_mutex_t imageListLock;
static pthread_mutex_t remoteCloneLock;
static pthread_mutex_t reloadLock;
#define NAMELEN  500
#define CACHELEN 20
typedef struct
{
	char name[NAMELEN];
	uint16_t rid;
	ticks deadline;
} imagecache;
static imagecache remoteCloneCache[CACHELEN];

// ##########################################

static bool isForbiddenExtension(const char* name);
static dnbd3_image_t* image_remove(dnbd3_image_t *image);
static dnbd3_image_t* image_free(dnbd3_image_t *image);
static bool image_load_all_internal(char *base, char *path);
static bool image_addToList(dnbd3_image_t *image);
static bool image_load(char *base, char *path, bool withUplink);
static bool image_clone(int sock, char *name, uint16_t revision, uint64_t imageSize);
static bool image_calcBlockCrc32(const int fd, const size_t block, const uint64_t realFilesize, uint32_t *crc);
static bool image_ensureDiskSpace(uint64_t size, bool force);

static dnbd3_cache_map_t* image_loadCacheMap(const char * const imagePath, const int64_t fileSize);
static uint32_t* image_loadCrcList(const char * const imagePath, const int64_t fileSize, uint32_t *masterCrc);
static bool image_checkRandomBlocks(dnbd3_image_t *image, const int count, int fromFd);
static void* closeUnusedFds(void*);
static bool isImageFromUpstream(dnbd3_image_t *image);
static void* saveLoadAllCacheMaps(void*);
static void saveCacheMap(dnbd3_image_t *image);
static void allocCacheMap(dnbd3_image_t *image, bool complete);
static void saveMetaData(dnbd3_image_t *image, ticks *now, time_t walltime);
static void loadImageMeta(dnbd3_image_t *image);

static void cmfree(ref *ref)
{
	dnbd3_cache_map_t *cache = container_of(ref, dnbd3_cache_map_t, reference);
	logadd( LOG_DEBUG2, "Freeing a cache map" );
	free( cache );
}

// ##########################################

void image_serverStartup()
{
	srand( (unsigned int)time( NULL ) );
	mutex_init( &imageListLock, LOCK_IMAGE_LIST );
	mutex_init( &remoteCloneLock, LOCK_REMOTE_CLONE );
	mutex_init( &reloadLock, LOCK_RELOAD );
	server_addJob( &closeUnusedFds, NULL, 10, 900 );
	server_addJob( &saveLoadAllCacheMaps, NULL, 9, 20 );
}

/**
 * Update cache-map of given image for the given byte range
 * start (inclusive) - end (exclusive)
 */
void image_updateCachemap(dnbd3_image_t *image, uint64_t start, uint64_t end, const bool set)
{
	assert( image != NULL );
	// This should always be block borders due to how the protocol works, but better be safe
	// than accidentally mark blocks as cached when they really aren't entirely cached.
	assert( end <= image->virtualFilesize );
	assert( start <= end );
	if ( set ) {
		// If we set as cached, move "inwards" in case we're not at 4k border
		end &= ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
		start = (uint64_t)(start + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
	} else {
		// If marking as NOT cached, move "outwards" in case we're not at 4k border
		start &= ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
		end = (uint64_t)(end + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
	}
	if ( start >= end )
		return;
	bool setNewBlocks = false;
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	if ( cache == NULL ) {
		// Image seems already complete
		if ( set ) {
			// This makes no sense
			logadd( LOG_DEBUG1, "image_updateCachemap(true) with no cache map: %s", image->path );
			return;
		}
		// Recreate a cache map, set it to all 1 initially as we assume the image was complete
		allocCacheMap( image, true );
		cache = ref_get_cachemap( image );
		if ( cache == NULL ) {
			logadd( LOG_WARNING, "WHAT!!!?!?!= No cache map right after alloc?! %s", image->path );
			return;
		}
	}
	// Set/unset
	const uint64_t firstByteInMap = start >> 15;
	const uint64_t lastByteInMap = (end - 1) >> 15;
	uint64_t pos;
	// First and last byte masks
	const uint8_t fb = (uint8_t)(0xff << ((start >> 12) & 7));
	const uint8_t lb = (uint8_t)(~(0xff << ((((end - 1) >> 12) & 7) + 1)));
	if ( firstByteInMap == lastByteInMap ) {
		if ( set ) {
			uint8_t o = atomic_fetch_or( &cache->map[firstByteInMap], (uint8_t)(fb & lb) );
			setNewBlocks = o != ( o | (fb & lb) );
		} else {
			atomic_fetch_and( &cache->map[firstByteInMap], (uint8_t)~(fb & lb) );
		}
	} else {
		atomic_thread_fence( memory_order_acquire );
		if ( set ) {
			uint8_t fo = atomic_fetch_or_explicit( &cache->map[firstByteInMap], fb, memory_order_relaxed );
			uint8_t lo = atomic_fetch_or_explicit( &cache->map[lastByteInMap], lb, memory_order_relaxed );
			setNewBlocks = ( fo != ( fo | fb ) || lo != ( lo | lb ) );
		} else {
			atomic_fetch_and_explicit( &cache->map[firstByteInMap], (uint8_t)~fb, memory_order_relaxed );
			atomic_fetch_and_explicit( &cache->map[lastByteInMap], (uint8_t)~lb, memory_order_relaxed );
		}
		// Everything in between
		const uint8_t nval = set ? 0xff : 0;
		for ( pos = firstByteInMap + 1; pos < lastByteInMap; ++pos ) {
			if ( atomic_exchange_explicit( &cache->map[pos], nval, memory_order_relaxed ) != nval && set ) {
				setNewBlocks = true;
			}
		}
		atomic_thread_fence( memory_order_release );
	}
	if ( setNewBlocks && image->crc32 != NULL ) {
		// If setNewBlocks is set, at least one of the blocks was not cached before, so queue all hash blocks
		// for checking, even though this might lead to checking some hash block again, if it was
		// already complete and the block range spanned at least two hash blocks.
		// First set start and end to borders of hash blocks
		start &= ~(uint64_t)(HASH_BLOCK_SIZE - 1);
		end = (end + HASH_BLOCK_SIZE - 1) & ~(uint64_t)(HASH_BLOCK_SIZE - 1);
		for ( pos = start; pos < end; pos += HASH_BLOCK_SIZE ) {
			const int block = (int)( pos / HASH_BLOCK_SIZE );
			if ( image_isHashBlockComplete( cache, block, image->realFilesize ) ) {
				integrity_check( image, block, false );
			}
		}
	} else if ( !set ) {
		cache->dirty = true;
	}
	ref_put( &cache->reference );
}

/**
 * Returns true if the given image is complete.
 * Also frees cache_map and deletes it on disk
 * if it hasn't been complete before
 * Locks on: image.lock
 */
bool image_isComplete(dnbd3_image_t *image)
{
	assert( image != NULL );
	if ( image->virtualFilesize == 0 ) {
		return false;
	}
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	if ( cache == NULL ) {
		return true;
	}
	bool complete = true;
	int j;
	const int map_len_bytes = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
	for (j = 0; j < map_len_bytes - 1; ++j) {
		if ( cache->map[j] != 0xFF ) {
			complete = false;
			break;
		}
	}
	if ( complete ) { // Every block except the last one is complete
		// Last one might need extra treatment if it's not a full byte
		const int blocks_in_last_byte = (image->virtualFilesize >> 12) & 7;
		uint8_t last_byte = 0;
		if ( blocks_in_last_byte == 0 ) {
			last_byte = 0xFF;
		} else {
			for (j = 0; j < blocks_in_last_byte; ++j)
				last_byte |= (uint8_t)(1 << j);
		}
		complete = ((cache->map[map_len_bytes - 1] & last_byte) == last_byte);
	}
	ref_put( &cache->reference );
	if ( !complete )
		return false;
	mutex_lock( &image->lock );
	// Lock and make sure current cache map is still the one we saw complete
	dnbd3_cache_map_t *current = ref_get_cachemap( image );
	if ( current == cache ) {
		// Set cache map NULL as it's complete
		ref_setref( &image->ref_cacheMap, NULL );
	}
	if ( current != NULL ) {
		ref_put( &current->reference );
	}
	mutex_unlock( &image->lock );
	if ( current == cache ) { // Successfully set cache map to NULL above
		char mapfile[PATHLEN] = "";
		snprintf( mapfile, PATHLEN, "%s.map", image->path );
		unlink( mapfile );
	}
	return true;
}

/**
 * Make sure readFd is open, useful when closeUnusedFd is active.
 * This function assumes you called image_lock first, so its known
 * to be active and the fd won't be closed halfway through the
 * function.
 * Does not update atime, so the fd might be closed again very soon.
 * Since the caller should have image_lock()ed first, it could do
 * a quick operation on it before calling image_release which
 * guarantees that the fd will not be closed meanwhile.
 */
bool image_ensureOpen(dnbd3_image_t *image)
{
	bool sizeChanged = false;
	if ( image->readFd != -1 && !image->problem.changed )
		return true;
	int newFd = image->readFd == -1 ? open( image->path, O_RDONLY ) : dup( image->readFd );
	if ( newFd == -1 ) {
		if ( !image->problem.read ) {
			logadd( LOG_WARNING, "Cannot open %s for reading", image->path );
			image->problem.read = true;
		}
	} else {
		// Check size + read access
		char buffer[100];
		const off_t flen = lseek( newFd, 0, SEEK_END );
		if ( flen == -1 ) {
			if ( !image->problem.read ) {
				logadd( LOG_WARNING, "Could not seek to end of %s (errno %d)", image->path, errno );
				image->problem.read = true;
			}
			close( newFd );
			newFd = -1;
		} else if ( (uint64_t)flen != image->realFilesize ) {
			if ( !image->problem.changed ) {
				logadd( LOG_WARNING, "Size of active image with closed fd changed from %" PRIu64 " to %" PRIu64,
						image->realFilesize, (uint64_t)flen );
			}
			sizeChanged = true;
		} else if ( pread( newFd, buffer, sizeof(buffer), 0 ) == -1 ) {
			if ( !image->problem.read ) {
				logadd( LOG_WARNING, "Reading first %d bytes from %s failed (errno=%d)",
						(int)sizeof(buffer), image->path, errno );
				image->problem.read = true;
			}
			close( newFd );
			newFd = -1;
		}
	}
	if ( newFd == -1 ) {
		if ( sizeChanged ) {
			image->problem.changed = true;
		}
		return false;
	}

	// Re-opened. Check if the "size/content changed" flag was set before and if so, check crc32,
	// but only if the size we just got above is correct.
	if ( image->problem.changed && !sizeChanged ) {
		if ( image->crc32 == NULL ) {
			// Cannot verify further, hope for the best
			image->problem.changed = false;
			logadd( LOG_DEBUG1, "Size of image %s:%d changed back to expected value", PIMG(image) );
		} else if ( image_checkRandomBlocks( image, 1, newFd ) ) {
			// This should have checked the first block (if complete) -> All is well again
			image->problem.changed = false;
			logadd( LOG_DEBUG1, "Size and CRC of image %s:%d changed back to expected value", PIMG(image) );
		}
	} else {
		image->problem.changed = sizeChanged;
	}

	mutex_lock( &image->lock );
	if ( image->readFd == -1 ) {
		image->readFd = newFd;
		image->problem.read = false;
		mutex_unlock( &image->lock );
	} else {
		// There was a race while opening the file (happens cause not locked cause blocking),
		// we lost the race so close new fd and proceed.
		// *OR* we dup()'ed above for cheating when the image changed before.
		mutex_unlock( &image->lock );
		close( newFd );
	}
	return image->readFd != -1;
}

dnbd3_image_t* image_byId(int imgId)
{
	int i;
	mutex_lock( &imageListLock );
	for (i = 0; i < _num_images; ++i) {
		dnbd3_image_t * const image = _images[i];
		if ( image != NULL && image->id == imgId ) {
			image->users++;
			mutex_unlock( &imageListLock );
			return image;
		}
	}
	mutex_unlock( &imageListLock );
	return NULL;
}

/**
 * Get an image by name+rid. This function increases a reference counter,
 * so you HAVE TO CALL image_release for every image_get() call at some
 * point...
 * Locks on: imageListLock, _images[].lock
 */
dnbd3_image_t* image_get(const char *name, uint16_t revision, bool ensureFdOpen)
{
	int i;
	dnbd3_image_t *candidate = NULL;
	// Simple sanity check
	const size_t slen = strlen( name );
	if ( slen == 0 || name[slen - 1] == '/' || name[0] == '/' ) return NULL ;
	// Go through array
	mutex_lock( &imageListLock );
	for (i = 0; i < _num_images; ++i) {
		dnbd3_image_t * const image = _images[i];
		if ( image == NULL || strcmp( image->name, name ) != 0 ) continue;
		if ( revision == image->rid ) {
			candidate = image;
			break;
		} else if ( revision == 0 && (candidate == NULL || candidate->rid < image->rid) ) {
			candidate = image;
		}
	}

	// Not found
	if ( candidate == NULL ) {
		mutex_unlock( &imageListLock );
		return NULL ;
	}

	candidate->users++;
	mutex_unlock( &imageListLock );

	if ( !ensureFdOpen ) // Don't want to re-check
		return candidate;

	if ( image_ensureOpen( candidate ) && !candidate->problem.read )
		return candidate; // We have a read fd and no read or changed problems

	// -- image could not be opened again, or is open but has problem --

	if ( _removeMissingImages && !file_isReadable( candidate->path ) ) {
		candidate = image_remove( candidate );
		// No image_release here, the image is still returned and should be released by caller
	} else if ( candidate->readFd != -1 ) {
		// We cannot just close the fd as it might be in use. Make a copy and remove old entry.
		candidate = image_remove( candidate );
		// Could not access the image with exising fd - mark for reload which will re-open the file.
		// make a copy of the image struct but keep the old one around. If/When it's not being used
		// anymore, it will be freed automatically.
		logadd( LOG_DEBUG1, "Reloading image file %s because of read problem/changed", candidate->path );
		dnbd3_image_t *img = calloc( sizeof(dnbd3_image_t), 1 );
		img->path = strdup( candidate->path );
		img->name = strdup( candidate->name );
		img->virtualFilesize = candidate->virtualFilesize;
		img->realFilesize = candidate->realFilesize;
		timing_get( &img->atime );
		img->masterCrc32 = candidate->masterCrc32;
		img->readFd = -1;
		img->rid = candidate->rid;
		img->users = 1;
		img->problem.read = true;
		img->problem.changed = candidate->problem.changed;
		img->ref_cacheMap = NULL;
		mutex_init( &img->lock, LOCK_IMAGE );
		if ( candidate->crc32 != NULL ) {
			const size_t mb = IMGSIZE_TO_HASHBLOCKS( candidate->virtualFilesize ) * sizeof(uint32_t);
			img->crc32 = malloc( mb );
			memcpy( img->crc32, candidate->crc32, mb );
		}
		dnbd3_cache_map_t *cache = ref_get_cachemap( candidate );
		if ( cache != NULL ) {
			ref_setref( &img->ref_cacheMap, &cache->reference );
			ref_put( &cache->reference );
		}
		if ( image_addToList( img ) ) {
			image_release( candidate );
			candidate = img;
			// Check if image is incomplete, initialize uplink
			if ( candidate->ref_cacheMap != NULL ) {
				uplink_init( candidate, -1, NULL, -1 );
			}
			// Try again with new instance
			image_ensureOpen( candidate );
		} else {
			img->users = 0;
			image_free( img );
		}
		// readFd == -1 and problem.read == true
	}

	return candidate; // We did all we can, hopefully it's working
}

/**
 * Lock the image by increasing its users count
 * Returns the image on success, NULL if it is not found in the image list
 * Every call to image_lock() needs to be followed by a call to image_release() at some point.
 * Locks on: imageListLock, _images[].lock
 */
dnbd3_image_t* image_lock(dnbd3_image_t *image)
{
	if ( image == NULL ) return NULL ;
	int i;
	mutex_lock( &imageListLock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] == image ) {
			assert( _images[i]->id == image->id );
			image->users++;
			mutex_unlock( &imageListLock );
			return image;
		}
	}
	mutex_unlock( &imageListLock );
	return NULL ;
}

/**
 * Release given image. This will decrease the reference counter of the image.
 * If the usage counter reaches 0 and the image is not in the images array
 * anymore, the image will be freed
 * Locks on: imageListLock, _images[].lock
 */
dnbd3_image_t* image_release(dnbd3_image_t *image)
{
	if ( image == NULL ) return NULL;
	mutex_lock( &imageListLock );
	assert( image->users > 0 );
	// Decrement and check for 0
	if ( --image->users != 0 ) { // Still in use, do nothing
		mutex_unlock( &imageListLock );
		return NULL;
	}
	// Getting here means we decreased the usage counter to zero
	// If the image is not in the images list anymore, we're
	// responsible for freeing it
	for (int i = 0; i < _num_images; ++i) {
		if ( _images[i] == image ) { // Found, do nothing
			assert( _images[i]->id == image->id );
			mutex_unlock( &imageListLock );
			return NULL;
		}
	}
	mutex_unlock( &imageListLock );
	// So it wasn't in the images list anymore either, get rid of it
	image = image_free( image );
	return NULL;
}

/**
 * Returns true if the given file name ends in one of our meta data
 * file extensions. Used to prevent loading them as images.
 */
static bool isForbiddenExtension(const char* name)
{
	const size_t len = strlen( name );
	if ( len < 4 ) return false;
	const char *ptr = name + len - 4;
	if ( strcmp( ptr, ".crc" ) == 0 ) return true; // CRC list
	if ( strcmp( ptr, ".map" ) == 0 ) return true; // cache map for incomplete images
	if ( len < 5 ) return false;
	--ptr;
	if ( strcmp( ptr, ".meta" ) == 0 ) return true; // Meta data (currently not in use)
	return false;
}

/**
 * Remove image from images array. Only free it if it has
 * no active users and was actually in the list.
 * Locks on: imageListLock, image[].lock
 * @return NULL if image was also freed, image otherwise
 */
static dnbd3_image_t* image_remove(dnbd3_image_t *image)
{
	bool mustFree = false;
	mutex_lock( &imageListLock );
	for ( int i = _num_images - 1; i >= 0; --i ) {
		if ( _images[i] == image ) {
			assert( _images[i]->id == image->id );
			_images[i] = NULL;
			mustFree = ( image->users == 0 );
		}
		if ( _images[i] == NULL && i + 1 == _num_images ) _num_images--;
	}
	mutex_unlock( &imageListLock );
	if ( mustFree ) image = image_free( image );
	return image;
}

/**
 * Kill all uplinks
 */
void image_killUplinks()
{
	int i;
	mutex_lock( &imageListLock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] == NULL ) continue;
		uplink_shutdown( _images[i] );
	}
	mutex_unlock( &imageListLock );
}

/**
 * Load all images in given path recursively.
 * Pass NULL to use path from config.
 */
bool image_loadAll(char *path)
{
	bool ret;
	char imgPath[PATHLEN];
	int imgId;
	dnbd3_image_t *imgHandle;

	if ( path == NULL ) path = _basePath;
	if ( mutex_trylock( &reloadLock ) != 0 ) {
		logadd( LOG_MINOR, "Could not (re)load image list, already in progress." );
		return false;
	}
	if ( _removeMissingImages ) {
		// Check if all loaded images still exist on disk
		logadd( LOG_INFO, "Checking for vanished images" );
		mutex_lock( &imageListLock );
		for ( int i = _num_images - 1; i >= 0; --i ) {
			if ( _shutdown ) break;
			if ( _images[i] == NULL ) {
				if ( i + 1 == _num_images ) _num_images--;
				continue;
			}
			imgId = _images[i]->id;
			snprintf( imgPath, PATHLEN, "%s", _images[i]->path );
			mutex_unlock( &imageListLock ); // isReadable hits the fs; unlock
			// Check if fill can still be opened for reading
			ret = file_isReadable( imgPath );
			// Lock again, see if image is still there, free if required
			mutex_lock( &imageListLock );
			if ( ret || i >= _num_images || _images[i] == NULL || _images[i]->id != imgId ) continue;
			// File not readable but still in list -- needs to be removed
			imgHandle = _images[i];
			_images[i] = NULL;
			if ( i + 1 == _num_images ) _num_images--;
			if ( imgHandle->users == 0 ) {
				// Image is not in use anymore, free the dangling entry immediately
				mutex_unlock( &imageListLock ); // image_free locks on this, and
				// might do several fs operations; unlock
				image_free( imgHandle );
				mutex_lock( &imageListLock );
			}
		}
		mutex_unlock( &imageListLock );
		if ( _shutdown ) {
			mutex_unlock( &reloadLock );
			return true;
		}
	}
	// Now scan for new images
	logadd( LOG_INFO, "Scanning for new or modified images" );
	ret = image_load_all_internal( path, path );
	mutex_unlock( &reloadLock );
	logadd( LOG_INFO, "Finished scanning %s", path );
	return ret;
}

/**
 * Free all images we have, but only if they're not in use anymore.
 * Locks on imageListLock
 * @return true if all images have been freed
 */
bool image_tryFreeAll()
{
	mutex_lock( &imageListLock );
	for (int i = _num_images - 1; i >= 0; --i) {
		if ( _images[i] != NULL && _images[i]->users == 0 ) {
			dnbd3_image_t *image = _images[i];
			_images[i] = NULL;
			image = image_free( image );
		}
		if ( i + 1 == _num_images && _images[i] == NULL ) _num_images--;
	}
	mutex_unlock( &imageListLock );
	return _num_images == 0;
}

/**
 * Free image. DOES NOT check if it's in use.
 * (Indirectly) locks on image.lock, uplink.queueLock
 */
static dnbd3_image_t* image_free(dnbd3_image_t *image)
{
	assert( image != NULL );
	assert( image->users == 0 );
	logadd( ( _shutdown ? LOG_DEBUG1 : LOG_INFO ), "Freeing image %s:%d", PIMG(image) );
	// uplink_shutdown might return false to tell us
	// that the shutdown is in progress. Bail out since
	// this will get called again when the uplink is done.
	if ( !uplink_shutdown( image ) )
		return NULL;
	if ( isImageFromUpstream( image ) ) {
		saveMetaData( image, NULL, 0 );
		if ( image->ref_cacheMap != NULL ) {
			saveCacheMap( image );
		}
	}
	mutex_lock( &image->lock );
	ref_setref( &image->ref_cacheMap, NULL );
	free( image->crc32 );
	free( image->path );
	free( image->name );
	image->crc32 = NULL;
	image->path = NULL;
	image->name = NULL;
	mutex_unlock( &image->lock );
	if ( image->readFd != -1 ) close( image->readFd );
	mutex_destroy( &image->lock );
	free( image );
	return NULL ;
}

bool image_isHashBlockComplete(dnbd3_cache_map_t * const cache, const uint64_t block, const uint64_t realFilesize)
{
	if ( cache == NULL )
		return true;
	const atomic_uint_least8_t *cacheMap = cache->map;
	const uint64_t end = (block + 1) * HASH_BLOCK_SIZE;
	if ( end <= realFilesize ) {
		// Trivial case: block in question is not the last block (well, or image size is multiple of HASH_BLOCK_SIZE)
		const int startCacheIndex = (int)( ( block * HASH_BLOCK_SIZE ) / ( DNBD3_BLOCK_SIZE * 8 ) );
		const int endCacheIndex = startCacheIndex + (int)( HASH_BLOCK_SIZE / ( DNBD3_BLOCK_SIZE * 8 ) );
		for ( int i = startCacheIndex; i < endCacheIndex; ++i ) {
			if ( cacheMap[i] != 0xff ) {
				return false;
			}
		}
	} else {
		// Special case: Checking last block, which is smaller than HASH_BLOCK_SIZE
		for (uint64_t mapPos = block * HASH_BLOCK_SIZE; mapPos < realFilesize; mapPos += DNBD3_BLOCK_SIZE ) {
			const size_t map_y = (size_t)( mapPos >> 15 );
			const int map_x = (int)( (mapPos >> 12) & 7 ); // mod 8
			const int mask = 1 << map_x;
			if ( (cacheMap[map_y] & mask) == 0 ) return false;
		}
	}
	return true;
}

/**
 * Load all images in the given path recursively,
 * consider *base the base path that is to be cut off
 */
static bool image_load_all_internal(char *base, char *path)
{
#define SUBDIR_LEN 150
	assert( path != NULL );
	assert( *path == '/' );
	struct dirent entry, *entryPtr;
	const size_t pathLen = strlen( path );
	char subpath[PATHLEN];
	struct stat st;
	DIR * const dir = opendir( path );

	if ( dir == NULL ) {
		logadd( LOG_ERROR, "Could not opendir '%s' for loading", path );
		return false;
	}

	while ( !_shutdown && (entryPtr = readdir( dir )) != NULL ) {
		entry = *entryPtr;
		if ( entry.d_name[0] == '.' )
			continue; // No hidden files, no . or ..
		if ( strlen( entry.d_name ) > SUBDIR_LEN ) {
			logadd( LOG_WARNING, "Skipping entry %s: Too long (max %d bytes)", entry.d_name, (int)SUBDIR_LEN );
			continue;
		}
		if ( entry.d_name[0] == '/' || path[pathLen - 1] == '/' ) {
			snprintf( subpath, PATHLEN, "%s%s", path, entry.d_name );
		} else {
			snprintf( subpath, PATHLEN, "%s/%s", path, entry.d_name );
		}
		if ( stat( subpath, &st ) < 0 ) {
			logadd( LOG_WARNING, "stat() for '%s' failed. Ignoring....", subpath );
			continue;
		}
		if ( S_ISDIR( st.st_mode ) ) {
			image_load_all_internal( base, subpath ); // Recurse
		} else if ( !isForbiddenExtension( subpath ) ) {
			image_load( base, subpath, true ); // Load image if possible
		}
	}
	closedir( dir );
	return true;
#undef SUBDIR_LEN
}

/**
 */
static bool image_addToList(dnbd3_image_t *image)
{
	int i;
	static int imgIdCounter = 0; // Used to assign unique numeric IDs to images
	mutex_lock( &imageListLock );
	// Now we're locked, assign unique ID to image (unique for this running server instance!)
	image->id = ++imgIdCounter;
	for ( i = 0; i < _num_images; ++i ) {
		if ( _images[i] != NULL ) continue;
		_images[i] = image;
		break;
	}
	if ( i >= _num_images ) {
		if ( _num_images >= _maxImages ) {
			mutex_unlock( &imageListLock );
			return false;
		}
		_images[_num_images++] = image;
	}
	mutex_unlock( &imageListLock );
	return true;
}

/**
 * Load image from given path. This will check if the image is
 * already loaded and updates its information in that case.
 * Note that this is NOT THREAD SAFE so make sure its always
 * called on one thread only.
 */
static bool image_load(char *base, char *path, bool withUplink)
{
	int revision = -1;
	dnbd3_cache_map_t *cache = NULL;
	uint32_t *crc32list = NULL;
	dnbd3_image_t *existing = NULL;
	int fdImage = -1;
	bool function_return = false; // Return false by default
	assert( base != NULL );
	assert( path != NULL );
	assert( *path == '/' );
	assert( strncmp( path, base, strlen(base)) == 0 );
	assert( base[strlen(base) - 1] != '/' );
	assert( strlen(path) > strlen(base) );
	char *lastSlash = strrchr( path, '/' );
	char *fileName = lastSlash + 1;
	char imgName[strlen( path )];
	const size_t fileNameLen = strlen( fileName );

	// Copy virtual path (relative path in "base")
	char * const virtBase = path + strlen( base ) + 1;
	assert( *virtBase != '/' );
	char *src = virtBase, *dst = imgName;
	while ( src <= lastSlash ) {
		*dst++ = *src++;
	}
	*dst = '\0';

	do {
		// Parse file name for revision
		// Try to parse *.r<ID> syntax
		size_t i;
		for (i = fileNameLen - 1; i > 1; --i) {
			if ( fileName[i] < '0' || fileName[i] > '9' ) break;
		}
		if ( i != fileNameLen - 1 && fileName[i] == 'r' && fileName[i - 1] == '.' ) {
			revision = atoi( fileName + i + 1 );
			src = fileName;
			while ( src < fileName + i - 1 ) {
				*dst++ = *src++;
			}
			*dst = '\0';
		}
	} while (0);

	// Legacy mode enabled and no rid extracted from filename?
	if ( _vmdkLegacyMode && revision == -1 ) {
		fdImage = open( path, O_RDONLY ); // Check if it exists
		if ( fdImage == -1 ) goto load_error;
		// Yes, simply append full file name and set rid to 1
		strcat( dst, fileName );
		revision = 1;
	}
	// Did we get anything?
	if ( revision <= 0 || revision >= 65536 ) {
		logadd( LOG_WARNING, "Image '%s' has invalid revision ID %d", path, revision );
		goto load_error;
	}

	// Get pointer to already existing image if possible
	existing = image_get( imgName, (uint16_t)revision, true );

	// ### Now load the actual image related data ###
	if ( fdImage == -1 ) {
		fdImage = open( path, O_RDONLY );
	}
	if ( fdImage == -1 ) {
		logadd( LOG_ERROR, "Could not open '%s' for reading...", path );
		goto load_error;
	}
	// Determine file size
	const off_t seekret = lseek( fdImage, 0, SEEK_END );
	if ( seekret < 0 ) {
		logadd( LOG_ERROR, "Could not seek to end of file '%s'", path );
		goto load_error;
	} else if ( seekret == 0 ) {
		logadd( LOG_WARNING, "Empty image file '%s'", path );
		goto load_error;
	}
	const uint64_t realFilesize = (uint64_t)seekret;
	const uint64_t virtualFilesize = ( realFilesize + (DNBD3_BLOCK_SIZE - 1) ) & ~(DNBD3_BLOCK_SIZE - 1);
	if ( realFilesize != virtualFilesize ) {
		logadd( LOG_DEBUG1, "Image size of '%s' is %" PRIu64 ", virtual size: %" PRIu64, path, realFilesize, virtualFilesize );
	}

	// 1. Allocate memory for the cache map if the image is incomplete
	cache = image_loadCacheMap( path, virtualFilesize );

	// XXX: Maybe try sha-256 or 512 first if you're paranoid (to be implemented)

	// 2. Load CRC-32 list of image
	uint32_t masterCrc = 0;
	const int hashBlockCount = IMGSIZE_TO_HASHBLOCKS( virtualFilesize );
	crc32list = image_loadCrcList( path, virtualFilesize, &masterCrc );

	// Compare data just loaded to identical image we apparently already loaded
	if ( existing != NULL ) {
		if ( existing->realFilesize != realFilesize ) {
			logadd( LOG_WARNING, "Size of image '%s:%d' has changed.", PIMG(existing) );
			// Image will be replaced below
		} else if ( existing->crc32 != NULL && crc32list != NULL
				&& memcmp( existing->crc32, crc32list, sizeof(uint32_t) * hashBlockCount ) != 0 ) {
			logadd( LOG_WARNING, "CRC32 list of image '%s:%d' has changed.", PIMG(existing) );
			logadd( LOG_WARNING, "The image will be reloaded, but you should NOT replace existing images while the server is running." );
			logadd( LOG_WARNING, "Actually even if it's not running this should never be done. Use a new RID instead!" );
			// Image will be replaced below
		} else if ( existing->crc32 == NULL && crc32list != NULL ) {
			logadd( LOG_INFO, "Found CRC-32 list for already loaded image '%s:%d', adding...", PIMG(existing) );
			existing->crc32 = crc32list;
			existing->masterCrc32 = masterCrc;
			crc32list = NULL;
			function_return = true;
			goto load_error; // Keep existing
		} else if ( existing->ref_cacheMap != NULL && cache == NULL ) {
			// Just ignore that fact, if replication is really complete the cache map will be removed anyways
			logadd( LOG_INFO, "Image '%s:%d' has no cache map on disk!", PIMG(existing) );
			function_return = true;
			goto load_error; // Keep existing
		} else {
			// Nothing changed about the existing image, so do nothing
			logadd( LOG_DEBUG1, "Did not change" );
			function_return = true;
			goto load_error; // Keep existing
		}
		// Remove existing image from images array, so it will be replaced by the reloaded image
		existing = image_remove( existing );
		existing = image_release( existing );
	}

	// Load fresh image
	dnbd3_image_t *image = calloc( 1, sizeof(dnbd3_image_t) );
	image->path = strdup( path );
	image->name = strdup( imgName );
	image->ref_cacheMap = NULL;
	ref_setref( &image->ref_cacheMap, &cache->reference );
	image->crc32 = crc32list;
	image->masterCrc32 = masterCrc;
	image->uplinkref = NULL;
	image->realFilesize = realFilesize;
	image->virtualFilesize = virtualFilesize;
	image->rid = (uint16_t)revision;
	image->users = 0;
	image->readFd = -1;
	timing_get( &image->nextCompletenessEstimate );
	image->completenessEstimate = -1;
	mutex_init( &image->lock, LOCK_IMAGE );
	loadImageMeta( image );

	// Prevent freeing in cleanup
	cache = NULL;
	crc32list = NULL;

	// Get rid of cache map if image is complete
	if ( image->ref_cacheMap != NULL ) {
		image_isComplete( image );
	}

	// Image is definitely incomplete, initialize uplink worker
	if ( image->ref_cacheMap != NULL ) {
		image->problem.uplink = true;
		if ( withUplink ) {
			uplink_init( image, -1, NULL, -1 );
		}
	}

	// ### Reaching this point means loading succeeded
	image->readFd = fdImage;
	if ( image_addToList( image ) ) {
		// Keep fd for reading
		fdImage = -1;
		// Check CRC32
		image_checkRandomBlocks( image, 4, -1 );
	} else {
		logadd( LOG_ERROR, "Image list full: Could not add image %s", path );
		image->readFd = -1; // Keep fdImage instead, will be closed below
		image = image_free( image );
		goto load_error;
	}
	logadd( LOG_DEBUG1, "Loaded image '%s:%d'\n", PIMG(image) );
	function_return = true;

	// Clean exit:
load_error: ;
	if ( existing != NULL ) existing = image_release( existing );
	if ( crc32list != NULL ) free( crc32list );
	if ( cache != NULL ) free( cache );
	if ( fdImage != -1 ) close( fdImage );
	return function_return;
}

static dnbd3_cache_map_t* image_loadCacheMap(const char * const imagePath, const int64_t fileSize)
{
	dnbd3_cache_map_t *retval = NULL;
	char mapFile[strlen( imagePath ) + 10 + 1];
	sprintf( mapFile, "%s.map", imagePath );
	int fdMap = open( mapFile, O_RDONLY );
	if ( fdMap != -1 ) {
		const int map_size = IMGSIZE_TO_MAPBYTES( fileSize );
		retval = calloc( 1, sizeof(*retval) + map_size );
		ref_init( &retval->reference, cmfree, 0 );
		const ssize_t rd = read( fdMap, retval->map, map_size );
		if ( map_size != rd ) {
			logadd( LOG_WARNING, "Could only read %d of expected %d bytes of cache map of '%s'", (int)rd, (int)map_size, imagePath );
			// Could not read complete map, that means the rest of the image file will be considered incomplete
		}
		close( fdMap );
		// Later on we check if the hash map says the image is complete
	}
	return retval;
}

static uint32_t* image_loadCrcList(const char * const imagePath, const int64_t fileSize, uint32_t *masterCrc)
{
	assert( masterCrc != NULL );
	uint32_t *retval = NULL;
	const int hashBlocks = IMGSIZE_TO_HASHBLOCKS( fileSize );
	// Currently this should only prevent accidental corruption (esp. regarding transparent proxy mode)
	// but maybe later on you want better security
	char hashFile[strlen( imagePath ) + 10 + 1];
	sprintf( hashFile, "%s.crc", imagePath );
	int fdHash = open( hashFile, O_RDONLY );
	if ( fdHash >= 0 ) {
		off_t fs = lseek( fdHash, 0, SEEK_END );
		if ( fs < (hashBlocks + 1) * 4 ) {
			logadd( LOG_WARNING, "Ignoring crc32 list for '%s' as it is too short", imagePath );
		} else {
			if ( pread( fdHash, masterCrc, sizeof(uint32_t), 0 ) != sizeof(uint32_t) ) {
				logadd( LOG_WARNING, "Error reading first crc32 of '%s'", imagePath );
			} else {
				const size_t crcFileLen = hashBlocks * sizeof(uint32_t);
				size_t pos = 0;
				retval = calloc( hashBlocks, sizeof(uint32_t) );
				while ( pos < crcFileLen ) {
					ssize_t ret = pread( fdHash, retval + pos, crcFileLen - pos, pos + sizeof(uint32_t) /* skip master-crc */ );
					if ( ret == -1 ) {
						if ( errno == EINTR || errno == EAGAIN ) continue;
					}
					if ( ret <= 0 ) break;
					pos += ret;
				}
				if ( pos != crcFileLen ) {
					free( retval );
					retval = NULL;
					logadd( LOG_WARNING, "Could not read crc32 list of '%s'", imagePath );
				} else {
					uint32_t lists_crc = crc32( 0, NULL, 0 );
					lists_crc = crc32( lists_crc, (uint8_t*)retval, hashBlocks * sizeof(uint32_t) );
					lists_crc = net_order_32( lists_crc );
					if ( lists_crc != *masterCrc ) {
						free( retval );
						retval = NULL;
						logadd( LOG_WARNING, "CRC-32 of CRC-32 list mismatch. CRC-32 list of '%s' might be corrupted.", imagePath );
					}
				}
			}
		}
		close( fdHash );
	}
	return retval;
}

/**
 * Check up to count random blocks from given image. If fromFd is -1, the check will
 * be run asynchronously using the integrity checker. Otherwise, the check will
 * happen in the function and return the result of the check.
 * @param image image to check
 * @param count number of blocks to check (max)
 * @param fromFd, check synchronously and use this fd for reading, -1 = async
 * @return true = OK, false = error. Meaningless if fromFd == -1
 */
static bool image_checkRandomBlocks(dnbd3_image_t *image, const int count, int fromFd)
{
	if ( image->crc32 == NULL )
		return true;
	// This checks the first block and (up to) count - 1 random blocks for corruption
	// via the known crc32 list. This is very sloppy and is merely supposed to detect
	// accidental corruption due to broken dnbd3-proxy functionality or file system
	// corruption, or people replacing/updating images which is a very stupid thing.
	assert( count > 0 );
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	const int hashBlocks = IMGSIZE_TO_HASHBLOCKS( image->virtualFilesize );
	int blocks[count+1]; // +1 for "-1" in sync case
	int index = 0, j;
	int block;
	if ( image_isHashBlockComplete( cache, 0, image->virtualFilesize ) ) {
		blocks[index++] = 0;
	}
	if ( hashBlocks > 1 && image_isHashBlockComplete( cache, hashBlocks - 1, image->virtualFilesize ) ) {
		blocks[index++] = hashBlocks - 1;
	}
	int tries = count * 5; // Try only so many times to find a non-duplicate complete block
	while ( index + 1 < count && --tries > 0 ) {
		block = rand() % hashBlocks; // Random block
		for ( j = 0; j < index; ++j ) { // Random block already in list?
			if ( blocks[j] == block ) goto while_end;
		}
		// Block complete? If yes, add to list
		if ( image_isHashBlockComplete( cache, block, image->virtualFilesize ) ) {
			blocks[index++] = block;
		}
while_end: ;
	}
	if ( cache != NULL ) {
		ref_put( &cache->reference );
	}
	if ( fromFd == -1 ) {
		// Async
		for ( int i = 0; i < index; ++i ) {
			integrity_check( image, blocks[i], true );
		}
		return true;
	}
	// Sync
	blocks[index] = -1;
	return image_checkBlocksCrc32( fromFd, image->crc32, blocks, image->realFilesize );
}

/**
 * Create a new image with the given image name and revision id in _basePath
 * Returns true on success, false otherwise
 */
bool image_create(char *image, int revision, uint64_t size)
{
	assert( image != NULL );
	assert( size >= DNBD3_BLOCK_SIZE );
	if ( revision <= 0 ) {
		logadd( LOG_ERROR, "revision id invalid: %d", revision );
		return false;
	}
	char path[PATHLEN], cache[PATHLEN+4];
	char *lastSlash = strrchr( image, '/' );
	if ( lastSlash == NULL ) {
		snprintf( path, PATHLEN, "%s/%s.r%d", _basePath, image, revision );
	} else {
		*lastSlash = '\0';
		snprintf( path, PATHLEN, "%s/%s", _basePath, image );
		mkdir_p( path );
		*lastSlash = '/';
		snprintf( path, PATHLEN, "%s/%s.r%d", _basePath, image, revision );
	}
	snprintf( cache, PATHLEN+4, "%s.map", path );
	size = (size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
	const int mapsize = IMGSIZE_TO_MAPBYTES(size);
	// Write files
	int fdImage = -1, fdCache = -1;
	fdImage = open( path, O_RDWR | O_TRUNC | O_CREAT, 0644 );
	fdCache = open( cache, O_RDWR | O_TRUNC | O_CREAT, 0644 );
	if ( fdImage < 0 ) {
		logadd( LOG_ERROR, "Could not open %s for writing.", path );
		goto failure_cleanup;
	}
	if ( fdCache < 0 ) {
		logadd( LOG_ERROR, "Could not open %s for writing.", cache );
		goto failure_cleanup;
	}
	// Try cache map first
	if ( !file_alloc( fdCache, 0, mapsize ) && !file_setSize( fdCache, mapsize ) ) {
		const int err = errno;
		logadd( LOG_DEBUG1, "Could not allocate %d bytes for %s (errno=%d)", mapsize, cache, err );
	}
	// Now write image
	bool fallback = false;
	if ( !_sparseFiles && !file_alloc( fdImage, 0, size ) ) {
		logadd( LOG_ERROR, "Could not allocate %" PRIu64 " bytes for %s (errno=%d)", size, path, errno );
		logadd( LOG_ERROR, "It is highly recommended to use a file system that supports preallocating disk"
				" space without actually writing all zeroes to the block device." );
		logadd( LOG_ERROR, "If you cannot fix this, try setting sparseFiles=true, but don't expect"
				" divine performance during replication." );
		if ( !_ignoreAllocErrors ) {
			goto failure_cleanup;
		}
		fallback = true;
	}
	if ( ( _sparseFiles || fallback ) && !file_setSize( fdImage, size ) ) {
		logadd( LOG_ERROR, "Could not create sparse file of %" PRIu64 " bytes for %s (errno=%d)", size, path, errno );
		logadd( LOG_ERROR, "Make sure you have enough disk space, check directory permissions, fs errors etc." );
		goto failure_cleanup;
	}
	close( fdImage );
	close( fdCache );
	return true;
	//
failure_cleanup: ;
	if ( fdImage >= 0 ) close( fdImage );
	if ( fdCache >= 0 ) close( fdCache );
	remove( path );
	remove( cache );
	return false;
}

static dnbd3_image_t *loadImageProxy(char * const name, const uint16_t revision, const size_t len);
static dnbd3_image_t *loadImageServer(char * const name, const uint16_t requestedRid);

/**
 * Does the same as image_get, but if the image is not known locally, or if
 * revision 0 is requested, it will:
 * a) Try to clone it from an authoritative dnbd3 server, if
 *    the server is running in proxy mode.
 * b) Try to load it from disk by constructing the appropriate file name.
 *
 *  If the return value is not NULL,
 * image_release needs to be called on the image at some point.
 * Locks on: remoteCloneLock, imageListLock, _images[].lock
 */
dnbd3_image_t* image_getOrLoad(char * const name, const uint16_t revision)
{
	dnbd3_image_t *image;
	// specific revision - try shortcut
	if ( revision != 0 ) {
		image = image_get( name, revision, true );
		if ( image != NULL )
			return image;
	}
	const size_t len = strlen( name );
	// Sanity check
	if ( len == 0 || name[len - 1] == '/' || name[0] == '/'
			|| name[0] == '.' || strstr( name, "/." ) != NULL ) return NULL;
	// Re-check latest local revision
	image = loadImageServer( name, revision );
	// If in proxy mode, check with upstream servers
	if ( _isProxy ) {
		// Forget the locally loaded one
		image_release( image );
		// Check with upstream - if unsuccessful, will return the same
		// as loadImageServer did
		image = loadImageProxy( name, revision, len );
	}
	// Lookup on local storage
	return image;
}

/**
 * Called if specific rid is not loaded, or if rid is 0 (some version might be loaded locally,
 * but we should check if there's a higher rid on a remote server).
 */
static dnbd3_image_t *loadImageProxy(char * const name, const uint16_t revision, const size_t len)
{
	// Already existing locally?
	dnbd3_image_t *image = NULL;
	if ( revision == 0 ) {
		image = image_get( name, revision, true );
	}

	// Doesn't exist or is rid 0, try remote if not already tried it recently
	declare_now;
	char *cmpname = name;
	int useIndex = -1, fallbackIndex = 0;
	if ( len >= NAMELEN ) cmpname += 1 + len - NAMELEN;
	mutex_lock( &remoteCloneLock );
	for (int i = 0; i < CACHELEN; ++i) {
		if ( remoteCloneCache[i].rid == revision && strcmp( cmpname, remoteCloneCache[i].name ) == 0 ) {
			useIndex = i;
			if ( timing_reached( &remoteCloneCache[i].deadline, &now ) ) break;
			mutex_unlock( &remoteCloneLock ); // Was recently checked...
			return image;
		}
		if ( timing_1le2( &remoteCloneCache[i].deadline, &remoteCloneCache[fallbackIndex].deadline ) ) {
			fallbackIndex = i;
		}
	}
	// Re-check to prevent two clients at the same time triggering this,
	// but only if rid != 0, since we would just get an old rid then
	if ( revision != 0 ) {
		if ( image == NULL ) image = image_get( name, revision, true );
		if ( image != NULL ) {
			mutex_unlock( &remoteCloneLock );
			return image;
		}
	}
	// Reaching this point means we should contact an authority server
	serialized_buffer_t serialized;
	// Mark as recently checked
	if ( useIndex == -1 ) {
		useIndex = fallbackIndex;
	}
	timing_set( &remoteCloneCache[useIndex].deadline, &now, SERVER_REMOTE_IMAGE_CHECK_CACHETIME );
	snprintf( remoteCloneCache[useIndex].name, NAMELEN, "%s", cmpname );
	remoteCloneCache[useIndex].rid = revision;
	mutex_unlock( &remoteCloneLock );

	// Get some alt servers and try to get the image from there
#define REP_NUM_SRV (8)
	dnbd3_host_t servers[REP_NUM_SRV];
	int uplinkSock = -1;
	dnbd3_host_t uplinkServer;
	const int count = altservers_getHostListForReplication( name, servers, REP_NUM_SRV );
	uint16_t remoteRid = revision;
	uint16_t acceptedRemoteRid = 0;
	uint16_t remoteProtocolVersion = 0;
	struct sockaddr_storage sa;
	socklen_t salen;
	poll_list_t *cons = sock_newPollList();
	logadd( LOG_DEBUG2, "Trying to clone %s:%d from %d hosts", name, (int)revision, count );
	for (int i = 0; i < count + 5; ++i) { // "i < count + 5" for 5 additional iterations, waiting on pending connects
		char *remoteName = NULL;
		uint64_t remoteImageSize = 0;
		bool ok = false;
		int sock;
		if ( i >= count ) {
			sock = sock_multiConnect( cons, NULL, 100, _uplinkTimeout );
			if ( sock == -2 ) break;
		} else {
			if ( log_hasMask( LOG_DEBUG2 ) ) {
				char host[50];
				size_t len = sock_printHost( &servers[i], host, sizeof(host) );
				host[len] = '\0';
				logadd( LOG_DEBUG2, "Trying to replicate from %s", host );
			}
			sock = sock_multiConnect( cons, &servers[i], 100, _uplinkTimeout );
		}
		if ( sock == -1 || sock == -2 ) continue;
		salen = sizeof(sa);
		if ( getpeername( sock, (struct sockaddr*)&sa, &salen ) == -1 ) {
			logadd( LOG_MINOR, "getpeername on successful connection failed!? (errno=%d)", errno );
			goto server_fail;
		}
		if ( !dnbd3_select_image( sock, name, revision, SI_SERVER_FLAGS ) ) goto server_fail;
		if ( !dnbd3_select_image_reply( &serialized, sock, &remoteProtocolVersion, &remoteName, &remoteRid, &remoteImageSize ) ) goto server_fail;
		if ( remoteProtocolVersion < MIN_SUPPORTED_SERVER || remoteRid == 0 ) goto server_fail;
		if ( revision != 0 && remoteRid != revision ) goto server_fail; // Want specific revision but uplink supplied different rid
		if ( revision == 0 && image != NULL && image->rid >= remoteRid ) goto server_fail; // Not actually a failure: Highest remote rid is <= highest local rid - don't clone!
		if ( remoteImageSize < DNBD3_BLOCK_SIZE || remoteName == NULL || strcmp( name, remoteName ) != 0 ) goto server_fail;
		if ( remoteImageSize > _maxReplicationSize ) {
			logadd( LOG_MINOR, "Won't proxy '%s:%d': Larger than maxReplicationSize", name, (int)revision );
			goto server_fail;
		}
		mutex_lock( &reloadLock );
		// Ensure disk space entirely if not using sparse files, otherwise just make sure we have some room at least
		if ( _sparseFiles ) {
			ok = image_ensureDiskSpace( 2ull * 1024 * 1024 * 1024, false ); // 2GiB, maybe configurable one day
		} else {
			ok = image_ensureDiskSpace( remoteImageSize + ( 10 * 1024 * 1024 ), false ); // some extra space for cache map etc.
		}
		if ( ok ) {
			ok = image_clone( sock, name, remoteRid, remoteImageSize ); // This sets up the file+map+crc and loads the img
		} else {
			logadd( LOG_INFO, "Not enough space to replicate '%s:%d'", name, (int)revision );
		}
		mutex_unlock( &reloadLock );
		if ( !ok ) goto server_fail;

		// Cloning worked :-)
		uplinkSock = sock;
		if ( !sock_sockaddrToDnbd3( (struct sockaddr*)&sa, &uplinkServer ) ) {
			uplinkServer.type = 0;
		}
		acceptedRemoteRid = remoteRid;
		break; // TODO: Maybe we should try the remaining servers if rid == 0, in case there's an even newer one

server_fail: ;
		close( sock );
	}
	sock_destroyPollList( cons );

	// If we still have a pointer to a local image, compare rid
	if ( image != NULL ) {
		if ( ( revision == 0 && image->rid >= acceptedRemoteRid ) || ( image->rid == revision ) ) {
			return image;
		}
		// release the reference
		image_release( image );
	}
	// If everything worked out, this call should now actually return the image
	image = image_get( name, acceptedRemoteRid, false );
	if ( image != NULL && uplinkSock != -1 ) {
		// If so, init the uplink and pass it the socket
		if ( !uplink_init( image, uplinkSock, &uplinkServer, remoteProtocolVersion ) ) {
			close( uplinkSock );
		} else {
			// Clumsy busy wait, but this should only take as long as it takes to start a thread, so is it really worth using a signalling mechanism?
			int i = 0;
			while ( image->problem.uplink && ++i < 100 )
				usleep( 2000 );
		}
	} else if ( uplinkSock != -1 ) {
		close( uplinkSock );
	}
	return image;
}

/**
 * Called if specific rid is not loaded, or if rid is 0, in which case we check on
 * disk which revision is latest.
 */
static dnbd3_image_t *loadImageServer(char * const name, const uint16_t requestedRid)
{
	char imageFile[PATHLEN] = "";
	uint16_t detectedRid = 0;
	bool isLegacyFile = false;

	if ( requestedRid != 0 ) {
		snprintf( imageFile, PATHLEN, "%s/%s.r%d", _basePath, name, (int)requestedRid );
		detectedRid = requestedRid;
	} else {
		glob_t g;
		snprintf( imageFile, PATHLEN, "%s/%s.r*", _basePath, name );
		const int ret = glob( imageFile, GLOB_NOSORT | GLOB_MARK, NULL, &g );
		imageFile[0] = '\0';
		if ( ret == 0 ) {
			long int best = 0;
			for ( size_t i = 0; i < g.gl_pathc; ++i ) {
				const char * const path = g.gl_pathv[i];
				const char * rev = strrchr( path, 'r' );
				if ( rev == NULL || rev == path || *(rev - 1) != '.' ) continue;
				rev++;
				if ( *rev < '0' || *rev > '9' ) continue;
				char *err = NULL;
				long int val = strtol( rev, &err, 10 );
				if ( err == NULL || *err != '\0' ) continue;
				if ( val > best ) {
					best = val;
					snprintf( imageFile, PATHLEN, "%s", g.gl_pathv[i] );
				}
			}
			if ( best > 0 && best < 65536 ) {
				detectedRid = (uint16_t)best;
			}
		}
		globfree( &g );
	}
	if ( _vmdkLegacyMode && requestedRid <= 1
			&& !isForbiddenExtension( name )
			&& ( detectedRid == 0 || !file_isReadable( imageFile ) ) ) {
		snprintf( imageFile, PATHLEN, "%s/%s", _basePath, name );
		detectedRid = 1;
		isLegacyFile = true;
	}
	logadd( LOG_DEBUG2, "Trying to load %s:%d ( -> %d) as %s", name, (int)requestedRid, (int)detectedRid, imageFile );
	// No file was determined, or it doesn't seem to exist/be readable
	if ( detectedRid == 0 ) {
		logadd( LOG_DEBUG2, "Not found, bailing out" );
		return image_get( name, requestedRid, true );
	}
	if ( !isLegacyFile && requestedRid == 0 ) {
		// rid 0 requested - check if detected rid is readable, decrease rid if not until we reach 0
		while ( detectedRid != 0 ) {
			dnbd3_image_t *image = image_get( name, detectedRid, true );
			if ( image != NULL ) {
				// globbed rid already loaded, return
				return image;
			}
			if ( file_isReadable( imageFile ) ) {
				// globbed rid is
				break;
			}
			logadd( LOG_DEBUG2, "%s: rid %d globbed but not readable, trying lower rid...", name, (int)detectedRid );
			detectedRid--;
			snprintf( imageFile, PATHLEN, "%s/%s.r%d", _basePath, name, requestedRid );
		}
	}

	// Now lock on the loading mutex, then check again if the image exists (we're multi-threaded)
	mutex_lock( &reloadLock );
	dnbd3_image_t* image = image_get( name, detectedRid, true );
	if ( image != NULL ) {
		// The image magically appeared in the meantime
		logadd( LOG_DEBUG2, "Magically appeared" );
		mutex_unlock( &reloadLock );
		return image;
	}
	// Still not loaded, let's try to do so
	logadd( LOG_DEBUG2, "Calling load" );
	image_load( _basePath, imageFile, false );
	mutex_unlock( &reloadLock );
	// If loading succeeded, this will return the image
	logadd( LOG_DEBUG2, "Calling get" );
	return image_get( name, requestedRid, true );
}

/**
 * Prepare a cloned image:
 * 1. Allocate empty image file and its cache map
 * 2. Use passed socket to request the crc32 list and save it to disk
 * 3. Load the image from disk
 * Returns: true on success, false otherwise
 */
static bool image_clone(int sock, char *name, uint16_t revision, uint64_t imageSize)
{
	// Allocate disk space and create cache map
	if ( !image_create( name, revision, imageSize ) ) return false;
	// CRC32
	const size_t len = strlen( _basePath ) + strlen( name ) + 20;
	char crcFile[len];
	snprintf( crcFile, len, "%s/%s.r%d.crc", _basePath, name, (int)revision );
	if ( !file_isReadable( crcFile ) ) {
		// Get crc32list from remote server
		size_t crc32len = IMGSIZE_TO_HASHBLOCKS(imageSize) * sizeof(uint32_t);
		uint32_t masterCrc;
		uint8_t *crc32list = malloc( crc32len );
		if ( !dnbd3_get_crc32( sock, &masterCrc, crc32list, &crc32len ) ) {
			free( crc32list );
			return false;
		}
		if ( crc32len != 0 ) {
			uint32_t lists_crc = crc32( 0, NULL, 0 );
			lists_crc = crc32( lists_crc, (uint8_t*)crc32list, crc32len );
			lists_crc = net_order_32( lists_crc );
			if ( lists_crc != masterCrc ) {
				logadd( LOG_WARNING, "OTF-Clone: Corrupted CRC-32 list. ignored. (%s)", name );
			} else {
				int fd = open( crcFile, O_WRONLY | O_CREAT, 0644 );
				ssize_t ret = write( fd, &masterCrc, sizeof(masterCrc) );
				ret += write( fd, crc32list, crc32len );
				close( fd );
				if ( (size_t)ret != crc32len + sizeof(masterCrc) ) {
					logadd( LOG_WARNING, "Could not save freshly received crc32 list for %s:%d", name, (int)revision );
					unlink( crcFile );
				}
			}
		}
		free( crc32list );
	}
	// HACK: Chop of ".crc" to get the image file name
	crcFile[strlen( crcFile ) - 4] = '\0';
	return image_load( _basePath, crcFile, false );
}

/**
 * Generate the crc32 block list file for the given file.
 * This function wants a plain file name instead of a dnbd3_image_t,
 * as it can be used directly from the command line.
 */
bool image_generateCrcFile(char *image)
{
	int fdCrc = -1;
	uint32_t crc;
	char crcFile[strlen( image ) + 4 + 1];
	int fdImage = open( image, O_RDONLY );

	if ( fdImage == -1 ) {
		logadd( LOG_ERROR, "Could not open %s.", image );
		return false;
	}

	const int64_t fileLen = lseek( fdImage, 0, SEEK_END );
	if ( fileLen <= 0 ) {
		logadd( LOG_ERROR, "Error seeking to end, or file is empty." );
		goto cleanup_fail;
	}

	struct stat sst;
	sprintf( crcFile, "%s.crc", image );
	if ( stat( crcFile, &sst ) == 0 ) {
		logadd( LOG_ERROR, "CRC File for %s already exists! Delete it first if you want to regen.", image );
		goto cleanup_fail;
	}

	fdCrc = open( crcFile, O_RDWR | O_CREAT, 0644 );
	if ( fdCrc == -1 ) {
		logadd( LOG_ERROR, "Could not open CRC File %s for writing..", crcFile );
		goto cleanup_fail;
	}
	// CRC of all CRCs goes first. Don't know it yet, write 4 bytes dummy data.
	if ( write( fdCrc, crcFile, sizeof(crc) ) != sizeof(crc) ) {
		logadd( LOG_ERROR, "Write error" );
		goto cleanup_fail;
	}

	printf( "Generating CRC32" );
	fflush( stdout );
	const int blockCount = IMGSIZE_TO_HASHBLOCKS( fileLen );
	for ( int i = 0; i < blockCount; ++i ) {
		if ( !image_calcBlockCrc32( fdImage, i, fileLen, &crc ) ) {
			goto cleanup_fail;
		}
		if ( write( fdCrc, &crc, sizeof(crc) ) != sizeof(crc) ) {
			printf( "\nWrite error writing crc file: %d\n", errno );
			goto cleanup_fail;
		}
		putchar( '.' );
		fflush( stdout );
	}
	close( fdImage );
	fdImage = -1;
	printf( "done!\n" );

	logadd( LOG_INFO, "Generating master-crc..." );
	fflush( stdout );
	// File is written - read again to calc master crc
	if ( lseek( fdCrc, 4, SEEK_SET ) != 4 ) {
		logadd( LOG_ERROR, "Could not seek to beginning of crc list in file" );
		goto cleanup_fail;
	}
	char buffer[400];
	int blocksToGo = blockCount;
	crc = crc32( 0, NULL, 0 );
	while ( blocksToGo > 0 ) {
		const int numBlocks = MIN( (int)( sizeof(buffer) / sizeof(crc) ), blocksToGo );
		if ( read( fdCrc, buffer, numBlocks * sizeof(crc) ) != numBlocks * (int)sizeof(crc) ) {
			logadd( LOG_ERROR, "Could not re-read from crc32 file" );
			goto cleanup_fail;
		}
		crc = crc32( crc, (uint8_t*)buffer, numBlocks * sizeof(crc) );
		blocksToGo -= numBlocks;
	}
	crc = net_order_32( crc );
	if ( pwrite( fdCrc, &crc, sizeof(crc), 0 ) != sizeof(crc) ) {
		logadd( LOG_ERROR, "Could not write master crc to file" );
		goto cleanup_fail;
	}
	logadd( LOG_INFO, "CRC-32 file successfully generated." );
	fflush( stdout );
	return true;

cleanup_fail:;
	if ( fdImage != -1 ) close( fdImage );
	if ( fdCrc != -1 ) close( fdCrc );
	return false;
}

json_t* image_getListAsJson()
{
	json_t *imagesJson = json_array();
	json_t *jsonImage;
	int i;
	char uplinkName[100];
	uint64_t bytesReceived;
	int completeness, idleTime;
	declare_now;

	mutex_lock( &imageListLock );
	for ( i = 0; i < _num_images; ++i ) {
		if ( _images[i] == NULL ) continue;
		dnbd3_image_t *image = _images[i];
		mutex_lock( &image->lock );
		idleTime = (int)timing_diff( &image->atime, &now );
		completeness = image_getCompletenessEstimate( image );
		mutex_unlock( &image->lock );
		dnbd3_uplink_t *uplink = ref_get_uplink( &image->uplinkref );
		if ( uplink == NULL ) {
			bytesReceived = 0;
			uplinkName[0] = '\0';
		} else {
			bytesReceived = uplink->bytesReceived;
			if ( !uplink_getHostString( uplink, uplinkName, sizeof(uplinkName) ) ) {
				uplinkName[0] = '\0';
			}
			ref_put( &uplink->reference );
		}

		int problems = 0;
#define addproblem(name,val) if (image->problem.name) problems |= (1 << val)
		addproblem(read, 0);
		addproblem(write, 1);
		addproblem(changed, 2);
		addproblem(uplink, 3);
		addproblem(queue, 4);

		jsonImage = json_pack( "{sisssisisisisIsi}",
				"id", image->id, // id, name, rid never change, so access them without locking
				"name", image->name,
				"rid", (int) image->rid,
				"users", image->users,
				"complete",  completeness,
				"idle", idleTime,
				"size", (json_int_t)image->virtualFilesize,
				"problems", problems );
		if ( bytesReceived != 0 ) {
			json_object_set_new( jsonImage, "bytesReceived", json_integer( (json_int_t) bytesReceived ) );
		}
		if ( uplinkName[0] != '\0' ) {
			json_object_set_new( jsonImage, "uplinkServer", json_string( uplinkName ) );
		}
		json_array_append_new( imagesJson, jsonImage );

	}
	mutex_unlock( &imageListLock );
	return imagesJson;
}

/**
 * Get completeness of an image in percent. Only estimated, not exact.
 * Returns: 0-100
 */
int image_getCompletenessEstimate(dnbd3_image_t * const image)
{
	assert( image != NULL );
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	if ( cache == NULL )
		return 100;
	const int len = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
	if ( unlikely( len == 0 ) ) {
		ref_put( &cache->reference );
		return 0;
	}
	declare_now;
	if ( !timing_reached( &image->nextCompletenessEstimate, &now ) ) {
		// Since this operation is relatively expensive, we cache the result for a while
		ref_put( &cache->reference );
		return image->completenessEstimate;
	}
	int i;
	int percent = 0;
	for ( i = 0; i < len; ++i ) {
		const uint8_t v = atomic_load_explicit( &cache->map[i], memory_order_relaxed );
		if ( v == 0xff ) {
			percent += 100;
		} else if ( v != 0 ) {
			percent += 50;
		}
	}
	ref_put( &cache->reference );
	image->completenessEstimate = percent / len;
	timing_set( &image->nextCompletenessEstimate, &now, 4 + rand() % 16 );
	return image->completenessEstimate;
}

/**
 * Check the CRC-32 of the given blocks. The array "blocks" is of variable length.
 * !! pass -1 as the last block so the function knows when to stop !!
 * Does NOT check whether block index is within image.
 * Returns true or false
 */
bool image_checkBlocksCrc32(const int fd, uint32_t *crc32list, const int *blocks, const uint64_t realFilesize)
{
	while ( *blocks != -1 ) {
		uint32_t crc;
		if ( !image_calcBlockCrc32( fd, *blocks, realFilesize, &crc ) ) {
			return false;
		}
		if ( crc != crc32list[*blocks] ) {
			logadd( LOG_WARNING, "Block %d is %x, should be %x", *blocks, crc, crc32list[*blocks] );
			return false;
		}
		blocks++;
	}
	return true;
}

/**
 * Calc CRC-32 of block. Value is returned as little endian.
 */
static bool image_calcBlockCrc32(const int fd, const size_t block, const uint64_t realFilesize, uint32_t *crc)
{
	// Make buffer 4k aligned in case fd has O_DIRECT set
#define BSIZE (512*1024)
	char rawBuffer[BSIZE + DNBD3_BLOCK_SIZE];
	char * const buffer = (char*)( ( (uintptr_t)rawBuffer + ( DNBD3_BLOCK_SIZE - 1 ) ) & ~( DNBD3_BLOCK_SIZE - 1 ) );
	// How many bytes to read from the input file
	const uint64_t bytesFromFile = MIN( HASH_BLOCK_SIZE, realFilesize - ( block * HASH_BLOCK_SIZE) );
	// Determine how many bytes we had to read if the file size were a multiple of 4k
	// This might be the same value if the real file's size is a multiple of 4k
	const uint64_t vbs = ( ( realFilesize + ( DNBD3_BLOCK_SIZE - 1 ) ) & ~( DNBD3_BLOCK_SIZE - 1 ) ) - ( block * HASH_BLOCK_SIZE );
	const uint64_t virtualBytesFromFile = MIN( HASH_BLOCK_SIZE, vbs );
	const off_t readPos = (int64_t)block * HASH_BLOCK_SIZE;
	size_t bytes = 0;
	assert( vbs >= bytesFromFile );
	*crc = crc32( 0, NULL, 0 );
	// Calculate the crc32 by reading data from the file
	while ( bytes < bytesFromFile ) {
		const size_t n = (size_t)MIN( BSIZE, bytesFromFile - bytes );
		const ssize_t r = pread( fd, buffer, n, readPos + bytes );
		if ( r <= 0 ) {
			logadd( LOG_WARNING, "CRC: Read error (errno=%d)", errno );
			return false;
		}
		*crc = crc32( *crc, (uint8_t*)buffer, r );
		bytes += (size_t)r;
	}
	// If the virtual file size is different, keep going using nullbytes
	if ( bytesFromFile < virtualBytesFromFile ) {
		memset( buffer, 0, BSIZE );
		bytes = (size_t)( virtualBytesFromFile - bytesFromFile );
		while ( bytes != 0 ) {
			const size_t len = MIN( BSIZE, bytes );
			*crc = crc32( *crc, (uint8_t*)buffer, len );
			bytes -= len;
		}
	}
	*crc = net_order_32( *crc );
	return true;
#undef BSIZE
}

/**
 * Call image_ensureDiskSpace (below), but aquire
 * reloadLock first.
 */
bool image_ensureDiskSpaceLocked(uint64_t size, bool force)
{
	bool ret;
	mutex_lock( &reloadLock );
	ret = image_ensureDiskSpace( size, force );
	mutex_unlock( &reloadLock );
	return ret;
}

/**
 * Make sure at least size bytes are available in _basePath.
 * Will delete old images to make room for new ones.
 * It will only delete images if a configurable uptime is
 * reached.
 * This can be overridden by setting force to true, in case
 * free space is desperately needed.
 * Return true iff enough space is available. false in random other cases
 */
static bool image_ensureDiskSpace(uint64_t size, bool force)
{
	for ( int maxtries = 0; maxtries < 50; ++maxtries ) {
		uint64_t available;
		if ( !file_freeDiskSpace( _basePath, NULL, &available ) ) {
			logadd( LOG_WARNING, "Could not get free disk space (errno %d), will assume there is enough space left.", errno );
			return true;
		}
		if ( available > size )
			return true; // Yay
		if ( !_isProxy || _autoFreeDiskSpaceDelay == -1 ) {
			logadd( LOG_INFO, "Only %dMiB free, %dMiB requested, but auto-freeing of disk space is disabled.",
					(int)(available / (1024ll * 1024)),
					(int)(size / (1024ll * 1024)) );
			return false; // If not in proxy mode at all, or explicitly disabled, never delete anything
		}
		if ( !force && dnbd3_serverUptime() < (uint32_t)_autoFreeDiskSpaceDelay ) {
			logadd( LOG_INFO, "Only %dMiB free, %dMiB requested, but server uptime < %d minutes...",
					(int)(available / (1024ll * 1024)),
					(int)(size / (1024ll * 1024)), _autoFreeDiskSpaceDelay / 60 );
			return false;
		}
		logadd( LOG_INFO, "Only %dMiB free, %dMiB requested, freeing an image...",
				(int)(available / (1024ll * 1024)),
				(int)(size / (1024ll * 1024)) );
		// Find least recently used image
		dnbd3_image_t *oldest = NULL;
		int i;
		mutex_lock( &imageListLock );
		for (i = 0; i < _num_images; ++i) {
			dnbd3_image_t *current = _images[i];
			if ( current == NULL || current->users != 0 )
				continue; // Empty slot or in use
			if ( oldest != NULL && timing_1le2( &oldest->atime, &current->atime ) )
				continue; // Already got a newer one
			if ( !isImageFromUpstream( current ) )
				continue; // Not replicated, don't touch
			// Oldest access time so far
			oldest = current;
		}
		if ( oldest != NULL ) {
			oldest->users++;
		}
		mutex_unlock( &imageListLock );
		if ( oldest == NULL ) {
			logadd( LOG_INFO, "All images are currently in use :-(" );
			return false;
		}
		declare_now;
		if ( !_sparseFiles && timing_diff( &oldest->atime, &now ) < 86400 ) {
			logadd( LOG_INFO, "Won't free any image, all have been in use in the past 24 hours :-(" );
			image_release( oldest ); // We did users++ above; image might have to be freed entirely
			return false;
		}
		logadd( LOG_INFO, "'%s:%d' has to go!", PIMG(oldest) );
		char *filename = strdup( oldest->path ); // Copy name as we remove the image first
		oldest = image_remove( oldest ); // Remove from list first...
		oldest = image_release( oldest ); // Decrease users counter; if it falls to 0, image will be freed
		// Technically the image might have been grabbed again, but chances for
		// this should be close to zero anyways since the image went unused for more than 24 hours..
		// Proper fix would be a "delete" flag in the image struct that will be checked in image_free
		unlink( filename );
		size_t len = strlen( filename ) + 10;
		char buffer[len];
		snprintf( buffer, len, "%s.map", filename );
		unlink( buffer );
		snprintf( buffer, len, "%s.crc", filename );
		unlink( buffer );
		snprintf( buffer, len, "%s.meta", filename );
		unlink( buffer );
		free( filename );
	}
	return false;
}

#define FDCOUNT (400)
static void* closeUnusedFds(void* nix UNUSED)
{
	if ( !_closeUnusedFd )
		return NULL;
	ticks deadline;
	timing_gets( &deadline, -UNUSED_FD_TIMEOUT );
	int fds[FDCOUNT];
	int fdindex = 0;
	setThreadName( "unused-fd-close" );
	mutex_lock( &imageListLock );
	for ( int i = 0; i < _num_images; ++i ) {
		dnbd3_image_t * const image = _images[i];
		if ( image == NULL || image->readFd == -1 )
			continue;
		if ( image->users == 0 && image->uplinkref == NULL && timing_reached( &image->atime, &deadline ) ) {
			logadd( LOG_DEBUG1, "Inactive fd closed for %s:%d", PIMG(image) );
			fds[fdindex++] = image->readFd;
			image->readFd = -1; // Not a race; image->users is 0 and to increase it you need imageListLock
			if ( fdindex == FDCOUNT )
				break;
		}
	}
	mutex_unlock( &imageListLock );
	// Do this after unlock since close might block
	for ( int i = 0; i < fdindex; ++i ) {
		close( fds[i] );
	}
	return NULL;
}

static bool isImageFromUpstream(dnbd3_image_t *image)
{
	if ( !_isProxy )
		return false; // Nothing to do
	// Check if we're a "hybrid proxy", i.e. there are only some namespaces (directories)
	// for which we have any upstream servers configured. If there's none, don't touch
	// the cache map on disk.
	if ( !altservers_imageHasAltServers( image->name ) )
		return false; // Nothing to do
	return true;
}

static void* saveLoadAllCacheMaps(void* nix UNUSED)
{
	static ticks nextSave;
	declare_now;
	bool full = timing_reached( &nextSave, &now );
	time_t walltime = 0;
	setThreadName( "cache-mapper" );
	if ( full ) {
		walltime = time( NULL );
		// Update at start to avoid concurrent runs
		timing_addSeconds( &nextSave, &now, CACHE_MAP_MAX_SAVE_DELAY );
	}
	mutex_lock( &imageListLock );
	for ( int i = 0; i < _num_images; ++i ) {
		dnbd3_image_t * const image = _images[i];
		if ( image == NULL )
			continue;
		image->users++;
		mutex_unlock( &imageListLock );
		const bool fromUpstream = isImageFromUpstream( image );
		dnbd3_cache_map_t *cache = ref_get_cachemap( image );
		if ( cache != NULL ) {
			if ( fromUpstream ) {
				// Replicated image, we're responsible for updating the map, so save it
				// Save if dirty bit is set, blocks were invalidated
				bool save = cache->dirty;
				dnbd3_uplink_t *uplink = ref_get_uplink( &image->uplinkref );
				if ( !save ) {
					// Otherwise, consider longer timeout and byte count limits of uplink
					if ( uplink != NULL ) {
						assert( uplink->bytesReceivedLastSave <= uplink->bytesReceived );
						uint64_t diff = uplink->bytesReceived - uplink->bytesReceivedLastSave;
						if ( diff > CACHE_MAP_MAX_UNSAVED_BYTES || ( full && diff != 0 ) ) {
							save = true;
						}
					}
				}
				if ( save ) {
					cache->dirty = false;
					if ( uplink != NULL ) {
						uplink->bytesReceivedLastSave = uplink->bytesReceived;
					}
					saveCacheMap( image );
				}
				if ( uplink != NULL ) {
					ref_put( &uplink->reference );
				}
			} else {
				// We're not replicating this image, if there's a cache map, reload
				// it periodically, since we might read from a shared storage that
				// another server instance is writing to.
				if ( full || ( !cache->unchanged && !image->problem.read ) ) {
					logadd( LOG_DEBUG2, "Reloading cache map of %s:%d", PIMG(image) );
					dnbd3_cache_map_t *onDisk = image_loadCacheMap(image->path, image->virtualFilesize);
					if ( onDisk == NULL ) {
						// Should be complete now
						logadd( LOG_DEBUG1, "External replication of %s:%d complete", PIMG(image) );
						ref_setref( &image->ref_cacheMap, NULL );
					} else {
						const int mapSize = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
						if ( memcmp( cache->map, onDisk->map, mapSize ) == 0 ) {
							// Unchanged
							cache->unchanged = true;
							onDisk->reference.free( &onDisk->reference );
						} else {
							// Replace
							ref_setref( &image->ref_cacheMap, &onDisk->reference );
							logadd( LOG_DEBUG2, "Map changed" );
						}
					}
				}
			} // end reload cache map
			ref_put( &cache->reference );
		} // end has cache map
		if ( full && fromUpstream ) {
			saveMetaData( image, &now, walltime );
		}
		image_release( image ); // Always do this instead of users-- to handle freeing
		mutex_lock( &imageListLock );
	}
	mutex_unlock( &imageListLock );
	return NULL;
}

/**
 * Saves the cache map of the given image.
 * Return false if this image doesn't have a cache map, or if the image
 * doesn't have any uplink to replicate from. In this case the image might
 * still have a cache map that was loaded from disk, and should be reloaded
 * periodically.
 * @param image the image
 */
static void saveCacheMap(dnbd3_image_t *image)
{
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	if ( cache == NULL )
		return; // Race - wasn't NULL in function call above...

	logadd( LOG_DEBUG2, "Saving cache map of %s:%d", PIMG(image) );
	const size_t size = IMGSIZE_TO_MAPBYTES(image->virtualFilesize);
	char mapfile[strlen( image->path ) + 4 + 1];
	strcpy( mapfile, image->path );
	strcat( mapfile, ".map" );

	int fd = open( mapfile, O_WRONLY | O_CREAT, 0644 );
	if ( fd == -1 ) {
		const int err = errno;
		ref_put( &cache->reference );
		logadd( LOG_WARNING, "Could not open file to write cache map to disk (errno=%d) file %s", err, mapfile );
		return;
	}

	// On Linux we could use readFd, but in general it's not guaranteed to work
	int imgFd = open( image->path, O_WRONLY );
	if ( imgFd == -1 ) {
		logadd( LOG_WARNING, "Cannot open %s for fsync(): errno=%d", image->path, errno );
	} else {
		if ( fsync( imgFd ) == -1 ) {
			logadd( LOG_ERROR, "fsync() on image file %s failed with errno %d. Resetting cache map.", image->path, errno );
			dnbd3_cache_map_t *old = image_loadCacheMap(image->path, image->virtualFilesize);
			const int mapSize = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
			if ( old == NULL ) {
				// Could not load old map. FS might be toast.
				logadd( LOG_ERROR, "Cannot load old cache map. Setting all zero." );
				memset( cache->map, 0, mapSize );
			} else {
				// AND the maps together to be safe
				for ( int i = 0; i < mapSize; ++i ) {
					cache->map[i] &= old->map[i];
				}
				old->reference.free( &old->reference );
			}
		}
		close( imgFd );
	}

	// Write current map to file
	size_t done = 0;
	while ( done < size ) {
		const ssize_t ret = write( fd, cache->map + done, size - done );
		if ( ret == -1 ) {
			if ( errno == EINTR ) continue;
			logadd( LOG_WARNING, "Could not write cache map (errno=%d) file %s", errno, mapfile );
			break;
		}
		if ( ret <= 0 ) {
			logadd( LOG_WARNING, "Unexpected return value %d for write() to %s", (int)ret, mapfile );
			break;
		}
		done += (size_t)ret;
	}
	ref_put( &cache->reference );
	if ( fsync( fd ) == -1 ) {
		logadd( LOG_WARNING, "fsync() on image map %s failed with errno %d", mapfile, errno );
	}
	close( fd );
	// TODO fsync on parent directory
}

static void allocCacheMap(dnbd3_image_t *image, bool complete)
{
	const uint8_t val = complete ? 0xff : 0;
	const int byteSize = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
	dnbd3_cache_map_t *cache = malloc( sizeof(*cache) + byteSize );
	ref_init( &cache->reference, cmfree, 0 );
	memset( cache->map, val, byteSize );
	mutex_lock( &image->lock );
	if ( image->ref_cacheMap != NULL ) {
		logadd( LOG_WARNING, "BUG: allocCacheMap called but there already is a map for %s:%d", PIMG(image) );
		free( cache );
	} else {
		ref_setref( &image->ref_cacheMap, &cache->reference );
	}
	mutex_unlock( &image->lock );
}

/**
 * It's assumed you hold a reference to the image
 */
static void saveMetaData(dnbd3_image_t *image, ticks *now, time_t walltime)
{
	if ( !image->accessed )
		return;
	ticks tmp;
	uint32_t diff;
	char *fn;
	if ( asprintf( &fn, "%s.meta", image->path ) == -1 ) {
		logadd( LOG_WARNING, "Cannot asprintf meta" );
		return;
	}
	if ( now == NULL ) {
		timing_get( &tmp );
		now = &tmp;
		walltime = time( NULL );
	}
	mutex_lock( &image->lock );
	image->accessed = false;
	diff = timing_diff( &image->atime, now );
	mutex_unlock( &image->lock );
	FILE *f = fopen( fn, "w" );
	if ( f == NULL ) {
		logadd( LOG_WARNING, "Cannot open %s for writing", fn );
	} else {
		fprintf( f, "[main]\natime=%"PRIu64"\n", (uint64_t)( walltime - diff ) );
		fclose( f );
	}
	free( fn );
	// TODO: fsync() dir
}

static void loadImageMeta(dnbd3_image_t *image)
{
	int32_t offset = 1;
	char *fn;
	if ( asprintf( &fn, "%s.meta", image->path ) == -1 ) {
		logadd( LOG_WARNING, "asprintf load" );
	} else {
		int fh = open( fn, O_RDONLY );
		free( fn );
		if ( fh != -1 ) {
			char buf[200];
			ssize_t ret = read( fh, buf, sizeof(buf)-1 );
			close( fh );
			if ( ret > 0 ) {
				buf[ret] = '\0';
				// Do it the cheap way until we actually store more stuff
				char *pos = strstr( buf, "atime=" );
				if ( pos != NULL ) {
					offset = (int32_t)( atol( pos + 6 ) - time( NULL ) );
				}
			}
		}
	}
	if ( offset == 1 ) {
		// Nothing from .meta file, use old guesstimate
		struct stat st;
		if ( stat( image->path, &st ) == 0 ) {
			// Negatively offset atime by file modification time
			offset = (int32_t)( st.st_mtime - time( NULL ) );
		} else {
			offset = 0;
		}
		image->accessed = true;
	}
	if ( offset > 0 ) {
		offset = 0;
	}
	timing_gets( &image->atime, offset );
}

