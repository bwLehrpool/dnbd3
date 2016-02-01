#include "image.h"
#include "helper.h"
#include "fileutil.h"
#include "../shared/log.h"
#include "uplink.h"
#include "locks.h"
#include "integrity.h"
#include "../shared/protocol.h"
#include "../shared/sockhelper.h"
#include "altservers.h"
#include "server.h"
#include "../shared/signal.h"

#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <zlib.h>
#include <inttypes.h>
#include <pthread.h>
#include <errno.h>
#include <glob.h>

#define PATHLEN (2000)
#define NONWORKING_RECHECK_INTERVAL_SECONDS (60)

// ##########################################

dnbd3_image_t *_images[SERVER_MAX_IMAGES];
int _num_images = 0;

static pthread_spinlock_t imageListLock;
static pthread_mutex_t remoteCloneLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t reloadLock = PTHREAD_MUTEX_INITIALIZER;
#define NAMELEN  500
#define CACHELEN 20
typedef struct
{
	char name[NAMELEN];
	uint16_t rid;
	time_t deadline;
} imagecache;
static imagecache remoteCloneCache[CACHELEN];

// ##########################################

static void image_remove(dnbd3_image_t *image);
static dnbd3_image_t* image_free(dnbd3_image_t *image);
static bool image_isHashBlockComplete(const uint8_t * const cacheMap, const uint64_t block, const uint64_t fileSize);
static bool image_load_all_internal(char *base, char *path);
static bool image_load(char *base, char *path, int withUplink);
static bool image_clone(int sock, char *name, uint16_t revision, uint64_t imageSize);
static bool image_calcBlockCrc32(const int fd, const int block, const uint64_t realFilesize, uint32_t *crc);
static bool image_ensureDiskSpace(uint64_t size);

static uint8_t* image_loadCacheMap(const char * const imagePath, const int64_t fileSize);
static uint32_t* image_loadCrcList(const char * const imagePath, const int64_t fileSize, uint32_t *masterCrc);
static bool image_checkRandomBlocks(const int count, int fdImage, const int64_t fileSize, uint32_t * const crc32list, uint8_t * const cache_map);

// ##########################################

void image_serverStartup()
{
	spin_init( &imageListLock, PTHREAD_PROCESS_PRIVATE );
}

/**
 * Returns true if the given image is complete.
 * DOES NOT LOCK
 */
bool image_isComplete(dnbd3_image_t *image)
{
	assert( image != NULL );
	if ( image->working && image->cache_map == NULL ) {
		return true;
	}
	if ( image->virtualFilesize == 0 ) {
		return false;
	}
	bool complete = true;
	int j;
	const int map_len_bytes = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
	for (j = 0; j < map_len_bytes - 1; ++j) {
		if ( image->cache_map[j] != 0xFF ) {
			complete = false;
			break;
		}
	}
	if ( complete ) // Every block except the last one is complete
	{ // Last one might need extra treatment if it's not a full byte
		const int blocks_in_last_byte = (image->virtualFilesize >> 12) & 7;
		uint8_t last_byte = 0;
		if ( blocks_in_last_byte == 0 ) {
			last_byte = 0xFF;
		} else {
			for (j = 0; j < blocks_in_last_byte; ++j)
				last_byte |= (1 << j);
		}
		complete = ((image->cache_map[map_len_bytes - 1] & last_byte) == last_byte);
	}
	return complete;
}

/**
 * Update cache-map of given image for the given byte range
 * start (inclusive) - end (exclusive)
 * Locks on: images[].lock
 */
void image_updateCachemap(dnbd3_image_t *image, uint64_t start, uint64_t end, const bool set)
{
	assert( image != NULL );
	// This should always be block borders due to how the protocol works, but better be safe
	// than accidentally mark blocks as cached when they really aren't entirely cached.
	end &= ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
	start = (uint64_t)(start + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
	bool dirty = false;
	uint64_t pos = start;
	spin_lock( &image->lock );
	if ( image->cache_map == NULL ) {
		// Image seems already complete
		spin_unlock( &image->lock );
		logadd( LOG_DEBUG1, "image_updateCachemap with no cache_map: %s", image->path );
		return;
	}
	while ( pos < end ) {
		const int map_y = pos >> 15;
		const int map_x = (pos >> 12) & 7; // mod 8
		const uint8_t bit_mask = 1 << map_x;
		if ( set ) {
			if ( (image->cache_map[map_y] & bit_mask) == 0 ) dirty = true;
			image->cache_map[map_y] |= bit_mask;
		} else {
			image->cache_map[map_y] &= ~bit_mask;
		}
		pos += DNBD3_BLOCK_SIZE;
	}
	if ( dirty && image->crc32 != NULL ) {
		// If dirty is set, at least one of the blocks was not cached before, so queue all hash blocks
		// for checking, even though this might lead to checking some hash block again, if it was
		// already complete and the block range spanned at least two hash blocks.
		// First set start and end to borders of hash blocks
		start &= ~(uint64_t)(HASH_BLOCK_SIZE - 1);
		end = (end + HASH_BLOCK_SIZE - 1) & ~(uint64_t)(HASH_BLOCK_SIZE - 1);
		pos = start;
		while ( pos < end ) {
			if ( image->cache_map == NULL ) break;
			const int block = pos / HASH_BLOCK_SIZE;
			if ( image_isHashBlockComplete( image->cache_map, block, image->virtualFilesize ) ) {
				spin_unlock( &image->lock );
				integrity_check( image, block );
				spin_lock( &image->lock );
			}
			pos += HASH_BLOCK_SIZE;
		}
	}
	spin_unlock( &image->lock );
}

/**
 * Mark image as complete by freeing the cache_map and deleting the map file on disk
 * Locks on: image.lock
 */
void image_markComplete(dnbd3_image_t *image)
{
	char mapfile[PATHLEN] = "";
	assert( image != NULL );
	spin_lock( &image->lock );
	if ( image->cache_map != NULL ) {
		free( image->cache_map );
		image->cache_map = NULL;
		snprintf( mapfile, PATHLEN, "%s.map", image->path );
	}
	spin_unlock( &image->lock );
	if ( mapfile[0] != '\0' ) {
		remove( mapfile );
	}
}

/**
 * Save cache map of every image
 */
void image_saveAllCacheMaps()
{
	spin_lock( &imageListLock );
	for (int i = 0; i < _num_images; ++i) {
		if ( _images[i] == NULL ) continue;
		dnbd3_image_t * const image = _images[i];
		spin_lock( &image->lock );
		image->users++;
		spin_unlock( &image->lock );
		spin_unlock( &imageListLock );
		image_saveCacheMap( image );
		spin_lock( &imageListLock );
		spin_lock( &image->lock );
		image->users--;
		spin_unlock( &image->lock );
	}
	spin_unlock( &imageListLock );
}

/**
 * Saves the cache map of the given image.
 * Return true on success.
 * Locks on: image.lock
 */
bool image_saveCacheMap(dnbd3_image_t *image)
{
	if ( image == NULL || image->cache_map == NULL ) return true;
	spin_lock( &image->lock );
	// Lock and get a copy of the cache map, as it could be freed by another thread that is just about to
	// figure out that this image's cache copy is complete
	if ( image->cache_map == NULL || image->virtualFilesize < DNBD3_BLOCK_SIZE ) {
		spin_unlock( &image->lock );
		return true;
	}
	const size_t size = IMGSIZE_TO_MAPBYTES(image->virtualFilesize);
	uint8_t *map = malloc( size );
	memcpy( map, image->cache_map, size );
	// Unlock. Use path and cacheFd without locking. path should never change after initialization of the image,
	// cacheFd is written to and we don't hold a spinlock during I/O
	// By increasing the user count we make sure the image is not freed in the meantime
	// TODO: If the caller isn't a user of the image we still have a race condition when entering the function
	image->users++;
	spin_unlock( &image->lock );
	assert( image->path != NULL );
	char mapfile[strlen( image->path ) + 4 + 1];
	int fd;
	strcpy( mapfile, image->path );
	strcat( mapfile, ".map" );

	fd = open( mapfile, O_WRONLY | O_CREAT, 0644 );
	if ( fd < 0 ) {
		spin_lock( &image->lock );
		image->users--;
		spin_unlock( &image->lock );
		free( map );
		return false;
	}

	write( fd, map, size );
	if ( image->cacheFd != -1 ) {
		fdatasync( image->cacheFd );
	}
	fdatasync( fd );
	close( fd );
	free( map );

	spin_lock( &image->lock );
	image->users--;
	spin_unlock( &image->lock );
	return true;
}

/**
 * Get an image by name+rid. This function increases a reference counter,
 * so you HAVE TO CALL image_release for every image_get() call at some
 * point...
 * Locks on: imageListLock, _images[].lock
 */
dnbd3_image_t* image_get(char *name, uint16_t revision, bool checkIfWorking)
{
	int i;
	dnbd3_image_t *candidate = NULL;
	// Simple sanity check
	const int len = strlen( name );
	if ( len == 0 || name[len - 1] == '/' || name[0] == '/' ) return NULL ;
	// Go through array
	spin_lock( &imageListLock );
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
		spin_unlock( &imageListLock );
		return NULL ;
	}

	spin_lock( &candidate->lock );
	spin_unlock( &imageListLock );
	candidate->users++;
	spin_unlock( &candidate->lock );

	if ( !checkIfWorking ) return candidate; // Found, but not interested in working state

	// Found, see if it works

	if ( candidate->working ) {
		// Last known state was "working", see if that should change
		if ( candidate->readFd == -1 ) {
			candidate->working = false;
		}
	} else { // ...not working...
		// Don't re-check too often
		spin_lock( &candidate->lock );
		bool check;
		const time_t now = time( NULL );
		check = ( now - candidate->lastWorkCheck ) > NONWORKING_RECHECK_INTERVAL_SECONDS;
		if ( check ) {
			candidate->lastWorkCheck = now;
		}
		spin_unlock( &candidate->lock );
		if ( !check ) {
			return candidate;
		}
		// Check if the local file exists, has the right size, and is readable (writable for incomplete image)
		if ( candidate->cache_map != NULL ) {
			// -- Incomplete - rw check
			if ( candidate->cacheFd == -1 ) { // Make sure file is open for writing
				candidate->cacheFd = open( candidate->path, O_RDWR );
				// It might have failed - still offer proxy mode, we just can't cache
				if ( candidate->cacheFd == -1 ) {
					logadd( LOG_WARNING, "Cannot re-open %s for writing - replication disabled", candidate->path );
				}
			}
			if ( candidate->uplink == NULL && candidate->cacheFd != -1 ) {
				uplink_init( candidate, -1, NULL );
			}
		}
		// Common for ro and rw images
		const off_t len = lseek( candidate->readFd, 0, SEEK_END );
		if ( len == -1 ) {
			logadd( LOG_WARNING, "lseek() on %s failed (errno=%d), removing image", candidate->path, errno );
			if ( _removeMissingImages ) {
				image_remove( candidate ); // No release here, the image is still returned and should be released by caller
			}
		} else if ( (uint64_t)len != candidate->realFilesize ) {
			logadd( LOG_DEBUG1, "Size of %s changed at runtime, keeping disabled! Expected: %" PRIu64 ", found: %" PRIu64
					". Try sending SIGHUP to server if you know what you're doing.",
					candidate->path, candidate->realFilesize, (uint64_t)len );
		} else {
			// Seek worked, file size is same, now see if we can read from file
			char buffer[100];
			if ( pread( candidate->readFd, buffer, sizeof(buffer), 0 ) == -1 ) {
				logadd( LOG_DEBUG2, "Reading first %d bytes from %s failed (errno=%d), removing image",
						(int)sizeof(buffer), candidate->path, errno );
				if ( _removeMissingImages ) {
					image_remove( candidate );
				}
			} else {
				// Seems everything is fine again \o/
				candidate->working = true;
				logadd( LOG_INFO, "Changed state of %s:%d to 'working'", candidate->name, candidate->rid );
			}
		}
	}

	return candidate; // Success :-)
}

/**
 * Lock the image by increasing its users count
 * Returns the image on success, NULL if it is not found in the image list
 * Every call to image_lock() needs to be followed by a call to image_release() at some point.
 * Locks on: imageListLock, _images[].lock
 */
dnbd3_image_t* image_lock(dnbd3_image_t *image) // TODO: get rid, fix places that do image->users--
{
	if ( image == NULL ) return NULL ;
	int i;
	spin_lock( &imageListLock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] == image ) {
			spin_lock( &image->lock );
			spin_unlock( &imageListLock );
			image->users++;
			spin_unlock( &image->lock );
			return image;
		}
	}
	spin_unlock( &imageListLock );
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
	spin_lock( &imageListLock );
	spin_lock( &image->lock );
	assert( image->users > 0 );
	image->users--;
	bool inUse = image->users != 0;
	spin_unlock( &image->lock );
	if ( inUse ) { // Still in use, do nothing
		spin_unlock( &imageListLock );
		return NULL;
	}
	// Getting here means we decreased the usage counter to zero
	// If the image is not in the images list anymore, we're
	// responsible for freeing it
	for (int i = 0; i < _num_images; ++i) {
		if ( _images[i] == image ) { // Found, do nothing
			spin_unlock( &imageListLock );
			return NULL;
		}
	}
	spin_unlock( &imageListLock );
	// So it wasn't in the images list anymore either, get rid of it
	if ( !inUse ) image = image_free( image );
	return NULL;
}

/**
 * Remove image from images array. Only free it if it has
 * no active users and was actually in the list.
 * Locks on: imageListLock, image[].lock
 */
static void image_remove(dnbd3_image_t *image)
{
	bool mustFree = false;
	spin_lock( &imageListLock );
	spin_lock( &image->lock );
	for ( int i = _num_images - 1; i >= 0; --i ) {
		if ( _images[i] == image ) {
			_images[i] = NULL;
			mustFree = ( image->users == 0 );
		}
		if ( _images[i] == NULL && i + 1 == _num_images ) _num_images--;
	}
	spin_unlock( &image->lock );
	spin_unlock( &imageListLock );
	if ( mustFree ) image = image_free( image );
}

/**
 * Kill all uplinks
 */
void image_killUplinks()
{
	int i;
	spin_lock( &imageListLock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] == NULL ) continue;
		spin_lock( &_images[i]->lock );
		if ( _images[i]->uplink != NULL ) {
			_images[i]->uplink->shutdown = true;
			signal_call( _images[i]->uplink->signal );
		}
		spin_unlock( &_images[i]->lock );
	}
	spin_unlock( &imageListLock );
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
	if ( _removeMissingImages ) {
		// Check if all loaded images still exist on disk
		logadd( LOG_DEBUG1, "Checking for vanished images" );
		spin_lock( &imageListLock );
		for ( int i = _num_images - 1; i >= 0; --i ) {
			if ( _shutdown ) break;
			if ( _images[i] == NULL ) {
				if ( i + 1 == _num_images ) _num_images--;
				continue;
			}
			imgId = _images[i]->id;
			snprintf( imgPath, PATHLEN, "%s", _images[i]->path );
			spin_unlock( &imageListLock ); // isReadable hits the fs; unlock
			// Check if fill can still be opened for reading
			ret = file_isReadable( imgPath );
			// Lock again, see if image is still there, free if required
			spin_lock( &imageListLock );
			if ( ret || i >= _num_images || _images[i] == NULL || _images[i]->id != imgId ) continue;
			// Image needs to be removed
			imgHandle = _images[i];
			_images[i] = NULL;
			if ( i + 1 == _num_images ) _num_images--;
			spin_lock( &imgHandle->lock );
			const bool freeImg = ( imgHandle->users == 0 );
			spin_unlock( &imgHandle->lock );
			if ( freeImg ) {
				// Image is not in use anymore, free the dangling entry immediately
				spin_unlock( &imageListLock ); // image_free might do several fs operations; unlock
				image_free( imgHandle );
				spin_lock( &imageListLock );
			}
		}
		spin_unlock( &imageListLock );
		if ( _shutdown ) return true;
	}
	// Now scan for new images
	logadd( LOG_DEBUG1, "Scanning for new or modified images" );
	pthread_mutex_lock( &reloadLock );
	ret = image_load_all_internal( path, path );
	pthread_mutex_unlock( &reloadLock );
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
	spin_lock( &imageListLock );
	for (int i = _num_images - 1; i >= 0; --i) {
		if ( _images[i] != NULL && _images[i]->users == 0 ) { // XXX Data race...
			_images[i] = image_free( _images[i] );
		}
		if ( i + 1 == _num_images && _images[i] == NULL ) _num_images--;
	}
	spin_unlock( &imageListLock );
	return _num_images == 0;
}

/**
 * Free image. DOES NOT check if it's in use.
 * Indirectly locks on image.lock, uplink.queueLock
 */
static dnbd3_image_t* image_free(dnbd3_image_t *image)
{
	assert( image != NULL );
	if ( !_shutdown ) {
		logadd( LOG_INFO, "Freeing image %s:%d", image->name, (int)image->rid );
	}
	//
	image_saveCacheMap( image );
	uplink_shutdown( image );
	spin_lock( &image->lock );
	free( image->cache_map );
	free( image->crc32 );
	free( image->path );
	free( image->name );
	spin_unlock( &image->lock );
	if ( image->cacheFd != -1 ) close( image->cacheFd );
	if ( image->readFd != -1 ) close( image->readFd );
	spin_destroy( &image->lock );
	//
	memset( image, 0, sizeof(*image) );
	free( image );
	return NULL ;
}

static bool image_isHashBlockComplete(const uint8_t * const cacheMap, const uint64_t block, const uint64_t realFilesize)
{
	if ( cacheMap == NULL ) return true;
	const uint64_t end = (block + 1) * HASH_BLOCK_SIZE;
	if ( end <= realFilesize ) {
		// Trivial case: block in question is not the last block (well, or image size is multiple of HASH_BLOCK_SIZE)
		const int startCacheIndex = (int)( ( block * HASH_BLOCK_SIZE ) / ( DNBD3_BLOCK_SIZE * 8 ) );
		const int endCacheIndex = startCacheIndex + ( HASH_BLOCK_SIZE / ( DNBD3_BLOCK_SIZE * 8 ) );
		for ( int i = startCacheIndex; i < endCacheIndex; ++i ) {
			if ( cacheMap[i] != 0xff ) {
				return false;
			}
		}
	} else {
		// Special case: Checking last block, which is smaller than HASH_BLOCK_SIZE
		for (uint64_t mapPos = block * HASH_BLOCK_SIZE; mapPos < realFilesize; mapPos += DNBD3_BLOCK_SIZE ) {
			const int map_y = mapPos >> 15;
			const int map_x = (mapPos >> 12) & 7; // mod 8
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
#define SUBDIR_LEN 120
	assert( path != NULL );
	assert( *path == '/' );
	struct dirent entry, *entryPtr;
	const int pathLen = strlen( path );
	char subpath[PATHLEN];
	struct stat st;
	DIR * const dir = opendir( path );

	if ( dir == NULL ) {
		logadd( LOG_ERROR, "Could not opendir '%s' for loading", path );
		return false;
	}

	while ( !_shutdown && (entryPtr = readdir( dir )) != NULL ) {
		entry = *entryPtr;
		if ( strcmp( entry.d_name, "." ) == 0 || strcmp( entry.d_name, ".." ) == 0 ) continue;
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
		} else {
			image_load( base, subpath, true ); // Load image if possible
		}
	}
	closedir( dir );
	return true;
#undef SUBDIR_LEN
}

/**
 * Load image from given path. This will check if the image is
 * already loaded and updates its information in that case.
 * Note that this is NOT THREAD SAFE so make sure its always
 * called on one thread only.
 */
static bool image_load(char *base, char *path, int withUplink)
{
	static int imgIdCounter = 0; // Used to assign unique numeric IDs to images
	int i, revision = -1;
	struct stat st;
	uint8_t *cache_map = NULL;
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
	const int fileNameLen = strlen( fileName );

	// Copy virtual path (relative path in "base")
	char * const virtBase = path + strlen( base ) + 1;
	assert( *virtBase != '/' );
	char *src = virtBase, *dst = imgName;
	while ( src <= lastSlash ) {
		*dst++ = *src++;
	}
	*dst = '\0';

	// Parse file name for revision
	if ( _vmdkLegacyMode && strend( fileName, ".vmdk" ) ) {
		// Easy - legacy mode, simply append full file name and set rid to 1
		strcat( dst, fileName );
		revision = 1;
	} else if ( !_vmdkLegacyMode ) {
		// Try to parse *.r<ID> syntax
		for (i = fileNameLen - 1; i > 1; --i) {
			if ( fileName[i] < '0' || fileName[i] > '9' ) break;
		}
		if ( i == fileNameLen - 1 ) return false;
		if ( fileName[i] != 'r' ) return false;
		if ( fileName[i - 1] != '.' ) return false;
		revision = atoi( fileName + i + 1 );
		src = fileName;
		while ( src < fileName + i - 1 ) {
			*dst++ = *src++;
		}
		*dst = '\0';
	}
	if ( revision <= 0 || revision >= 65536 ) {
		logadd( LOG_WARNING, "Image '%s' has invalid revision ID %d", path, revision );
		goto load_error;
	}

	// Get pointer to already existing image if possible
	existing = image_get( imgName, revision, true );

	// ### Now load the actual image related data ###
	fdImage = open( path, O_RDONLY );
	if ( fdImage < 0 ) {
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
	cache_map = image_loadCacheMap( path, virtualFilesize );

	// XXX: Maybe try sha-256 or 512 first if you're paranoid (to be implemented)

	// 2. Load CRC-32 list of image
	uint32_t masterCrc;
	const int hashBlockCount = IMGSIZE_TO_HASHBLOCKS( virtualFilesize );
	crc32list = image_loadCrcList( path, virtualFilesize, &masterCrc );

	// Check CRC32
	if ( crc32list != NULL ) {
		if ( !image_checkRandomBlocks( 4, fdImage, realFilesize, crc32list, cache_map ) ) {
			logadd( LOG_ERROR, "quick crc32 check of %s failed. Data corruption?", path );
			goto load_error;
		}
	}

	// Compare data just loaded to identical image we apparently already loaded
	if ( existing != NULL ) {
		if ( existing->realFilesize != realFilesize ) {
			logadd( LOG_WARNING, "Size of image '%s:%d' has changed.", existing->name, (int)existing->rid );
			// Image will be replaced below
		} else if ( existing->crc32 != NULL && crc32list != NULL
		        && memcmp( existing->crc32, crc32list, sizeof(uint32_t) * hashBlockCount ) != 0 ) {
			logadd( LOG_WARNING, "CRC32 list of image '%s:%d' has changed.", existing->name, (int)existing->rid );
			logadd( LOG_WARNING, "The image will be reloaded, but you should NOT replace existing images while the server is running." );
			logadd( LOG_WARNING, "Actually even if it's not running this should never be done. Use a new RID instead!" );
			// Image will be replaced below
		} else if ( existing->crc32 == NULL && crc32list != NULL ) {
			logadd( LOG_INFO, "Found CRC-32 list for already loaded image '%s:%d', adding...", existing->name, (int)existing->rid );
			existing->crc32 = crc32list;
			existing->masterCrc32 = masterCrc;
			crc32list = NULL;
			function_return = true;
			goto load_error; // Keep existing
		} else if ( existing->cache_map != NULL && cache_map == NULL ) {
			// Just ignore that fact, if replication is really complete the cache map will be removed anyways
			logadd( LOG_INFO, "Image '%s:%d' has no cache map on disk!", existing->name, (int)existing->rid );
			function_return = true;
			goto load_error; // Keep existing
		} else {
			// Nothing changed about the existing image, so do nothing
			function_return = true;
			goto load_error; // Keep existing
		}
		// Remove existing image from images array, so it will be replaced by the reloaded image
		image_remove( existing );
		image_release( existing );
		existing = NULL;
	}

	// Load fresh image
	dnbd3_image_t *image = calloc( 1, sizeof(dnbd3_image_t) );
	image->path = strdup( path );
	image->name = strdup( imgName );
	image->cache_map = cache_map;
	image->crc32 = crc32list;
	image->masterCrc32 = masterCrc;
	image->uplink = NULL;
	image->realFilesize = realFilesize;
	image->virtualFilesize = virtualFilesize;
	image->rid = revision;
	image->users = 0;
	image->readFd = -1;
	image->cacheFd = -1;
	image->working = (image->cache_map == NULL );
	spin_init( &image->lock, PTHREAD_PROCESS_PRIVATE );
	if ( stat( path, &st ) == 0 ) {
		image->atime = st.st_mtime;
	} else {
		image->atime = time( NULL );
	}

	// Prevent freeing in cleanup
	cache_map = NULL;
	crc32list = NULL;

	// Get rid of cache map if image is complete
	if ( image->cache_map != NULL && image_isComplete( image ) ) {
		image_markComplete( image );
		image->working = true;
	}

	// Image is definitely incomplete, open image file for writing, so we can update the cache
	if ( image->cache_map != NULL ) {
		image->working = false;
		image->cacheFd = open( path, O_WRONLY );
		if ( image->cacheFd < 0 ) {
			// Proxy mode without disk caching is pointless, bail out
			image->cacheFd = -1;
			logadd( LOG_ERROR, "Could not open incomplete image %s for writing!", path );
			image = image_free( image );
			goto load_error;
		}
		if ( withUplink ) {
			uplink_init( image, -1, NULL );
		}
	}

	// ### Reaching this point means loading succeeded
	// Add to images array
	spin_lock( &imageListLock );
	// Now we're locked, assign unique ID to image (unique for this running server instance!)
	image->id = ++imgIdCounter;
	for ( i = 0; i < _num_images; ++i ) {
		if ( _images[i] != NULL ) continue;
		_images[i] = image;
		break;
	}
	if ( i >= _num_images ) {
		if ( _num_images >= SERVER_MAX_IMAGES ) {
			spin_unlock( &imageListLock );
			logadd( LOG_ERROR, "Cannot load image '%s': maximum number of images reached.", path );
			image = image_free( image );
			goto load_error;
		}
		_images[_num_images++] = image;
	}
	// Keep fd for reading
	image->readFd = fdImage;
	fdImage = -1;
	spin_unlock( &imageListLock );
	logadd( LOG_DEBUG1, "Loaded image '%s:%d'\n", image->name, (int)image->rid );

	function_return = true;

	// Clean exit:
	load_error: ;
	if ( existing != NULL ) image_release( existing );
	if ( crc32list != NULL ) free( crc32list );
	if ( cache_map != NULL ) free( cache_map );
	if ( fdImage != -1 ) close( fdImage );
	return function_return;
}

static uint8_t* image_loadCacheMap(const char * const imagePath, const int64_t fileSize)
{
	uint8_t *retval = NULL;
	char mapFile[strlen( imagePath ) + 10 + 1];
	sprintf( mapFile, "%s.map", imagePath );
	int fdMap = open( mapFile, O_RDONLY );
	if ( fdMap >= 0 ) {
		const int map_size = IMGSIZE_TO_MAPBYTES( fileSize );
		retval = calloc( 1, map_size );
		const ssize_t rd = read( fdMap, retval, map_size );
		if ( map_size != rd ) {
			logadd( LOG_WARNING, "Could only read %d of expected %d bytes of cache map of '%s'", (int)rd, (int)map_size, fileSize );
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
				const off_t listEnd = hashBlocks * (off_t)sizeof(uint32_t);
				off_t pos = 0;
				retval = calloc( hashBlocks, sizeof(uint32_t) );
				while ( pos < listEnd ) {
					ssize_t ret = pread( fdHash, retval + pos, listEnd - pos, pos + sizeof(uint32_t) /* skip master-crc */ );
					if ( ret == -1 ) {
						if ( errno == EINTR || errno == EAGAIN ) continue;
					}
					if ( ret <= 0 ) break;
					pos += ret;
				}
				if ( pos != listEnd ) {
					free( retval );
					retval = NULL;
					logadd( LOG_WARNING, "Could not read crc32 list of '%s'", imagePath );
				} else {
					uint32_t lists_crc = crc32( 0L, Z_NULL, 0 );
					lists_crc = crc32( lists_crc, (Bytef*)retval, hashBlocks * sizeof(uint32_t) );
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

static bool image_checkRandomBlocks(const int count, int fdImage, const int64_t realFilesize, uint32_t * const crc32list, uint8_t * const cache_map)
{
	// This checks the first block and (up to) count - 1 random blocks for corruption
	// via the known crc32 list. This is very sloppy and is merely supposed to detect
	// accidental corruption due to broken dnbd3-proxy functionality or file system
	// corruption.
	assert( count > 0 );
	const int hashBlocks = IMGSIZE_TO_HASHBLOCKS( realFilesize );
	int blocks[count + 1];
	int index = 0, j;
	int block;
	if ( image_isHashBlockComplete( cache_map, 0, realFilesize ) ) blocks[index++] = 0;
	int tries = count * 5; // Try only so many times to find a non-duplicate complete block
	while ( index + 1 < count && --tries > 0 ) {
		block = rand() % hashBlocks; // Random block
		for ( j = 0; j < index; ++j ) { // Random block already in list?
			if ( blocks[j] == block ) goto while_end;
		}
		// Block complete? If yes, add to list
		if ( image_isHashBlockComplete( cache_map, block, realFilesize ) ) blocks[index++] = block;
while_end: ;
	}
	blocks[MIN(index, count)] = -1; // End of array has to be marked by a -1
	return image_checkBlocksCrc32( fdImage, crc32list, blocks, realFilesize ); // Return result of check
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
	char path[PATHLEN], cache[PATHLEN];
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
	snprintf( cache, PATHLEN, "%s.map", path );
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
	if ( !file_alloc( fdCache, 0, mapsize ) ) {
		const int err = errno;
		logadd( LOG_ERROR, "Could not allocate %d bytes for %s (errno=%d)", mapsize, cache, err );
		goto failure_cleanup;
	}
	// Now write image
	if ( !file_alloc( fdImage, 0, size ) ) {
		const int err = errno;
		logadd( LOG_ERROR, "Could not allocate %" PRIu64 " bytes for %s (errno=%d)", size, path, err );
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
 * b) Try to load it from disk by constructing the appropriate file name, if not
 *    running in proxy mode.
 *
 *  If the return value is not NULL,
 * image_release needs to be called on the image at some point.
 * Locks on: remoteCloneLock, imageListLock, _images[].lock
 */
dnbd3_image_t* image_getOrLoad(char * const name, const uint16_t revision)
{
	// specific revision - try shortcut
	if ( revision != 0 ) {
		dnbd3_image_t *image = image_get( name, revision, true );
		if ( image != NULL ) return image;
	}
	const size_t len = strlen( name );
	// Sanity check
	if ( len == 0 || name[len - 1] == '/' || name[0] == '/'
			|| name[0] == '.' || strstr( name, "/." ) != NULL ) return NULL;
	// Call specific function depending on whether this is a proxy or not
	if ( _isProxy ) {
		return loadImageProxy( name, revision, len );
	} else {
		return loadImageServer( name, revision );
	}
}

/**
 * Called if specific rid is not loaded, or if rid is 0 (some version might be loaded locally,
 * but we should check if there's a higher rid on a remote server).
 */
static dnbd3_image_t *loadImageProxy(char * const name, const uint16_t revision, const size_t len)
{
	int i;
	// Already existing locally?
	dnbd3_image_t *image = NULL;
	if ( revision == 0 ) {
		image = image_get( name, revision, true );
	}

	// Doesn't exist or is rid 0, try remote if not already tried it recently
	const time_t now = time( NULL );
	char *cmpname = name;
	int useIndex = -1, fallbackIndex = 0;
	if ( len >= NAMELEN ) cmpname += 1 + len - NAMELEN;
	pthread_mutex_lock( &remoteCloneLock );
	for (i = 0; i < CACHELEN; ++i) {
		if ( remoteCloneCache[i].rid == revision && strcmp( cmpname, remoteCloneCache[i].name ) == 0 ) {
			useIndex = i;
			if ( remoteCloneCache[i].deadline < now ) break;
			pthread_mutex_unlock( &remoteCloneLock ); // Was recently checked...
			return image;
		}
		if ( remoteCloneCache[i].deadline < remoteCloneCache[fallbackIndex].deadline ) {
			fallbackIndex = i;
		}
	}
	// Re-check to prevent two clients at the same time triggering this,
	// but only if rid != 0, since we would just get an old rid then
	if ( revision != 0 ) {
		if ( image == NULL ) image = image_get( name, revision, true );
		if ( image != NULL ) {
			pthread_mutex_unlock( &remoteCloneLock );
			return image;
		}
	}
	// Reaching this point means we should contact an authority server
	serialized_buffer_t serialized;
	// Mark as recently checked
	if ( useIndex == -1 ) {
		useIndex = fallbackIndex;
	}
	remoteCloneCache[useIndex].deadline = now + SERVER_REMOTE_IMAGE_CHECK_CACHETIME;
	snprintf( remoteCloneCache[useIndex].name, NAMELEN, "%s", cmpname );
	remoteCloneCache[useIndex].rid = revision;
	pthread_mutex_unlock( &remoteCloneLock );

	// Get some alt servers and try to get the image from there
	dnbd3_host_t servers[4];
	int uplinkSock = -1;
	dnbd3_host_t *uplinkServer = NULL;
	const int count = altservers_get( servers, 4, false );
	uint16_t remoteProtocolVersion;
	uint16_t remoteRid = revision;
	uint64_t remoteImageSize;
	for (i = 0; i < count; ++i) {
		char *remoteName;
		bool ok = false;
		int sock = sock_connect( &servers[i], 750, _uplinkTimeout );
		if ( sock == -1 ) continue;
		if ( !dnbd3_select_image( sock, name, revision, FLAGS8_SERVER ) ) goto server_fail;
		if ( !dnbd3_select_image_reply( &serialized, sock, &remoteProtocolVersion, &remoteName, &remoteRid, &remoteImageSize ) ) goto server_fail;
		if ( remoteProtocolVersion < MIN_SUPPORTED_SERVER || remoteRid == 0 ) goto server_fail;
		if ( revision != 0 && remoteRid != revision ) goto server_fail; // Want specific revision but uplink supplied different rid
		if ( revision == 0 && image != NULL && image->rid >= remoteRid ) goto server_fail; // Not actually a failure: Highest remote rid is <= highest local rid - don't clone!
		if ( remoteImageSize < DNBD3_BLOCK_SIZE || remoteName == NULL || strcmp( name, remoteName ) != 0 ) goto server_fail;
		if ( remoteImageSize > SERVER_MAX_PROXY_IMAGE_SIZE ) goto server_fail;
		pthread_mutex_lock( &reloadLock );
		ok = image_ensureDiskSpace( remoteImageSize )
				&& image_clone( sock, name, remoteRid, remoteImageSize ); // This sets up the file+map+crc and loads the img
		pthread_mutex_unlock( &reloadLock );
		if ( !ok ) goto server_fail;

		// Cloning worked :-)
		uplinkSock = sock;
		uplinkServer = &servers[i];
		break;

server_fail: ;
		close( sock );
	}

	// If we still have a pointer to a local image, release the reference
	if ( image != NULL ) image_release( image );
	// If everything worked out, this call should now actually return the image
	image = image_get( name, remoteRid, false );
	if ( image != NULL && uplinkSock != -1 && uplinkServer != NULL ) {
		// If so, init the uplink and pass it the socket
		if ( !uplink_init( image, uplinkSock, uplinkServer ) ) {
			close( uplinkSock );
		} else {
			// Clumsy busy wait, but this should only take as long as it takes to start a thread, so is it really worth using a signalling mechanism?
			i = 0;
			while ( !image->working && ++i < 100 )
				usleep( 2000 );
		}
	} else if ( uplinkSock >= 0 ) {
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

	if ( _vmdkLegacyMode ) {
		if ( strend( name, ".vmdk" ) ) {
			snprintf( imageFile, PATHLEN, "%s/%s", _basePath, name );
			detectedRid = MAX( 1, requestedRid );
		}
	} else if ( requestedRid != 0 ) {
		snprintf( imageFile, PATHLEN, "%s/%s.r%d", _basePath, name, requestedRid );
		detectedRid = requestedRid;
	} else {
		glob_t g = { 0 };
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
	logadd( LOG_DEBUG2, "Trying to load %s:%d ( -> %d) as %s", name, (int)requestedRid, (int)detectedRid, imageFile );
	// No file was determined, or it doesn't seem to exist/be readable
	if ( imageFile[0] == '\0' ) {
		logadd( LOG_DEBUG2, "Not found, bailing out" );
		return image_get( name, detectedRid, true );
	}
	if ( !_vmdkLegacyMode && requestedRid == 0 ) {
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
	pthread_mutex_lock( &reloadLock );
	dnbd3_image_t* image = image_get( name, detectedRid, true );
	if ( image != NULL ) {
		// The image magically appeared in the meantime
		logadd( LOG_DEBUG2, "Magically appeared" );
		pthread_mutex_unlock( &reloadLock );
		return image;
	}
	// Still not loaded, let's try to do so
	logadd( LOG_DEBUG2, "Calling load" );
	image_load( _basePath, imageFile, false );
	pthread_mutex_unlock( &reloadLock );
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
			uint32_t lists_crc = crc32( 0L, Z_NULL, 0 );
			lists_crc = crc32( lists_crc, (Bytef*)crc32list, crc32len );
			if ( lists_crc != masterCrc ) {
				logadd( LOG_WARNING, "OTF-Clone: Corrupted CRC-32 list. ignored. (%s)", name );
			} else {
				int fd = open( crcFile, O_WRONLY | O_CREAT, 0644 );
				write( fd, &lists_crc, sizeof(uint32_t) );
				write( fd, crc32list, crc32len );
				close( fd );
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
	crc = crc32( 0L, Z_NULL, 0 );
	while ( blocksToGo > 0 ) {
		const int numBlocks = MIN( (int)( sizeof(buffer) / sizeof(crc) ), blocksToGo );
		if ( read( fdCrc, buffer, numBlocks * sizeof(crc) ) != numBlocks * (int)sizeof(crc) ) {
			logadd( LOG_ERROR, "Could not re-read from crc32 file" );
			goto cleanup_fail;
		}
		crc = crc32( crc, (Bytef*)buffer, numBlocks * sizeof(crc) );
		blocksToGo -= numBlocks;
	}
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
	char buffer[100] = { 0 };
	uint64_t bytesReceived;
	int users, completeness;

	spin_lock( &imageListLock );
	for ( i = 0; i < _num_images; ++i ) {
		if ( _images[i] == NULL ) continue;
		dnbd3_image_t *image = _images[i];
		spin_lock( &image->lock );
		spin_unlock( &imageListLock );
		users = image->users;
		completeness = image_getCompletenessEstimate( image );
		if ( image->uplink == NULL ) {
			bytesReceived = 0;
		} else {
			bytesReceived = image->uplink->bytesReceived;
			if ( !host_to_string( &image->uplink->currentServer, buffer, sizeof(buffer) ) ) {
				buffer[0] = '\0';
			}
		}
		image->users++; // Prevent freeing after we unlock
		spin_unlock( &image->lock );

		jsonImage = json_pack( "{sisssisisi}",
				"id", image->id, // id, name, rid never change, so access them without locking
				"name", image->name,
				"rid", (int) image->rid,
				"users", users,
				"complete",  completeness );
		if ( bytesReceived != 0 ) {
			json_object_set_new( jsonImage, "uplinkServer", json_string( buffer ) );
			json_object_set_new( jsonImage, "receivedBytes", json_integer( (json_int_t) bytesReceived ) );
		}
		json_array_append_new( imagesJson, jsonImage );

		image = image_release( image ); // Since we did image->users++;
		spin_lock( &imageListLock );
	}
	spin_unlock( &imageListLock );
	return imagesJson;
}

/**
 * Get completeness of an image in percent. Only estimated, not exact.
 * Returns: 0-100
 * DOES NOT LOCK, so make sure to do so before calling
 */
int image_getCompletenessEstimate(dnbd3_image_t * const image)
{
	assert( image != NULL );
	if ( image->cache_map == NULL ) return image->working ? 100 : 0;
	const time_t now = time( NULL );
	if ( now < image->nextCompletenessEstimate ) {
		// Since this operation is relatively expensive, we cache the result for a while
		return image->completenessEstimate;
	}
	int i;
	int percent = 0;
	const int len = IMGSIZE_TO_MAPBYTES( image->virtualFilesize );
	if ( len == 0 ) return 0;
	for ( i = 0; i < len; ++i ) {
		if ( image->cache_map[i] == 0xff ) {
			percent += 100;
		} else if ( image->cache_map[i] != 0 ) {
			percent += 50;
		}
	}
	image->completenessEstimate = percent / len;
	image->nextCompletenessEstimate = now + 10 + rand() % 30;
	return image->completenessEstimate;
}

/**
 * Check the CRC-32 of the given blocks. The array blocks is of variable length.
 * !! pass -1 as the last block so the function knows when to stop !!
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

static bool image_calcBlockCrc32(const int fd, const int block, const uint64_t realFilesize, uint32_t *crc)
{
	char buffer[40000];
	*crc = crc32( 0L, Z_NULL, 0 );
	int bytes = 0;
	// How many bytes to read from the input file
	const int bytesFromFile = MIN( HASH_BLOCK_SIZE, realFilesize - ( (int64_t)block * HASH_BLOCK_SIZE) );
	// Determine how many bytes we had to read if the file size were a multiple of 4k
	// This might be the same value if the real file's size is a multiple of 4k
	const int64_t vbs = ( ( realFilesize + ( DNBD3_BLOCK_SIZE - 1 ) ) & ~( DNBD3_BLOCK_SIZE - 1 ) ) - ( (int64_t)block * HASH_BLOCK_SIZE);
	const int virtualBytesFromFile = (int)MIN( HASH_BLOCK_SIZE, vbs );
	const off_t readPos = (int64_t)block * HASH_BLOCK_SIZE;
	// Calculate the crc32 by reading data from the file
	while ( bytes < bytesFromFile ) {
		const int n = MIN( (int)sizeof(buffer), bytesFromFile - bytes );
		const int r = pread( fd, buffer, n, readPos + bytes );
		if ( r <= 0 ) {
			logadd( LOG_WARNING, "CRC: Read error (errno=%d)", errno );
			return false;
		}
		*crc = crc32( *crc, (Bytef*)buffer, r );
		bytes += r;
	}
	// If the virtual file size is different, keep going using nullbytes
	if ( bytesFromFile < virtualBytesFromFile ) {
		memset( buffer, 0, sizeof(buffer) );
		bytes = virtualBytesFromFile - bytesFromFile;
		while ( bytes != 0 ) {
			const int len = MIN( (int)sizeof(buffer), bytes );
			*crc = crc32( *crc, (Bytef*)buffer, len );
			bytes -= len;
		}
	}
	return true;
}

/**
 * Make sure at least size bytes are available in _basePath.
 * Will delete old images to make room for new ones.
 * TODO: Store last access time of images. Currently the
 * last access time is reset on server restart. Thus it will
 * currently only delete images if server uptime is > 10 hours
 * Return true iff enough space is available. false in random other cases
 */
static bool image_ensureDiskSpace(uint64_t size)
{
	for ( int maxtries = 0; maxtries < 20; ++maxtries ) {
		const int64_t available = file_freeDiskSpace( _basePath );
		if ( available == -1 ) {
			const int e = errno;
			logadd( LOG_WARNING, "Could not get free disk space (errno %d), will assume there is enough space left... ;-)\n", e );
			return true;
		}
		if ( (uint64_t)available > size ) return true;
		if ( dnbd3_serverUptime() < 10 * 3600 ) {
			logadd( LOG_INFO, "Only %dMiB free, %dMiB requested, but server uptime < 10 hours...", (int)(available / (1024ll * 1024ll)),
			        (int)(size / (1024 * 1024)) );
			return false;
		}
		logadd( LOG_INFO, "Only %dMiB free, %dMiB requested, freeing an image...", (int)(available / (1024ll * 1024ll)),
		        (int)(size / (1024 * 1024)) );
		// Find least recently used image
		dnbd3_image_t *oldest = NULL;
		int i; // XXX improve locking
		for (i = 0; i < _num_images; ++i) {
			if ( _images[i] == NULL ) continue;
			dnbd3_image_t *current = image_lock( _images[i] );
			if ( current == NULL ) continue;
			if ( current->atime != 0 && current->users == 1 ) { // Just from the lock above
				if ( oldest == NULL || oldest->atime > current->atime ) {
					// Oldest access time so far
					oldest = current;
				}
			}
			image_release( current );
		}
		if ( oldest == NULL || time( NULL ) - oldest->atime < 86400 ) {
			logadd( LOG_DEBUG1, "No image is old enough :-(\n" );
			return false;
		}
		oldest = image_lock( oldest );
		if ( oldest == NULL ) continue; // Image freed in the meantime? Try again
		logadd( LOG_INFO, "'%s:%d' has to go!", oldest->name, (int)oldest->rid );
		unlink( oldest->path );
		size_t len = strlen( oldest->path ) + 5 + 1;
		char buffer[len];
		snprintf( buffer, len, "%s.map", oldest->path );
		unlink( buffer );
		snprintf( buffer, len, "%s.crc", oldest->path );
		unlink( buffer );
		snprintf( buffer, len, "%s.meta", oldest->path );
		unlink( buffer );
		image_remove( oldest );
		image_release( oldest );
	}
	return false;
}

/*
 void image_find_latest()
 {
 // Not in array or most recent rid is requested, try file system
 if (revision != 0) {
 // Easy case - specific RID
 char
 } else {
 // Determine base directory where the image in question has to reside.
 // Eg, the _basePath is "/srv/", requested image is "rz/ubuntu/default-13.04"
 // Then searchPath has to be set to "/srv/rz/ubuntu"
 char searchPath[strlen(_basePath) + len + 1];
 char *lastSlash = strrchr(name, '/');
 char *baseName; // Name of the image. In the example above, it will be "default-13.04"
 if ( lastSlash == NULL ) {
 *searchPath = '\0';
 baseName = name;
 } else {
 char *from = name, *to = searchPath;
 while (from < lastSlash) *to++ = *from++;
 *to = '\0';
 baseName = lastSlash + 1;
 }
 // Now we have the search path in our real file system and the expected image name.
 // The revision naming sceme is <IMAGENAME>.r<RID>, so if we're looking for revision 13,
 // our example image has to be named default-13.04.r13
 }
 }
 */
