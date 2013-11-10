#include "image.h"
#include "helper.h"
#include "fileutil.h"
#include "memlog.h"
#include "uplink.h"
#include "locks.h"
#include "integrity.h"
#include "protocol.h"
#include "sockhelper.h"
#include "altservers.h"
#include "server.h"

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

// ##########################################

dnbd3_image_t *_images[SERVER_MAX_IMAGES];
int _num_images = 0;
pthread_spinlock_t _images_lock;

static pthread_mutex_t remoteCloneLock = PTHREAD_MUTEX_INITIALIZER;
#define NAMELEN  500
#define CACHELEN 100
typedef struct
{
	char name[NAMELEN];
	uint16_t rid;
	time_t deadline;
} imagecache;
static imagecache remoteCloneCache[CACHELEN];
static int remoteCloneCacheIndex = -1;

// ##########################################

static int image_isHashBlockComplete(uint8_t * const cacheMap, const uint64_t block, const uint64_t fileSize);
static int image_load_all_internal(char *base, char *path);
static int image_try_load(char *base, char *path, int withUplink);
static int64_t image_pad(const char *path, const int64_t currentSize);
static int image_clone(int sock, char *name, uint16_t revision, uint64_t imageSize);
static int image_ensureDiskSpace(uint64_t size);

// ##########################################

/**
 * Returns TRUE if the given image is complete
 */
int image_isComplete(dnbd3_image_t *image)
{
	assert( image != NULL );
	if ( image->working && image->cache_map == NULL ) {
		return TRUE;
	}
	if ( image->filesize == 0 ) {
		return FALSE;
	}
	int complete = TRUE, j;
	const int map_len_bytes = IMGSIZE_TO_MAPBYTES( image->filesize );
	for (j = 0; j < map_len_bytes - 1; ++j) {
		if ( image->cache_map[j] != 0xFF ) {
			complete = FALSE;
			break;
		}
	}
	if ( complete ) // Every block except the last one is complete
	{ // Last one might need extra treatment if it's not a full byte
		const int blocks_in_last_byte = (image->filesize >> 12) & 7;
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
void image_updateCachemap(dnbd3_image_t *image, uint64_t start, uint64_t end, const int set)
{
	assert( image != NULL );
	// This should always be block borders due to how the protocol works, but better be safe
	// than accidentally mark blocks as cached when they really aren't entirely cached.
	end &= ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
	start = (uint64_t)(start + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
	int dirty = FALSE;
	uint64_t pos = start;
	spin_lock( &image->lock );
	if ( image->cache_map == NULL ) {
		// Image seems already complete
		spin_unlock( &image->lock );
		printf( "[DEBUG] image_updateCachemap with no cache_map: %s", image->path );
		return;
	}
	while ( pos < end ) {
		const int map_y = pos >> 15;
		const int map_x = (pos >> 12) & 7; // mod 8
		const uint8_t bit_mask = 0b00000001 << map_x;
		if ( set ) {
			if ( (image->cache_map[map_y] & bit_mask) == 0 ) dirty = TRUE;
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
			if ( image_isHashBlockComplete( image->cache_map, block, image->filesize ) ) {
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
 * DOES NOT LOCK ON THE IMAGE, DO SO BEFORE CALLING
 */
void image_markComplete(dnbd3_image_t *image)
{
	assert( image != NULL );
	if ( image->cache_map == NULL ) return;
	free( image->cache_map );
	image->cache_map = NULL;
	char mapfile[strlen( image->path ) + 4 + 1];
	sprintf( mapfile, "%s.map", image->path );
	remove( mapfile );
}

/**
 * Saves the cache map of the given image.
 * Return TRUE on success.
 * Locks on: image.lock
 */
int image_saveCacheMap(dnbd3_image_t *image)
{
	if ( image == NULL || image->cache_map == NULL ) return TRUE;
	spin_lock( &image->lock );
	// Lock and get a copy of the cache map, as it could be freed by another thread that is just about to
	// figure out that this image's cache copy is complete
	if ( image->cache_map == NULL || image->filesize < DNBD3_BLOCK_SIZE ) {
		spin_unlock( &image->lock );
		return TRUE;
	}
	const size_t size = IMGSIZE_TO_MAPBYTES(image->filesize);
	uint8_t *map = malloc( size );
	memcpy( map, image->cache_map, size );
	// Unlock. Use path and cacheFd without locking. path should never change after initialization of the image,
	// cacheFd is written to and we don't hold a spinlock during I/O
	// By increasing the user count we make sure the image is not freed in the meantime
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
		return FALSE;
	}

	write( fd, map, size );
	if ( image->cacheFd != -1 ) {
		fsync( image->cacheFd );
	}
	fsync( fd );
	close( fd );
	free( map );

	spin_lock( &image->lock );
	image->users--;
	spin_unlock( &image->lock );
	return TRUE;
}

/**
 * Get an image by name+rid. This function increases a reference counter,
 * so you HAVE TO CALL image_release for every image_get() call at some
 * point...
 * Locks on: _images_lock, _images[].lock
 */
dnbd3_image_t* image_get(char *name, uint16_t revision)
{
	int i;
	dnbd3_image_t *candidate = NULL;
	// Simple sanity check
	const int len = strlen( name );
	if ( len == 0 || name[len - 1] == '/' || name[0] == '/' ) return NULL ;
	// Always use lowercase name
	strtolower( name );
	// Go through array
	spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		dnbd3_image_t * const image = _images[i];
		if ( image == NULL || strcmp( image->lower_name, name ) != 0 ) continue;
		if ( revision == image->rid ) {
			candidate = image;
			break;
		} else if ( revision == 0 && (candidate == NULL || candidate->rid < image->rid) ) {
			candidate = image;
		}
	}

	// Not found
	if ( candidate == NULL ) {
		spin_unlock( &_images_lock );
		return NULL ;
	}

	spin_lock( &candidate->lock );
	spin_unlock( &_images_lock );
	candidate->users++;
	spin_unlock( &candidate->lock );

	// Found, see if it works
	struct stat st;
	if ( candidate->working && stat( candidate->path, &st ) < 0 ) {
		// Either the image is already marked as "not working", or the file cannot be accessed
		printf( "[DEBUG] File '%s' has gone away...\n", candidate->path );
		candidate->working = FALSE; // No file? OUT!
	} else if ( !candidate->working && candidate->cache_map != NULL && candidate->uplink == NULL && file_isWritable( candidate->path ) ) {
		// Not working and has file + cache-map, try to init uplink (uplink_init will check if proxy mode is enabled)
		uplink_init( candidate, -1, NULL );
	} else if ( candidate->working && candidate->uplink != NULL && candidate->uplink->queueLen > SERVER_UPLINK_QUEUELEN_THRES ) {
		// To many pending uplink requests. We take that as a hint that the uplink is clogged or no working uplink server
		// exists, so "working" is changed to FALSE for now. Should a new uplink server be found the uplink thread will
		// set this back to TRUE some time.
		candidate->working = FALSE;
	}
	return candidate; // Success :-)
}

/**
 * Lock the image by increasing its users count
 * Returns the image on success, NULL if it is not found in the image list
 * Every call to image_lock() needs to be followed by a call to image_release() at some point.
 * Locks on: _images_lock, _images[].lock
 */
dnbd3_image_t* image_lock(dnbd3_image_t *image)
{
	if ( image == NULL ) return NULL ;
	int i;
	spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] == image ) {
			spin_lock( &image->lock );
			spin_unlock( &_images_lock );
			image->users++;
			spin_unlock( &image->lock );
			return image;
		}
	}
	spin_unlock( &_images_lock );
	return NULL ;
}

/**
 * Release given image. This will decrease the reference counter of the image.
 * If the usage counter reaches 0 and the image is not in the images array
 * anymore, the image will be freed
 * Locks on: _images_lock, _images[].lock
 */
void image_release(dnbd3_image_t *image)
{
	assert( image != NULL );
	spin_lock( &image->lock );
	assert( image->users > 0 );
	image->users--;
	if ( image->users > 0 ) { // Still in use, do nothing
		spin_unlock( &image->lock );
		return;
	}
	spin_unlock( &image->lock );
	spin_lock( &_images_lock );
	spin_lock( &image->lock );
	// Check active users again as we unlocked
	if ( image->users == 0 ) {
		// Not in use anymore, see if it's in the images array
		for (int i = 0; i < _num_images; ++i) {
			if ( _images[i] == image ) { // Found, do nothing
				spin_unlock( &image->lock );
				spin_unlock( &_images_lock );
				return;
			}
		}
	}
	// Not found, free
	spin_unlock( &image->lock );
	spin_unlock( &_images_lock );
}

/**
 * Remove image from images array. Only free it if it has
 * no active users
 * Locks on: _images_lock, image[].lock
 */
void image_remove(dnbd3_image_t *image)
{
	spin_lock( &_images_lock );
	spin_lock( &image->lock );
	for (int i = _num_images - 1; i >= 0; --i) {
		if ( _images[i] != image ) continue;
		_images[i] = NULL;
		if ( i + 1 == _num_images ) _num_images--;
	}
	spin_unlock( &image->lock );
	if ( image->users <= 0 ) image = image_free( image );
	spin_unlock( &_images_lock );
}

/**
 * Kill all uplinks
 */
void image_killUplinks()
{
	int i;
	spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] == NULL ) continue;
		spin_lock( &_images[i]->lock );
		if ( _images[i]->uplink != NULL ) {
			_images[i]->uplink->shutdown = TRUE;
			if ( _images[i]->uplink->signal != -1 ) {
				write( _images[i]->uplink->signal, "", 1 );
			}
		}
		spin_unlock( &_images[i]->lock );
	}
	spin_unlock( &_images_lock );
}

/**
 * Free image. DOES NOT check if it's in use.
 * Indirectly locks on image.lock, uplink.queueLock
 * DO NOT lock on the image when calling.
 */
dnbd3_image_t* image_free(dnbd3_image_t *image)
{
	assert( image != NULL );
	//
	image_saveCacheMap( image );
	uplink_shutdown( image );
	free( image->cache_map );
	free( image->crc32 );
	free( image->path );
	free( image->lower_name );
	if ( image->cacheFd != -1 ) close( image->cacheFd );
	spin_destroy( &image->lock );
	//
	memset( image, 0, sizeof(dnbd3_image_t) );
	free( image );
	return NULL ;
}

/**
 * Load all images in given path recursively.
 * Pass NULL to use path from config.
 */
int image_loadAll(char *path)
{
	if ( path == NULL ) {
		return image_load_all_internal( _basePath, _basePath );
	}
	return image_load_all_internal( path, path );
}

static int image_isHashBlockComplete(uint8_t * const cacheMap, const uint64_t block, const uint64_t fileSize)
{
	if ( cacheMap == NULL ) return TRUE;
	const uint64_t end = (block + 1) * HASH_BLOCK_SIZE;
	if ( end <= fileSize ) {
		for (uint64_t mapPos = block * HASH_BLOCK_SIZE; mapPos < end; mapPos += (DNBD3_BLOCK_SIZE * 8)) {
			if ( cacheMap[mapPos / (DNBD3_BLOCK_SIZE * 8)] != 0xff ) {
				return FALSE;
			}
		}
	} else {
		for (uint64_t mapPos = block * HASH_BLOCK_SIZE; mapPos < fileSize; mapPos += DNBD3_BLOCK_SIZE ) {
			const int map_y = mapPos >> 15;
			const int map_x = (mapPos >> 12) & 7; // mod 8
			const int mask = 1 << map_x;
			if ( (cacheMap[map_y] & mask) == 0 ) return FALSE;
		}
	}
	return TRUE;
}

/**
 * Load all images in the given path recursively,
 * consider bash the base path that is to be cut off
 */
static int image_load_all_internal(char *base, char *path)
{
#define SUBDIR_LEN 120
	assert( path != NULL );
	assert( *path == '/' );
	struct dirent *entry;
	DIR *dir = opendir( path );
	if ( dir == NULL ) {
		memlogf( "[ERROR] Could not opendir '%s' for loading", path );
		return FALSE;
	}
	const int pathLen = strlen( path );
	const int len = pathLen + SUBDIR_LEN + 1;
	char subpath[len];
	struct stat st;
	while ( (entry = readdir( dir )) != NULL ) {
		if ( strcmp( entry->d_name, "." ) == 0 || strcmp( entry->d_name, ".." ) == 0 ) continue;
		if ( strlen( entry->d_name ) > SUBDIR_LEN ) {
			memlogf( "[WARNING] Skipping entry %s: Too long (max %d bytes)", entry->d_name, (int)SUBDIR_LEN );
			continue;
		}
		if ( entry->d_name[0] == '/' || path[pathLen - 1] == '/' ) {
			snprintf( subpath, len, "%s%s", path, entry->d_name );
		} else {
			snprintf( subpath, len, "%s/%s", path, entry->d_name );
		}
		if ( stat( subpath, &st ) < 0 ) {
			memlogf( "[WARNING] stat() for '%s' failed. Ignoring....", subpath );
			continue;
		}
		if ( S_ISDIR( st.st_mode )) {
			image_load_all_internal( base, subpath ); // Recurse
		} else {
			image_try_load( base, subpath, TRUE ); // Load image if possible
		}
	}
	closedir( dir );
	return TRUE;
#undef SUBDIR_LEN
}

static int image_try_load(char *base, char *path, int withUplink)
{
	int i, revision;
	struct stat st;
	uint8_t *cache_map = NULL;
	uint32_t *crc32list = NULL;
	dnbd3_image_t *existing = NULL;
	int fdImage = -1;
	int function_return = FALSE;
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
	char * const virtBase = path + strlen( base ) + 1;
	// Copy virtual path
	assert( *virtBase != '/' );
	char *src = virtBase, *dst = imgName;
	while ( src <= lastSlash ) {
		*dst++ = *src++;
	}
	*dst = '\0';
	if ( _vmdkLegacyMode && strend( fileName, ".vmdk" ) ) {
		// Easy - legacy mode, simply append full file name and set rid to 1
		strcat( dst, fileName );
		revision = 1;
	} else {
		// Try to parse *.r<ID> syntax
		for (i = fileNameLen - 1; i > 1; --i) {
			if ( fileName[i] < '0' || fileName[i] > '9' ) break;
		}
		if ( i == fileNameLen - 1 ) return FALSE;
		if ( fileName[i] != 'r' ) return FALSE;
		if ( fileName[i - 1] != '.' ) return FALSE;
		revision = atoi( fileName + i + 1 );
		src = fileName;
		while ( src < fileName + i - 1 ) {
			*dst++ = *src++;
		}
		*dst = '\0';
	}
	char mapFile[strlen( path ) + 10 + 1];
	char hashFile[strlen( path ) + 10 + 1];
	if ( revision <= 0 ) {
		memlogf( "[WARNING] Image '%s' has invalid revision ID %d", path, revision );
		goto load_error;
	}
	strtolower( imgName );
	// Get pointer to already existing image if possible
	existing = image_get( imgName, revision );
	// ### Now load the actual image related data ###
	fdImage = open( path, O_RDONLY );
	if ( fdImage < 0 ) {
		memlogf( "[ERROR] Could not open '%s' for reading...", path );
		goto load_error;
	}
	int64_t fileSize = lseek( fdImage, 0, SEEK_END );
	if ( fileSize < 0 ) {
		memlogf( "[ERROR] Could not seek to end of file '%s'", path );
		goto load_error;
	}
	if ( fileSize == 0 ) {
		memlogf( "[WARNING] Empty image file '%s'", path );
		goto load_error;
	}
	if ( fileSize % DNBD3_BLOCK_SIZE != 0 ) {
		memlogf( "[INFO] Image size of '%s' is not a multiple of %d, fixing...", path, (int)DNBD3_BLOCK_SIZE );
		fileSize = image_pad( path, fileSize );
		if ( fileSize == 0 ) goto load_error;
	}
	// 1. Allocate memory for the cache map if the image is incomplete
	sprintf( mapFile, "%s.map", path );
	int fdMap = open( mapFile, O_RDONLY );
	if ( fdMap >= 0 ) {
		size_t map_size = IMGSIZE_TO_MAPBYTES( fileSize );
		cache_map = calloc( 1, map_size );
		int rd = read( fdMap, cache_map, map_size );
		if ( map_size != rd ) {
			memlogf( "[WARNING] Could only read %d of expected %d bytes of cache map of '%s'", (int)rd, (int)map_size, path );
		}
		close( fdMap );
		// Later on we check if the hash map says the image is complete
	}
	// TODO: Maybe try sha-256 or 512 first if you're paranoid (to be implemented)
	const int hashBlocks = IMGSIZE_TO_HASHBLOCKS( fileSize );
	// Currently this should only prevent accidental corruption (esp. regarding transparent proxy mode)
	// but maybe later on you want better security
	// 2. Load CRC-32 list of image
	sprintf( hashFile, "%s.crc", path );
	uint32_t masterCrc;
	int fdHash = open( hashFile, O_RDONLY );
	if ( fdHash >= 0 ) {
		off_t fs = lseek( fdHash, 0, SEEK_END );
		if ( fs < (hashBlocks + 1) * 4 ) {
			memlogf( "[WARNING] Ignoring crc32 list for '%s' as it is too short", path );
		} else {
			if ( 0 != lseek( fdHash, 0, SEEK_SET ) ) {
				memlogf( "[WARNING] Could not seek back to beginning of '%s'", hashFile );
			} else {
				if ( read( fdHash, &masterCrc, sizeof(masterCrc) ) != 4 ) {
					memlogf( "[WARNING] Error reading first crc32 of '%s'", path );
				} else {
					crc32list = calloc( hashBlocks, sizeof(uint32_t) );
					if ( read( fdHash, crc32list, hashBlocks * sizeof(uint32_t) ) != hashBlocks * sizeof(uint32_t) ) {
						free( crc32list );
						crc32list = NULL;
						memlogf( "[WARNING] Could not read crc32 list of '%s'", path );
					} else {
						uint32_t lists_crc = crc32( 0L, Z_NULL, 0 );
						lists_crc = crc32( lists_crc, (Bytef*)crc32list, hashBlocks * sizeof(uint32_t) );
						if ( lists_crc != masterCrc ) {
							free( crc32list );
							crc32list = NULL;
							memlogf( "[WARNING] CRC-32 of CRC-32 list mismatch. CRC-32 list of '%s' might be corrupted.", path );
						}
					}
				}
			}
		}
		close( fdHash );
	}
	// Check CRC32
	if ( crc32list != NULL ) {
		// This checks the first block and two random blocks (which might accidentally be the same)
		// for corruption via the known crc32 list. This is very sloppy and is merely supposed
		// to detect accidental corruption due to broken dnbd3-proxy functionality or file system
		// corruption.
		int blocks[4], index = 0, block; // = { 0, rand() % blcks, rand() % blcks, -1 };
		if ( image_isHashBlockComplete( cache_map, 0, fileSize ) ) blocks[index++] = 0;
		block = rand() % hashBlocks;
		if ( image_isHashBlockComplete( cache_map, block, fileSize ) ) blocks[index++] = block;
		block = rand() % hashBlocks;
		if ( image_isHashBlockComplete( cache_map, block, fileSize ) ) blocks[index++] = block;
		blocks[index] = -1;
		if ( !image_checkBlocksCrc32( fdImage, crc32list, blocks, fileSize ) ) {
			memlogf( "[ERROR] Quick integrity check for '%s' failed.", path );
			goto load_error;
		}
	}
	// Compare to existing image
	if ( existing != NULL ) {
		if ( existing->filesize != fileSize ) {
			memlogf( "[WARNING] Size of image '%s' has changed.", path );
		} else if ( existing->crc32 != NULL && crc32list != NULL
		        && memcmp( existing->crc32, crc32list, sizeof(uint32_t) * hashBlocks ) != 0 ) {
			memlogf( "[WARNING] CRC32 list of image '%s' has changed.", path );
		} else if ( existing->crc32 == NULL && crc32list != NULL ) {
			memlogf( "[INFO] Found CRC-32 list for already loaded image, adding...", path );
			existing->crc32 = crc32list;
			existing->masterCrc32 = masterCrc;
			crc32list = NULL;
			function_return = TRUE;
			goto load_error;
		} else { // Nothing changed about the existing image, so do nothing
			function_return = TRUE;
			goto load_error;
		}
		// Remove image from images array
		image_release( existing );
		image_remove( existing );
		existing = NULL;
	}
	// Load fresh image
	dnbd3_image_t *image = calloc( 1, sizeof(dnbd3_image_t) );
	image->path = strdup( path );
	image->lower_name = strdup( imgName );
	image->cache_map = cache_map;
	image->crc32 = crc32list;
	image->masterCrc32 = masterCrc;
	image->uplink = NULL;
	image->filesize = fileSize;
	image->rid = revision;
	image->users = 0;
	image->cacheFd = -1;
	if ( stat( path, &st ) == 0 ) {
		image->atime = st.st_mtime;
	} else {
		image->atime = time( NULL );
	}
	image->working = (image->cache_map == NULL );
	spin_init( &image->lock, PTHREAD_PROCESS_PRIVATE );
	// Get rid of cache map if image is complete
	if ( image->cache_map != NULL && image_isComplete( image ) ) {
		image_markComplete( image );
		image->working = TRUE;
	}
	if ( image->cache_map != NULL ) {
		image->working = FALSE;
		image->cacheFd = open( path, O_WRONLY );
		if ( image->cacheFd < 0 ) {
			image->cacheFd = -1;
			memlogf( "[ERROR] Could not open incomplete image %s for writing!", path );
			image = image_free( image );
			goto load_error;
		}
		if ( withUplink ) {
			uplink_init( image, -1, NULL );
		}
	}
	// Prevent freeing in cleanup
	cache_map = NULL;
	crc32list = NULL;
	// Add to images array
	spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] != NULL ) continue;
		_images[i] = image;
		break;
	}
	if ( i >= _num_images ) {
		if ( _num_images >= SERVER_MAX_IMAGES ) {
			memlogf( "[ERROR] Cannot load image '%s': maximum number of images reached.", path );
			spin_unlock( &_images_lock );
			image = image_free( image );
			goto load_error;
		}
		_images[_num_images++] = image;
		printf( "[DEBUG] Loaded image '%s'\n", image->lower_name );
	}
	spin_unlock( &_images_lock );
	function_return = TRUE;
	// Clean exit:
	load_error: ;
	if ( existing != NULL ) image_release( existing );
	if ( crc32list != NULL ) free( crc32list );
	if ( cache_map != NULL ) free( cache_map );
	if ( fdImage != -1 ) close( fdImage );
	return function_return;
}

/**
 * Create a new image with the given image name and revision id in _basePath
 * Returns TRUE on success, FALSE otherwise
 */
int image_create(char *image, int revision, uint64_t size)
{
	assert( image != NULL );
	assert( size >= DNBD3_BLOCK_SIZE );
	if ( revision <= 0 ) {
		memlogf( "[ERROR] revision id invalid: %d", revision );
		return FALSE;
	}
	const int PATHLEN = 2000;
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
	if ( file_isReadable( path ) ) {
		memlogf( "[ERROR] Image %s with rid %d already exists!", image, revision );
		return FALSE;
	}
	snprintf( cache, PATHLEN, "%s.map", path );
	size = (size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
	const int mapsize = IMGSIZE_TO_MAPBYTES(size);
	// Write files
	int fdImage = -1, fdCache = -1;
	fdImage = open( path, O_RDWR | O_TRUNC | O_CREAT, 0644 );
	fdCache = open( cache, O_RDWR | O_TRUNC | O_CREAT, 0644 );
	if ( fdImage < 0 ) {
		memlogf( "[ERROR] Could not open %s for writing.", path );
		goto failure_cleanup;
	}
	if ( fdCache < 0 ) {
		memlogf( "[ERROR] Could not open %s for writing.", cache );
		goto failure_cleanup;
	}
	// Try cache map first
	if ( !file_alloc( fdCache, 0, mapsize ) ) {
		const int err = errno;
		memlogf( "[ERROR] Could not allocate %d bytes for %s (errno=%d)", mapsize, cache, err );
		goto failure_cleanup;
	}
	// Now write image
	if ( !file_alloc( fdImage, 0, size ) ) {
		const int err = errno;
		memlogf( "[ERROR] Could not allocate %" PRIu64 " bytes for %s (errno=%d)", size, path, err );
		goto failure_cleanup;
	}
	close( fdImage );
	close( fdCache );
	return TRUE;
	//
	failure_cleanup: ;
	if ( fdImage >= 0 ) close( fdImage );
	if ( fdCache >= 0 ) close( fdCache );
	remove( path );
	remove( cache );
	return FALSE;
}

/**
 * Does the same as image_get, but if the image is not found locally,
 * it will try to clone it from an authoritative dnbd3 server and return the
 * image. If the return value is not NULL, image_release needs to be called
 * on the image at some point.
 * Locks on: remoteCloneLock, _images_lock, _images[].lock
 */
dnbd3_image_t* image_getOrClone(char *name, uint16_t revision)
{
	if ( !_isProxy ) return image_get( name, revision );
	int i;
	const size_t len = strlen( name );
	// Sanity check
	if ( len == 0 || name[len - 1] == '/' || name[0] == '/' ) return NULL ;
	// Already existing locally?
	dnbd3_image_t *image = image_get( name, revision );
	if ( image != NULL ) return image;
	// Doesn't exist, try remote if not already tried it recently
	if ( remoteCloneCacheIndex == -1 ) {
		remoteCloneCacheIndex = 0;
		memset( remoteCloneCache, 0, sizeof(remoteCloneCache) );
	}
	const time_t now = time( NULL );

	char *cmpname = name;
	if ( len >= NAMELEN ) cmpname += 1 + len - NAMELEN;
	pthread_mutex_lock( &remoteCloneLock );
	for (i = 0; i < CACHELEN; ++i) {
		if ( remoteCloneCache[i].rid != revision
		        || remoteCloneCache[i].deadline < now
		        || strcmp( cmpname, remoteCloneCache[i].name ) != 0 ) continue;
		pthread_mutex_unlock( &remoteCloneLock ); // Was recently checked...
		return image_get( name, revision );
	}
	// Re-check to prevent two clients at the same time triggering this
	image = image_get( name, revision );
	if ( image != NULL ) {
		pthread_mutex_unlock( &remoteCloneLock );
		return image;
	}
	// Reaching this point means we should contact an authority server
	serialized_buffer_t serialized;
	// Mark as recently checked
	remoteCloneCacheIndex = (remoteCloneCacheIndex + 1) % CACHELEN;
	remoteCloneCache[remoteCloneCacheIndex].deadline = now + SERVER_REMOTE_IMAGE_CHECK_CACHETIME;
	snprintf( remoteCloneCache[remoteCloneCacheIndex].name, NAMELEN, "%s", cmpname );
	remoteCloneCache[remoteCloneCacheIndex].rid = revision;
	// Get some alt servers and try to get the image from there
	dnbd3_host_t servers[4];
	int uplinkSock = -1;
	dnbd3_host_t *uplinkServer = NULL;
	const int count = altservers_get( servers, 4 );
	uint16_t remoteVersion, remoteRid;
	uint64_t remoteImageSize;
	for (i = 0; i < count; ++i) {
		int sock = sock_connect( &servers[i], 750, _uplinkTimeout );
		if ( sock < 0 ) continue;
		if ( !dnbd3_select_image( sock, name, revision, FLAGS8_SERVER ) ) goto server_fail;
		char *remoteName;
		if ( !dnbd3_select_image_reply( &serialized, sock, &remoteVersion, &remoteName, &remoteRid, &remoteImageSize ) ) goto server_fail;
		if ( remoteVersion < MIN_SUPPORTED_SERVER ) goto server_fail;
		if ( revision != 0 && remoteRid != revision ) goto server_fail;
		if ( remoteImageSize < DNBD3_BLOCK_SIZE || remoteName == NULL || strcmp( name, remoteName ) != 0 ) goto server_fail;
		if ( remoteImageSize > SERVER_MAX_PROXY_IMAGE_SIZE ) goto server_fail;
		if ( !image_ensureDiskSpace( remoteImageSize ) ) goto server_fail;
		if ( !image_clone( sock, name, remoteRid, remoteImageSize ) ) goto server_fail;
		// Cloning worked :-)
		uplinkSock = sock;
		uplinkServer = &servers[i];
		break;
		server_fail: ;
		close( sock );
	}
	pthread_mutex_unlock( &remoteCloneLock );
	// If everything worked out, this call should now actually return the image
	image = image_get( name, remoteRid );
	if ( image != NULL && uplinkSock != -1 && uplinkServer != NULL ) {
		// If so, init the uplink and pass it the socket
		uplink_init( image, uplinkSock, uplinkServer );
		image->working = TRUE;
	} else if ( uplinkSock >= 0 ) {
		close( uplinkSock );
	}
	return image;
}

/**
 * Prepare a cloned image:
 * 1. Allocate empty image file and its cache map
 * 2. Use passed socket to request the crc32 list and save it to disk
 * 3. Load the image from disk
 * Returns: TRUE on success, FALSE otherwise
 */
static int image_clone(int sock, char *name, uint16_t revision, uint64_t imageSize)
{
	// Allocate disk space and create cache map
	if ( !image_create( name, revision, imageSize ) ) return FALSE;
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
			return FALSE;
		}
		if ( crc32len != 0 ) {
			uint32_t lists_crc = crc32( 0L, Z_NULL, 0 );
			lists_crc = crc32( lists_crc, (Bytef*)crc32list, crc32len );
			if ( lists_crc != masterCrc ) {
				memlogf( "[WARNING] OTF-Clone: Corrupted CRC-32 list. ignored. (%s)", name );
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
	return image_try_load( _basePath, crcFile, FALSE );
}

/**
 * Generate the crc32 block list file for the given file.
 * This function wants a plain file name instead of a dnbd3_image_t,
 * as it can be used directly from the command line.
 */
int image_generateCrcFile(char *image)
{
	int fdImage = open( image, O_RDONLY );
	if ( fdImage < 0 ) {
		printf( "Could not open %s.\n", image );
		return FALSE;
	}
// force size to be multiple of DNBD3_BLOCK_SIZE
	int64_t fileLen = lseek( fdImage, 0, SEEK_END );
	if ( fileLen <= 0 ) {
		printf( "Error seeking to end, or file is empty.\n" );
		close( fdImage );
		return FALSE;
	}
	if ( fileLen % DNBD3_BLOCK_SIZE != 0 ) {
		printf( "File length is not a multiple of DNBD3_BLOCK_SIZE\n" );
		const int64_t ret = image_pad( image, fileLen );
		if ( ret < fileLen ) {
			printf( "Error appending to file in order to make it block aligned.\n" );
			close( fdImage );
			return FALSE;
		}
		printf( "...fixed!\n" );
		fileLen = ret;
	}
	if ( lseek( fdImage, 0, SEEK_SET ) != 0 ) {
		printf( "Seeking back to start failed.\n" );
		close( fdImage );
		return FALSE;
	}
	char crcFile[strlen( image ) + 4 + 1];
	sprintf( crcFile, "%s.crc", image );
	struct stat sst;
	if ( stat( crcFile, &sst ) == 0 ) {
		printf( "CRC File for %s already exists! Delete it first if you want to regen.\n", image );
		close( fdImage );
		return FALSE;
	}
	int fdCrc = open( crcFile, O_RDWR | O_CREAT, 0644 );
	if ( fdCrc < 0 ) {
		printf( "Could not open CRC File %s for writing..\n", crcFile );
		close( fdImage );
		return FALSE;
	}
	// CRC of all CRCs goes first. Don't know it yet, write 4 bytes dummy data.
	if ( write( fdCrc, crcFile, 4 ) != 4 ) {
		printf( "Write error\n" );
		close( fdImage );
		close( fdCrc );
		return FALSE;
	}
	char buffer[80000]; // Read buffer from image
	int finished = FALSE; // end of file reached
	int hasSum; // unwritten (unfinished?) crc32 exists
	int blocksToGo = 0; // Count number of checksums written
	printf( "Generating CRC32" );
	fflush( stdout );
	do {
		// Start of a block - init
		uint32_t crc = crc32( 0L, Z_NULL, 0 );
		int remaining = HASH_BLOCK_SIZE;
		hasSum = FALSE;
		while ( remaining > 0 ) {
			const int blockSize = MIN(remaining, sizeof(buffer));
			const int ret = read( fdImage, buffer, blockSize );
			if ( ret < 0 ) { // Error
				printf( "Read error\n" );
				close( fdImage );
				close( fdCrc );
				return FALSE;
			} else if ( ret == 0 ) { // EOF
				finished = TRUE;
				break;
			} else { // Read something
				hasSum = TRUE;
				crc = crc32( crc, (Bytef*)buffer, ret );
				remaining -= ret;
			}
		}
		// Write to file
		if ( hasSum ) {
			if ( write( fdCrc, &crc, 4 ) != 4 ) {
				printf( "Write error\n" );
				close( fdImage );
				close( fdCrc );
				return FALSE;
			}
			printf( "." );
			fflush( stdout );
			blocksToGo++;
		}
	} while ( !finished );
	close( fdImage );
	printf( "done!\nGenerating master-crc..." );
	fflush( stdout );
	// File is written - read again to calc master crc
	if ( lseek( fdCrc, 4, SEEK_SET ) != 4 ) {
		printf( "Could not seek to beginning of crc list in file\n" );
		close( fdCrc );
		return FALSE;
	}
	uint32_t crc = crc32( 0L, Z_NULL, 0 );
	while ( blocksToGo > 0 ) {
		const int numBlocks = MIN(1000, blocksToGo);
		if ( read( fdCrc, buffer, numBlocks * 4 ) != numBlocks * 4 ) {
			printf( "Could not re-read from crc32 file\n" );
			close( fdCrc );
			return FALSE;
		}
		crc = crc32( crc, (Bytef*)buffer, numBlocks * 4 );
		blocksToGo -= numBlocks;
	}
	if ( lseek( fdCrc, 0, SEEK_SET ) != 0 ) {
		printf( "Could not seek back to beginning of crc32 file\n" );
		close( fdCrc );
		return FALSE;
	}
	if ( write( fdCrc, &crc, 4 ) != 4 ) {
		printf( "Could not write master crc to file\n" );
		close( fdCrc );
		return FALSE;
	}
	printf( "..done!\nCRC-32 file successfully generated.\n" );
	fflush( stdout );
	return TRUE;
}

void image_printAll()
{
	int i, percent, pending, j;
	char buffer[100] = { 0 };
	spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] == NULL ) continue;
		spin_lock( &_images[i]->lock );
		printf( "Image: %s\n", _images[i]->lower_name );
		percent = image_getCompletenessEstimate( _images[i] );
		printf( "  Complete: %d%%\n", percent );
		if ( _images[i]->uplink != NULL ) {
			host_to_string( &_images[i]->uplink->currentServer, buffer, sizeof(buffer) );
			pending = 0;
			spin_lock( &_images[i]->uplink->queueLock );
			for (j = 0; j < _images[i]->uplink->queueLen; ++j) {
				if ( _images[i]->uplink->queue[j].status != ULR_FREE ) pending++;
			}
			spin_unlock( &_images[i]->uplink->queueLock );
			printf( "  Uplink: %s -- %d pending requests\n", buffer, pending );
		}
		printf( "  Users: %d\n", _images[i]->users );
		spin_unlock( &_images[i]->lock );
	}
	spin_unlock( &_images_lock );
}

/**
 * Get completeness of an image in percent. Only estimated, not exact.
 * Returns: 0-100
 * DOES NOT LOCK, so make sure to do so before calling
 */
int image_getCompletenessEstimate(const dnbd3_image_t * const image)
{
	assert( image != NULL );
	if ( image->cache_map == NULL ) return image->working ? 100 : 0;
	int i;
	int percent = 0;
	const size_t len = IMGSIZE_TO_MAPBYTES(image->filesize);
	if ( len == 0 ) return 0;
	for (i = 0; i < len; ++i) {
		if ( image->cache_map[i] == 0xff ) {
			percent += 100;
		} else if ( image->cache_map[i] > 0 ) {
			percent += 50;
		}
	}
	return percent / len;
}

/**
 * Check the CRC-32 of the given blocks. The array blocks is of variable length.
 * !! pass -1 as the last block so the function knows when to stop !!
 * Returns TRUE or FALSE
 */
int image_checkBlocksCrc32(int fd, uint32_t *crc32list, const int *blocks, const uint64_t fileSize)
{
	char buffer[40000];
	while ( *blocks != -1 ) {
		if ( lseek( fd, (int64_t)*blocks * HASH_BLOCK_SIZE, SEEK_SET ) != (int64_t)*blocks * HASH_BLOCK_SIZE ) {
			memlogf( "Seek error" );
			return FALSE;
		}
		uint32_t crc = crc32( 0L, Z_NULL, 0 );
		int bytes = 0;
		const int bytesToGo = MIN(HASH_BLOCK_SIZE, fileSize - ((int64_t)*blocks * HASH_BLOCK_SIZE));
		while ( bytes < bytesToGo ) {
			const int n = MIN(sizeof(buffer), bytesToGo - bytes);
			const int r = read( fd, buffer, n );
			if ( r <= 0 ) {
				memlogf( "Read error" );
				return FALSE;
			}
			crc = crc32( crc, (Bytef*)buffer, r );
			bytes += r;
		}
		if ( crc != crc32list[*blocks] ) {
			printf( "Block %d is %x, should be %x\n", *blocks, crc, crc32list[*blocks] );
			return FALSE;
		}
		blocks++;
	}
	return TRUE;
}

static int64_t image_pad(const char *path, const int64_t currentSize)
{
	const int missing = DNBD3_BLOCK_SIZE - (currentSize % DNBD3_BLOCK_SIZE );
	char buffer[missing];
	memset( buffer, 0, missing );
	int tmpFd = open( path, O_WRONLY | O_APPEND );
	int success = FALSE;
	if ( tmpFd < 0 ) {
		memlogf( "[WARNING] Can't open image for writing, can't fix %s", path );
	} else if ( lseek( tmpFd, currentSize, SEEK_SET ) != currentSize ) {
		memlogf( "[WARNING] lseek() failed, can't fix %s", path );
	} else if ( write( tmpFd, buffer, missing ) != missing ) {
		memlogf( "[WARNING] write() failed, can't fix %s", path );
	} else {
		success = TRUE;
	}
	if ( tmpFd >= 0 ) close( tmpFd );
	if ( success ) {
		return currentSize + missing;
	} else {
		return 0;
	}
}

/**
 * Make sure at least size bytes are available in _basePath.
 * Will delete old images to make room for new ones.
 * TODO: Store last access time of images. Currently the
 * last access time is reset on server restart. Thus it will
 * currently only delete images if server uptime is > 10 hours
 * Return TRUE iff enough space is available. FALSE in random other cases
 */
static int image_ensureDiskSpace(uint64_t size)
{
	for (;;) {
		const uint64_t available = file_freeDiskSpace( _basePath );
		if ( available > size ) return TRUE;
		if ( dnbd3_serverUptime() < 10 * 3600 ) {
			memlogf( "[INFO] Only %dMiB free, %dMiB requested, but server uptime < 10 hours...", (int)(available / (1024 * 1024)),
			        (int)(size / (1024 * 1024)) );
			return FALSE;
		}
		memlogf( "[INFO] Only %dMiB free, %dMiB requested, freeing an image...", (int)(available / (1024 * 1024)),
		        (int)(size / (1024 * 1024)) );
		// Find least recently used image
		dnbd3_image_t *oldest = NULL;
		time_t mtime = 0;
		int i;
		spin_lock( &_images_lock );
		for (i = 0; i < _num_images; ++i) {
			if ( _images[i] == NULL ) continue;
			dnbd3_image_t *current = image_lock( _images[i] );
			if ( current == NULL ) continue;
			if ( current->users == 1 ) { // Just from the lock above
				if ( oldest == NULL || oldest->atime > _images[i]->atime ) {
					// Oldest access time so far
					oldest = _images[i];
					if ( oldest->atime == 0 ) mtime = file_lastModification( oldest->path );
				} else if ( oldest->atime == 0 && _images[i]->atime == 0 ) {
					// Oldest access time is 0 (=never used since server startup), so take file modification time into account
					const time_t m = file_lastModification( _images[i]->path );
					if ( m < mtime ) {
						mtime = m;
						oldest = _images[i];
					}
				}
			}
			image_release( current );
		}
		spin_unlock( &_images_lock );
		if ( oldest == NULL ) return FALSE;
		oldest = image_lock( oldest );
		if ( oldest == NULL ) return FALSE;
		memlogf( "[INFO] '%s' has to go!", oldest->lower_name );
		unlink( oldest->path );
		image_remove( oldest );
		image_release( oldest );
	}
	return FALSE;
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
