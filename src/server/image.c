#include "image.h"
#include "helper.h"
#include "memlog.h"
#include "uplink.h"

#include <glib/gmacros.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <zlib.h>

// ##########################################

dnbd3_image_t *_images[SERVER_MAX_IMAGES];
int _num_images = 0;
pthread_spinlock_t _images_lock;

// ##########################################

static int image_load_all_internal(char *base, char *path);
static int image_try_load(char *base, char *path);
static int image_check_blocks_crc32(int fd, uint32_t *crc32list, int *blocks);
static dnbd3_image_t* image_free(dnbd3_image_t *image);

// ##########################################

/**
 * Returns TRUE if the given image is complete
 */
int image_is_complete(dnbd3_image_t *image)
{
	assert( image != NULL );
	if ( image->working && image->cache_map == NULL ) {
		return TRUE;
	}
	if ( image->filesize == 0 || !image->working ) {
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
 * Saves the cache map of the given image.
 * Return TRUE on success.
 */
int image_save_cache_map(dnbd3_image_t *image)
{
	if ( image == NULL ) return TRUE;
	char mapfile[strlen( image->path ) + 4 + 1];
	int fd;
	strcpy( mapfile, image->path );
	strcat( mapfile, ".map" );

	fd = open( mapfile, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR );
	if ( fd < 0 ) return FALSE;

	write( fd, image->cache_map, ((image->filesize + (1 << 15) - 1) >> 15) * sizeof(char) );
	close( fd );

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
	pthread_spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		dnbd3_image_t * const image = _images[i];
		if ( image == NULL ) continue;
		if ( strcmp( image->lower_name, name ) == 0 && revision == image->rid ) {
			candidate = image;
			break;
		} else if ( revision == 0 && (candidate == NULL || candidate->rid < image->rid) ) {
			candidate = image;
		}
	}

	if ( candidate == NULL ) {
		pthread_spin_unlock( &_images_lock );
		return NULL ;
	}

	pthread_spin_lock( &candidate->lock );
	pthread_spin_unlock( &_images_lock );

	if ( candidate == NULL ) return NULL ; // Not found
	// Found, see if it works
	struct stat st;
	if ( !candidate->working || stat( candidate->path, &st ) < 0 ) {
		candidate->working = FALSE;
		pthread_spin_unlock( &candidate->lock );
		return NULL ; // Not working (anymore)
	}
	candidate->users++;
	pthread_spin_unlock( &candidate->lock );
	return candidate; // Success :-)
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
	pthread_spin_lock( &image->lock );
	assert( image->users > 0 );
	image->users--;
	if ( image->users > 0 ) { // Still in use, do nothing
		pthread_spin_unlock( &image->lock );
		return;
	}
	pthread_spin_unlock( &image->lock );
	pthread_spin_lock( &_images_lock );
	pthread_spin_lock( &image->lock );
	// Check active users again as we unlocked
	if ( image->users == 0 ) {
		// Not in use anymore, see if it's in the images array
		for (int i = 0; i < _num_images; ++i) {
			if ( _images[i] == image ) { // Found, do nothing
				pthread_spin_unlock( &image->lock );
				pthread_spin_unlock( &_images_lock );
				return;
			}
		}
	}
	// Not found, free
	pthread_spin_unlock( &image->lock );
	pthread_spin_unlock( &_images_lock );
	image_free( image );
}

/**
 * Remove image from images array. Only free it if it has
 * no active users
 */
void image_remove(dnbd3_image_t *image)
{
	pthread_spin_lock( &_images_lock );
	pthread_spin_lock( &image->lock );
	for (int i = _num_images - 1; i >= 0; --i) {
		if ( _images[i] != image ) continue;
		_images[i] = NULL;
		if ( i + 1 == _num_images ) _num_images--;
	}
	pthread_spin_unlock( &image->lock );
	if ( image->users <= 0 ) image = image_free( image );
	pthread_spin_unlock( &_images_lock );
}

/**
 * Load all images in given path recursively.
 * Pass NULL to use path from config.
 */
int image_load_all(char *path)
{
	if ( path == NULL ) {
		return image_load_all_internal( _basePath, _basePath );
	}
	return image_load_all_internal( path, path );
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
			image_try_load( base, subpath ); // Load image if possible
		}
	}
	closedir( dir );
	return TRUE;
#undef SUBDIR_LEN
}

static int image_try_load(char *base, char *path)
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
	assert( base[strlen(base) - 1] == '/' );
	char *lastSlash = strrchr( path, '/' );
	char *fileName = lastSlash + 1;
	char imgName[strlen( path )];
	const int fileNameLen = strlen( fileName );
	char * const virtBase = path + strlen( base );
	// Copy virtual path
	assert( *virtBase != '/' );
	char *src = virtBase, *dst = imgName;
	while ( src < lastSlash ) {
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
	// 1. Allocate memory for the cache map if the image is incomplete
	sprintf( mapFile, "%s.map", path );
	int fdMap = open( path, O_RDONLY );
	if ( fdMap >= 0 ) {
		size_t map_size = IMGSIZE_TO_MAPBYTES( fileSize );
		cache_map = calloc( 1, map_size );
		int rd = read( fdMap, cache_map, map_size );
		if ( map_size != rd ) {
			memlogf( "[WARNING] Could only read %d of expected %d bytes of cache map of '%s'", (int)rd, (int)map_size, path );
		}
		close( fdMap );
	}
	// TODO: Maybe try sha-256 or 512 first if you're paranoid (to be implemented)
	const int hashBlocks = IMGSIZE_TO_HASHBLOCKS( fileSize );
	// Currently this should only prevent accidental corruption (esp. regarding transparent proxy mode)
	// but maybe later on you want better security
	// 2. Load CRC-32 list of image
	sprintf( hashFile, "%s.crc", path );
	int fdHash = open( hashFile, O_RDONLY );
	if ( fdHash >= 0 ) {
		off_t fs = lseek( fdHash, 0, SEEK_END );
		if ( fs < (hashBlocks + 1) * 4 ) {
			memlogf( "[WARNING] Ignoring crc32 list for '%s' as it is too short", path );
		} else {
			if ( 0 != lseek( fdHash, 0, SEEK_SET ) ) {
				memlogf( "[WARNING] Could not seek back to beginning of '%s'", hashFile );
			} else {
				uint32_t crcCrc;
				if ( read( fdHash, &crcCrc, sizeof(crcCrc) ) != 4 ) {
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
						if ( lists_crc != crcCrc ) {
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
		int blocks[] = { 0, rand() % hashBlocks, rand() % hashBlocks, -1 };
		if ( !image_check_blocks_crc32( fdImage, crc32list, blocks ) ) {
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
		} else {
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
	image->uplink = NULL;
	image->filesize = fileSize;
	image->rid = revision;
	image->users = 0;
	if ( stat( path, &st ) == 0 ) {
		image->atime = st.st_mtime;
	} else {
		image->atime = time( NULL );
	}
	image->working = (image->cache_map == NULL );
	pthread_spin_init( &image->lock, PTHREAD_PROCESS_PRIVATE );
	// Get rid of cache map if image is complete
	if ( image->cache_map != NULL && image_is_complete( image ) ) {
		remove( mapFile );
		free( image->cache_map );
		image->cache_map = NULL;
		image->working = TRUE;
	}
	// Prevent freeing in cleanup
	cache_map = NULL;
	crc32list = NULL;
	// Add to images array
	pthread_spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] != NULL ) continue;
		_images[i] = image;
		break;
	}
	if ( i >= _num_images ) {
		if ( _num_images >= SERVER_MAX_IMAGES ) {
			memlogf( "[ERROR] Cannot load image '%s': maximum number of images reached.", path );
			pthread_spin_unlock( &_images_lock );
			image = image_free( image );
			goto load_error;
		}
		_images[_num_images++] = image;
	}
	pthread_spin_unlock( &_images_lock );
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
 * Check the CRC-32 of the given blocks. The array blocks is of variable length.
 * !! pass -1 as the last block so the function knows when to stop !!
 */
static int image_check_blocks_crc32(int fd, uint32_t *crc32list, int *blocks)
{
	char buffer[32768];
	while ( *blocks != -1 ) {
		if ( lseek( fd, *blocks * HASH_BLOCK_SIZE, SEEK_SET ) != *blocks * HASH_BLOCK_SIZE) {
			memlogf( "Seek error" );
			return FALSE;
		}
		uint32_t crc = crc32( 0L, Z_NULL, 0 );
		int bytes = 0;
		while ( bytes < HASH_BLOCK_SIZE) {
			const int n = MIN(sizeof(buffer), HASH_BLOCK_SIZE - bytes);
			const int r = read( fd, buffer, n );
			if ( r <= 0 ) {
				memlogf( "Read error" );
				return FALSE;
			}
			crc = crc32( crc, (Bytef*)buffer, r );
			bytes += r;
		}
		if ( crc != crc32list[*blocks] ) return FALSE;
		blocks++;
	}
	return TRUE;
}

static dnbd3_image_t* image_free(dnbd3_image_t *image)
{
	assert( image != NULL );
	//
	free( image->cache_map );
	free( image->crc32 );
	free( image->path );
	free( image->lower_name );
	uplink_shutdown( image->uplink );
	pthread_spin_destroy( &image->lock );
	//
	memset( image, 0, sizeof(dnbd3_image_t) );
	free( image );
	return NULL ;
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
