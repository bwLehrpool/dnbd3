#include "image.h"

#include <glib/gmacros.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

// ##########################################

static void image_load_all(char *path);
static int image_try_load(char *base, char *path);

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
	if ( !candidate->working || candidate->delete_soft < time( NULL ) || stat( candidate->path, &st ) < 0 ) {
		candidate->working = FALSE;
		pthread_spin_unlock( &candidate->lock );
		return NULL ; // Not working (anymore)
	}
	candidate->users++;
	pthread_spin_unlock( &candidate->lock );
	return candidate; // Success :-)
}

/**
 * Release given image. This will merely decrease the reference counter of the image.
 * Locks on: _images[].lock
 */
void image_release(dnbd3_image_t *image)
{
	assert( image != NULL );
	pthread_spin_lock( &image->lock );
	assert( image->users > 0 );
	image->users--;
	pthread_spin_unlock( &image->lock );
}

void image_load_all()
{

}

/**
 * Load all images in the given path
 */
static int image_load_all(char *base, char *path)
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
			image_load_all( base, subpath ); // Recurse
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
		while (src < fileName + i - 1) {
			*dst++ = *src++;
		}
		*dst = '\0';
	}
	if (revision <= 0) {
		memlogf("[WARNING] Image '%s' has invalid revision ID %d", path, revision);
		return FALSE;
	}
	// TODO: LOAD IMAGE DATA ETC.
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
