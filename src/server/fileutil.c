#include "fileutil.h"
#include "helper.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

bool file_isReadable(char *file)
{
	int fd = open( file, O_RDONLY );
	if ( fd < 0 ) return false;
	close( fd );
	return true;
}

bool file_isWritable(char *file)
{
	int fd = open( file, O_WRONLY );
	if ( fd >= 0 ) {
		close( fd );
		return true;
	}
	fd = open( file, O_WRONLY | O_CREAT, 0600 );
	if ( fd < 0 ) return false;
	close( fd );
	remove( file );
	return true;
}

bool mkdir_p(const char* path)
{
	assert( path != NULL );
	if ( *path == '\0' ) return true;
	char buffer[strlen( path ) + 1];
	strcpy( buffer, path );
	char *current = buffer;
	char *slash;
	while ( (slash = strchr( current, '/' )) != NULL ) {
		*slash = '\0';
		if ( *buffer != '\0' && mkdir( buffer, 0755 ) != 0 && errno != EEXIST ) return false;
		*slash = '/';
		current = slash + 1;
	}
	if ( mkdir( buffer, 0755 ) != 0 && errno != EEXIST ) return false;
	return true;
}

bool file_alloc(int fd, uint64_t offset, uint64_t size)
{
#ifdef __linux__
	if ( fallocate( fd, 0, offset, size ) == 0 ) return true; // fast way
#elif defined(__FreeBSD__)
	if ( posix_fallocate( fd, offset, size ) == 0 ) return true; // slow way
#endif
	return false;
}

bool file_setSize(int fd, uint64_t size)
{
	if ( ftruncate( fd, size ) == 0 ) return true;

	// Try really hard... image loading logic relies on the file
	// having the proper apparent size
	uint8_t byte = 0;
	(void)!pread( fd, &byte, 1, size - 1 );
	if ( pwrite( fd, &byte, 1, size - 1 ) == 1 ) return true;
	return false;
}

bool file_freeDiskSpace(const char * const path, uint64_t *total, uint64_t *avail)
{
	struct statvfs fiData;
	if ( statvfs( path, &fiData ) < 0 ) {
		return false;
	}
	if ( avail != NULL ) {
		*avail = ((uint64_t)fiData.f_bavail * (uint64_t)fiData.f_frsize);
	}
	if ( total != NULL ) {
		*total = ((uint64_t)fiData.f_blocks * (uint64_t)fiData.f_frsize);
	}
	return true;
}

time_t file_lastModification(const char * const file)
{
	struct stat st;
	if ( stat( file, &st ) != 0 ) return 0;
	return st.st_mtime;
}

int file_loadLineBased(const char * const file, int minFields, int maxFields, void (*cb)(int argc, char **argv, void *data), void *data)
{
	char buffer[1000], *line;
	char *items[20];
	int count = 0, itemCount;

	if ( file == NULL || cb == NULL ) return -1;
	FILE *fp = fopen( file, "r" );
	if ( fp == NULL ) return -1;
	while ( fgets( buffer, sizeof(buffer), fp ) != NULL ) {
		itemCount = 0;
		for (line = buffer; *line != '\0' && itemCount < 20; ) { // Trim left and scan for "-" prefix
			while ( *line == ' ' || *line == '\t' ) ++line;
			if ( *line == '\r' || *line == '\n' || *line == '\0' ) break; // Ignore empty lines
			items[itemCount++] = line;
			if ( itemCount >= maxFields ) {
				trim_right( line );
				break;
			}
			while ( *line != '\0' && *line != ' ' && *line != '\t' && *line != '\r' && *line != '\n' ) ++line;
			if ( *line != '\0' ) *line++ = '\0';
		}
		if ( itemCount >= minFields ) {
			cb( itemCount, items, data );
			count++;
		}
	}
	fclose( fp );
	return count;
}

