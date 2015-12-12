#include "fileutil.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

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
	if ( fallocate( fd, 0, offset, size ) == 0 ) return true; // fast way
	if ( posix_fallocate( fd, offset, size ) == 0 ) return true; // slow way
	if ( lseek( fd, offset + size - 1, SEEK_SET ) != (off_t)offset ) return false; // dumb way
	if ( write( fd, "", 1 ) != 1 ) return false;
	return true;
}

int64_t file_freeDiskSpace(const char * const path)
{
	struct statvfs fiData;
	if ( (statvfs( path, &fiData )) < 0 ) {
		return -1;
	}
	return ((int64_t)fiData.f_bavail * (int64_t)fiData.f_bsize);
}

time_t file_lastModification(const char * const file)
{
	struct stat st;
	if ( stat( file, &st ) != 0 ) return 0;
	return st.st_mtime;
}
