/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 *
 * Changed by Stephan Schwaer
 * */

#include "../shared/protocol.h"
#include "../shared/signal.h"
#include "connection.h"
#include "../serialize.h"
#include "helper.h"
#include "../shared/log.h"

#define FUSE_USE_VERSION 30
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
/* for printing uint */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define debugf(...) do { logadd( LOG_DEBUG1, __VA_ARGS__ ); } while (0)

static const char *imagePathName = "/img";
static uint64_t imageSize;
/* Debug/Benchmark variables */
static bool useDebug = false;
static bool useLog = false;
static log_info logInfo;

void error(const char *msg)
{
	perror( msg );
	exit( 0 );
}

static int image_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	memset( stbuf, 0, sizeof( struct stat ) );
	if ( strcmp( path, "/" ) == 0 ) {
		stbuf->st_mode = S_IFDIR | 0444;
		stbuf->st_nlink = 2;
	} else if ( strcmp( path, imagePathName ) == 0 ) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = imageSize;
	} else {
		res = -ENOENT;
	}
	return res;
}

static int image_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset UNUSED, struct fuse_file_info *fi UNUSED)
{
	if ( strcmp( path, "/" ) != 0 ) {
		return -ENOENT;
	}
	filler( buf, ".", NULL, 0 );
	filler( buf, "..", NULL, 0 );
	filler( buf, imagePathName + 1, NULL, 0 );
	return 0;
}

static int image_open(const char *path, struct fuse_file_info *fi)
{
	if ( strcmp( path, imagePathName ) != 0 ) {
		return -ENOENT;
	}
	if ( ( fi->flags & 3 ) != O_RDONLY ) {
		return -EACCES;
	}
	return 0;
}

static int image_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi UNUSED)
{
	if ( (uint64_t)offset >= imageSize ) {
		return 0;
	}
//	if ( strcmp( path, imagePathName ) != 0 ) {
//		return -ENOENT;
//	}
	if ( offset + size > imageSize ) {
		size = imageSize - offset;
	}

	/* count the requested blocks */
	uint64_t startBlock = offset / ( 4096 );
	const uint64_t endBlock = ( offset + size - 1 ) / ( 4096 );

	if ( useDebug ) {
		for ( ; startBlock <= endBlock; startBlock++ ) {
			logInfo.blockRequestCount[startBlock] += 1;
		}
	}

	dnbd3_async_t request;
	request.buffer = buf;
	request.length = (uint32_t)size;
	request.offset = offset;
	request.signalFd = signal_newBlocking();

	if ( !connection_read( &request ) ) {
		return -EINVAL;
	}
	while ( !request.finished ) {
		int ret = signal_wait( request.signalFd, 10000 );
		if ( ret < 0 ) {
			debugf( "fuse_read signal wait returned %d", ret );
		}
	}
	signal_close( request.signalFd );
	if ( request.success ) {
		return request.length;
	} else {
		return -EIO;
	}
}

/* close the connection */
void image_destroy(void *private_data UNUSED)
{
	if ( useLog ) {
		printLog( &logInfo );
	}
	connection_close();
	return;
}

/* map the implemented fuse operations */
static struct fuse_operations image_oper = {
	.getattr = image_getattr,
	.readdir = image_readdir,
	.open = image_open,
	.read = image_read,
	.destroy = image_destroy,
};

int main(int argc, char *argv[])
{
	char *server_address = NULL;
	char *image_Name = NULL;
	char *mountPoint = NULL;
	int opt;
	bool testOpt = false;

	if ( argc == 1 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "--usage" ) == 0 ) {
exit_usage:
		printf( "Usage: %s [-l] [-d] [-t] -m <mountpoint> -s <serverAdress> -i <imageName>\n", argv[0] );
		printf( "    -l: creates a logfile log.txt at program path\n" );
		printf( "    -d: fuse debug mode\n" );
		printf( "    -t: use hardcoded server, port and image for testing\n" );
		exit( EXIT_FAILURE );
	}

	log_setConsoleMask( 65535 );

	while ( ( opt = getopt( argc,argv,"m:s:p:i:tdl" ) ) != -1 ) {
		switch ( opt ) {
		case 'm':
			mountPoint = optarg;
			break;
		case 's':
			server_address = optarg;
			break;
		case 'i':
			image_Name = optarg;
			break;
		case 't':
			testOpt = true;
			break;
		case 'd':
			useDebug = true;
			break;
		case 'l':
			useLog = true;
			useDebug = true;
			break;
		default:
			goto exit_usage;
		}
	}

	if ( testOpt ) {
		/* values for testing. */
		server_address = "132.230.4.1 132.230.8.113 132.230.4.60";
		image_Name = "windows7-umwelt.vmdk";
		useLog = true;
	}

	if ( server_address == NULL || image_Name == NULL || mountPoint == NULL ) {
		goto exit_usage;
	}

	int arg_count = 4;
	if ( useDebug ) {
		arg_count++;
	}
	char *args[6] = { "foo", "-o", "ro,allow_other,kernel_cache,max_readahead=262144", mountPoint, "-d" };

	if ( !connection_init( server_address, image_Name, 0 ) ) {
		printf( "Tschüss\n" );
		return 1;
	}
	imageSize = connection_getImageSize();

	/* initialize benchmark variables */
	logInfo.receivedBytes = 0;
	logInfo.imageSize = imageSize;
	logInfo.imageBlockCount = ( imageSize + 4095 ) / 4096;

	uint8_t tmpShrt[logInfo.imageBlockCount];
	memset( tmpShrt, 0, sizeof tmpShrt );

	logInfo.blockRequestCount = tmpShrt;

	printf( "ImagePathName: %s\n",imagePathName );
	return fuse_main( arg_count, args, &image_oper, NULL );
}

