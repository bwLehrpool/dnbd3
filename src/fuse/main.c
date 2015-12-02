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
#include <getopt.h>
#include <time.h>

#define debugf(...) do { logadd( LOG_DEBUG1, __VA_ARGS__ ); } while (0)

static const char * const IMAGE_PATH = "/img";
static const char * const STATS_PATH = "/status";

static uint64_t imageSize;
/* Debug/Benchmark variables */
static bool useDebug = false;
static log_info logInfo;
static struct timespec startupTime;
static uid_t owner;

void error(const char *msg)
{
	perror( msg );
	exit( 0 );
}

static int image_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	memset( stbuf, 0, sizeof( struct stat ) );
	stbuf->st_ctim = stbuf->st_atim = stbuf->st_mtim = startupTime;
	stbuf->st_uid = owner;
	if ( strcmp( path, "/" ) == 0 ) {
		stbuf->st_mode = S_IFDIR | 0550;
		stbuf->st_nlink = 2;
	} else if ( strcmp( path, IMAGE_PATH ) == 0 ) {
		stbuf->st_mode = S_IFREG | 0440;
		stbuf->st_nlink = 1;
		stbuf->st_size = imageSize;
	} else if ( strcmp( path, STATS_PATH ) == 0 ) {
		stbuf->st_mode = S_IFREG | 0440;
		stbuf->st_nlink = 1;
		stbuf->st_size = 4096;
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
	filler( buf, IMAGE_PATH + 1, NULL, 0 );
	filler( buf, STATS_PATH + 1, NULL, 0 );
	return 0;
}

static int image_open(const char *path, struct fuse_file_info *fi)
{
	if ( strcmp( path, IMAGE_PATH ) != 0 && strcmp( path, STATS_PATH ) != 0 ) {
		return -ENOENT;
	}
	if ( ( fi->flags & 3 ) != O_RDONLY ) {
		return -EACCES;
	}
	return 0;
}

static int fillStatsFile(char *buf, size_t size, off_t offset) {
	if ( offset == 0 ) {
		return connection_printStats( buf, size );
	}
	char buffer[4096];
	int ret = connection_printStats( buffer, sizeof buffer );
	int len = MIN( ret - (int)offset, (int)size );
	if ( len == 0 )
		return 0;
	if ( len < 0 ) {
		return -EOF;
	}
	memcpy( buf, buffer + offset, len );
	return len;
}

static int image_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi UNUSED)
{
	if ( (uint64_t)offset >= imageSize ) {
		return 0;
	}

	if ( path[1] == STATS_PATH[1] ) {
		return fillStatsFile(buf, size, offset);
	}
	//return -ENOENT;

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
	if ( useDebug ) {
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

static void printVersion()
{
	char *arg[] = { "foo", "-V" };
	printf( "DNBD3-Fuse Version 1.2.3.4\n" );
	fuse_main( 2, arg, NULL, NULL );
	exit( 0 );
}

static void printUsage(char *argv0, int exitCode)
{
	char *arg[] = { argv0, "-h" };
	printf( "Usage: %s [--debug] [--option mountOpts] --host <serverAddress(es)> --image <imageName> [--rid revision] <mountPoint>\n", argv0 );
	printf( "Or:    %s [-d] [-o mountOpts] -h <serverAddress(es)> -i <imageName> [-r revision] <mountPoint>\n", argv0 );
	printf( "   -h --host       List of space separated hosts to use\n" );
	printf( "   -i --image      Remote image name to request\n" );
	printf( "   -r --rid        Revision to use (omit or pass 0 for latest)\n" );
	printf( "   -o --option     Mount options to pass to libfuse\n" );
	printf( "   -d --debug      Don't fork and print debug output (fuse > stderr, dnbd3 > stdout)\n" );
	fuse_main( 2, arg, NULL, NULL );
	exit( exitCode );
}

static const char *optString = "h:i:r:o:HvVdtsf";
static const struct option longOpts[] = {
        { "host", required_argument, NULL, 'h' },
        { "image", required_argument, NULL, 'i' },
        { "rid", required_argument, NULL, 'r' },
        { "option", required_argument, NULL, 'o' },
        { "help", no_argument, NULL, 'H' },
        { "version", no_argument, NULL, 'v' },
        { "debug", no_argument, NULL, 'd' },
        { 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	char *server_address = NULL;
	char *image_Name = NULL;
	uint16_t rid = 0;
	char **newArgv;
	int newArgc;
	int opt, lidx;
	bool testOpt = false;

	if ( argc <= 1 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "--usage" ) == 0 ) {
		printUsage( argv[0], 0 );
	}

	log_setConsoleMask( 65535 );

	newArgv = calloc( argc + 10, sizeof(char*) );
	newArgv[0] = argv[0];
	newArgc = 1;
	while ( ( opt = getopt_long( argc, argv, optString, longOpts, &lidx ) ) != -1 ) {
		switch ( opt ) {
		case 'h':
			server_address = optarg;
			break;
		case 'i':
			image_Name = optarg;
			break;
		case 'r':
			rid = (uint16_t)atoi(optarg);
			break;
		case 'o':
			newArgv[newArgc++] = "-o";
			newArgv[newArgc++] = optarg;
			if ( strstr( optarg, "use_ino" ) != NULL ) {
				printf( "************************\n"
						"* WARNING: use_ino mount option is unsupported, use at your own risk!\n"
						"************************\n" );
			}
			break;
		case 'H':
			printUsage( argv[0], 0 );
			break;
		case 'v':
		case 'V':
			printVersion();
			break;
		case 'd':
			useDebug = true;
			newArgv[newArgc++] = "-d";
			break;
		case 's':
			useDebug = true;
			newArgv[newArgc++] = "-s";
			break;
		case 'f':
			useDebug = true;
			newArgv[newArgc++] = "-f";
			break;
		case 't':
			testOpt = true;
			break;
		default:
			printUsage( argv[0], EXIT_FAILURE );
		}
	}

	if ( optind >= argc ) { // Missing mount point
		printUsage( argv[0], EXIT_FAILURE );
	}

	if ( testOpt ) {
		/* values for testing. */
		server_address = "132.230.4.1 132.230.8.113 132.230.4.60";
		image_Name = "windows7-umwelt.vmdk";
		useDebug = true;
	}
	if ( server_address == NULL || image_Name == NULL ) {
		printUsage( argv[0], EXIT_FAILURE );
	}

	// Since dnbd3 is always read only and the remote image will not change
	newArgv[newArgc++] = "-o";
	newArgv[newArgc++] = "kernel_cache,default_permissions";
	// Mount point goes last
	newArgv[newArgc++] = argv[optind];

	if ( !connection_init( server_address, image_Name, rid ) ) {
		printf( "Could not connect to any server. Bye.\n" );
		return EXIT_FAILURE;
	}
	imageSize = connection_getImageSize();

	/* initialize benchmark variables */
	logInfo.receivedBytes = 0;
	logInfo.imageSize = imageSize;
	logInfo.imageBlockCount = ( imageSize + 4095 ) / 4096;

	uint8_t tmpShrt[logInfo.imageBlockCount];
	memset( tmpShrt, 0, sizeof tmpShrt );

	logInfo.blockRequestCount = tmpShrt;

	printf( "ImagePathName: %s\nFuseArgs:",IMAGE_PATH );
	for ( int i = 0; i < newArgc; ++i ) {
		printf( " '%s'", newArgv[i] );
	}
	putchar('\n');
	clock_gettime( CLOCK_REALTIME, &startupTime );
	owner = getuid();
	return fuse_main( newArgc, newArgv, &image_oper, NULL );
}
