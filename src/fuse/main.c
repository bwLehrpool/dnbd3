/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 *
 * Changed by Stephan Schwaer
 * */

#include "../protocol.h"
#include "../serialize.h"
#include "helper.h"

#define FUSE_USE_VERSION 30
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
/* for socket */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
/* for printing uint */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

/* variables for socket */
int sock = -1;
int n;

char *server_address = NULL;
int portno = -1;
char *image_Name = NULL;
const char *imagePathName = "/image";
uint16_t rid;
static uint64_t imageSize;
/* Debug/Benchmark variables */
bool useDebug = false;
bool useLog = false;
log_info logInfo;
uint8_t printCount = 0;

void error(const char *msg)
{
	perror( msg );
	exit( 0 );
}

static void dnbd3_connect()
{
	while ( true ) {
		if ( sock != -1 ) {
			close( sock );
		}
		sock = connect_to_server( server_address, portno );

		if ( sock == -1 ) {
			printf( "[ERROR] Connection Error!\n" );
			goto fail;
		}

		printf( "Selecting image " );

		serialized_buffer_t sbuffer;
		uint16_t protocol_version;
		char *name;
		uint16_t rrid;

		if ( dnbd3_select_image( sock, image_Name, rid, 0 ) != 1 ) {
			printf( "- Error\n" );
			goto fail;
		}
		printf( "- Success\n" );

		if ( !dnbd3_select_image_reply( &sbuffer, sock, &protocol_version, &name, &rrid, &imageSize ) ) {
			printf( "Error reading reply\n" );
			goto fail;
		}
		printf( "Reply successful\n" );

		if ( rid != 0 && rid != rrid ) {
			printf( "Got unexpected rid %d, wanted %d\n", (int)rrid, (int)rid );
			sleep( 10 );
			goto fail;
		}
		rid = rrid;

		printf( "Protocol version: %i, Image: %s, RevisionID: %i, Size: %i MiB\n", (int)protocol_version, name, (int) rrid, (int)( imageSize/ ( 1024*1024 ) ) );
		return;

fail: ;
		sleep( 2 );
	}
}

static int image_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	memset( stbuf, 0, sizeof( struct stat ) );
	if ( strcmp( path, "/" ) == 0 ) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if ( strcmp( path, imagePathName ) == 0 ) {
		stbuf->st_mode = S_IFREG | 0755;
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
	/* buffer for throwing away unwanted messages. */
	char tBuf[100];

	if ( strcmp( path, imagePathName ) != 0 ) {
		return -ENOENT;
	}
	if ( offset >= imageSize ) {
		return 0;
	}
	if ( offset + size > imageSize ) {
		size = imageSize - offset;
	}

	if ( sock == -1 ) {
retry: ;
		 dnbd3_connect();
	}

	/* seek inside the image */
	if ( !dnbd3_get_block( sock, offset, size, offset ) ) {
		printf( "[ERROR] Get block error!\n" );
		goto retry;
	}

	/* count the requested blocks */
	uint64_t startBlock = offset / ( 4096 );
	uint64_t endBlock = ( offset + size - 1 ) / ( 4096 );

	printf( "StartBlockRequest: %"PRIu64"\n", startBlock );
	printf( "EndBlockRequest: %"PRIu64"\n", endBlock );

	if ( useDebug ) {
		for ( ; startBlock <= endBlock; startBlock++ ) {
			logInfo.blockRequestCount[startBlock] += 1;
		}
	}

	dnbd3_reply_t reply;

	/*see if the received package is a requested block, throw away if not */
	while ( true ) {
		if ( !dnbd3_get_reply( sock, &reply ) ) {
			printf( "[ERROR] Reply error\n" );
			goto retry;
		}
		printf( "Reply success\n" );

		if ( reply.cmd == CMD_ERROR ) {
			printf( "Got a CMD_ERROR!\n" );
			goto retry;
		}
		if ( reply.cmd != CMD_GET_BLOCK ) {
			printf( "Received block isn't a wanted block, throwing it away...\n" );
			int tDone = 0;
			int todo;
			while ( tDone < reply.size ) {
				todo = reply.size - tDone > 100 ? 100: reply.size - tDone;

				n = read( sock, tBuf, todo );
				if ( n <= 0 ) {
					if ( n < 0 && ( errno == EAGAIN || errno == EINTR ) ) {
						continue;
					}
					printf( "[ERROR] Errno %i and %i\n",errno, n );
					goto retry;
				}
				tDone += n;
			}
			continue;
		}
		break;
	}

	printf( "Payloadsize: %i\n", ( int ) reply.size );
	printf( "Offset: %"PRIu64"\n", reply.handle );

	if ( size != reply.size || offset != reply.handle ) {
		printf( "Size: %i, reply.size: %i!\n", ( int ) size, ( int ) reply.size );
		printf( "Handle: %" PRIu64 ", reply.handle: %" PRIu64 "!\n", offset, reply.handle );
		goto retry;
	}
	/* read the data block data from received package */
	int done = 0;
	while ( done < size ) {
		n = read( sock, buf + done, size - done );
		if ( n <= 0 ) {
			if ( n < 0 && ( errno == EAGAIN || errno == EINTR ) ) {
				continue;
			}
			printf( "[ERROR] Error: %i and %i\n",errno, n );
			goto retry;
		}
		done += n;
		/* for benchmarking */
		logInfo.receivedBytes += n;
	}
	printf( "Received bytes: %i MiB\n", ( int )( logInfo.receivedBytes/ ( 1024*1024 ) ) );

	/* logfile stuff */
	if ( useLog ) {
		if ( printCount == 0 ) {
			printLog( &logInfo );
		}
		printCount++;
	}
	return size;
}

/* close the connection */
void image_destroy(void *private_data)
{
	if ( useLog ) {
		printLog( &logInfo );
	}
	if ( sock != -1 ) {
		close( sock );
		sock = -1;
	}
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
	char *mountPoint = NULL;
	int opt;
	bool testOpt = false;

	if ( argc == 1 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "--usage" ) == 0 ) {
exit_usage:
		printf( "Usage: %s [-l] [-d] [-t] -m <mountpoint> -s <serverAdress> -p <port> -i <imageName>\n", argv[0] );
		printf( "    -l: creates a logfile log.txt at program path\n" );
		printf( "    -d: fuse debug mode\n" );
		printf( "    -t: use hardcoded server, port and image for testing\n" );
		exit( EXIT_FAILURE );
	}

	while ( ( opt = getopt( argc,argv,"m:s:p:i:tdl" ) ) != -1 ) {
		switch ( opt ) {
		case 'm':
			mountPoint = optarg;
			break;
		case 's':
			server_address = optarg;
			break;
		case 'p':
			portno = atoi( optarg );
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
		server_address = "132.230.4.1";
		portno = 5003;
		image_Name = "windows7-umwelt.vmdk";
		useLog = true;
	}

	if ( server_address == NULL || portno == -1 || image_Name == NULL || mountPoint == NULL ) {
		goto exit_usage;
	}

	int arg_count = 5;
	if ( useDebug ) {
		arg_count++;
	}
	char *args[6] = {"foo", "-o", "ro,allow_other", "-s", mountPoint, "-d"};

	dnbd3_connect();

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

