/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 *
 * Changed by Stephan Schwaer
 * FUSE lowlevel by Alan Reichert
 * */

#include "connection.h"
#include "helper.h"
#include "../shared/protocol.h"
#include "../shared/log.h"

#define FUSE_USE_VERSION 30
#include "../config.h"
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
/* for printing uint */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

#define debugf(...) do { logadd( LOG_DEBUG1, __VA_ARGS__ ); } while (0)

#define INO_ROOT (1)
#define INO_STATS (2)
#define INO_IMAGE (3)

static const char *IMAGE_NAME = "img";
static const char *STATS_NAME = "status";

static struct fuse_session *_fuseSession = NULL;

static uint64_t imageSize;
/* Debug/Benchmark variables */
static bool useDebug = false;
static log_info logInfo;
static struct timespec startupTime;
static uid_t owner;

static int reply_buf_limited( fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize );
static void fillStatsFile( fuse_req_t req, size_t size, off_t offset );
static void image_destroy( void *private_data );
static void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );
static void image_ll_init( void *userdata, struct fuse_conn_info *conn );
static void image_ll_lookup( fuse_req_t req, fuse_ino_t parent, const char *name );
static void image_ll_open( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );
static void image_ll_readdir( fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi );
static void image_ll_read( fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi );
static int image_stat( fuse_ino_t ino, struct stat *stbuf );
static void printUsage( char *argv0, int exitCode );
static void printVersion();

static int image_stat( fuse_ino_t ino, struct stat *stbuf )
{
	switch ( ino ) {
	case INO_ROOT:
		stbuf->st_mode = S_IFDIR | 0550;
		stbuf->st_nlink = 2;
		stbuf->st_mtim = startupTime;
		break;
	case INO_IMAGE:
		stbuf->st_mode = S_IFREG | 0440;
		stbuf->st_nlink = 1;
		stbuf->st_size = imageSize;
		stbuf->st_mtim = startupTime;
		break;
	case INO_STATS:
		stbuf->st_mode = S_IFREG | 0440;
		stbuf->st_nlink = 1;
		stbuf->st_size = 4096;
		clock_gettime( CLOCK_REALTIME, &stbuf->st_mtim );
		break;
	default:
		return -1;
	}
	stbuf->st_ctim = stbuf->st_atim = startupTime;
	stbuf->st_uid = owner;
	stbuf->st_ino = ino;
	return 0;
}

static void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi )
{
	struct stat stbuf = { 0 };
	( void ) fi;

	if ( image_stat( ino, &stbuf ) == -1 ) {
		fuse_reply_err( req, ENOENT );
	} else {
		fuse_reply_attr( req, &stbuf, ino == INO_IMAGE ? 120 : 1 ); // seconds validity timeout
	}
}

static void image_ll_lookup( fuse_req_t req, fuse_ino_t parent, const char *name )
{
	( void )parent;

	if ( strcmp( name, IMAGE_NAME ) == 0 || strcmp( name, STATS_NAME ) == 0 ) {
		struct fuse_entry_param e = { 0 };
		if ( strcmp( name, IMAGE_NAME ) == 0 ) {
			e.ino = INO_IMAGE;
			e.attr_timeout = e.entry_timeout = 120;
		} else {
			e.ino = INO_STATS;
			e.attr_timeout = e.entry_timeout = 1;
		}
		if ( image_stat( e.ino, &e.attr ) == 0 ) {
			fuse_reply_entry( req, &e );
			return;
		}
	}
	fuse_reply_err( req, ENOENT );
}

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add( fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino )
{
	struct stat stbuf = { .st_ino = ino };
	size_t oldsize = b->size;
	b->size += fuse_add_direntry( req, NULL, 0, name, NULL, 0 );
	b->p = ( char * ) realloc( b->p, b->size );
	fuse_add_direntry( req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size );
	return;
}

static int reply_buf_limited( fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize )
{
	if ( off >= 0 && off < (off_t)bufsize ) {
		return fuse_reply_buf( req, buf + off, MIN( bufsize - off, maxsize ) );
	}
	return fuse_reply_buf( req, NULL, 0 );
}

static void image_ll_readdir( fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi )
{
	( void ) fi;

	if ( ino != INO_ROOT ) {
		fuse_reply_err( req, ENOTDIR );
	} else {
		struct dirbuf b;
		memset( &b, 0, sizeof( b ) );
		dirbuf_add( req, &b, ".", INO_ROOT );
		dirbuf_add( req, &b, "..", INO_ROOT );
		dirbuf_add( req, &b, IMAGE_NAME, INO_IMAGE );
		dirbuf_add( req, &b, STATS_NAME, INO_STATS );
		reply_buf_limited( req, b.p, b.size, off, size );
		free( b.p );
	}
}

static void image_ll_open( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi )
{
	if ( ino != INO_IMAGE && ino != INO_STATS ) {
		fuse_reply_err( req, EISDIR );
	} else if ( ( fi->flags & 3 ) != O_RDONLY ) {
		fuse_reply_err( req, EACCES );
	} else {
		// auto caching
		fi->keep_cache = 1;
		fuse_reply_open( req, fi );
	}
}

static void fillStatsFile( fuse_req_t req, size_t size, off_t offset ) {
	char buffer[4096];
	int ret = (int)connection_printStats( buffer, sizeof buffer );
	int len = MIN( ret - (int)offset, (int)size );
	if ( len < 0 ) {
		fuse_reply_err( req, 0 );
		return;
	}
	fuse_reply_buf( req, buffer + offset, len );
}

static void image_ll_read( fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi )
{
	assert( ino == INO_STATS || ino == INO_IMAGE );

	( void )fi;

	if ( ino == INO_STATS ) {
		fillStatsFile( req, size, offset );
		return;
	}

	if ( (uint64_t)offset >= imageSize ) {
		fuse_reply_err( req, 0 );
		return;
	}
	if ( offset + size > imageSize ) {
		size = imageSize - offset;
	}
	if ( size == 0 || size > UINT32_MAX ) {
		fuse_reply_err( req, 0 );
		return;
	}

	if ( useDebug ) {
		uint64_t startBlock = offset / ( 4096 );
		const uint64_t endBlock = ( offset + size - 1 ) / ( 4096 );

		for ( ; startBlock <= endBlock; startBlock++ )
		{
			++logInfo.blockRequestCount[startBlock];
		}
	}
	dnbd3_async_t *request = malloc( sizeof(dnbd3_async_t) + size );
	request->length = (uint32_t)size;
	request->offset = offset;
	request->fuse_req = req;

	if ( !connection_read( request ) ) {
		fuse_reply_err( req, EIO );
		free( request );
	}
}

static void noopSigHandler( int signum )
{
	(void)signum;
}

static void image_ll_init( void *userdata, struct fuse_conn_info *conn )
{
	( void ) userdata;
	( void ) conn;
	if ( !connection_initThreads() ) {
		logadd( LOG_ERROR, "Could not initialize threads for dnbd3 connection, exiting..." );
		if ( _fuseSession != NULL ) {
			fuse_session_exit( _fuseSession );
		}
	}
}

/* close the connection */
static void image_destroy( void *private_data UNUSED )
{
	if ( useDebug ) {
		printLog( &logInfo );
	}
	connection_close();
}

/* map the implemented fuse operations */
static struct fuse_lowlevel_ops image_oper = {
	.lookup = image_ll_lookup,
	.getattr = image_ll_getattr,
	.readdir = image_ll_readdir,
	.open = image_ll_open,
	.read = image_ll_read,
	.init = image_ll_init,
	.destroy = image_destroy,
};

static void printVersion()
{
	char *arg[] = { "foo", "-V" };
	printf( "DNBD3-Fuse Version 1.2.3.4, protocol version %d\n", (int)PROTOCOL_VERSION );
	struct fuse_args args = FUSE_ARGS_INIT( 2, arg );
	fuse_parse_cmdline( &args, NULL, NULL, NULL );
	exit( 0 );
}

static void printUsage( char *argv0, int exitCode )
{
	char *arg[] = { argv0, "-h" };
	struct fuse_args args = FUSE_ARGS_INIT( 2, arg );
	fuse_parse_cmdline( &args, NULL, NULL, NULL );
	printf( "\n" );
	printf( "Usage: %s [--debug] [--option mountOpts] --host <serverAddress(es)> --image <imageName> [--rid revision] <mountPoint>\n", argv0 );
	printf( "Or:    %s [-d] [-o mountOpts] -h <serverAddress(es)> -i <imageName> [-r revision] <mountPoint>\n", argv0 );
	printf( "   -d --debug      Don't fork, write stats file, and print debug output (fuse -> stderr, dnbd3 -> stdout)\n" );
	printf( "   -f              Don't fork (dnbd3 -> stdout)\n" );
	printf( "   -h --host       List of space separated hosts to use\n" );
	printf( "   -i --image      Remote image name to request\n" );
	printf( "   -l --log        Write log to given location\n" );
	printf( "   -o --option     Mount options to pass to libfuse\n" );
	printf( "   -r --rid        Revision to use (omit or pass 0 for latest)\n" );
	printf( "   -S --sticky     Use only servers from command line (no learning from servers)\n" );
	printf( "   -s              Single threaded mode\n" );
	exit( exitCode );
}

static const char *optString = "dfHh:i:l:o:r:SsVv";
static const struct option longOpts[] = {
	{ "debug", no_argument, NULL, 'd' },
	{ "help", no_argument, NULL, 'H' },
	{ "host", required_argument, NULL, 'h' },
	{ "image", required_argument, NULL, 'i' },
	{ "log", required_argument, NULL, 'l' },
	{ "option", required_argument, NULL, 'o' },
	{ "rid", required_argument, NULL, 'r' },
	{ "sticky", no_argument, NULL, 'S' },
	{ "version", no_argument, NULL, 'v' },
	{ 0, 0, 0, 0 }
};

int main( int argc, char *argv[] )
{
	char *server_address = NULL;
	char *image_Name = NULL;
	char *log_file = NULL;
	uint16_t rid = 0;
	char **newArgv;
	int newArgc;
	int opt, lidx;
	bool learnNewServers = true;
	bool single_thread = false;
	struct fuse_chan *ch;
	char *mountpoint;
	int foreground = 0;

	if ( argc <= 1 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "--usage" ) == 0 ) {
		printUsage( argv[0], 0 );
	}

	// TODO Make log mask configurable
	log_setConsoleMask( 65535 );
	log_setConsoleTimestamps( true );
	log_setFileMask( 65535 );

	newArgv = calloc( argc + 10, sizeof( char* ) );
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
			rid = (uint16_t)atoi( optarg );
			break;
		case 'o':
			newArgv[newArgc++] = "-o";
			newArgv[newArgc++] = optarg;
			if ( strstr( optarg, "use_ino" ) != NULL ) {
				logadd( LOG_WARNING, "************************" );
				logadd( LOG_WARNING, "* WARNING: use_ino mount option is unsupported, use at your own risk!" );
				logadd( LOG_WARNING, "************************" );
			}
			if ( strstr( optarg, "intr" ) != NULL ) {
				logadd( LOG_WARNING, "************************" );
				logadd( LOG_WARNING, "* WARNING: intr mount option is unsupported, use at your own risk!" );
				logadd( LOG_WARNING, "************************" );
			}
			break;
		case 'l':
			log_file = optarg;
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
			foreground = 1;
			break;
		case 's':
			single_thread = true;
			break;
		case 'S':
			learnNewServers = false;
			break;
		case 'f':
			foreground = 1;
			break;
		default:
			printUsage( argv[0], EXIT_FAILURE );
		}
	}

	if ( optind >= argc ) { // Missing mount point
		printUsage( argv[0], EXIT_FAILURE );
	}

	if ( server_address == NULL || image_Name == NULL ) {
		printUsage( argv[0], EXIT_FAILURE );
	}

	if ( log_file != NULL ) {
		if ( !log_openLogFile( log_file ) ) {
			logadd( LOG_WARNING, "Could not open log file at '%s'", log_file );
		}
	}

	// Prepare our handler
	struct sigaction newHandler;
	memset( &newHandler, 0, sizeof( newHandler ) );
	newHandler.sa_handler = &noopSigHandler;
	sigemptyset( &newHandler.sa_mask );
	sigaction( SIGHUP, &newHandler, NULL );
	sigset_t sigmask;
	sigemptyset( &sigmask );
	sigaddset( &sigmask, SIGHUP );
	pthread_sigmask( SIG_BLOCK, &sigmask, NULL );

	if ( !connection_init( server_address, image_Name, rid, learnNewServers ) ) {
		logadd( LOG_ERROR, "Could not connect to any server. Bye.\n" );
		return EXIT_FAILURE;
	}
	imageSize = connection_getImageSize();

	/* initialize benchmark variables */
	logInfo.receivedBytes = 0;
	logInfo.imageSize = imageSize;
	logInfo.imageBlockCount = ( imageSize + 4095 ) / 4096;
	if ( useDebug ) {
		logInfo.blockRequestCount = calloc( logInfo.imageBlockCount, sizeof(uint8_t) );
	} else {
		logInfo.blockRequestCount = NULL;
	}

	// Since dnbd3 is always read only and the remote image will not change
	newArgv[newArgc++] = "-o";
	newArgv[newArgc++] = "ro,default_permissions";
	// Mount point goes last
	newArgv[newArgc++] = argv[optind];

	printf( "ImagePathName: /%s\nFuseArgs:", IMAGE_NAME );
	for ( int i = 0; i < newArgc; ++i ) {
		printf( " '%s'", newArgv[i] );
	}
	putchar( '\n' );
	clock_gettime( CLOCK_REALTIME, &startupTime );
	owner = getuid();

	// Fuse lowlevel loop
	struct fuse_args args = FUSE_ARGS_INIT( newArgc, newArgv );
	int fuse_err = 1;
	if ( fuse_parse_cmdline( &args, &mountpoint, NULL, NULL ) == -1 ) {
		logadd( LOG_ERROR, "FUSE: Parsing command line failed" );
	} else if ( ( ch = fuse_mount( mountpoint, &args ) ) == NULL ) {
		logadd( LOG_ERROR, "Mounting file system failed" );
	} else {
		_fuseSession = fuse_lowlevel_new( &args, &image_oper, sizeof( image_oper ), NULL );
		if ( _fuseSession == NULL ) {
			logadd( LOG_ERROR, "Could not initialize fuse session" );
		} else {
			if ( fuse_set_signal_handlers( _fuseSession ) == -1 ) {
				logadd( LOG_ERROR, "Could not install fuse signal handlers" );
			} else {
				fuse_session_add_chan( _fuseSession, ch );
				fuse_daemonize( foreground );
				if ( single_thread ) {
					fuse_err = fuse_session_loop( _fuseSession );
				} else {
					fuse_err = fuse_session_loop_mt( _fuseSession ); //MT produces errors (race conditions) in libfuse and didnt improve speed at all
				}
				fuse_remove_signal_handlers( _fuseSession );
				fuse_session_remove_chan( ch );
			}
			fuse_session_destroy( _fuseSession );
			_fuseSession = NULL;
		}
		fuse_unmount( mountpoint, ch );
	}
	fuse_opt_free_args( &args );
	free( newArgv );
	connection_join();
	logadd( LOG_DEBUG1, "Terminating. FUSE REPLIED: %d\n", fuse_err );
	return fuse_err;
}
