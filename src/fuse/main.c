/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 *
 * Changed by Stephan Schwaer
 * FUSE lowlevel by Alan Reichert
 * */

#include "main.h"
#include "cowfile.h"
#include "connection.h"
#include "helper.h"
#include <dnbd3/version.h>
#include <dnbd3/build.h>
#include <dnbd3/shared/protocol.h>
#include <dnbd3/shared/log.h>
#include <dnbd3/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
/* for printing uint */
//#define __STDC_FORMAT_MACROS
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
bool useCow = false;
bool cow_merge_after_upload = false;
static atomic_uint_fast64_t imageSize;
static atomic_uint_fast64_t *imageSizePtr =&imageSize;

/* Debug/Benchmark variables */
static bool useDebug = false;
static log_info logInfo;
static struct timespec startupTime;
static uid_t owner;
static int reply_buf_limited( fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize );
static void fillStatsFile( fuse_req_t req, size_t size, off_t offset );
static void image_destroy( void *private_data );
static void image_ll_init( void *userdata, struct fuse_conn_info *conn );
static void image_ll_lookup( fuse_req_t req, fuse_ino_t parent, const char *name );
static void image_ll_open( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );
static void image_ll_readdir( fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi );
static void image_ll_read( fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi );
static void image_ll_write( fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi );
static void image_ll_setattr( fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi );
static int image_stat( fuse_ino_t ino, struct stat *stbuf );
static void printUsage( char *argv0, int exitCode );
static void printVersion();

static int image_stat( fuse_ino_t ino, struct stat *stbuf )
{
	switch ( ino ) {
	case INO_ROOT:
		stbuf->st_mode = S_IFDIR | 0550;
		if( useCow ) {
			stbuf->st_mode = S_IFDIR | 0770;
		}
		stbuf->st_nlink = 2;
		stbuf->st_mtim = startupTime;
		break;
	case INO_IMAGE:
		if ( useCow ) {
			stbuf->st_mode = S_IFREG | 0660;
		} else {
			stbuf->st_mode = S_IFREG | 0440;
		}
		stbuf->st_nlink = 1;
		stbuf->st_size = *imageSizePtr;
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

void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi )
{
	struct stat stbuf = { 0 };
	( void ) fi;

	if ( image_stat( ino, &stbuf ) == -1 ) {
		fuse_reply_err( req, ENOENT );
	} else {
		fuse_reply_attr( req, &stbuf, ino == INO_IMAGE ? 1200 : 1 ); // seconds validity timeout
	}
}

static void image_ll_lookup( fuse_req_t req, fuse_ino_t parent, const char *name )
{
	( void )parent;

	if ( strcmp( name, IMAGE_NAME ) == 0 || strcmp( name, STATS_NAME ) == 0 ) {
		struct fuse_entry_param e = { 0 };
		if ( strcmp( name, IMAGE_NAME ) == 0 ) {
			e.ino = INO_IMAGE;
			e.attr_timeout = e.entry_timeout = 1200;
		} else {
			e.ino = INO_STATS;
			e.attr_timeout = e.entry_timeout = 0;
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
	} else if ( ( fi->flags & 3 ) != O_RDONLY && !useCow ) {
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

	if ( size == 0 || size > UINT32_MAX ) {
		fuse_reply_err( req, 0 );
		return;
	}

	if ( (uint64_t)offset >= *imageSizePtr ) {
		fuse_reply_err( req, 0 );
		return;
	}
	if ( offset + size > *imageSizePtr ) {
		size = *imageSizePtr - offset;
	}

	if ( useCow ) {
		cowfile_read(req, size, offset);
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


	dnbd3_async_parent_t *parent = malloc( sizeof(dnbd3_async_parent_t) + size );
	parent->request.length = (uint32_t)size;
	parent->request.offset = offset;
	parent->request.fuse_req = req;

	if ( !connection_read( &parent->request ) ) {
		fuse_reply_err( req, EIO );
		free( parent );
	}
}

static void noopSigHandler( int signum )
{
	(void)signum;
}

static void image_ll_init( void *userdata UNUSED, struct fuse_conn_info *conn UNUSED )
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


static void image_ll_write( fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi )
{
	assert( ino == INO_STATS || ino == INO_IMAGE );

	( void )fi;

	if ( ino == INO_STATS ) {
		fuse_reply_err( req, EACCES );
		return;
	}

	cow_request_t* cowRequest = malloc(sizeof(cow_request_t));
	cowRequest->fuseRequestSize = size;
	cowRequest->workCounter = ATOMIC_VAR_INIT( 1 );
	cowRequest->writeBuffer = buf;
	cowRequest->readBuffer = NULL;
	cowRequest->errorCode = ATOMIC_VAR_INIT( 0 );
	cowRequest->fuseRequestOffset = off;
	cowRequest->bytesWorkedOn = ATOMIC_VAR_INIT( 0 );
	cowfile_write(req, cowRequest, off, size);
}

static void image_ll_setattr( fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi )
{
	if ( ino != INO_IMAGE ) {
		fuse_reply_err( req, EACCES );
		return;
	}
	if (to_set & FUSE_SET_ATTR_SIZE) {
		cowfile_setSize( req,   attr->st_size, ino, fi);
	}
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

/* map the implemented fuse operations with copy on write */
static struct fuse_lowlevel_ops image_oper_cow = {
	.lookup = image_ll_lookup,
	.getattr = image_ll_getattr,
	.readdir = image_ll_readdir,
	.open = image_ll_open,
	.read = image_ll_read,
	.init = image_ll_init,
	.destroy = image_destroy,
	.write = image_ll_write,
	.setattr = image_ll_setattr,
};


static void printVersion()
{
	char *arg[] = { "foo", "-V" };
	printf( "dnbd3-fuse version: %s\n", DNBD3_VERSION_LONG );
	printf( "Built: %s\n", DNBD3_BUILD_DATE );
	printf( "Protocol version: %d\n", (int)PROTOCOL_VERSION );
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
	printf( "Usage:   %s [--debug] [--option mountOpts] --host <serverAddress(es)> --image <imageName> [--rid revision] <mountPoint>\n", argv0 );
	printf( "Or:      %s [-d] [-o mountOpts] -h <serverAddress(es)> -i <imageName> [-r revision] <mountPoint>\n", argv0 );
	printf( "For cow: %s [-d] [-o mountOpts] -h <serverAddress(es)> -i <imageName> [-r revision] -c <path> -C <cowServerAddress> -m [--cow-stats-stdout] [--cow-stats-file] <mountPoint>\n", argv0 );
	printf( "   -d --debug      Don't fork, write stats file, and print debug output (fuse -> stderr, dnbd3 -> stdout)\n" );
	printf( "   -f              Don't fork (dnbd3 -> stdout)\n" );
	printf( "   -h --host       List of space separated hosts to use\n" );
	printf( "   -i --image      Remote image name to request\n" );
	printf( "   -l --log        Write log to given location\n" );
	printf( "   -o --option     Mount options to pass to libfuse\n" );
	printf( "   -r --rid        Revision to use (omit or pass 0 for latest)\n" );
	printf( "   -S --sticky     Use only servers from command line (no learning from servers)\n" );
	printf( "   -s              Single threaded mode\n" );
	printf( "   -c              Enables cow, creates the cow files at given location\n" );
	printf( "   -L              Loads the cow files from the given location\n" );
	printf( "   -C              Host address of the cow server\n" );
	printf( "--upload-uuid <id> Use provided UUID as upload session id instead of asking server/loading from file\n" );
	printf( "--cow-stats-stdout prints the cow status in stdout\n" );
	printf( "--cow-stats-file   creates and updates the cow status file\n" );
	printf( "   -m --merge      tell server to merge and create new revision on exit\n" );
	exit( exitCode );
}

static const char *optString = "dfHh:i:l:o:r:SsVvc:L:C:m";
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
	{ "cow", required_argument, NULL, 'c' },
	{ "loadcow", required_argument, NULL, 'L' },
	{ "cowServer", required_argument, NULL, 'C' },
	{ "merge", no_argument, NULL, 'm' },
	{ "upload-uuid", required_argument, NULL, 'uuid' },
	{ "cow-stats-stdout", no_argument, NULL, 'sout' },
	{ "cow-stats-file", no_argument, NULL, 'sfil' },
	{ 0, 0, 0, 0 }
};

int main( int argc, char *argv[] )
{
	char *server_address = NULL;
	char *cow_server_address = NULL;
	char *image_Name = NULL;
	char *log_file = NULL;
	cow_merge_after_upload  = false;
	uint16_t rid = 0;
	char **newArgv;
	int newArgc;
	int opt, lidx;
	bool learnNewServers = true;
	bool single_thread = false;
	struct fuse_chan *ch;
	char *mountpoint;
	int foreground = 0;
	char *cow_file_path = NULL;
	bool loadCow = false;
	bool sStdout = false;
	bool sFile = false;
	const char *cowUuidOverride = NULL;

	log_init();

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
		case 'c':
			cow_file_path = optarg;
			useCow = true;
			break;
		case 'C':
			cow_server_address = optarg;
			break;
		case 'm':
			cow_merge_after_upload = true;
			break;
		case 'L':
			cow_file_path = optarg;
			useCow = true;
			loadCow = true;
			break;
		case 'sout':
			sStdout = true;
			break;
		case 'sfil':
			sFile = true;
			break;
		case 'uuid':
			cowUuidOverride = optarg;
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
	if( useCow && cow_server_address == NULL ) {
		printf( "for -c you also need a cow server address. Please also use -C\n" );
		printUsage( argv[0], EXIT_FAILURE );
	}
	if( cow_merge_after_upload && !useCow ) {
		printf( "-m only works if cow is enabled. \n" );
		printUsage( argv[0], EXIT_FAILURE );
	}
	if ( loadCow ) {
		if( cow_server_address == NULL ) {
			printf( "for -L you also need a cow server address. Please also use -C\n" );
			printUsage( argv[0], EXIT_FAILURE );
		}

		if ( !cowfile_load( cow_file_path, &imageSizePtr, cow_server_address, sStdout, sFile, cowUuidOverride ) ) {
			return EXIT_FAILURE;
		}
	}
	do {
		// The empty handler prevents fuse from registering its own handler
		struct sigaction newHandler = { .sa_handler = &noopSigHandler };
		sigemptyset( &newHandler.sa_mask );
		sigaction( SIGHUP, &newHandler, NULL );
	} while ( 0 );
		if ( useCow ) {
			sigset_t sigmask;
			sigemptyset( &sigmask );
			sigaddset( &sigmask, SIGQUIT ); // Block here and unblock in cow as abort signal
			pthread_sigmask( SIG_BLOCK, &sigmask, NULL );
		}

	if ( !connection_init( server_address, image_Name, rid, learnNewServers ) ) {
		logadd( LOG_ERROR, "Could not connect to any server. Bye.\n" );
		return EXIT_FAILURE;
	}
	imageSize = connection_getImageSize();

	/* initialize benchmark variables */
	logInfo.receivedBytes = 0;
	logInfo.imageSize = *imageSizePtr;
	logInfo.imageBlockCount = ( *imageSizePtr + 4095 ) / 4096;
	if ( useDebug ) {
		logInfo.blockRequestCount = calloc( logInfo.imageBlockCount, sizeof(uint8_t) );
	} else {
		logInfo.blockRequestCount = NULL;
	}
	
	newArgv[newArgc++] = "-o";
	if ( useCow ) {
		newArgv[newArgc++] = "default_permissions";
	} else {
		newArgv[newArgc++] = "ro,default_permissions";
	}
	// Mount point goes last
	newArgv[newArgc++] = argv[optind];

	printf( "ImagePathName: /%s\nFuseArgs:", IMAGE_NAME );
	for ( int i = 0; i < newArgc; ++i ) {
		printf( " '%s'", newArgv[i] );
	}
	putchar( '\n' );
	clock_gettime( CLOCK_REALTIME, &startupTime );
	owner = getuid();

	if ( useCow & !loadCow) {
		if( !cowfile_init( cow_file_path, connection_getImageName(), connection_getImageRID(),  &imageSizePtr, cow_server_address,  sStdout, sFile, cowUuidOverride ) ) {
			return EXIT_FAILURE;
		}
	}

	// Fuse lowlevel loop
	struct fuse_args args = FUSE_ARGS_INIT( newArgc, newArgv );
	int fuse_err = 1;
	if ( fuse_parse_cmdline( &args, &mountpoint, NULL, NULL ) == -1 ) {
		logadd( LOG_ERROR, "FUSE: Parsing command line failed" );
	} else if ( ( ch = fuse_mount( mountpoint, &args ) ) == NULL ) {
		logadd( LOG_ERROR, "Mounting file system failed" );
	} else {
		if(useCow){
			_fuseSession = fuse_lowlevel_new( &args, &image_oper_cow, sizeof( image_oper_cow ), NULL );
		} else{
			_fuseSession = fuse_lowlevel_new( &args, &image_oper, sizeof( image_oper ), NULL );
		}
		if ( _fuseSession == NULL ) {
			logadd( LOG_ERROR, "Could not initialize fuse session" );
		} else {
			fuse_session_add_chan( _fuseSession, ch );
			// Do not spawn any threads before we daemonize, they'd die at this point
			fuse_daemonize( foreground );
			if ( fuse_set_signal_handlers( _fuseSession ) == -1 ) {
				logadd( LOG_WARNING, "Could not install fuse signal handlers" );
			}
			if ( useCow ) {
				if ( !cowfile_startBackgroundThreads() ) {
					logadd( LOG_ERROR, "Could not start cow background threads" );
				}
			}
			if ( single_thread ) {
				fuse_err = fuse_session_loop( _fuseSession );
			} else {
				fuse_err = fuse_session_loop_mt( _fuseSession ); //MT produces errors (race conditions) in libfuse and didnt improve speed at all
			}
			fuse_remove_signal_handlers( _fuseSession );
			fuse_session_remove_chan( ch );
			fuse_session_destroy( _fuseSession );
			_fuseSession = NULL;
		}
		fuse_unmount( mountpoint, ch );
		if( useCow ) {
			cowfile_close();
		}
	}
	fuse_opt_free_args( &args );
	free( newArgv );
	connection_join();
	logadd( LOG_DEBUG1, "Terminating. FUSE REPLIED: %d\n", fuse_err );
	return fuse_err;
}

void main_shutdown(void)
{
	fuse_session_exit( _fuseSession );
	// TODO: Figure out why this doesn't wake up the fuse mainloop.
	// For now, just send SIGQUIT followed by SIGTERM....
	kill( 0, SIGINT );
}
