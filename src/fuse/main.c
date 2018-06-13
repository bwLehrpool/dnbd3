/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 *
 * Changed by Stephan Schwaer
 * */

#include "connection.h"
#include "helper.h"
#include "../shared/protocol.h"
#include "../shared/log.h"

#define FUSE_USE_VERSION 30
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/* for printing uint */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

#define debugf(...) do { logadd( LOG_DEBUG1, __VA_ARGS__ ); } while (0)

static const char * const IMAGE_PATH = "/img";
static const char * const STATS_PATH = "/status";

static uint64_t imageSize;
/* Debug/Benchmark variables */
static bool useDebug = false;
static log_info logInfo;
static struct timespec startupTime;
static uid_t owner;
static bool keepRunning = true;
static void (*fuse_sigIntHandler)(int) = NULL;
static void (*fuse_sigTermHandler)(int) = NULL;
static struct fuse_operations dnbd3_fuse_no_operations;

#define SIGPOOLSIZE 6
static pthread_spinlock_t sigLock;
static dnbd3_signal_t *signalPool[SIGPOOLSIZE];
static dnbd3_signal_t **sigEnd = signalPool + SIGPOOLSIZE;
static void signalInit()
{
	pthread_spin_init( &sigLock, PTHREAD_PROCESS_PRIVATE );
	for ( size_t i = 0; i < SIGPOOLSIZE; ++i ) {
		signalPool[i] = NULL;
	}
}
static inline dnbd3_signal_t *signalGet()
{
	pthread_spin_lock( &sigLock );
	for ( dnbd3_signal_t **it = signalPool; it < sigEnd; ++it ) {
		if ( *it != NULL ) {
			dnbd3_signal_t *ret = *it;
			*it = NULL;
			pthread_spin_unlock( &sigLock );
			return ret;
		}
	}
	pthread_spin_unlock( &sigLock );
	return signal_newBlocking();
}
static inline void signalPut(dnbd3_signal_t *signal)
{
	pthread_spin_lock( &sigLock );
	for ( dnbd3_signal_t **it = signalPool; it < sigEnd; ++it ) {
		if ( *it == NULL ) {
			*it = signal;
			pthread_spin_unlock( &sigLock );
			return;
		}
	}
	pthread_spin_unlock( &sigLock );
	signal_close( signal );
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
		clock_gettime( CLOCK_REALTIME, &stbuf->st_mtim );
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
		return (int)connection_printStats( buf, size );
	}
	char buffer[4096];
	int ret = (int)connection_printStats( buffer, sizeof buffer );
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
	if ( size > __INT_MAX__ ) {
		// fuse docs say we MUST fill the buffer with exactly size bytes and return size,
		// otherwise the buffer will we padded with zeros. Since the return value is just
		// an int, we could not properly fulfill read requests > 2GB. Since there is no
		// mention of a guarantee that this will never happen, better add a safety check.
		// Way to go fuse.
		return -EIO;
	}
	if ( path[1] == STATS_PATH[1] ) {
		return fillStatsFile( buf, size, offset );
	}

	if ( (uint64_t)offset >= imageSize ) {
		return -EIO;
	}

	if ( offset + size > imageSize ) {
		size = imageSize - offset;
	}

	if ( useDebug ) {
		/* count the requested blocks */
		uint64_t startBlock = offset / ( 4096 );
		const uint64_t endBlock = ( offset + size - 1 ) / ( 4096 );

		for ( ; startBlock <= endBlock; startBlock++ ) {
			++logInfo.blockRequestCount[startBlock];
		}
	}

	dnbd3_async_t request;
	request.buffer = buf;
	request.length = (uint32_t)size;
	request.offset = offset;
	request.signal = signalGet();

	if ( !connection_read( &request ) ) {
		signalPut( request.signal );
		return -EINVAL;
	}
	while ( !request.finished ) {
		int ret = signal_wait( request.signal, 5000 );
		if ( !keepRunning ) {
			connection_close();
			break;
		}
		if ( ret < 0 ) {
			debugf( "fuse_read signal wait returned %d", ret );
		}
	}
	signalPut( request.signal );
	if ( request.success ) {
		return request.length;
	} else {
		return -EIO;
	}
}

static void image_sigHandler(int signum) {
	keepRunning = false;
	if ( signum == SIGINT && fuse_sigIntHandler != NULL ) {
		fuse_sigIntHandler(signum);
	}
	if ( signum == SIGTERM && fuse_sigTermHandler != NULL ) {
		fuse_sigTermHandler(signum);
	}
}

static void* image_init(struct fuse_conn_info *conn UNUSED)
{
	if ( !connection_initThreads() ) {
		logadd( LOG_ERROR, "Could not initialize threads for dnbd3 connection, exiting..." );
		exit( EXIT_FAILURE );
	}
	// Prepare our handler
	struct sigaction newHandler;
	memset( &newHandler, 0, sizeof(newHandler) );
	newHandler.sa_handler = &image_sigHandler;
	sigemptyset( &newHandler.sa_mask );
	struct sigaction oldHandler;
	// Retrieve old handlers when setting
	sigaction( SIGINT, &newHandler, &oldHandler );
	fuse_sigIntHandler = oldHandler.sa_handler;
	logadd( LOG_DEBUG1, "Previous SIGINT handler was %p", (void*)(uintptr_t)fuse_sigIntHandler );
	sigaction( SIGTERM, &newHandler, &oldHandler );
	fuse_sigTermHandler = oldHandler.sa_handler;
	logadd( LOG_DEBUG1, "Previous SIGTERM handler was %p", (void*)(uintptr_t)fuse_sigIntHandler );
	return NULL;
}

/* close the connection */
static void image_destroy(void *private_data UNUSED)
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
	.init = image_init,
	.destroy = image_destroy,
};

static void printVersion()
{
	char *arg[] = { "foo", "-V" };
	printf( "DNBD3-Fuse Version 1.2.3.4, protocol version %d\n", (int)PROTOCOL_VERSION );
	fuse_main( 2, arg, &dnbd3_fuse_no_operations, NULL );
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
	printf( "   -l --log        Write log to given location\n" );
	printf( "   -o --option     Mount options to pass to libfuse\n" );
	printf( "   -d --debug      Don't fork and print debug output (fuse > stderr, dnbd3 > stdout)\n" );
	fuse_main( 2, arg, &dnbd3_fuse_no_operations, NULL );
	exit( exitCode );
}

static const char *optString = "h:i:r:l:o:HvVdtsf";
static const struct option longOpts[] = {
        { "host", required_argument, NULL, 'h' },
        { "image", required_argument, NULL, 'i' },
        { "rid", required_argument, NULL, 'r' },
        { "log", required_argument, NULL, 'l' },
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
	char *log_file = NULL;
	uint16_t rid = 0;
	char **newArgv;
	int newArgc;
	int opt, lidx;
	bool testOpt = false;

	if ( argc <= 1 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "--usage" ) == 0 ) {
		printUsage( argv[0], 0 );
	}

	// TODO Make log mask configurable
	log_setConsoleMask( 65535 );
	log_setConsoleTimestamps( true );
	log_setFileMask( 65535 );

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

	if ( log_file != NULL ) {
		if ( !log_openLogFile( log_file ) ) {
			logadd( LOG_WARNING, "Could not open log file at '%s'", log_file );
		}
	}

	if ( !connection_init( server_address, image_Name, rid ) ) {
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
	newArgv[newArgc++] = "ro,auto_cache,default_permissions";
	// Mount point goes last
	newArgv[newArgc++] = argv[optind];

	printf( "ImagePathName: %s\nFuseArgs:",IMAGE_PATH );
	for ( int i = 0; i < newArgc; ++i ) {
		printf( " '%s'", newArgv[i] );
	}
	putchar('\n');
	clock_gettime( CLOCK_REALTIME, &startupTime );
	owner = getuid();
	signalInit();
	return fuse_main( newArgc, newArgv, &image_oper, NULL );
}
