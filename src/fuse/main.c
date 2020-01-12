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


static const char * const IMAGE_PATH = "/img";
static const char *IMAGE_NAME = "img";
static const char *STATS_NAME = "status";

static uint64_t imageSize;
/* Debug/Benchmark variables */
static bool useDebug = false;
static log_info logInfo;
static struct timespec startupTime;
static uid_t owner;
static void (*fuse_sigIntHandler)(int) = NULL;
static void (*fuse_sigTermHandler)(int) = NULL;

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize);
static int fillStatsFile(char *buf, size_t size, off_t offset);
static void image_destroy(void *private_data);
static void image_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void image_ll_init(void *userdata, struct fuse_conn_info *conn);
static void image_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
static void image_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void image_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
static void image_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi);
static int image_stat(fuse_ino_t ino, struct stat *stbuf);
static void printUsage(char *argv0, int exitCode);
static void printVersion();

static int image_stat(fuse_ino_t ino, struct stat *stbuf)
{
	stbuf->st_ctim = stbuf->st_atim = stbuf->st_mtim = startupTime;
	stbuf->st_uid = owner;
	stbuf->st_ino = ino;
	switch (ino) {
	case 1:
		stbuf->st_mode = S_IFDIR | 0550;
		stbuf->st_nlink = 2;
		break;

	case 2:
		stbuf->st_mode = S_IFREG | 0440;
		stbuf->st_nlink = 1;
		stbuf->st_size = imageSize;
		break;
	case 3:
		stbuf->st_mode = S_IFREG | 0440;
		stbuf->st_nlink = 1;
		stbuf->st_size = 4096;
		clock_gettime( CLOCK_REALTIME, &stbuf->st_mtim );
		break;

	default:
		return -1;
	}
	return 0;
}

static void image_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void) fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (image_stat(ino, &stbuf) == -1)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &stbuf, 1.0); // 1.0 seconds validity timeout
}

static void image_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;

	if (strcmp(name, IMAGE_NAME) == 0 || strcmp(name, STATS_NAME) == 0) {
		memset(&e, 0, sizeof(e));
		if (strcmp(name, IMAGE_NAME) == 0) e.ino = 2;
		else e.ino = 3;
		e.attr_timeout = 1.0;
		e.entry_timeout = 1.0;
		image_stat(e.ino, &e.attr);

		fuse_reply_entry(req, &e);
	}
	else fuse_reply_err(req, ENOENT);
}

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;
	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size);
	return;
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize)
{
	if (off < bufsize)
		return fuse_reply_buf(req, buf + off, min(bufsize - off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

static void image_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	(void) fi;

	if (ino != 1)
		fuse_reply_err(req, ENOTDIR);
	else {
		struct dirbuf b;

		memset(&b, 0, sizeof(b));
		dirbuf_add(req, &b, ".", 1);
		dirbuf_add(req, &b, "..", 1);
		dirbuf_add(req, &b, IMAGE_NAME, 2);
		dirbuf_add(req, &b, STATS_NAME, 3);
		reply_buf_limited(req, b.p, b.size, off, size);
		free(b.p);
	}
}

static void image_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	if (ino != 2 && ino != 3)
		fuse_reply_err(req, EISDIR);
	else if ((fi->flags & 3) != O_RDONLY)
		fuse_reply_err(req, EACCES);
	else {
		// auto caching 
		fi->keep_cache = 1;
		fuse_reply_open(req, fi);
	}
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

static void image_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
	assert(ino == 2 || ino == 3);

	(void)fi;
	int len = 0;
	char *buf = NULL;

	if (size > __INT_MAX__)
	{
		// fuse docs say we MUST fill the buffer with exactly size bytes and return size,
		// otherwise the buffer will we padded with zeros. Since the return value is just
		// an int, we could not properly fulfill read requests > 2GB. Since there is no
		// mention of a guarantee that this will never happen, better add a safety check.
		// Way to go fuse.
		// return -EIO;
		fuse_reply_err(req, EIO);
	}
	if (ino == 3)
	{
		buf = (char *)malloc(4096); // they use 4096 byte buffer in fillStatsFile() for the status-file
		len = fillStatsFile(buf, size, offset);
		fuse_reply_buf(req, buf, len);
		free(buf);
		buf = NULL;
	}

	if ((uint64_t)offset >= imageSize)
	{
		fuse_reply_err(req, 0);
	}

	if (offset + size > imageSize)
	{
		size = imageSize - offset;
	}

	if (useDebug)
	{
		uint64_t startBlock = offset / (4096);
		const uint64_t endBlock = (offset + size - 1) / (4096);

		for (; startBlock <= endBlock; startBlock++)
		{
			++logInfo.blockRequestCount[startBlock];
		}
	}
	if (!keepRunning) connection_close();
	if (ino == 2 && size != 0) // with size == 0 there is nothing to do
	{
		dnbd3_async_t *request = malloc(sizeof(dnbd3_async_t));
		request->length = (uint32_t)size;
		request->offset = offset;
		request->fuse_req = req;

		if (!connection_read(request)) fuse_reply_err(req, EINVAL);
	}
}

static void image_sigHandler(int signum) {
	int temp_errno = errno; // Threadsanitizer: don't spoil errno
	if ( signum == SIGINT && fuse_sigIntHandler != NULL ) {
		keepRunning = false;
		fuse_sigIntHandler(signum);
	}
	if ( signum == SIGTERM && fuse_sigTermHandler != NULL ) {
		keepRunning = false;
		fuse_sigTermHandler(signum);
	}
	errno = temp_errno;
}

static void image_ll_init(void *userdata, struct fuse_conn_info *conn)
{
	(void) userdata;
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
	struct fuse_args args = FUSE_ARGS_INIT(2, arg);
	fuse_parse_cmdline(&args, NULL, NULL, NULL);
	exit( 0 );
}

static void printUsage(char *argv0, int exitCode)
{
	char *arg[] = { argv0, "-h" };
	struct fuse_args args = FUSE_ARGS_INIT(2, arg);
	fuse_parse_cmdline(&args, NULL, NULL, NULL);
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

int main(int argc, char *argv[])
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
	int fuse_err;

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
			foreground = 1;
			break;
		case 's':
			single_thread = true;
			break;
		case 'S':
			learnNewServers = false;
			break;
		case 'f':
			newArgv[newArgc++] = "-f";
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

	printf( "ImagePathName: %s\nFuseArgs:",IMAGE_PATH );
	for ( int i = 0; i < newArgc; ++i ) {
		printf( " '%s'", newArgv[i] );
	}
	putchar('\n');
	clock_gettime( CLOCK_REALTIME, &startupTime );
	owner = getuid();

	// Fuse lowlevel loop
	struct fuse_args args = FUSE_ARGS_INIT(newArgc, newArgv);
	if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 && (ch = fuse_mount(mountpoint, &args)) != NULL) {
		struct fuse_session *se;

		se = fuse_lowlevel_new(&args, &image_oper, sizeof(image_oper), NULL);
		if (se != NULL) {
			if (fuse_set_signal_handlers(se) != -1) {
				fuse_session_add_chan(se, ch);
				//fuse_daemonize(foreground);
				if (single_thread) fuse_err = fuse_session_loop(se);
				else fuse_err = fuse_session_loop_mt(se);  //MT produces errors (race conditions) in libfuse and didnt improve speed at all
				fuse_remove_signal_handlers(se);
				fuse_session_remove_chan(ch);
			}
			fuse_session_destroy(se);
		}
		fuse_unmount(mountpoint, ch);
	}
	fuse_opt_free_args(&args);
	free(newArgv);
	logadd( LOG_DEBUG1, "Terminating. FUSE REPLIED: %d\n", fuse_err);
	return fuse_err;
}
