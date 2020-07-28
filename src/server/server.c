		/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
 *
 * This file may be licensed under the terms of of the
 * GNU General Public License Version 2 (the ``GPL'').
 *
 * Software distributed under the License is distributed
 * on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied. See the GPL for the specific language
 * governing rights and limitations.
 *
 * You should have received a copy of the GPL along with this
 * program. If not, go to http://www.gnu.org/licenses/gpl.html
 * or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "server.h"
#include "helper.h"

#include "locks.h"
#include "image.h"
#include "uplink.h"
#include "net.h"
#include "altservers.h"
#include "integrity.h"
#include "threadpool.h"
#include "rpc.h"
#include "fuse.h"

#include "../version.h"
#include "../shared/sockhelper.h"
#include "../shared/timing.h"

#include <signal.h>
#include <getopt.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>

#define LONGOPT_CRC4       1000
#define LONGOPT_ASSERT     1001
#define LONGOPT_CREATE     1002
#define LONGOPT_REVISION   1003
#define LONGOPT_SIZE       1004
#define LONGOPT_ERRORMSG   1005

typedef struct _job job_t;

struct _job {
	job_t *next;
	void *(*startRoutine)(void *);
	void *arg;
	ticks dueDate;
	int intervalSecs;
};

static job_t *jobHead;
static _Atomic(job_t *) newJob;
static bool hasTimerThread = false;
static pthread_t timerThread;

static pid_t mainPid;
static pthread_t mainThread;

#define DEFAULT_TIMER_TIMEOUT (60)

static poll_list_t *listeners = NULL;

/**
 * Time the server was started
 */
static ticks startupTime;
static bool sigReload = false, sigLogCycle = false;

/**
 * Copied to in signal handler so we can print info
 * later on
 */
static siginfo_t lastSignal;

void printSignal();

static poll_list_t* setupNetwork(char *bindAddress);

static dnbd3_client_t* dnbd3_prepareClient(struct sockaddr_storage *client, int fd);

static void dnbd3_handleSignal(int signum);

static void dnbd3_handleSignal2(int signum, siginfo_t *info, void *data);

static void* server_asyncImageListLoad(void *data);

static void* timerMainloop(void*);

static int handlePendingJobs(void);

static void queueJobInternal(job_t *job);

/**
 * Print help text for usage instructions
 */
void dnbd3_printHelp(char *argv_0)
{
	printf( "Version: %s\n\n", VERSION_STRING );
	printf( "Usage: %s [OPTIONS]...\n", argv_0 );
	printf( "Start the DNBD3 server\n" );
	printf( "-c or --config      Configuration directory (default /etc/dnbd3-server/)\n" );
#ifdef BUILD_SERVER_FUSE
	printf( "-m or --mount       FUSE mount point\n ");
#endif
	printf( "-n or --nodaemon    Start server in foreground\n" );
	printf( "-b or --bind        Local Address to bind to\n" );
	printf( "-h or --help        Show this help text and quit\n" );
	printf( "-v or --version     Show version and quit\n" );
	printf( "\nManagement functions:\n" );
	printf( "--crc [image-file]  Generate crc block list for given image\n" );
	printf( "--create [image-name] --revision [rid] --size [filesize]\n"
			"\tCreate a local empty image file with a zeroed cache-map for the specified image\n" );
	printf( "--errormsg [text]   Just serve given error message via HTTP, no service otherwise\n" );
	printf( "\n" );
	exit( 0 );
}

/**
 * Print version information
 */
void dnbd3_printVersion()
{
	printf( "Version: %s\n", VERSION_STRING );
	exit( 0 );
}

/**
 * Clean up structs, connections, write out data, then exit
 */
_Noreturn static void dnbd3_cleanup()
{
	int retries;

	_shutdown = true;
	logadd( LOG_INFO, "Cleanup..." );

	dfuse_shutdown();

	if ( hasTimerThread ) {
		pthread_kill( timerThread, SIGINT );
		thread_join( timerThread, NULL );
	}

	if ( listeners != NULL ) {
		sock_destroyPollList( listeners );
	}
	listeners = NULL;

	// Kill connection to all clients
	net_disconnectAll();

	// Disable threadpool
	threadpool_close();

	// Terminate all uplinks
	image_killUplinks();

	// Terminate integrity checker
	integrity_shutdown();

	// Wait for clients to disconnect
	net_waitForAllDisconnected();

	threadpool_waitEmpty();

	// Clean up images
	retries = 5;
	while ( !image_tryFreeAll() && --retries > 0 ) {
		logadd( LOG_INFO, "Waiting for images to free...\n" );
		sleep( 1 );
	}

	free( _basePath );
	free( _configDir );
	exit( EXIT_SUCCESS );
}

/**
 * Program entry point
 */
int main(int argc, char *argv[])
{
	int demonize = 1;
	int opt = 0;
	int longIndex = 0;
	char *paramCreate = NULL;
	char *bindAddress = NULL;
	char *errorMsg = NULL;
	char *mountDir = NULL;
	int64_t paramSize = -1;
	int paramRevision = -1;
	static const char *optString = "b:c:m:d:hnv?";
	static const struct option longOpts[] = {
			{ "config", required_argument, NULL, 'c' },
			{ "mount", required_argument, NULL, 'm' },
			{ "nodaemon", no_argument, NULL, 'n' },
			{ "reload", no_argument, NULL, 'r' },
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "bind", required_argument, NULL, 'b' },
			{ "crc", required_argument, NULL, LONGOPT_CRC4 },
			{ "assert", no_argument, NULL, LONGOPT_ASSERT },
			{ "create", required_argument, NULL, LONGOPT_CREATE },
			{ "revision", required_argument, NULL, LONGOPT_REVISION },
			{ "size", required_argument, NULL, LONGOPT_SIZE },
			{ "errormsg", required_argument, NULL, LONGOPT_ERRORMSG },
			{ 0, 0, 0, 0 }
	};

	mainPid = getpid();
	mainThread = pthread_self();
	opt = getopt_long( argc, argv, optString, longOpts, &longIndex );

	while ( opt != -1 ) {
		switch ( opt ) {
		case 'c':
			_configDir = strdup( optarg );
			break;
		case 'm':
#ifndef BUILD_SERVER_FUSE
			fprintf( "FUSE support not enabled at build time.\n" );
			return 8;
#endif
			mountDir = strdup( optarg );
			break;
		case 'n':
			demonize = 0;
			break;
		case 'h':
		case '?':
			dnbd3_printHelp( argv[0] );
			break;
		case 'v':
			dnbd3_printVersion();
			break;
		case 'b':
			bindAddress = strdup( optarg );
			break;
		case LONGOPT_CRC4:
			return image_generateCrcFile( optarg ) ? 0 : EXIT_FAILURE;
		case LONGOPT_ASSERT:
			printf( "Now leaking memory:\n" );
			char *bla = malloc( 10 );
			bla[2] = 3;
			bla = NULL;
			printf( "Testing use after free:\n" );
			char *test = malloc( 10 );
			test[0] = 1;
			free( (void*)test );
			test[1] = 2;
			printf( "Testing a failing assertion:\n" );
			assert( 4 == 5 );
			printf( "Assertion 4 == 5 seems to hold. ;-)\n" );
			return EXIT_SUCCESS;
		case LONGOPT_CREATE:
			paramCreate = strdup( optarg );
			break;
		case LONGOPT_REVISION:
			paramRevision = atoi( optarg );
			break;
		case LONGOPT_SIZE:
			paramSize = strtoll( optarg, NULL, 10 );
			break;
		case LONGOPT_ERRORMSG:
			errorMsg = strdup( optarg );
			break;
		}
		opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
	}

	// Load general config

	if ( _configDir == NULL ) _configDir = strdup( "/etc/dnbd3-server" );
	globals_loadConfig();
	if ( _basePath == NULL && errorMsg == NULL ) {
		logadd( LOG_ERROR, "Aborting, set proper basePath in %s/%s", _configDir, CONFIG_FILENAME );
		exit( EXIT_FAILURE );
	}

	timing_setBase();
	timing_get( &startupTime );

#ifdef AFL_MODE
	// ###### AFL
	//
	image_serverStartup();
	net_init();
	uplink_globalsInit();
	rpc_init();
	if ( !image_loadAll( NULL ) || _shutdown ) {
		fprintf( stderr, "Error loading images\n" );
		exit( 3 );
	}
	{
		struct sockaddr_storage client;
		memset( &client, 0, sizeof client );
		client.ss_family = AF_INET;
		dnbd3_client_t *dnbd3_client = dnbd3_prepareClient( &client, 1 );
		if ( dnbd3_client == NULL ) {
			fprintf( stderr, "New client failed\n" );
			exit( 1 );
		}
#ifdef __AFL_HAVE_MANUAL_CONTROL
		__AFL_INIT();
#endif
		net_handleNewConnection( dnbd3_client );
		exit( 0 );
	}
	//
	// ###### AFL END
#endif


	// One-shots first:

	if ( paramCreate != NULL ) {
		return image_create( paramCreate, paramRevision, paramSize ) ? 0 : EXIT_FAILURE;
	}

	// No one-shot detected, normal server operation or errormsg serving
	if ( demonize ) {
		logadd( LOG_INFO, "Forking into background, see log file for further information" );
		if ( daemon( 0, 0 ) == -1 ) {
			logadd( LOG_ERROR, "Could not daemon(): errno=%d", errno );
			exit( 1 );
		}
	}
	if ( errorMsg != NULL ) {
		setupNetwork( bindAddress );
		logadd( LOG_INFO, "Running errormsg server" );
		while ( true ) {
			const int fd = sock_accept( listeners, NULL, NULL );
			if ( fd >= 0 ) {
				rpc_sendErrorMessage( fd, errorMsg );
			} else {
				const int err = errno;
				if ( err == EINTR || err == EAGAIN ) continue;
				logadd( LOG_ERROR, "Client accept failure (err=%d)", err );
				usleep( 10000 ); // 10ms
			}
		}
		exit( 0 );
	}
	image_serverStartup();
	altservers_init();
	integrity_init();
	net_init();
	uplink_globalsInit();
	rpc_init();
	if ( mountDir != NULL && !dfuse_init( NULL, mountDir ) ) {
		logadd( LOG_ERROR, "Cannot mount fuse directory to %s", mountDir );
		dnbd3_cleanup();
		return EXIT_FAILURE;
	}
	logadd( LOG_INFO, "DNBD3 server starting...." );
	logadd( LOG_INFO, "Machine type: " ENDIAN_MODE );
	logadd( LOG_INFO, "Build Type: " TOSTRING( BUILD_TYPE ) );
	logadd( LOG_INFO, "Version: %s", VERSION_STRING );

	if ( altservers_load() < 0 ) {
		logadd( LOG_WARNING, "Could not load alt-servers. Does the file exist in %s?", _configDir );
	}

	// setup signal handler
	struct sigaction sa = {
		.sa_sigaction = dnbd3_handleSignal2,
		.sa_flags = SA_SIGINFO,
	};
	sigaction( SIGTERM, &sa, NULL );
	sigaction( SIGINT, &sa, NULL );
	sigaction( SIGUSR1, &sa, NULL );
	sigaction( SIGHUP, &sa, NULL );
	sigaction( SIGUSR2, &sa, NULL );
	signal( SIGPIPE, SIG_IGN );

	logadd( LOG_INFO, "Loading images...." );
	// Load all images in base path
	if ( !image_loadAll( NULL ) || _shutdown ) {
		if ( _shutdown ) {
			logadd( LOG_ERROR, "Received shutdown request while loading images." );
		} else {
			logadd( LOG_ERROR, "Could not load images." );
		}
		free( bindAddress );
		dnbd3_cleanup();
		return _shutdown ? 0 : 1;
	}

	// Give other threads some time to start up before accepting connections
	usleep( 100000 );

	// setup network
	listeners = setupNetwork( bindAddress );

	// Initialize thread pool
	if ( !threadpool_init( 8 ) ) {
		logadd( LOG_ERROR, "Could not init thread pool!\n" );
		dnbd3_cleanup();
		exit( EXIT_FAILURE );
	}

	logadd( LOG_INFO, "Server is ready." );

	if ( thread_create( &timerThread, NULL, &timerMainloop, NULL ) == 0 ) {
		hasTimerThread = true;
	}

	// +++++++++++++++++++++++++++++++++++++++++++++++++++ main loop
	struct sockaddr_storage client;
	socklen_t len;
	int fd;
	while ( !_shutdown ) {
		// Handle signals
		printSignal();
		if ( sigReload ) {
			sigReload = false;
			logadd( LOG_INFO, "SIGHUP received, re-scanning image directory" );
			threadpool_run( &server_asyncImageListLoad, NULL, "IMAGE_RELOAD" );
		}
		if ( sigLogCycle ) {
			sigLogCycle = false;
			logadd( LOG_INFO, "SIGUSR2 received, reopening log file..." );
			if ( log_openLogFile( NULL ) )
				logadd( LOG_INFO, "Log file has been reopened." );
			else
				logadd( LOG_WARNING, "Could not cycle log file." );
		}
		//
		len = sizeof(client);
		fd = sock_accept( listeners, &client, &len );
		if ( fd == -1 ) {
			const int err = errno;
			if ( err == EINTR || err == EAGAIN ) continue;
			logadd( LOG_ERROR, "Client accept failure (err=%d)", err );
			usleep( 10000 ); // 10ms
			continue;
		}

		dnbd3_client_t *dnbd3_client = dnbd3_prepareClient( &client, fd );
		if ( dnbd3_client == NULL ) {
			close( fd );
			continue;
		}

		if ( !threadpool_run( &net_handleNewConnection, (void *)dnbd3_client, "CLIENT" ) ) {
			logadd( LOG_ERROR, "Could not start thread for new connection." );
			free( dnbd3_client );
			continue;
		}
	}
	printSignal();
	free( bindAddress );
	dnbd3_cleanup();
	return 0;
}

void printSignal()
{
	if ( lastSignal.si_signo != 0 ) {
		logadd( LOG_INFO, "Signal %d (via %d) by pid %u, uid %u",
				lastSignal.si_signo, lastSignal.si_code,
				(unsigned int)lastSignal.si_pid, (unsigned int)lastSignal.si_uid );
		if ( lastSignal.si_pid != 0 ) {
			char buffer[500], path[100];
			snprintf( path, sizeof(path), "/proc/%u/exe", (unsigned int)lastSignal.si_pid );
			ssize_t len = readlink( path, buffer, sizeof(buffer) );
			if ( len > 0 ) {
				logadd( LOG_INFO, "%u is %.*s", (unsigned int)lastSignal.si_pid, (int)len, buffer );
			}
		}
		lastSignal.si_signo = 0;
	}
}

static poll_list_t* setupNetwork(char *bindAddress)
{
	listeners = sock_newPollList();
	if ( listeners == NULL ) {
		logadd( LOG_ERROR, "Didnt get a poll list!" );
		exit( EXIT_FAILURE );
	}
	if ( !sock_listen( listeners, bindAddress, (uint16_t)_listenPort ) ) {
		logadd( LOG_ERROR, "Could not listen on any local interface." );
		exit( EXIT_FAILURE );
	}
	return listeners;
}

/**
 * Initialize and partially populate the client struct - called when an incoming
 * connection is accepted. As this might be an HTTP request we don't initialize the
 * locks, that would happen later once we know.
 */
static dnbd3_client_t* dnbd3_prepareClient(struct sockaddr_storage *client, int fd)
{
	dnbd3_client_t *dnbd3_client = calloc( 1, sizeof(dnbd3_client_t) );
	if ( dnbd3_client == NULL ) { // This will never happen thanks to memory overcommit
		logadd( LOG_ERROR, "Could not alloc dnbd3_client_t for new client." );
		return NULL;
	}

	if ( client->ss_family == AF_INET ) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)client;
		dnbd3_client->host.type = HOST_IP4;
		memcpy( dnbd3_client->host.addr, &(v4->sin_addr), 4 );
		dnbd3_client->host.port = v4->sin_port;
	} else if ( client->ss_family == AF_INET6 ) {
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)client;
		dnbd3_client->host.type = HOST_IP6;
		memcpy( dnbd3_client->host.addr, &(v6->sin6_addr), 16 );
		dnbd3_client->host.port = v6->sin6_port;
	} else {
		logadd( LOG_ERROR, "New client has unknown address family %d, disconnecting...", (int)client->ss_family );
		free( dnbd3_client );
		return NULL;
	}
	dnbd3_client->sock = fd;
	return dnbd3_client;
}

static void dnbd3_handleSignal(int signum)
{
	if ( _shutdown ) return;
	if ( signum == SIGINT || signum == SIGTERM ) {
		_shutdown = true;
	} else if ( signum == SIGUSR1 || signum == SIGHUP ) {
		sigReload = true;
	} else if ( signum == SIGUSR2 ) {
		sigLogCycle = true;
	}
}

static void dnbd3_handleSignal2(int signum, siginfo_t *info, void *data UNUSED)
{
	if ( info->si_pid != mainPid ) { // Source is not this process
		memcpy( &lastSignal, info, sizeof(siginfo_t) ); // Copy signal info
		if ( info->si_pid != 0 && !pthread_equal( pthread_self(), mainThread ) ) {
			pthread_kill( mainThread, info->si_signo ); // And relay signal if we're not the main thread
		}
		// Source is not this process -- only then do we honor signals
		if ( pthread_equal( pthread_self(), mainThread ) ) {
			// Signal received by main thread -- handle
			dnbd3_handleSignal( signum );
		}
	}
}

uint32_t dnbd3_serverUptime()
{
	ticks now;
	timing_get( &now );
	return timing_diff( &startupTime, &now );
}

static void* server_asyncImageListLoad(void *data UNUSED)
{
	setThreadName( "img-list-loader" );
	globals_loadConfig();
	image_loadAll( NULL );
	return NULL;
}

static void* timerMainloop(void* stuff UNUSED)
{
	setThreadName( "timer" );
	while ( !_shutdown ) {
		// Handle jobs/timer events; returns timeout until next event
		int to = handlePendingJobs();
		sleep( MIN( MAX( 1, to ), DEFAULT_TIMER_TIMEOUT ) );
	}
	logadd( LOG_DEBUG1, "Timer thread done" );
	return NULL;
}

static int handlePendingJobs(void)
{
	declare_now;
	job_t *todo, **temp, *old;
	int diff;
	todo = jobHead;
	for ( temp = &todo; *temp != NULL; temp = &(*temp)->next ) {
		diff = (int)timing_diff( &now, &(*temp)->dueDate );
		if ( diff > 0 ) // Found one that's in the future
			break;
	}
	jobHead = *temp; // Make it list head
	*temp = NULL; // Split off part before that
	while ( todo != NULL ) {
		threadpool_run( todo->startRoutine, todo->arg, "TIMER_TASK" );
		old = todo;
		todo = todo->next;
		if ( old->intervalSecs == 0 ) {
			free( old ); // oneshot
		} else {
			timing_set( &old->dueDate, &now, old->intervalSecs );
			queueJobInternal( old ); // repeated
		}
	}
	// See if any new jobs have been queued
	while ( newJob != NULL ) {
		todo = newJob;
		// NULL should never happen since we're the only consumer
		assert( todo != NULL );
		if ( !atomic_compare_exchange_weak( &newJob, &todo, NULL ) )
			continue;
		do {
			old = todo;
			todo = todo->next;
			queueJobInternal( old );
		} while ( todo != NULL );
	}
	// Return new timeout
	if ( jobHead == NULL )
		return DEFAULT_TIMER_TIMEOUT;
	return (int)timing_diff( &now, &jobHead->dueDate );
}

static void queueJobInternal(job_t *job)
{
	assert( job != NULL );
	job_t **it;
	for ( it = &jobHead; *it != NULL; it = &(*it)->next ) {
		if ( timing_1le2( &job->dueDate, &(*it)->dueDate ) )
			break;
	}
	job->next = *it;
	*it = job;
}

void server_addJob(void *(*startRoutine)(void *), void *arg, int delaySecs, int intervalSecs)
{
	declare_now;
	job_t *new = malloc( sizeof(*new) );
	new->startRoutine = startRoutine;
	new->arg = arg;
	new->intervalSecs = intervalSecs;
	timing_set( &new->dueDate, &now, delaySecs );
	for ( ;; ) {
		new->next = newJob;
		if ( atomic_compare_exchange_weak( &newJob, &new->next, new ) )
			break;
	}
}

