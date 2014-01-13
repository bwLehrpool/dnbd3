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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

#include "../types.h"
#include "../version.h"

#include "locks.h"
#include "sockhelper.h"
#include "server.h"
#include "image.h"
#include "uplink.h"
#include "net.h"
#include "altservers.h"
#include "memlog.h"
#include "globals.h"
#include "integrity.h"
#include "helper.h"

#define MAX_SERVER_SOCKETS 50 // Assume there will be no more than 50 sockets the server will listen on
static int sockets[MAX_SERVER_SOCKETS], socket_count = 0;
#ifdef _DEBUG
int _fake_delay = 0;
#endif

dnbd3_client_t *_clients[SERVER_MAX_CLIENTS];
int _num_clients = 0;
pthread_spinlock_t _clients_lock;

/**
 * Time the server was started
 */
static time_t _startupTime = 0;
static int _doReload = FALSE, _printStats = FALSE;

static int dnbd3_add_client(dnbd3_client_t *client);
static void dnbd3_handle_signal(int signum);
static void dnbd3_printClients();

/**
 * Print help text for usage instructions
 */
void dnbd3_print_help(char *argv_0)
{
	printf( "Usage: %s [OPTIONS]...\n", argv_0 );
	printf( "Start the DNBD3 server\n" );
	printf( "-c or --config      Configuration file (default /etc/dnbd3-server.conf)\n" );
#ifdef _DEBUG
	printf( "-d or --delay       Add a fake network delay of X µs\n" );
#endif
	printf( "-n or --nodaemon    Start server in foreground\n" );
	printf( "-b or --bind        Local Address to bind to\n" );
	//printf( "-r or --reload      Reload configuration file\n" );
	//printf( "-s or --stop        Stop running dnbd3-server\n" );
	//printf( "-i or --info        Print connected clients and used images\n" );
	printf( "-h or --help        Show this help text and quit\n" );
	printf( "-v or --version     Show version and quit\n" );
	printf( "Management functions:\n" );
	printf( "--crc [image-file]  Generate crc block list for given image\n" );
	printf( "--create [image-name] --revision [rid] --size [filesize]\n"
			"\tCreate a local empty image file with a zeroed cache-map for the specified image\n" );
	printf( "\n" );
	exit( 0 );
}

/**
 * Print version information
 */
void dnbd3_print_version()
{
	printf( "Version: %s\n", VERSION_STRING );
	exit( 0 );
}

/**
 * Clean up structs, connections, write out data, then exit
 */
void dnbd3_cleanup()
{
	int i, count;

	_shutdown = TRUE;
	debug_locks_stop_watchdog();
	memlogf( "INFO: Cleanup...\n" );

	for (int i = 0; i < socket_count; ++i) {
		if ( sockets[i] == -1 ) continue;
		close( sockets[i] );
		sockets[i] = -1;
	}
	socket_count = 0;

	// Kill connection to all clients
	spin_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] == NULL ) continue;
		dnbd3_client_t * const client = _clients[i];
		spin_lock( &client->lock );
		if ( client->sock >= 0 ) shutdown( client->sock, SHUT_RDWR );
		spin_unlock( &client->lock );
	}
	spin_unlock( &_clients_lock );

	// Terminate the altserver checking thread
	altservers_shutdown();

	// Terminate all uplinks
	image_killUplinks();

	// Terminate integrity checker
	integrity_shutdown();

	// Wait for clients to disconnect
	int retries = 10;
	do {
		count = 0;
		spin_lock( &_clients_lock );
		for (i = 0; i < _num_clients; ++i) {
			if ( _clients[i] == NULL ) continue;
			count++;
		}
		spin_unlock( &_clients_lock );
		if ( count != 0 ) {
			printf( "%d clients still active...\n", count );
			sleep( 1 );
		}
	} while ( count != 0 && --retries > 0 );
	_num_clients = 0;

	// Clean up images
	spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		if ( _images[i] == NULL ) continue;
		_images[i] = image_free( _images[i] );
	}
	_num_images = 0;
	spin_unlock( &_images_lock );

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
	int64_t paramSize = -1;
	int paramRevision = -1;
	static const char *optString = "c:d:b:nrsihv?";
	static const struct option longOpts[] = {
	        { "config", required_argument, NULL, 'c' },
	        { "delay", required_argument, NULL, 'd' },
	        { "nodaemon", no_argument, NULL, 'n' },
	        { "reload", no_argument, NULL, 'r' },
	        { "stop", no_argument, NULL, 's' },
	        { "info", no_argument, NULL, 'i' },
	        { "help", no_argument, NULL, 'h' },
	        { "version", no_argument, NULL, 'v' },
	        { "bind", required_argument, NULL, 'b' },
	        { "crc", required_argument, NULL, 'crc4' },
	        { "assert", no_argument, NULL, 'asrt' },
	        { "create", required_argument, NULL, 'crat' },
	        { "revision", required_argument, NULL, 'rvid' },
	        { "size", required_argument, NULL, 'size' },
	        { 0, 0, 0, 0 }
	};

	opt = getopt_long( argc, argv, optString, longOpts, &longIndex );

	while ( opt != -1 ) {
		switch ( opt ) {
		case 'c':
			_configDir = strdup( optarg );
			break;
		case 'd':
			#ifdef _DEBUG
			_fake_delay = atoi( optarg );
			break;
#else
			printf( "This option is only available in debug builds.\n\n" );
			return EXIT_FAILURE;
#endif
		case 'n':
			demonize = 0;
			break;
		case 'r':
			printf( "INFO: Reloading configuration file...\n\n" );
			//dnbd3_rpc_send(RPC_RELOAD);
			return EXIT_SUCCESS;
		case 's':
			printf( "INFO: Stopping running server...\n\n" );
			//dnbd3_rpc_send(RPC_EXIT);
			return EXIT_SUCCESS;
		case 'i':
			printf( "INFO: Requesting information...\n\n" );
			//dnbd3_rpc_send(RPC_IMG_LIST);
			return EXIT_SUCCESS;
		case 'h':
			case '?':
			dnbd3_print_help( argv[0] );
			break;
		case 'v':
			dnbd3_print_version();
			break;
		case 'b':
			bindAddress = strdup( optarg );
			break;
		case 'crc4':
			return image_generateCrcFile( optarg ) ? 0 : EXIT_FAILURE;
		case 'asrt':
			printf( "Testing a failing assertion:\n" );
			assert( 4 == 5 );
			printf( "Assertion 4 == 5 seems to hold. ;-)\n" );
			return EXIT_SUCCESS;
		case 'crat':
			paramCreate = strdup( optarg );
			break;
		case 'rvid':
			paramRevision = atoi( optarg );
			break;
		case 'size':
			paramSize = strtoll( optarg, NULL, 10 );
			break;
		}
		opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
	}

	// Load general config

	if ( _configDir == NULL ) _configDir = strdup( "/etc/dnbd3-server" );
	globals_loadConfig();
	if ( _basePath == NULL ) {
		printf( "ERROR: basePath not set in %s/%s\n", _configDir, CONFIG_FILENAME );
		exit( EXIT_FAILURE );
	}

	// One-shots first:

	if ( paramCreate != NULL ) {
		return image_create( paramCreate, paramRevision, paramSize ) ? 0 : EXIT_FAILURE;
	}

	// No one-shot detected, normal server operation

	if ( demonize ) daemon( 1, 0 );
	initmemlog();
	spin_init( &_clients_lock, PTHREAD_PROCESS_PRIVATE );
	spin_init( &_images_lock, PTHREAD_PROCESS_PRIVATE );
	altservers_init();
	integrity_init();
	memlogf( "DNBD3 server starting.... Machine type: " ENDIAN_MODE );

	if ( altservers_load() < 0 ) {
		memlogf( "[WARNING] Could not load alt-servers. Does the file exist in %s?", _configDir );
	}

#ifdef _DEBUG
	debug_locks_start_watchdog();
#endif

	// setup signal handler
	signal( SIGTERM, dnbd3_handle_signal );
	signal( SIGINT, dnbd3_handle_signal );
	signal( SIGUSR1, dnbd3_handle_signal );
	signal( SIGHUP, dnbd3_handle_signal );
	signal( SIGUSR2, dnbd3_handle_signal );

	printf( "Loading images....\n" );
	// Load all images in base path
	if ( !image_loadAll( NULL ) ) {
		printf( "[ERROR] Could not load images.\n" );
		return EXIT_FAILURE;
	}

	_startupTime = time( NULL );

	// Give other threads some time to start up before accepting connections
	sleep( 2 );

	// setup network
	sockets[socket_count] = sock_listen_any( PF_INET, PORT, bindAddress );
	if ( sockets[socket_count] != -1 ) ++socket_count;
#ifdef WITH_IPV6
	sockets[socket_count] = sock_listen_any(PF_INET6, PORT, NULL);
	if (sockets[socket_count] != -1) ++socket_count;
#endif
	if ( socket_count == 0 ) exit( EXIT_FAILURE );
	struct sockaddr_storage client;
	socklen_t len;
	int fd;

	// setup rpc
	//pthread_t thread_rpc;
	//pthread_create(&(thread_rpc), NULL, &dnbd3_rpc_mainloop, NULL);

	pthread_attr_t threadAttrs;
	pthread_attr_init( &threadAttrs );
	pthread_attr_setdetachstate( &threadAttrs, PTHREAD_CREATE_DETACHED );

	memlogf( "[INFO] Server is ready..." );

	// +++++++++++++++++++++++++++++++++++++++++++++++++++ main loop
	while ( !_shutdown ) {
		// Handle signals
		if ( _doReload ) {
			_doReload = FALSE;
			memlogf( "INFO: SIGUSR1 received, re-scanning image directory" );
			image_loadAll( NULL );
		}
		if ( _printStats ) {
			_printStats = FALSE;
			printf( "[DEBUG] SIGUSR2 received, stats incoming\n" );
			printf( " ** Images **\n" );
			image_printAll();
			printf( " ** Clients **\n" );
			dnbd3_printClients();
		}
		//
		len = sizeof(client);
		fd = accept_any( sockets, socket_count, &client, &len );
		if ( fd < 0 ) {
			const int err = errno;
			if ( err == EINTR || err == EAGAIN ) continue;
			memlogf( "[ERROR] Client accept failure (err=%d)", err );
			usleep( 10000 ); // 10ms
			continue;
		}
		//memlogf("INFO: Client %s connected\n", inet_ntoa(client.sin_addr));

		sock_set_timeout( fd, SOCKET_TIMEOUT_SERVER_MS );

		dnbd3_client_t *dnbd3_client = dnbd3_init_client( &client, fd );
		if ( dnbd3_client == NULL ) {
			close( fd );
			continue;
		}

		// This has to be done before creating the thread, otherwise a race condition might occur when the new thread dies faster than this thread adds the client to the list after creating the thread
		if ( !dnbd3_add_client( dnbd3_client ) ) {
			dnbd3_client = dnbd3_free_client( dnbd3_client );
			continue;
		}

		if ( 0 != pthread_create( &(dnbd3_client->thread), &threadAttrs, net_client_handler, (void *)(uintptr_t)dnbd3_client ) ) {
			memlogf( "[ERROR] Could not start thread for new client." );
			dnbd3_remove_client( dnbd3_client );
			dnbd3_client = dnbd3_free_client( dnbd3_client );
			continue;
		}
	}
	dnbd3_cleanup();
}

/**
 * Initialize and populate the client struct - called when an incoming
 * connection is accepted
 */
dnbd3_client_t* dnbd3_init_client(struct sockaddr_storage *client, int fd)
{
	dnbd3_client_t *dnbd3_client = calloc( 1, sizeof(dnbd3_client_t) );
	if ( dnbd3_client == NULL ) { // This will never happen thanks to memory overcommit
		memlogf( "[ERROR] Could not alloc dnbd3_client_t for new client." );
		return NULL ;
	}

	if ( client->ss_family == AF_INET ) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)client;
		dnbd3_client->host.type = AF_INET;
		memcpy( dnbd3_client->host.addr, &(v4->sin_addr), 4 );
		dnbd3_client->host.port = v4->sin_port;
	} else if ( client->ss_family == AF_INET6 ) {
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)client;
		dnbd3_client->host.type = AF_INET6;
		memcpy( dnbd3_client->host.addr, &(v6->sin6_addr), 16 );
		dnbd3_client->host.port = v6->sin6_port;
	} else {
		memlogf( "[ERROR] New client has unknown address family %d, disconnecting...", (int)client->ss_family );
		free( dnbd3_client );
		return NULL ;
	}
	dnbd3_client->running = TRUE;
	dnbd3_client->sock = fd;
	spin_init( &dnbd3_client->lock, PTHREAD_PROCESS_PRIVATE );
	pthread_mutex_init( &dnbd3_client->sendMutex, NULL );
	return dnbd3_client;
}

/**
 * Remove a client from the clients array
 * Locks on: _clients_lock
 */
void dnbd3_remove_client(dnbd3_client_t *client)
{
	int i;
	spin_lock( &_clients_lock );
	const int cutoff = MAX(10, _num_clients / 2);
	for (i = _num_clients - 1; i >= 0; --i) {
		if ( _clients[i] != client ) continue;
		_clients[i] = NULL;
		if ( i > cutoff && i + 1 == _num_clients ) --_num_clients;
	}
	spin_unlock( &_clients_lock );
}

/**
 * Free the client struct recursively.
 * !! Make sure to call this function after removing the client from _dnbd3_clients !!
 * Locks on: _clients[].lock, _images[].lock
 * might call functions that lock on _images, _image[], uplink.queueLock, client.sendMutex
 */
dnbd3_client_t* dnbd3_free_client(dnbd3_client_t *client)
{
	spin_lock( &client->lock );
	if ( client->sock >= 0 ) close( client->sock );
	client->sock = -1;
	if ( client->image != NULL ) {
		spin_lock( &client->image->lock );
		if ( client->image->uplink != NULL ) uplink_removeClient( client->image->uplink, client );
		spin_unlock( &client->image->lock );
		image_release( client->image );
	}
	client->image = NULL;
	spin_unlock( &client->lock );
	spin_destroy( &client->lock );
	pthread_mutex_lock( &client->sendMutex );
	pthread_mutex_unlock( &client->sendMutex );
	pthread_mutex_destroy( &client->sendMutex );
	free( client );
	return NULL ;
}

//###//

/**
 * Add client to the clients array.
 * Locks on: _clients_lock
 */
static int dnbd3_add_client(dnbd3_client_t *client)
{
	int i;
	spin_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] != NULL ) continue;
		_clients[i] = client;
		spin_unlock( &_clients_lock );
		return TRUE;
	}
	if ( _num_clients >= SERVER_MAX_CLIENTS ) {
		spin_unlock( &_clients_lock );
		memlogf( "[ERROR] Maximum number of clients reached!" );
		return FALSE;
	}
	_clients[_num_clients++] = client;
	spin_unlock( &_clients_lock );
	return TRUE;
}

static void dnbd3_handle_signal(int signum)
{
	if ( signum == SIGINT || signum == SIGTERM ) {
		_shutdown = TRUE;
	} else if ( signum == SIGUSR1 || signum == SIGHUP ) {
		_doReload = TRUE;
	} else if ( signum == SIGUSR2 ) {
		_printStats = TRUE;
	}
}

int dnbd3_serverUptime()
{
	return (int)(time( NULL ) - _startupTime);
}

static void dnbd3_printClients()
{
	int i;
	char buffer[100];
	spin_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] == NULL ) continue;
		spin_lock( &_clients[i]->lock );
		host_to_string( &_clients[i]->host, buffer, sizeof(buffer) );
		printf( "Client %s\n", buffer );
		if ( _clients[i]->image != NULL ) printf( "  Image: %s\n", _clients[i]->image->lower_name );
		spin_unlock( &_clients[i]->lock );
	}
	spin_unlock( &_clients_lock );
}
