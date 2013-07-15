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
#include <stdint.h>
#include <unistd.h>

#include "../types.h"
#include "../version.h"

#include "sockhelper.h"
#include "server.h"
#include "image.h"
#include "uplink.h"
#include "net.h"
#include "memlog.h"

#define MAX_SERVER_SOCKETS 50 // Assume there will be no more than 50 sockets the server will listen on
static int sockets[MAX_SERVER_SOCKETS], socket_count = 0;
#ifdef _DEBUG
int _fake_delay = 0;
#endif

dnbd3_client_t *_clients[SERVER_MAX_CLIENTS];
int _num_clients = 0;
pthread_spinlock_t _clients_lock;

char *_config_file_name = DEFAULT_SERVER_CONFIG_FILE;
char *_rpc_password = NULL;
char *_cache_dir = NULL;

static int dnbd3_add_client(dnbd3_client_t *client);
static dnbd3_client_t* dnbd3_free_client(dnbd3_client_t *client);
static void dnbd3_load_config();
static void dnbd3_handle_sigpipe(int signum);
static void dnbd3_handle_sigterm(int signum);

/**
 * Print help text for usage instructions
 */
void dnbd3_print_help(char *argv_0)
{
	printf( "Usage: %s [OPTIONS]...\n", argv_0 );
	printf( "Start the DNBD3 server\n" );
	printf( "-f or --file        Configuration file (default /etc/dnbd3-server.conf)\n" );
#ifdef _DEBUG
	printf("-d or --delay       Add a fake network delay of X µs\n");
#endif
	printf( "-n or --nodaemon    Start server in foreground\n" );
	printf( "-r or --reload      Reload configuration file\n" );
	printf( "-s or --stop        Stop running dnbd3-server\n" );
	printf( "-i or --info        Print connected clients and used images\n" );
	printf( "-H or --help        Show this help text and quit\n" );
	printf( "-V or --version     Show version and quit\n" );
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
	int i;

	memlogf( "INFO: Cleanup...\n" );

	for (int i = 0; i < socket_count; ++i) {
		if ( sockets[i] == -1 ) continue;
		close( sockets[i] );
		sockets[i] = -1;
	}
	socket_count = 0;

	// Clean up clients
	pthread_spin_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		dnbd3_client_t * const client = _clients[i];
		pthread_spin_lock( &client->lock );
		if ( client->sock >= 0 ) shutdown( client->sock, SHUT_RDWR );
		if ( client->thread != 0 ) pthread_join( client->thread, NULL );
		_clients[i] = NULL;
		pthread_spin_unlock( &client->lock );
		free( client );
	}
	_num_clients = 0;
	pthread_spin_unlock( &_clients_lock );

	// Clean up images
	pthread_spin_lock( &_images_lock );
	for (i = 0; i < _num_images; ++i) {
		dnbd3_image_t *image = _images[i];
		pthread_spin_lock( &image->lock );
		// save cache maps to files
		image_save_cache_map( image );
		// free uplink connection
		uplink_shutdown( image->uplink );
		// free other stuff
		free( image->cache_map );
		free( image->path );
		free( image->lower_name );
		_images[i] = NULL;
		pthread_spin_unlock( &image->lock );
		free( image );
	}
	_num_images = 0;
	pthread_spin_unlock( &_images_lock );

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
	static const char *optString = "f:d:nrsiHV?";
	static const struct option longOpts[] = { { "file", required_argument, NULL, 'f' }, { "delay", required_argument, NULL, 'd' }, {
	        "nodaemon", no_argument, NULL, 'n' }, { "reload", no_argument, NULL, 'r' }, { "stop", no_argument, NULL, 's' }, { "info",
	        no_argument, NULL, 'i' }, { "help", no_argument, NULL, 'H' }, { "version", no_argument, NULL, 'V' } };

	opt = getopt_long( argc, argv, optString, longOpts, &longIndex );

	while ( opt != -1 ) {
		switch ( opt ) {
		case 'f':
			_config_file_name = strdup( optarg );
			break;
		case 'd':
#ifdef _DEBUG
			_fake_delay = atoi(optarg);
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
		case 'H':
			dnbd3_print_help( argv[0] );
			break;
		case 'V':
			dnbd3_print_version();
			break;
		case '?':
			dnbd3_print_help( argv[0] );
			break;
		}
		opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
	}

	if ( demonize ) daemon( 1, 0 );

	pthread_spin_init( &_clients_lock, PTHREAD_PROCESS_PRIVATE );
	pthread_spin_init( &_images_lock, PTHREAD_PROCESS_PRIVATE );
	pthread_spin_init( &_alts_lock, PTHREAD_PROCESS_PRIVATE );

	initmemlog();
	memlogf( "DNBD3 server starting.... Machine type: " ENDIAN_MODE );

	// load config file
	dnbd3_load_config();

	// setup signal handler
	signal( SIGPIPE, dnbd3_handle_sigpipe );
	signal( SIGTERM, dnbd3_handle_sigterm );
	signal( SIGINT, dnbd3_handle_sigterm );

	// Load all images in base path
	if (!image_load_all(NULL)) {
		printf("[ERROR] Could not load images.\n");
		return EXIT_FAILURE;
	}

	// setup network
	sockets[socket_count] = sock_listen_any( PF_INET, PORT );
	if ( sockets[socket_count] != -1 ) ++socket_count;
#ifdef WITH_IPV6
	sockets[socket_count] = sock_listen_any(PF_INET6, PORT);
	if (sockets[socket_count] != -1)
	++socket_count;
#endif
	if ( socket_count == 0 ) exit( EXIT_FAILURE );
	struct sockaddr_storage client;
	socklen_t len;
	int fd;

	// setup rpc
	//pthread_t thread_rpc;
	//pthread_create(&(thread_rpc), NULL, &dnbd3_rpc_mainloop, NULL);

	// setup the job thread (query other servers, delete old images etc.)
	//pthread_t thread_job;
	//pthread_create(&(thread_job), NULL, &dnbd3_job_thread, NULL);

	memlogf( "[INFO] Server is ready..." );

	// main loop
	while ( 1 ) {
		len = sizeof(client);
		fd = accept_any( sockets, socket_count, &client, &len );
		if ( fd < 0 ) {
			memlogf( "[ERROR] Client accept failure" );
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
			dnbd3_free_client( dnbd3_client );
			continue;
		}

		if ( 0 != pthread_create( &(dnbd3_client->thread), NULL, net_client_handler, (void *)(uintptr_t)dnbd3_client ) ) {
			memlogf( "[ERROR] Could not start thread for new client." );
			dnbd3_remove_client( dnbd3_client );
			dnbd3_free_client( dnbd3_client );
			continue;
		}
		pthread_detach( dnbd3_client->thread );
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
	if ( dnbd3_client == NULL ) {
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
	dnbd3_client->sock = fd;
	pthread_spin_init( &dnbd3_client->lock, PTHREAD_PROCESS_PRIVATE );
	return dnbd3_client;
}

/**
 * Remove a client from the clients array
 * Locks on: _clients_lock
 */
void dnbd3_remove_client(dnbd3_client_t *client)
{
	int i;
	pthread_spin_lock( &_clients_lock );
	for (i = _num_clients - 1; i >= 0; --i) {
		if ( _clients[i] != client ) continue;
		_clients[i] = NULL;
		if ( i + 1 == _num_clients ) --_num_clients;
	}
	pthread_spin_unlock( &_clients_lock );
}

//###//

/**
 * Add client to the clients array.
 * Locks on: _clients_lock
 */
static int dnbd3_add_client(dnbd3_client_t *client)
{
	int i;
	pthread_spin_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] != NULL ) continue;
		_clients[i] = client;
		pthread_spin_unlock( &_clients_lock );
		return TRUE;
	}
	if ( _num_clients >= SERVER_MAX_CLIENTS ) {
		pthread_spin_unlock( &_clients_lock );
		memlogf( "[ERROR] Maximum number of clients reached!" );
		return FALSE;
	}
	_clients[_num_clients++] = client;
	pthread_spin_unlock( &_clients_lock );
	return TRUE;
}

/**
 * Free the client struct recursively.
 * !! Make sure to call this function after removing the client from _dnbd3_clients !!
 * Locks on: _clients[].lock
 */
static dnbd3_client_t* dnbd3_free_client(dnbd3_client_t *client)
{
	GSList *it;
	pthread_spin_lock(&client->lock);
	for (it = client->sendqueue; it; it = it->next) {
		free( it->data );
	}
	g_slist_free( client->sendqueue );
	if ( client->sock >= 0 ) close( client->sock );
	client->sock = -1;
	if ( client->image != NULL ) image_release( client->image );
	client->image = NULL;
	pthread_spin_unlock(&client->lock);
	pthread_spin_destroy(&client->lock);
	free( client );
	return NULL;
}

static void dnbd3_load_config()
{
	// Load configuration
}

static void dnbd3_handle_sigpipe(int signum)
{
	memlogf( "INFO: SIGPIPE received (%s)", strsignal( signum ) );
}

static void dnbd3_handle_sigterm(int signum)
{
	memlogf( "INFO: SIGTERM or SIGINT received (%s)", strsignal( signum ) );
	dnbd3_cleanup();
}
