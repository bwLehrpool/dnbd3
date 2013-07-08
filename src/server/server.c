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

#include "../types.h"
#include "../version.h"

#include "sockhelper.h"
#include "server.h"
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

dnbd3_image_t *_images[SERVER_MAX_IMAGES];
int _num_images = 0;
pthread_spinlock_t _images_lock;

dnbd3_alt_server_t *_alt_servers[SERVER_MAX_ALTS];
int _num_alts = 0;
pthread_spinlock_t _alts_lock;

char *_config_file_name = DEFAULT_SERVER_CONFIG_FILE;
char *_rpc_password = NULL;
char *_cache_dir = NULL;


void dnbd3_print_help(char *argv_0)
{
	printf("Usage: %s [OPTIONS]...\n", argv_0);
	printf("Start the DNBD3 server\n");
	printf("-f or --file        Configuration file (default /etc/dnbd3-server.conf)\n");
#ifdef _DEBUG
	printf("-d or --delay       Add a fake network delay of X µs\n");
#endif
	printf("-n or --nodaemon    Start server in foreground\n");
	printf("-r or --reload      Reload configuration file\n");
	printf("-s or --stop        Stop running dnbd3-server\n");
	printf("-i or --info        Print connected clients and used images\n");
	printf("-H or --help        Show this help text and quit\n");
	printf("-V or --version     Show version and quit\n");
	exit(0);
}

void dnbd3_print_version()
{
	printf("Version: %s\n", VERSION_STRING);
	exit(0);
}

void dnbd3_cleanup()
{
	int fd, i;
	GSList *iterator = NULL;

	memlogf("INFO: Cleanup...\n");

	for (int i = 0; i < socket_count; ++i)
	{
		if (sockets[i] == -1)
			continue;
		close(sockets[i]);
		sockets[i] = -1;
	}
	socket_count = 0;

	pthread_spin_lock(&_clients_lock);
	for (i = 0; i < _num_clients; ++i)
	{
		dnbd3_client_t * const client = _clients[i];
		pthread_spin_lock(&client->lock);
		if (client->sock != -1) shutdown(client->sock, SHUT_RDWR);
		if (client->thread != 0) pthread_join(client->thread, NULL);
		_clients[i] = NULL;
		pthread_spin_unlock(&client->lock);
		free(client);
	}
	_num_clients = 0;
	pthread_spin_unlock(&_clients_lock);

	pthread_spin_lock(&_images_lock);
	for (i = 0; i < _num_images; ++i)
	{
		// save cache maps to files
		dnbd3_image_t *image = _images[i];
		if (image->cache_file)
		{
			char tmp[strlen(image->cache_file)+4];
			strcpy(tmp, image->cache_file);
			strcat(tmp, ".map");
			fd = open(tmp, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);

			if (fd > 0)
				write(fd, image->cache_map,  ((image->filesize + (1 << 15) - 1) >> 15) * sizeof(char));

			close(fd);
		}
		// Close bock devices of proxied images
		if (image->file && strncmp(image->file, "/dev/dnbd", 9) == 0)
		{
			int fd = open(image->file, O_RDONLY);
			dnbd3_ioctl_t msg;
			memset(&msg, 0, sizeof(msg));
			msg.len = sizeof(msg);
			ioctl(fd, IOCTL_CLOSE, &msg);
			close(fd);
		}

		free(image->cache_map);
		free(image->config_group);
		free(image->low_name);
		free(image->file);
		free(image->cache_file);
		g_free(image);
	}
	pthread_spin_unlock(&_images_lock);

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int demonize = 1;
	int opt = 0;
	int longIndex = 0;
	static const char *optString = "f:d:nrsiHV?";
	static const struct option longOpts[] =
	{
		{ "file", required_argument, NULL, 'f' },
		{ "delay", required_argument, NULL, 'd' },
		{ "nodaemon", no_argument, NULL, 'n' },
		{ "reload", no_argument, NULL, 'r' },
		{ "stop", no_argument, NULL, 's' },
		{ "info", no_argument, NULL, 'i' },
		{ "help", no_argument, NULL, 'H' },
		{ "version", no_argument, NULL, 'V' }
	};

	opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

	while (opt != -1)
	{
		switch (opt)
		{
		case 'f':
			_config_file_name = strdup(optarg);
			break;
		case 'd':
#ifdef _DEBUG
			_fake_delay = atoi(optarg);
			break;
#else
			printf("This option is only available in debug builds.\n\n");
			return EXIT_FAILURE;
#endif
		case 'n':
			demonize = 0;
			break;
		case 'r':
			printf("INFO: Reloading configuration file...\n\n");
			//dnbd3_rpc_send(RPC_RELOAD);
			return EXIT_SUCCESS;
		case 's':
			printf("INFO: Stopping running server...\n\n");
			//dnbd3_rpc_send(RPC_EXIT);
			return EXIT_SUCCESS;
		case 'i':
			printf("INFO: Requesting information...\n\n");
			//dnbd3_rpc_send(RPC_IMG_LIST);
			return EXIT_SUCCESS;
		case 'H':
			dnbd3_print_help(argv[0]);
			break;
		case 'V':
			dnbd3_print_version();
			break;
		case '?':
			dnbd3_print_help(argv[0]);
			break;
		}
		opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
	}

	if (demonize)
		daemon(1, 0);

	pthread_spin_init(&_spinlock, PTHREAD_PROCESS_PRIVATE);

	initmemlog();
	memlogf("DNBD3 server starting.... Machine type: " ENDIAN_MODE);

	// load config file
	dnbd3_load_config();

	// setup signal handler
	signal(SIGPIPE, dnbd3_handle_sigpipe);
	signal(SIGTERM, dnbd3_handle_sigterm);
	signal(SIGINT, dnbd3_handle_sigterm);

	// setup network
	sockets[socket_count] = sock_listen_any(PF_INET, PORT);
	if (sockets[socket_count] != -1)
		++socket_count;
#ifdef WITH_IPV6
	sockets[socket_count] = sock_listen_any(PF_INET6, PORT);
	if (sockets[socket_count] != -1)
		++socket_count;
#endif
	if (socket_count == 0)
		exit(EXIT_FAILURE);
	struct sockaddr_storage client;
	socklen_t len;
	int fd;

	// setup rpc
	pthread_t thread_rpc;
	pthread_create(&(thread_rpc), NULL, &dnbd3_rpc_mainloop, NULL);

	// setup the job thread (query other servers, delete old images etc.)
	pthread_t thread_job;
	pthread_create(&(thread_job), NULL, &dnbd3_job_thread, NULL);

	memlogf("[INFO] Server is ready...");

	// main loop
	while (1)
	{
		len = sizeof(client);
		fd = accept_any(sockets, socket_count, &client, &len);
		if (fd < 0)
		{
			memlogf("[ERROR] Client accept failure");
			continue;
		}
		//memlogf("INFO: Client %s connected\n", inet_ntoa(client.sin_addr));

		sock_set_timeout(fd, SOCKET_TIMEOUT_SERVER_MS);

		dnbd3_client_t *dnbd3_client = g_new0(dnbd3_client_t, 1);
		if (dnbd3_client == NULL)
		{
			memlogf("[ERROR] Could not alloc dnbd3_client_t for new client.");
			close(fd);
			continue;
		}
		if (client.ss_family == AF_INET) {
			struct sockaddr_in *v4 = (struct sockaddr_in *)&client;
			dnbd3_client->host.type = AF_INET;
			memcpy(dnbd3_client->host.addr, &(v4->sin_addr), 4);
			dnbd3_client->host.port = v4->sin_port;
		}
		else if (client.ss_family == AF_INET6)
		{
			struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&client;
			dnbd3_client->host.type = AF_INET6;
			memcpy(dnbd3_client->host.addr, &(v6->sin6_addr), 16);
			dnbd3_client->host.port = v6->sin6_port;
		}
		else
		{
			memlogf("[ERROR] New client has unknown address family %d, disconnecting...", (int)client.ss_family);
			close(fd);
			g_free(dnbd3_client);
			continue;
		}
		dnbd3_client->sock = fd;
		dnbd3_client->image = NULL;

		// This has to be done before creating the thread, otherwise a race condition might occur when the new thread dies faster than this thread adds the client to the list after creating the thread
		pthread_spin_lock(&_spinlock);
		_dnbd3_clients = g_slist_prepend(_dnbd3_clients, dnbd3_client);
		pthread_spin_unlock(&_spinlock);

		if (0 != pthread_create(&(dnbd3_client->thread), NULL, net_client_handler, (void *) (uintptr_t) dnbd3_client))
		{
			memlogf("[ERROR] Could not start thread for new client.");
			pthread_spin_lock(&_spinlock);
			_dnbd3_clients = g_slist_remove(_dnbd3_clients, dnbd3_client);
			pthread_spin_unlock(&_spinlock);
			dnbd3_free_client(dnbd3_client);
			close(fd);
			continue;
		}
		pthread_detach(dnbd3_client->thread);
	}

	dnbd3_cleanup();
}

/**
 * Free the client struct recursively
 */
void dnbd3_free_client(dnbd3_client_t *client)
{
	GSList *it; // Doesn't lock, so call this function after removing the client from _dnbd3_clients
	for (it = client->sendqueue; it; it = it->next)
	{
		free(it->data);
	}
	g_slist_free(client->sendqueue);
	g_free(client);
}
