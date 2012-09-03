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
#include <arpa/inet.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>

#include "../types.h"
#include "../version.h"

#include "server.h"
#include "utils.h"
#include "net.h"
#include "ipc.h"
#include "memlog.h"

static int sock;
#ifdef _DEBUG
int _fake_delay = 0;
#endif
pthread_spinlock_t _spinlock;

GSList *_dnbd3_clients = NULL;
char *_config_file_name = DEFAULT_SERVER_CONFIG_FILE;
char *_local_namespace = NULL;
char *_ipc_password = NULL;
GSList *_dnbd3_images = NULL; // of dnbd3_image_t
GSList *_trusted_servers = NULL;

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
	int fd;
	memlogf("INFO: Cleanup...\n");

	close(sock);
	sock = -1;

	dnbd3_ipc_shutdown();

	pthread_spin_lock(&_spinlock);
	GSList *iterator = NULL;
	for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
	{
		dnbd3_client_t *client = iterator->data;
		shutdown(client->sock, SHUT_RDWR);
		pthread_join(client->thread, NULL);
		g_free(client);
	}
	g_slist_free(_dnbd3_clients);


	for (iterator = _dnbd3_images; iterator; iterator = iterator->next)
	{
		// save cache maps to files
		dnbd3_image_t *image = iterator->data;
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

		free(image->cache_map);
		free(image->config_group);
		free(image->low_name);
		free(image->file);
		free(image->cache_file);
		g_free(image);
	}
	g_slist_free(_dnbd3_images);

	pthread_spin_unlock(&_spinlock);
#ifndef IPC_TCP
	unlink(UNIX_SOCKET);
#endif
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
			dnbd3_ipc_send(IPC_RELOAD);
			return EXIT_SUCCESS;
		case 's':
			printf("INFO: Stopping running server...\n\n");
			dnbd3_ipc_send(IPC_EXIT);
			return EXIT_SUCCESS;
		case 'i':
			printf("INFO: Requesting information...\n\n");
			dnbd3_ipc_send(IPC_INFO);
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
	sock = dnbd3_setup_socket();
	if (sock < 0)
		exit(EXIT_FAILURE);
	struct sockaddr_in client;
	unsigned int len = sizeof(client);
	int fd;
	struct timeval timeout;
	timeout.tv_sec = SOCKET_TIMEOUT_SERVER;
	timeout.tv_usec = 0;

	// setup ipc
	pthread_t thread_ipc;
	pthread_create(&(thread_ipc), NULL, &dnbd3_ipc_mainloop, NULL);

	memlogf("[INFO] Server is ready...");

	// main loop
	while (1)
	{
		fd = accept(sock, (struct sockaddr *) &client, &len);
		if (fd < 0)
		{
			memlogf("[ERROR] Accept failure");
			continue;
		}
		//memlogf("INFO: Client %s connected\n", inet_ntoa(client.sin_addr));

		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));

		dnbd3_client_t *dnbd3_client = g_new0(dnbd3_client_t, 1);
		if (dnbd3_client == NULL)
		{
			memlogf("[ERROR] Could not alloc dnbd3_client_t for new client.");
			close(fd);
			continue;
		}
		// TODO: Extend this if you ever want to add IPv6 (something like:)
		// dnbd3_client->addrtype = AF_INET6;
		// memcpy(dnbd3_client->ipaddr, &(client.sin6_addr), 16);
		dnbd3_client->addrtype = AF_INET;
		memcpy(dnbd3_client->ipaddr, &(client.sin_addr), 4);
		dnbd3_client->sock = fd;
		dnbd3_client->image = NULL;

		// This has to be done before creating the thread, otherwise a race condition might occur when the new thread dies faster than this thread adds the client to the list after creating the thread
		pthread_spin_lock(&_spinlock);
		_dnbd3_clients = g_slist_prepend(_dnbd3_clients, dnbd3_client);
		pthread_spin_unlock(&_spinlock);

		if (0 != pthread_create(&(dnbd3_client->thread), NULL, dnbd3_handle_query, (void *) (uintptr_t) dnbd3_client))
		{
			memlogf("[ERROR] Could not start thread for new client.");
			pthread_spin_lock(&_spinlock);
			_dnbd3_clients = g_slist_remove(_dnbd3_clients, dnbd3_client);
			pthread_spin_unlock(&_spinlock);
			g_free(dnbd3_client);
			close(fd);
			continue;
		}
		pthread_detach(dnbd3_client->thread);
	}

	dnbd3_cleanup();
}
