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

#include "../types.h"
#include "../version.h"

#include "server.h"
#include "utils.h"
#include "hashtable.h"
#include "signal.h"
#include "net.h"

int _sock;

pthread_spinlock_t _spinlock;
char *_config_file_name = DEFAULT_CONFIG_FILE;
GSList *_dnbd3_clients = NULL;

void dnbd3_print_help(char* argv_0)
{
    printf("Usage: %s [OPTIONS]...\n", argv_0);
    printf("Start the DNBD3 server\n");
    printf("-f or --file \t\t Configuration file (default /etc/dnbd3-server.conf)\n");
    printf("-n or --nodaemon \t\t Start server in foreground\n");
    printf("-r or --reload \t\t Reload configuration file\n");
    printf("-s or --stop \t\t Stop running dnbd3-server\n");
    printf("-h or --help \t\t Show this help text and quit\n");
    printf("-v or --version \t Show version and quit\n");
    exit(0);
}

void dnbd3_print_version()
{
    printf("Version: %s\n", VERSION_STRING);
    exit(0);
}

void dnbd3_cleanup()
{
    printf("INFO: Cleanup...\n");
    GSList *iterator = NULL;
    for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
    {
        dnbd3_client_t *client =  iterator->data;
        shutdown(client->sock, SHUT_RDWR);
        pthread_join(*client->thread, NULL);
    }

    g_slist_free(_dnbd3_clients);

    close(_sock);
    dnbd3_delete_pid_file();
    exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[])
{
    int demonize = 1;
    int opt = 0;
    int longIndex = 0;
    static const char *optString = "f:nrshv?";
    static const struct option longOpts[] =
    {
    { "file", required_argument, NULL, 'f' },
    { "nodaemon", no_argument, NULL, 'n' },
    { "reload", no_argument, NULL, 'r' },
    { "stop", no_argument, NULL, 's' },
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'v' } };

    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

    while (opt != -1)
    {
        switch (opt)
        {
        case 'f':
            _config_file_name = optarg;
            break;
        case 'n':
            demonize = 0;
            break;
        case 'r':
            printf("INFO: Reloading configuration file...\n");
            dnbd3_send_signal(SIGHUP);
            return EXIT_SUCCESS;
        case 's':
            printf("INFO: Stopping running server...\n");
            dnbd3_send_signal(SIGTERM);
            return EXIT_SUCCESS;
        case 'h':
            dnbd3_print_help(argv[0]);
            break;
        case 'v':
            dnbd3_print_version();
            break;
        case '?':
            dnbd3_print_help(argv[0]);
        }
        opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
    }

    if (demonize)
        daemon(1, 0);

    // load config file
    pthread_spin_init(&_spinlock, PTHREAD_PROCESS_PRIVATE);
    dnbd3_load_config(_config_file_name);

    // setup signal handler
    signal(SIGPIPE, dnbd3_handle_sigpipe);
    signal(SIGHUP, dnbd3_handle_sighup);
    signal(SIGTERM, dnbd3_handle_sigterm);
    signal(SIGINT, dnbd3_handle_sigterm);

    // setup network
    _sock = dnbd3_setup_socket();
    if (_sock < 0)
        exit(EXIT_FAILURE);
    struct sockaddr_in client;
    unsigned int len = sizeof(client);
    int fd;
    struct timeval timeout;
    timeout.tv_sec = SERVER_SOCKET_TIMEOUT;
    timeout.tv_usec = 0;

    dnbd3_write_pid_file(getpid());
    printf("INFO: Server is ready...\n");

    // main loop
    while (1)
    {
        fd = accept(_sock, (struct sockaddr*) &client, &len);
        if (fd < 0)
        {
            printf("ERROR: Accept failure\n");
            continue;
        }
        printf("INFO: Client %s connected\n", inet_ntoa(client.sin_addr));

        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));

        pthread_t thread;
        dnbd3_client_t *dnbd3_client = (dnbd3_client_t *) malloc(sizeof(dnbd3_client_t));
        strcpy(dnbd3_client->ip, inet_ntoa(client.sin_addr));
        dnbd3_client->sock = fd;
        dnbd3_client->thread = &thread;

        _dnbd3_clients = g_slist_append (_dnbd3_clients, dnbd3_client);

        pthread_create(&(thread), NULL, dnbd3_handle_query, (void *) (uintptr_t) dnbd3_client);
    }

    dnbd3_cleanup();
}
