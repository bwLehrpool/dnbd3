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
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

#include <pthread.h>

#include "../types.h"
#include "../version.h"

#include "utils.h"
#include "hashtable.h"

int _sock;
pthread_spinlock_t spinlock;
char *config_file_name = DEFAULT_CONFIG_FILE;

void print_help(char* argv_0)
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

void print_version()
{
    printf("Version: %s\n", VERSION_STRING);
    exit(0);
}

void cleanup()
{
    close(_sock);
    dnbd3_delete_pid_file();
    exit(EXIT_SUCCESS);
}

void handle_sigpipe(int signum)
{
    printf("ERROR: Received signal SIGPIPE, Broken pipe (errno: %i)\n", errno);
    return;
}

void handle_sighup(int signum)
{
    printf("INFO: SIGHUP received!\n");
    printf("INFO: Reloading configuration...\n");
    pthread_spin_lock(&spinlock);
    dnbd3_reload_config(config_file_name);
    pthread_spin_unlock(&spinlock);
}

void handle_sigterm(int signum)
{
    printf("INFO: SIGTERM or SIGINT received!\n");
    cleanup();
}

void *handle_query(void *client_socket)
{
    int image_file = -1;
    off_t filesize = 0;
    int sock = (int) (uintptr_t) client_socket;
    struct dnbd3_request request;
    struct dnbd3_reply reply;
    uint16_t cmd;

    while (recv(sock, &request, sizeof(struct dnbd3_request), MSG_WAITALL) > 0)
    {
        cmd = request.cmd;
        switch (cmd)
        {
        case CMD_PING:
            reply.cmd = request.cmd;
            memcpy(reply.handle, request.handle, sizeof(request.handle));
            send(sock, (char *) &reply, sizeof(struct dnbd3_reply), 0);
            break;

        case CMD_GET_SIZE:
            pthread_spin_lock(&spinlock); // because of reloading config
            image_file = open(dnbd3_ht_search(request.image_id), O_RDONLY);
            pthread_spin_unlock(&spinlock);
            if (image_file < 0)
            {
                printf("ERROR: Client requested an unknown image id.\n");
                filesize = 0;
            }
            else
            {
                struct stat st;
                fstat(image_file, &st);
                filesize = st.st_size;
            }
            reply.cmd = request.cmd;
            reply.filesize = filesize;
            send(sock, (char *) &reply, sizeof(struct dnbd3_reply), 0);
            break;

        case CMD_GET_BLOCK:
            if (image_file < 0)
                break;

            reply.cmd = request.cmd;
            memcpy(reply.handle, request.handle, sizeof(request.handle));
            send(sock, (char *) &reply, sizeof(struct dnbd3_reply), 0);

            if (sendfile(sock, image_file, (off_t *) &request.offset, request.size) < 0)
                printf("ERROR: sendfile returned -1\n");

            break;

        default:
            printf("ERROR: Unknown command\n");
            break;
        }

    }
    close(sock);
    printf("INFO: Client exit.\n");
    pthread_exit((void *) 0);
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
            config_file_name = optarg;
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
            print_help(argv[0]);
            break;
        case 'v':
            print_version();
            break;
        case '?':
            exit(1);
        }
        opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
    }

    if (demonize)
        daemon(1, 0);

    // load config file
    pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE);
    dnbd3_load_config(config_file_name);

    // setup signal handler
    signal(SIGPIPE, handle_sigpipe);
    signal(SIGHUP, handle_sighup);
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    // setup network
    struct sockaddr_in server;
    struct sockaddr_in client;
    int fd;
    unsigned int len;

    // Create socket
    _sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (_sock < 0)
    {
        printf("ERROR: Socket failure\n");
        exit(EXIT_FAILURE);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET; // IPv4
    server.sin_addr.s_addr = htonl(INADDR_ANY); // Take all IPs
    server.sin_port = htons(PORT); // set port number

    // Bind to socket
    if (bind(_sock, (struct sockaddr*) &server, sizeof(server)) < 0)
    {
        printf("ERROR: Bind failure\n");
        exit(EXIT_FAILURE);
    }

    // Listen on socket
    if (listen(_sock, 50) == -1)
    {
        printf("ERROR: Listen failure\n");
        exit(EXIT_FAILURE);
    }

    dnbd3_write_pid_file(getpid());
    printf("INFO: Server is ready...\n");

    struct timeval timeout;
    timeout.tv_sec = SERVER_SOCKET_TIMEOUT;
    timeout.tv_usec = 0;

    while (1)
    {
        len = sizeof(client);
        fd = accept(_sock, (struct sockaddr*) &client, &len);
        if (fd < 0)
        {
            printf("ERROR: Accept failure\n");
            exit(EXIT_FAILURE);
        }
        printf("INFO: Client: %s connected\n", inet_ntoa(client.sin_addr));

        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));

        // FIXME: catch SIGKILL/SIGTERM and close all socket before exit
        pthread_t thread;
        pthread_create(&(thread), NULL, handle_query, (void *) (uintptr_t) fd);
        pthread_detach(thread);
    }

    cleanup();
}
