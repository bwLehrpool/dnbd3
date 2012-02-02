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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "ipc.h"
#include "config.h"
#include "server.h"
#include "utils.h"

void* dnbd3_ipc_receive()
{
    int server_sock, client_sock;
    struct sockaddr_un server, client;
    unsigned int len = sizeof(client);

    GSList *iterator = NULL;

    // Create socket
    if ((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        perror("ERROR: IPC socket");
        exit(EXIT_FAILURE);
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, UNIX_SOCKET);
    unlink(UNIX_SOCKET);

    // Bind to socket
    if (bind(server_sock, &server, sizeof(server.sun_family) + strlen(server.sun_path)) < 0)
    {
        perror("ERROR: IPC bind");
        exit(EXIT_FAILURE);
    }

    // Listen on socket
    if (listen(server_sock, 5) < 0)
    {
        perror("ERROR: IPC listen");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        int cmd;
        int num = 0;
        char buf[4096];

        // Accept connection
        if ((client_sock = accept(server_sock, &client, &len)) < 0)
        {
            perror("ERROR: IPC accept");
            exit(EXIT_FAILURE);
        }

        recv(client_sock, &cmd, sizeof(int), MSG_WAITALL);

        switch (cmd)
        {
        case IPC_EXIT:
            close(server_sock);
            dnbd3_cleanup();
            break;

        case IPC_RELOAD:
            printf("INFO: Reloading configuration...\n");
            pthread_spin_lock(&_spinlock);
            dnbd3_reload_config(_config_file_name);
            pthread_spin_unlock(&_spinlock);
            break;

        case IPC_INFO:
            num = g_slist_length(_dnbd3_clients);
            send(client_sock, &num, sizeof(int), MSG_WAITALL); // send number of clients
            for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
            {
                dnbd3_client_t *client = iterator->data;
                if (client->image)
                {
                    sprintf(buf, "%s\t%s\n", client->ip, client->image->file);
                    send(client_sock, buf, sizeof(buf), MSG_WAITALL);
                }
            }
            close(client_sock);
            break;

        default:
            printf("ERROR: Unknown command: %i", cmd);
            break;

        }

    }

    close(server_sock);
}

void dnbd3_ipc_send(int cmd)
{
    int client_sock;
    struct sockaddr_un server;

    // Create socket
    if ((client_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        perror("ERROR: IPC socket");
        exit(EXIT_FAILURE);
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, UNIX_SOCKET);

    // Connect to server
    if (connect(client_sock, &server, sizeof(server.sun_family) + strlen(server.sun_path)) < 0)
    {
        perror("ERROR: IPC connect");
        exit(EXIT_FAILURE);
    }

    int i, num = 0;
    char buf[4096];

    switch (cmd)
    {
    case IPC_EXIT:
        send(client_sock, &cmd, sizeof(int), MSG_WAITALL);
        break;

    case IPC_RELOAD:
        send(client_sock, &cmd, sizeof(int), MSG_WAITALL);
        break;

    case IPC_INFO:
        send(client_sock, &cmd, sizeof(int), MSG_WAITALL);
        recv(client_sock, &num, sizeof(int), MSG_WAITALL);

        printf("INFO: Number clients connected: %i\n", num);

        for (i = 0; i < num; i++)
        {
            if (recv(client_sock, &buf, sizeof(buf), MSG_WAITALL) > 0)
                printf("INFO: %s", buf);
        }

        break;

    default:
        printf("ERROR: Unknown command: %i", cmd);
        break;

    }

    close(client_sock);
}
