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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "server.h"
#include "utils.h"

void *dnbd3_handle_query(void *dnbd3_client)
{
    dnbd3_client_t *client = (dnbd3_client_t *) (uintptr_t) dnbd3_client;
    dnbd3_request_t request;
    dnbd3_reply_t reply;

    int image_file = -1;
    dnbd3_image_t *image;

    struct in_addr server;
    int i = 0;

    while (recv(client->sock, &request, sizeof(dnbd3_request_t), MSG_WAITALL) > 0)
    {
        reply.cmd = request.cmd;
        reply.error = 0;
        memcpy(reply.handle, request.handle, sizeof(request.handle));

        // TODO: lock CMD_GET_SERVERS and CMD_GET_SIZE because of reloading cfg...
        // pthread_spin_lock(&_spinlock);
        // pthread_spin_unlock(&_spinlock);

        switch (request.cmd)
        {
        case CMD_GET_SERVERS:
            if(!client->image)
            { // configuration was reloaded, send error
                reply.size = 0;
                reply.error = ERROR_RELOAD;
                send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);
                continue;
            }

            if (client->image->num_servers < MAX_NUMBER_SERVERS)
                reply.size = client->image->num_servers * sizeof(struct in_addr);
            else
                reply.size = MAX_NUMBER_SERVERS * sizeof(struct in_addr);

            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);

            for (i = 0; i < client->image->num_servers && i < MAX_NUMBER_SERVERS; i++)
            {
                inet_aton(client->image->servers[i], &server);
                send(client->sock, (char *) &server, sizeof(struct in_addr), 0);
            }
            continue;

        case CMD_GET_SIZE:
            image = dnbd3_get_image(request.vid, request.rid);

            if(!image)
            { // image not found, send error
                printf("ERROR: Client requested an unknown image id.\n");
                reply.size = 0;
                reply.error = ERROR_SIZE;
                send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);
                continue;
            }

            image_file = open(image->file, O_RDONLY);
            reply.size = sizeof(uint64_t);
            client->image = image;
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);
            send(client->sock, &image->filesize, sizeof(uint64_t), 0);
            continue;

        case CMD_GET_BLOCK:
            if (image_file < 0)
                continue;

            reply.size = request.size;
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);

            if (sendfile(client->sock, image_file, (off_t *) &request.offset, request.size) < 0)
                printf("ERROR: sendfile returned -1\n");

            continue;

        default:
            printf("ERROR: Unknown command\n");
            continue;

        }

    }
    close(client->sock);
    close(image_file);
    _dnbd3_clients = g_slist_remove(_dnbd3_clients, client);
    free(client);
    printf("INFO: Client %s exit\n", client->ip);
    pthread_exit((void *) 0);
}

int dnbd3_setup_socket()
{
    int sock;
    struct sockaddr_in server;

    // Create socket
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
    {
        printf("ERROR: Socket failure\n");
        return -1;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET; // IPv4
    server.sin_addr.s_addr = htonl(INADDR_ANY); // Take all IPs
    server.sin_port = htons(PORT); // set port number

    // Bind to socket
    if (bind(sock, (struct sockaddr*) &server, sizeof(server)) < 0)
    {
        printf("ERROR: Bind failure\n");
        return -1;
    }

    // Listen on socket
    if (listen(sock, 50) == -1)
    {
        printf("ERROR: Listen failure\n");
        return -1;
    }

    return sock;
}
