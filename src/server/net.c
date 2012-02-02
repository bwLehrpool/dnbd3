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

#include "server.h"
#include "utils.h"

void *dnbd3_handle_query(void *dnbd3_client)
{
    dnbd3_client_t *client = (dnbd3_client_t *) (uintptr_t) dnbd3_client;
    int image_file = -1;
    dnbd3_request_t request;
    dnbd3_reply_t reply;
    uint16_t cmd;

    while (recv(client->sock, &request, sizeof(dnbd3_request_t), MSG_WAITALL) > 0)
    {
        cmd = request.cmd;
        switch (cmd)
        {
        case CMD_PING:
            reply.cmd = request.cmd;
            memcpy(reply.handle, request.handle, sizeof(request.handle));
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);
            break;

        case CMD_GET_SIZE:
            pthread_spin_lock(&_spinlock); // because of reloading config
            dnbd3_image_t *image = dnbd3_get_image(request.vid, request.rid);
            pthread_spin_unlock(&_spinlock);
            if (image)
            {
                image_file = open(image->file, O_RDONLY);
                reply.filesize = image->filesize;
                client->image = image;
            }
            else
            {
                printf("ERROR: Client requested an unknown image id.\n");
                reply.filesize = 0;
            }
            reply.cmd = request.cmd;
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);
            break;

        case CMD_GET_BLOCK:
            if (image_file < 0)
                break;

            reply.cmd = request.cmd;
            memcpy(reply.handle, request.handle, sizeof(request.handle));
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);

            if (sendfile(client->sock, image_file, (off_t *) &request.offset, request.size) < 0)
                printf("ERROR: sendfile returned -1\n");

            break;

        default:
            printf("ERROR: Unknown command\n");
            break;
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
