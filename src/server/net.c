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
#include <netinet/tcp.h>

#include "server.h"
#include "utils.h"

void *dnbd3_handle_query(void *dnbd3_client)
{
    dnbd3_client_t *client = (dnbd3_client_t *) (uintptr_t) dnbd3_client;
    dnbd3_request_t request;
    dnbd3_reply_t reply;

    int cork = 1;
    int uncork = 0;

    dnbd3_image_t *image = NULL;
    int image_file, image_cache = -1;

    struct in_addr alt_server;
    int i = 0;

    uint64_t map_y;
    char map_x, bit_mask;

    uint64_t todo_size, todo_offset, cur_offset, last_offset = 0;
    int dirty = 0;

    while (recv(client->sock, &request, sizeof(dnbd3_request_t), MSG_WAITALL) > 0)
    {
        reply.cmd = request.cmd;
        reply.size = 0;
        memcpy(reply.handle, request.handle, sizeof(request.handle));

        pthread_spin_lock(&client->spinlock);
        switch (request.cmd)
        {
        case CMD_GET_SERVERS:
            image = dnbd3_get_image(request.vid, request.rid);
            if(!image)
                goto error;

            int num = (image->num_servers < NUMBER_SERVERS) ? image->num_servers : NUMBER_SERVERS;
            reply.vid = image->vid;
            reply.rid = image->rid;
            reply.size = num * sizeof(struct in_addr);
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);

            for (i = 0; i < num; i++)
            {
                inet_aton(image->servers[i], &alt_server);
                send(client->sock, (char *) &alt_server, sizeof(struct in_addr), 0);
            }
            client->image = image;
            image->atime = time(NULL); // TODO: check if mutex is needed
            break;

        case CMD_GET_SIZE:
            image = dnbd3_get_image(request.vid, request.rid);
            if(!image)
                goto error;

            reply.vid = image->vid;
            reply.rid = image->rid;
            reply.size = sizeof(uint64_t);
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);

            send(client->sock, &image->filesize, sizeof(uint64_t), 0);
            image_file = open(image->file, O_RDONLY);
            client->image = image;
            image->atime = time(NULL); // TODO: check if mutex is needed

            if (image->cache_file)
                image_cache = open(image->cache_file, O_RDWR);

            break;

        case CMD_GET_BLOCK:
            if (image_file < 0)
                goto error;

            setsockopt(client->sock, SOL_TCP, TCP_CORK, &cork, sizeof(cork));
            reply.size = request.size;
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);

            // caching is off
            if (!image->cache_file)
            {
                if (sendfile(client->sock, image_file, (off_t *) &request.offset, request.size) < 0)
                    printf("ERROR: Sendfile failed (sock)\n");

                setsockopt(client->sock, SOL_TCP, TCP_CORK, &uncork, sizeof(uncork));
                break;
            }

            // caching is on
            dirty = 0;
            todo_size = 0;
            todo_offset = request.offset;
            cur_offset = request.offset;
            last_offset = request.offset + request.size;

            while(cur_offset < last_offset)
            {
                map_y = cur_offset >> 15;
                map_x = (cur_offset >> 12) & 7; // mod 8
                bit_mask = 0b00000001 << (map_x);

                cur_offset += 4096;

                if ((image->cache_map[map_y] & bit_mask) != 0) // cache hit
                {
                    if (todo_size != 0) // fetch missing chunks
                    {
                        lseek(image_cache, todo_offset, SEEK_SET);
                        if (sendfile(image_cache, image_file, (off_t *) &todo_offset, todo_size) < 0)
                            printf("ERROR: Sendfile failed (cache)\n");
                        todo_size = 0;
                        dirty = 1;
                    }
                    todo_offset = cur_offset;
                }
                else
                {
                    todo_size += 4096;
                }
            }

            // whole request was missing
            if (todo_size != 0)
            {
                lseek(image_cache, todo_offset, SEEK_SET);
                if (sendfile(image_cache, image_file, (off_t *) &todo_offset, todo_size) < 0)
                    printf("ERROR: Sendfile failed (cache)\n");

                dirty = 1;
            }

            if (dirty)
            {
                // set 1 in cache map for whole request
                cur_offset = request.offset;
                while(cur_offset < last_offset)
                {
                    map_y = cur_offset >> 15;
                    map_x = (cur_offset >> 12) & 7; // mod 8
                    bit_mask = 0b00000001 << (map_x);
                    image->cache_map[map_y] |= bit_mask;
                    cur_offset += 4096;
                }
            }

            // send data to client
            if (sendfile(client->sock, image_cache, (off_t *) &request.offset, request.size) < 0)
                printf("ERROR: Sendfile failed (net)\n");

            setsockopt(client->sock, SOL_TCP, TCP_CORK, &uncork, sizeof(uncork));
            break;

        default:
            printf("ERROR: Unknown command\n");
            break;

        }

        pthread_spin_unlock(&client->spinlock);
        continue;

        error:
            printf("ERROR: Client requested an unknown image id.\n");
            send(client->sock, (char *) &reply, sizeof(dnbd3_reply_t), 0);
            pthread_spin_unlock(&client->spinlock);
            continue;

    }
    close(client->sock);
    close(image_file);
    close(image_cache);
    pthread_spin_lock(&_spinlock);
    _dnbd3_clients = g_slist_remove(_dnbd3_clients, client);
    pthread_spin_unlock(&_spinlock);
    printf("INFO: Client %s exit\n", client->ip);
    free(client);
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
    if (listen(sock, 100) == -1)
    {
        printf("ERROR: Listen failure\n");
        return -1;
    }

    return sock;
}
