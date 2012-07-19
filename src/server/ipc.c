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
#include <sys/stat.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>

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

    struct tm * timeinfo;
    char time_buff[64];

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

    // Set groupID and permissions on ipc socket
    struct group *grp;
    grp = getgrnam(UNIX_SOCKET_GROUP);
    if (grp == NULL)
    {
    	printf("WARN: Group '%s' not found.\n", UNIX_SOCKET_GROUP);
    }
    else
    {
    	chmod(UNIX_SOCKET, 0775);
    	chown(UNIX_SOCKET, -1, grp->gr_gid);
    }

    while (1)
    {
    	int i = 0;
        uint32_t cmd;

        // Accept connection
        if ((client_sock = accept(server_sock, &client, &len)) < 0)
        {
            perror("ERROR: IPC accept");
            exit(EXIT_FAILURE);
        }

        recv(client_sock, &cmd, sizeof(cmd), MSG_WAITALL);

        switch (ntohl(cmd))
        {
        case IPC_EXIT:
        	printf("INFO: Server shutdown...\n");
        	close(client_sock);
            close(server_sock);
            dnbd3_cleanup();
            break;

        case IPC_RELOAD:
            printf("INFO: Reloading configuration...\n");
            dnbd3_reload_config(_config_file_name);
            close(client_sock);
            break;

        case IPC_INFO:
            pthread_spin_lock(&_spinlock);

            int reply_size = (g_slist_length(_dnbd3_clients) + _num_images) * 4096 + 20;
            char *reply = calloc(reply_size, sizeof(char));
            char line[4096];

            strcat(reply, "Exported images (atime, vid, rid, file):\n");
            strcat( reply, "========================================\n");
            for (i = 0; i < _num_images; i++)
            {
                timeinfo = localtime(&_images[i].atime);
                strftime (time_buff,64,"%d.%m.%y %H:%M:%S",timeinfo);
                sprintf(line, "%s\t%i\t%i\t%s\n", time_buff, _images[i].vid, _images[i].rid,_images[i].file);
                strcat(reply, line);
            }
            sprintf(line, "\nNumber images: %Zu\n\n", _num_images);
            strcat(reply, line);
            strcat(reply, "Connected clients (ip, file):\n");
            strcat(reply, "=============================\n");
            for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
            {
                dnbd3_client_t *client = iterator->data;
                if (client->image)
                {
                    sprintf(line, "%s\t%s\n", client->ip, client->image->file);
                    strcat(reply, line);
                }
            }
            sprintf(line, "\nNumber clients: %i\n\n", g_slist_length(_dnbd3_clients));
            strcat(reply, line);

            send(client_sock, reply, reply_size*sizeof(char), MSG_WAITALL);

            pthread_spin_unlock(&_spinlock);
            close(client_sock);
            free(reply);
            break;

        default:
            printf("ERROR: Unknown command: %i\n", cmd);
            close(client_sock);
            break;

        }
    }
    close(server_sock);
}

void dnbd3_ipc_send(int cmd)
{
    int client_sock;
    struct sockaddr_un server;
    uint32_t cmd_net = htonl(cmd);
    char buf[64];

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

    // Send and receive messages
    send(client_sock, &cmd_net, sizeof(cmd_net), MSG_WAITALL);
	while (recv(client_sock, &buf, sizeof(buf), MSG_WAITALL) > 0)
		printf("%s", buf);

    close(client_sock);
}
