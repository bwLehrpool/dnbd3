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
#include <arpa/inet.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "ipc.h"
#include "config.h"
#include "server.h"
#include "utils.h"

void* dnbd3_ipc_receive()
{
    GSList *iterator = NULL;

    struct tm * timeinfo;
    char time_buff[64];

    int server_sock, client_sock;

#ifdef IPC_TCP
    struct sockaddr_in server, client;
    unsigned int len = sizeof(client);

    // Create socket
    if ((server_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        perror("ERROR: IPC socket");
        exit(EXIT_FAILURE);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET; // IPv4
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(IPC_PORT); // set port number

    // Bind to socket
    if (bind(server_sock, (struct sockaddr*) &server, sizeof(server)) < 0)
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
#else
    struct sockaddr_un server, client;
    unsigned int len = sizeof(client);

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
#endif

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

            xmlDocPtr doc;
            xmlNodePtr root_node, images_node, clients_node, tmp_node;
            xmlChar *xmlbuff;
            int buffersize;

            doc = xmlNewDoc(BAD_CAST "1.0");
            root_node = xmlNewNode(NULL, BAD_CAST "dnbd3-server");
            xmlDocSetRootElement(doc, root_node);

            // Images
            images_node = xmlNewNode(NULL, BAD_CAST "images");
            xmlAddChild(root_node, images_node);
			for (i = 0; i < _num_images; i++)
			{
				char vid[20], rid[20];
				sprintf(vid,"%d",_images[i].vid);
				sprintf(rid,"%d",_images[i].rid);
				timeinfo = localtime(&_images[i].atime);
				strftime(time_buff,64,"%d.%m.%y %H:%M:%S",timeinfo);
				tmp_node = xmlNewNode(NULL, BAD_CAST "image");
				xmlNewProp(tmp_node, BAD_CAST "atime", BAD_CAST time_buff);
				xmlNewProp(tmp_node, BAD_CAST "vid", BAD_CAST vid);
				xmlNewProp(tmp_node, BAD_CAST "rid", BAD_CAST rid);
				xmlNewProp(tmp_node, BAD_CAST "file", BAD_CAST _images[i].file);
				xmlAddChild(images_node, tmp_node);
			}

			// Clients
            clients_node = xmlNewNode(NULL, BAD_CAST "clients");
            xmlAddChild(root_node, clients_node);
			for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
			{
				dnbd3_client_t *client = iterator->data;
				if (client->image)
				{
					tmp_node = xmlNewNode(NULL, BAD_CAST "client");
					xmlNewProp(tmp_node, BAD_CAST "ip", BAD_CAST client->ip);
					xmlNewProp(tmp_node, BAD_CAST "file", BAD_CAST client->image->file);
					xmlAddChild(clients_node, tmp_node);
				}
			}

			// Dump and send
            xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);
            send(client_sock, (char *) xmlbuff, buffersize, MSG_WAITALL);

            // Cleanup
            pthread_spin_unlock(&_spinlock);
            close(client_sock);
            xmlFree(xmlbuff);
            xmlFreeDoc(doc);
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
	uint32_t cmd_net = htonl(cmd);
    int client_sock, size;
    char buf[64];

    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;

#ifdef IPC_TCP
    struct sockaddr_in server;

    // Create socket
    if ((client_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        perror("ERROR: IPC socket");
        exit(EXIT_FAILURE);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET; // IPv4
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(IPC_PORT); // set port number

    // Connect to server
    if (connect(client_sock, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
        perror("ERROR: IPC connect");
        exit(EXIT_FAILURE);
    }
#else
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
#endif

    // Send message
    send(client_sock, &cmd_net, sizeof(cmd_net), MSG_WAITALL);

    if (cmd == IPC_INFO)
    {
    	// Parse reply
    	ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
		while ( (size=recv(client_sock, &buf, sizeof(buf), MSG_WAITALL)) > 0)
			xmlParseChunk(ctxt, buf, size, 0);

		// Indicate the parsing is finished
		xmlParseChunk(ctxt, buf, 0, 1);
		doc = ctxt->myDoc;

		// Print reply to stdout
		if (ctxt->wellFormed)
		{
		    int n, i;

		    xmlXPathContextPtr xpathCtx;
		    xmlXPathObjectPtr xpathObj;
		    xmlChar* xpathExpr;
		    xmlNodeSetPtr nodes;
		    xmlNodePtr cur;

		    // Print images
		    xpathExpr = BAD_CAST "/dnbd3-server/images/image";
		    xpathCtx = xmlXPathNewContext(doc);
		    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
		    printf("Exported images (atime, vid, rid, file):\n");
		    printf("========================================\n");
		    nodes = xpathObj->nodesetval;
		    n = (nodes) ? nodes->nodeNr : 0;
		    for(i = 0; i < n; ++i)
		    {
				if(nodes->nodeTab[i]->type == XML_ELEMENT_NODE)
				{
					cur = nodes->nodeTab[i];
					xmlChar *atime = xmlGetNoNsProp(cur, BAD_CAST "atime");
					xmlChar *vid = xmlGetNoNsProp(cur, BAD_CAST "vid");
					xmlChar *rid = xmlGetNoNsProp(cur, BAD_CAST "rid");
					xmlChar *file = xmlGetNoNsProp(cur, BAD_CAST "file");
					printf("%s\t%s\t%s\t%s\n", atime, vid, rid, file);
				}
		    }
		    printf("\nNumber images: %d\n\n", n);
		    xmlXPathFreeObject(xpathObj);
		    xmlXPathFreeContext(xpathCtx);

		    // Print clients
		    xpathExpr = BAD_CAST "/dnbd3-server/clients/client";
		    xpathCtx = xmlXPathNewContext(doc);
		    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
		    printf("Connected clients (ip, file):\n");
		    printf("=============================\n");
		    nodes = xpathObj->nodesetval;
		    n = (nodes) ? nodes->nodeNr : 0;
		    for(i = 0; i < n; ++i)
		    {
				if(nodes->nodeTab[i]->type == XML_ELEMENT_NODE)
				{
					cur = nodes->nodeTab[i];
					xmlChar *ip = xmlGetNoNsProp(cur, BAD_CAST "ip");
					xmlChar *file = xmlGetNoNsProp(cur, BAD_CAST "file");
					printf("%s\t%s\n", ip, file);
				}
		    }
		    printf("\nNumber clients: %d\n\n", n);
		    xmlXPathFreeObject(xpathObj);
		    xmlXPathFreeContext(xpathCtx);
			//xmlDocDump(stdout, doc);
		}
		else
		{
			printf("ERROR: Failed to parse reply\n");
		}

		// Cleanup
		xmlFreeParserCtxt(ctxt);
		xmlFreeDoc(doc);
		xmlCleanupParser();
    }

    close(client_sock);
}
