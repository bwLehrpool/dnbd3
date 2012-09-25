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

#include "ipc.h"
#include "../config.h"
#include "server.h"
#include "saveload.h"
#include "memlog.h"
#include "helper.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <sys/stat.h>
#include <grp.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include "xmlutil.h"

#define IPC_PORT (PORT+1)

static int server_sock = -1;
static volatile int keep_running = 1;
static char *payload = NULL;

#define char_repeat_br(_c, _times) do { \
	int _makro_i_ = (_times); \
	while (--_makro_i_ >= 0) putchar(_c); \
	putchar('\n'); \
} while (0)

static int ipc_receive(int client_sock);
static int get_highest_fd(GSList *sockets);
static int is_password_correct(xmlDocPtr doc);
static int get_terminal_width();

static int get_highest_fd(GSList *sockets)
{
	GSList *iterator;
	int max = server_sock;

	for (iterator = sockets; iterator; iterator = iterator->next)
	{
		const int fd = (int)(size_t)iterator->data;
		if (fd > max)
			max = fd;
	}
	//printf("Max fd: %d\n", max);
	return max;
}

void *dnbd3_ipc_mainloop()
{

	// Check version and initialize
	LIBXML_TEST_VERSION

	payload = malloc(MAX_IPC_PAYLOAD);
	if (payload == NULL)
	{
		memlogf("[CRITICAL] Couldn't allocate IPC payload buffer. IPC disabled.");
		pthread_exit((void *)0);
		return NULL;
	}

#ifdef IPC_TCP
	struct sockaddr_in server, client;
	socklen_t len = sizeof(client);

	// Create socket
	if ((server_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		perror("ERROR: IPC socket");
		exit(EXIT_FAILURE);
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET; // IPv4
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(IPC_PORT); // set port number

	const int optval = 1;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	// Bind to socket
	if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) < 0)
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
	socklen_t len = sizeof(client);

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
		memlogf("WARN: Group '%s' not found.\n", UNIX_SOCKET_GROUP);
	}
	else
	{
		chmod(UNIX_SOCKET, 0775);
		chown(UNIX_SOCKET, -1, grp->gr_gid);
	}
#endif

	// Run connection-accepting loop

	fd_set all_sockets, readset, exceptset;

	GSList *sockets = NULL, *iterator;

	int client_sock, ret, flags;
	int maxfd = server_sock + 1;
	int error_count = 0;

	struct timeval client_timeout, select_timeout;
	client_timeout.tv_sec = 0;
	client_timeout.tv_usec = 500 * 1000;

	FD_ZERO(&all_sockets);
	FD_SET(server_sock, &all_sockets);

	// Make listening socket non-blocking
	flags = fcntl(server_sock, F_GETFL, 0);
	if (flags == -1)
		flags = 0;
	fcntl(server_sock, F_SETFL, flags | O_NONBLOCK);

	while (keep_running)
	{
		readset = exceptset = all_sockets;
		select_timeout.tv_sec = 4;
		select_timeout.tv_usec = 0;
		ret = select(maxfd, &readset, NULL, &exceptset, &select_timeout);
		while (ret > 0)
		{
			--ret;
			if (FD_ISSET(server_sock, &readset))
			{
				// Accept connection
				if ((client_sock = accept(server_sock, &client, &len)) < 0)
				{
					if (errno != EAGAIN)
					{
						memlogf("[ERROR] Error accepting an IPC connection");
						if (++error_count > 10)
							goto end_loop;
					}
					continue;
				}
				error_count = 0;
				// Apply read/write timeout
				setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout));
				setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout));
				// Make new connection blocking
				flags = fcntl(client_sock, F_GETFL, 0);
				if (flags == -1)
					flags = 0;
				fcntl(client_sock, F_SETFL, flags & ~(int)O_NONBLOCK);
				sockets = g_slist_prepend(sockets, (void *)(size_t)client_sock);
				if (client_sock >= maxfd)
					maxfd = client_sock + 1;
				//printf("Max fd: %d\n", (maxfd-1));
				FD_SET(client_sock, &all_sockets);
			}
			else if (FD_ISSET(server_sock, &exceptset))
			{
				memlogf("[ERROR] An exception occurred on the IPC listening socket.");
				if (++error_count > 10)
					goto end_loop;
			}
			else
			{
				// Must be an active IPC connection
				int del = -1;
				for (iterator = sockets; iterator; iterator = iterator->next)
				{
					if (del != -1)
					{
						// Delete a previously closed connection from list (delayed, otherwise list might get messed up)
						sockets = g_slist_remove(sockets, (void *)(size_t)del);
						del = -1;
						maxfd = get_highest_fd(sockets) + 1;
					}
					client_sock = (int)(size_t)iterator->data;
					if (FD_ISSET(client_sock, &readset))
					{
						// Client sending data
						if (!ipc_receive(client_sock))
						{
							// Connection has been closed
							close(client_sock);
							del = client_sock;
							FD_CLR(client_sock, &all_sockets);
						}
					}
					else if (FD_ISSET(client_sock, &exceptset))
					{
						// Something unexpected happened, just close connection
						close(client_sock);
						del = client_sock;
						FD_CLR(client_sock, &all_sockets);
					}
				}
				if (del != -1)
				{
					// In case last socket was closed during iteration
					sockets = g_slist_remove(sockets, (void *)(size_t)del);
					maxfd = get_highest_fd(sockets) + 1;
				}
			}
		} // End select loop
	} // End mainloop

end_loop:
	memlogf("[INFO] Shutting down IPC interface.");
	if (server_sock != -1)
	{
		close(server_sock);
		server_sock = -1;
	}

	free(payload);
	xmlCleanupParser();
	pthread_exit((void *)0);
	return NULL;
}

void dnbd3_ipc_shutdown()
{
	keep_running = 0;
	if (server_sock == -1)
		return;
	close(server_sock);
	server_sock = -1;
}

/**
 * Returns !=0 if send/recv successful, 0 on any kind of network failure
 */
static int ipc_receive(int client_sock)
{
	GSList *iterator, *iterator2;

#define STRBUFLEN 100
	char strbuffer[STRBUFLEN];

	dnbd3_ipc_t header;

	uint32_t cmd;

	int ret, locked;
	int return_value = 0;
	xmlDocPtr docReply = NULL, docRequest = NULL;
	xmlNodePtr root_node, parent_node, tmp_node, log_parent_node, log_node, server_node;
	xmlChar *xmlbuff;
	int buffersize;

	ret = recv(client_sock, &header, sizeof(header), MSG_WAITALL);
	if (ret != sizeof(header))
		return ((ret < 0 && errno == EAGAIN) ? 1 : 0);
	cmd = ntohl(header.cmd); // Leave header.cmd in network byte order for reply
	header.size = ntohl(header.size);

	header.error = htonl(ERROR_UNSPECIFIED_ERROR); // Default value of error, so remember to set it for the reply if call succeeded

	if (header.size != 0)
	{
		// Message has payload, receive it
		if (header.size > MAX_IPC_PAYLOAD)
		{
			memlogf("[WARNING] IPC command with payload of %u bytes ignored.", (unsigned int)header.size);
			return 0;
		}
		if (!recv_data(client_sock, payload, header.size))
			return 0;

		docRequest = xmlReadMemory(payload, header.size, "noname.xml", NULL, 0);
	}

	switch (cmd)
	{
	case IPC_EXIT:
		memlogf("[INFO] Server shutdown by IPC request");
		header.size = ntohl(0);
		header.error = ntohl(0);
		return_value = send_data(client_sock, &header, sizeof(header));
		dnbd3_cleanup();
		break;

	case IPC_INFO:
		locked = 0;
		xmlbuff = NULL;
		docReply = xmlNewDoc(BAD_CAST "1.0");
		if (docReply == NULL)
			goto get_info_reply_cleanup;
		root_node = xmlNewNode(NULL, BAD_CAST "data");
		if (root_node == NULL)
			goto get_info_reply_cleanup;
		xmlDocSetRootElement(docReply, root_node);

		xmlNewTextChild(root_node, NULL, BAD_CAST "defaultns", BAD_CAST _local_namespace);

		// Images
		parent_node = xmlNewNode(NULL, BAD_CAST "images");
		if (parent_node == NULL)
			goto get_info_reply_cleanup;
		xmlAddChild(root_node, parent_node);
		locked = 1;
		pthread_spin_lock(&_spinlock);
		for (iterator = _dnbd3_images; iterator; iterator = iterator->next)
		{
			const dnbd3_image_t *image = iterator->data;
			tmp_node = xmlNewNode(NULL, BAD_CAST "image");
			if (tmp_node == NULL)
				goto get_info_reply_cleanup;
			xmlNewProp(tmp_node, BAD_CAST "name", BAD_CAST image->config_group);
			sprintf(strbuffer, "%u", (unsigned int)image->atime);
			xmlNewProp(tmp_node, BAD_CAST "atime", BAD_CAST strbuffer);
			sprintf(strbuffer, "%d", image->rid);
			xmlNewProp(tmp_node, BAD_CAST "rid", BAD_CAST strbuffer);
			sprintf(strbuffer, "%llu", (unsigned long long)image->filesize);
			xmlNewProp(tmp_node, BAD_CAST "size", BAD_CAST strbuffer);
			if (image->file)
				xmlNewProp(tmp_node, BAD_CAST "file", BAD_CAST image->file);
			xmlNewProp(tmp_node, BAD_CAST "servers", BAD_CAST "???"); // TODO
			if (image->cache_file && image->cache_map)
			{
				xmlNewProp(tmp_node, BAD_CAST "cachefile", BAD_CAST image->cache_file);
				int i, complete = 0, size = IMGSIZE_TO_MAPBYTES(image->filesize);
				for (i = 0; i < size; ++i)
					if (image->cache_map[i])
						complete += 100;
				sprintf(strbuffer, "%d", complete / size);
				xmlNewProp(tmp_node, BAD_CAST "cachefill", BAD_CAST strbuffer);
			}
			xmlAddChild(parent_node, tmp_node);
		}
		pthread_spin_unlock(&_spinlock);
		locked = 0;

		// Clients
		parent_node = xmlNewNode(NULL, BAD_CAST "clients");
		if (parent_node == NULL)
			goto get_info_reply_cleanup;
		xmlAddChild(root_node, parent_node);
		locked = 1;
		pthread_spin_lock(&_spinlock);
		for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
		{
			dnbd3_client_t *client = iterator->data;
			if (client->image)
			{
				tmp_node = xmlNewNode(NULL, BAD_CAST "client");
				if (tmp_node == NULL)
					goto get_info_reply_cleanup;
				*strbuffer = '\0';
				host_to_string(&client->host, strbuffer, STRBUFLEN);
				xmlNewProp(tmp_node, BAD_CAST "ip", BAD_CAST strbuffer);
				xmlNewProp(tmp_node, BAD_CAST "file", BAD_CAST client->image->file);
				xmlAddChild(parent_node, tmp_node);
			}
		}
		pthread_spin_unlock(&_spinlock);
		locked = 0;

		// Trusted servers
		parent_node = xmlNewNode(NULL, BAD_CAST "trusted");
		if (parent_node == NULL)
			goto get_info_reply_cleanup;
		xmlAddChild(root_node, parent_node);
		locked = 1;
		pthread_spin_lock(&_spinlock);
		for (iterator = _trusted_servers; iterator; iterator = iterator->next)
		{
			dnbd3_trusted_server_t *server = iterator->data;
			if (server->host.type != 0)
			{
				tmp_node = xmlNewNode(NULL, BAD_CAST "server");
				if (tmp_node == NULL)
					goto get_info_reply_cleanup;
				xmlNodePtr namespace_root = xmlNewNode(NULL, BAD_CAST "namespaces");
				if (namespace_root == NULL)
					goto get_info_reply_cleanup;
				host_to_string(&server->host, strbuffer, STRBUFLEN);
				xmlNewProp(tmp_node, BAD_CAST "address", BAD_CAST strbuffer);
				if (server->comment)
					xmlNewProp(tmp_node, BAD_CAST "comment", BAD_CAST server->comment);
				for (iterator2 = server->namespaces; iterator2; iterator2 = iterator2->next)
				{
					const dnbd3_namespace_t *ns = iterator2->data;
					server_node = xmlNewNode(NULL, BAD_CAST "namespace");
					if (server_node == NULL)
						goto get_info_reply_cleanup;
					xmlAddChild(namespace_root, server_node);
					xmlNewProp(server_node, BAD_CAST "name", BAD_CAST ns->name);
					if (ns->auto_replicate)
						xmlNewProp(server_node, BAD_CAST "replicate", BAD_CAST "1");
					if (ns->recursive)
						xmlNewProp(server_node, BAD_CAST "recursive", BAD_CAST "1");
				}
				xmlAddChild(parent_node, tmp_node);
				xmlAddChild(tmp_node, namespace_root);
			}
		}
		pthread_spin_unlock(&_spinlock);
		locked = 0;

		// Log
		log_parent_node = xmlNewChild(root_node, NULL, BAD_CAST "log", NULL);
		if (log_parent_node == NULL)
			goto get_info_reply_cleanup;
		char *log = fetchlog(0);
		if (log == NULL)
			log = "LOG IS NULL";
		log_node = xmlNewCDataBlock(docReply, BAD_CAST log, strlen(log));
		if (log_node == NULL)
			goto get_info_reply_cleanup;
		xmlAddChild(log_parent_node, log_node);

		// Dump and send
		xmlDocDumpFormatMemory(docReply, &xmlbuff, &buffersize, 1);
		header.size = htonl(buffersize);
		header.error = htonl(0);

get_info_reply_cleanup:
		if (locked)
			pthread_spin_unlock(&_spinlock);
		// Send reply
		return_value = send_data(client_sock, &header, sizeof(header));
		if (return_value && xmlbuff)
			return_value = send_data(client_sock, xmlbuff, buffersize);
		// Cleanup
		xmlFree(xmlbuff);
		free(log);
		break;

	case IPC_ADDIMG:
	case IPC_DELIMG:
		if (docRequest)
		{
			if (!is_password_correct(docRequest))
			{
				header.error = htonl(ERROR_WRONG_PASSWORD);
				header.size = htonl(0);
				return_value = send_data(client_sock, &header, sizeof(header));
				break;
			}

			xmlNodePtr cur = NULL;
			int count = 0;

			FOR_EACH_NODE(docRequest, "/data/images/image", cur)
			{
				if (cur->type != XML_ELEMENT_NODE)
					continue;
				NEW_POINTERLIST;
				++count;
				dnbd3_image_t image;
				memset(&image, 0, sizeof(dnbd3_image_t));
				image.config_group = (char *)XML_GETPROP(cur, "name");
				char *rid_str = (char *)XML_GETPROP(cur, "rid");
				image.file = (char *)XML_GETPROP(cur, "file");
				image.cache_file = (char *)XML_GETPROP(cur, "cache");
				if (image.file && !file_exists(image.file))
				{
					header.error = htonl(ERROR_FILE_NOT_FOUND);
				}
				else if (image.cache_file && !file_writable(image.cache_file))
				{
					header.error = htonl(ERROR_NOT_WRITABLE);
				}
				else
				{
					if (image.config_group && rid_str)
					{
						image.rid = atoi(rid_str);
						if (cmd == IPC_ADDIMG)
							header.error = htonl(dnbd3_add_image(&image));
						else
							header.error = htonl(dnbd3_del_image(&image));
					}
					else
						header.error = htonl(ERROR_MISSING_ARGUMENT);
				}
				FREE_POINTERLIST;
			} END_FOR_EACH;
			if (count == 0)
				header.error = htonl(ERROR_MISSING_ARGUMENT);
		}
		else
			header.error = htonl(ERROR_INVALID_XML);

		header.size = htonl(0);
		printf("Code: %d\n", (int)ntohl(header.error));
		return_value = send_data(client_sock, &header, sizeof(header));
		break;

	case IPC_ADDNS:
	case IPC_DELNS:
		if (docRequest)
		{
			if (!is_password_correct(docRequest))
			{
				header.error = htonl(ERROR_WRONG_PASSWORD);
				header.size = htonl(0);
				return_value = send_data(client_sock, &header, sizeof(header));
				break;
			}

			xmlNodePtr cur = NULL;

			FOR_EACH_NODE(docRequest, "/data/namespaces/namespace", cur)
			{
				if (cur->type != XML_ELEMENT_NODE)
					continue;
				NEW_POINTERLIST;
				char *host = (char *)XML_GETPROP(cur, "server");
				char *ns = (char *)XML_GETPROP(cur, "name");
				char *flags = (char *)XML_GETPROP(cur, "flags");
				char *comment = (char *)XML_GETPROP(cur, "comment");
				pthread_spin_lock(&_spinlock);
				if (host && ns)
				{
					if (cmd == IPC_ADDNS)
					{
						dnbd3_trusted_server_t *server = dnbd3_get_trusted_server(host, TRUE, comment);
						if (server)
							dnbd3_add_trusted_namespace(server, ns, flags);
					}
					else
					{
						dnbd3_trusted_server_t *server = dnbd3_get_trusted_server(host, FALSE, comment);
						if (server)
							dnbd3_del_trusted_namespace(server, ns);
					}
				}
				pthread_spin_unlock(&_spinlock);
				FREE_POINTERLIST;
			} END_FOR_EACH;

		}
		else
			header.error = htonl(ERROR_INVALID_XML);

		header.size = htonl(0);
		return_value = send_data(client_sock, &header, sizeof(header));
		break;

	default:
		memlogf("[ERROR] Unknown IPC command: %u", (unsigned int)header.cmd);
		header.size = htonl(0);
		header.error = htonl(ERROR_UNKNOWN_COMMAND);
		return_value = send_data(client_sock, &header, sizeof(header));
		break;

	}

	xmlFreeDoc(docReply);
	xmlFreeDoc(docRequest);

	return return_value;
}

void dnbd3_ipc_send(int cmd)
{
	int client_sock, size;

	// Check version and initialize
	LIBXML_TEST_VERSION

#ifdef IPC_TCP
	struct sockaddr_in server;
	struct timeval client_timeout;

	// Create socket
	if ((client_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		perror("ERROR: IPC socket");
		exit(EXIT_FAILURE);
	}

	client_timeout.tv_sec = 4;
	client_timeout.tv_usec = 0;
	setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout));
	setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout));

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET; // IPv4
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(IPC_PORT); // set port number

	// Connect to server
	if (connect(client_sock, (struct sockaddr *)&server, sizeof(server)) < 0)
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
	dnbd3_ipc_t header;
	header.cmd = htonl(cmd);
	header.size = 0;
	header.error = 0;
	send(client_sock, (char *)&header, sizeof(header), MSG_WAITALL);
	recv(client_sock, &header, sizeof(header), MSG_WAITALL);
	header.cmd = ntohl(header.cmd);
	header.size = ntohl(header.size);
	header.error = ntohl(header.error);

	if (cmd == IPC_INFO && header.size > 0)
	{
		char *buf = malloc(header.size + 1);
		size = recv(client_sock, buf, header.size, MSG_WAITALL);
		printf("\n%s\n\n", buf);
		xmlDocPtr doc = xmlReadMemory(buf, size, "noname.xml", NULL, 0);
		buf[header.size] = 0;

		if (doc)
		{
			int count;
			int term_width = get_terminal_width();
			xmlNodePtr cur, childit;

			// Print log
			char *log = getTextFromPath(doc, "/data/log");
			if (log)
			{
				printf("--- Last log lines ----\n%s\n\n", log);
				xmlFree(log);
			}

			int watime = 17, wname = 0, wrid = 5;
			FOR_EACH_NODE(doc, "/data/images/image", cur)
			{
				if (cur->type != XML_ELEMENT_NODE)
					continue;
				NEW_POINTERLIST; // This macro defines an array of pointers
				char *vid = XML_GETPROP(cur, "name"); // XML_GETPROP is a macro wrapping xmlGetNoNsProp()
				char *rid = XML_GETPROP(cur, "rid"); // Each of these calls allocates memory for the string
				wname = MAX(wname, strlen(vid));
				wrid = MAX(wrid, strlen(rid));
				FREE_POINTERLIST; // This macro simply frees all pointers in the above array
			} END_FOR_EACH;

			char format[100], strbuffer[STRBUFLEN];
			snprintf(format, 100,
			         "%%-%ds %%-%ds %%%ds %%s\n", watime, wname, wrid);

			// Print images
			printf("Exported images\n");
			printf(format, "atime", "name", "rid", "file");
			char_repeat_br('=', term_width);
			count = 0;
			FOR_EACH_NODE(doc, "/data/images/image", cur)
			{
				if (cur->type != XML_ELEMENT_NODE)
					continue;
				NEW_POINTERLIST;
				++count;
				char *numatime = XML_GETPROP(cur, "atime");
				char *vid = XML_GETPROP(cur, "name");
				char *rid = XML_GETPROP(cur, "rid");
				char *file = XML_GETPROP(cur, "file");
				time_t at = (time_t)atol(numatime);
				struct tm *timeinfo = localtime(&at);
				strftime(strbuffer, STRBUFLEN, "%d.%m.%y %H:%M:%S", timeinfo);
				printf(format, strbuffer, vid, rid, file);
				FREE_POINTERLIST;
			} END_FOR_EACH;
			char_repeat_br('=', term_width);
			printf("\nNumber of images: %d\n\n", count);

			// Print clients
			printf("Connected clients (ip, file):\n");
			char_repeat_br('=', term_width);
			count = 0;
			FOR_EACH_NODE(doc, "/data/clients/client", cur)
			{
				if (cur->type != XML_ELEMENT_NODE)
					continue;
				++count;
				xmlChar *ip = xmlGetNoNsProp(cur, BAD_CAST "ip");
				xmlChar *file = xmlGetNoNsProp(cur, BAD_CAST "file");
				printf("%-40s %s\n", ip, file);
				// Too lazy to free vars, client will exit anyways
			} END_FOR_EACH;
			char_repeat_br('=', term_width);
			printf("\nNumber clients: %d\n\n", count);

			// Print trusted servers
			printf("Trusted servers:\n");
			char_repeat_br('=', term_width);
			count = 0;
			FOR_EACH_NODE(doc, "/data/trusted/server", cur)
			{
				if (cur->type != XML_ELEMENT_NODE)
					continue;
				NEW_POINTERLIST;
				++count;
				char *address = XML_GETPROP(cur, "address");
				char *comment = XML_GETPROP(cur, "comment");
				if (comment)
					printf("%-30s (%s)\n", address, comment);
				else
					printf("%-30s\n", address);
				for (childit = cur->children; childit; childit = childit->next)
				{
					if (childit->type != XML_ELEMENT_NODE || childit->name == NULL || strcmp((const char*)childit->name, "namespace") != 0)
						continue;
					NEW_POINTERLIST;
					char *name = XML_GETPROP(childit, "name");
					char *replicate = XML_GETPROP(childit, "replicate");
					char *recursive = XML_GETPROP(childit, "recursive");
					printf("     %-40s ", name);
					if (replicate && *replicate != '0')
						printf(" replicate");
					if (recursive && *recursive != '0')
						printf(" recursive");
					putchar('\n');
					FREE_POINTERLIST;
				}
				FREE_POINTERLIST;
			} END_FOR_EACH;
			char_repeat_br('=', term_width);
			printf("\nNumber servers: %d\n\n", count);

			// Cleanup
			xmlFreeDoc(doc);
			xmlCleanupParser();

//			xmlDocDump(stdout, doc);

		}
		else
		{
			printf("ERROR: Failed to parse reply\n-----------\n%s\n-------------\n", buf);
		}

	}

	close(client_sock);
}

/**
 * Check if the correct server password is present in xpath /data/password
 * return !=0 if correct, 0 otherwise
 */
static int is_password_correct(xmlDocPtr doc)
{
	if (_ipc_password == NULL)
	{
		memlogf("[WARNING] IPC access granted as no password is set!");
		return 1;
	}
	char *pass = getTextFromPath(doc, "/data/password");
	if (pass == NULL)
		return 0;
	if (strcmp(pass, _ipc_password) == 0)
	{
		xmlFree(pass);
		return 1;
	}
	xmlFree(pass);
	return 0;
}

static int get_terminal_width()
{
	struct winsize w;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) < 0)
		return 80;
	return w.ws_col;
}
