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

#include "ipc.h"
#include "../config.h"
#include "server.h"
#include "utils.h"
#include "memlog.h"

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
static int send_reply(int client_sock, void *data_in, int len);
static int recv_data(int client_sock, void *buffer_out, int len);
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
 * Send message to client, return !=0 on success, 0 on failure
 */
static int send_reply(int client_sock, void *data_in, int len)
{
	if (len <= 0) // Nothing to send
		return 1;
	char *data = data_in; // Needed for pointer arithmetic
	int ret, i;
	for (i = 0; i < 3; ++i) // Retry at most 3 times, each try takes at most 0.5 seconds (socket timeout)
	{
		ret = send(client_sock, data, len, 0);
		if (ret == 0) // Connection closed
			return 0;
		if (ret < 0)
		{
			if (errno != EAGAIN) // Some unexpected error
				return 0;
			usleep(1000); // 1ms
			continue;
		}
		len -= ret;
		if (len <= 0) // Sent everything
			return 1;
		data += ret; // move target buffer pointer
	}
	return 0;
}

/**
 * Receive data from client, return !=0 on success, 0 on failure
 */
static int recv_data(int client_sock, void *buffer_out, int len)
{
	if (len <= 0) // Nothing to receive
		return 1;
	char *data = buffer_out; // Needed for pointer arithmetic
	int ret, i;
	for (i = 0; i < 3; ++i) // Retry at most 3 times, each try takes at most 0.5 seconds (socket timeout)
	{
		ret = recv(client_sock, data, len, MSG_WAITALL);
		if (ret == 0) // Connection closed
			return 0;
		if (ret < 0)
		{
			if (errno != EAGAIN) // Some unexpected error
				return 0;
			usleep(1000); // 1ms
			continue;
		}
		len -= ret;
		if (len <= 0) // Received everything
			return 1;
		data += ret; // move target buffer pointer
	}
	return 0;
}

/**
 * Returns !=0 if send/recv successful, 0 on any kind of network failure
 */
static int ipc_receive(int client_sock)
{
	GSList *iterator = NULL;

	struct tm *timeinfo;
#define STRBUFLEN 100
	char strbuffer[STRBUFLEN];

	dnbd3_ipc_t header;

	uint32_t cmd;

	int ret, locked;
	int return_value = 0;
	xmlDocPtr docReply = NULL, docRequest = NULL;
	xmlNodePtr root_node, images_node, clients_node, tmp_node, log_parent_node, log_node;
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
	}

	switch (cmd)
	{
	case IPC_EXIT:
		memlogf("[INFO] Server shutdown by IPC request");
		header.size = ntohl(0);
		header.error = ntohl(0);
		return_value = send_reply(client_sock, &header, sizeof(header));
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

		// Images
		images_node = xmlNewNode(NULL, BAD_CAST "images");
		if (images_node == NULL)
			goto get_info_reply_cleanup;
		xmlAddChild(root_node, images_node);
		locked = 1;
		pthread_spin_lock(&_spinlock);
		for (iterator = _dnbd3_images; iterator; iterator = iterator->next)
		{
			const dnbd3_image_t *image = iterator->data;
			tmp_node = xmlNewNode(NULL, BAD_CAST "image");
			if (tmp_node == NULL)
				goto get_info_reply_cleanup;
			xmlNewProp(tmp_node, BAD_CAST "name", BAD_CAST image->config_group);
			timeinfo = localtime(&image->atime);
			strftime(strbuffer, STRBUFLEN, "%d.%m.%y %H:%M:%S", timeinfo);
			xmlNewProp(tmp_node, BAD_CAST "atime", BAD_CAST strbuffer);
			sprintf(strbuffer, "%d", image->rid);
			xmlNewProp(tmp_node, BAD_CAST "rid", BAD_CAST strbuffer);
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
				xmlNewProp(tmp_node, BAD_CAST "cachefill", BAD_CAST image->cache_file);
			}
			xmlAddChild(images_node, tmp_node);
		}
		// Clients
		clients_node = xmlNewNode(NULL, BAD_CAST "clients");
		if (clients_node == NULL)
			goto get_info_reply_cleanup;
		xmlAddChild(root_node, clients_node);
		for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
		{
			dnbd3_client_t *client = iterator->data;
			if (client->image)
			{
				tmp_node = xmlNewNode(NULL, BAD_CAST "client");
				if (tmp_node == NULL)
					goto get_info_reply_cleanup;
				*strbuffer = '\0';
				inet_ntop(client->addrtype, client->ipaddr, strbuffer, STRBUFLEN);
				xmlNewProp(tmp_node, BAD_CAST "ip", BAD_CAST strbuffer);
				xmlNewProp(tmp_node, BAD_CAST "file", BAD_CAST client->image->file);
				xmlAddChild(clients_node, tmp_node);
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
		return_value = send_reply(client_sock, &header, sizeof(header));
		if (return_value && xmlbuff)
			return_value = send_reply(client_sock, xmlbuff, buffersize);
		// Cleanup
		xmlFree(xmlbuff);
		free(log);
		break;

	case IPC_ADDIMG:
	case IPC_DELIMG:
		if (header.size == 0)
		{
			header.size = htonl(0);
			header.error = htonl(ERROR_MISSING_ARGUMENT);
			return_value = send_reply(client_sock, &header, sizeof(header));
			break;
		}
		docRequest = xmlReadMemory(payload, header.size, "noname.xml", NULL, 0);

		if (docRequest)
		{
			if (!is_password_correct(docRequest))
			{
				header.error = htonl(ERROR_WRONG_PASSWORD);
				header.size = htonl(0);
				return_value = send_reply(client_sock, &header, sizeof(header));
				break;
			}

			xmlNodePtr cur = NULL;
			int count = 0;

			FOR_EACH_NODE(docRequest, "/data/images/image", cur)
			{
				if (cur->type == XML_ELEMENT_NODE)
				{
					++count;
					dnbd3_image_t image;
					memset(&image, 0, sizeof(dnbd3_image_t));
					image.config_group = (char *)xmlGetNoNsProp(cur, BAD_CAST "name");
					char *rid_str = (char *)xmlGetNoNsProp(cur, BAD_CAST "rid");
					image.file = (char *)xmlGetNoNsProp(cur, BAD_CAST "file");
					image.cache_file = (char *)xmlGetNoNsProp(cur, BAD_CAST "cache");
					if (image.config_group && rid_str && image.file && image.cache_file)
					{
						image.rid = atoi(rid_str);
						if (cmd == IPC_ADDIMG)
							header.error = htonl(dnbd3_add_image(&image));
						else
							header.error = htonl(dnbd3_del_image(&image));
					}
					else
						header.error = htonl(ERROR_MISSING_ARGUMENT);
					xmlFree(image.config_group);
					xmlFree(rid_str);
					xmlFree(image.file);
					xmlFree(image.cache_file);
				}
			} END_FOR_EACH;
			if (count == 0)
				header.error = htonl(ERROR_MISSING_ARGUMENT);
		}
		else
			header.error = htonl(ERROR_INVALID_XML);

		header.size = htonl(0);
		return_value = send_reply(client_sock, &header, sizeof(header));
		break;

	default:
		memlogf("[ERROR] Unknown IPC command: %u", (unsigned int)header.cmd);
		header.size = htonl(0);
		header.error = htonl(ERROR_UNKNOWN_COMMAND);
		return_value = send_reply(client_sock, &header, sizeof(header));
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
		xmlDocPtr doc = xmlReadMemory(buf, size, "noname.xml", NULL, 0);
		buf[header.size] = 0;

		if (doc)
		{
			int count;
			int term_width = get_terminal_width();
			xmlNodePtr cur;

			// Print log
			xmlChar *log = getTextFromPath(doc, "/data/log");
			if (log)
			{
				printf("--- Last log lines ----\n%s\n\n", log);
			}

			int watime = 0, wname = 0, wrid = 5;
			FOR_EACH_NODE(doc, "/data/images/image", cur)
			{
				if (cur->type == XML_ELEMENT_NODE)
				{
					xmlChar *atime = xmlGetNoNsProp(cur, BAD_CAST "atime");
					xmlChar *vid = xmlGetNoNsProp(cur, BAD_CAST "name");
					xmlChar *rid = xmlGetNoNsProp(cur, BAD_CAST "rid");
					watime = MAX(watime, xmlStrlen(atime));
					wname = MAX(wname, xmlStrlen(vid));
					wrid = MAX(wrid, xmlStrlen(rid));
					// Too lazy to free vars, client will exit anyways
				}
			} END_FOR_EACH;

			char format[100];
			snprintf(format, 100,
				"%%-%ds %%-%ds %%%ds %%s\n", watime, wname, wrid);

			// Print images
			printf("Exported images\n");
			printf(format, "atime", "name", "rid", "file");
			char_repeat_br('=', term_width);
			count = 0;
			FOR_EACH_NODE(doc, "/data/images/image", cur)
			{
				if (cur->type == XML_ELEMENT_NODE)
				{
					++count;
					xmlChar *atime = xmlGetNoNsProp(cur, BAD_CAST "atime");
					xmlChar *vid = xmlGetNoNsProp(cur, BAD_CAST "name");
					xmlChar *rid = xmlGetNoNsProp(cur, BAD_CAST "rid");
					xmlChar *file = xmlGetNoNsProp(cur, BAD_CAST "file");
					printf(format, atime, vid, rid, file);
					// Too lazy to free vars, client will exit anyways
				}
			} END_FOR_EACH;
			char_repeat_br('=', term_width);
			printf("\nNumber of images: %d\n\n", count);

			// Print clients
			printf("Connected clients (ip, file):\n");
			char_repeat_br('=', term_width);
			count = 0;
			FOR_EACH_NODE(doc, "/data/clients/client", cur)
			{
				if (cur->type == XML_ELEMENT_NODE)
				{
					++count;
					xmlChar *ip = xmlGetNoNsProp(cur, BAD_CAST "ip");
					xmlChar *file = xmlGetNoNsProp(cur, BAD_CAST "file");
					printf("%-40s %s\n", ip, file);
					// Too lazy to free vars, client will exit anyways
				}
			} END_FOR_EACH;
			char_repeat_br('=', term_width);
			printf("\nNumber clients: %d\n\n", count);

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
	xmlChar *pass = getTextFromPath(doc, "/data/password");
	if (pass == NULL)
		return 0;
	if (strcmp((char*)pass, _ipc_password) == 0)
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
