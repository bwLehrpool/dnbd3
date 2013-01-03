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

#include "rpc.h"
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

#define RPC_PORT (PORT+1)

static int server_sock = -1;
static volatile int keep_running = 1;
static char *payload = NULL;

#define char_repeat_br(_c, _times) do { \
	int _makro_i_ = (_times); \
	while (--_makro_i_ >= 0) putchar(_c); \
	putchar('\n'); \
} while (0)

static int rpc_receive(int client_sock);
static int get_highest_fd(GSList *sockets);
static int is_password_correct(xmlDocPtr doc);
static int get_terminal_width();
static int rpc_send_reply(int sock, dnbd3_rpc_t* header, int result_code, xmlDocPtr payload);

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

void *dnbd3_rpc_mainloop()
{

	// Check version and initialize
	LIBXML_TEST_VERSION

	payload = malloc(MAX_RPC_PAYLOAD);
	if (payload == NULL)
	{
		memlogf("[CRITICAL] Couldn't allocate RPC payload buffer. RPC disabled.");
		pthread_exit((void *)0);
		return NULL;
	}

	struct sockaddr_in server, client;
	socklen_t len = sizeof(client);

	// Create socket
	if ((server_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		perror("ERROR: RPC socket");
		exit(EXIT_FAILURE);
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET; // IPv4
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(RPC_PORT); // set port number

	const int optval = 1;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	// Bind to socket
	if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		perror("ERROR: RPC bind");
		exit(EXIT_FAILURE);
	}

	// Listen on socket
	if (listen(server_sock, 5) < 0)
	{
		perror("ERROR: RPC listen");
		exit(EXIT_FAILURE);
	}

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
						memlogf("[ERROR] Error accepting an RPC connection");
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
				memlogf("[ERROR] An exception occurred on the RPC listening socket.");
				if (++error_count > 10)
					goto end_loop;
			}
			else
			{
				// Must be an active RPC connection
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
						if (!rpc_receive(client_sock))
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
	memlogf("[INFO] Shutting down RPC interface.");
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

void dnbd3_rpc_shutdown()
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
static int rpc_receive(int client_sock)
{
	GSList *iterator, *iterator2;

#define STRBUFLEN 100
	char strbuffer[STRBUFLEN];

	dnbd3_rpc_t header;

	uint32_t cmd;

	int ret, locked = 0;
	int return_value = 0;
	xmlDocPtr docReply = NULL, docRequest = NULL;
	xmlNodePtr root_node, parent_node, tmp_node, log_parent_node, log_node, server_node;

	ret = recv(client_sock, &header, sizeof(header), MSG_WAITALL);
	if (ret != sizeof(header))
		return ((ret < 0 && errno == EAGAIN) ? 1 : 0);
	cmd = ntohl(header.cmd); // Leave header.cmd in network byte order for reply
	header.size = ntohl(header.size);

	int rpc_error = ERROR_UNSPECIFIED_ERROR; // Default value of error, so remember to set it for the reply if call succeeded

	if (header.size != 0)
	{
		// Message has payload, receive it
		if (header.size > MAX_RPC_PAYLOAD)
		{
			memlogf("[WARNING] RPC command with payload of %u bytes ignored.", (unsigned int)header.size);
			return 0;
		}
		if (!recv_data(client_sock, payload, header.size))
			return 0;

		docRequest = xmlReadMemory(payload, header.size, "noname.xml", NULL, 0);
	}

	switch (cmd)
	{
	case RPC_EXIT:
		memlogf("[INFO] Server shutdown by RPC request");
		header.size = ntohl(0);
		return_value = send_data(client_sock, &header, sizeof(header));
		dnbd3_cleanup();
		break;

	case RPC_IMG_LIST:
		if (!createXmlDoc(&docReply, &root_node, "data"))
			goto case_end;

		// Images
		parent_node = xmlNewNode(NULL, BAD_CAST "images");
		if (parent_node == NULL)
			goto case_end;
		xmlAddChild(root_node, parent_node);
		locked = 1;
		pthread_spin_lock(&_spinlock);
		for (iterator = _dnbd3_images; iterator; iterator = iterator->next)
		{
			const dnbd3_image_t *image = iterator->data;
			tmp_node = xmlNewNode(NULL, BAD_CAST "image");
			if (tmp_node == NULL)
				goto case_end;
			xmlNewProp(tmp_node, BAD_CAST "name", BAD_CAST image->low_name);
			xmlAddDecimalProp(image->rid, tmp_node, "rid");
			xmlAddDecimalProp(image->atime, tmp_node, "atime");
			xmlAddDecimalProp(image->delete_soft, tmp_node, "softdelete");
			xmlAddDecimalProp(image->delete_hard, tmp_node, "harddelete");
			xmlAddDecimalProp(image->filesize, tmp_node, "size");
			if (image->file)
				xmlNewProp(tmp_node, BAD_CAST "file", BAD_CAST image->file);
			if (image->cache_file && image->cache_map)
			{
				xmlNewProp(tmp_node, BAD_CAST "cachefile", BAD_CAST image->cache_file);
				int i, complete = 0, size = IMGSIZE_TO_MAPBYTES(image->filesize);
				for (i = 0; i < size; ++i)
					if (image->cache_map[i])
						complete += 100;
				xmlAddDecimalProp(complete / size, tmp_node, "cachefill");
			}
			// Build space separated list of alt servers
			int i;
			char serverstr[1000] = {0}, target[100];
			for (i = 0; i < NUMBER_SERVERS; ++i)
			{
				if (image->servers[i].host.type == 0) continue;
				if (!host_to_string(&(image->servers[i].host), target, 100)) continue;
				if (*serverstr) strcat(serverstr, " ");
				strcat(serverstr, target);
			}
			xmlNewProp(tmp_node, BAD_CAST "servers", BAD_CAST serverstr); // TODO
			xmlAddChild(parent_node, tmp_node);
		}
		pthread_spin_unlock(&_spinlock);
		locked = 0;

		// Dump and send
		rpc_error = 0;
		break;

	case RPC_CLIENT_LIST:
		if (!createXmlDoc(&docReply, &root_node, "data"))
			goto case_end;

		// Clients
		parent_node = xmlNewNode(NULL, BAD_CAST "clients");
		if (parent_node == NULL)
			goto case_end;
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
					goto case_end;
				host_to_string(&client->host, strbuffer, STRBUFLEN);
				xmlNewProp(tmp_node, BAD_CAST "address", BAD_CAST strbuffer);
				xmlNewProp(tmp_node, BAD_CAST "image", BAD_CAST client->image->low_name);
				xmlAddDecimalProp(client->image->rid, tmp_node, "rid");
				xmlAddChild(parent_node, tmp_node);
			}
		}
		pthread_spin_unlock(&_spinlock);
		locked = 0;

		// Dump and send
		rpc_error = 0;
		break;

	case RPC_TRUSTED_LIST:
		if (!createXmlDoc(&docReply, &root_node, "data"))
			goto case_end;

		// Trusted servers
		parent_node = xmlNewNode(NULL, BAD_CAST "trusted");
		if (parent_node == NULL)
			goto case_end;
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
					goto case_end;
				xmlNodePtr namespace_root = xmlNewNode(NULL, BAD_CAST "namespaces");
				if (namespace_root == NULL)
					goto case_end;
				host_to_string(&server->host, strbuffer, STRBUFLEN);
				xmlNewProp(tmp_node, BAD_CAST "address", BAD_CAST strbuffer);
				if (server->comment)
					xmlNewProp(tmp_node, BAD_CAST "comment", BAD_CAST server->comment);
				for (iterator2 = server->namespaces; iterator2; iterator2 = iterator2->next)
				{
					const dnbd3_namespace_t *ns = iterator2->data;
					server_node = xmlNewNode(NULL, BAD_CAST "namespace");
					if (server_node == NULL)
						goto case_end;
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

		// Dump and send
		rpc_error = 0;
		break;

	case RPC_GET_LOG:
		if (!createXmlDoc(&docReply, &root_node, "data"))
			goto case_end;

		// Log
		log_parent_node = xmlNewChild(root_node, NULL, BAD_CAST "log", NULL);
		if (log_parent_node == NULL)
			goto case_end;
		char *log = fetchlog(0);
		if (log == NULL)
			log = strdup("LOG IS NULL");
		log_node = xmlNewCDataBlock(docReply, BAD_CAST log, strlen(log));
		free(log);
		if (log_node == NULL)
			goto case_end;
		xmlAddChild(log_parent_node, log_node);

		// Dump and send
		rpc_error = 0;
		break;

	case RPC_ADD_IMG:
	case RPC_DEL_IMG:
		if (docRequest)
		{
			if (!is_password_correct(docRequest))
			{
				rpc_error = ERROR_WRONG_PASSWORD;
				break;
			}

			xmlNodePtr cur = NULL;
			int count = 0;

			FOR_EACH_NODE(docRequest, "/data/image", cur)
			{
				if (cur->type != XML_ELEMENT_NODE)
					continue;
				NEW_POINTERLIST;
				++count;
				dnbd3_image_t image;
				memset(&image, 0, sizeof(dnbd3_image_t));
				image.config_group = XML_GETPROP(cur, "name");
				char *rid_str = XML_GETPROP(cur, "rid");
				image.file = XML_GETPROP(cur, "file");
				image.cache_file = XML_GETPROP(cur, "cache");
				if (image.file && !file_exists(image.file))
				{
					printf("Image File: %s\n", image.file);
					rpc_error = ERROR_FILE_NOT_FOUND;
				}
				else if (image.cache_file && !file_writable(image.cache_file))
				{
					rpc_error = ERROR_NOT_WRITABLE;
				}
				else
				{
					if (image.config_group && rid_str)
					{
						image.rid = atoi(rid_str);
						if (cmd == RPC_ADD_IMG)
						{
							rpc_error = dnbd3_add_image(&image);
						}
						else
						{
							char *soft = XML_GETPROP(cur, "softdelete");
							char *hard = XML_GETPROP(cur, "harddelete");
							image.delete_soft = time(NULL);
							image.delete_hard = time(NULL);
							if (soft) image.delete_soft += atoi(soft);
							if (hard) image.delete_hard += atoi(hard);
							rpc_error = dnbd3_del_image(&image);
						}
					}
					else
						rpc_error = ERROR_MISSING_ARGUMENT;
				}
				FREE_POINTERLIST;
			} END_FOR_EACH;
			if (count == 0)
				rpc_error = ERROR_MISSING_ARGUMENT;
		}
		else
			rpc_error = ERROR_INVALID_XML;

		break;

	case RPC_ADD_NS:
	case RPC_DEL_NS:
		if (docRequest)
		{
			if (!is_password_correct(docRequest))
			{
				rpc_error = ERROR_WRONG_PASSWORD;
				break;
			}

			xmlNodePtr cur = NULL;

			FOR_EACH_NODE(docRequest, "/data/namespaces/namespace", cur)
			{
				if (cur->type != XML_ELEMENT_NODE)
					continue;
				NEW_POINTERLIST;
				char *host = XML_GETPROP(cur, "address");
				char *ns = XML_GETPROP(cur, "name");
				char *flags = XML_GETPROP(cur, "flags");
				char *comment = XML_GETPROP(cur, "comment");
				pthread_spin_lock(&_spinlock);
				if (host && ns)
				{
					if (cmd == RPC_ADD_NS)
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
			rpc_error = ERROR_INVALID_XML;

		break;

	default:
		memlogf("[ERROR] Unknown RPC command: %u", (unsigned int)header.cmd);
		rpc_error = htonl(ERROR_UNKNOWN_COMMAND);
		break;

	}
case_end:

	if (locked)
		pthread_spin_unlock(&_spinlock);
	// Send reply
	return_value = rpc_send_reply(client_sock, &header, rpc_error, docReply);

	xmlFreeDoc(docReply);
	xmlFreeDoc(docRequest);

	return return_value;
}

void dnbd3_rpc_send(int cmd)
{
	int client_sock, size;

	// Check version and initialize
	LIBXML_TEST_VERSION

	struct sockaddr_in server;
	struct timeval client_timeout;

	// Create socket
	if ((client_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		perror("ERROR: RPC socket");
		exit(EXIT_FAILURE);
	}

	client_timeout.tv_sec = 4;
	client_timeout.tv_usec = 0;
	setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout));
	setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout));

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET; // IPv4
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(RPC_PORT); // set port number

	// Connect to server
	if (connect(client_sock, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		perror("ERROR: RPC connect");
		exit(EXIT_FAILURE);
	}

	// Send message
	dnbd3_rpc_t header;
	header.cmd = htonl(cmd);
	header.size = 0;
	send(client_sock, (char *)&header, sizeof(header), MSG_WAITALL);
	recv(client_sock, &header, sizeof(header), MSG_WAITALL);
	header.cmd = ntohl(header.cmd);
	header.size = ntohl(header.size);

	if (cmd == RPC_IMG_LIST && header.size > 0)
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
	if (_rpc_password == NULL)
	{
		memlogf("[WARNING] RPC access granted as no password is set!");
		return 1;
	}
	char *pass = getTextFromPath(doc, "/data/password");
	if (pass == NULL)
		return 0;
	if (strcmp(pass, _rpc_password) == 0)
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

#define RETBUFLEN 8000
static char returnbuffer[RETBUFLEN];
static int rpc_send_reply(int sock, dnbd3_rpc_t* header, int result_code, xmlDocPtr payload)
{
	if (result_code == 0 && payload != NULL)
	{
		// No error
		xmlChar *xmlbuff = NULL;
		int buffersize;
		xmlDocDumpFormatMemory(payload, &xmlbuff, &buffersize, 1);
		header->size = htonl(buffersize);
		if (!send_data(sock, header, sizeof(*header)))
			return FALSE;
		if (xmlbuff)
			return send_data(sock, xmlbuff, buffersize);
		return TRUE;
	}
	// Error code, build xml struct (lazy shortcut)
	int len = snprintf(returnbuffer, RETBUFLEN, "<?xml version=\"1.0\"?>\n"
		"<data>\n"
		"<result retcode=\"%d\" retstr=\"%s\" />\n"
		"</data>", result_code, "TODO");
	if (len >= RETBUFLEN)
		len = 10;
	header->size = htonl(len);
	header->cmd = htonl(RPC_ERROR);
	if (!send_data(sock, header, sizeof(*header)))
		return FALSE;
	return send_data(sock, returnbuffer, len);
}
