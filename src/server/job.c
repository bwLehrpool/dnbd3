#include "job.h"
#include "saveload.h"
#include "helper.h"
#include "memlog.h"
#include "ipc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib/gslist.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include "xmlutil.h"
#include "../config.h"

#define DEV_STRLEN 12 // INCLUDING NULLCHAR (increase to 13 if you need more than 100 (0-99) devices)
#define MAX_NUM_DEVICES_TO_CHECK 100

#ifndef	FALSE
#define	FALSE	(0)
#endif

#ifndef	TRUE
#define	TRUE	(!FALSE)
#endif

typedef struct
{
	char available;
	char name[DEV_STRLEN];
} device_t;

// "/dev/dnbdXX" == 11 bytes per device + nullchar = 12
static device_t *devices = NULL;
static int num_devices = 0;
static char keep_running = TRUE;

// Private functions
static char *get_free_device();
static void query_servers();
static void add_alt_server(dnbd3_image_t *image, dnbd3_host_t *host);
static void remove_alt_server(dnbd3_trusted_server_t *server);
static void update_image_atimes(time_t now);

//

void *dnbd3_job_thread(void *data)
{
	int i, j;
	// Determine number of available dnbd3 devices, which are needed for proxy mode
	char dev[DEV_STRLEN];
	for (i = 0; i < MAX_NUM_DEVICES_TO_CHECK; ++i)
	{
		snprintf(dev, DEV_STRLEN, "/dev/dnbd%d", i);
		if (access(dev, W_OK | R_OK)) // Need RW access to device to read and do ioctl
			continue;
		++num_devices;
	}
	if (num_devices > 0)
	{
		devices = calloc(num_devices, sizeof(*devices));
		for (i = 0, j = 0; i < MAX_NUM_DEVICES_TO_CHECK; ++i)
		{
			memset(dev, 0, DEV_STRLEN);
			snprintf(dev, DEV_STRLEN, "/dev/dnbd%d", i);
			if (access(dev, W_OK | R_OK))
				continue;
			if (j >= num_devices) // More available devices during second iteration? :-(
				break;
			memcpy(devices[j].name, dev, DEV_STRLEN);
			devices[j].available = TRUE;
			++j;
		}
	}
	memlogf("[INFO] %d available dnbd3 devices for proxy mode", j);
	//
	time_t next_delete_invocation = 0;
	//
	// Job/Watchdog mainloop
	while (keep_running)
	{
		const time_t starttime = time(NULL);
		//
		// Update image atime
		update_image_atimes(starttime);
		// Call image deletion function if last call is more than 5 minutes ago
		if (starttime < next_delete_invocation)
		{
			next_delete_invocation = starttime + 300;
			dnbd3_exec_delete(TRUE);
		}
		// TODO: Replicate proxied images (limited bandwidth)
		// Query other servers for new images/status/...
		query_servers();
		// TODO: Switch server of dnbd device based on more sophisticated inputs than just rtt
		// Calc sleep timeout for next iteration
		sleep(30 - (time(NULL) - starttime)); // Sleep 30 seconds, but account for the time it took to execute the loop
	}
	//
	free(devices);
	devices = NULL;
	pthread_exit(NULL);
	return NULL;
}

void dnbd3_job_shutdown()
{
	keep_running = FALSE;
}

static void update_image_atimes(time_t now)
{
	GSList *iterator;
	pthread_spin_lock(&_spinlock);
	for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
	{
		dnbd3_client_t *client = iterator->data;
		if (client && client->image && !client->is_server)
			client->image->atime = now;
	}
	pthread_spin_unlock(&_spinlock);
}

static void query_servers()
{
	if (_trusted_servers == NULL)
		return;
	struct timeval client_timeout, connect_timeout;
	client_timeout.tv_sec = 0;
	client_timeout.tv_usec = 500 * 1000;
	connect_timeout.tv_sec = 1;
	connect_timeout.tv_usec = 0;
	int client_sock, num;
	dnbd3_trusted_server_t *server;
	dnbd3_host_t host;
	struct sockaddr_in addr4;
	for (num = 0;; ++num)
	{
		char *xmlbuffer = NULL;
		// "Iterate" this way to prevent holding the lock for a long time, although it is possible to skip a server this way...
		pthread_spin_lock(&_spinlock);
		server = g_slist_nth_data(_trusted_servers, num);
		if (server == NULL)
		{
			pthread_spin_unlock(&_spinlock);
			break; // Done
		}
		host = server->host;
		pthread_spin_unlock(&_spinlock);
		// Connect
		if (host.type != AF_INET)
		{
			printf("[DEBUG] Unsupported addr type '%d', ignoring trusted server.\n", (int)host.type);
			continue;
		}
		// Create socket (Extend for IPv6)
		if ((client_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			printf("[DEBUG] Error creating server-to-server socket.\n");
			continue;
		}
		// Set host (IPv4)
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		memcpy(&addr4.sin_addr.s_addr, host.addr, 4);
		addr4.sin_port = htons(ntohs(host.port) + 1);
		// Connect to server
		setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &connect_timeout, sizeof(connect_timeout));
		setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &connect_timeout, sizeof(connect_timeout));
		if (connect(client_sock, (struct sockaddr *)&addr4, sizeof(addr4)) < 0)
		{
			printf("[DEBUG] Could not connect to other server...\n");
			goto communication_error;
		}
		// Apply read/write timeout
		setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout));
		setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout));
		//
		// Send and receive info from server
		// Send message
		dnbd3_ipc_t header;
		header.cmd = htonl(IPC_INFO);
		header.size = 0;
		header.error = 0;
		send(client_sock, (char *)&header, sizeof(header), 0);
		if (!recv_data(client_sock, &header, sizeof(header)))
		{
			printf("[DEBUG] Could not get status from other server...\n");
			goto communication_error;
		}
		header.cmd = ntohl(header.cmd);
		header.size = ntohl(header.size);
		header.error = ntohl(header.error);
		if (header.cmd != IPC_INFO || header.error != 0)
		{
			printf("[DEBUG] Error. Reply from other server was cmd:%d, error:%d\n", (int)header.cmd, (int)header.error);
			goto communication_error;
		}
		if (header.size > MAX_IPC_PAYLOAD)
		{
			memlogf("[WARNING] XML payload from other server exceeds MAX_IPC_PAYLOAD (%d > %d)", (int)header.size, (int)MAX_IPC_PAYLOAD);
			goto communication_error;
		}
		xmlbuffer = malloc(header.size);
		if (!recv_data(client_sock, xmlbuffer, header.size))
		{
			printf("[DEBUG] Error reading XML payload from other server.\n");
			goto communication_error;
		}
		close(client_sock);
		//
		// Process data, update server info, add/remove this server as alt server for images, replicate images, etc.
		xmlDocPtr doc = xmlReadMemory(xmlbuffer, header.size, "noname.xml", NULL, 0);

		if (doc == NULL)
		{
			memlogf("[WARNING] Could not parse XML data received by other server.");
			goto communication_error;
		}
		// Data seems ok
		char *ns = getTextFromPath(doc, "/data/namespace");
		if (ns && *ns == '\0')
		{
			xmlFree(ns);
			ns = NULL;
		}
		else
		{
			printf("[DEBUG] Other server's default namespace is '%s'\n", ns);
			if  (!is_valid_namespace(ns))
			{
				printf("[DEBUG] Ignoring invalid namespace from other server.\n");
				xmlFree(ns);
				ns = NULL;
			}
		}

		xmlNodePtr cur;
		FOR_EACH_NODE(doc, "/data/images/image", cur)
		{
			if (cur->type != XML_ELEMENT_NODE)
				continue;
			NEW_POINTERLIST;
			char *image = XML_GETPROP(cur, "name");
			char *ridstr = XML_GETPROP(cur, "rid");
			if (!image || !ridstr)
				goto free_current_image;
			int rid = atoi(ridstr);
			if (rid <= 0)
			{
				printf("[DEBUG] Ignoring remote image with rid %d\n", rid);
				goto free_current_image;
			}
			char *slash = strrchr(image, '/');
			if (slash == NULL)
			{
				if (!ns)
					goto free_current_image;
				if (!is_valid_imagename(image))
				{
					printf("[DEBUG] Invalid image name: '%s'\n", image);
					goto free_current_image;
				}
				snprintf(xmlbuffer, MAX_IPC_PAYLOAD, "%s/%s", ns, image);
			}
			else
			{
				*slash++ = '\0';
				if (!is_valid_namespace(image))
				{
					printf("[DEBUG] Ignoring remote image with invalid namespace '%s'\n", image);
					goto free_current_image;
				}
				if (!is_valid_imagename(slash))
				{
					printf("[DEBUG] Ignoring remote image with invalid name '%s'\n", slash);
					goto free_current_image;
				}
				snprintf(xmlbuffer, MAX_IPC_PAYLOAD, "%s/%s", image, slash);
			}
			// Image seems legit, check if there's a local copy
			pthread_spin_lock(&_spinlock);
			dnbd3_image_t *local_image = dnbd3_get_image(xmlbuffer, rid, FALSE);
			if (local_image == NULL)
			{
				pthread_spin_unlock(&_spinlock);
				// Image is NEW, add it!
				// TODO: Check if replication is requested for this namespace
				dnbd3_image_t newimage;
				memset(&newimage, 0, sizeof(newimage));
				newimage.config_group = xmlbuffer;
				newimage.rid = rid;
				dnbd3_add_image(&newimage);
				pthread_spin_lock(&_spinlock);
				local_image = dnbd3_get_image(xmlbuffer, rid, FALSE);
				if (local_image)
					add_alt_server(local_image, &server->host);
				pthread_spin_unlock(&_spinlock);
			}
			else
			{
				// Image is already KNOWN, add alt server if appropriate
				// TODO: Check if requested for namespace
				add_alt_server(local_image, &server->host);
				pthread_spin_unlock(&_spinlock);
			}
			// Cleanup
free_current_image:
			FREE_POINTERLIST;
		} END_FOR_EACH;


		// ...
		xmlFreeDoc(doc);
		//
		continue;
communication_error:
		close(client_sock);
		free(xmlbuffer);
		pthread_spin_lock(&_spinlock);
		if (g_slist_find(_trusted_servers, server))
		{
			if (server->unreachable < 10 && ++server->unreachable == 5)
				remove_alt_server(server);
		}
		pthread_spin_unlock(&_spinlock);
	}
}

/**
 * !! Call this while holding the lock !!
 */
static void add_alt_server(dnbd3_image_t *image, dnbd3_host_t *host)
{
	int i;
	for (i = 0; i < NUMBER_SERVERS; ++i)
	{
		if (is_same_server(host, &image->servers[i].host))
		{	// Alt server already known for this image
			if (image->servers[i].failures)
			{	// It was disabled, re-enable and send info to clients
				image->servers[i].failures = 0;
				break;
			}
			else	// Alt-Server already known and active, do nothing
				return;
		}
	}
	// Add to list if it wasn't in there
	if (i >= NUMBER_SERVERS)
		for (i = 0; i < NUMBER_SERVERS; ++i)
		{
			if (image->servers[i].host.type == 0)
			{
				image->servers[i].host = *host;
				break;
			}
		}
	// Broadcast to connected clients
	GSList *itc;
	dnbd3_reply_t header;
	header.cmd = CMD_GET_SERVERS;
	header.magic = dnbd3_packet_magic;
	header.size = sizeof(dnbd3_server_entry_t);
	fixup_reply(header);
	for (itc = _dnbd3_clients; itc; itc = itc->next)
	{
		dnbd3_client_t *const client = itc->data;
		if (client->image == image)
		{
			// Don't send message directly as the lock is being held; instead, enqueue it
			NEW_BINSTRING(message, sizeof(header) + sizeof(*host));
			memcpy(message->data, &header, sizeof(header));
			memcpy(message->data + sizeof(header), host, sizeof(*host));
			client->sendqueue = g_slist_append(client->sendqueue, message);
		}
	}
}

/**
 * !! Call this while holding the lock !!
 */
static void remove_alt_server(dnbd3_trusted_server_t *server)
{
	GSList *iti, *itc;
	int i;
	dnbd3_reply_t header;
	header.cmd = CMD_GET_SERVERS;
	header.magic = dnbd3_packet_magic;
	header.size = sizeof(dnbd3_server_entry_t);
	fixup_reply(header);
	// Iterate over all images
	for (iti = _dnbd3_images; iti; iti = iti->next)
	{
		dnbd3_image_t *const image = iti->data;
		// Check if any alt_server for that image is the server to be removed
		for (i = 0; i < NUMBER_SERVERS; ++i)
		{
			if (is_same_server(&server->host, &image->servers[i].host))
			{
				// Remove server from that image and tell every connected client about it
				image->servers[i].failures = 1;
				for (itc = _dnbd3_clients; itc; itc = itc->next)
				{
					dnbd3_client_t *const client = itc->data;
					if (client->image == image)
					{
						// Don't send message directly as the lock is being held; instead, enqueue it
						NEW_BINSTRING(message, sizeof(header) + sizeof(image->servers[i]));
						memcpy(message->data, &header, sizeof(header));
						memcpy(message->data + sizeof(header), &image->servers[i], sizeof(image->servers[i]));
						client->sendqueue = g_slist_append(client->sendqueue, message);
					}
				}
				image->servers[i].host.type = 0;
			}
		}
	}
}

/**
 * Get full name of an available dnbd3 device, eg. /dev/dnbd4
 * Returned buffer is owned by this module, do not modify or free!
 * Returns NULL if all devices are in use
 */
static char *get_free_device()
{
	if (devices == NULL)
		return NULL;
	int i, c;
	char buffer[100];
	for (i = 0; i < num_devices; ++i)
	{
		if (!devices[i].available)
			continue;
		devices[i].available = FALSE;
		// Check sysfs if device is maybe already connected
		snprintf(buffer, 100, "/sys/devices/virtual/block/%s/net/cur_server_addr", devices[i].name + 5);
		FILE *f = fopen(buffer, "r");
		if (f == NULL)
		{
			printf("[DEBUG] Could not open %s - device marked as used.\n", buffer);
			continue;
		}
		c = fgetc(f);
		fclose(f);
		if (c > 0)
		{
			// Could read something, so the device is connected
			printf("[DEBUG] Free device %s is actually in use - marked as such.\n", devices[i].name);
			continue;
		}
		return devices[i].name;
	}
	memlogf("[WARNING] No more free dnbd3 devices - proxy mode probably affected.");
	return NULL;
}
