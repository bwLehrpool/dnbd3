#include "job.h"
#include "saveload.h"
#include "helper.h"
#include "memlog.h"
#include "rpc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
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
static void return_free_device(char *name);
static void connect_proxy_images();
static void query_servers();
static char *create_cache_filename(char *name, int rid, char *buffer, int maxlen);
static void add_alt_server(dnbd3_image_t *image, dnbd3_host_t *host);
static void remove_alt_server(dnbd3_trusted_server_t *server);
static void dnbd3_update_atimes(time_t now);

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
		num_devices = j;
	}
	memlogf("[INFO] %d available dnbd3 devices for proxy mode", num_devices);
	//
	time_t next_delete_invocation = 0;
	//
	// Job/Watchdog mainloop
	while (keep_running)
	{
		const time_t starttime = time(NULL);
		//
		// Update image atime
		dnbd3_update_atimes(starttime);
		// Call image deletion function if last call is more than 5 minutes ago
		if (starttime < next_delete_invocation)
		{
			next_delete_invocation = starttime + 300;
			dnbd3_exec_delete(TRUE);
		}
		// Check for proxied images that have not been set up yet
		connect_proxy_images();
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

static void connect_proxy_images()
{
	int s, n;
	dnbd3_server_entry_t servers[NUMBER_SERVERS];
	char imagename[1000];
	int rid;
	dnbd3_ioctl_t msg;
	memset(&msg, 0, sizeof(dnbd3_ioctl_t));
	msg.len = (uint16_t)sizeof(dnbd3_ioctl_t);
	msg.read_ahead_kb = DEFAULT_READ_AHEAD_KB;
	msg.is_server = TRUE;
	for (n = 0 ;; ++n)
	{
		pthread_spin_lock(&_spinlock);
		dnbd3_image_t *image = g_slist_nth_data(_dnbd3_images, n);
		if (image == NULL)
		{	// End of list reached
			pthread_spin_unlock(&_spinlock);
			break;
		}
		if (image->working && image->cache_map && image->file)
		{	// Check if cache is complete
			int complete = TRUE, j;
			const int map_len_bytes = IMGSIZE_TO_MAPBYTES(image->filesize);
			for (j = 0; j < map_len_bytes - 1; ++j)
			{
				if (image->cache_map[j] != 0xFF)
				{
					complete = FALSE;
					break;
				}
			}
			if (complete)
			{
				const int blocks_in_last_byte = (image->filesize >> 12) & 7;
				uint8_t last_byte = 0;
				if (blocks_in_last_byte == 0)
					last_byte = 0xFF;
				else
					for (j = 0; j < blocks_in_last_byte; ++j)
						last_byte |= (1 << j);
				complete = ((image->cache_map[map_len_bytes - 1] & last_byte) == last_byte);
			}
			if (!complete)
			{
				pthread_spin_unlock(&_spinlock);
				continue;
			}
			// Image is 100% cached, disconnect dnbd3 device
			memlogf("[INFO] Disconnecting %s because local copy of %s is complete.", image->file, image->config_group);
			int dh = open(image->file, O_RDONLY);
			if (dh < 0)
				memlogf("[ERROR] Could not open() device '%s'", image->file);
			else
			{
				if (ioctl(dh, IOCTL_CLOSE, (void*)0) != 0)
					memlogf("[ERROR] Could not IOCTL_CLOSE device '%s'", image->file);
				else
					return_free_device(image->file);
				close(dh);
			}
			free(image->file);
			image->file = NULL;
			pthread_spin_unlock(&_spinlock);
			continue;
		}
		if (image->working || image->file || image->low_name == NULL)
		{	// Nothing to do
			pthread_spin_unlock(&_spinlock);
			continue;
		}
		char *devname = get_free_device();
		if (devname == NULL)
		{	// All devices busy
			pthread_spin_unlock(&_spinlock);
			continue;
		}
		// Remember image information as the image pointer isn't
		// guaranteed to stay valid after unlocking
		snprintf(imagename, 1000, "%s", image->low_name);
		rid = image->rid;
		memcpy(servers, image->servers, sizeof(servers[0]) * NUMBER_SERVERS);
		pthread_spin_unlock(&_spinlock);
		int dh = open(devname, O_RDWR);
		if (dh < 0)
		{
			pthread_spin_lock(&_spinlock);
			return_free_device(devname);
			pthread_spin_unlock(&_spinlock);
			continue;
		}
		for (s = 0; s < NUMBER_SERVERS; ++s)
		{
			if (servers[s].host.type == 0)
				continue;
			// connect device
			printf("[DEBUG] Connecting device....\n");
			msg.host = servers[s].host;
			msg.imgname = imagename;
			msg.imgnamelen = strlen(imagename);
			msg.rid = rid;
			if (ioctl(dh, IOCTL_OPEN, &msg) < 0)
				continue;
			printf("[DEBUG] Connected! Adding alt servers...\n");
			// connected
			for (++s; s < NUMBER_SERVERS; ++s)
			{
				if (servers[s].host.type == 0)
					continue;
				msg.host = servers[s].host;
				if (ioctl(dh, IOCTL_ADD_SRV, &msg) < 0)
					memlogf("[WARNING] Could not add alt server to proxy device");
				else
					printf("[DEBUG] Added an alt server\n");
			}
			printf("[DEBUG] Done, handling file size...\n");
			// LOCK + UPDATE
			int isworking = FALSE, alloc_cache = FALSE;
			pthread_spin_lock(&_spinlock);
			if (g_slist_find(_dnbd3_images, image) == NULL)
			{	// Image not in list anymore, was deleted in meantime...
				if (ioctl(dh, IOCTL_CLOSE, &msg) < 0)
					memlogf("[WARNING] Could not close device after use - lost %s", devname);
				else
					return_free_device(devname);
				pthread_spin_unlock(&_spinlock);
				break;
			}
			// Image still exists
			image->file = strdup(devname);
			long long oct = 0;
			int t, ret;
			for (t = 0; t < 10 && dh >= 0; ++t)
			{	// For some reason the ioctl might return 0 right after connecting
				ret = ioctl(dh, BLKGETSIZE64, &oct);
				if (ret == 0 && oct > 0)
					break;
				close(dh);
				usleep(100 * 1000);
				dh = open(devname, O_RDONLY);
			}
			if (dh < 0 || ret != 0)
				memlogf("[ERROR] SIZE fail on %s (ret=%d, oct=%lld)", devname, ret, oct);
			else if (oct == 0)
				memlogf("[ERROR] Reported disk size is 0.");
			else if (image->filesize != 0 && image->filesize != oct)
				memlogf("[ERROR] Remote and local size of image do not match: %llu != %llu for %s", (unsigned long long)oct, (unsigned long long)image->filesize, image->low_name);
			else
				isworking = TRUE;
			image->filesize = (uint64_t)oct;
			if (image->cache_file != NULL && isworking && image->cache_map == NULL)
			{
				printf("[DEBUG] Image has cache file %s\n", image->cache_file);
				const int mapsize = IMGSIZE_TO_MAPBYTES(image->filesize);
				image->cache_map = calloc(mapsize, 1);
				off_t cachelen = -1;
				int ch = open(image->cache_file, O_RDONLY);
				if (ch >= 0)
				{
					cachelen = lseek(ch, 0, SEEK_END);
					close(ch);
				}
				if (ch < 0 || cachelen != image->filesize)
					alloc_cache = TRUE;
				if (cachelen == image->filesize)
				{
					char mapfile[strlen(image->cache_file) + 5];
					sprintf(mapfile, "%s.map", image->cache_file);
					int cmh = open(mapfile, O_RDONLY);
					if (cmh >= 0)
					{
						if (lseek(cmh, 0, SEEK_END) != mapsize)
							memlogf("[WARNING] Existing cache map has wrong size.");
						else
						{
							lseek(cmh, 0, SEEK_SET);
							read(cmh, image->cache_map, mapsize);
							printf("[DEBUG] Found existing cache file and map for %s\n", image->low_name);
						}
						close(cmh);
					}
				}
			}
			char cfname[1000] = {0};
			off_t fs = image->filesize;
			if (isworking && !(alloc_cache && image->cache_file))
			{
				image->working = TRUE;
				memlogf("[WARNING] Proxy-Mode enabled without cache directory. This will most likely hurt performance.");
				goto continue_with_next_image;
			}
			snprintf(cfname, 1000, "%s", image->cache_file);
			pthread_spin_unlock(&_spinlock);
			if (isworking && *cfname)
			{
				int ch = open(cfname, O_WRONLY | O_CREAT, 0600);
				if (ch >= 0)
				{
					// Pre-allocate disk space
					printf("[DEBUG] Pre-allocating disk space...\n");
					lseek(ch, fs - 1, SEEK_SET);
					write(ch, &ch, 1);
					close(ch);
					printf("[DEBUG] Allocation complete.\n");
					pthread_spin_lock(&_spinlock);
					if (g_slist_find(_dnbd3_images, image) != NULL)
					{
						image->working = TRUE;
						memlogf("[INFO] Enabled relayed image %s (%lld)", image->low_name, (long long)fs);
						goto continue_with_next_image;
					}
					unlink(cfname);
					memlogf("[WARNING] Image has gone away");
					pthread_spin_unlock(&_spinlock);
				}
				else
					memlogf("[WARNING] Could not pre-allocate %s", cfname);
			}
			break;
		} // <-- end loop over servers
		// If this point is reached, replication was not successful
		pthread_spin_lock(&_spinlock);
		if (g_slist_find(_dnbd3_images, image) != NULL)
		{
			free(image->file);
			image->file = NULL;
		}
		return_free_device(devname);
continue_with_next_image:
		pthread_spin_unlock(&_spinlock);
		close(dh);
	}
}

static void dnbd3_update_atimes(time_t now)
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
	char xmlbuffer[MAX_RPC_PAYLOAD];
	for (num = 0;; ++num)
	{
		// "Iterate" this way to prevent holding the lock for a long time,
		// although there is a very small chance to skip a server this way...
		pthread_spin_lock(&_spinlock);
		server = g_slist_nth_data(_trusted_servers, num);
		if (server == NULL)
		{
			pthread_spin_unlock(&_spinlock);
			break; // Done
		}
		host = server->host; // Copy host, in case server gets deleted by another thread
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
		dnbd3_rpc_t header;
		header.cmd = htonl(RPC_IMG_LIST);
		header.size = 0;
		send(client_sock, (char *)&header, sizeof(header), 0);
		if (!recv_data(client_sock, &header, sizeof(header)))
		{
			printf("[DEBUG] Could not get status from other server...\n");
			goto communication_error;
		}
		header.cmd = ntohl(header.cmd);
		header.size = ntohl(header.size);
		if (header.cmd != RPC_IMG_LIST)
		{
			printf("[DEBUG] Error. Reply from other server was cmd:%d, error:%d\n", (int)header.cmd, (int)-1);
			goto communication_error;
		}
		if (header.size > MAX_RPC_PAYLOAD)
		{
			memlogf("[WARNING] XML payload from other server exceeds MAX_RPC_PAYLOAD (%d > %d)", (int)header.size, (int)MAX_RPC_PAYLOAD);
			goto communication_error;
		}
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

		xmlNodePtr cur;
		FOR_EACH_NODE(doc, "/data/images/image", cur)
		{
			if (cur->type != XML_ELEMENT_NODE)
				continue;
			NEW_POINTERLIST;
			char *image = XML_GETPROP(cur, "name");
			char *ridstr = XML_GETPROP(cur, "rid");
			char *sizestr = XML_GETPROP(cur, "size");
			if (!image || !ridstr || !sizestr)
				goto free_current_image;
			const int rid = atoi(ridstr);
			const long long size = atoll(sizestr);
			if (rid <= 0)
			{
				printf("[DEBUG] Ignoring remote image with rid %d\n", rid);
				goto free_current_image;
			}
			char *slash = strrchr(image, '/');
			if (slash == NULL)
			{
				printf("[DEBUG] Ignoring remote image with no '/' in name...\n");
				goto free_current_image;
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
				snprintf(xmlbuffer, MAX_RPC_PAYLOAD, "%s/%s", image, slash);
			}
			// Image seems legit, check if there's a local copy
			dnbd3_namespace_t *trust;
			pthread_spin_lock(&_spinlock);
			trust = dnbd3_get_trust_level(&host, image);
			if (trust == NULL)
			{	// Namespace of image is not trusted
				pthread_spin_unlock(&_spinlock);
				printf("[DEBUG] No NS match: '%s'\n", xmlbuffer);
				goto free_current_image;
			}
			char *sdel = XML_GETPROP(cur, "softdelete");
			char *hdel = XML_GETPROP(cur, "harddelete");
			const time_t softdelete = sdel ? atol(sdel) : 0;
			const time_t harddelete = hdel ? atol(hdel) : 0;
			dnbd3_image_t *local_image = dnbd3_get_image(xmlbuffer, rid, FALSE);
			if (local_image == NULL && trust->auto_replicate)
			{
				pthread_spin_unlock(&_spinlock);
				// Image is NEW, add it!
				dnbd3_image_t newimage;
				char cachefile[90];
				memset(&newimage, 0, sizeof(newimage));
				newimage.config_group = xmlbuffer;
				newimage.rid = rid;
				newimage.filesize = size;
				newimage.delete_hard = harddelete;
				newimage.delete_soft = softdelete;
				if (_cache_dir)
				{
					newimage.cache_file = create_cache_filename(xmlbuffer, rid, cachefile, 90);
					printf("[DEBUG] Cache file is %s\n", newimage.cache_file);
				}
				dnbd3_add_image(&newimage);
				pthread_spin_lock(&_spinlock);
				local_image = dnbd3_get_image(xmlbuffer, rid, FALSE);
				if (local_image)
					add_alt_server(local_image, &host);
				pthread_spin_unlock(&_spinlock);
			}
			else if (local_image != NULL)
			{
				// Image is already KNOWN, add alt server if appropriate
				if (local_image->filesize == 0) // Size is unknown, just assume the trusted server got it right
					local_image->filesize = size;
				if (size != local_image->filesize)
					printf("[DEBUG] Ignoring remote image '%s' because it has a different size from the local version! (remote: %llu, local: %llu)\n", local_image->config_group, size, (unsigned long long)local_image->filesize);
				else
					add_alt_server(local_image, &host);
				if (local_image->cache_file && trust->auto_replicate) {
					local_image->delete_hard = harddelete;
					local_image->delete_soft = softdelete;
				}
				pthread_spin_unlock(&_spinlock);
			}
			else
			{
				printf("[DEBUG] No NS match: '%s'\n", xmlbuffer);
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
		pthread_spin_lock(&_spinlock);
		if (g_slist_find(_trusted_servers, server))
		{
			if (server->unreachable < 10 && ++server->unreachable == 5)
				remove_alt_server(server);
		}
		pthread_spin_unlock(&_spinlock);
	}
}

static char *create_cache_filename(char *name, int rid, char *buffer, int maxlen)
{
	if (_cache_dir == NULL)
		return NULL;
	size_t cdl = strlen(_cache_dir);
	if (maxlen < 15 + cdl)
		return NULL;
	if (strlen(name) + 16 + cdl < maxlen)
		snprintf(buffer, maxlen, "%s/%s_rid_%d.cache", _cache_dir, name, rid);
	else
	{
		char *slash = strrchr(name, '/');
		if (slash == NULL)
		{
			snprintf(buffer, maxlen - 17, "%s/%s", _cache_dir, name);
			snprintf(buffer + maxlen - 17, 17, "_rid_%d.cache", rid);
		}
		else
		{
			snprintf(buffer, maxlen, "%s/%s", _cache_dir, name);
			snprintf(buffer + cdl, maxlen - cdl, "%s_rid_%d.cache", slash, rid);
		}
	}
	char *ptr = buffer + cdl + 1;
	while (*ptr)
	{
		if (*ptr == '/' || *ptr < 32 || *ptr == ' ' || *ptr == '\\' || *ptr == '*' || *ptr == '?')
			*ptr = '_';
		++ptr;
	}
	FILE *fh;
	while ((fh = fopen(buffer, "rb")))
	{	// Alter file name as long as a file by that name already exists
		fclose(fh);
		char *c = buffer + rand() % strlen(buffer);
		*c = rand() % 26 + 'A';
	}
	return buffer;
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
				image->servers[i].failures = 0;
				break;
			}
		}
	if (i >= NUMBER_SERVERS) // To many known alt servers already
		return;
	// Broadcast to connected clients. Note that 'i' now points to the new server
	printf("[DEBUG] Adding alt server to %s\n", image->low_name);
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
			NEW_BINSTRING(message, sizeof(header) + sizeof(image->servers[i]));
			memcpy(message->data, &header, sizeof(header));
			memcpy(message->data + sizeof(header), &image->servers[i], sizeof(image->servers[i]));
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

static void return_free_device(char *name)
{
	if (devices == NULL)
		return;
	int i;
	for (i = 0; i < num_devices; ++i)
	{
		if (devices[i].available || strcmp(devices[i].name, name) != 0)
			continue;
		devices[i].available = TRUE;
		break;
	}
}
