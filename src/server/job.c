#include "job.h"
#include "saveload.h"
#include "memlog.h"

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
	connect_timeout.tv_sec = 2;
	connect_timeout.tv_usec = 0;
	int client_sock, num;
	dnbd3_trusted_server_t *server;
	dnbd3_host_t host;
	struct sockaddr_in addr4;
	for (num = 0;; ++num)
	{
		// "Iterate" this way to prevent holding the lock for a long time, although it is possible to skip a server this way...
		pthread_spin_lock(&_spinlock);
		server = g_slist_nth_data(_trusted_servers, num);
		if (server == NULL)
		{
			pthread_spin_unlock(&_spinlock);
			break; // Done
		}
		memcpy(&host, &server->host, sizeof(host));
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
		addr4.sin_port = host.port;
		// Connect to server
		setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &connect_timeout, sizeof(connect_timeout));
		setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &connect_timeout, sizeof(connect_timeout));
		if (connect(client_sock, (struct sockaddr *)&addr4, sizeof(addr4)) < 0)
		{
			printf("[DEBUG] Could not connect to other server...\n");
			close(client_sock); // TODO: Remove from alt server list if failed too often
			continue;
		}
		// Apply read/write timeout
		setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout));
		setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout));
		//
		// TODO: Send and receive info from server
		//
		close(client_sock);
		//
		// TODO: Process data, update server info, add/remove this server as alt server for images, replicate images, etc.
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
