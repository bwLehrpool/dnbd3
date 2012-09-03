#include "job.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <glib/gslist.h>

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
		// TODO: Update image atime
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

static void query_servers()
{
	struct timeval client_timeout;
	client_timeout.tv_sec = 0;
	client_timeout.tv_usec = 500 * 1000;
	int client_sock;
	// Apply read/write timeout
	setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout));
	setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout));
}

/**
 * Get full name of an available dnbd3 device, eg. /dev/dnbd4
 * Returned buffer is owned by this module, do not modify or free!
 */
static char *get_free_device()
{
	if (devices == NULL)
		return NULL;
	int i;
	for (i = 0; i < num_devices; ++i)
	{
		if (!devices[i].available)
			continue;
		// TODO: Check sysfs if device is maybe already connected
		return devices[i].name;
	}
	return NULL;
}
