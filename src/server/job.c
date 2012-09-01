#include "job.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

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

static char* get_free_device();

void* dnbd3_job_thread(void *data)
{
	int i, j;
	// Determine number of available dnbd3 devices, which are needed for proxy mode
	char dev[DEV_STRLEN];
	for (i = 0; i < MAX_NUM_DEVICES_TO_CHECK; ++i)
	{
		sprintf(dev, "/dev/dnbd%d", i);
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
			sprintf(dev, "/dev/dnbd%d", i);
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
	// Job/Watchdog mainloop
	while (keep_running)
	{
		// TODO: Update image atime
		// TODO: Handle image deletion
		// TODO: Replicate proxied images (limited bandwidth)
		// TODO: Query other servers for new images/status/...
		// TODO: Switch server of dnbd device based on more sophisticated inputs than just rtt
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

/**
 * Get full name of an available dnbd3 device, eg. /dev/dnbd4
 * Returned buffer is owned by this module, do not modify or free!
 */
static char* get_free_device()
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
