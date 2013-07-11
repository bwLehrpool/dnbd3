#ifndef _IMAGE_H_
#define _IMAGE_H_


typedef struct
{
	int fd;
} dnbd3_connection_t;

/**
 * Image struct. An image path could be something like
 * /mnt/images/rz/zfs/Windows7 ZfS.vmdk.1
 * and the lower_name would then be
 * rz/zfs/windows7 zfs.vmdk
 */
typedef struct
{
	char *path;            // absolute path of the image
	char *lower_name;      // relative path, all lowercase, minus revision ID
	uint8_t *cache_map;    // cache map telling which parts are locally cached, NULL if complete
	uint32_t *crc32;       // list of crc32 checksums for each 16MiB block in image
	dnbd3_connection_t *uplink; // pointer to a server connection
	uint64_t filesize;     // size of image
	int rid;               // revision of image
	int users;             // clients currently using this image
	time_t atime;          // last access time
	char working;          // TRUE if image exists and completeness is == 100% or a working upstream proxy is connected
	pthread_spinlock_t lock;
} dnbd3_image_t;

int image_is_complete(dnbd3_image_t *image);

int image_save_cache_map(dnbd3_image_t *image);

dnbd3_image_t* image_get(char *name, uint16_t revision);

void image_release(dnbd3_image_t *image);

void image_load_all();



#endif
