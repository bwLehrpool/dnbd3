#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include "../types.h"
#include <stdint.h>
#include <time.h>
#include <pthread.h>

// ######### All structs/types used by the server ########

typedef struct _dnbd3_connection dnbd3_connection_t;
typedef struct _dnbd3_image dnbd3_image_t;

// Slot is free, can be used.
// Must only be set in uplink_handle_receive() or uplink_remove_client()
#define ULR_FREE 0
// Slot is occupied, reply has not yet been received, matching request can safely rely on reuse.
// Must only be set in uplink_request()
#define ULR_PENDING 1
// Slot is being processed, do not consider for hop on.
// Must only be set in uplink_handle_receive()
#define ULR_PROCESSING 2
typedef struct
{
	uint64_t handle;          // Client defined handle to pass back in reply
	uint64_t from;            // First byte offset of requested block (ie. 4096)
	volatile uint32_t to;     // Last byte + 1 of requested block (ie. 8192, if request len is 4096, resulting in bytes 4096-8191)
	volatile int socket;      // Socket to send reply to
	volatile int status;      // status of this entry: ULR_*
} dnbd3_queued_request_t;

#define RTT_IDLE 0 // Not in progress
#define RTT_INPROGRESS 1 // In progess, not finished
#define RTT_DONTCHANGE 2 // Finished, but no better alternative found
#define RTT_DOCHANGE 3 // Finished, better alternative written to .betterServer + .betterFd
struct _dnbd3_connection
{
	int fd;                     // socket fd to remote server
	int signal;                 // write end of pipe used to wake up the process
	pthread_t thread;           // thread holding the connection
	pthread_spinlock_t lock;    // lock for synchronization on request queue etc.
	dnbd3_queued_request_t queue[SERVER_MAX_UPLINK_QUEUE];
	volatile int queuelen;      // length of queue
	dnbd3_image_t *image;       // image that this uplink is used for do not call get/release for this pointer
	dnbd3_host_t currentServer; // Current server we're connected to
	volatile int rttTestResult; // RTT_*
	dnbd3_host_t betterServer;  // The better server
	int betterFd;               // Active connection to better server, ready to use
	uint8_t *recvBuffer;        // Buffer for receiving payload
	int recvBufferLen;          // Len of ^^
};

typedef struct
{
	uint16_t len;
	uint8_t data[65535];
} dnbd3_binstring_t;
// Do not always allocate as much memory as required to hold the entire binstring struct,
// but only as much as is required to hold the actual data
#define NEW_BINSTRING(_name, _len) \
	dnbd3_binstring_t *_name = malloc(sizeof(uint16_t) + _len); \
	_name->len = _len

typedef struct
{
	char comment[COMMENT_LENGTH];
	time_t last_told;
	dnbd3_host_t host;
	int rtt[];
} dnbd3_alt_server_t;

typedef struct
{
	char comment[COMMENT_LENGTH];
	dnbd3_host_t host;
	dnbd3_host_t mask;
} dnbd3_acess_rules_t;

/**
 * Image struct. An image path could be something like
 * /mnt/images/rz/zfs/Windows7 ZfS.vmdk.1
 * and the lower_name would then be
 * rz/zfs/windows7 zfs.vmdk
 */
struct _dnbd3_image
{
	char *path;            // absolute path of the image
	char *lower_name;      // relative path, all lowercase, minus revision ID
	uint8_t *cache_map;    // cache map telling which parts are locally cached, NULL if complete
	uint32_t *crc32;       // list of crc32 checksums for each 16MiB block in image
	dnbd3_connection_t *uplink; // pointer to a server connection
	uint64_t filesize;     // size of image
	int cacheFd;           // used to write to the image, in case it is relayed. ONLY USE FROM UPLINK THREAD!
	int rid;               // revision of image
	int users;             // clients currently using this image
	time_t atime;          // last access time
	char working;          // TRUE if image exists and completeness is == 100% or a working upstream proxy is connected
	pthread_spinlock_t lock;
};

typedef struct
{
	int sock;
	dnbd3_host_t host;
	uint8_t is_server;         // TRUE if a server in proxy mode, FALSE if real client
	pthread_t thread;
	dnbd3_image_t *image;
	pthread_spinlock_t lock;
	//GSList *sendqueue;         // list of dnbd3_binstring_t*
} dnbd3_client_t;

// #######################################################

/**
 * Base directory where all images are stored in. Will always have a trailing slash
 */
extern char *_basePath;

/**
 * Whether or not simple *.vmdk files should be treated as revision 1
 */
extern int _vmdkLegacyMode;

extern int _shutdown;

#endif /* GLOBALS_H_ */
