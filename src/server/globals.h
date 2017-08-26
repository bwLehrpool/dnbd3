#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include "../types.h"
#include "../shared/fdsignal.h"
#include "serverconfig.h"
#include <stdint.h>
#include <time.h>
#include <pthread.h>

// ######### All structs/types used by the server ########

typedef struct _dnbd3_connection dnbd3_connection_t;
typedef struct _dnbd3_image dnbd3_image_t;
typedef struct _dnbd3_client dnbd3_client_t;

// Slot is free, can be used.
// Must only be set in uplink_handle_receive() or uplink_remove_client()
#define ULR_FREE 0
// Slot has been filled with a request that hasn't been sent to the upstream server yet, matching request can safely rely on reuse.
// Must only be set in uplink_request()
#define ULR_NEW 1
// Slot is occupied, reply has not yet been received, matching request can safely rely on reuse.
// Must only be set in uplink_mainloop()
#define ULR_PENDING 2
// Slot is being processed, do not consider for hop on.
// Must only be set in uplink_handle_receive()
#define ULR_PROCESSING 3
typedef struct
{
	uint64_t handle;  // Client defined handle to pass back in reply
	uint64_t from;    // First byte offset of requested block (ie. 4096)
	uint64_t to;      // Last byte + 1 of requested block (ie. 8192, if request len is 4096, resulting in bytes 4096-8191)
	dnbd3_client_t * client; // Client to send reply to
	int status;      // status of this entry: ULR_*
	time_t entered;           // When this request entered the queue (for debugging)
} dnbd3_queued_request_t;

#define RTT_IDLE 0 // Not in progress
#define RTT_INPROGRESS 1 // In progess, not finished
#define RTT_DONTCHANGE 2 // Finished, but no better alternative found
#define RTT_DOCHANGE 3 // Finished, better alternative written to .betterServer + .betterFd
#define RTT_NOT_REACHABLE 4 // No uplink was reachable
struct _dnbd3_connection
{
	int fd;                     // socket fd to remote server
	dnbd3_signal_t* signal;     // used to wake up the process
	pthread_t thread;           // thread holding the connection
	pthread_spinlock_t queueLock; // lock for synchronization on request queue etc.
	dnbd3_queued_request_t queue[SERVER_MAX_UPLINK_QUEUE];
	int queueLen;               // length of queue
	dnbd3_image_t *image;       // image that this uplink is used for; do not call get/release for this pointer
	dnbd3_host_t currentServer; // Current server we're connected to
	pthread_spinlock_t rttLock; // When accessing rttTestResult, betterFd or betterServer
	int rttTestResult;          // RTT_*
	dnbd3_host_t betterServer;  // The better server
	int betterFd;               // Active connection to better server, ready to use
	uint8_t *recvBuffer;        // Buffer for receiving payload
	uint32_t recvBufferLen;     // Len of ^^
	volatile bool shutdown;     // signal this thread to stop, must only be set from uplink_shutdown() or cleanup in uplink_mainloop()
	bool replicatedLastBlock;   // bool telling if the last block has been replicated yet
	int nextReplicationIndex;   // Which index in the cache map we should start looking for incomplete blocks at
	uint64_t replicationHandle; // Handle of pending replication request
	uint64_t bytesReceived;     // Number of bytes received by the connection.
};

typedef struct
{
	uint16_t len;
	uint8_t data[65535];
} dnbd3_binstring_t;
// Do not always allocate as much memory as required to hold the entire binstring struct,
// but only as much as is required to hold the actual data (relevant for kernel module)
#define NEW_BINSTRING(_name, _len) \
	dnbd3_binstring_t *_name = malloc(sizeof(uint16_t) + _len); \
	_name->len = _len

typedef struct
{
	char comment[COMMENT_LENGTH];
	dnbd3_host_t host;
	int rtt[SERVER_RTT_PROBES];
	int rttIndex;
	bool isPrivate, isClientOnly;
	time_t lastFail;
	int numFails;
} dnbd3_alt_server_t;

typedef struct
{
	char comment[COMMENT_LENGTH];
	dnbd3_host_t host;
	dnbd3_host_t mask;
} dnbd3_acess_rules_t;

/**
 * Image struct. An image path could be something like
 * /mnt/images/rz/zfs/Windows7 ZfS.vmdk.r1
 * and the name would then be
 * rz/zfs/windows7 zfs.vmdk
 */
struct _dnbd3_image
{
	char *path;            // absolute path of the image
	char *name;            // public name of the image (usually relative path minus revision ID)
	dnbd3_connection_t *uplink; // pointer to a server connection
	uint8_t *cache_map;    // cache map telling which parts are locally cached, NULL if complete
	uint64_t virtualFilesize;   // virtual size of image (real size rounded up to multiple of 4k)
	uint64_t realFilesize;      // actual file size on disk
	time_t atime;          // last access time
	time_t lastWorkCheck;  // last time a non-working image has been checked
	time_t nextCompletenessEstimate; // last time the completeness estimate was updated
	uint32_t *crc32;       // list of crc32 checksums for each 16MiB block in image
	uint32_t masterCrc32;  // CRC-32 of the crc-32 list
	int readFd;            // used to read the image. Used from multiple threads, so use atomic operations (pread et al)
	int cacheFd;           // used to write to the image, in case it is relayed. ONLY USE FROM UPLINK THREAD!
	int rid;               // revision of image
	int completenessEstimate; // Completeness estimate in percent
	int users;             // clients currently using this image
	int id;                // Unique ID of this image. Only unique in the context of this running instance of DNBD3-Server
	bool working;          // true if image exists and completeness is == 100% or a working upstream proxy is connected
	pthread_spinlock_t lock;
};

struct _dnbd3_client
{
#define HOSTNAMELEN (48)
	uint64_t bytesSent;    // Byte counter for this client. Use statsLock when accessing
	dnbd3_image_t *image;
	uint32_t tmpBytesSent; // Temporary byte counter that gets added to the global counter periodically. Use statsLock when accessing
	int sock;
	bool isServer;         // true if a server in proxy mode, false if real client
	dnbd3_host_t host;
	char hostName[HOSTNAMELEN];
	pthread_mutex_t sendMutex;
	pthread_spinlock_t lock;
	pthread_spinlock_t statsLock;
};

// #######################################################
#define CONFIG_FILENAME "server.conf"

/**
 * Base directory where the configuration files reside. Will never have a trailing slash.
 */
extern char *_configDir;

/**
 * Base directory where all images are stored in. Will never have a trailing slash.
 */
extern char *_basePath;

/**
 * Whether or not simple *.vmdk files should be treated as revision 1
 */
extern bool _vmdkLegacyMode;

/**
 * How much artificial delay should we add when a server connects to us?
 */
extern int _serverPenalty;

/**
 * How much artificial delay should we add when a client connects to us?
 */
extern int _clientPenalty;

/**
 * Is server shutting down?
 */
extern volatile bool _shutdown;

/**
 * Is server allowed to provide images in proxy mode?
 */
extern bool _isProxy;

/**
 * Only use servers as upstream proxy which are private?
 */
extern bool _proxyPrivateOnly;

/**
 * Whether to remove missing images from image list on SIGHUP
 */
extern bool _removeMissingImages;

/**
 * Read timeout when waiting for or sending data on an uplink
 */
extern int _uplinkTimeout;

/**
 * Read timeout when waiting for or sending data from/to client
 */
extern int _clientTimeout;

/**
 * If true, images with no active client will have their fd closed after some
 * idle time.
 */
extern bool _closeUnusedFd;

/**
 * Should we replicate incomplete images in the background?
 * Otherwise, only blocks that were explicitly requested will be cached.
 */
extern bool _backgroundReplication;

/**
 * Port to listen on (default: #define PORT (5003))
 */
extern int _listenPort;

/**
 * Load the server configuration.
 */
void globals_loadConfig();

#endif /* GLOBALS_H_ */
