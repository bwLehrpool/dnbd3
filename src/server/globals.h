#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include <dnbd3/types.h>
#include <dnbd3/shared/fdsignal.h>
#include <dnbd3/config/server.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include "reftypes.h"

typedef struct timespec ticks;

// ######### All structs/types used by the server ########

typedef struct _dnbd3_uplink dnbd3_uplink_t;
typedef struct _dnbd3_image dnbd3_image_t;
typedef struct _dnbd3_client dnbd3_client_t;

typedef void (*uplink_callback)(void *data, uint64_t handle, uint64_t start, uint32_t length, const char *buffer);

typedef struct _dnbd3_queue_client
{
	struct _dnbd3_queue_client *next;
	void* data; // Passed back to callback
	uint64_t handle;    // Passed back to callback
	uint64_t from, to;  // Client range
	uplink_callback callback; // Callback function
} dnbd3_queue_client_t;

typedef struct _dnbd3_queue_entry
{
	struct _dnbd3_queue_entry *next;
	uint64_t   handle;   // Our handle for this entry
	uint64_t   from;     // First byte offset of requested block (ie. 4096)
	uint64_t   to;       // Last byte + 1 of requested block (ie. 8192, if request len is 4096, resulting in bytes 4096-8191)
	dnbd3_queue_client_t *clients;
#ifdef DEBUG
	ticks      entered;  // When this request entered the queue (for debugging)
#endif
	uint8_t    hopCount; // How many hops this request has already taken across proxies
	bool       sent;     // Already sent to uplink?
} dnbd3_queue_entry_t;

typedef struct _ns
{
	struct _ns *next;
	char *name;
	size_t len;
} dnbd3_ns_t;

typedef struct
{
	int fails;                    // Hard fail: Connection failed
	int rttIndex;
	uint32_t rtt[SERVER_RTT_PROBES];
	bool isPrivate, isClientOnly;
	bool blocked;                 // If true count down fails until 0 to enable again
	ticks lastFail;               // Last hard fail
	dnbd3_host_t host;
	char comment[COMMENT_LENGTH];
	_Atomic(dnbd3_ns_t *) nameSpaces; // Linked list of name spaces
} dnbd3_alt_server_t;

typedef struct
{
	int fails;                    // Soft fail: Image not found
	int rttIndex;
	uint32_t rtt[SERVER_RTT_PROBES];
	bool blocked;                 // True if server is to be ignored and fails should be counted down
	bool initDone;
} dnbd3_alt_local_t;

typedef struct {
	int fd;            // Socket fd for this connection
	int version;       // Protocol version of remote server
	int index;         // Entry in uplinks list
} dnbd3_server_connection_t;

#define RTT_IDLE 0 // Not in progress
#define RTT_INPROGRESS 1 // In progess, not finished
#define RTT_DONTCHANGE 2 // Finished, but no better alternative found
#define RTT_DOCHANGE 3 // Finished, better alternative written to .betterServer + .betterFd
#define RTT_NOT_REACHABLE 4 // No uplink was reachable
struct _dnbd3_uplink
{
	ref reference;
	dnbd3_server_connection_t current; // Currently active connection; fd == -1 means disconnected
	dnbd3_server_connection_t better; // Better connection as found by altserver worker; fd == -1 means none
	dnbd3_signal_t* signal;     // used to wake up the process
	pthread_t thread;           // thread holding the connection
	pthread_mutex_t sendMutex;  // For locking socket while sending
	pthread_mutex_t queueLock;  // lock for synchronization on request queue etc.
	dnbd3_image_t *image;       // image that this uplink is used for; do not call get/release for this pointer
	pthread_mutex_t rttLock;    // When accessing rttTestResult, betterFd or betterServer
	atomic_int rttTestResult;   // RTT_*
	int cacheFd;                // used to write to the image, in case it is relayed. ONLY USE FROM UPLINK THREAD!
	uint8_t *recvBuffer;        // Buffer for receiving payload
	uint32_t recvBufferLen;     // Len of ^^
	atomic_bool shutdown;       // signal this thread to stop, must only be set from uplink_shutdown() or cleanup in uplink_mainloop()
	bool replicatedLastBlock;   // bool telling if the last block has been replicated yet
	bool cycleDetected;         // connection cycle between proxies detected for current remote server
	int nextReplicationIndex;   // Which index in the cache map we should start looking for incomplete blocks at
	                            // If BGR == BGR_HASHBLOCK, -1 means "currently no incomplete block"
	atomic_uint_fast64_t bytesReceived; // Number of bytes received by the uplink since startup.
	atomic_uint_fast64_t bytesReceivedLastSave; // Number of bytes received when we last saved the cache map
	int queueLen;               // length of queue
	int idleTime;               // How many seconds the uplink was idle (apart from keep-alives)
	dnbd3_queue_entry_t *queue;
	atomic_uint_fast32_t queueId;
	dnbd3_alt_local_t altData[SERVER_MAX_ALTS];
};

typedef struct
{
	uint8_t host[16];
	int bytes;
	int bitMask;
	int permissions;
} dnbd3_access_rule_t;

typedef struct
{
	ref reference;
	atomic_bool dirty;     // Cache map has been modified outside uplink (only integrity checker for now)
	bool unchanged;        // How many times in a row a reloaded cache map went unchanged
	_Atomic uint8_t map[];
} dnbd3_cache_map_t;

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
	weakref uplinkref;     // pointer to a server connection
	weakref ref_cacheMap;  // cache map telling which parts are locally cached, NULL if complete
	uint64_t virtualFilesize;   // virtual size of image (real size rounded up to multiple of 4k)
	uint64_t realFilesize;      // actual file size on disk
	uint64_t wwn;               // WorldWideName
	ticks atime;                // last access time
	ticks nextCompletenessEstimate; // next time the completeness estimate should be updated
	uint32_t *crc32;       // list of crc32 checksums for each 16MiB block in image
	uint32_t masterCrc32;  // CRC-32 of the crc-32 list
	int readFd;            // used to read the image. Used from multiple threads, so use atomic operations (pread et al)
	atomic_int completenessEstimate; // Completeness estimate in percent
	atomic_int users;      // clients currently using this image. XXX Lock on imageListLock when modifying and checking whether the image should be freed. Reading it elsewhere is fine without the lock.
	int id;                // Unique ID of this image. Only unique in the context of this running instance of DNBD3-Server
	struct {
		atomic_bool read;        // Error reading from file
		atomic_bool write;       // Error writing to file
		atomic_bool changed;     // File disappeared or changed, thorough check required if it seems to be back
		atomic_bool uplink;      // No uplink connected
		atomic_bool queue;       // Too many requests waiting on uplink
	} problem;
	uint16_t rid;          // revision of image
	bool accessed;         // image was accessed since .meta was written
	bool wantCheck;        // true if the entire image should be checked as soon as the according thread is idle
	pthread_mutex_t lock;
};
#define PIMG(x) (x)->name, (int)(x)->rid

struct _dnbd3_client
{
#define HOSTNAMELEN (48)
	atomic_uint_fast64_t bytesSent;   // Byte counter for this client.
	dnbd3_image_t * _Atomic image;    // Image in use by this client, or NULL during handshake
	int sock;
	_Atomic uint8_t relayedCount;     // How many requests are in-flight to the uplink server
	bool isServer;                    // true if a server in proxy mode, false if real client
	dnbd3_host_t host;
	char hostName[HOSTNAMELEN];       // inet_ntop version of host
	pthread_mutex_t sendMutex;        // Held while writing to sock if image is incomplete (since uplink uses socket too)
	pthread_mutex_t lock;
	pthread_t thread;
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
extern atomic_bool _vmdkLegacyMode;

/**
 * How much artificial delay should we add when a server connects to us?
 */
extern atomic_int _serverPenalty;

/**
 * How much artificial delay should we add when a client connects to us?
 */
extern atomic_int _clientPenalty;

/**
 * Is server shutting down?
 */
extern atomic_bool _shutdown;

/**
 * Is server allowed to provide images in proxy mode?
 */
extern atomic_bool _isProxy;

/**
 * Only use servers as upstream proxy which are private?
 */
extern atomic_bool _proxyPrivateOnly;

/**
 * Whether to remove missing images from image list on SIGHUP
 */
extern atomic_bool _removeMissingImages;

/**
 * Read timeout when waiting for or sending data on an uplink
 */
extern atomic_uint _uplinkTimeout;

/**
 * Read timeout when waiting for or sending data from/to client
 */
extern atomic_uint _clientTimeout;

/**
 * If true, images with no active client will have their fd closed after some
 * idle time.
 */
extern atomic_bool _closeUnusedFd;

/**
 * Should we replicate incomplete images in the background?
 * Otherwise, only blocks that were explicitly requested will be cached.
 */
extern atomic_int _backgroundReplication;
#define BGR_DISABLED (0)
#define BGR_FULL (1)
#define BGR_HASHBLOCK (2)

/**
 * Minimum connected clients for background replication to kick in
 */
extern atomic_int _bgrMinClients;

/**
 * How many in-flight replication requests we should target (per uplink)
 */
extern atomic_int _bgrWindowSize;

/**
 * (In proxy mode): If connecting client is a proxy, and the requested image
 * is not known locally, should we ask our known alt servers for it?
 * Otherwise the request is rejected.
 */
extern atomic_bool _lookupMissingForProxy;

/**
 * Should we preallocate proxied images right at the start to make
 * sure we can cache it entirely, or rather create sparse files
 * with holes in them? With sparse files, we just keep writing
 * cached blocks to disk until it is full, and only then will we
 * start to delete old images. This might be a bit flaky so use
 * only in space restricted environments. Also make sure your
 * file system actually supports sparse files / files with holes
 * in them, or you might get really shitty performance.
 * This setting will have no effect if background replication is
 * turned on.
 */
extern atomic_bool _sparseFiles;

/**
 * If true, don't abort image replication if preallocating
 * the image fails, but retry with sparse file.
 */
extern atomic_bool _ignoreAllocErrors;

/**
 * Port to listen on (default: #define PORT (5003))
 */
extern atomic_int _listenPort;

/**
 * Max number of DNBD3 clients we accept
 */
extern atomic_int _maxClients;

/**
 * Max number of Images we support (in baseDir)
 */
extern atomic_int _maxImages;

/**
 * Maximum payload length we accept on uplinks and thus indirectly
 * from clients in case the requested range is not cached locally.
 * Usually this isn't even a megabyte for "real" clients (blockdev
 * or fuse).
 */
extern atomic_uint _maxPayload;

/**
 * If in proxy mode, don't replicate images that are
 * larger than this according to the uplink server.
 */
extern atomic_uint_fast64_t _maxReplicationSize;

/**
 * Pretend to be a client when talking to others servers,
 * effectively not setting the server bit during connection
 * setup. Useful for local caching.
 */
extern atomic_bool _pretendClient;

/**
 * Minimum uptime in seconds before proxy starts deleting old
 * images if running out of space. -1 disables automatic deletion.
 * Only relevant in proxy mode.
 */
extern atomic_int _autoFreeDiskSpaceDelay;

/**
 * Specifies if the iSCSI server should be initialized, enabled
 * and used upon start of DNBD3 server.
 */
extern atomic_bool _iSCSIServer;

/**
 * When handling a client request, this sets the maximum amount
 * of bytes we prefetch offset right at the end of the client request.
 * The prefetch size will be MIN( length * 3, _maxPrefetch ), if
 * length <= _maxPrefetch, so effectively, setting this to 0 disables
 * any prefetching.
 */
extern atomic_uint _maxPrefetch;

/**
 * Use with care. Can severely degrade performance.
 * Set either 0 or very high.
 */
extern atomic_uint _minRequestSize;

/**
 * Load the server configuration.
 */
void globals_loadConfig();

/**
 * Dump the effective configuration in use to given buffer.
 */
size_t globals_dumpConfig(char *buffer, size_t size);

#endif /* GLOBALS_H_ */
