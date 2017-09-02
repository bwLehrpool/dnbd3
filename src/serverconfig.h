#ifndef _SERVERCONFIG_H_
#define _SERVERCONFIG_H_

#include "config.h"

// +++++ Performance related
#define SERVER_MAX_CLIENTS 4000
#define SERVER_MAX_IMAGES  5000
#define SERVER_MAX_ALTS    250
#define SERVER_MAX_UPLINK_FAILS  8 // How many times may a server fail until it is considered bad
#define SERVER_BAD_UPLINK_IGNORE 120 // How many seconds is a server considered bad?
#define SERVER_MAX_UPLINK_QUEUE  1500 // Maximum number of queued requests per uplink
#define SERVER_UPLINK_QUEUELEN_THRES  900 // Threshold where we start dropping incoming clients
#define SERVER_MAX_PENDING_ALT_CHECKS 50
#define SERVER_CACHE_MAP_SAVE_INTERVAL 90

// Time in ms to wait for a read/write call to complete on an uplink connection
#define SOCKET_TIMEOUT_UPLINK 5000
// Same for client connections. Be a bit more liberal here
#define SOCKET_TIMEOUT_CLIENT 15000
// When waiting for the next request header from client, allow the timeout from above
// to expire this many times. This allows for greater idle times without also increasing
// the timeout for cases where we wait for additional data or are actively sending a reply
#define SOCKET_TIMEOUT_CLIENT_RETRIES 3

// +++++ Other magic constants
#define SERVER_RTT_PROBES 5
#define SERVER_RTT_DELAY_INIT 5
#define SERVER_RTT_DELAY_MAX 45
#define SERVER_RTT_DELAY_FAILED 180

#define SERVER_REMOTE_IMAGE_CHECK_CACHETIME 120 // 2 minutes
#define SERVER_MAX_PROXY_IMAGE_SIZE 100000000000LL // 100GB

// Which is the minimum protocol version the server expects from the client
#define MIN_SUPPORTED_CLIENT 2
// Same for when we're a proxy talking to another server
#define MIN_SUPPORTED_SERVER 2

// Length of comment fields (for alt server etc.)
#define COMMENT_LENGTH 120

#define RTT_THRESHOLD_FACTOR(us) (((us) * 2) / 3) // 2/3 = current to best must be 33% worse

// How many seconds have to pass after the last client disconnected until the imagefd is closed
#define UNUSED_FD_TIMEOUT 3600

#endif

