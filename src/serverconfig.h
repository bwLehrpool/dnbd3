#ifndef _SERVERCONFIG_H_
#define _SERVERCONFIG_H_

#include "config.h"

// +++++ Performance/memory related
#define SERVER_MAX_CLIENTS 4000
#define SERVER_MAX_IMAGES  5000
#define SERVER_MAX_ALTS    50
// +++++ Uplink handling (proxy mode)
#define SERVER_GLOBAL_DUP_TIME 6 // How many seconds to wait before changing global fail counter again
#define SERVER_BAD_UPLINK_MIN 10 // Thresold for fails at which we start ignoring the server occasionally
#define SERVER_BAD_UPLINK_MAX 20 // Hard block server if it failed this many times
#define SERVER_BAD_UPLINK_LOCAL_BLOCK 10 // If a server didn't supply the requested image this many times, block it for some time
#define SERVER_BAD_UPLINK_IGNORE 180 // How many seconds is a server ignored
#define UPLINK_MAX_QUEUE  500 // Maximum number of queued requests per uplink
#define UPLINK_MAX_CLIENTS_PER_REQUEST 32 // Maximum number of clients that can attach to one uplink request
#define SERVER_UPLINK_QUEUELEN_THRES  900 // Threshold where we start dropping incoming clients
#define SERVER_MAX_PENDING_ALT_CHECKS 500 // Length of queue for pending alt checks requested by uplinks

// Wait a maximum of 5 minutes before saving cache map (if data was received at all)
#define CACHE_MAP_MAX_SAVE_DELAY 300
// If more than 500MB have been received from uplink without saving cache map, do so
#define CACHE_MAP_MAX_UNSAVED_BYTES ((uint64_t)500 * 1000 * 1000)

// Time in ms to wait for a read/write call to complete on an uplink connection
#define SOCKET_TIMEOUT_UPLINK 5000
// Same for client connections. Be a bit more liberal here
#define SOCKET_TIMEOUT_CLIENT 15000
// When waiting for the next request header from client, allow the timeout from above
// to expire this many times. This allows for greater idle times without also increasing
// the timeout for cases where we wait for additional data or are actively sending a reply
#define SOCKET_TIMEOUT_CLIENT_RETRIES 3

#define SERVER_UPLINK_KEEPALIVE_INTERVAL 10 // (Seconds) Send keep-alive if nothing else is happening on the uplink
#define SERVER_UPLINK_IDLE_TIMEOUT 1800 // (Seconds) Timeout after which we tear down an uplink connection if no blocks needed to be fetched

// +++++ Other magic constants
#define SERVER_RTT_PROBES 5 // How many probes to average over
#define SERVER_RTT_INTERVAL_INIT 5 // Initial interval between probes
#define SERVER_RTT_INTERVAL_MAX 45 // Maximum interval between probes
#define SERVER_RTT_MAX_UNREACH 10 // If no server was reachable this many times, stop RTT measurements for a while
#define SERVER_RTT_INTERVAL_FAILED 180 // Interval to use if no uplink server is reachable for above many times

#define SERVER_REMOTE_IMAGE_CHECK_CACHETIME 120 // 2 minutes

// Which is the minimum protocol version the server expects from the client
#define MIN_SUPPORTED_CLIENT 2
// Same for when we're a proxy talking to another server
#define MIN_SUPPORTED_SERVER 2

// Length of comment fields (for alt server etc.)
#define COMMENT_LENGTH 120

#define RTT_THRESHOLD_FACTOR(us) (((us) * 2) / 3) // 2/3 = current to best must be 33% worse
#define RTT_UNREACHABLE 0x7FFFFFFu // Use this value for timeout/unreachable as RTT. Don't set too high or you might get overflows. 0x7FFFFFF = 134 seconds

// How many seconds have to pass after the last client disconnected until the imagefd is closed
#define UNUSED_FD_TIMEOUT 3600

#endif

