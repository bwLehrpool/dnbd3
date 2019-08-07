#include "connection.h"
#include "helper.h"
#include "../config.h"
#include "../shared/protocol.h"
#include "../shared/fdsignal.h"
#include "../shared/sockhelper.h"
#include "../shared/log.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/* Constants */
static const size_t SHORTBUF = 100;
#define SOCKET_KEEPALIVE_TIMEOUT (3)
#define MAX_ALTS (8)
#define MAX_HOSTS_PER_ADDRESS (2)
#define RTT_COUNT (4)

/* Module variables */
static char trash[4096];

// Known alt servers
typedef struct _alt_server {
	dnbd3_host_t host;
	int consecutiveFails;
	int rtt;
	int rtts[RTT_COUNT];
	int rttIndex;
	int bestCount;
} alt_server_t;
alt_server_t altservers[MAX_ALTS];
dnbd3_server_entry_t newservers[MAX_ALTS];
pthread_spinlock_t altLock;

bool connection_init_n_times(
		const char *hosts,
		const char *lowerImage,
		const uint16_t rid,
		int ntimes,
		int blockSize,
		BenchCounters* counters
		) {
	for (int run_i = 0; run_i < ntimes; ++run_i) {
		counters->attempts++;

		putchar('.');
		fflush(stdout);
		int sock = -1;
		char host[SHORTBUF];
		serialized_buffer_t buffer;
		uint16_t remoteVersion, remoteRid;
		char *remoteName;
		uint64_t remoteSize;

		dnbd3_host_t tempHosts[MAX_HOSTS_PER_ADDRESS];
		const char *current, *end;
		int altIndex = 0;
		memset( altservers, 0, sizeof altservers );
		current = hosts;
		do {
			// Get next host from string
			while ( *current == ' ' ) current++;
			end = strchr( current, ' ' );
			size_t len = (end == NULL ? SHORTBUF : (size_t)( end - current ) + 1);
			if ( len > SHORTBUF ) len = SHORTBUF;
			snprintf( host, len, "%s", current );
			int newHosts = sock_resolveToDnbd3Host( host, tempHosts, MAX_HOSTS_PER_ADDRESS );
			for ( int i = 0; i < newHosts; ++i ) {
				if ( altIndex >= MAX_ALTS )
					break;
				altservers[altIndex].host = tempHosts[i];
				altIndex += 1;
			}
			current = end + 1;
		} while ( end != NULL && altIndex < MAX_ALTS );
		// Connect
		for ( int i = 0; i < altIndex; ++i ) {
			if ( altservers[i].host.type == 0 )
				continue;
			// Try to connect
			dnbd3_reply_t reply;
			sock = sock_connect( &altservers[i].host, 3500, 10000 );
			if ( sock == -1 ) {
				counters->fails++;
				logadd( LOG_ERROR, "Could not connect to host (errno=%d)", errno );
			} else if ( !dnbd3_select_image( sock, lowerImage, rid, 0 ) ) {
				counters->fails++;
				logadd( LOG_ERROR, "Could not send select image" );
			} else if ( !dnbd3_select_image_reply( &buffer, sock, &remoteVersion, &remoteName, &remoteRid, &remoteSize ) ) {
				counters->fails++;
				logadd( LOG_ERROR, "Could not read select image reply (%d)", errno );
			} else if ( rid != 0 && rid != remoteRid ) {
				counters->fails++;
				logadd( LOG_ERROR, "rid mismatch" );
			} else if ( !dnbd3_get_block( sock, run_i * blockSize, blockSize, 0, 0 ) ) {
				counters->fails++;
				logadd( LOG_ERROR, "send: get block failed" );
			} else if ( !dnbd3_get_reply( sock, &reply ) ) {
				counters->fails++;
				logadd( LOG_ERROR, "recv: get block header failed" );
			} else {
				int rv, togo = blockSize;
				do {
					rv = recv( sock, trash, MIN( sizeof(trash), togo ), MSG_WAITALL|MSG_NOSIGNAL );
					if ( rv == -1 && errno == EINTR )
						continue;
					if ( rv <= 0 )
						break;
					togo -= rv;
				} while ( togo > 0 );
				if ( togo != 0 ) {
					counters->fails++;
					logadd( LOG_ERROR, "recv: get block payload failed (remaining %d)", togo );
				} else {
					counters->success++;
					close( sock );
					sock = -1;
					continue;
				}
			}
			// Failed
			if ( sock != -1 ) {
				close( sock );
				sock = -1;
			}
		}
		if ( sock != -1 ) {
			close( sock );
		}
	}
	return true;
}
