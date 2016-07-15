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
#define MAX_ALTS (8)
#define MAX_HOSTS_PER_ADDRESS (2)
// If a server wasn't reachable this many times, we slowly start skipping it on measurements
static const int FAIL_BACKOFF_START_COUNT = 8;
#define RTT_COUNT (4)

/* Module variables */

// Init guard
static bool connectionInitDone = false;
static bool keepRunning = true;

static struct {
	int sockFd;
	pthread_mutex_t sendMutex;
	dnbd3_signal_t* panicSignal;
	dnbd3_host_t currentServer;
	uint64_t startupTime;
} connection;

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
		BenchCounters* counters,
		bool closeSockets
		) {
	for (int run_i = 0; run_i < ntimes; ++run_i) {
		counters->attempts++;

		printf(".");
		int sock = -1;
		char host[SHORTBUF];
		serialized_buffer_t buffer;
		uint16_t remoteVersion, remoteRid;
		char *remoteName;
		uint64_t remoteSize;

		if ( !connectionInitDone && keepRunning ) {
			dnbd3_host_t tempHosts[MAX_HOSTS_PER_ADDRESS];
			const char *current, *end;
			int altIndex = 0;
			memset( altservers, 0, sizeof altservers );
			connection.sockFd = -1;
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
			logadd( LOG_INFO, "Got %d servers from init call", altIndex );
			// Connect
			for ( int i = 0; i < altIndex; ++i ) {
				if ( altservers[i].host.type == 0 )
					continue;
				// Try to connect
				sock = sock_connect( &altservers[i].host, 500, SOCKET_KEEPALIVE_TIMEOUT * 1000 );
				if ( sock == -1 ) {
					counters->fails++;
					logadd( LOG_ERROR, "Could not connect to host" );
				} else if ( !dnbd3_select_image( sock, lowerImage, rid, 0 ) ) {
					counters->fails++;
					logadd( LOG_ERROR, "Could not send select image" );
				} else if ( !dnbd3_select_image_reply( &buffer, sock, &remoteVersion, &remoteName, &remoteRid, &remoteSize ) ) {
					counters->fails++;
					logadd( LOG_ERROR, "Could not read select image reply (%d)", errno );
				} else if ( rid != 0 && rid != remoteRid ) {
					counters->fails++;
					logadd( LOG_ERROR, "rid mismatch" );
				} else {
					counters->success++;
					break;
				}
				// Failed
				logadd( LOG_DEBUG1, "Server does not offer requested image... " );
				if ( sock != -1 ) {
					close( sock );
					sock = -1;
				}
			}
			if ( sock != -1 ) {
				// connectionInitDone = true;
				if (closeSockets) {
					close( sock );
				}
			}
		}
	}
	return true;
}
