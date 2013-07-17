#include "uplink.h"
#include "locks.h"
#include <pthread.h>
#include <sys/socket.h>
#include <string.h>

dnbd3_alt_server_t *_alt_servers[SERVER_MAX_ALTS];
int _num_alts = 0;
pthread_spinlock_t _alts_lock;

/**
 * Get <size> known (working) alt servers, ordered by network closeness
 * (by finding the smallest possible subnet)
 */
int uplink_get_matching_alt_servers(dnbd3_host_t *host, dnbd3_server_entry_t *output, int size)
{
	if ( host == NULL || host->type == 0 || _num_alts == 0 ) return 0;
	int i, j;
	int count = 0;
	int distance[size];
	spin_lock( &_alts_lock );
	for (i = 0; i < _num_alts; ++i) {
		if ( host->type != _alt_servers[i]->host.type ) continue; // Wrong address family
		if ( count == 0 ) {
			// Trivial - this is the first entry
			memcpy( &output[0].host, &_alt_servers[i]->host, sizeof(dnbd3_host_t) );
			output[0].failures = 0;
			distance[0] = uplink_net_closeness( host, &output[0].host );
			count++;
		} else {
			// Other entries already exist, insert in proper position
			const int dist = uplink_net_closeness( host, &_alt_servers[i]->host );
			for (j = 0; j < size; ++j) {
				if ( j < count && dist <= distance[j] ) continue;
				if (j > count) break; // Should never happen but just in case...
				if ( j < count ) {
					// Check if we're in the middle and need to move other entries...
					if (j + 1 < size) {
						memmove(&output[j + 1], &output[j], sizeof(dnbd3_server_entry_t) * (size - j - 1));
						memmove(&distance[j + 1], &distance[j], sizeof(int) * (size - j - 1));
					}
				} else {
					count++;
				}
				memcpy( &output[j].host, &_alt_servers[i]->host, sizeof(dnbd3_host_t) );
				output[j].failures = 0;
				distance[j] = dist;
				break;
			}
		}
	}
	spin_unlock( &_alts_lock );
	return count;
}

/**
 * Determine how close two addresses are to each other by comparing the number of
 * matching bits from the left of the address. Does not count individual bits but
 * groups of 4 for speed.
 */
int uplink_net_closeness(dnbd3_host_t *host1, dnbd3_host_t *host2)
{
	if ( host1 == NULL || host2 == NULL || host1->type != host2->type ) return -1;
	int retval = 0;
	const int max = host1->type == AF_INET ? 4 : 16;
	for (int i = 0; i < max; ++i) {
		if ( (host1->addr[i] & 0xf0) != (host2->addr[i] & 0xf0) ) return retval;
		++retval;
		if ( (host1->addr[i] & 0x0f) != (host2->addr[i] & 0x0f) ) return retval;
		++retval;
	}
	return retval;
}

void uplink_shutdown( dnbd3_connection_t *uplink)
{
	return;
}
