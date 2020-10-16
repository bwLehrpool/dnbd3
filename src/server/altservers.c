#include "ini.h"
#include "altservers.h"
#include "locks.h"
#include "threadpool.h"
#include "helper.h"
#include "image.h"
#include "fileutil.h"
#include <dnbd3/shared/protocol.h>
#include <dnbd3/shared/timing.h>
#include <dnbd3/config/server.h>
#include "reference.h"

#include <assert.h>
#include <inttypes.h>
#include <jansson.h>

#define LOG(lvl, msg, ...) logadd(lvl, msg " (%s:%d)", __VA_ARGS__, PIMG(image))
#define LOG_GOTO(jumplabel, lvl, ...) do { LOG(lvl, __VA_ARGS__); goto jumplabel; } while (0);
#define ERROR_GOTO(jumplabel, ...) LOG_GOTO(jumplabel, LOG_ERROR, __VA_ARGS__)

static dnbd3_alt_server_t altServers[SERVER_MAX_ALTS];
static atomic_int numAltServers = 0;
static pthread_mutex_t altServersLock;

static void *altservers_runCheck(void *data);
static int altservers_getListForUplink(dnbd3_uplink_t *uplink, const char *image, int *servers, int size, int current);
static void altservers_findUplinkInternal(dnbd3_uplink_t *uplink);
static uint32_t altservers_updateRtt(dnbd3_uplink_t *uplink, int index, uint32_t rtt);
static void altservers_imageFailed(dnbd3_uplink_t *uplink, int server);

void altservers_init()
{
	srand( (unsigned int)time( NULL ) );
	// Init lock
	mutex_init( &altServersLock, LOCK_ALT_SERVER_LIST );
}

static void addAltFromLegacy(int argc, char **argv, void *data)
{
	char *shost;
	dnbd3_host_t host;
	bool isPrivate = false;
	bool isClientOnly = false;
	if ( argv[0][0] == '#' ) return;
	for (shost = argv[0]; *shost != '\0'; ) { // Trim left and scan for "-" prefix
		if ( *shost == '-' ) isPrivate = true;
		else if ( *shost == '+' ) isClientOnly = true;
		else if ( *shost != ' ' && *shost != '\t' ) break;
		shost++;
	}
	if ( !parse_address( shost, &host ) ) {
		logadd( LOG_WARNING, "Invalid entry in alt-servers file ignored: '%s'", shost );
		return;
	}
	if ( argc == 1 ) argv[1] = "";
	if ( altservers_add( &host, argv[1], isPrivate, isClientOnly, NULL ) ) {
		(*(int*)data)++;
	}
}

static int addAltFromIni(void *countptr, const char* section, const char* key, const char* value)
{
	dnbd3_host_t host;
	char *strhost = strdup( section );
	if ( !parse_address( strhost, &host ) ) {
		free( strhost );
		logadd( LOG_WARNING, "Invalid host section in alt-servers file ignored: '%s'", section );
		return 1;
	}
	free( strhost );
	int index;
	if ( altservers_add( &host, "", false, false, &index ) ) {
		(*(int*)countptr)++;
	}
	if ( index == -1 )
		return 1;
	if ( strcmp( key, "for" ) == 0 ) {
		if ( strncmp( value, "client", 6 ) == 0 ) {
			altServers[index].isClientOnly = true;
			altServers[index].isPrivate = false;
		} else if ( strcmp( value, "replication" ) == 0 ) {
			altServers[index].isClientOnly = false;
			altServers[index].isPrivate = true;
		} else {
			logadd( LOG_WARNING, "Invalid value in alt-servers section %s for key %s: '%s'", section, key, value );
		}
	} else if ( strcmp( key, "comment" ) == 0 ) {
		snprintf( altServers[index].comment, COMMENT_LENGTH, "%s", value );
	} else if ( strcmp( key, "namespace" ) == 0 ) {
		dnbd3_ns_t *elem = malloc( sizeof(*elem) );
		elem->name = strdup( value );
		elem->len = strlen( value );
		do {
			elem->next = altServers[index].nameSpaces;
		} while ( !atomic_compare_exchange_weak( &altServers[index].nameSpaces, &elem->next, elem ) );
	} else {
		logadd( LOG_DEBUG1, "Unknown key in alt-servers section: '%s'", key );
	}
	return 1;
}

int altservers_load()
{
	int count = 0;
	char *name;
	if ( asprintf( &name, "%s/%s", _configDir, "alt-servers" ) == -1 ) return -1;
	if ( !file_isReadable( name ) ) {
		free( name );
		return 0;
	}
	ini_parse( name, &addAltFromIni, &count );
	if ( numAltServers == 0 ) {
		logadd( LOG_INFO, "Could not parse %s as .ini file, trying to load as legacy format.", name );
		file_loadLineBased( name, 1, 2, &addAltFromLegacy, (void*)&count );
	}
	free( name );
	logadd( LOG_DEBUG1, "Added %d alt servers\n", count );
	return count;
}

bool altservers_add(dnbd3_host_t *host, const char *comment, const int isPrivate, const int isClientOnly, int *index)
{
	int i, freeSlot = -1;
	if ( index == NULL ) {
		index = &freeSlot;
	}
	mutex_lock( &altServersLock );
	for (i = 0; i < numAltServers; ++i) {
		if ( isSameAddressPort( &altServers[i].host, host ) ) {
			mutex_unlock( &altServersLock );
			*index = i;
			return false;
		} else if ( freeSlot == -1 && altServers[i].host.type == 0 ) {
			freeSlot = i;
		}
	}
	if ( freeSlot == -1 ) {
		if ( numAltServers >= SERVER_MAX_ALTS ) {
			logadd( LOG_WARNING, "Cannot add another alt server, maximum of %d already reached.", (int)SERVER_MAX_ALTS );
			mutex_unlock( &altServersLock );
			*index = -1;
			return false;
		}
		freeSlot = numAltServers++;
	}
	altServers[freeSlot].host = *host;
	altServers[freeSlot].isPrivate = isPrivate;
	altServers[freeSlot].isClientOnly = isClientOnly;
	altServers[freeSlot].nameSpaces = NULL;
	if ( comment != NULL ) snprintf( altServers[freeSlot].comment, COMMENT_LENGTH, "%s", comment );
	mutex_unlock( &altServersLock );
	*index = freeSlot;
	return true;
}

/**
 * ONLY called from the passed uplink's main thread
 */
void altservers_findUplinkAsync(dnbd3_uplink_t *uplink)
{
	if ( uplink->shutdown )
		return;
	if ( uplink->current.fd != -1 && numAltServers <= 1 )
		return;
	// if betterFd != -1 it means the uplink is supposed to switch to another
	// server. As this function here is called by the uplink thread, it can
	// never be that the uplink is supposed to switch, but instead calls
	// this function.
	assert( uplink->better.fd == -1 );
	// it is however possible that an RTT measurement is currently in progress,
	// so check for that case and do nothing if one is in progress
	if ( uplink->rttTestResult != RTT_INPROGRESS ) {
		dnbd3_uplink_t *current = ref_get_uplink( &uplink->image->uplinkref );
		if ( current == uplink ) {
			threadpool_run( &altservers_runCheck, uplink, "UPLINK" );
		} else if ( current != NULL ) {
			ref_put( &current->reference );
		}
	}
}

static bool isImageAllowed(dnbd3_alt_server_t *alt, const char *image)
{
	if ( alt->nameSpaces == NULL )
		return true;
	for ( dnbd3_ns_t *it = alt->nameSpaces; it != NULL; it = it->next ) {
		if ( strncmp( it->name, image, it->len ) == 0 )
			return true;
	}
	return false;
}

/**
 * Get <size> known (working) alt servers, ordered by network closeness
 * (by finding the smallest possible subnet)
 * Private servers are excluded, so this is what you want to call to
 * get a list of servers you can tell a client about
 */
int altservers_getListForClient(dnbd3_client_t *client, dnbd3_server_entry_t *output, int size)
{
	dnbd3_host_t *host = &client->host;
	if ( host->type == 0 || numAltServers == 0 || output == NULL || size <= 0 )
		return 0;
	int i, j;
	int count = 0;
	uint16_t scores[SERVER_MAX_ALTS] = { 0 };
	if ( size > numAltServers ) size = numAltServers;
	mutex_lock( &altServersLock );
	for ( i = 0; i < numAltServers; ++i ) {
		if ( altServers[i].host.type == 0 || altServers[i].isPrivate )
			continue; // Slot is empty or uplink is for replication only
		if ( !isImageAllowed( &altServers[i], client->image->name ) )
			continue;
		scores[i] = (uint16_t)( 10 + altservers_netCloseness( host, &altServers[i].host ) );
	}
	while ( count < size ) {
		i = -1;
		for ( j = 0; j < numAltServers; ++j ) {
			if ( scores[j] == 0 )
				continue;
			if ( i == -1 || scores[j] > scores[i] ) {
				i = j;
			}
		}
		if ( i == -1 )
			break;
		scores[i] = 0;
		output[count].host = altServers[i].host;
		output[count].failures = 0;
		count++;
	}
	mutex_unlock( &altServersLock );
	return count;
}

bool altservers_toString(int server, char *buffer, size_t len)
{
	return host_to_string( &altServers[server].host, buffer, len );
}

static bool isUsableForUplink( dnbd3_uplink_t *uplink, int server, ticks *now )
{
	dnbd3_alt_local_t *local = ( uplink == NULL ? NULL : &uplink->altData[server] );
	dnbd3_alt_server_t *global = &altServers[server];
	if ( global->isClientOnly || ( !global->isPrivate && _proxyPrivateOnly ) )
		return false;
	// Blocked locally (image not found on server...)
	if ( local != NULL && local->blocked ) {
		if ( --local->fails > 0 )
			return false;
		local->blocked = false;
	}
	if ( global->blocked ) {
		if ( timing_diff( &global->lastFail, now ) < SERVER_GLOBAL_DUP_TIME )
			return false;
		global->lastFail = *now;
		if ( --global->fails > 0 )
			return false;
		global->blocked = false;
	}
	// Not blocked, depend on both fail counters
	int fails = ( local == NULL ? 0 : local->fails ) + global->fails;
	return fails < SERVER_BAD_UPLINK_MIN || ( rand() % fails ) < SERVER_BAD_UPLINK_MIN;
}

int altservers_getHostListForReplication(const char *image, dnbd3_host_t *servers, int size)
{
	int idx[size];
	int num = altservers_getListForUplink( NULL, image, idx, size, -1 );
	for ( int i = 0; i < num; ++i ) {
		servers[i] = altServers[idx[i]].host;
	}
	return num;
}

/**
 * Returns true if there is at least one alt-server the
 * given image name would be allowed to be cloned from.
 */
bool altservers_imageHasAltServers(const char *image)
{
	bool ret = false;
	mutex_lock( &altServersLock );
	for ( int i = 0; i < numAltServers; ++i ) {
		if ( altServers[i].isClientOnly || ( !altServers[i].isPrivate && _proxyPrivateOnly ) )
			continue;
		if ( !isImageAllowed( &altServers[i], image ) )
			continue;
		ret = true;
		break;
	}
	mutex_unlock( &altServersLock );
	return ret;
}

/**
 * Get <size> alt servers. If there are more alt servers than
 * requested, random servers will be picked.
 * This function is suited for finding uplink servers as
 * it includes private servers and ignores any "client only" servers
 * @param current index of server for current connection, or -1 in panic mode
 */
static int altservers_getListForUplink(dnbd3_uplink_t *uplink, const char *image, int *servers, int size, int current)
{
	if ( size <= 0 )
		return 0;
	int count = 0;
	declare_now;
	mutex_lock( &altServersLock );
	// If we don't have enough servers to randomize, take a shortcut
	if ( numAltServers <= size ) {
		for ( int i = 0; i < numAltServers; ++i ) {
			if ( current == -1 || i == current || isUsableForUplink( uplink, i, &now ) ) {
				if ( isImageAllowed( &altServers[i], image ) ) {
					servers[count++] = i;
				}
			}
		}
	} else {
		// Plenty of alt servers; randomize
		uint8_t state[SERVER_MAX_ALTS] = { 0 };
		if ( current != -1 ) { // Make sure we also test the current server
			servers[count++] = current;
			state[current] = 2;
		}
		for ( int tr = size * 10; tr > 0 && count < size; --tr ) {
			int idx = rand() % numAltServers;
			if ( state[idx] != 0 )
				continue;
			if ( !isImageAllowed( &altServers[idx], image ) ) {
				state[idx] = 2; // Mark as used without adding, so it will be ignored in panic loop
			} else if ( isUsableForUplink( uplink, idx, &now ) ) {
				servers[count++] = idx;
				state[idx] = 2; // Used
			} else {
				state[idx] = 1; // Potential
			}
		}
		// If panic mode, consider others too
		for ( int tr = size * 10; current == -1 && tr > 0 && count < size; --tr ) {
			int idx = rand() % numAltServers;
			if ( state[idx] == 2 )
				continue;
			servers[count++] = idx;
			state[idx] = 2; // Used
		}
	}
	mutex_unlock( &altServersLock );
	return count;
}

json_t* altservers_toJson()
{
	json_t *list = json_array();

	mutex_lock( &altServersLock );
	char host[100];
	const int count = numAltServers;
	dnbd3_alt_server_t src[count];
	memcpy( src, altServers, sizeof(src) );
	mutex_unlock( &altServersLock );
	for (int i = 0; i < count; ++i) {
		json_t *rtts = json_array();
		for (int j = 0; j < SERVER_RTT_PROBES; ++j) {
			json_array_append_new( rtts, json_integer( src[i].rtt[ (j + src[i].rttIndex + 1) % SERVER_RTT_PROBES ] ) );
		}
		sock_printHost( &src[i].host, host, sizeof(host) );
		json_t *server = json_pack( "{ss,ss,so,sb,sb,si}",
			"comment", src[i].comment,
			"host", host,
			"rtt", rtts,
			"isPrivate", (int)src[i].isPrivate,
			"isClientOnly", (int)src[i].isClientOnly,
			"numFails", src[i].fails
		);
		json_array_append_new( list, server );
	}
	return list;
}

/**
 * Update rtt history of given server - returns the new average for that server.
 */
static uint32_t altservers_updateRtt(dnbd3_uplink_t *uplink, int index, uint32_t rtt)
{
	uint32_t avg = 0, j;
	dnbd3_alt_local_t *local = &uplink->altData[index];
	mutex_lock( &altServersLock );
	if ( likely( local->initDone ) ) {
		local->rtt[++local->rttIndex % SERVER_RTT_PROBES] = rtt;
		for ( j = 0; j < SERVER_RTT_PROBES; ++j ) {
			avg += local->rtt[j];
		}
		avg /= SERVER_RTT_PROBES;
	} else { // First rtt measurement -- copy to every slot
		for ( j = 0; j < SERVER_RTT_PROBES; ++j ) {
			local->rtt[j] = rtt;
		}
		avg = rtt;
		local->initDone = true;
	}
	altServers[index].rtt[++altServers[index].rttIndex % SERVER_RTT_PROBES] = avg;
	mutex_unlock( &altServersLock );
	return avg;
}

/**
 * Determine how close two addresses are to each other by comparing the number of
 * matching bits from the left of the address. Does not count individual bits but
 * groups of 4 for speed.
 * Return: Closeness - higher number means closer
 */
int altservers_netCloseness(dnbd3_host_t *host1, dnbd3_host_t *host2)
{
	if ( host1 == NULL || host2 == NULL || host1->type != host2->type ) return -1;
	int retval = 0;
	const int max = host1->type == HOST_IP4 ? 4 : 16;
	for (int i = 0; i < max; ++i) {
		if ( (host1->addr[i] & 0xf0) != (host2->addr[i] & 0xf0) ) return retval;
		++retval;
		if ( (host1->addr[i] & 0x0f) != (host2->addr[i] & 0x0f) ) return retval;
		++retval;
	}
	return retval;
}

/**
 * Called if an uplink server failed during normal uplink operation. This unit keeps
 * track of how often servers fail, and consider them disabled for some time if they
 * fail too many times.
 */
void altservers_serverFailed(int server)
{
	declare_now;
	mutex_lock( &altServersLock );
	if ( timing_diff( &altServers[server].lastFail, &now ) > SERVER_GLOBAL_DUP_TIME ) {
		altServers[server].lastFail = now;
		if ( altServers[server].fails++ >= SERVER_BAD_UPLINK_MAX ) {
			altServers[server].blocked = true;
		}
	}
	mutex_unlock( &altServersLock );
}

/**
 * Called from RTT checker if connecting to a server succeeded but
 * subsequently selecting the given image failed. Handle this within
 * the uplink and don't increase the global fail counter.
 */
static void altservers_imageFailed(dnbd3_uplink_t *uplink, int server)
{
	mutex_lock( &altServersLock );
	if ( uplink->altData[server].fails++ >= SERVER_BAD_UPLINK_MAX ) {
		uplink->altData[server].blocked = true;
	}
	mutex_unlock( &altServersLock );
}

static void *altservers_runCheck(void *data)
{
	dnbd3_uplink_t * const uplink = (dnbd3_uplink_t*)data;

	assert( uplink != NULL );
	setThreadName( "altserver-check" );
	altservers_findUplinkInternal( uplink );
	ref_put( &uplink->reference ); // Acquired in findUplinkAsync
	return NULL;
}

void altservers_findUplink(dnbd3_uplink_t *uplink)
{
	altservers_findUplinkInternal( uplink );
	// Above function is sync, which means normally when it
	// returns, rttTestResult will not be RTT_INPROGRESS.
	// But we might have an ansync call running in parallel, which would
	// mean the above call returns immediately. Wait for that check
	// to finish too.
	while ( uplink->rttTestResult == RTT_INPROGRESS ) {
		usleep( 5000 );
	}
}

int altservers_hostToIndex(dnbd3_host_t *host)
{
	for ( int i = 0; i < numAltServers; ++i ) {
		if ( isSameAddressPort( host, &altServers[i].host ) )
			return i;
	}
	return -1;
}

const dnbd3_host_t* altservers_indexToHost(int server)
{
	return &altServers[server].host;
}

// XXX Sync call above must block until async worker has finished XXX
static void altservers_findUplinkInternal(dnbd3_uplink_t *uplink)
{
	const int ALTS = 4;
	int itAlt, numAlts, current;
	bool panic;
	int servers[ALTS + 1];
	struct timespec start, end;

	if ( _shutdown )
		return;
	mutex_lock( &uplink->rttLock );
	// Maybe we already have a result, or check is currently running
	if ( uplink->better.fd != -1 || uplink->rttTestResult == RTT_INPROGRESS ) {
		mutex_unlock( &uplink->rttLock );
		return;
	}
	assert( uplink->rttTestResult != RTT_DOCHANGE );
	uplink->rttTestResult = RTT_INPROGRESS;
	panic = ( uplink->current.fd == -1 );
	current = uplink->current.index; // Current server index (or last one in panic mode)
	mutex_unlock( &uplink->rttLock );
	// First, get 4 alt servers
	numAlts = altservers_getListForUplink( uplink, uplink->image->name, servers, ALTS, panic ? -1 : current );
	// If we're already connected and only got one server anyways, there isn't much to do
	if ( numAlts == 0 || ( numAlts == 1 && !panic ) ) {
		uplink->rttTestResult = RTT_DONTCHANGE;
		return;
	}
	dnbd3_image_t * const image = image_lock( uplink->image );
	if ( image == NULL ) { // Check again after locking
		uplink->rttTestResult = RTT_NOT_REACHABLE;
		logadd( LOG_WARNING, "Image has gone away that was queued for RTT measurement" );
		return;
	}
	logadd( LOG_DEBUG2, "Running alt check for %s:%d", PIMG(image) );
	assert( uplink->rttTestResult == RTT_INPROGRESS );
	// Test them all
	dnbd3_server_connection_t best = { .fd = -1 };
	unsigned long bestRtt = RTT_UNREACHABLE;
	unsigned long currentRtt = RTT_UNREACHABLE;
	uint64_t offset = 0;
	uint32_t length = DNBD3_BLOCK_SIZE;
	// Try to use the range of the first request in the queue as RTT block.
	// In case we have a cluster of servers where none of them has a complete
	// copy, we at least make sure the one we're potentially switching to
	// has the next block we're about to request.
	mutex_lock( &uplink->queueLock );
	if ( uplink->queue != NULL ) {
		offset = uplink->queue->from;
		length = (uint32_t)( uplink->queue->to - offset );
	}
	mutex_unlock( &uplink->queueLock );
	for (itAlt = 0; itAlt < numAlts; ++itAlt) {
		int server = servers[itAlt];
		// Connect
		clock_gettime( BEST_CLOCK_SOURCE, &start );
		int sock = sock_connect( &altServers[server].host, 750, 1000 );
		if ( sock == -1 ) { // Connection failed means global error
			altservers_serverFailed( server );
			continue;
		}
		// Select image ++++++++++++++++++++++++++++++
		if ( !dnbd3_select_image( sock, image->name, image->rid, SI_SERVER_FLAGS ) ) {
			goto image_failed;
		}
		// See if selecting the image succeeded ++++++++++++++++++++++++++++++
		uint16_t protocolVersion, rid;
		uint64_t imageSize;
		char *name;
		serialized_buffer_t serialized;
		if ( !dnbd3_select_image_reply( &serialized, sock, &protocolVersion, &name, &rid, &imageSize ) ) {
			goto image_failed;
		}
		if ( protocolVersion < MIN_SUPPORTED_SERVER ) { // Server version unsupported; global fail
			goto server_failed;
		}
		if ( name == NULL || strcmp( name, image->name ) != 0 ) {
			ERROR_GOTO( image_failed, "[RTT] Server offers image '%s' instead of '%s'", name, image->name );
		}
		if ( rid != image->rid ) {
			ERROR_GOTO( image_failed, "[RTT] Server provides rid %d instead of %d", (int)rid, (int)image->rid );
		}
		if ( imageSize != image->virtualFilesize ) {
			ERROR_GOTO( image_failed, "[RTT] Remote size: %" PRIu64 ", expected: %" PRIu64, imageSize, image->virtualFilesize );
		}
		// Request block (NOT random! First or from queue) ++++++++++++
		if ( !dnbd3_get_block( sock, offset, length, 0, COND_HOPCOUNT( protocolVersion, 1 ) ) ) {
			LOG_GOTO( image_failed, LOG_DEBUG1, "[RTT%d] Could not request block", server );
		}
		// See if requesting the block succeeded ++++++++++++++++++++++
		dnbd3_reply_t reply;
		if ( !dnbd3_get_reply( sock, &reply ) ) {
			LOG_GOTO( image_failed, LOG_DEBUG1, "[RTT%d] Received corrupted reply header after CMD_GET_BLOCK", server );
		}
		// check reply header
		if ( reply.cmd != CMD_GET_BLOCK || reply.size != length ) {
			// Sanity check failed; count this as global error (malicious/broken server)
			ERROR_GOTO( server_failed, "[RTT] Reply to first block request is %" PRIu32 " bytes", reply.size );
		}
		// flush payload to include this into measurement
		char buffer[DNBD3_BLOCK_SIZE];
		uint32_t todo = length;
		ssize_t ret;
		while ( todo != 0 && ( ret = recv( sock, buffer, MIN( DNBD3_BLOCK_SIZE, todo ), MSG_WAITALL ) ) > 0 ) {
			todo -= (uint32_t)ret;
		}
		if ( todo != 0 ) {
			ERROR_GOTO( image_failed, "[RTT%d] Could not read first block payload", server );
		}
		clock_gettime( BEST_CLOCK_SOURCE, &end );
		// Measurement done - everything fine so far
		mutex_lock( &uplink->rttLock );
		const bool isCurrent = ( uplink->current.index == server );
		mutex_unlock( &uplink->rttLock );
		uint32_t rtt = (uint32_t)((end.tv_sec - start.tv_sec) * 1000000
				+ (end.tv_nsec - start.tv_nsec) / 1000); // µs
		uint32_t avg = altservers_updateRtt( uplink, server, rtt );
		// If a cycle was detected, or we lost connection to the current (last) server, penaltize it one time
		if ( ( uplink->cycleDetected || panic ) && isCurrent ) {
			avg = (avg * 2) + 50000;
		}
		if ( !panic && isCurrent ) {
			// Was measuring current server
			currentRtt = avg;
			close( sock );
		} else if ( avg < bestRtt ) {
			// Was another server, update "best"
			if ( best.fd != -1 ) {
				close( best.fd );
			}
			best.fd = sock;
			bestRtt = avg;
			best.index = server;
			best.version = protocolVersion;
		} else {
			// Was too slow, ignore
			close( sock );
		}
		// We're done, call continue
		continue;
		// Jump here if anything went wrong
		// This will cleanup and continue
image_failed:
		altservers_imageFailed( uplink, server );
		goto failed;
server_failed:
		altservers_serverFailed( server );
failed:
		close( sock );
	}
	// Done testing all servers. See if we should switch
	if ( best.fd != -1 && (panic || (bestRtt < 10000000 && RTT_THRESHOLD_FACTOR(currentRtt) > bestRtt)) ) {
		// yep
		if ( currentRtt > 10000000 || panic ) {
			LOG( LOG_DEBUG1, "Change - best: %luµs, current: -", bestRtt );
		} else {
			LOG( LOG_DEBUG1, "Change - best: %luµs, current: %luµs", bestRtt, currentRtt );
		}
		sock_setTimeout( best.fd, _uplinkTimeout );
		mutex_lock( &uplink->rttLock );
		uplink->better = best;
		uplink->rttTestResult = RTT_DOCHANGE;
		mutex_unlock( &uplink->rttLock );
		signal_call( uplink->signal );
	} else if ( best.fd == -1 && currentRtt == RTT_UNREACHABLE ) {
		// No server was reachable, including current
		uplink->rttTestResult = RTT_NOT_REACHABLE;
	} else {
		// nope
		if ( best.fd != -1 ) {
			close( best.fd );
		}
		uplink->cycleDetected = false; // It's a lie, but prevents rtt measurement triggering again right away
		mutex_lock( &uplink->rttLock );
		uplink->rttTestResult = RTT_DONTCHANGE;
		mutex_unlock( &uplink->rttLock );
	}
	image_release( image );
}

