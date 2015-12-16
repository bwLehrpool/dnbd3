#include "rpc.h"
#include "server.h"
#include "net.h"
#include "uplink.h"
#include "../shared/log.h"
#include "locks.h"
#include "../shared/sockhelper.h"
#include "helper.h"
#include "image.h"

#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include <inttypes.h>

static void clientsToJson(json_t *jsonClients);

void rpc_sendStatsJson(int sock)
{
	json_t *jsonClients = json_array();
	clientsToJson( jsonClients );
	const uint64_t bytesReceived = uplink_getTotalBytesReceived();
	const uint64_t bytesSent = net_getTotalBytesSent();
	const int uptime = dnbd3_serverUptime();

	json_t *statisticsJson = json_pack( "{sIsI}",
			"bytesReceived", (json_int_t) bytesReceived,
			"bytesSent", (json_int_t) bytesSent );
	json_object_set_new( statisticsJson, "clients", jsonClients );
	json_object_set_new( statisticsJson, "images", image_getListAsJson() );
	json_object_set_new( statisticsJson, "uptime", json_integer( uptime ) );
	char *jsonString = json_dumps( statisticsJson, 0 );
	json_decref( statisticsJson );

	char buffer[500];
	snprintf(buffer, sizeof buffer , "HTTP/1.1 200 OK\r\n"
			"Connection: Close\r\n"
			"Content-Length: %d\r\n"
			"Content-Type: application/json\r\n"
			"\r\n",
			(int) strlen( jsonString ) );
	write( sock, buffer, strlen( buffer ) );
	sock_sendAll( sock, jsonString, strlen( jsonString ), 10 );
	// Wait for flush
	shutdown( sock, SHUT_WR );
	while ( read( sock, buffer, sizeof buffer ) > 0 );
	free( jsonString );
}

static void clientsToJson(json_t *jsonClients)
{
	json_t *clientStats;
	int i;
	int imgId;
	uint64_t bytesSent;
	char host[HOSTNAMELEN];
	host[HOSTNAMELEN-1] = '\0';

	spin_lock( &_clients_lock );
	for ( i = 0; i < _num_clients; ++i ) {
		if ( _clients[i] == NULL ) {
			continue;
		}
		// Do not lock on client.lock here:
		// 1) .image can only be set once, will never change (just like .image.id)
		// 2) .hostName never changes as well
		// 3) .bytesSent and .tmpBytesSent are guarded by .statsLock
		// 4) the client cannot be freed, as it's still in the list and we hold the list's lock
		if ( _clients[i]->image == NULL ) {
			imgId = -1;
		} else {
			strncpy( host, _clients[i]->hostName, HOSTNAMELEN - 1 );
			imgId = _clients[i]->image->id;
			spin_lock( &_clients[i]->statsLock );
			bytesSent = _clients[i]->bytesSent;
			net_updateGlobalSentStatsFromClient( _clients[i] ); // Do this since we read the totalBytesSent counter later
			spin_unlock( &_clients[i]->statsLock );
		}
		spin_unlock( &_clients_lock );
		// Unlock so we give other threads a chance to access the client list.
		// We might not get an atomic snapshot of the currently connected clients,
		// but that doesn't really make a difference anyways.
		if ( imgId != -1 ) {
			clientStats = json_pack( "{sssisI}",
					"address", host,
					"imageId", imgId,
					"bytesSent", (json_int_t)bytesSent );
			json_array_append_new( jsonClients, clientStats );
		}
		spin_lock( &_clients_lock );
	}
	spin_unlock( &_clients_lock );
}
