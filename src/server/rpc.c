#include "rpc.h"
#include "server.h"
#include "net.h"
#include "uplink.h"
#include "log.h"
#include "locks.h"
#include "sockhelper.h"
#include "helper.h"
#include "image.h"

#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include <inttypes.h>

static void clientsToJson(json_t *jsonClients);

void rpc_sendStatsJson(int sock)
{
	const uint64_t receivedBytes = uplink_getTotalBytesReceived();
	const uint64_t sentBytes = net_getTotalBytesSent();
	const int uptime = dnbd3_serverUptime();
	json_t *jsonClients = json_array();

	clientsToJson( jsonClients );

	json_t *statisticsJson = json_pack( "{sIsI}", "receivedBytes", (json_int_t) receivedBytes, "sentBytes", (json_int_t) sentBytes );
	json_object_set_new( statisticsJson, "clients", jsonClients );
	json_object_set_new( statisticsJson, "images", image_fillJson() );
	json_object_set_new( statisticsJson, "uptime", json_integer( uptime ) );
	char *jsonString = json_dumps( statisticsJson, 0 );

	char buffer[500];
	snprintf(buffer, sizeof buffer , "HTTP/1.1 200 OK\r\nConnection: Close\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n",
			(int) strlen( jsonString ) );
	write( sock, buffer, strlen( buffer ) );
	sock_sendAll( sock, jsonString, strlen( jsonString ), 10 );
	json_decref( statisticsJson );
	// Wait for flush
	shutdown( sock, SHUT_WR );
	while ( read( sock, buffer, sizeof buffer ) > 0 );
	free( jsonString );
}

static void clientsToJson(json_t *jsonClients)
{
	json_t *clientStats;
	int i;
	char clientName[100];
	const char *imageName;
	spin_lock( &_clients_lock );
	for (i = 0; i < _num_clients; ++i) {
		if ( _clients[i] == NULL ) continue;
		spin_lock( &_clients[i]->lock );
		host_to_string( &_clients[i]->host, clientName, sizeof(clientName) );
		imageName =_clients[i]->image != NULL ? _clients[i]->image->lower_name : "NULL";
		clientStats = json_pack( "{sssssI}", "client", clientName, "image", imageName , "bytesSent", (json_int_t)_clients[i]->bytesSent );
		json_array_append_new( jsonClients, clientStats );
		spin_unlock( &_clients[i]->lock );
	}
	spin_unlock( &_clients_lock );
}
