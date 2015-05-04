#include <unistd.h>
#include <string.h>
#include <jansson.h>

#include "rpc.h"
#include "server.h"
#include "net.h"
#include "uplink.h"
#include "log.h"
#include "locks.h"
#include "helper.h"

static void clientsToJson(json_t *jsonClients);

void rpc_sendStatsJson(int sock)
{
	uint64_t receivedBytes = uplink_getTotalBytesReceived();
	uint64_t sentBytes = net_getTotalBytesSent();

	json_t *jsonClients = json_array();
	clientsToJson( jsonClients );

	json_t *statisticsJson = json_pack( "{sisi}", "receivedBytes", (json_int_t) receivedBytes, "sentBytes", (json_int_t) sentBytes );
	json_object_set( statisticsJson, "clients", jsonClients );
	char *jsonString = json_dumps( statisticsJson, 0 );

	char buffer[500];
	snprintf(buffer, sizeof(buffer), "HTTP/1.1 200 OK\r\nConnection: Close\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n",
			(int) strlen( jsonString ) );
	write( sock, buffer, strlen( buffer ) );
	write( sock, jsonString, strlen( jsonString ) );
	json_decref( statisticsJson );
	json_decref( jsonClients );
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
		clientStats = json_pack( "{sssssi}", "client", clientName, "image", imageName , "bytesSent", (json_int_t) _clients[i]->bytesSent );
		json_array_append( jsonClients, clientStats );
		json_decref( clientStats );
		spin_unlock( &_clients[i]->lock );
	}
	spin_unlock( &_clients_lock );
}
