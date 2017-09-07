#include "rpc.h"
#include "helper.h"
#include "net.h"
#include "uplink.h"
#include "locks.h"
#include "image.h"
#include "../shared/sockhelper.h"

#include <jansson.h>

void rpc_sendStatsJson(int sock)
{
	// Call this first because it will update the total bytes sent counter
	json_t *jsonClients = net_clientsToJson();
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

