#include <unistd.h>
#include <jansson.h>

#include "rpc.h"

void rpc_sendStatsJson(int sock)
{
	int receivedBytes = 0;
	int sentBytes = 1;
	json_t *statisticsJson = json_pack( "{sisi}", "receivedBytes", receivedBytes, "sentBytes", sentBytes );
	char* jsonString = json_dumps(statisticsJson, 0);
	char bla[500];
	snprintf(bla, sizeof bla, "HTTP/1.1 200 OK\r\nConnection: Close\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n", (int)strlen(jsonString));
	write( sock, bla, strlen(bla) );
	int n = write( sock, jsonString, strlen(jsonString));
	json_decref(statisticsJson);
	free(jsonString);
}
