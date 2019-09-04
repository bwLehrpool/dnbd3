#ifndef _ALTSERVERS_H_
#define _ALTSERVERS_H_

#include "globals.h"

struct json_t;

void altservers_init();

int altservers_load();

bool altservers_add(dnbd3_host_t *host, const char *comment, const int isPrivate, const int isClientOnly, int *index);

void altservers_findUplinkAsync(dnbd3_uplink_t *uplink);

void altservers_findUplink(dnbd3_uplink_t *uplink);

int altservers_getListForClient(dnbd3_host_t *host, dnbd3_server_entry_t *output, int size);

int altservers_getHostListForReplication(dnbd3_host_t *servers, int size);

bool altservers_toString(int server, char *buffer, size_t len);

int altservers_netCloseness(dnbd3_host_t *host1, dnbd3_host_t *host2);

void altservers_serverFailed(int server);

int altservers_hostToIndex(dnbd3_host_t *host);

const dnbd3_host_t* altservers_indexToHost(int server);

struct json_t* altservers_toJson();

#endif /* UPLINK_CONNECTOR_H_ */
