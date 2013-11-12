#ifndef _ALTSERVERS_H_
#define _ALTSERVERS_H_

#include "globals.h"

void altservers_init();

int altservers_load();

int altservers_add(dnbd3_host_t *host, const char *comment, const int isPrivate, const int isClientOnly);

void altservers_findUplink(dnbd3_connection_t *uplink);

int altservers_getMatching(dnbd3_host_t *host, dnbd3_server_entry_t *output, int size);

int altservers_get(dnbd3_host_t *output, int size);

int altservers_netCloseness(dnbd3_host_t *host1, dnbd3_host_t *host2);

void altservers_serverFailed(const dnbd3_host_t * const host);

#endif /* UPLINK_CONNECTOR_H_ */
