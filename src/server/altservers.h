#ifndef _ALTSERVERS_H_
#define _ALTSERVERS_H_

#include "globals.h"

void altserver_init();

void altserver_find_uplink(dnbd3_connection_t *uplink);

int altservers_get_matching(dnbd3_host_t *host, dnbd3_server_entry_t *output, int size);

int altservers_net_closeness(dnbd3_host_t *host1, dnbd3_host_t *host2);

#endif /* UPLINK_CONNECTOR_H_ */
