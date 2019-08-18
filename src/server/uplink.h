#ifndef _UPLINK_H_
#define _UPLINK_H_

#include "globals.h"
#include "../types.h"

void uplink_globalsInit();

uint64_t uplink_getTotalBytesReceived();

bool uplink_init(dnbd3_image_t *image, int sock, dnbd3_host_t *host, int version);

void uplink_removeClient(dnbd3_uplink_t *uplink, dnbd3_client_t *client);

bool uplink_request(dnbd3_client_t *client, uint64_t handle, uint64_t start, uint32_t length, uint8_t hopCount);

void uplink_shutdown(dnbd3_image_t *image);

#endif /* UPLINK_H_ */
