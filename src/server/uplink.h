#ifndef _UPLINK_H_
#define _UPLINK_H_

#include "globals.h"
#include "../types.h"

void uplink_globalsInit();

uint64_t uplink_getTotalBytesReceived();

bool uplink_init(dnbd3_image_t *image, int sock, dnbd3_host_t *host, int version);

void uplink_removeEntry(dnbd3_uplink_t *uplink, void *data, uplink_callback callback);

bool uplink_requestClient(dnbd3_client_t *client, uplink_callback callback, uint64_t handle, uint64_t start, uint32_t length, uint8_t hops);

bool uplink_request(dnbd3_image_t *image, void *data, uplink_callback callback, uint64_t handle, uint64_t start, uint32_t length);

bool uplink_shutdown(dnbd3_image_t *image);

bool uplink_getHostString(dnbd3_uplink_t *uplink, char *buffer, size_t len);

#endif /* UPLINK_H_ */
