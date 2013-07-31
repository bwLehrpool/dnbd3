#ifndef _UPLINK_H_
#define _UPLINK_H_

#include "../types.h"
#include "globals.h"


int uplink_init(dnbd3_image_t *image);

int uplink_request(dnbd3_client_t *client, uint64_t handle, uint64_t start, uint32_t length);

void uplink_shutdown(dnbd3_image_t *image);

#endif /* UPLINK_H_ */
