#ifndef _IMAGE_H_
#define _IMAGE_H_

#include "server.h"

int image_is_complete(dnbd3_image_t *image);

int image_save_cache_map(dnbd3_image_t *image);

dnbd3_image_t* image_get(char *name, uint16_t revision);

void image_release(dnbd3_image_t *image);

void image_load_all();



#endif
