#ifndef _IMAGE_H_
#define _IMAGE_H_

#include "../config.h"
#include "globals.h"

extern dnbd3_image_t *_images[SERVER_MAX_IMAGES];
extern int _num_images;
extern pthread_spinlock_t _images_lock;

int image_is_complete(dnbd3_image_t *image);

int image_save_cache_map(dnbd3_image_t *image);

dnbd3_image_t* image_get(char *name, uint16_t revision);

void image_release(dnbd3_image_t *image);

dnbd3_image_t* image_free(dnbd3_image_t *image);

int image_load_all(char *path);



#endif
