#ifndef _IMAGE_H_
#define _IMAGE_H_

#include "../config.h"
#include "globals.h"

extern dnbd3_image_t *_images[SERVER_MAX_IMAGES];
extern int _num_images;
extern pthread_spinlock_t _images_lock;

int image_is_complete(dnbd3_image_t *image);

void image_update_cachemap( dnbd3_image_t *image, uint64_t start, uint64_t end, const int set );

int image_save_cache_map(dnbd3_image_t *image);

dnbd3_image_t* image_get(char *name, uint16_t revision);

void image_release(dnbd3_image_t *image);

dnbd3_image_t* image_free(dnbd3_image_t *image);

int image_load_all(char *path);


int image_generate_crc_file(char *image);

// one byte in the map covers 8 4kib blocks, so 32kib per byte
// "+ (1 << 15) - 1" is required to account for the last bit of
// the image that is smaller than 32kib
// this would be the case whenever the image file size is not a
// multiple of 32kib (= the number of blocks is not divisible by 8)
// ie: if the image is 49152 bytes and you do 49152 >> 15 you get 1,
// but you actually need 2 bytes to have a complete cache map
#define IMGSIZE_TO_MAPBYTES(bytes) ((int)(((bytes) + (1 << 15) - 1) >> 15))

// calculate number of hash blocks in file. One hash block is 16MiB
#define HASH_BLOCK_SIZE ((int64_t)(1 << 24))
#define IMGSIZE_TO_HASHBLOCKS(bytes) ((int)(((bytes) + HASH_BLOCK_SIZE - 1) / HASH_BLOCK_SIZE))

#endif
