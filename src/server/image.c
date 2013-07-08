#include "image.h"

#include <glib/gmacros.h>
#include <assert.h>

int image_is_complete(dnbd3_image_t *image)
{
	assert(image != NULL);
	if (image->working && image->cache_map == NULL) {
		return TRUE;
	}
	if (image->filesize == 0 || !image->working) {
		return FALSE;
	}
   int complete = TRUE, j;
   const int map_len_bytes = IMGSIZE_TO_MAPBYTES(image->filesize);
   for (j = 0; j < map_len_bytes - 1; ++j)
   {
           if (image->cache_map[j] != 0xFF)
           {
                   complete = FALSE;
                   break;
           }
   }
   if (complete) // Every block except the last one is complete
   { // Last one might need extra treatment if it's not a full byte
           const int blocks_in_last_byte = (image->filesize >> 12) & 7;
           uint8_t last_byte = 0;
           if (blocks_in_last_byte == 0) {
                   last_byte = 0xFF;
           } else {
                   for (j = 0; j < blocks_in_last_byte; ++j)
                           last_byte |= (1 << j);
           }
           complete = ((image->cache_map[map_len_bytes - 1] & last_byte) == last_byte);
   }
   return complete;
}
