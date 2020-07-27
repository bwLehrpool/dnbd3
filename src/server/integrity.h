#ifndef _INTEGRITY_H_
#define _INTEGRITY_H_

#include "globals.h"

void integrity_init();

void integrity_shutdown();

void integrity_check(dnbd3_image_t *image, int block, bool blocking);

#endif /* INTEGRITY_H_ */
