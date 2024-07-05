#ifndef _INTEGRITY_H_
#define _INTEGRITY_H_

#include "globals.h"

void integrity_init(void);

void integrity_shutdown(void);

void integrity_check(dnbd3_image_t *image, int block, bool blocking);

void integrity_trigger(void);

#endif /* INTEGRITY_H_ */
