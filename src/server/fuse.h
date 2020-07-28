#ifndef _FUSE_H_
#define _FUSE_H_

#include <stdbool.h>

bool dfuse_init(const char *opts, const char *dir);

void dfuse_shutdown();

#endif
