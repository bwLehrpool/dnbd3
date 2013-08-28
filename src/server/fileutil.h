#ifndef _FILEUTIL_H_
#define _FILEUTIL_H_

#include "../types.h"
#include <time.h>

int file_isReadable(char *file);
int file_isWritable(char *file);
int mkdir_p(const char* path);
int file_alloc(int fd, uint64_t offset, uint64_t size);
uint64_t file_freeDiskSpace(const char * const path);
time_t file_lastModification(const char * const file);

#endif /* FILEUTIL_H_ */
