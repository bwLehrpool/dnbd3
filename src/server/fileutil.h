#ifndef _FILEUTIL_H_
#define _FILEUTIL_H_

#include "../types.h"
#include <time.h>

bool file_isReadable(char *file);
bool file_isWritable(char *file);
bool mkdir_p(const char* path);
bool file_alloc(int fd, uint64_t offset, uint64_t size);
int64_t file_freeDiskSpace(const char * const path);
time_t file_lastModification(const char * const file);

#endif /* FILEUTIL_H_ */
