#ifndef _FILEUTIL_H_
#define _FILEUTIL_H_

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

bool file_isReadable(char *file);
bool file_isWritable(char *file);
bool mkdir_p(const char* path);
bool file_alloc(int fd, uint64_t offset, uint64_t size);
int64_t file_freeDiskSpace(const char * const path);
time_t file_lastModification(const char * const file);
int file_loadLineBased(const char * const file, int minFields, int maxFields, void (*cb)(int argc, char **argv, void *data), void *data);

#endif /* FILEUTIL_H_ */
