#include <unistd.h>

int file_open(char *filename);

int file_getsize(int fd, off_t *size);

int file_read(int fd, void *buf, size_t size, off_t pos);
