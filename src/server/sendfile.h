#ifndef SENDFILE_H_
#define SENDFILE_H_

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/**
 * Platform-agnostic wrapper around sendfile, with retry logic.
 * @param fd file to read from
 * @param sock socket to write to
 * @param foffset offset in file to start reading from
 * @param bytes number of bytes to read/send
 * @return true on success
 */
bool sendfile_all(int fd, int sock, off_t foffset, size_t bytes);

#endif