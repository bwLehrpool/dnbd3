#ifndef _MAIN_H_
#define _MAIN_H_

#include "../shared/fdsignal.h"
#include "../shared/timing.h"
#include <fuse_lowlevel.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


//static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino);
static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize);
static int fillStatsFile(char *buf, size_t size, off_t offset);
static void image_destroy(void *private_data);
static void image_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void image_ll_init(void *userdata, struct fuse_conn_info *conn);
static void image_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
static void image_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void image_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
static void image_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi);
static int image_stat(fuse_ino_t ino, struct stat *stbuf);
static void printUsage(char *argv0, int exitCode);
static void printVersion();
int main(int argc, char *argv[]);

#endif /* MAIN_H_ */
