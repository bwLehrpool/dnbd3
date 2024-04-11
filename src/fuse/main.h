#ifndef _MAIN_H_
#define _MAIN_H_

#define FUSE_USE_VERSION 30
#include <fuse_lowlevel.h>
#include <stdbool.h>

extern bool useCow;
extern bool cow_merge_after_upload;
void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );
void main_shutdown(void);

#endif /* main_H_ */
