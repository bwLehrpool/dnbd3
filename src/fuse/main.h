#ifndef _MAIN_H_
#define _MAIN_H_

#include "cowfile.h"
#include "connection.h"
#include "helper.h"
#include <dnbd3/version.h>
#include <dnbd3/build.h>
#include <dnbd3/shared/protocol.h>
#include <dnbd3/shared/log.h>


#define FUSE_USE_VERSION 30
#include <dnbd3/config.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
/* for printing uint */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#define debugf(...) do { logadd( LOG_DEBUG1, __VA_ARGS__ ); } while (0)

#define INO_ROOT (1)
#define INO_STATS (2)
#define INO_IMAGE (3)

extern bool useCow;
extern bool cow_merge_after_upload;
void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );

#endif /* main_H_ */