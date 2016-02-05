#include "signal.h"

#if defined(linux) || defined(__linux) || defined(__linux__)
#warning "Using eventfd based signalling"
#include "signal.inc/eventfd.c"
#elif __SIZEOF_INT__ == 4 && __SIZEOF_POINTER__ == 8
#warning "Using pointer-packing pipe based signalling"
#include "signal.inc/pipe64.c"
#else
#warning "Using fallback pipe based signalling"
#include "signal.inc/pipe_malloc.c"
#endif

