#include <dnbd3/shared/fdsignal.h>

#if defined(__linux__)
//#warning "Using eventfd based signalling"
#include "fdsignal.inc/eventfd.c"
#elif __SIZEOF_INT__ == 4 && __SIZEOF_POINTER__ == 8
//#warning "Using pointer-packing pipe based signalling"
#include "fdsignal.inc/pipe64.c"
#else
_Static_assert( sizeof(int) != 4 || sizeof(void*) != 8, "Something's goofy, fix preprocessor check above!" );
//#warning "Using fallback pipe based signalling"
#include "fdsignal.inc/pipe_malloc.c"
#endif

