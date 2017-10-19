#include "timing.h"
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct timespec basetime;

void timing_abort()
{
	printf( "Cannot get CLOCK_MONOTONIC(_RAW), errno=%d\n", errno );
	exit( 1 );
}

void timing_setBase()
{
	if ( clock_gettime( BEST_CLOCK_SOURCE, &basetime ) == -1 ) {
		memset( &basetime, 0, sizeof(basetime) );
	}
}

