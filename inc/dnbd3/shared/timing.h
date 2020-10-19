#ifndef _D_TIMING_H
#define _D_TIMING_H

#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef CLOCK_MONOTONIC_RAW
#define BEST_CLOCK_SOURCE CLOCK_MONOTONIC_RAW
#else
#define BEST_CLOCK_SOURCE CLOCK_MONOTONIC
#endif

typedef struct timespec ticks;

extern struct timespec basetime;

/**
 * Assign src to dst while adding secs seconds.
 */
#define timing_set(dst,src,secs) do { (dst)->tv_sec = (src)->tv_sec + (secs); (dst)->tv_nsec = (src)->tv_nsec; } while (0)

/**
 * Define variable now, initialize to timing_get.
 */
#define declare_now ticks now; timing_get( &now )

/**
 * Call this once to calibrate on startup.
 * Although overflows of CLOCK_MONOTONIC(_RAW) should
 * by definition never happen, we still have a fixed size
 * int that could at some point. By forcing the counter
 * to start at 0 on startup the point of overflow
 * will be very far in the future (decades for 32bit time_t,
 * end of universe for 64bit).
 */
void timing_setBase();

/**
 * Internal, do not use. Moved to another function
 * to prevent inlining of error handling code, which
 * should be very unlikely to ever trigger.
 */
_Noreturn void timing_abort();

/**
 * Get current time. Shortcut for clock_gettime with error check.
 */
static inline void timing_get(ticks* retval)
{
	if ( clock_gettime( BEST_CLOCK_SOURCE, retval ) == -1 ) timing_abort();
	retval->tv_sec -= basetime.tv_sec;
}

/**
 * Get a ticks instance somewhere in the future.
 * Useful for timeouts.
 */
static inline void timing_gets(ticks* retval, int32_t addSeconds)
{
	timing_get( retval );
	retval->tv_sec += addSeconds;
}

static inline void timing_addSeconds(ticks* retval, ticks* base, int32_t addSeconds)
{
	retval->tv_sec = base->tv_sec + addSeconds;
	retval->tv_nsec = base->tv_nsec;
}

/**
 * Check whether given timeout is reached.
 * Might trigger up to one second early.
 */
static inline bool timing_reached(const ticks* timeout, const ticks* now)
{
	return now->tv_sec >= timeout->tv_sec;
}
#define timing_1le2(one,two) timing_reached(one,two)

/**
 * Precise check whether given timeout has been reached.
 */
static inline bool timing_reachedPrecise(const ticks* timeout, const ticks* now)
{
	return now->tv_sec > timeout->tv_sec
			|| (now->tv_sec == timeout->tv_sec && now->tv_nsec > timeout->tv_nsec);
}

/**
 * Shortcut for above. Useful if not used in loop.
 * Might trigger up to one second early.
 */
static inline bool timing_isReached(const ticks* timeout)
{
	ticks now;
	timing_get( &now );
	return timing_reached( timeout, &now );
}
/**
 * Shortcut for above. Useful if not used in loop.
 */
static inline bool timing_isReachedPrecise(const ticks* timeout)
{
	ticks now;
	timing_get( &now );
	return timing_reachedPrecise( timeout, &now );
}


/**
 * Get difference between two ticks, rounded down to seconds.
 * Make sure you pass the arguments in the proper order. If
 * end is before start, 0 will always be returned.
 */
static inline uint32_t timing_diff(const ticks *start, const ticks *end)
{
	if ( end->tv_sec <= start->tv_sec ) return 0;
	return (uint32_t)( ( end->tv_sec - start->tv_sec )
			+ ( start->tv_nsec > end->tv_nsec ? -1 : 0 ) );
}

/**
 * Get difference between two ticks, rounded down to milliseconds.
 * Same as above; passing arguments in reverse will always return 0.
 */
static inline uint64_t timing_diffMs(const ticks *start, const ticks *end)
{
	if ( end->tv_sec < start->tv_sec ) return 0;
	uint64_t diff = (uint64_t)( end->tv_sec - start->tv_sec ) * 1000;
	if ( start->tv_nsec >= end->tv_nsec ) {
		if ( diff == 0 ) return 0;
		diff -= (start->tv_nsec - end->tv_nsec) / 1000000;
	} else {
		diff += (end->tv_nsec - start->tv_nsec) / 1000000;
	}
	return diff;
}

/**
 * Get difference between two ticks, rounded down to microseconds.
 * Same as above; passing arguments in reverse will always return 0.
 */
static inline uint64_t timing_diffUs(const ticks *start, const ticks *end)
{
	if ( end->tv_sec < start->tv_sec ) return 0;
	uint64_t diff = (uint64_t)( end->tv_sec - start->tv_sec ) * 1000000;
	if ( start->tv_nsec >= end->tv_nsec ) {
		if ( diff == 0 ) return 0;
		diff -= ( start->tv_nsec - end->tv_nsec ) / 1000;
	} else {
		diff += ( end->tv_nsec - start->tv_nsec ) / 1000;
	}
	return diff;
}


#endif
