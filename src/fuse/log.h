#ifndef LOG_H_
#define LOG_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

typedef unsigned int logmask_t;
#define LOG_ERROR    ((logmask_t)1)  // Fatal error, server will terminate
#define LOG_WARNING  ((logmask_t)2)  // Major issue, something is broken but keep running
#define LOG_MINOR    ((logmask_t)4)  // Minor issue, more of a hickup than serious problem
#define LOG_INFO     ((logmask_t)8)  // Informational message
#define LOG_DEBUG1  ((logmask_t)16)  // Debug information, use this for non-spammy stuff
#define LOG_DEBUG2  ((logmask_t)32)  // Use this for debug messages that will show up a lot

//void log_setFileMask(logmask_t mask);

//void log_setConsoleMask(logmask_t mask);

/**
 * Open or reopen the log file. If path is NULL and the
 * function was called with a path before, the same path
 * will be used again.
 */
//bool log_openLogFile(const char *path);

/**
 * Add a line to the log
 */
void logadd(const logmask_t mask, const char *text, ...)
{
	va_list args;
	va_start( args, text );
	vprintf( text, args );
	va_end( args );
}

/**
 * Return last size bytes of log.
 */
//bool log_fetch(char *buffer, int size);

#endif /* LOG_H_ */
