/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Simon Rettberg
 *
 * This file may be licensed under the terms of the
 * GNU General Public License Version 2 (the ``GPL'').
 *
 * Software distributed under the License is distributed
 * on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied. See the GPL for the specific language
 * governing rights and limitations.
 *
 * You should have received a copy of the GPL along with this
 * program. If not, go to http://www.gnu.org/licenses/gpl.html
 * or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef LOG_H_
#define LOG_H_

#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>

typedef unsigned int logmask_t;
#define LOG_ERROR    ((logmask_t)1)  // Fatal error, server will terminate
#define LOG_WARNING  ((logmask_t)2)  // Major issue, something is broken but keep running
#define LOG_MINOR    ((logmask_t)4)  // Minor issue, more of a hickup than serious problem
#define LOG_INFO     ((logmask_t)8)  // Informational message
#define LOG_DEBUG1  ((logmask_t)16)  // Debug information, use this for non-spammy stuff
#define LOG_DEBUG2  ((logmask_t)32)  // Use this for debug messages that will show up a lot

/**
 * Initialize the logging (constructor)
 */
void log_init(void);

/**
 * Check if cansoleMask | fileMask has all of mask set.
 */
bool log_hasMask(const logmask_t mask);

void log_setFileMask(logmask_t mask);

void log_setConsoleMask(logmask_t mask);

void log_setConsoleTimestamps(bool on);

/**
 * Set console output stream
 * The output stream can be either stdout or stderr
 *
 * Note: A call of this function is optional and only required if the output
 *       stream should be changed from stdout to stderr since the log
 *       implementation defaults to the output stream stdout
 */
int log_setConsoleOutputStream(FILE *outputStream);

/**
 * Open or reopen the log file. If path is NULL and the
 * function was called with a path before, the same path
 * will be used again.
 */
bool log_openLogFile(const char *path);

/**
 * Add a line to the log
 */
void logadd(const logmask_t mask, const char *text, ...)
	__attribute__ ((format (printf, 2, 3)));

/**
 * Return last size bytes of log.
 */
ssize_t log_fetch(char *buffer, int size);

#endif /* LOG_H_ */
