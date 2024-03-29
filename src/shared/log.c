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

#include <dnbd3/shared/log.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define LINE_LEN (800)

static pthread_mutex_t logLock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic logmask_t maskFile = 31;
static _Atomic logmask_t maskCon  = 15;

static char *logFile = NULL;
static int logFd = -1;
static FILE *logOutStream;

static bool consoleTimestamps = false;


static int writeLevel(char *buffer, logmask_t level);


void log_init(void) {
	logOutStream = stdout;
}

bool log_hasMask(const logmask_t mask)
{
	return ( ( maskFile | maskCon ) & mask ) == mask;
}

void log_setFileMask(logmask_t mask)
{
	maskFile = mask;
}

void log_setConsoleMask(logmask_t mask)
{
	maskCon = mask;
}

void log_setConsoleTimestamps(bool on)
{
	consoleTimestamps = on;
}

int log_setConsoleOutputStream(FILE *outputStream)
{
	if ( outputStream != stdout && outputStream != stderr )
		return -EINVAL;

	logOutStream = outputStream;
	return 0;
}

bool log_openLogFile(const char *path)
{
	pthread_mutex_lock( &logLock );
	if ( logFd >= 0 ) {
		close( logFd );
	}
	if ( path == NULL && logFile == NULL )
		goto unlock;
	if ( path != NULL ) {
		free( logFile );
		logFile = strdup( path );
	}
	logFd = open( logFile, O_WRONLY | O_CREAT | O_APPEND, 0644 );
	if ( logFd < 0 )
		goto unlock;
unlock: ;
	pthread_mutex_unlock( &logLock );
	return logFd >= 0;
}

void logadd(const logmask_t mask, const char *fmt, ...)
{
	if ( ( (maskFile | maskCon) & mask ) == 0 )
		return;
	va_list ap;
	int ret;
	time_t rawtime;
	struct tm timeinfo;
	char buffer[LINE_LEN];
	bool toFile = maskFile & mask;
	bool toOutStream = maskCon & mask;
	size_t offset;

	if ( toFile || ( toOutStream && consoleTimestamps ) ) {
		time( &rawtime );
		localtime_r( &rawtime, &timeinfo );
		offset = strftime( buffer, LINE_LEN, "[%d.%m. %H:%M:%S] ", &timeinfo );
	} else {
		offset = 0;
	}
	const char *stdoutLine = buffer + offset;
	offset += writeLevel( buffer + offset, mask );
	va_start( ap, fmt );
	ret = vsnprintf( buffer + offset, LINE_LEN - offset, fmt, ap );
	va_end( ap );
	if ( ret < 0 ) return;
	offset += ret;
	if ( offset + 1 >= LINE_LEN ) {
		buffer[LINE_LEN-2] = '\0';
		offset = LINE_LEN - 2;
	}
	if ( buffer[offset-1] != '\n' ) {
		buffer[offset++] = '\n';
		buffer[offset] = '\0';
	}
	if ( toFile ) {
		pthread_mutex_lock( &logLock );
		if ( logFd >= 0 ) {
			size_t done = 0;
			while (done < offset ) {
				const ssize_t wr = write( logFd, buffer + done, offset - done );
				if ( wr < 0 ) {
					if ( errno == EINTR ) continue;
					printf( "Logging to file failed! (errno=%d)\n", errno );
					break;
				}
				done += (size_t)wr;
			}
		}
		pthread_mutex_unlock( &logLock );
	}
	if ( toOutStream ) {
		if ( consoleTimestamps )
			stdoutLine = buffer;
		fputs( stdoutLine, logOutStream );
		fflush( logOutStream );
	}
}

ssize_t log_fetch(char *buffer, int size)
{
	if ( logFile == NULL || size <= 1 )
		return -1;
	int fd = open( logFile, O_RDONLY );
	if ( fd < 0 )
		return -1;
	off_t off = lseek( fd, 0, SEEK_END );
	if ( off == (off_t)-1 ) {
		close( fd );
		return -1;
	}
	if ( (off_t)size <= off ) {
		off -= size;
	} else {
		off = 0;
	}
	ssize_t ret = pread( fd, buffer, size - 1, off );
	close( fd );
	buffer[ret] = '\0';
	return ret;
}

static int writeLevel(char *buffer, logmask_t level)
{
	const char *word;
	char *dest = buffer;
	switch ( level ) {
	case LOG_ERROR:
		word = "ERROR";
		break;
	case LOG_WARNING:
		word = "WARNING";
		break;
	case LOG_MINOR:
		word = "Warning";
		break;
	case LOG_INFO:
		word = "Info";
		break;
	case LOG_DEBUG1:
		word = "DEBUG1";
		break;
	case LOG_DEBUG2:
		word = "DEBUG2";
		break;
	default:
		word = "!?!?!?";
		break;
	}
	while ( ( *dest++ = *word++ ) );
	*--dest = ':';
	*++dest = ' ';
	return (int)( dest - buffer ) + 1;
}

