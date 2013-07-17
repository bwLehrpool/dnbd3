/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Simon Rettberg
 *
 * This file may be licensed under the terms of of the
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

#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "locks.h"

#define MAX(a,b) (a > b ? a : b)

static pthread_spinlock_t logLock;

#define LINE_LEN 500
#define LINE_COUNT 50

typedef struct
{
	uint16_t len;
	char text[LINE_LEN];
} LogLine;

// This will be used as a ring buffer
static volatile LogLine *logBuffer = NULL;
// bufferPos counts up, use modulo LINE_COUNT to get array index
static volatile int bufferPos = 0;

void initmemlog()
{
	// Use main spinlock to make sure we really init only once
	if (logBuffer) return;
	spin_init(&logLock, PTHREAD_PROCESS_PRIVATE);
	logBuffer = (LogLine *)calloc(LINE_COUNT, sizeof(LogLine));
}

void memlogf(const char *fmt, ...)
{
	if (!logBuffer) return; // Not initialized yet
	va_list ap;
	int ret;
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	spin_lock(&logLock);
	LogLine *const line = (LogLine *)&(logBuffer[bufferPos % LINE_COUNT]);
	const size_t offset = strftime(line->text, LINE_LEN, "[%d.%m. %H:%M:%S] ", timeinfo);
	if (offset == 0) *line->text = '\0';
	va_start(ap, fmt);
	ret = vsnprintf(line->text + offset, LINE_LEN - offset, fmt, ap);
	va_end(ap);
	char *end = line->text + strlen(line->text);
	while (end > line->text && *--end == '\n') *end = '\0'; // remove trailing \n
	// glibc 2.0 would return -1 if the buffer was too small
	// glibc 2.1 would return the number of bytes required if the buffer was too small
	// so to be safe either way, let strlen do the job
	line->len = strlen(line->text);
	if (ret > 0 || line->len > 0) ++bufferPos;
	spin_unlock(&logLock);
	puts(line->text);
}

char *fetchlog(int maxlines)
{
	if (!logBuffer) return NULL;
	if (maxlines <= 0 || maxlines > LINE_COUNT) maxlines = LINE_COUNT;
	const int start = MAX(0, bufferPos - maxlines);
	int len = 1, i;
	//printf("Outputting log from %d to %d\n", start, bufferPos);
	spin_lock(&logLock);
	// Determine required buffer space for all log lines
	for (i = start; i < bufferPos; ++i)
	{
		if (logBuffer[i % LINE_COUNT].len > 0)
		{
			len += logBuffer[i % LINE_COUNT].len + 1;
		}
	}
	//printf("Have to allocate %d bytes\n", len);
	// Allocate buffer. If this is a bottleneck because of malloc, consider passing a buffer to the function that the caller allocates on the stack
	char *retval = (char *)calloc(len, sizeof(char));
	if (retval == NULL) goto endFunction;
	// Concatenate all log lines, delimit using '\n'
	char *pos = retval;
	for (i = start; i < bufferPos; ++i)
	{
		LogLine *const line = (LogLine *)&(logBuffer[i % LINE_COUNT]);
		if (line->len > 0)
		{
			memcpy(pos, (char *)line->text, line->len);
			pos += line->len;
			*pos++ = '\n';
		}
	}
	*pos = '\0';
endFunction:
	spin_unlock(&logLock);
	return retval;
}
