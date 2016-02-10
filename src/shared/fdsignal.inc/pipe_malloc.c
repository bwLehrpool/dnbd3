#include <poll.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

struct _dnbd3_signal {
	int read;
	int write;
};

/*
 * Generic (posix) implelentation of signals, using pipes.
 * A struct containing both fds will be malloc()ed for each
 * signal.
 */

dnbd3_signal_t* signal_new()
{
	dnbd3_signal_t *ret = signal_newBlocking();
	if ( ret == NULL ) return NULL;
	fcntl( ret->read, F_SETFL, O_NONBLOCK );
	fcntl( ret->write, F_SETFL, O_NONBLOCK );
	return ret;
}

dnbd3_signal_t* signal_newBlocking()
{
	int fds[2];
	if ( pipe( fds ) == -1 ) return NULL;
	dnbd3_signal_t* ret = malloc( sizeof(dnbd3_signal_t) );
	ret->read = fds[0];
	ret->write = fds[1];
	return ret;
}

int signal_call(const dnbd3_signal_t* const signal)
{
	if ( signal == NULL ) return SIGNAL_ERROR;
	static char one = 1;
	// Write one byte on every call, so the number of bytes read will
	// match the number of events
	return write( signal->write, &one, 1 ) > 0 ? SIGNAL_OK : SIGNAL_ERROR;
}

int signal_wait(const dnbd3_signal_t* const signal, int timeoutMs)
{
	if ( signal == NULL ) return SIGNAL_ERROR;
	struct pollfd ps = {
		.fd = signal->read,
		.events = POLLIN
	};
	int ret = poll( &ps, 1, timeoutMs );
	if ( ret == 0 ) return SIGNAL_TIMEOUT;
	if ( ret == -1 ) return SIGNAL_ERROR;
	if ( ps.revents & ( POLLERR | POLLNVAL ) ) return SIGNAL_ERROR;
	return signal_clear( signal );
}

int signal_clear(const dnbd3_signal_t* const signal)
{
	if ( signal == NULL ) return SIGNAL_ERROR;
	char throwaway[100];
	ssize_t ret, total = 0;
	do {
		ret = read( signal->read, throwaway, sizeof throwaway );
		if ( ret < 0 ) {
			if ( errno == EAGAIN ) return (int)total;
			return SIGNAL_ERROR;
		}
		total += ret;
	} while ( (size_t)ret == sizeof throwaway );
	return (int)total;
}

void signal_close(const dnbd3_signal_t* const signal)
{
	close( signal->read );
	close( signal->write );
	free( (void*)signal );
}

int signal_getWaitFd(const dnbd3_signal_t* const signal)
{
	if ( signal == NULL ) return -1;
	return signal->read;
}

