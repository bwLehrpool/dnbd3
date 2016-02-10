#include <poll.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#define P_READ (0)
#define P_WRITE (1)

/*
 * Generic (posix) implelentation of signals, using pipes.
 * 64bit version, packing two ints into a pointer.
 * This version requires that you use -fno-strict-aliasing
 * since it's doing evil pointer casting.
 */

dnbd3_signal_t* signal_new()
{
	int fds[2];
	if ( pipe( fds ) == -1 ) return NULL;
	fcntl( fds[P_READ], F_SETFL, O_NONBLOCK );
	fcntl( fds[P_WRITE], F_SETFL, O_NONBLOCK );
	return (dnbd3_signal_t*)*((uintptr_t*)fds);
}

dnbd3_signal_t* signal_newBlocking()
{
	int fds[2];
	if ( pipe( fds ) == -1 ) return NULL;
	return (dnbd3_signal_t*)*((uintptr_t*)fds);
}

int signal_call(const dnbd3_signal_t* const signal)
{
	if ( signal == NULL ) return SIGNAL_ERROR;
	static char one = 1;
	const int* fds = (int*)&signal;
	// Write one byte on every call, so the number of bytes read will
	// match the number of events
	return write( fds[P_WRITE], &one, 1 ) > 0 ? SIGNAL_OK : SIGNAL_ERROR;
}

int signal_wait(const dnbd3_signal_t* const signal, int timeoutMs)
{
	if ( signal == NULL ) return SIGNAL_ERROR;
	const int* fds = (int*)&signal;
	struct pollfd ps = {
		.fd = fds[P_READ],
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
	const int* fds = (int*)&signal;
	ssize_t ret, total = 0;
	do {
		ret = read( fds[P_READ], throwaway, sizeof throwaway );
		if ( ret < 0 ) {
			if ( errno == EAGAIN ) return total;
			return SIGNAL_ERROR;
		}
		total += ret;
	} while ( (size_t)ret == sizeof throwaway );
	return (int)total;
}

void signal_close(const dnbd3_signal_t* const signal)
{
	const int* fds = (int*)&signal;
	close( fds[P_READ] );
	close( fds[P_WRITE] );
}

int signal_getWaitFd(const dnbd3_signal_t* const signal)
{
	if ( signal == NULL ) return -1;
	const int* fds = (int*)&signal;
	return fds[P_READ];
}

