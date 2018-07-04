#include <sys/eventfd.h>
#include <poll.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>

/*
 * Linux implementation of signals.
 * Internally, eventfds are used for signalling, as they
 * provide the least overhead. We don't allocate any struct
 * ever, but cast the event fd+1 to dnbd3_signal_t*
 * to save all the malloc() and free() calls.
 */

dnbd3_signal_t* signal_new()
{
	// On error, eventfd() returns -1, so essentially we return NULL on error.
	// (Yes, NULL doesn't have to be 0 everywhere, but cmon)
	return (dnbd3_signal_t*)(intptr_t)( eventfd( 0, EFD_NONBLOCK ) + 1 );
}

dnbd3_signal_t* signal_newBlocking()
{
	return (dnbd3_signal_t*)(intptr_t)( eventfd( 0, 0 ) + 1 );
}

int signal_call(const dnbd3_signal_t* const signal)
{
	if ( signal == NULL ) return SIGNAL_ERROR;
	static const uint64_t one = 1;
	const int signalFd = ( (int)(intptr_t)signal ) - 1;
	return write( signalFd, &one, sizeof one ) == sizeof one ? SIGNAL_OK : SIGNAL_ERROR;
}

int signal_wait(const dnbd3_signal_t* const signal, int timeoutMs)
{
	if ( signal == NULL ) return SIGNAL_ERROR;
	const int signalFd = ( (int)(intptr_t)signal ) - 1;
	struct pollfd ps = {
		.fd = signalFd,
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
	uint64_t ret;
	const int signalFd = ( (int)(intptr_t)signal ) - 1;
	if ( read( signalFd, &ret, sizeof ret ) != sizeof ret ) {
		if ( errno == EAGAIN ) return 0;
		return SIGNAL_ERROR;
	}
	return (int)ret;
}

void signal_close(const dnbd3_signal_t* const signal)
{
	const int signalFd = ( (int)(intptr_t)signal ) - 1;
	close( signalFd );
}

int signal_getWaitFd(const dnbd3_signal_t* const signal)
{
	if ( signal == NULL ) return -1;
	const int signalFd = ( (int)(intptr_t)signal ) - 1;
	return signalFd;
}

