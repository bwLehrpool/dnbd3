#include "signal.h"
#include <sys/eventfd.h>
#include <poll.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>

int signal_new()
{
	return eventfd( 0, EFD_NONBLOCK );
}

int signal_newBlocking()
{
	return eventfd( 0, 0 );
}

int signal_call(int signalFd)
{
	if ( signalFd < 0 ) return 0;
	static uint64_t one = 1;
	return write( signalFd, &one, sizeof one ) == sizeof one;
}

int signal_wait(int signalFd, int timeoutMs)
{
	struct pollfd ps = {
		.fd = signalFd,
		.events = POLLIN
	};
	int ret = poll( &ps, 1, timeoutMs );
	if ( ret == 0 ) return SIGNAL_TIMEOUT;
	if ( ret == -1 ) return SIGNAL_ERROR;
	if ( ps.revents & ( POLLERR | POLLNVAL ) ) return SIGNAL_ERROR;
	return signal_clear( signalFd );
}

int signal_clear(int signalFd)
{
	uint64_t ret;
	if ( read( signalFd, &ret, sizeof ret ) != sizeof ret ) {
		if ( errno == EAGAIN ) return 0;
		return SIGNAL_ERROR;
	}
	return (int)ret;
}

void signal_close(int signalFd)
{
	close( signalFd );
}

