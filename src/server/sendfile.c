#include "sendfile.h"

#if defined(__linux__)
#include <sys/sendfile.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#else
#error "What platform is this?"
#endif

#include <errno.h>

bool sendfile_all(const int fd, const int sock, off_t foffset, const size_t bytes)
{
	if ( bytes == 0 )
		return true;
#ifdef DNBD3_SERVER_AFL
	errno = 0;
	return true;
#elif defined(__linux__)
	size_t done = 0;
	int againCount = 0;

	while ( done < bytes ) {
		const ssize_t sent = sendfile( sock, fd, &foffset, bytes - done );
		if ( sent == 0 ) // Probably EOF, like with send(), but manpage is not clear :-/
			return false;
		if ( sent < 0 ) {
			if ( errno == EAGAIN || errno == EINTR ) {
				// Retry once, but give up otherwise - EAGAIN might just be the send timeout
				if ( ++againCount > 1 )
					return false;
				continue;
			}
			return false;
		}
		done += sent;
	}
#elif defined(__FreeBSD__)
	off_t sent;
	size_t done = 0;
	int againCount = 0;

	while ( done < bytes ) {
		const int ret = sendfile( fd, sock, foffset + done, bytes - done, NULL, &sent, 0 );
		if ( ret == 0 || errno == EAGAIN || errno == EINTR ) {
			// Retry once, but give up otherwise - EAGAIN might just be the send timeout
			if ( sent == 0 && ++againCount > 1 )
				return false;
			done += sent;
			continue;
		}
		// Something else went wrong
		return false;
	}
#endif
	return true;
}