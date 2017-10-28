#include "sockhelper.h"
#include "log.h"
#include <arpa/inet.h> // inet_ntop
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>

#define MAXLISTEN 20

struct _poll_list {
	int count;
	struct pollfd entry[MAXLISTEN];
};

int sock_connect(const dnbd3_host_t * const addr, const int connect_ms, const int rw_ms)
{
	// TODO: Move out of here, this unit should contain general socket functions
	// TODO: Rework the dnbd3_host_t to not use AF_* as these could theoretically change
	// TODO: Abstract away from sockaddr_in* like the rest of the functions here do,
	// so WITH_IPV6 can finally be removed as everything is transparent.
	struct sockaddr_storage ss;
	int proto, addrlen;
	memset( &ss, 0, sizeof ss );
	if ( addr->type == HOST_IP4 ) {
		// Set host (IPv4)
		struct sockaddr_in *addr4 = (struct sockaddr_in*)&ss;
		addr4->sin_family = AF_INET;
		memcpy( &addr4->sin_addr, addr->addr, 4 );
		addr4->sin_port = addr->port;
		proto = PF_INET;
		addrlen = sizeof *addr4;
	}
#ifdef WITH_IPV6
	else if ( addr->type == HOST_IP6 ) {
		// Set host (IPv6)
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&ss;
		addr6->sin6_family = AF_INET6;
		memcpy( &addr6->sin6_addr, addr->addr, 16 );
		addr6->sin6_port = addr->port;
		proto = PF_INET6;
		addrlen = sizeof *addr6;
	}
#endif
	else {
		logadd( LOG_DEBUG1, "Unsupported address type: %d\n", (int)addr->type );
		return -1;
	}
	int client_sock = socket( proto, SOCK_STREAM, IPPROTO_TCP );
	if ( client_sock == -1 ) return -1;
	// Apply connect timeout
	sock_setTimeout( client_sock, connect_ms );
	for ( int i = 0;; ++i ) {
		int ret = connect( client_sock, (struct sockaddr *)&ss, addrlen );
		if ( ret != -1 ) break;
		if ( errno == EINTR && i < 5 ) continue;
		close( client_sock );
		return -1;
	}
	// Apply read/write timeout
	sock_setTimeout( client_sock, rw_ms );
	return client_sock;
}

// TODO: Pretty much same as in server/*
int sock_resolveToDnbd3Host(const char * const address, dnbd3_host_t * const dest, const int count)
{
	if ( count <= 0 )
		return 0;
	struct addrinfo hints, *res, *ptr;
	char bufferAddr[100], bufferPort[6];
	char *addr = bufferAddr;
	const char *portStr = NULL;
	int addCount = 0;

	// See if we have a port
	snprintf( bufferAddr, sizeof bufferAddr, "%s", address );
	char *c1, *c2;
	c1 = strchr( addr, ':' );
	if ( c1 != NULL ) {
		c2 = strchr( c1 + 1, ':' );
		if ( c2 == NULL ) {
			*c1 = '\0';
			portStr = c1 + 1;
		} else if ( *addr == '[' ) {
			// IPv6 - support [1:2::3]:123
			do {
				c1 = strchr( c2 + 1, ':' );
				if ( c1 != NULL ) c2 = c1;
			} while ( c1 != NULL );
			if ( *(c2 - 1 ) == ']' ) {
				*( c2 - 1 ) = '\0';
				*c2 = '\0';
				addr += 1;
				portStr = c2 + 1;
			}
		}
	}
	if ( portStr == NULL ) {
		portStr = bufferPort;
		snprintf( bufferPort, sizeof bufferPort, "%d", (int)PORT );
	}

	// Set hints for local addresses.
	memset( &hints, 0, sizeof( hints ) );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ( getaddrinfo( addr, portStr, &hints, &res ) != 0 || res == NULL ) {
		return 0;
	}
	for ( ptr = res; ptr != NULL && count > 0; ptr = ptr->ai_next ) {
		if ( ptr->ai_addr->sa_family == AF_INET ) {
			// Set host (IPv4)
			struct sockaddr_in *addr4 = (struct sockaddr_in*)ptr->ai_addr;
			dest[addCount].type = HOST_IP4;
			dest[addCount].port = addr4->sin_port;
			memcpy( dest[addCount].addr, &addr4->sin_addr, 4 );
			addCount += 1;
#ifdef WITH_IPV6
		} else if ( ptr->ai_addr->sa_family == AF_INET6 ) {
			// Set host (IPv6)
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)ptr->ai_addr;
			dest[addCount].type = HOST_IP6;
			dest[addCount].port = addr6->sin6_port;
			memcpy( dest[addCount].addr, &addr6->sin6_addr, 16 );
			addCount += 1;
#endif
		}
	}

	freeaddrinfo( res );
	return addCount;
}

void sock_setTimeout(const int sockfd, const int milliseconds)
{
	struct timeval tv;
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds * 1000) % 1000000;
	setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) );
	setsockopt( sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv) );
}

poll_list_t* sock_newPollList()
{
	poll_list_t *list = (poll_list_t*)malloc( sizeof( poll_list_t ) );
	list->count = 0;
	return list;
}

void sock_destroyPollList(poll_list_t *list)
{
	for ( int i = 0; i < list->count; ++i ) {
		if ( list->entry[i].fd >= 0 ) close( list->entry[i].fd );
	}
	free( list );
}

size_t sock_printHost(const dnbd3_host_t * const host, char * const buffer, const size_t len)
{
	// Worst case: Port 5 chars, ':' to separate ip and port 1 char, terminating null 1 char = 7, [] for IPv6
	if ( len < 10 ) return 0;
	char *output = buffer;
	if ( host->type == HOST_IP6 ) {
		*output++ = '[';
		inet_ntop( AF_INET6, host->addr, output, (socklen_t)( len - 10 ) );
		output += strlen( output );
		*output++ = ']';
	} else if ( host->type == HOST_IP4 ) {
		inet_ntop( AF_INET, host->addr, output, (socklen_t)( len - 8 ) );
		output += strlen( output );
	} else {
		int ret = snprintf( output, len, "<?addrtype=%d>", (int)host->type );
		if ( ret <= 0 ) return 0;
		return MIN( (size_t)ret, len-1 );
	}
	*output = '\0';
	if ( host->port != 0 ) {
		// There are still at least 7 bytes left in the buffer, port is at most 5 bytes + ':' + '\0' = 7
		int ret = snprintf( output, 7, ":%d", (int)ntohs( host->port ) );
		if ( ret < 0 ) ret = 0;
		output += MIN( ret, 6 );
	}
	return output - buffer;
}

size_t sock_printable(const struct sockaddr * const addr, const socklen_t addrLen, char *output, const size_t len)
{
	char host[100], port[10];
	int outlen = 0;
	int ret = getnameinfo( addr, addrLen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV );
	if ( ret == 0 ) {
		if ( addr->sa_family == AF_INET ) {
			outlen = snprintf( output, len, "%s:%s", host, port );
		} else {
			outlen = snprintf( output, len, "[%s]:%s", host, port );
		}
	}
	if ( outlen <= 0 ) return 0;
	return MIN( (size_t)outlen, len-1 );
}

bool sock_listen(poll_list_t* list, char* bind_addr, uint16_t port)
{
	if ( list->count >= MAXLISTEN ) return false;
	struct addrinfo hints, *res = NULL, *ptr;
	char portStr[6];
	const int on = 1;
	int openCount = 0;
	// Set hints for local addresses.
	memset( &hints, 0, sizeof(hints) );
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf( portStr, sizeof portStr, "%d", (int)port );
	if ( getaddrinfo( bind_addr, portStr, &hints, &res ) != 0 || res == NULL ) return false;
	// Attempt to bind to all of the addresses as long as there's room in the poll list
	for( ptr = res; ptr != NULL; ptr = ptr->ai_next ) {
		char bla[100];
		if ( !sock_printable( (struct sockaddr*)ptr->ai_addr, ptr->ai_addrlen, bla, 100 ) ) snprintf( bla, 100, "[invalid]" );
		logadd( LOG_DEBUG1, "Binding to %s...", bla );
		int sock = socket( ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol );
		if ( sock < 0 ) {
			logadd( LOG_WARNING, "(Bind to %s): cannot socket(), errno=%d", bla, errno );
			continue;
		}
		setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );
		if ( ptr->ai_family == PF_INET6 ) setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on) );
		if ( bind( sock, ptr->ai_addr, ptr->ai_addrlen ) == -1 ) {
			logadd( LOG_WARNING, "(Bind to %s): cannot bind(), errno=%d", bla, errno );
			close( sock );
			continue;
		}
		if ( listen( sock, 20 ) == -1 ) {
			logadd( LOG_WARNING, "(Bind to %s): cannot listen(), errno=%d", errno );
			close( sock );
			continue;
		}
		list->entry[list->count].fd = sock;
		list->entry[list->count].events = POLLIN | POLLRDHUP;
		list->count++;
		openCount++;
		if ( list->count >= MAXLISTEN ) break;
	}
	freeaddrinfo( res );
	return openCount > 0;
}

int sock_listenAny(poll_list_t* list, uint16_t port)
{
	return sock_listen( list, NULL, port );
}

int sock_accept(poll_list_t *list, struct sockaddr_storage *addr, socklen_t *length_ptr)
{
	int ret = poll( list->entry, list->count, -1 );
	if ( ret < 0 ) {
		return -1;
	}
	for ( int i = list->count - 1; i >= 0; --i ) {
		if ( list->entry[i].revents == 0 ) continue;
		if ( list->entry[i].revents == POLLIN ) return accept( list->entry[i].fd, (struct sockaddr *)addr, length_ptr );
		if ( list->entry[i].revents & ( POLLNVAL | POLLHUP | POLLERR | POLLRDHUP ) ) {
			logadd( LOG_DEBUG1, "poll fd revents=%d for index=%d and fd=%d", (int)list->entry[i].revents, i, list->entry[i].fd );
			if ( ( list->entry[i].revents & POLLNVAL ) == 0 ) close( list->entry[i].fd );
			if ( i != list->count ) list->entry[i] = list->entry[list->count];
			list->count--;
		}
	}
	return -1;
}

void sock_set_nonblock(int sock)
{
	int flags = fcntl( sock, F_GETFL, 0 );
	if ( flags == -1 ) flags = 0;
	fcntl( sock, F_SETFL, flags | O_NONBLOCK );
}

void sock_set_block(int sock)
{
	int flags = fcntl( sock, F_GETFL, 0 );
	if ( flags == -1 ) flags = 0;
	fcntl( sock, F_SETFL, flags & ~(int)O_NONBLOCK );
}

bool sock_append(poll_list_t *list, const int sock, bool wantRead, bool wantWrite)
{
	if ( sock == -1 || list->count >= MAXLISTEN ) return false;
	list->entry[list->count++].fd = sock;
	list->entry[list->count++].events = (short)( ( wantRead ? POLLIN : 0 ) | ( wantWrite ? POLLOUT : 0 ) | POLLRDHUP );
	list->count++;
	return true;
}

ssize_t sock_sendAll(const int sock, const void *buffer, const size_t len, int maxtries)
{
	size_t done = 0;
	ssize_t ret = 0;
	while ( done < len ) {
		if ( maxtries >= 0 && --maxtries == -1 ) break;
		ret = send( sock, (const uint8_t*)buffer + done, len - done, MSG_NOSIGNAL );
		if ( ret == -1 ) {
			if ( errno == EINTR ) continue;
			if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
				continue;
			}
			break;
		}
		if ( ret == 0 ) break;
		done += ret;
	}
	if ( done == 0 ) return ret;
	return done;
}

ssize_t sock_recv(const int sock, void *buffer, const size_t len)
{
	size_t done = 0;
	ssize_t ret = 0;
	int intrs = 0;
	while ( done < len ) {
		ret = recv( sock, (char*)buffer + done, len - done, MSG_NOSIGNAL );
		if ( ret == -1 ) {
			if ( errno == EINTR && ++intrs < 10 ) continue;
			break;
		}
		if ( ret == 0 ) break;
		done += ret;
	}
	if ( done == 0 ) return ret;
	return done;
}

