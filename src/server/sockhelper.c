#include "sockhelper.h"
#include "memlog.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

static inline int connect_shared(const int client_sock, void* addr, const int addrlen, int connect_ms, int rw_ms)
{
	struct timeval tv;
	// Connect to server
	tv.tv_sec = connect_ms / 1000;
	tv.tv_usec = connect_ms * 1000;
	setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(client_sock, (struct sockaddr *)addr, addrlen) == -1)
	{
		//int e = errno;
		//printf("connect -1 (%d)\n", e);
		return -1;
	}
	// Apply read/write timeout
	tv.tv_sec = rw_ms / 1000;
	tv.tv_usec = rw_ms * 1000;
	setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	return client_sock;
}

int sock_connect4(struct sockaddr_in *addr, const int connect_ms, const int rw_ms)
{
	int client_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_sock == -1) return -1;
	return connect_shared(client_sock, addr, sizeof(struct sockaddr_in), connect_ms, rw_ms);
}

int sock_connect6(struct sockaddr_in6 *addr, const int connect_ms, const int rw_ms)
{
#ifdef WITH_IPV6
	int client_sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (client_sock == -1) return -1;
	return connect_shared(client_sock, addr, sizeof(struct sockaddr_in6), connect_ms, rw_ms);
#else
	printf("[DEBUG] Not compiled with IPv6 support.\n");
	return -1;
#endif
}

int sock_connect(const dnbd3_host_t * const addr, const int connect_ms, const int rw_ms)
{
	if (addr->type == AF_INET)
	{
		// Set host (IPv4)
		struct sockaddr_in addr4;
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		memcpy(&addr4.sin_addr, addr->addr, 4);
		addr4.sin_port = addr->port;
		return sock_connect4(&addr4, connect_ms, rw_ms);
	}
#ifdef WITH_IPV6
	else if (addr->type == AF_INET6)
	{
		// Set host (IPv6)
		struct sockaddr_in6 addr6;
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		memcpy(&addr6.sin6_addr, addr->addr, 16);
		addr6.sin6_port = addr->port;
		return sock_connect6(&addr6, connect_ms, rw_ms);
	}
#endif
	printf("[DEBUG] Unsupported address type: %d\n", (int)addr->type);
	return -1;
}

void sock_set_timeout(const int sockfd, const int milliseconds)
{
	struct timeval tv;
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds * 1000) % 1000000;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int sock_listen_any(int protocol_family, uint16_t port)
{
	struct sockaddr_storage addr;
	memset(&addr, 0, sizeof(addr));
	if (protocol_family == PF_INET)
	{
		struct sockaddr_in *v4 = (struct sockaddr_in *)&addr;
		v4->sin_addr.s_addr = INADDR_ANY;
		v4->sin_port = htons(port);
		v4->sin_family = AF_INET;
	}
#ifdef WITH_IPV6
	else if (protocol_family == PF_INET6)
	{
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&addr;
		v6->sin6_addr = in6addr_any;
		v6->sin6_port = htons(port);
		v6->sin6_family = AF_INET6;
	}
#endif
	else
	{
		printf("[DEBUG] sock_listen: Unsupported protocol: %d\n", protocol_family);
		return -1;
	}
	return sock_listen(&addr, sizeof(addr));
}

int sock_listen(struct sockaddr_storage *addr, int addrlen)
{
	int pf; // On Linux AF_* == PF_*, but this is not guaranteed on all platforms, so let's be safe here:
	if (addr->ss_family == AF_INET)
		pf = PF_INET;
#ifdef WITH_IPV6
	else if (addr->ss_family == AF_INET6)
		pf = PF_INET6;
#endif
	else
	{
		printf("[DEBUG] sock_listen: unsupported address type: %d\n", (int)addr->ss_family);
		return -1;
	}
	int sock;

	// Create socket
	sock = socket(pf, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		memlogf("[ERROR] sock_listen: Socket setup failure"); // TODO: print port number to help troubleshooting
		return -1;
	}
	const int on = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (pf == PF_INET6)
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

	// Bind to socket
	if (bind(sock, (struct sockaddr *) addr, addrlen) < 0)
	{
		int e = errno;
		close(sock);
		memlogf("[ERROR] Bind failure (%d)", e); // TODO: print port number to help troubleshooting
		return -1;
	}

	// Listen on socket
	if (listen(sock, 20) == -1)
	{
		close(sock);
		memlogf("[ERROR] Listen failure"); // TODO ...
		return -1;
	}

	return sock;
}

int accept_any(const int * const sockets, const int socket_count, struct sockaddr_storage *addr, socklen_t *length_ptr)
{
	fd_set set;
	FD_ZERO(&set);
	int max = 0;
	for (int i = 0; i < socket_count; ++i)
	{
		FD_SET(sockets[i], &set);
		if (sockets[i] > max)
			max = sockets[i];
	}
	if (select(max + 1, &set, NULL, NULL, NULL) <= 0) return -1;
	for (int i = 0; i < socket_count; ++i)
	{
		if (FD_ISSET(sockets[i], &set))
			return accept(sockets[i], (struct sockaddr *)addr, length_ptr);
	}
	return -1;
}

void sock_set_nonblock(int sock)
{
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1)
		flags = 0;
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

void sock_set_block(int sock)
{
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1)
		flags = 0;
	fcntl(sock, F_SETFL, flags & ~(int)O_NONBLOCK);
}

int sock_add_array(const int sock, int *array, int *array_fill, const int array_length)
{
	if (sock == -1)
		return TRUE;
	for (int i = 0; i < *array_fill; ++i)
	{
		if (array[i] == -1)
		{
			array[i] = sock;
			return TRUE;
		}
	}
	if (*array_fill >= array_length)
		return FALSE;
	array[*array_fill] = sock;
	(*array_fill) += 1;
	return TRUE;
}
