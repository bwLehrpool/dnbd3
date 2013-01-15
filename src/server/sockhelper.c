#include "sockhelper.h"
#include <string.h>
#include <stdio.h>

static inline int connect_shared(const int client_sock, void* addr, const int addrlen, int connect_ms, int rw_ms)
{
	struct timeval tv;
	// Connect to server
	tv.tv_sec = connect_ms / 1000;
	tv.tv_usec = connect_ms * 1000;
	setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(client_sock, (struct sockaddr *)&addr, addrlen) == -1)
	{
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
	int client_sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (client_sock == -1) return -1;
	return connect_shared(client_sock, addr, sizeof(struct sockaddr_in6), connect_ms, rw_ms);
}

int sock_connect(const dnbd3_host_t * const addr, const int connect_ms, const int rw_ms)
{
	if (addr->type == AF_INET)
	{
		// Set host (IPv4)
		struct sockaddr_in addr4;
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		memcpy(&addr4.sin_addr.s_addr, addr->addr, 4);
		addr4.sin_port = addr->port;
		return sock_connect4(&addr4, connect_ms, rw_ms);
	}
	else if (addr->type == AF_INET6)
	{
		// Set host (IPv6)
		struct sockaddr_in6 addr6;
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		memcpy(&addr6.sin6_addr.s6_addr, addr->addr, 16);
		addr6.sin6_port = addr->port;
		return sock_connect6(&addr6, connect_ms, rw_ms);
	}
	printf("[DEBUG] Unsupported address type: %d\n", (int)addr->type);
	return -1;
}

