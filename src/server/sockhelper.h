#ifndef SOCKHELPER_H_
#define SOCKHELPER_H_

#include <stdint.h>
#include "../types.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

int sock_connect4(struct sockaddr_in *addr, const int connect_ms, const int rw_ms);

int sock_connect6(struct sockaddr_in6 *addr, const int connect_ms, const int rw_ms);

/**
 * Connect to given dnbd3_host_t.
 * @param addr - address of host to connect to
 * @param connect_ms - timeout in milliseconds after which the connection attempt fails
 * @param rw_ms - read/write timeout in milliseconds to apply on successful connect
 * @return socket file descriptor, or -1 on error
 */
int sock_connect(const dnbd3_host_t * const addr, const int connect_ms, const int rw_ms);

void sock_set_timeout(const int sockfd, const int milliseconds);

/**
 * Listen on all interfaces/available IP addresses, using the given protocol.
 * IPv4 and IPv6 are supported.
 * @param protocol_family PF_INET or PF_INET6
 * @param port port to listen on
 * @return the socket descriptor if successful, -1 otherwise.
 */
int sock_listen_any(int protocol_family, uint16_t port, char* bind_addr);

/**
 * Listen on a specific address and port.
 * @param addr pointer to a properly filled sockaddr_in or sockaddr_in6
 * @param addrlen length of the passed struct
 */
int sock_listen(struct sockaddr_storage *addr, int addrlen);

/**
 * This is a multi-socket version of accept. Pass in an array of listening sockets.
 * If any of the sockets has an incoming connection, accept it and return the new socket's fd.
 * On error, return -1, just like accept().
 * @param sockets array of listening socket fds
 * @param socket_count number of sockets in that array
 * @return fd of new client socket, -1 on error
 */
int accept_any(const int * const sockets, const int socket_count, struct sockaddr_storage *addr, socklen_t *length_ptr);

void sock_set_nonblock(int sock);

void sock_set_block(int sock);

/**
 * Take IPv4 as string and a port and fill sockaddr_in struct.
 * This should be refactored to work for IPv4 and IPv6 and use sockaddr_storage.
 */
inline void sock_set_addr4(char *ip, uint16_t port, struct sockaddr_in *addr)
{
	memset( addr, 0, sizeof(*addr) );
	addr->sin_family = AF_INET; // IPv4
	addr->sin_addr.s_addr = inet_addr( ip );
	addr->sin_port = htons( port ); // set port number
}

/**
 * Add given socket to array. Take an existing empty slot ( == -1) if available,
 * append to end otherwise. Updates socket count variable passed by reference.
 * The passed socket fd is only added if it is != -1 for convenience, so you can
 * directly pass the return value of sock_listen or sock_create, without checking the
 * return value first.
 * @param sock socket fd to add
 * @param array the array of socket fds to add the socket to
 * @param array_fill pointer to int telling how many sockets there are in the array. Empty slots
 * in between are counted too. In other words: represents the index of the last valid socket fd in the
 * array plus one, or 0 if there are none.
 * @param array_length the capacity of the array
 * @return true on success or if the passed fd was -1, false iff the array is already full
 */
bool sock_add_array(const int sock, int *array, int *array_fill, const int array_length);

#endif /* SOCKHELPER_H_ */
