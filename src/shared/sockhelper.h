#ifndef SOCKHELPER_H_
#define SOCKHELPER_H_

/*
 * Helper functions for dealing with sockets. These functions should
 * abstract from the IP version by using getaddrinfo() and thelike.
 */

#include "../types.h"
#include <stdint.h>
#include <sys/socket.h>
#include <string.h>

typedef struct _poll_list poll_list_t;

/**
 * Connect to given dnbd3_host_t.
 * @param addr - address of host to connect to
 * @param connect_ms - timeout in milliseconds after which the connection attempt fails
 * @param rw_ms - read/write timeout in milliseconds to apply on successful connect
 * @return socket file descriptor, or -1 on error
 */
int sock_connect(const dnbd3_host_t * const addr, const int connect_ms, const int rw_ms);

/**
 * Resolve/parse given address and put the result(s) into passed dnbd3_host_t array,
 * but only up to count entries.
 * @return Number of items added to array
 */
int sock_resolveToDnbd3Host(const char * const address, dnbd3_host_t * const dest, const int count);

void sock_setTimeout(const int sockfd, const int milliseconds);

int sock_printHost(const dnbd3_host_t * const host, char *output, const int len);

int sock_printable(struct sockaddr *addr, socklen_t addrLen, char *output, int len);

/**
 * Create new poll list.
 */
poll_list_t* sock_newPollList();

/**
 * Delete a poll list, closing all sockets first if necessary.
 */
void sock_destroyPollList(poll_list_t *list);

/**
 * Listen on all interfaces/available IP addresses, using the given protocol.
 * IPv4 and IPv6 are supported.
 * @param protocol_family PF_INET or PF_INET6
 * @param port port to listen on
 * @return the socket descriptor if successful, -1 otherwise.
 */
int sock_listenAny(poll_list_t* list, uint16_t port);

/**
 * Listen on a specific address and port.
 * @param addr pointer to a properly filled sockaddr_in or sockaddr_in6
 * @param addrlen length of the passed struct
 */
bool sock_listen(poll_list_t* list, char* bind_addr, uint16_t port);

/**
 * This is a multi-socket version of accept. Pass in an array of listening sockets.
 * If any of the sockets has an incoming connection, accept it and return the new socket's fd.
 * On error, return -1, just like accept().
 * @param sockets array of listening socket fds
 * @param socket_count number of sockets in that array
 * @return fd of new client socket, -1 on error
 */
int sock_accept(poll_list_t *list, struct sockaddr_storage *addr, socklen_t *length_ptr);

void sock_set_nonblock(int sock);

void sock_set_block(int sock);

/**
 * Add given socket to array. Take an existing empty slot ( == -1) if available,
 * append to end otherwise. Updates socket count variable passed by reference.
 *
 * @param poll_list_t list the poll list to add the socket to
 * @param sock socket fd to add
 * @param wantRead whether to set the EPOLLIN flag
 * @param wantWrite whether to set the EPOLLOUT flag
 * @return true on success, false iff the array is already full or socket is < 0
 */
bool sock_append(poll_list_t *list, const int sock, bool wantRead, bool wantWrite);

/**
 * Send the whole buffer, calling write() multiple times if neccessary.
 * Give up after calling write() maxtries times.
 * Set maxtries < 0 to try infinitely.
 */
ssize_t sock_sendAll(const int sock, void *buffer, const size_t len, int maxtries);

/**
 * Send given buffer, repeatedly calling recv on partial send or EINTR.
 */
ssize_t sock_recv(const int sock, void *buffer, const size_t len);

#endif /* SOCKHELPER_H_ */
