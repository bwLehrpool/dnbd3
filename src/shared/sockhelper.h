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

bool sock_sockaddrToDnbd3(struct sockaddr* sa, dnbd3_host_t *host);

void sock_setTimeout(const int sockfd, const int milliseconds);

size_t sock_printHost(const dnbd3_host_t * const host, char *output, const size_t len);

size_t sock_printable(const struct sockaddr * const addr, const socklen_t addrLen, char *output, const size_t len);

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
 * @return true if any listen call was successful
 */
bool sock_listenAny(poll_list_t* list, uint16_t port);

/**
 * Listen on a specific address and port.
 * @param bind_addr human readable address to bind to for listening
 * @param port to listen on
 */
bool sock_listen(poll_list_t* list, char* bind_addr, uint16_t port);

/**
 * Asynchroneously connect to multiple hosts.
 * This can be called multiple times with varying timeouts. Calling it
 * the first time on an empty list is identical to sock_connect(). On
 * consecutive calls, more nonblocking sockets in connecting state will
 * be added to the list, and on each of these calls, all the pending
 * sockets will be checked for successful connection (or error), respecting
 * the passed timeout.
 * host can be NULL to just wait on the sockets already in the list.
 * If at least one socket completed the connection
 * within the given timeout, it will be removed from the list and
 * returned. On error or timeout, -1 is returned. If there are no more sockets
 * in the list, -2 is returned.
 */
int sock_multiConnect(poll_list_t* list, const dnbd3_host_t* host, int connect_ms, int rw_ms);

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
ssize_t sock_sendAll(const int sock, const void *buffer, const size_t len, int maxtries);

/**
 * Send given buffer, repeatedly calling recv on partial send or EINTR.
 */
ssize_t sock_recv(const int sock, void *buffer, const size_t len);

#endif /* SOCKHELPER_H_ */
