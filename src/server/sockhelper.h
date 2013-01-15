#ifndef SOCKHELPER_H_
#define SOCKHELPER_H_

#include <stdint.h>
#include "../types.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

#endif /* SOCKHELPER_H_ */
