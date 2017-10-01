#ifndef _RPC_H_
#define _RPC_H_

struct dnbd3_host_t;

void rpc_sendStatsJson(int sock, struct dnbd3_host_t* host, const void *data, const int dataLen);

#endif
