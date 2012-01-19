#ifndef TYPES_H_
#define TYPES_H_

#include "config.h"

// ioctl
#define DNBD3_MAGIC  'd'
#define IOCTL_SET_HOST	_IO(0xab, 1)
#define IOCTL_SET_PORT	_IO(0xab, 2)
#define IOCTL_CONNECT	_IO(0xab, 3)

// network
#define CMD_GET_BLOCK   1
#define CMD_GET_SIZE    2

#pragma pack(1)
typedef struct dnbd3_request {
	uint16_t cmd;
	uint64_t offset;
	uint64_t size;
	char handle[8];
} dnbd3_request_t;
#pragma pack(0)

#pragma pack(1)
typedef struct dnbd3_reply {
	uint16_t cmd;
	uint64_t filesize;
	char handle[8];
} dnbd3_reply_t;
#pragma pack(0)

#endif /* TYPES_H_ */
