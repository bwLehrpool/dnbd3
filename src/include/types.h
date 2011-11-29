#ifndef TYPES_H_
#define TYPES_H_

#include "../config.h"

#define DNBD_MAGIC  'd'

#define CMD_GET_BLOCK   1
#define CMD_GET_SIZE    2

#define IOCTL_SET_HOST	_IO(0xab, 1)
#define IOCTL_SET_PORT	_IO(0xab, 2)
#define IOCTL_CONNECT	_IO(0xab, 3)

#pragma pack(1)
typedef struct dnbd3_request {
	uint16_t cmd;
	uint64_t offset;
	uint64_t size;
} dnbd3_request_t;
#pragma pack(0)

#pragma pack(1)
typedef struct dnbd3_reply {
	uint16_t cmd;
	uint64_t filesize;
} dnbd3_reply_t;
#pragma pack(0)

#endif /* TYPES_H_ */
