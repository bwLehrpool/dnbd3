#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include "../types.h"
#include "../serialize.h"
#include <errno.h>

#define FLAGS8_SERVER (1)

#define REPLY_OK (0)
#define REPLY_ERRNO (-1)
#define REPLY_AGAIN (-2)
#define REPLY_INTR (-3)
#define REPLY_CLOSED (-4)
#define REPLY_INCOMPLETE (-5)
#define REPLY_WRONGMAGIC (-6)

static inline int dnbd3_read_reply(int sock, dnbd3_reply_t *reply, bool wait)
{
	int ret = recv( sock, reply, sizeof(*reply), (wait ? MSG_WAITALL : MSG_DONTWAIT) | MSG_NOSIGNAL );
	if ( ret == 0 ) return REPLY_CLOSED;
	if ( ret < 0 ) {
		if ( errno == EAGAIN || errno == EWOULDBLOCK ) return REPLY_AGAIN;
		if ( errno == EINTR ) return REPLY_INTR;
		return REPLY_ERRNO;
	}
	if ( !wait && ret != sizeof(*reply) ) ret += recv( sock, ((char*)reply) + ret, sizeof(*reply) - ret, MSG_WAITALL | MSG_NOSIGNAL );
	if ( ret != sizeof(*reply) ) return REPLY_INCOMPLETE;
	fixup_reply( *reply );
	if ( reply->magic != dnbd3_packet_magic ) return REPLY_WRONGMAGIC;
	return REPLY_OK;
}

static inline bool dnbd3_get_reply(int sock, dnbd3_reply_t *reply)
{
	return dnbd3_read_reply( sock, reply, true ) == REPLY_OK;
}

static inline bool dnbd3_select_image(int sock, char *lower_name, uint16_t rid, uint8_t flags8)
{
	serialized_buffer_t serialized;
	dnbd3_request_t request;
	struct iovec iov[2];
	serializer_reset_write( &serialized );
	serializer_put_uint16( &serialized, PROTOCOL_VERSION );
	serializer_put_string( &serialized, lower_name );
	serializer_put_uint16( &serialized, rid );
	serializer_put_uint8( &serialized, flags8 );
	const ssize_t len = serializer_get_written_length( &serialized );
	request.magic = dnbd3_packet_magic;
	request.cmd = CMD_SELECT_IMAGE;
	request.size = len;
#ifdef _DEBUG
	request.handle = 0;
	request.offset = 0;
#endif
	fixup_request( request );
	iov[0].iov_base = &request;
	iov[0].iov_len = sizeof(request);
	iov[1].iov_base = &serialized;
	iov[1].iov_len = len;
	return writev( sock, iov, 2 ) == len + (ssize_t)sizeof(request);
}

static inline bool dnbd3_get_block(int sock, uint64_t offset, uint32_t size, uint64_t handle)
{
	dnbd3_request_t request;
	request.magic = dnbd3_packet_magic;
	request.handle = handle;
	request.cmd = CMD_GET_BLOCK;
	request.offset = offset;
	request.size = size;
	fixup_request( request );
	return send( sock, &request, sizeof(request), MSG_NOSIGNAL ) == sizeof(request);
}

static inline bool dnbd3_get_crc32(int sock, uint32_t *master, void *buffer, size_t *bufferLen)
{
	dnbd3_request_t request;
	dnbd3_reply_t reply;
	request.magic = dnbd3_packet_magic;
	request.handle = 0;
	request.cmd = CMD_GET_CRC32;
	request.offset = 0;
	request.size = 0;
	fixup_request( request );
	if ( send( sock, &request, sizeof(request), 0 ) != sizeof(request) ) return false;
	if ( !dnbd3_get_reply( sock, &reply ) ) return false;
	if ( reply.size == 0 ) {
		*bufferLen = 0;
		return true;
	}
	if ( reply.size < 4 ) return false;
	reply.size -= 4;
	if ( reply.cmd != CMD_GET_CRC32 || reply.size > *bufferLen ) return false;
	*bufferLen = reply.size;
	if ( recv( sock, master, sizeof(uint32_t), MSG_WAITALL | MSG_NOSIGNAL ) != sizeof(uint32_t) ) return false;
	uint32_t done = 0;
	while ( done < reply.size ) {
		const ssize_t ret = recv( sock, (char*)buffer + done, reply.size - done, 0 );
		if ( ret <= 0 ) return false;
		done += ret;
	}
	return true;
}

/**
 * Pass a full serialized_buffer_t and a socket fd. Parsed data will be returned in further arguments.
 * Note that all strings will point into the passed buffer, so there's no need to free them.
 * This function will also read the header for you, as this message can only occur during connection,
 * where no unrequested messages could arrive inbetween.
 */
static inline bool dnbd3_select_image_reply(serialized_buffer_t *buffer, int sock, uint16_t *protocol_version, char **name, uint16_t *rid,
        uint64_t *imageSize)
{
	dnbd3_reply_t reply;
	if ( !dnbd3_get_reply( sock, &reply ) ) {
		return false;
	}
	if ( reply.cmd != CMD_SELECT_IMAGE || reply.size < 3 || reply.size > MAX_PAYLOAD ) {
		return false;
	}
// receive reply payload
	if ( recv( sock, buffer, reply.size, MSG_WAITALL | MSG_NOSIGNAL ) != reply.size ) {
		return false;
	}
// handle/check reply payload
	serializer_reset_read( buffer, reply.size );
	*protocol_version = serializer_get_uint16( buffer );
	*name = serializer_get_string( buffer );
	*rid = serializer_get_uint16( buffer );
	*imageSize = serializer_get_uint64( buffer );
	return true;
}

#endif
