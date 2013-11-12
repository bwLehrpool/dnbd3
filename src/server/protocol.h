#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include "../types.h"
#include "../serialize.h"

#define FLAGS8_SERVER 1

static inline int dnbd3_get_reply(int sock, dnbd3_reply_t *reply)
{
	if ( recv( sock, reply, sizeof(*reply), MSG_WAITALL ) != sizeof(*reply) ) {
		return FALSE;
	}
	fixup_reply( *reply );
	if ( reply->magic != dnbd3_packet_magic ) return FALSE;
	return TRUE;
}

static inline int dnbd3_select_image(int sock, char *lower_name, uint16_t rid, uint8_t flags8)
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
	return writev( sock, iov, 2 ) == len + sizeof(request);
}

static inline int dnbd3_get_block(int sock, uint64_t offset, uint32_t size)
{
	dnbd3_request_t request;
	request.magic = dnbd3_packet_magic;
	request.handle = 0;
	request.cmd = CMD_GET_BLOCK;
	request.offset = offset;
	request.size = size;
	fixup_request( request );
	return send( sock, &request, sizeof(request), 0 ) == sizeof(request);
}

static inline int dnbd3_get_crc32(int sock, uint32_t *master, void *buffer, size_t *bufferLen)
{
	dnbd3_request_t request;
	dnbd3_reply_t reply;
	request.magic = dnbd3_packet_magic;
	request.handle = 0;
	request.cmd = CMD_GET_CRC32;
	request.offset = 0;
	request.size = 0;
	fixup_request( request );
	if ( send( sock, &request, sizeof(request), 0 ) != sizeof(request) ) return FALSE;
	if ( !dnbd3_get_reply( sock, &reply ) ) return FALSE;
	if ( reply.size == 0 ) {
		*bufferLen = 0;
		return TRUE;
	}
	if ( reply.size < 4 ) return FALSE;
	reply.size -= 4;
	if ( reply.cmd != CMD_GET_CRC32 || reply.size > *bufferLen ) return FALSE;
	*bufferLen = reply.size;
	if ( recv( sock, master, sizeof(uint32_t), MSG_WAITALL ) != sizeof(uint32_t) ) return FALSE;
	int done = 0;
	while ( done < reply.size ) {
		const int ret = recv( sock, buffer + done, reply.size - done, 0 );
		if ( ret <= 0 ) return FALSE;
		done += ret;
	}
	return TRUE;
}

/**
 * Pass a full serialized_buffer_t and a socket fd. Parsed data will be returned in further arguments.
 * Note that all strings will point into the passed buffer, so there's no need to free them.
 */
static inline int dnbd3_select_image_reply(serialized_buffer_t *buffer, int sock, uint16_t *protocol_version, char **name, uint16_t *rid,
        uint64_t *imageSize)
{
	dnbd3_reply_t reply;
	if ( !dnbd3_get_reply( sock, &reply ) ) {
		return FALSE;
	}
	if ( reply.cmd != CMD_SELECT_IMAGE || reply.size < 3 || reply.size > MAX_PAYLOAD ) {
		return FALSE;
	}
// receive reply payload
	if ( recv( sock, buffer, reply.size, MSG_WAITALL ) != reply.size ) {
		return FALSE;
	}
// handle/check reply payload
	serializer_reset_read( buffer, reply.size );
	*protocol_version = serializer_get_uint16( buffer );
	*name = serializer_get_string( buffer );
	*rid = serializer_get_uint16( buffer );
	*imageSize = serializer_get_uint64( buffer );
	return TRUE;
}

#endif