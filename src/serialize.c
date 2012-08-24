#include "serialize.h"
#include "types.h"

#ifndef MIN
#define MIN(a,b) (a < b ? a : b)
#endif

void serializer_reset_read(serialized_buffer_t *buffer, size_t data_len)
{
	buffer->buffer_end = buffer->buffer + MIN(MAX_PAYLOAD, data_len);
	buffer->buffer_pointer = buffer->buffer;
}

void serializer_reset_write(serialized_buffer_t *buffer)
{
	buffer->buffer_end = buffer->buffer + MAX_PAYLOAD;
	buffer->buffer_pointer = buffer->buffer;
}

uint16_t serializer_get_uint16(serialized_buffer_t *buffer)
{
	uint16_t ret;
	if (buffer->buffer_pointer + 2 > buffer->buffer_end) return 0;
	memcpy(&ret, buffer->buffer_pointer, 2);
	*buffer->buffer_pointer += 2;
	return net_order_16(ret);
}

uint64_t serializer_get_uint64(serialized_buffer_t *buffer)
{
	uint64_t ret;
	if (buffer->buffer_pointer + 8 > buffer->buffer_end) return 0;
	memcpy(&ret, buffer->buffer_pointer, 8);
	*buffer->buffer_pointer += 8;
	return net_order_64(ret);
}

char* serializer_get_string(serialized_buffer_t *buffer)
{
	char *ptr = buffer->buffer_pointer, *start = buffer->buffer_pointer;
	while (ptr < buffer->buffer_end && *ptr) ++ptr;
	if (*ptr) return NULL; // String did not terminate within buffer (possibly corrupted/malicious packet)
	buffer->buffer_pointer = ptr + 1;
	return start;
}

void serializer_put_uint16(serialized_buffer_t *buffer, uint16_t value)
{
	if (buffer->buffer_pointer + 2 > buffer->buffer_end) return;
	value = net_order_16(value);
	memcpy(buffer->buffer_pointer, &value, 2);
	buffer->buffer_pointer += 2;
}

void serializer_put_uint64(serialized_buffer_t *buffer, uint64_t value)
{
	if (buffer->buffer_pointer + 8 > buffer->buffer_end) return;
	value = net_order_64(value);
	memcpy(buffer->buffer_pointer, &value, 8);
	buffer->buffer_pointer += 8;
}

void serializer_put_string(serialized_buffer_t *buffer, char *value)
{
	size_t len = strlen(value) + 1;
	if (buffer->buffer_pointer + len > buffer->buffer_end) return;
	memcpy(buffer->buffer_pointer, value, len);
	buffer->buffer_pointer += len;
}

ssize_t serializer_get_written_length(serialized_buffer_t *buffer)
{
	return buffer->buffer_pointer - buffer->buffer;
}
