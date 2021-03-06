// SPDX-License-Identifier: GPL-2.0
#include <dnbd3/shared/serialize.h>
#include <dnbd3/types.h>

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

uint8_t serializer_get_uint8(serialized_buffer_t *buffer)
{
	if (buffer->buffer_pointer + 1 > buffer->buffer_end)
		return 0;
	return (uint8_t)*buffer->buffer_pointer++;
}

uint16_t serializer_get_uint16(serialized_buffer_t *buffer)
{
	uint16_t ret;

	if (buffer->buffer_pointer + 2 > buffer->buffer_end)
		return 0;
	memcpy(&ret, buffer->buffer_pointer, 2);
	buffer->buffer_pointer += 2;
	return net_order_16(ret);
}

uint64_t serializer_get_uint64(serialized_buffer_t *buffer)
{
	uint64_t ret;

	if (buffer->buffer_pointer + 8 > buffer->buffer_end)
		return 0;
	memcpy(&ret, buffer->buffer_pointer, 8);
	buffer->buffer_pointer += 8;
	return net_order_64(ret);
}

char *serializer_get_string(serialized_buffer_t *buffer)
{
	char *ptr = buffer->buffer_pointer, *start = buffer->buffer_pointer;

	if (ptr >= buffer->buffer_end)
		return NULL;
	while (ptr < buffer->buffer_end && *ptr)
		++ptr;
	// String did not terminate within buffer (possibly corrupted/malicious packet)
	if (*ptr)
		return NULL;
	buffer->buffer_pointer = ptr + 1;
	return start;
}

void serializer_put_uint8(serialized_buffer_t *buffer, uint8_t value)
{
	if (buffer->buffer_pointer + 1 > buffer->buffer_end)
		return;
	*buffer->buffer_pointer++ = (char)value;
}

void serializer_put_uint16(serialized_buffer_t *buffer, uint16_t value)
{
	if (buffer->buffer_pointer + 2 > buffer->buffer_end)
		return;
	value = net_order_16(value);
	memcpy(buffer->buffer_pointer, &value, 2);
	buffer->buffer_pointer += 2;
}

void serializer_put_uint64(serialized_buffer_t *buffer, uint64_t value)
{
	if (buffer->buffer_pointer + 8 > buffer->buffer_end)
		return;
	value = net_order_64(value);
	memcpy(buffer->buffer_pointer, &value, 8);
	buffer->buffer_pointer += 8;
}

void serializer_put_string(serialized_buffer_t *buffer, const char *value)
{
	const size_t len = strlen(value) + 1;

	if (buffer->buffer_pointer + len > buffer->buffer_end)
		return;
	memcpy(buffer->buffer_pointer, value, len);
	buffer->buffer_pointer += len;
}

uint32_t serializer_get_written_length(serialized_buffer_t *buffer)
{
	return (uint32_t)(buffer->buffer_pointer - buffer->buffer);
}
