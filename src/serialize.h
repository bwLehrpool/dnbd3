#ifndef SERIALIZER_H_
#define SERIALIZER_H_

#include "config.h"

typedef struct
{
	char buffer[MAX_PAYLOAD]; // This MUST be the first member or send_reply() will blow up
	char *buffer_end;
	char *buffer_pointer;
} serialized_buffer_t;

void serializer_reset_read(serialized_buffer_t *buffer, size_t data_len);

void serializer_reset_write(serialized_buffer_t *buffer);

ssize_t serializer_get_written_length(serialized_buffer_t *buffer);

//

uint8_t serializer_get_uint8(serialized_buffer_t *buffer);

uint16_t serializer_get_uint16(serialized_buffer_t *buffer);

uint64_t serializer_get_uint64(serialized_buffer_t *buffer);

char* serializer_get_string(serialized_buffer_t *buffer);

//

void serializer_put_uint8(serialized_buffer_t *buffer, uint16_t value);

void serializer_put_uint16(serialized_buffer_t *buffer, uint16_t value);

void serializer_put_uint64(serialized_buffer_t *buffer, uint64_t value);

void serializer_put_string(serialized_buffer_t *buffer, char *value);

#endif
