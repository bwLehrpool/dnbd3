#ifndef _URLENCODE_H_
#define _URLENCODE_H_

#include "picohttpparser/picohttpparser.h"

struct field {
	struct string name;
	struct string value;
};

/**
 * decode given x-form-urlencoded string. Breaks constness rules by
 * casting the const char* s from str to char* and modifying it, then
 * populating out with pointers into it, so make sure the memory
 * is actually writable.
 */
void urldecode(struct string* str, struct field *out, size_t *out_num);

#endif
