#include "urldecode.h"
#include <stdlib.h>
#include <ctype.h>

#define hex2int(a) do { \
			if ( a >= 'a' ) {                           \
				a = (char)(a - ( 'a' - 'A' - 10 ));      \
			} else if ( a > 'F' ) {                     \
				goto normie;                             \
			} else if ( a >= 'A' ) {                    \
				a = (char)(a - ( 'A' - 10 ));            \
			} else if ( a < '0' || a > '9' ) {          \
				goto normie;                             \
			} else {                                    \
				a = (char)(a - '0');                     \
			}                                           \
} while (0)

void urldecode(struct string* str, struct field *out, size_t *out_num)
{
	char *src = (char*)str->s;
	char *dst = src;
	const char * const end = str->s + str->l;
	char a, b;
	size_t max_out = *out_num;
	*out_num = 0;
	do {
		if ( *out_num == max_out ) return;
		out->name.s = dst;
		while ( src < end && *src != '=' ) {
			*dst++ = *src++;
		}
		if ( src == end ) return;
		out->name.l = (size_t)( dst - out->name.s );
		++src;
		out->value.s = ++dst;
		while ( src < end && *src != '&' ) {
			if ( *src == '%' && src + 2 < end ) {
				if ( src[1] > 'f' || src[2] > 'f' ) goto normie;
				a = src[1];
				hex2int(a);
				b = src[2];
				hex2int(b);
				*dst++ = (char)( (16 * a) + b );
				src += 3;
			} else if (*src == '+') {
				*dst++ = (char)' ';
				++src;
			} else {
	normie:;
				*dst++ = *src++;
			}
		}
		out->value.l = (size_t)( dst - out->value.s );
		out++;
		(*out_num)++;
		if ( src++ >= end ) return;
		++dst;
	} while ( 1 );
}

