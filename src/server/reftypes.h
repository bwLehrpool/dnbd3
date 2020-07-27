#ifndef _REFTYPES_H_
#define _REFTYPES_H_

#include <stdatomic.h>

_Static_assert( sizeof( void * ) == sizeof( _Atomic( void * ) ), "Atomic pointer bad" );

typedef _Atomic( void * ) weakref;

#define aligned_ref(ptr) \
	((union _aligned_ref_ *)((ptr) - (uintptr_t)(ptr) % sizeof(union _aligned_ref_)))

union _aligned_ref_ {
	struct _ref_ *ref;
	void *_padding[( 32 - 1 ) / sizeof( void * ) + 1];
};

typedef struct _ref_ {
	_Atomic long count;
	void ( *free )( struct _ref_ * );
	char _padding[sizeof( union _aligned_ref_ )];
	char _aligned_ref[sizeof( union _aligned_ref_ )];
} ref;

#endif
