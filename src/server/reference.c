#ifndef unlikely
#define unlikely(x) (x)
#endif
#include "reference.h"
#include <stdio.h>
#include <stdlib.h>

void ref_init( ref *reference, void ( *freefun )( ref * ), long count )
{
	reference->count = count;
	reference->free = freefun;
}

_Noreturn void _ref_error( const char *message )
{
	fprintf( stderr, "%s\n", message );
	abort();
}

void ref_setref( weakref *weakref, ref *ref )
{
	union _aligned_ref_ *new_weakref = 0;
	if ( ref ) {
		( new_weakref = aligned_ref( ref->_aligned_ref ) )->ref = ref;
		ref->count += sizeof( union _aligned_ref_ ) + 1;
	}
	char *old_weakref = (char *)atomic_exchange( weakref, new_weakref );
	if ( !old_weakref )
		return;
	struct _ref_ *old_ref = aligned_ref( old_weakref )->ref;
	old_ref->count += old_weakref - (char *)aligned_ref( old_weakref ) - sizeof( union _aligned_ref_ );
	ref_put( old_ref );
}
