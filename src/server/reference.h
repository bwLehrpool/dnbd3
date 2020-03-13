#ifndef _REFERENCE_H_
#define _REFERENCE_H_

#include "reftypes.h"
#include <stddef.h>
#include <stdint.h>

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - (char *)&(((type *)NULL)->member)))

void ref_init( ref *reference, void ( *freefun )( ref * ), long count );

void ref_setref( weakref *weakref, ref *ref );

_Noreturn void _ref_error( const char *message );

static inline ref *ref_get( weakref *weakref )
{
	char *old_weakref = (char *)*weakref;
	do {
		if ( old_weakref == NULL )
			return NULL;
		if ( aligned_ref( old_weakref ) != aligned_ref( old_weakref + 1 ) ) {
			old_weakref = (char *)*weakref;
			continue;
		}
	} while ( !atomic_compare_exchange_weak( weakref, (void **)&old_weakref, old_weakref + 1 ) );
	struct _ref_ *ref = aligned_ref( old_weakref )->ref;
	if ( unlikely( ++ref->count == -1 ) ) {
		_ref_error( "Reference counter overflow. Aborting." );
	}
	char *cur_weakref = ( char * )*weakref;
	do {
		if ( aligned_ref( cur_weakref ) != aligned_ref( old_weakref ) ) {
			ref->count--;
			break;
		}
	} while ( !atomic_compare_exchange_weak( weakref, (void **)&cur_weakref, cur_weakref - 1 ) );
	return ref;
}

static inline void ref_inc( ref *ref )
{
	++ref->count;
}

static inline void ref_put( ref *ref )
{
	if ( --ref->count == 0 ) {
		ref->free( ref );
	}
}

#define ref_get_uplink(wr) __extension__({ \
	ref* ref = ref_get( wr ); \
	ref == NULL ? NULL : container_of(ref, dnbd3_uplink_t, reference); \
})

#define ref_get_cachemap(image) __extension__({ \
	ref* ref = ref_get( &(image)->ref_cacheMap ); \
	ref == NULL ? NULL : container_of(ref, dnbd3_cache_map_t, reference); \
})

#endif
