		/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2025 Sebastian Vater <sebastian.vater@rz.uni-freiburg.de>
 *
 * This file may be licensed under the terms of the
 * GNU General Public License Version 2 (the ``GPL'').
 *
 * Software distributed under the License is distributed
 * on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied. See the GPL for the specific language
 * governing rights and limitations.
 *
 * You should have received a copy of the GPL along with this
 * program. If not, go to http://www.gnu.org/licenses/gpl.html
 * or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dnbd3/shared/log.h>
#include "iscsi.h"

/**
 * @file iscsi.c
 * @author Sebastian Vater
 * @date 16 Jul 2025
 * @brief iSCSI implementation for DNBD3.
 *
 * This file contains the iSCSI implementation according to
 * RFC7143 for dnbd3-server.
 * All server-side network sending and client-side network
 * receiving code is done here.
 * @see https://www.rfc-editor.org/rfc/rfc7143
 */

/**
 * Merges multiple strings using printf style formatting
 * and allocates memory for holding the result.
 *
 * @param[in] buf Buffer to merge into.
 * @param[in] format printf style format string.
 * @param[in] args Values to fill in the format with.
 * @return New buffer which holds the final result.
 */
uint8_t *iscsi_vsprintf_append_realloc(char *buf, const char *format, va_list args)
{
	va_list args_copy;
	uint orig_size = 0;

	if ( buf != NULL )
		orig_size = strlen( (char *) buf );

	va_copy( args_copy, args );
	uint new_size = vsnprintf( NULL, 0, format, args_copy );
	va_end( args_copy );

	new_size += orig_size + 1;

	uint8_t *new_buf = realloc( buf, new_size );

	if ( new_buf == NULL ) {
		logadd( LOG_ERROR, "iscsi_vsprintf_append_realloc: Out of memory while allocating string buffer" );

		return NULL;
	}

	vsnprintf( (char *) new_buf + orig_size, (new_size - orig_size), format, args );

	return new_buf;
}

/**
 * Merges strings using printf style formatting and allocates
 * memory for holding the result.
 *
 * @param[in] buf Buffer to merge into.
 * @param[in] format printf style format string.
 * @param[in] ... Values to fill in the format string with.
 * @return New buffer which holds the final result.
 */
uint8_t *iscsi_sprintf_append_realloc(char *buf, const char *format, ...)
{
	va_list args;

	va_start( args, format );
	uint8_t *ret_buf = iscsi_vsprintf_append_realloc( buf, format, args );
	va_end( args );

	return ret_buf;
}

/**
 * Merges strings using printf style formatting and allocates
 * memory for holding the result.
 *
 * @param[in] format printf style format string.
 * @param[in] args Values to fill in the format with.
 * @return New buffer which holds the final result.
 */
uint8_t *iscsi_vsprintf_alloc(const char *format, va_list args)
{
	return iscsi_vsprintf_append_realloc( NULL, format, args );
}

/**
 * Allocates a buffer large enough to hold printf style
 * string concatenation and fills it using vspnrintf.
 *
 * @param[in] format Format string  to allocate and fill.
 * @param[in] ... Values to fill in the format string with.
 * @return New buffer containing the formatted string.
 */
uint8_t *iscsi_sprintf_alloc(const char *format, ... )
{
	va_list args;

	va_start( args, format );
	uint8_t *buf = iscsi_vsprintf_alloc( format, args );
	va_end( args );

	return buf;
}

/**
 * Creates a ultra hardcore speed optimized empty hash map and
 * allocates enough buckets to hold default capacity elements.
 * The speed optimizations require all keys having a size of
 * a multiple of 8 bytes with zero padding. Also the capacity
 * always nas to be a power of two.
 * TODO: Move all hash map related functions to different source file
 * later and implement in a lock-free way for better concurrency.
 *
 * @param[in] capacity Desired initial capacity, will be rounded up
 * to the nearest power of two. If set to 0, a default capacity of
 * 32 buckets will be used instead.
 * @return A pointer to the hash map structure or NULL in case of an error.
 */
iscsi_hashmap *iscsi_hashmap_create(const uint capacity)
{
	iscsi_hashmap *map = (iscsi_hashmap *) malloc( sizeof(iscsi_hashmap) );

	if ( map == NULL ) {
		logadd( LOG_ERROR, "iscsi_hashmap_create: Out of memory while allocating iSCSI hash map" );

		return map;
	}

	if ( capacity > 0UL ) {
		uint new_capacity = (capacity + 1); // 1UL << (lg(capacity - 1) + 1)

		new_capacity |= (new_capacity >>  1UL);
		new_capacity |= (new_capacity >>  2UL);
		new_capacity |= (new_capacity >>  4UL);
		new_capacity |= (new_capacity >>  8UL);
		new_capacity |= (new_capacity >> 16UL);

		map->capacity = ++new_capacity; // Round up actual new capacity to nearest power of two
	} else {
		map->capacity = ISCSI_HASHMAP_DEFAULT_CAPACITY;
	}

	map->buckets = (iscsi_hashmap_bucket *) calloc( map->capacity, sizeof(struct iscsi_hashmap_bucket) );

	if ( map->buckets == NULL ) {
		free( map );

		logadd( LOG_ERROR, "iscsi_hashmap_create: Out of memory while allocating iSCSI hash map buckets" );

		return NULL;
	}

	map->cap_load      = (map->capacity * 3UL) >> 2UL; // 75% of capacity
	map->count         = 0;
	map->removed_count = 0;
	map->first         = NULL;
	map->last          = (iscsi_hashmap_bucket *) &map->first;

	return map;
}

/**
 * Deallocates all buckets and the hash map itself allocated
 * by iscsi_hashmap_create. The elements associated with the
 * buckets are NOT freed by this function, this has to be done
 * either manually or using the function iscsi_hashmap_iterate.
 *
 * @param[in] map Pointer to hash map and its buckets to deallocate.
 * If this is NULL, nothing is done.
 */
void iscsi_hashmap_destroy(iscsi_hashmap *map)
{
	if ( map != NULL ) {
		if ( map->buckets != NULL )
			free( map->buckets );

		free( map );
	}
}

/**
 * Puts an old bucket into a resized hash map.
 *
 * @param[in] map Pointer to resized hash map, may NOT be NULL, so
 * be careful.
 * @param[in] old_entry The old bucket to be put into the resized
 * hash map.
 * @return New bucket where the bucket has been put into.
 */
static iscsi_hashmap_bucket *iscsi_hashmap_resize_entry(iscsi_hashmap *map, const iscsi_hashmap_bucket *old_entry)
{
	uint32_t index = old_entry->hash & (map->capacity - 1);

	for ( ;; ) {
		iscsi_hashmap_bucket *entry = &map->buckets[index];

		if ( entry->key == NULL ) {
			*entry = *old_entry;

			return entry;
		}

		index = (index + 1) & (map->capacity - 1);
	}
}

/**
 * Resizes a hash map by doubling its bucket capacity. if any
 * buckets have been removed, they are finally purged. The
 * old bucket list is freed after the resize operation has
 * been finished.
 *
 * @param[in] map Pointer to hash map to resize. This may NOT be
 * NULL, so be careful.
 * @retval -1 An error occured during resize.
 * @retval 0 Hash map has been resized successfully.
 */
static int iscsi_hashmap_resize(iscsi_hashmap *map)
{
	const uint old_capacity           = map->capacity;
	iscsi_hashmap_bucket *old_buckets = map->buckets;

	map->capacity <<= ISCSI_HASHMAP_RESIZE_SHIFT;

	map->buckets = (iscsi_hashmap_bucket *) calloc( map->capacity, sizeof(struct iscsi_hashmap_bucket) );

	if ( map->buckets == NULL ) {
		map->capacity = old_capacity;
		map->buckets  = old_buckets;

		return -1;
	}

	map->cap_load      = (map->capacity * 3UL) >> 2UL; // 75% of capacity
	map->last          = (iscsi_hashmap_bucket *) &map->first;
	map->count        -= map->removed_count;
	map->removed_count = 0;

	do {
		iscsi_hashmap_bucket *current = map->last->next;

		if ( current->key == NULL ) {
			map->last->next = current->next;

			continue;
		}

		map->last->next = iscsi_hashmap_resize_entry(map, map->last->next);
		map->last       = map->last->next;
	} while ( map->last->next != NULL );

	free( old_buckets );

	return 0;
}

/**
 * Calculates the hash code of data with a specified length.
 *
 * @param[in] data Pointer to data to be hashed, NULL is NOT
 * an allowed here, so be careful. Data needs 8 byte alignment
 * and needs to be zero padded.
 * @param[in] len Number of bytes of hash data, must be larger
 * than 0 and is rounded up to the nearest 8 byte integer prior
 * calculating the hash code, so be careful.
 * @return Hash code of data.
 */
static inline uint32_t iscsi_hashmap_hash_data(const uint8_t *data, const size_t len)
{
	const uint64_t *hash_data = (const uint64_t *) data;
	size_t num_blocks = iscsi_align(len, ISCSI_HASHMAP_KEY_ALIGN) >> ISCSI_HASHMAP_KEY_ALIGN_SHIFT;
	uint64_t hash = ISCSI_HASHMAP_HASH_INITIAL;

	do {
		hash ^= *hash_data++;
		hash *= ISCSI_HASHMAP_HASH_MUL;
	} while ( --num_blocks > 0UL );

	return (uint32_t) (hash ^ hash >> 32ULL);
}

/**
 * Finds a bucket by key of a specified hash map by
 * key, key size and hash code. This function may
 * only be called if the bucket is guaranteed to
 * be found, otherwise this function hangs, so be
 * careful.
 *
 * @param[in] map Pointer to hash map where the key to be
 * searched for is located, may NOT be NULL, so be careful.
 * @param[in] key Pointer to key. NULL is invalid, so be
 * careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] hash Hash of the key to be searched for.
 * @return Pointer to found bucket.
 */
static iscsi_hashmap_bucket *iscsi_hashmap_find_entry(iscsi_hashmap *map, const uint8_t *key, size_t key_size, uint32_t hash)
{
	uint32_t index = hash & (map->capacity - 1);

	for ( ;; ) {
		iscsi_hashmap_bucket *entry = &map->buckets[index];

		if ( (entry->key == NULL && entry->value == NULL) || (entry->key != NULL && entry->key_size == key_size && entry->hash == hash && (memcmp( entry->key, key, key_size ) == 0)) )
			return entry;

		index = (index + 1) & (map->capacity - 1);
	}
}

/**
 * Creates a key from data and size and ensures
 * its requirements for usage in hash map buckets.
 * Currently keys to be used in a hash map bucket
 * require a size of multiple by 8 bytes with
 * the zero padding.
 *
 * @param[in] data Pointer to data to construct the key
 * from and may NOT be NULL, so be careful.
 * @param[in] len Length of the data to construct the key
 * from, MUST be larger than 0, so be careful.
 * @return Pointer to generated usable key or NULL in
 * case of an error (usually memory exhaustion).
 */
uint8_t *iscsi_hashmap_key_create(const uint8_t *data, const size_t len)
{
	const size_t key_size = iscsi_align(len, ISCSI_HASHMAP_KEY_ALIGN);
	uint8_t *key = (uint8_t *) malloc( key_size );

	if ( key == NULL ) {
		logadd( LOG_ERROR, "iscsi_hashmap_key_create: Out of memory while allocating iSCSI hash map key" );

		return key;
	}

	memcpy( key, data, len );
	memset( key + len, 0, (key_size - len) ); // Zero pad additional bytes in case length is not a multiple of 8

	return key;
}

/**
 * Deallocates a key allocated with the function
 * iscsi_hashmap_key_create.
 *
 * @param[in] key Pointer to key to deallocate, may NOT
 * be NULL, so be careful.
 */
void iscsi_hashmap_key_destroy(uint8_t *key) {
	free( key );
}

/**
 * Default callback function for deallocation of
 * allocated hash map resources by simply calling
 * free.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[in] value Value of the key, NULL is allowed.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_hashmap_key_destroy_value_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	if ( value != NULL )
		free( value );

	iscsi_hashmap_key_destroy( key );

	return 0L;
}

/**
 * Adds a key / value pair to a specified hash map
 * bucket list, if it doesn't exist already. The
 * buckets are resized automatically if required.
 * This function neither does make a copy of the key,
 * nor of the value. Keys should be allocated using
 * the function iscsi_hashmap_key_create or freed by
 * using iscsi_hashmap_key_destroy in order to
 * ensure the alignment and padding requirements.
 *
 * @param[in] map Pointer to hash map where the key and
 * value pair should be added to, may NOT be NULL, so
 * be careful.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[in] value Value of the key to add, NULL is
 * allowed.
 * @retval -1 Adding key / value pair would have required
 * hash map resizing which failed (probably due to
 * memory exhaustion).
 * @retval 0 Key / value pair was added successfully.
 */
int iscsi_hashmap_put(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t *value)
{
	if ( ((map->count + 1) > map->cap_load) && (iscsi_hashmap_resize( map ) < 0) )
		return -1;

	const uint32_t hash = iscsi_hashmap_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key == NULL ) {
		map->last->next = entry;
		map->last       = entry;
		entry->next     = NULL;

		map->count++;

		entry->key      = key;
		entry->key_size = key_size;
		entry->hash     = hash;
	}

	entry->value = value;

	return 0;
}

/**
 * Adds a key / value pair if it doesn't exist
 * using the value of `*out_in_val`. If the pair
 * does exist, value will be set in `*out_in`,
 * meaning the value of the pair will be in
 * '*out_in` regardless of whether or not it it
 * existed in the first place.
 * The buckets are resized automatically if required.
 * This function neither does make a copy of the key,
 * nor of the value. Keys should be allocated using
 * the function iscsi_hashmap_key_create or freed by
 * using iscsi_hashmap_key_destroy in order to
 * ensure the alignment and padding requirements.
 *
 * @param[in] map Pointer to hash map where the key and
 * value pair should be added to, may NOT be NULL, so
 * be careful.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[in,out] out_in_value Value of the key to add,
 * NULL is allowed.
 * @retval -1 Adding key / value pair would have required
 * hash map resizing which failed (probably due to
 * memory exhaustion).
 * @retval 0 Key / value pair was added successfully.
 * @retval 1 Key already existed.
 */
int iscsi_hashmap_get_put(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t **out_in_value)
{
	if ( ((map->count + 1) > map->cap_load) && (iscsi_hashmap_resize( map ) < 0) )
		return -1;

	const uint32_t hash = iscsi_hashmap_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key == NULL ) {
		map->last->next = entry;
		map->last       = entry;
		entry->next     = NULL;

		map->count++;

		entry->value    = *out_in_value;
		entry->key      = key;
		entry->key_size = key_size;
		entry->hash     = hash;

		return 0;
	}

	*out_in_value = entry->value;

	return 1;
}

/**
 * Adds a key / value pair to a specified hash map
 * bucket list. If the key already exists, it will
 * be overwritten and a callback function will be
 * invoked in order to allow, e.g. deallocation of
 * resources, if necessary. The buckets are resized
 * automatically if required. This function neither
 * does make a copy of the key, nor of the value.
 * Keys should be allocated using the function
 * iscsi_hashmap_key_create or freed by using
 * iscsi_hashmap_key_destroy in order to ensure the
 * alignment and padding requirements.
 *
 * @param[in] map Pointer to hash map where the key and
 * value pair should be added to, may NOT be NULL, so
 * be careful.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[in] value Value of the key to add, NULL is
 * allowed.
 * @param[in] callback Callback function which allows,
 * for example, a dallocation of resources for the
 * overwritten key and value pair. The function is
 * invoked just before overwriting the old values.
 * This may NOT be NULL, so take caution.
 * @param[in] user_data Pointer to user specific data
 * passed to the callback function in case more
 * information is needed.
 * @return -1 in case adding key / value pair would
 * have required hash map resizing which failed
 * (probably due to memory exhaustion), 0 if the
 * Key / value pair was added successfully and
 * the callback function also returned 0, otherwise
 * the return value got by the callbuck function.
 */
int iscsi_hashmap_put_free(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t *value, iscsi_hashmap_callback callback, uint8_t *user_data)
{
	if ( ((map->count + 1) > map->cap_load) && (iscsi_hashmap_resize( map ) < 0) )
		return -1;

	const uint32_t hash = iscsi_hashmap_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key == NULL ) {
		map->last->next = entry;
		map->last       = entry;
		entry->next     = NULL;

		map->count++;

		entry->key      = key;
		entry->key_size = key_size;
		entry->hash     = hash;
		entry->value    = value;

		return 0;
	}

	int err = callback( entry->key, key_size, entry->value, user_data );

	entry->key   = key;
	entry->value = value;

	return err;
}

/**
 * Checks whether a specified key exists in a hash map.
 *
 * @param[in] map Pointer to the hash map to be searched
 * for the key to check for existence and may not be
 * NULL, so take caution.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @retval TRUE The key exists.
 * @retval FALSE The key does not exist.
 */
int iscsi_hashmap_contains(iscsi_hashmap *map, const uint8_t *key, const size_t key_size)
{
	const uint32_t hash = iscsi_hashmap_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	return entry->key != NULL;
}

/**
 * Retrieves the value of a specified key from a hash map. Since the
 * hash map supports NULL values, it is stored in an output variable.
 *
 * @param[in] map Pointer to the hash map to be searched
 * for the key of which the value should be retrieved and
 * may not be NULL, so take caution.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[out] out_value Pointer where the value of the found key
 * is stored, maybe NULL if either the key's value is NULL or
 * in case the key was not found. The pointer to the value itself
 * may NOT be NULL, so be careful.
 * @retval TRUE The key has been found and its value stored
 * in the 'out_value' parameter.
 * @retval FALSE The key has not been found and NULL has been
 * stored in the 'out_value' parameter.
 */
int iscsi_hashmap_get(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t **out_value)
{
	const uint32_t hash = iscsi_hashmap_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	*out_value = entry->value;

	return entry->key != NULL;
}

/**
 * Removes an element from the bucket list of the hash map.
 * Buckets are marked as removed by setting their key and
 * value to NULL. The actual removal will be done upon next
 * resize operation. If the specified key already has been
 * removed, this function will do nothing.
 *
 * @param[in] map Pointer to the hash map to remove from
 * and may not be NULL, so take caution.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 */
void iscsi_hashmap_remove(iscsi_hashmap *map, const uint8_t *key, const size_t key_size)
{
	const uint32_t hash = iscsi_hashmap_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key != NULL ) {
		entry->key   = NULL;
		entry->value = NULL;

		map->removed_count++;
	}
}

/**
 * Removes an element from the bucket list of the hash map.
 * Buckets are marked as removed by setting their key and
 * value to NULL. The actual removal will be done upon next
 * resize operation. A callback function is invoked if the
 * key to be removed is found in the bucket list and allows,
 * e.g. to free any resources associated with the key. If
 * the key is not found, this function will do nothing.
 *
 * @param[in] map Pointer to the hash map to remove from
 * and may not be NULL, so take caution.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[in] callback Callback function which allows,
 * for example, a dallocation of resources for the
 * key and value pair to be removed. The function is
 * invoked just before marking the key / value pair
 * as removed. This may NOT be NULL, so take caution.
 * @param[in] user_data Pointer to user specific data
 * passed to the callback function in case more
 * information is needed.
 */
void iscsi_hashmap_remove_free(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, iscsi_hashmap_callback callback, uint8_t *user_data)
{
	const uint32_t hash = iscsi_hashmap_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key != NULL ) {
		callback( entry->key, entry->key_size, entry->value, user_data );

		entry->key   = NULL;
		entry->value = NULL;

		map->removed_count++;
	}
}

/**
 * Returns the number of elements stored in the specified
 * hash map. Elements marked for removal are not included.
 *
 * @param[in] map Pointer to the hash map to count the
 * number of elements, may NOT be NULL, so take caution.
 * @return Number of elements currently in use by the
 * hash map. Buckets marked for removal are not counted.
 */
int iscsi_hashmap_size(iscsi_hashmap *map)
{
	return (map->count - map->removed_count);
}

/**
 * An iterator through the elements of a specified
 * hash map which uses a callback function for each
 * element not marked for removal, which also can
 * abort the iteration, if necessary.
 *
 * @param[in] map Pointer to the hash map to iterate
 * through, may NOT be NULL, so take caution.
 * @param[in] callback Callback function to be
 * invoked for each element not marked for removal
 * in the hash map. If the return value of the callback
 * function is below zero, the iteration will stop.
 * @param[in] user_data Pointer to user specific data
 * passed to the callback function in case more
 * information is needed.
 * @return The return code from the last invoked
 * callback function. A negative value indicates an
 * abortion of the iteration process.
 */
int iscsi_hashmap_iterate(iscsi_hashmap *map, iscsi_hashmap_callback callback, uint8_t *user_data)
{
	iscsi_hashmap_bucket *current = map->first;
	int err = 0;

	while ( current != NULL ) {
		if ( current->key != NULL ) {
			err = callback( current->key, current->key_size, current->value, user_data );

			if ( err < 0 )
				break;
		}

		current = current->next;
	}

	return err;
}

/**
 * Allocates an iSCSI packet data Basic Header Segment (BHS)
 * and zero fills the structure.
 *
 * @return a pointer to BHS structure with all fields
 * initialized or NULL if the allocation failed.
 */
iscsi_bhs_packet *iscsi_create_packet()
{
	iscsi_bhs_packet *bhs_pkt = (iscsi_bhs_packet *) malloc( sizeof(struct iscsi_bhs_packet) );

	if ( bhs_pkt == NULL ) {
		logadd( LOG_ERROR, "iscsi_create_packet: Out of memory while allocating BHS iSCSI packet data" );

		return bhs_pkt;
	}

    bhs_pkt->opcode = 0; // Initialize everything to zero
    bhs_pkt->opcode_fields[0] = 0;
    bhs_pkt->opcode_fields[1] = 0;
    bhs_pkt->opcode_fields[2] = 0;
	bhs_pkt->total_ahs_len = 0;
	bhs_pkt->ds_len[0] = 0;
	bhs_pkt->ds_len[1] = 0;
	bhs_pkt->ds_len[2] = 0;
	bhs_pkt->lun_opcode.lun = 0ULL;
	bhs_pkt->init_task_tag = 0UL;

	memset( bhs_pkt->opcode_spec_fields, 0, sizeof(bhs_pkt->opcode_spec_fields) );

	return bhs_pkt;
}

/**
 * Deallocates all aquired resources by iscsi_create_packet.
 *
 * @param[in] packet_data Pointer to packet data to deallocate. If this is
 * NULL, this function does nothing.
 */
void iscsi_destroy_packet(iscsi_bhs_packet *packet_data)
{
	if (packet_data != NULL)
		free( packet_data );
}

/**
 * Constructs and appends an Additional Header Segment (AHS) to already allocated
 * packet data. There is no guarantee that the pointer stays the same. Any references
 * to the old structure need to be updated!
 * This function currently throws away any data beyond AHS.
 *
 * @param[in] packet_data Pointer to packet data to append to. If NULL, a Basic
 * Header Segment (BHS) will be created and initialized before adding a first
 * AHS.
 * @param[in] ahs_len Length of AHS packet data to be appended.
 * @return New pointer to BHS structure with additional AHS attached or NULL in case
 * of an reallocation error or total AHS length exceeds 255 DWORD's.
 */
iscsi_bhs_packet *iscsi_append_ahs_packet(iscsi_bhs_packet *packet_data, const uint32_t ahs_len)
{
	if ( packet_data == NULL ) {
		packet_data = iscsi_create_packet();

		if ( packet_data == NULL )
			return packet_data;
	}

	const uint32_t old_pkt_size = (const uint32_t) sizeof(struct iscsi_bhs_packet) + (packet_data->total_ahs_len << 2UL);
	const uint32_t new_pkt_size = old_pkt_size + iscsi_align(ahs_len, ISCSI_ALIGN_SIZE);

	if ( new_pkt_size > (sizeof(struct iscsi_bhs_packet) + 1020UL) ) {
		logadd( LOG_ERROR, "iscsi_append_ahs_packet: Total numer of AHS packets exceeds 255 DWORDs" );

		return NULL;
	}

	packet_data = (iscsi_bhs_packet *) realloc( packet_data, new_pkt_size );

	if ( packet_data == NULL ) {
		logadd( LOG_ERROR, "iscsi_append_ahs_packet: Out of memory while allocating iSCSI AHS packet data for appending" );

		return packet_data;
	}

	iscsi_ahs_packet *ahs_pkt = (iscsi_ahs_packet *) ((uint8_t *) packet_data + old_pkt_size);
	ahs_pkt->len = iscsi_get_be16(ahs_len);
	ahs_pkt->type = 0;
	ahs_pkt->specific = 0;
	memset( ahs_pkt->data, 0, (new_pkt_size - old_pkt_size) - offsetof(struct iscsi_ahs_packet, data) );
	packet_data->total_ahs_len += (ahs_len + (ISCSI_ALIGN_SIZE - 1)) >> 2UL;

	return packet_data;
}

/**
 * Gets the total number of AHS packets.
 *
 * @param[in] packet_data Pointer to packet data of which the
 * number of AHS packets should be counted.
 * @return The number of AHS packets or zero in case none exist or
 * -1 in case of error.
 */
int iscsi_get_ahs_packets(const iscsi_bhs_packet *packet_data)
{
	if ( packet_data == NULL )
		return -1;
	else if ( packet_data->total_ahs_len == 0 )
		return 0;

	iscsi_ahs_packet *ahs_pkt = (iscsi_ahs_packet *) ((iscsi_bhs_packet *) packet_data + 1); // First AHS packet
	int count = 0L;
	uint32_t ahs_len = (uint32_t) packet_data->total_ahs_len << 2UL;

	while ( (int32_t) ahs_len > 0L ) {
		uint32_t len = iscsi_get_be16(ahs_pkt->len) + offsetof(struct iscsi_ahs_packet, data); // Total length of current AHS packet
		len = iscsi_align(len, ISCSI_ALIGN_SIZE);

		ahs_len -= len;
		ahs_pkt = ((uint8_t *) ahs_pkt) + (len - offsetof(struct iscsi_ahs_packet, data)); // Advance pointer to next AHS packet
		count++;
	}

	return count;
}

/**
 * Gets the pointer of an AHS packet by specified index.
 *
 * @param[in] packet_data Pointer to packet data of which the
 * AHS packet should be retrieved.
 * @param[in] index Zero-based index number of AHS packet to
 * be received.
 * @return The pointer to the AHS packet at specified index on
 * success or NULL in case of an error or if the specific index
 * is out of range.
 */
iscsi_ahs_packet *iscsi_get_ahs_packet(const iscsi_bhs_packet *packet_data, const int index)
{
	if ( packet_data == NULL || (packet_data->total_ahs_len == 0) )
		return NULL;

	iscsi_ahs_packet *ahs_pkt = (iscsi_ahs_packet *) ((iscsi_bhs_packet *) packet_data + 1); // First AHS packet
	int count = index;
	uint32_t ahs_len = (uint32_t) packet_data->total_ahs_len << 2UL;

	while ( (int32_t) ahs_len > 0L ) {
		if ( count-- < 0L )
			return ahs_pkt;

		uint32_t len = iscsi_get_be16(ahs_pkt->len) + offsetof(struct iscsi_ahs_packet, data); // Total length of current AHS packet
		len = iscsi_align(len, ISCSI_ALIGN_SIZE);

		ahs_len -= len;
		ahs_pkt = ((uint8_t *) ahs_pkt) + (len - offsetof(struct iscsi_ahs_packet, data)); // Advance pointer to next AHS packet
	}

	logadd( LOG_ERROR, "iscsi_get_ahs_packet: Specified index for AHS packet does not exist" );

	return NULL;
}

/**
 * Constructs and appends DataSegment (DS) to already allocated packet data.
 * There is no guarantee that the pointer stays the same. Any references
 * to the old structure need to be updated!
 * This function currently erases an already available DataSegment and
 * throws away any data beyond DS.
 *
 * @param[in] packet_data Pointer to BHS packet data to append to. If NULL, a Basic
 * Header Segment (BHS) will be created and initialized before adding the DataSegment.
 * @param[in] header_digest_size Length of optional header digest (0 or 4 for now) to
 * add.
 * @param[in] ds_len Length of DataSegment packet data to be appended. May
 * not exceed 16MiB - 1 (16777215 bytes).
 * @param[in] data_digest_size Length of optional data digest (0 or 4 for now) to
 * add.
 * @return New pointer to BHS structure with additional DataSegment attached or
 * NULL in case of an reallocation error, either header or data digest size does not
 * confirm to the iSCSI standard or DS length exceeds 16777215 bytes.
 */
iscsi_bhs_packet *iscsi_append_ds_packet(iscsi_bhs_packet *packet_data, const int header_digest_size, const uint32_t ds_len, const int data_digest_size)
{
	if ( ((header_digest_size != 0) && header_digest_size != ISCSI_DIGEST_SIZE) || ((data_digest_size != 0) && data_digest_size != ISCSI_DIGEST_SIZE) || (ds_len >= 16777216UL) )
		return NULL;

	if ( packet_data == NULL ) {
		packet_data = iscsi_create_packet();

		if ( packet_data == NULL )
			return packet_data;
	}

	const uint32_t old_pkt_size = (const uint32_t) sizeof(struct iscsi_bhs_packet) + ((uint32_t) packet_data->total_ahs_len << 2UL);
	const uint32_t new_pkt_size = old_pkt_size + header_digest_size + iscsi_align(ds_len, ISCSI_ALIGN_SIZE) + data_digest_size;

	packet_data = (iscsi_bhs_packet *) realloc( packet_data, new_pkt_size );

	if ( packet_data == NULL ) {
		logadd( LOG_ERROR, "iscsi_append_ds_packet: Out of memory while allocating iSCSI DS packet data for appending" );

		return packet_data;
	}

	iscsi_put_be24( packet_data->ds_len, ds_len );
	memset( ((uint8_t *) packet_data) + old_pkt_size, 0, (new_pkt_size - old_pkt_size) );

	return packet_data;
}

static const uint32_t crc32c_lut[] = { // Created with a polynomial reflect value of 0x82F63B78
	0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
	0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
	0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
	0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
	0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
	0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
	0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
	0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
	0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
	0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
	0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
	0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
	0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
	0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
	0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
	0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
	0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
	0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
	0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
	0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
	0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
	0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
	0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D, 0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
	0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
	0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
	0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
	0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
	0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
	0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
	0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
	0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
	0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351};

/**
 * Calculates CRC32C with 0x82F63B78 polynomial reflect according to iSCSI specs
 * TODO: Implement optimized SSE4.2 and ARM versions
 *
 * @param[in] data Pointer to data to calculate CRC32C for.
 * @param[in] len Length of data to be calculated. Must be
 * divisable by 4 which is guaranteed by iSCSI standard.
 * @param[in] crc32c Previous CRC32C in case of multiple passes.
 * @return CRC32C value. THis function cannot fail.
 */
static inline uint32_t iscsi_crc32c_update(const uint8_t *data, const uint len, uint32_t crc32c)
{
	for ( uint i = 0; i < len; i += 4 ) {
		crc32c = (crc32c >> 8UL) ^ crc32c_lut[(crc32c ^ data[i]) & 0xFF];
		crc32c = (crc32c >> 8UL) ^ crc32c_lut[(crc32c ^ data[i + 1]) & 0xFF];
		crc32c = (crc32c >> 8UL) ^ crc32c_lut[(crc32c ^ data[i + 2]) & 0xFF];
		crc32c = (crc32c >> 8UL) ^ crc32c_lut[(crc32c ^ data[i + 3]) & 0xFF];
	}

	return crc32c;
}

/**
 * Calculates header digest (CRC32C) with 0x82F63B78 polynomial reflect
 * according to iSCSI specs and stores the result in the iSCSI packet
 * data. This function cannot fail.
 *
 * @param[in] packet_data Pointer to ISCSI BHS packet to calculate CRC32C for.
 */
void iscsi_calc_header_digest(const iscsi_bhs_packet *packet_data)
{
	const uint32_t len = sizeof(struct iscsi_bhs_packet) + ((const uint32_t) packet_data->total_ahs_len << 2UL);
	uint8_t *hdr_digest = ((uint8_t *) packet_data) + len;
	const uint32_t crc32c = iscsi_crc32c_update( (const uint8_t *) packet_data, iscsi_align(len, 4), ISCSI_CRC32C_INITIAL ) ^ ISCSI_CRC32C_XOR;

	iscsi_put_be32( hdr_digest, crc32c );
}

/**
 * Verifies header digest (CRC32C) with 0x82F63B78 polynomial reflect
 * according to iSCSI specs. This function cannot fail.
 *
 * @param[in] packet_data Pointer to ISCSI BHS packet to validate CRC32C for.
 * @return True if CRC32C matches the stored value, false otherwise.
 */
int iscsi_validate_header_digest(const iscsi_bhs_packet *packet_data)
{
	const uint32_t len = sizeof(struct iscsi_bhs_packet) + ((const uint32_t) packet_data->total_ahs_len << 2UL);
	const uint8_t *hdr_digest = ((uint8_t *) packet_data) + len;
	const uint32_t pkt_crc32c = *(uint32_t *) hdr_digest;
	const uint32_t crc32c = iscsi_crc32c_update( (const uint8_t *) packet_data, len, ISCSI_CRC32C_INITIAL ) ^ ISCSI_CRC32C_XOR;

	return iscsi_get_be32(pkt_crc32c) == crc32c;
}

/**
 * Calculates data digest (CRC32) with 0x82F63B78 polynomial reflect
 * of a whole DataSegment (CRC32C) according to the iSCSI specs.
 * The resulting CRC32C will be stored in the iSCSI packet.
 *
 * @param[in] packet_data Pointer to ISCSI DS packet to calculate CRC32C for.
 * @param[in] header_digest_size Length of optional header digest (0 or 4 for now) in
 * order to calculate correct DataSegment index. The header digest size IS NOT checked
 * for conforming to iSCSI specs, so be careful.
 */
void iscsi_calc_data_digest(const iscsi_bhs_packet *packet_data, const int header_digest_size)
{
	const uint32_t ds_idx = (const uint32_t) sizeof(struct iscsi_bhs_packet) + ((const uint32_t) packet_data->total_ahs_len << 2UL) + header_digest_size;
	const uint8_t *data = ((uint8_t *) packet_data) + ds_idx;
	const uint32_t ds_len = iscsi_get_be24(packet_data->ds_len);
	const uint32_t len = iscsi_align(ds_len, 4);
	uint8_t *data_digest = ((uint8_t *) packet_data) + ds_idx + len;
	const uint32_t crc32c = iscsi_crc32c_update( data, len, ISCSI_CRC32C_INITIAL ) ^ ISCSI_CRC32C_XOR;

	iscsi_put_be32( data_digest, crc32c );
}

/**
 * Verifies data digest (CRC32C) with 0x82F63B78 polynomial reflect
 * according to iSCSI specs. This function cannot fail.
 *
 * @param[in] packet_data Pointer to ISCSI BHS packet to calculate CRC32C for.
 * @param[in] header_digest_size Length of optional header digest (0 or 4 for now) in
 * order to calculate correct DataSegment index. The header digest size IS NOT checked
 * for conforming to iSCSI specs, so be careful.
 * @return True if CRC32C matches the stored value, false otherwise.
 */
int iscsi_validate_data_digest(const iscsi_bhs_packet *packet_data, const int header_digest_size)
{
	const uint32_t ds_idx = (const uint32_t) sizeof(struct iscsi_bhs_packet) + ((const uint32_t) packet_data->total_ahs_len << 2UL) + header_digest_size;
	const uint8_t *data = ((uint8_t *) packet_data) + ds_idx;
	const uint32_t ds_len = iscsi_get_be24(packet_data->ds_len);
	const uint32_t len = iscsi_align(ds_len, 4);
	const uint8_t *data_digest = data + len;
	const uint32_t pkt_crc32c = *(uint32_t *) data_digest;
	const uint32_t crc32c = iscsi_crc32c_update( (const uint8_t *) data, len, ISCSI_CRC32C_INITIAL ) ^ ISCSI_CRC32C_XOR;

	return iscsi_get_be32(pkt_crc32c) == crc32c;
}

/**
 * Checks whether packet data is an iSCSI packet or not.
 * Since iSCSI doesn't have a magic identifier for its packets, a
 * partial heuristic approach is needed for it. There is not always
 * a guarantee that a packet clearly belongs to iSCSI. If header
 * and/or data digests are present, their respective CRC32C's are
 * validated, too. Note that this function does NOT check if the
 * iSCSI command fits in, e.g. a SCSI data in/out command without
 * prior authentication, which is NOT allowed by the iSCSI standard,
 * will NOT be considered an error by this function as it has no
 * knowledge of prior commands sent.
 *
 * @param[in] packet_data Pointer to packet data to check for iSCSI, may
 * not be NULL.
 * @param[in] len Length of packet data to be checked for iSCSI, must be
 * at least 48 bytes (minimum BHS header size).
 * @param[in] header_digest_size Length of optional header digest (0 or 4 for now) in
 * order to validate header digest. The header digest size IS NOT checked for
 * conforming to iSCSI specs, so be careful.
 * @param[in] data_digest_size Length of optional data digest (0 or 4 for now) in
 * order to validate data digest size. The data digest size IS NOT checked for
 * conforming to iSCSI specs, so take caution.
 * @return 0 if it's clearly a iSCSI packet (detected without
 * heuristics) or a positive integfer value up to 65536, if heuristics
 * were necessary. A negative value is returned in case of an error or
 * if it's clearly not an iSCSI packet.
 */
int iscsi_validate_packet(const struct iscsi_bhs_packet *packet_data, const uint32_t len, const int header_digest_size, const int data_digest_size)
{
	if ( packet_data == NULL )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_NO_DATA;
	else if ( len < sizeof (struct iscsi_bhs_packet) )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_SIZE_TOO_SMALL;

	const uint32_t ahs_len = (uint32_t) packet_data->total_ahs_len << 2UL; // AHS length is in DWORD's
	const uint32_t ds_len = (uint32_t) iscsi_get_be24(packet_data->ds_len);

	if ( len != (sizeof (struct iscsi_bhs_packet) + ahs_len + header_digest_size + iscsi_align(ds_len, ISCSI_ALIGN_SIZE) + data_digest_size) )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_SIZE_MISMATCH;

	const uint8_t opcode = ISCSI_GET_OPCODE(packet_data->opcode);

	switch ( opcode ) {
		case ISCSI_CLIENT_NOP_OUT : {
			if ( (int8_t) packet_data->opcode < 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // MSB always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_nop_out_packet *nop_out_pkt = (const iscsi_nop_out_packet *) packet_data;

			if ( (*(uint16_t *) nop_out_pkt->reserved != 0) || (nop_out_pkt->reserved[2] != 0) || (nop_out_pkt->reserved2[0] != 0) || (nop_out_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_SCSI_CMD : {
			if ( (int8_t) packet_data->opcode < 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // MSB always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_scsi_cmd_packet *scsi_cmd_pkt = (const iscsi_scsi_cmd_packet *) packet_data;

			if ( scsi_cmd_pkt->reserved != 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved field needs to be zero, but is NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_TASK_FUNC_REQ : {
			if ( ((int8_t) packet_data->opcode < 0) || (ahs_len != 0) || (ds_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // MSB MUST always be cleared, AHS and DataSegment MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_task_mgmt_func_req_packet *task_mgmt_func_req_pkt = (const iscsi_task_mgmt_func_req_packet *) packet_data;

			if ( (task_mgmt_func_req_pkt->reserved != 0) || (task_mgmt_func_req_pkt->reserved2 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_LOGIN_REQ : {
			if ( (packet_data->opcode != (opcode | 0x40)) || (ahs_len != 0) || (ds_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bit 6 always MUST be set, AHS and DataSegment MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_login_req_packet *login_req_pkt = (const iscsi_login_req_packet *) packet_data;

			if ( (ISCSI_VERSION_MIN < login_req_pkt->version_min) || (ISCSI_VERSION_MAX > login_req_pkt->version_max) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_UNSUPPORTED_VERSION;

			if ( (login_req_pkt->reserved != 0) || (login_req_pkt->reserved2[0] != 0) || (login_req_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_TEXT_REQ : {
			if ( ((int8_t) packet_data->opcode < 0) || (ds_len == 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // MSB always MUST be cleared for this opcode and DataSegment is mandatory -> invalid iSCSI packet data

			const iscsi_text_req_packet *text_req_pkt = (const iscsi_text_req_packet *) packet_data;

			if ( (text_req_pkt->reserved != 0) || (text_req_pkt->reserved2[0] != 0) || (text_req_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_SCSI_DATA_OUT : {
			if ( (packet_data->opcode != opcode) || (ds_len == 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode and DataSegment is mandatory -> invalid iSCSI packet data

			const iscsi_scsi_data_out_req_packet *scsi_data_out_req_pkt = (const iscsi_scsi_data_out_req_packet *) packet_data;

			if ( (scsi_data_out_req_pkt->reserved != 0) || (scsi_data_out_req_pkt->reserved2 != 0) || (scsi_data_out_req_pkt->reserved3 != 0) || (scsi_data_out_req_pkt->reserved4 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_LOGOUT_REQ : {
			if ( (int8_t) packet_data->opcode < 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // MSB always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_logout_req_packet *logout_req_pkt = (const iscsi_logout_req_packet *) packet_data;

			if ( (logout_req_pkt->reserved != 0) || (logout_req_pkt->reserved2 != 0) || (logout_req_pkt->reserved3 != 0) || (logout_req_pkt->reserved4[0] != 0) || (logout_req_pkt->reserved4[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_SNACK_REQ : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_snack_req_packet *snack_req_pkt = (const iscsi_snack_req_packet *) packet_data;

			if ( (snack_req_pkt->reserved != 0) || (snack_req_pkt->reserved2 != 0) || (snack_req_pkt->reserved3 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_VENDOR_CODE1 :
		case ISCSI_CLIENT_VENDOR_CODE2 :
		case ISCSI_CLIENT_VENDOR_CODE3 : {
			break;
		}
		case ISCSI_SERVER_NOP_IN : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_nop_in_packet *nop_in_pkt = (const iscsi_nop_in_packet *) packet_data;

			if ( (*(uint16_t *) nop_in_pkt->reserved != 0) || (nop_in_pkt->reserved[2] != 0) || (nop_in_pkt->reserved2[0] != 0) || (nop_in_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_SCSI_RESPONSE : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_TASK_FUNC_RES : {
			if ( (packet_data->opcode != opcode) || (ahs_len != 0) || (ds_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared, AHS and DataSegment MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_task_mgmt_func_response_packet *task_mgmt_func_response_pkt = (const iscsi_task_mgmt_func_response_packet *) packet_data;

			if ( (task_mgmt_func_response_pkt->reserved != 0) || (task_mgmt_func_response_pkt->reserved2 != 0) || (task_mgmt_func_response_pkt->reserved3 != 0) || (task_mgmt_func_response_pkt->reserved4 != 0) || (task_mgmt_func_response_pkt->reserved5 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_LOGIN_RES : {
			if ( (packet_data->opcode != opcode) || (ds_len == 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data and DataSegment is mandatory

			const iscsi_login_response_packet *login_response_pkt = (const iscsi_login_response_packet *) packet_data;

			if ( (ISCSI_VERSION_MIN < login_response_pkt->version_max) || (ISCSI_VERSION_MAX > login_response_pkt->version_max) || (ISCSI_VERSION_MIN < login_response_pkt->version_active) || (ISCSI_VERSION_MAX > login_response_pkt->version_active) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_UNSUPPORTED_VERSION;

			if ( (login_response_pkt->reserved != 0) || (login_response_pkt->reserved2 != 0) || (login_response_pkt->reserved3 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_TEXT_RES : {
			if ( (packet_data->opcode != opcode) || (ds_len == 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode and DataSegment is mandatory -> invalid iSCSI packet data

			const iscsi_text_response_packet *text_response_pkt = (const iscsi_text_response_packet *) packet_data;

			if ( (text_response_pkt->reserved != 0) || (text_response_pkt->reserved2[0] != 0) || (text_response_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_SCSI_DATA_IN : {
			if ( (packet_data->opcode != opcode) || (ds_len == 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode and DataSegment is mandatory -> invalid iSCSI packet data

			const iscsi_scsi_data_in_response_packet *scsi_data_in_pkt = (const iscsi_scsi_data_in_response_packet *) packet_data;

			if ( scsi_data_in_pkt->reserved != 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved field needs to be zero, but is NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_LOGOUT_RES : {
			if ( (packet_data->opcode != opcode) || (ahs_len != 0) || (ds_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared, AHS and DataSegment MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_logout_response_packet *logout_response_pkt = (const iscsi_logout_response_packet *) packet_data;

			if ( (logout_response_pkt->reserved != 0) || (logout_response_pkt->reserved2 != 0) || (logout_response_pkt->reserved3 != 0) || (logout_response_pkt->reserved4 != 0) || (logout_response_pkt->reserved5 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_READY_XFER : {
			if ( (packet_data->opcode != opcode) || (ahs_len != 0) || (ds_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // AHS and DataSegment MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_r2t_packet *r2t_pkt = (const iscsi_r2t_packet *) packet_data;

			if ( r2t_pkt->reserved != 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved field needs to be zero, but is NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_ASYNC_MSG : {
			if ( (packet_data->opcode != opcode) || (ds_len == 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode and DataSegment is mandatory -> invalid iSCSI packet data

			const iscsi_async_msg_packet *async_msg_pkt = (const iscsi_async_msg_packet *) packet_data;

			if ( (async_msg_pkt->tag != 0xFFFFFFFFUL) || (async_msg_pkt->reserved != 0) || (async_msg_pkt->reserved2 != 0) || (async_msg_pkt->reserved3 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_VENDOR_CODE1 :
		case ISCSI_SERVER_VENDOR_CODE2 :
		case ISCSI_SERVER_VENDOR_CODE3 : {
			break;
		}
		case ISCSI_SERVER_REJECT : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared according to specs -> invalid iSCSI packet data

			const iscsi_reject_packet *reject_pkt = (const iscsi_reject_packet *) packet_data;

			if ( (reject_pkt->tag != 0xFFFFFFFFUL) || (reject_pkt->reserved != 0) || (reject_pkt->reserved2 != 0) || (reject_pkt->reserved3 != 0) || (reject_pkt->reserved4[0] != 0) || (reject_pkt->reserved4[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT, tag always MUST be 0xFFFFFFFFUL -> invalid iSCSI packet data

			break;
		}
		default : {
			return ISCSI_VALIDATE_PACKET_RESULT_ERROR_INVALID_OPCODE;

			break;
		}
	}

	if ( (header_digest_size != 0) && (iscsi_validate_header_digest( packet_data ) == 0) )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_CRC32C_HDR_DIGEST;

	if ( (data_digest_size != 0) && (iscsi_validate_data_digest( packet_data, header_digest_size ) == 0) )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_CRC32C_DATA_DIGEST;

	return ISCSI_VALIDATE_PACKET_RESULT_OK; // All tests for iSCSI passed, return 0
}

/**
 * Parses and extracts a specific key and value pair out of an iSCSI packet
 * data stream amd puts the extracted data into a hash map to be used by
 * the iSCSI implementation.
 *
 * @param[in] pairs Pointer to hash map containing all related keys and pairs.
 * May NOT be NULL, so take caution.
 * @param[in] packet_data Pointer to key / value pair to be parsed. NULL is
 * an illegal value, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @return Number of bytes used by the extracted key / vair pair or
 * a negative value in case of an error. This can be used for
 * incrementing the offset to the next key / value pair.
 */
static int iscsi_parse_text_key_value_pair(iscsi_hashmap *pairs, const uint8_t *packet_data, const uint32_t len)
{
	const uint key_val_len = strnlen( packet_data, len );
	const uint8_t *key_end = memchr( packet_data, '=', key_val_len );

	if ( key_end == NULL ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Key / value separator '=' not found" );

		return -1L;
	}

	const uint key_len = (key_end - packet_data);

	if ( key_len == 0 ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Empty key found which is NOT allowed according to iSCSI specs" );

		return -1L;
	}

	if ( key_len > ISCSI_TEXT_KEY_MAX_LEN ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Key value is too large (max 63 bytes)" );

		return -1L;
	}

	const uint hash_key_len = (key_len + 1UL);
	uint8_t *hash_key = iscsi_hashmap_key_create( packet_data, hash_key_len );

	if ( hash_key == NULL )
		return -1L;

	hash_key[key_len] = '\0';

	if ( iscsi_hashmap_contains( pairs, hash_key, hash_key_len ) ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Forbidden duplicate key discovered" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1L;
	}

	const uint val_len = strnlen( key_end + 1UL, key_val_len - key_len - 1UL );
	const uint max_len = (strcmp( hash_key, "CHAP_C" ) == 0) || (strcmp( hash_key, "CHAP_R" ) == 0) ? ISCSI_TEXT_VALUE_MAX_LEN : ISCSI_TEXT_VALUE_MAX_SIMPLE_LEN;

	if ( val_len > max_len ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Value length larger than iSCSI specs allow" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1L;
	}

	const uint8_t *hash_val = (uint8_t *) malloc( val_len + 1UL );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Out of memory allocating memory for value string" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1L;
	}

	memcpy( hash_val, key_end + 1, val_len );

	const int rc = iscsi_hashmap_put( pairs, hash_key, hash_key_len, hash_val );

	if ( rc < 0 )
		return -1L;

	return hash_key_len + val_len + 1UL; // Number of bytes for processed key / value pair (+1 for '=' and NUL terminator)
}

/**
 * Parses and extracts all key and value pairs out of iSCSI packet
 * data amd puts the extracted data into a hash map to be used by
 * the iSCSI implementation.
 *
 * @param[in] pairs Pointer to hash map that should contain all
 * extracted keys and pairs. May NOT be NULL, so take caution.
 * @param[in] packet_data Pointer to first key and value pair to
 * be parsed. NULL is an illegal value here, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @param[in] cbit Non-zero value of C bit was set in previously.
 * @param[in] partial_pairs Array of partial pair pointers in
 * case C bit was set (multiple iSCSI packets for text data).
 * @retval -1 An error occured during parsing key.
 * @retval 0 Key and value pair was parsed successfully and was added to
 * hash map.
 */
int iscsi_parse_key_value_pairs(iscsi_hashmap **pairs, const uint8_t *packet_data, uint len, int c_bit, uint8_t **partial_pairs)
{
	if ( len == 0 )
		return 0L; // iSCSI specs don't allow zero length

	if ( (partial_pairs != NULL) && (*partial_pairs != NULL) ) { // Strip partial text parameters in case C bit was enabled previously
		uint key_val_pair_len;

		for (key_val_pair_len = 0; (key_val_pair_len < len) && packet_data[key_val_pair_len] != '\0'; key_val_pair_len++) {
		}

		const uint8_t *tmp_partial_buf = iscsi_sprintf_alloc( "%s%s", *partial_pairs, (const char *) packet_data );

		if ( tmp_partial_buf == NULL )
			return -1L;

		const int rc = iscsi_parse_text_key_value_pair( pairs, tmp_partial_buf, (key_val_pair_len + strlen( *partial_pairs )) );
		free( tmp_partial_buf );

		if ( rc < 0 )
			return -1L;

		free( *partial_pairs );
		*partial_pairs = NULL;

		packet_data += (key_val_pair_len + 1);
		len         -= (key_val_pair_len + 1);
	}

	if ( c_bit ) { // Strip partial parameters in case C bit was enabled previousley
		if ( partial_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_parse_key_value_pairs: C bit set but missing partial parameter" );

			return -1L;
		}

		uint key_val_pair_len;

		for (key_val_pair_len = len - 1; (packet_data[key_val_pair_len] != '\0') && (key_val_pair_len > 0); key_val_pair_len--) {
		}

		if ( key_val_pair_len != 0 )
			key_val_pair_len++; // NUL char found, don't copy to target buffer'

		*partial_pairs = (uint8_t *) malloc ( (len - key_val_pair_len) + 1 );

		if ( *partial_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_parse_key_value_pairs: Out of memory allocating partial parameter" );

			return -1L;
		}

		memcpy( *partial_pairs, &packet_data[key_val_pair_len], (len - key_val_pair_len) );

		if ( key_val_pair_len != 0 )
			len = key_val_pair_len - 1;
		else
			return 0L;
	}

	int offset = 0L;

	while ( (offset < len) && (packet_data[offset] != '\0') ) {
		const int rc = iscsi_parse_text_key_value_pair( pairs, (packet_data + offset), (len - offset) );

		if ( rc < 0 )
			return -1L;

		offset += rc;
	}

	return 0L;
}

/**
 * Creates a data structure for an incoming iSCSI connection request
 * from iSCSI packet data.
 *
 * @param[in] login_req_pkt Pointer to iSCSI packet data to construct iSCSI
 * connection request from. May be NULL in which case this function does
 * nothing.
 * @return Pointer to initialized iSCSI connection structure or NULL in
 * case of an error (invalid iSCSI packet data or memory exhaustion).
 */
iscsi_connection *iscsi_connection_create(const iscsi_login_req_packet *login_req_pkt)
{
	iscsi_connection *conn = (iscsi_connection *) malloc( sizeof(struct iscsi_connection) );

	if ( conn == NULL ) {
		logadd( LOG_ERROR, "iscsi_create_connection: Out of memory while allocating iSCSI connection" );

		return NULL;
	}

	conn->key_value_pairs = iscsi_hashmap_create( 0UL );

	if ( conn->key_value_pairs == NULL ) {
		logadd( LOG_ERROR, "iscsi_create_connection: Out of memory while allocating iSCSI text key / value pair hash map" );

		free( conn );

		return NULL;
	}

	conn->header_digest = 0L;
	conn->data_digest = 0L;

	conn->isid.a = login_req_pkt->isid.a;
	conn->isid.b = iscsi_get_be16(login_req_pkt->isid.b);
	conn->isid.c = login_req_pkt->isid.c;
	conn->isid.d = iscsi_get_be16(login_req_pkt->isid.d);

	conn->tsih = login_req_pkt->tsih; // Identifier, no need for endianess conversion
	conn->init_task_tag = login_req_pkt->init_task_tag; // Identifier, no need for endianess conversion
	conn->cid = login_req_pkt->cid; // Identifier, no need for endianess conversion
	conn->cmd_sn = iscsi_get_be32(login_req_pkt->cmd_sn);
	conn->exp_stat_sn = iscsi_get_be32(login_req_pkt->exp_stat_sn);

	return conn;
}

/**
 * Deallocates a data structure of an iSCSI connection
 * request and all allocated hash maps which don't
 * require closing of external resources like closing
 * TCP/IP socket connections.
 *
 * @param[in] conn Pointer to iSCSI connection structure to be
 * deallocated, TCP/IP connections are NOT closed by this
 * function, use iscsi_connection_close for this. This may be
 * NULL in which case this function does nothing.
 */
void iscsi_connection_destroy(iscsi_connection *conn)
{
	if ( conn != NULL ) {
		if ( conn->key_value_pairs != NULL ) {
			iscsi_hashmap_iterate( conn->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( conn->key_value_pairs );

			conn->key_value_pairs = NULL;
		}

		free( conn );
	}
}

/**
 * Callback function for deallocation of an iSCSI
 * connection stored in the hash map managing all
 * iSCSI connections.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[in] value Value of the key, NULL is allowed.
 * @return Always returns 0a as this function cannot fail.
 */
int iscsi_connection_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_connection_destroy( (iscsi_connection *) value );
	iscsi_hashmap_key_destroy( key );

	return 0L;
}
