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

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <dnbd3/config.h>
#include <dnbd3/shared/log.h>
#include <dnbd3/shared/sockhelper.h>
#include <dnbd3/types.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include "fileutil.h"
#include "globals.h"
#include "helper.h"
#include "image.h"
#include "ini.h"
#include "iscsi.h"
#include "locks.h"
#include "threadpool.h"

/**
 * @file iscsi.c
 * @author Sebastian Vater
 * @date 16 Jul 2025
 * @brief iSCSI implementation for DNBD3.
 *
 * This file contains the iSCSI implementation according to
 * RFC7143 for dnbd3-server.\n
 * All server-side network sending and client-side network
 * receiving code is done here.\n
 * @see https://www.rfc-editor.org/rfc/rfc7143
 */


/**
 * @brief Allocates and appends a buffer and sprintf's it.
 *
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
	uint orig_size = 0U;

	if ( buf != NULL )
		orig_size = (uint) strlen( (char *) buf );

	va_copy( args_copy, args );
	uint new_size = vsnprintf( NULL, 0, format, args_copy );
	va_end( args_copy );

	new_size += (uint) (orig_size + 1U);

	uint8_t *new_buf = realloc( buf, new_size );

	if ( new_buf == NULL ) {
		logadd( LOG_ERROR, "iscsi_vsprintf_append_realloc: Out of memory while allocating string buffer" );

		return NULL;
	}

	vsnprintf( (char *) (new_buf + orig_size), (new_size - orig_size), format, args );

	return new_buf;
}

/**
 * @brief Allocates and appends a buffer and sprintf's it.
 *
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
 * @brief Allocates a buffer and sprintf's it.
 *
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
 * @brief Allocates a buffer and sprintf's it.
 *
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
 * @brief Copies a string with additional padding character to fill in a specified size.
 *
 * This function does NOT pad, but truncates
 * instead if the string length equals or is
 * larger than the maximum allowed size.
 *
 * @param[in] dst Pointer to destination string to copy
 * with padding and may NOT be NULL, so be
 * careful.
 * @param[in] src Pointer to string for copying. NULL
 * is NOT allowed here, take caution.
 * @param[in] size Total size in bytes for padding.
 * @param[in] pad Padding character to use.
 */
void iscsi_strcpy_pad(char *dst, const char *src, const size_t size, const int pad)
{
	const size_t len = strlen( src );

	if ( len < size ) {
		memcpy( dst, src, len );
		memset( (dst + len), pad, (size - len) );
	} else {
		memcpy( dst, src, size );
	}
}

/**
 * @brief Creates an empty hash map with either specified or default capacity.
 *
 * Creates a ultra hardcore speed optimized empty
 * hash map and allocates enough buckets to hold
 * default capacity elements.\n
 * The speed optimizations require all keys
 * having a size of a multiple of 8 bytes with
 * zero padding. Also the capacity always nas
 * to be a power of two.\n
 * TODO: Move all hash map related functions to
 * different source file later and implement in
 * a lock-free way for better concurrency.
 *
 * @param[in] capacity Desired initial capacity, will be rounded up
 * to the nearest power of two. If set to 0, a
 * default capacity of 32 buckets will be used
 * instead.
 * @return A pointer to the hash map structure or NULL in case of an error.
 */
iscsi_hashmap *iscsi_hashmap_create(const uint capacity)
{
	iscsi_hashmap *map = (iscsi_hashmap *) malloc( sizeof(iscsi_hashmap) );

	if ( map == NULL ) {
		logadd( LOG_ERROR, "iscsi_hashmap_create: Out of memory while allocating iSCSI hash map" );

		return map;
	}

	if ( capacity > 0U ) {
		uint new_capacity = (uint) iscsi_align_pow2_ceil( (uint32_t) capacity );

		if ( (capacity + 1U) > (uint) ((new_capacity * 3U) >> 2U) )
			new_capacity += new_capacity; // If specified capacity does not fit in 75% of requested capacity, double actual size

		map->capacity = new_capacity; // Round up actual new capacity to nearest power of two
	} else {
		map->capacity = ISCSI_HASHMAP_DEFAULT_CAPACITY;
	}

	map->buckets = (iscsi_hashmap_bucket *) calloc( map->capacity, sizeof(struct iscsi_hashmap_bucket) );

	if ( map->buckets == NULL ) {
		free( map );

		logadd( LOG_ERROR, "iscsi_hashmap_create: Out of memory while allocating iSCSI hash map buckets" );

		return NULL;
	}

	iscsi_list_create( &map->list );

	map->last_insert_id = 0ULL;
	map->cap_load       = (uint) ((map->capacity * 3U) >> 2U); // 75% of capacity
	map->count          = 0U;

	return map;
}

/**
 * @brief Deallocates the hash map objects and buckets, not elements. Use iscsi_hashmap_iterate to deallocate the elements themselves.
 *
 * Deallocates all buckets and the hash map itself
 * allocated by iscsi_hashmap_create. The elements
 * associated with the buckets are NOT freed by this
 * function, this has to be done either manually or
 * using the function iscsi_hashmap_iterate.
 *
 * @param[in] map Pointer to hash map and its buckets to deallocate.
 * If this is NULL, nothing is done.
 */
void iscsi_hashmap_destroy(iscsi_hashmap *map)
{
	if ( map != NULL ) {
		if ( map->buckets != NULL ) {
			free( map->buckets );

			map->buckets = NULL;
		}

		free( map );
	}
}

/**
 * @brief Creates a key suitable for hash map usage (ensures 8-byte boundary and zero padding).
 *
 * Creates a key from data and size and ensures
 * its requirements for usage in hash map buckets.\n
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
	const size_t key_size = ISCSI_ALIGN(len, ISCSI_HASHMAP_KEY_ALIGN);
	uint8_t *key          = (uint8_t *) malloc( key_size );

	if ( key == NULL ) {
		logadd( LOG_ERROR, "iscsi_hashmap_key_create: Out of memory while allocating iSCSI hash map key" );

		return key;
	}

	memcpy( key, data, len );
	memset( (key + len), 0, (key_size - len) ); // Zero pad additional bytes in case length is not a multiple of 8

	return key;
}

/**
 * @brief Creates an unique key identifier suitable for hash map usage (ensures 8-byte boundary and zero padding).
 *
 * Creates a unique key identifier by adding
 * the capacity and element count plus one
 * together as an unsigned 64-bit integer
 * and uses the resulting value as key data
 * which ensure the requirements for usage
 * in hash map buckets.\n
 * This function returns the same identifier if
 * the previously generated key identifier has
 * NOT been added to the hash map yet.\n
 * Currently keys to be used in a hash map bucket
 * require a size of multiple by 8 bytes with
 * the zero padding.
 *
 * @param[in] map Pointer to hash map to construct the key
 * for and may NOT be NULL, so be careful.
 * @param[out] key Pointer to key to store the
 * unique key in. NULL is NOT allowed here, be
 * careful.
 */
void iscsi_hashmap_key_create_id(iscsi_hashmap *map, uint64_t *key)
{
	*key = ++map->last_insert_id;
}

/**
 * @brief Deallocates all resources acquired by iscsi_hashmap_create_key.
 *
 * Deallocates a key allocated with the function
 * iscsi_hashmap_key_create.
 *
 * @param[in] key Pointer to key to deallocate, may NOT
 * be NULL, so be careful.
 */
void iscsi_hashmap_key_destroy(uint8_t *key)
{
	free( key );
}

/**
 * @brief Deallocates a key in a hash map.
 *
 * Default callback function for deallocation of
 * hash map resources by simply deallocating
 * the key.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, not used here.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_hashmap_key_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_hashmap_key_destroy( key );

	return 0;
}

/**
 * @brief Deallocates a value in a hash map.
 *
 * Default callback function for deallocation of
 * hash map resources by simply deallocating
 * the value.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_hashmap_destroy_value_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	if ( value != NULL )
		free( value );

	return 0;
}

/**
 * @brief Deallocates a key / value pair in a hash map by calling free (default destructor).
 *
 * Default callback function for deallocation of
 * allocated hash map resources by simply calling
 * free.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key,
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_hashmap_key_destroy_value_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	if ( value != NULL )
		free( value );

	iscsi_hashmap_key_destroy( key );

	return 0;
}

/**
 * @brief Compares two hash keys with equal length match.
 *
 * This function is optimized to compare
 * 8 bytes at once and requires number
 * of blocks specified in QWORDs. Both
 * keys must be equal in size of a
 * QWORD alignment.
 *
 * @param[in] buf Pointer to key buffer of which key
 * to compare. May NOT be NULL, so be
 * careful.
 * @param[in] key Pointer to key to compare with.
 * NULL is NOT allowed here, take
 * caution.
 * @param[in] num_blocks Number of blocks in QWORDs (8 bytes)
 * to be compared.
 */
static inline bool iscsi_hashmap_key_eq(const uint64_t *buf, const uint64_t *key, size_t num_blocks)
{
	do {
		if ( *buf++ != *key++ )
			return false;
	} while ( --num_blocks > 0UL );

	return true;
}

/**
 * @brief Finds a bucket by key of a specified hash map by key, key size and hash code.
 *
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
	const size_t num_blocks = ISCSI_ALIGN(key_size, ISCSI_HASHMAP_KEY_ALIGN) >> ISCSI_HASHMAP_KEY_ALIGN_SHIFT;
	uint32_t index          = (hash & (map->capacity - 1U));

	for ( ;; ) {
		iscsi_hashmap_bucket *entry = &map->buckets[index];

		if ( ((entry->key == NULL) && (entry->value == NULL)) || ((entry->key != NULL) && (entry->key_size == key_size) && (entry->hash == hash) && iscsi_hashmap_key_eq( (uint64_t *) entry->key, (uint64_t *) key, num_blocks )) )
			return entry;

		index = ((index + 1UL) & (map->capacity - 1U));
	}
}

/**
 * @brief Calculates the hash code of data with a specified length.
 *
 * Calculates the hash code of data with a specified
 * length.
 *
 * @param[in] data Pointer to data to be hashed, NULL is NOT
 * an allowed here, so be careful. Data needs 8 byte alignment
 * and needs to be zero padded.
 * @param[in] len Number of bytes of hash data, must be larger
 * than 0 and is rounded up to the nearest 8 byte integer prior
 * calculating the hash code, so be careful.
 * @return Hash code of data.
 */
static inline uint32_t iscsi_hashmap_key_hash_data(const uint8_t *data, const size_t len)
{
	const uint64_t *hash_data = (const uint64_t *) data;
	size_t num_blocks         = ISCSI_ALIGN(len, ISCSI_HASHMAP_KEY_ALIGN) >> ISCSI_HASHMAP_KEY_ALIGN_SHIFT;
	uint64_t hash             = ISCSI_HASHMAP_HASH_INITIAL;

	do {
		hash ^= *hash_data++;
		hash *= ISCSI_HASHMAP_HASH_MUL;
	} while ( --num_blocks > 0UL );

	return (uint32_t) (hash ^ hash >> 32ULL);
}

/**
 * @brief Puts an old bucket into a resized hash map.
 *
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
	uint32_t index = (old_entry->hash & (map->capacity - 1U));

	for ( ;; ) {
		iscsi_hashmap_bucket *entry = &map->buckets[index];

		if ( entry->key == NULL ) {
			entry->key       = old_entry->key;
			entry->key_size  = old_entry->key_size;
			entry->hash      = old_entry->hash;
			entry->value     = old_entry->value;

			return entry;
		}

		index = ((index + 1) & (map->capacity - 1U));
	}
}

/**
 * @brief Resizes a hash map by doubling its bucket capacity.
 *
 * Resizes a hash map by doubling its bucket capacity The
 * old bucket list is freed after the
 * resize operation has been finished.
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
	iscsi_list old_list               = {map->list.head, map->list.tail, map->list.pred};

	map->capacity <<= ISCSI_HASHMAP_RESIZE_SHIFT;

	map->buckets = (iscsi_hashmap_bucket *) calloc( map->capacity, sizeof(struct iscsi_hashmap_bucket) );

	if ( map->buckets == NULL ) {
		map->capacity = old_capacity;
		map->buckets  = old_buckets;

		return -1;
	}

	map->cap_load = (uint) ((map->capacity * 3U) >> 2U); // 75% of capacity

	iscsi_list_clear( &map->list );

	iscsi_hashmap_bucket *current;
	iscsi_hashmap_bucket *tmp;

	iscsi_list_foreach_safe_node ( &old_list, current, tmp ) {
		if ( current->key == NULL )
			continue;

		current = iscsi_hashmap_resize_entry( map, current );

		iscsi_list_enqueue( &map->list, &current->node );
	}

	free( old_buckets );

	return 0;
}

/**
 * @brief Assigns key / value pair to hash map at the tail of doubly linked list without making copies.
 *
 * Adds a key / value pair to a specified hash map
 * bucket list, if it doesn't exist already. The
 * buckets are resized automatically if required.\n
 * This function neither does make a copy of the key,
 * nor of the value. Keys should be allocated using
 * the function iscsi_hashmap_key_create or freed by
 * using iscsi_hashmap_key_destroy in order to
 * ensure the alignment and padding requirements.\n
 * The new pair will always added to the tail of the
 * linked list.
 *
 * @param[in] map Pointer to hash map where the key and
 * value pair should be added to, may NOT be NULL, so
 * be careful.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key to add, NULL is
 * allowed.
 * @retval -1 Adding key / value pair would have required
 * hash map resizing which failed (probably due to
 * memory exhaustion).
 * @retval 0 Key / value pair was added successfully.
 */
int iscsi_hashmap_put(iscsi_hashmap *map, uint8_t *key, const size_t key_size, uint8_t *value)
{
	if ( ((map->count + 1U) > map->cap_load) && (iscsi_hashmap_resize( map ) < 0) )
		return -1;

	const uint32_t hash         = iscsi_hashmap_key_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key == NULL ) {
		iscsi_list_enqueue( &map->list, &entry->node );

		map->count++;

		entry->key      = key;
		entry->key_size = key_size;
		entry->hash     = hash;
	}

	entry->value = value;

	return 0;
}

/**
 * @brief Assigns key / value pair to hash map at the tail of doubly linked list without making copies.
 *
 * Adds a key / value pair if it doesn't exist
 * using the value of `*out_in_val`. If the pair
 * does exist, value will be set in `*out_in`,
 * meaning the value of the pair will be in
 * '*out_in` regardless of whether or not it it
 * existed in the first place.\n
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
 * @param[in] key_size Number of bytes for the key.
 * @param[in,out] out_in_value Value of the key to add,
 * NULL is allowed.
 * @retval -1 Adding key / value pair would have required
 * hash map resizing which failed (probably due to
 * memory exhaustion).
 * @retval 0 Key / value pair was added successfully.
 * @retval 1 Key already existed.
 */
int iscsi_hashmap_get_put(iscsi_hashmap *map, uint8_t *key, const size_t key_size, uint8_t **out_in_value)
{
	if ( ((map->count + 1U) > map->cap_load) && (iscsi_hashmap_resize( map ) < 0) )
		return -1;

	const uint32_t hash         = iscsi_hashmap_key_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key == NULL ) {
		iscsi_list_enqueue( &map->list, &entry->node );

		entry->key      = key;
		entry->key_size = key_size;
		entry->hash     = hash;
		entry->value    = *out_in_value;

		map->count++;

		return 0;
	}

	*out_in_value = entry->value;

	return 1;
}

/**
 * @brief Assigns key / value pair to hash map without making copies with callback function in case the key already exists.
 *
 * Adds a key / value pair to a specified hash map
 * bucket list. If the key already exists, it will
 * be overwritten and a callback function will be
 * invoked in order to allow, e.g. deallocation of
 * resources, if necessary. The buckets are resized
 * automatically if required. This function neither
 * does make a copy of the key, nor of the value.\n
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
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key to add, NULL is
 * allowed.
 * @param[in] callback Callback function which allows,
 * for example, a dallocation of resources for the
 * overwritten key and value pair. The function is
 * invoked just before overwriting the old values.
 * This may NOT be NULL, so take caution.
 * @param[in,out] user_data Pointer to user specific data
 * passed to the callback function in case more
 * information is needed.
 * @return -1 in case adding key / value pair would
 * have required hash map resizing which failed
 * (probably due to memory exhaustion), 0 if the
 * Key / value pair was added successfully and
 * the callback function also returned 0, otherwise
 * the return value got by the callbuck function.
 */
int iscsi_hashmap_put_free(iscsi_hashmap *map, uint8_t *key, const size_t key_size, uint8_t *value, iscsi_hashmap_callback callback, uint8_t *user_data)
{
	if ( ((map->count + 1U) > map->cap_load) && (iscsi_hashmap_resize( map ) < 0) )
		return -1;

	const uint32_t hash         = iscsi_hashmap_key_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key == NULL ) {
		iscsi_list_enqueue( &map->list, &entry->node );

		entry->key      = key;
		entry->key_size = key_size;
		entry->hash     = hash;
		entry->value    = value;

		map->count++;

		return 0;
	}

	int err = callback( entry->key, key_size, entry->value, user_data );

	entry->key   = key;
	entry->value = value;

	return err;
}

/**
 * @brief Checks whether a specified key exists.
 *
 * Checks whether a specified key exists in a hash map.
 *
 * @param[in] map Pointer to the hash map to be searched
 * for the key to check for existence and may NOT be
 * NULL, so take caution.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @retval true The key exists.
 * @retval false The key does not exist.
 */
bool iscsi_hashmap_contains(iscsi_hashmap *map, const uint8_t *key, const size_t key_size)
{
	const uint32_t hash         = iscsi_hashmap_key_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	return (entry->key != NULL);
}

/**
 * @brief Retrieves the value of a specified key.
 *
 * Retrieves the value of a specified key from a hash
 * map. Since the hash map supports NULL values, it
 * is stored in an output variable.
 *
 * @param[in] map Pointer to the hash map to be searched
 * for the key of which the value should be
 * retrieved and may NOT be NULL, so take
 * caution.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[out] out_value Pointer where the value of the found key
 * is stored, maybe NULL if either the key's value
 * is NULL or in case the key was not found. The
 * pointer to the value itself may NOT be NULL,
 * so be careful.
 * @retval 0 The key has been found and its value stored
 * in the 'out_value' parameter.
 * @retval -1 The key has not been found and NULL has been
 * stored in the 'out_value' parameter.
 */
int iscsi_hashmap_get(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t **out_value)
{
	const uint32_t hash         = iscsi_hashmap_key_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	*out_value = entry->value;

	return ((entry->key != NULL) ? 0 : -1);
}

/**
 * @brief Removes an element both from the doubly linked list and by setting key and value both to NULL.
 *
 * Removes an element from the bucket list of the
 * hash map. Removing sets the buckets key and
 * value to NULL.
 * If the specified key already has been removed,
 * this function will do nothing.
 *
 * @param[in] map Pointer to the hash map to remove from
 * and may NOT be NULL, so take caution.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 */
void iscsi_hashmap_remove(iscsi_hashmap *map, const uint8_t *key, const size_t key_size)
{
	const uint32_t hash         = iscsi_hashmap_key_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key != NULL ) {
		iscsi_list_remove( &entry->node );

		map->count--;

		entry->key   = NULL;
		entry->value = NULL;
	}
}

/**
 * @brief Removes an element both from the doubly linked list and by setting key and value both to NULL and but invokes a callback function before actual removal.
 *
 * Removes an element from the bucket list of the
 * hash map.\n
 * Removing sets the buckets key and
 * value to NULL. A callback function is invoked
 * if the key to be removed is found in the
 * bucket list and allows, e.g. to free any
 * resources associated with the key. If the key
 * is not found, this function will do nothing.
 *
 * @param[in] map Pointer to the hash map to remove from
 * and may NOT be NULL, so take caution.
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] callback Callback function which allows,
 * for example, a dallocation of resources for
 * the key and value pair to be removed. The
 * function is invoked just before marking the
 * key / value pair as removed. This may NOT
 * be NULL, so take caution.
 * @param[in,out] user_data Pointer to user specific data
 * passed to the callback function in case
 * more information is needed.
 */
void iscsi_hashmap_remove_free(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, iscsi_hashmap_callback callback, uint8_t *user_data)
{
	const uint32_t hash         = iscsi_hashmap_key_hash_data( key, key_size );
	iscsi_hashmap_bucket *entry = iscsi_hashmap_find_entry( map, key, key_size, hash );

	if ( entry->key != NULL ) {
		iscsi_list_remove( &entry->node );

		map->count--;

		callback( entry->key, entry->key_size, entry->value, user_data );

		entry->key   = NULL;
		entry->value = NULL;
	}
}

/**
 * @brief Retrieves the number of elements of the hash map.
 *
 * Returns the number of elements stored in the
 * specified hash map.
 *
 * @param[in] map Pointer to the hash map to count the
 * number of elements, may NOT be NULL, so
 * take caution.
 * @return Number of elements currently in use by the
 * hash map.
 */
uint iscsi_hashmap_size(const iscsi_hashmap *map)
{
	return map->count;
}

/**
 * @brief Iterator with callback function invoked on each element.
 *
 * An iterator through the elements of a
 * specified hash map which uses a callback
 * function for each element, which also
 * can abort the iteration, if necessary.\n
 * It is safe to remove the current iterating
 * element in the callback function from the
 * hash map.
 *
 * @param[in] map Pointer to the hash map to iterate
 * through, may NOT be NULL, so take caution.
 * @param[in] callback Callback function to be
 * invoked for each element. If the return
 * value of the callback function is below
 * zero, the iteration will stop.
 * @param[in,out] user_data Pointer to user specific data
 * passed to the callback function in case more
 * information is needed.
 * @return The return code from the last invoked
 * callback function. A negative value indicates
 * an abortion of the iteration process.
 */
int iscsi_hashmap_iterate(iscsi_hashmap *map, iscsi_hashmap_callback callback, uint8_t *user_data)
{
	iscsi_hashmap_bucket *current;
	iscsi_hashmap_bucket *tmp;
	int err = 0;

	iscsi_list_foreach_safe_node ( &map->list, current, tmp ) {
		if ( current->key == NULL )
			continue;

		err = callback( current->key, current->key_size, current->value, user_data );

		if ( err < 0 )
			break;
	}

	return err;
}


/// iSCSI global vector. MUST be initialized with iscsi_create before any iSCSI functions are used.
iscsi_globals *iscsi_globvec = NULL;

/// Read/write lock for iSCSI global vector. MUST be initialized with iscsi_create before any iSCSI functions are used.
pthread_rwlock_t iscsi_globvec_rwlock;


/// iSCSI connection negotation key and value pair lookup table.
static const iscsi_key_value_pair_lut_entry iscsi_connection_key_value_pair_lut[] = {
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST, (uint8_t *) "None", (uint8_t *) "CRC32C\0None\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST, 0 },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST, (uint8_t *) "None", (uint8_t *) "CRC32C\0None\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST, 0 },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN, (uint8_t *) "8192", (uint8_t *) "512\016777215\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_MULTI_NEGOTIATION | ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_OVERRIDE_DEFAULT },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_OF_MARKER, (uint8_t *) "No", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND, 0 },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IF_MARKER, (uint8_t *) "No", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND, 0 },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_OF_MARK_INT, (uint8_t *) "1", (uint8_t *) "1\0""65535\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, 0 },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IF_MARK_INT, (uint8_t *) "1", (uint8_t *) "1\0""65535\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, 0 },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD, (uint8_t *) "None", (uint8_t *) "CHAP\0None\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST, 0 },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_A, (uint8_t *) "5", (uint8_t *) "5\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_N, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_R, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_I, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_C, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ NULL, NULL, NULL, ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_INVALID, 0 }
};

/// iSCSI session negotation key and value pair lookup table.
static const iscsi_key_value_pair_lut_entry iscsi_session_key_value_pair_lut[] = {
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS, (uint8_t *) "1", (uint8_t *) "1\0""65535\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_SEND_TARGETS, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_SPECIAL_HANDLING },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_NAME, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_NAME, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, 0 },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, 0 },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_ALIAS, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, 0 },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, (uint8_t *) "1", (uint8_t *) "1\0""65535\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T, (uint8_t *) "Yes", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA, (uint8_t *) "Yes", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, (uint8_t *) "262144", (uint8_t *) "512\0""16777215\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE | ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_OTHER_MAX_VALUE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN, (uint8_t *) "65536", (uint8_t *) "512\0""16777215\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE | ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_PREVIOUS_VALUE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_WAIT, (uint8_t *) "2", (uint8_t *) "0\0""3600\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MAX, 0 },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_RETAIN, (uint8_t *) "20", (uint8_t *) "0\0""3600\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, 0 },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T, (uint8_t *) "1", (uint8_t *) "1\0""65536\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_PDU_IN_ORDER, (uint8_t *) "Yes", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_SEQ_IN_ORDER, (uint8_t *) "Yes", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_ERR_RECOVERY_LEVEL, (uint8_t *) "0", (uint8_t *) "0\0""2\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, 0 },
	{ ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, (uint8_t *) "Normal", (uint8_t *) "Normal\0Discovery\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, 0 },
	{ NULL, NULL, NULL, ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_INVALID, 0 }
};

/**
 * @brief Initializes a global key and value pair with type and list / range informations for fast access.
 *
 * This function is used to initialize the iSCSI
 * global key and value pair list containing
 * the key types and allowed values.
 *
 * @param[in] key_value_pairs Pointer to key and value pair hash map
 * which should store the global key and value
 * informations, may NOT be NULL, so take caution.
 * @param[in] lut Lookup table to use for initialization.
 * NULL is not allowed here, so be careful.
 * @return 0 on success, a negative error code otherwise.
 */
static int iscsi_global_key_value_pair_init(iscsi_hashmap *key_value_pairs, const iscsi_key_value_pair_lut_entry *lut)
{
	for ( uint i = 0U, j = 1U; lut[i].key != NULL; i++, j += j ) {
		iscsi_key_value_pair *key_value_pair = (iscsi_key_value_pair *) malloc( sizeof(struct iscsi_key_value_pair) );

		if ( key_value_pair == NULL ) {
			logadd( LOG_ERROR, "iscsi_global_key_value_pair_init: Out of memory allocating key value pair" );

			return -1;
		}

		const uint key_len = (uint) (strlen( (char *) lut[i].key ) + 1U);

		key_value_pair->value       = lut[i].value;
		key_value_pair->list_range  = lut[i].list_range;
		key_value_pair->type        = lut[i].type;
		key_value_pair->flags       = lut[i].flags;
		key_value_pair->state_mask  = j;

		const int rc = iscsi_hashmap_put( key_value_pairs, (uint8_t *) lut[i].key, key_len, (uint8_t *) key_value_pair );

		if ( rc < 0 ) {
			free( key_value_pair );

			return rc;
		}
	}

	return 0;
}

/**
 * @brief Allocates and initializes the iSCSI global vector structure.
 *
 * This function MUST be called before any iSCSI
 * related functions are used.\n
 * It is safe to call this function if the iSCSI
 * global vector already has been initialized
 * in which case this function does nothing.
 *
 * @return 0 if the iSCSI global vector has been initialized
 * successfully and is ready to use, a negative
 * error code otherwise (memory exhausted).
 */
int iscsi_create()
{
	pthread_rwlock_wrlock( &iscsi_globvec_rwlock );

	if ( iscsi_globvec == NULL ) {
		iscsi_globals *globvec = (iscsi_globals *) malloc( sizeof(struct iscsi_globals) );

		if ( globvec == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector" );

			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		globvec->devices = iscsi_hashmap_create( _maxImages );

		if ( globvec->devices == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector devices hash map" );

			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		if ( pthread_rwlock_init( &globvec->devices_rwlock, NULL ) != 0 ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing read/write lock for iSCSI global vector devices hash map" );

			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		globvec->portal_groups = iscsi_hashmap_create( 1U );

		if ( globvec->portal_groups == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector portal groups hash map" );

			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		if ( pthread_rwlock_init( &globvec->portal_groups_rwlock, NULL ) != 0 ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing read/write lock for iSCSI global vector portal groups hash map" );

			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		globvec->target_nodes = iscsi_hashmap_create( _maxImages );

		if ( globvec->target_nodes == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector target nodes hash map" );

			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		if ( pthread_rwlock_init( &globvec->target_nodes_rwlock, NULL ) != 0 ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing read/write lock for iSCSI global vector target nodes hash map" );

			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		globvec->sessions = iscsi_hashmap_create( _maxClients );

		if ( globvec->sessions == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector sessions hash map" );

			pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		if ( pthread_rwlock_init( &globvec->sessions_rwlock, NULL ) != 0 ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing read/write lock for iSCSI global vector sessions hash map map" );

			iscsi_hashmap_destroy( globvec->sessions );
			pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		globvec->session_key_value_pairs = iscsi_hashmap_create( ((sizeof(iscsi_session_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1) );

		if ( globvec->session_key_value_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector session key and value pairs hash map" );

			pthread_rwlock_destroy( &globvec->sessions_rwlock );
			iscsi_hashmap_destroy( globvec->sessions );
			pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		int rc = iscsi_global_key_value_pair_init( globvec->session_key_value_pairs, &iscsi_session_key_value_pair_lut[0] );

		if ( rc < 0 ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing iSCSI global vector session key and value pairs hash map" );

			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			pthread_rwlock_destroy( &globvec->sessions_rwlock );
			iscsi_hashmap_destroy( globvec->sessions );
			pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		globvec->connection_key_value_pairs = iscsi_hashmap_create( ((sizeof(iscsi_connection_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1) );

		if ( globvec->connection_key_value_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector connection key and value pairs hash map" );

			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			pthread_rwlock_destroy( &globvec->sessions_rwlock );
			iscsi_hashmap_destroy( globvec->sessions );
			pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		rc = iscsi_global_key_value_pair_init( globvec->connection_key_value_pairs, &iscsi_connection_key_value_pair_lut[0] );

		if ( rc < 0 ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing iSCSI global vector connection key and value pairs hash map" );

			iscsi_hashmap_iterate( globvec->connection_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->connection_key_value_pairs );
			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			pthread_rwlock_destroy( &globvec->sessions_rwlock );
			iscsi_hashmap_destroy( globvec->sessions );
			pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		globvec->scsi_device_config = iscsi_hashmap_create( 0U );

		if ( globvec->scsi_device_config == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector SCSI device configuration" );

			iscsi_hashmap_iterate( globvec->connection_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->connection_key_value_pairs );
			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			pthread_rwlock_destroy( &globvec->sessions_rwlock );
			iscsi_hashmap_destroy( globvec->sessions );
			pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		if ( pthread_mutex_init( &globvec->scsi_device_config_mutex, NULL ) != 0 ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing mutex for iSCSI global vector SCSI device configuration" );

			iscsi_hashmap_destroy( globvec->scsi_device_config );
			iscsi_hashmap_iterate( globvec->connection_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->connection_key_value_pairs );
			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			pthread_rwlock_destroy( &globvec->sessions_rwlock );
			iscsi_hashmap_destroy( globvec->sessions );
			pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
			iscsi_hashmap_destroy( globvec->target_nodes );
			pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
			iscsi_hashmap_destroy( globvec->portal_groups );
			pthread_rwlock_destroy( &globvec->devices_rwlock );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return -1;
		}

		globvec->flags                          = (ISCSI_GLOBALS_FLAGS_INIT_R2T | ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA | ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER | ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER | ISCSI_GLOBALS_FLAGS_SCSI_IO_REMOVABLE | ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_PROTECT);
		globvec->target_name_check              = ISCSI_GLOBALS_TARGET_NAME_CHECK_FULL;
		globvec->max_sessions                   = 0U;
		globvec->header_digest                  = 0;
		globvec->data_digest                    = 0;
		globvec->scsi_device_type               = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_DIRECT;
		globvec->max_recv_ds_len                = ISCSI_DEFAULT_RECV_DS_LEN;
		globvec->max_session_conns              = ISCSI_GLOBALS_DEFAULT_MAX_CONNECTIONS;
		globvec->max_outstanding_r2t            = ISCSI_GLOBALS_DEFAULT_MAX_OUTSTANDING_R2T;
		globvec->default_time_to_wait           = ISCSI_GLOBALS_DEFAULT_TIME_TO_WAIT;
		globvec->default_time_to_retain         = ISCSI_GLOBALS_DEFAULT_TIME_TO_RETAIN;
		globvec->first_burst_len                = ISCSI_GLOBALS_DEFAULT_FIRST_BURST_LEN;
		globvec->max_burst_len                  = ISCSI_GLOBALS_DEFAULT_MAX_BURST_LEN;
		globvec->err_recovery_level             = ISCSI_GLOBALS_DEFAULT_ERR_RECOVERY_LEVEL;
		globvec->chap_group                     = 0L;
		globvec->scsi_physical_block_size       = ISCSI_SCSI_EMU_PHYSICAL_BLOCK_SIZE;
		globvec->scsi_physical_block_size_shift = iscsi_get_log2_of_pow2( globvec->scsi_physical_block_size );
		globvec->scsi_logical_block_size        = ISCSI_SCSI_EMU_BLOCK_SIZE;
		globvec->scsi_logical_block_size_shift  = iscsi_get_log2_of_pow2( globvec->scsi_logical_block_size );

		iscsi_config_load( globvec );

		iscsi_globvec = globvec;
	}

	pthread_rwlock_unlock( &iscsi_globvec_rwlock );

	return 0;
}

/**
 * @brief Deallocates all resources acquired by iscsi_create.
 *
 * This function MUST be called before program termination
 * for ensuring proper clean up.\n
 * After this function returns, calling any iSCSI related
 * function except iscsi_create is strictly forbidden.\n
 * It is safe to call this function if the iSCSI global
 * vector already has been destroyed in which case this
 * function does nothing.
 */
void iscsi_destroy()
{
	pthread_rwlock_wrlock( &iscsi_globvec_rwlock );

	iscsi_globals *globvec = iscsi_globvec;

	if ( globvec != NULL ) {
		iscsi_globvec = NULL;

		pthread_mutex_destroy( &globvec->scsi_device_config_mutex );
		iscsi_hashmap_iterate( globvec->scsi_device_config, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( globvec->scsi_device_config );
		globvec->scsi_device_config = NULL;

		iscsi_hashmap_iterate( globvec->connection_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( globvec->connection_key_value_pairs );
		globvec->connection_key_value_pairs = NULL;

		iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( globvec->session_key_value_pairs );
		globvec->session_key_value_pairs = NULL;

		pthread_rwlock_destroy( &globvec->sessions_rwlock );
		iscsi_hashmap_iterate( globvec->sessions, iscsi_session_destroy_callback, NULL );
		iscsi_hashmap_destroy( globvec->sessions );
		globvec->sessions = NULL;

		pthread_rwlock_destroy( &globvec->target_nodes_rwlock );
		iscsi_hashmap_iterate( globvec->target_nodes, iscsi_target_node_destroy_callback, NULL );
		iscsi_hashmap_destroy( globvec->target_nodes );
		globvec->target_nodes = NULL;

		pthread_rwlock_destroy( &globvec->portal_groups_rwlock );
		iscsi_hashmap_iterate( globvec->portal_groups, iscsi_portal_group_destroy_callback, NULL );
		iscsi_hashmap_destroy( globvec->portal_groups );
		globvec->portal_groups = NULL;

		pthread_rwlock_destroy( &globvec->devices_rwlock );
		iscsi_hashmap_iterate( globvec->devices, iscsi_device_destroy_callback, NULL );
		iscsi_hashmap_destroy( globvec->devices );
		globvec->devices = NULL;

		free( globvec );
	}

	pthread_rwlock_unlock( &iscsi_globvec_rwlock );
}

/**
 * @brief Parses an INI configuration value and returns an integer representation of string with special boolean and suffixes handling.
 *
 * This function also handles boolean values 'true',
 * 'yes', 'on', 'enabled' and 'activated', returning 1
 * for them, as well as 'false', 'no', 'off', 'disabled'
 * and 'deactivated' having a return value of 0.\n
 * Also the suffixes 'm' for minutes, 'h' for hours and
 * 'd' for days are understood as time units.\n
 * SI units 'K', 'M', 'G', 'T', 'P' and 'E' are
 * understood as well.\n
 * If a 'b' or 'B' follows, 1000 will be used as a
 * multiplier instead of 1024.\n
 * Parsing will be internally done in 64 bits and the
 * final result is clamped between -2147483647 and
 * 2147483647.
 *
 * @param[in] value Pointer to string for parsing. May
 * NOT be NULL, so be careful.
 * @return Parsed integer value or -2147483648
 * in case of an error.
 */
static int32_t iscsi_config_parse_int(const uint8_t *value)
{
	if ( *value == '\0' )
		return -2147483648L;

	if ( (strcasecmp( (char *) value, "true" ) == 0) || (strcasecmp( (char *) value, "yes" ) == 0) || (strcasecmp( (char *) value, "on" ) == 0) || (strcasecmp( (char *) value, "enabled" ) == 0) || (strcasecmp( (char *) value, "activated" ) == 0) )
		return 1L;
	else if ( (strcasecmp( (char *) value, "false" ) == 0) || (strcasecmp( (char *) value, "no" ) == 0) || (strcasecmp( (char *) value, "off" ) == 0) || (strcasecmp( (char *) value, "disabled" ) == 0) || (strcasecmp( (char *) value, "deactivated" ) == 0) )
		return 0L;

	uint8_t *val_end;
	int64_t rc = (int64_t) strtoll( (char *) value, (char **) &val_end, 10 );

	if ( value == val_end )
		return -2147483648L;

	while ( (*val_end == '\t') || (*val_end == ' ') ) {
		val_end++;
	}

	switch ( *val_end ) {
		case '\0' : {
			break;
		}
		case 'm' : {
			rc *= 60LL;
			val_end++;

			break;
		}
		case 'h' : {
			rc *= 3600LL;
			val_end++;

			break;
		}
		case 'd' : {
			rc *= 86400LL;
			val_end++;

			break;
		}
		default : {
			const uint8_t c = (*val_end++ | ('a' - 'A'));
			const bool ten  = ((*val_end | ('a' - 'A')) == 'b');

			switch ( c ) {
				case 'k' : {
					rc = (ten ? (rc * 1000LL) : (rc << 10LL));

					break;
				}
				case 'm' : {
					rc = (ten ? (rc * 1000000LL) : (rc << 20LL));

					break;
				}
				case 'g' : {
					rc = (ten ? (rc * 1000000000LL) : (rc << 30LL));

					break;
				}
				case 't' : {
					rc = (ten ? (rc * 1000000000000LL) : (rc << 40LL));

					break;
				}
				case 'p' : {
					rc = (ten ? (rc * 1000000000000000LL) : (rc << 50LL));

					break;
				}
				case 'e' : {
					rc = (ten ? (rc * 1000000000000000000LL) : (rc << 60LL));

					break;
				}
				default : {
					return -2147483648L;

					break;
				}
			}

			if ( ten )
				val_end++;

			break;
		}
	}

	if ( *val_end != '\0' )
		return -2147483648L;

	if ( rc < -2147483647LL )
		rc = -2147483647LL;
	else if ( rc > 2147483647LL )
		rc = 2147483647LL;

	return (int32_t) rc;
}

/**
 * @brief Callback function from DNBD3 INI parser invoked for handling a specific key=value pair in a specified INI section.
 *
 * This function checks whether the INI
 * section belongs to the iSCSI server
 * configuration part.\n
 * Currently, the sections 'iscsi' and
 * 'scsi' for the SCSI emulation are
 * processed.
 *
 * @param[in] user_data Pointer to iSCSI global vector where
 * to store the configuration data. May
 * NOT be NULL, so be careful.
 * @param[in] section Pointer to currently processing
 * INI section. NULL is NOT allowed here,
 * take caution.
 * @param[in] key Pointer to currently processing INI
 * key. May NOT be NULL, so be careful.
 * @param[in] value Pointer to currently processing INI
 * value. NULL is prohibited, so take
 * caution.
 * @retval 1 INI parsing was successful.
 * @retval 0 An error occured during INI parsing.
 */
static int iscsi_config_load_from_ini(void *user_data, const char *section, const char *key, const char *value)
{
	iscsi_globals *globvec = (iscsi_globals *) user_data;

	if ( strcasecmp( section, ISCSI_GLOBALS_SECTION_ISCSI ) == 0 ) {
		const int32_t num_value = iscsi_config_parse_int( (uint8_t *) value );

		if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_ISCSI_KEY_TARGET_NAME_CHECK ) == 0 ) {
			if ( strcasecmp( value, "None" ) == 0 )
				globvec->target_name_check = ISCSI_GLOBALS_TARGET_NAME_CHECK_NONE;
			else if ( strcasecmp( value, "Relaxed" ) == 0 )
				globvec->target_name_check = ISCSI_GLOBALS_TARGET_NAME_CHECK_RELAXED;
			else
				globvec->target_name_check = ISCSI_GLOBALS_TARGET_NAME_CHECK_FULL;
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_ISCSI_KEY_MAX_SESSIONS ) == 0 ) {
			globvec->max_sessions = (uint) num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST ) == 0 ) {
			globvec->header_digest = ((strcasecmp( value, "CRC32C" ) == 0) ? ISCSI_DIGEST_SIZE : 0);
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST ) == 0 ) {
			globvec->data_digest = ((strcasecmp( value, "CRC32C" ) == 0) ? ISCSI_DIGEST_SIZE : 0);
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN ) == 0 ) {
			if ( (num_value >= 512L) && (num_value <= (int32_t) ISCSI_MAX_DS_SIZE) )
				globvec->max_recv_ds_len = num_value;
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_ISCSI_MAX_CONNECTIONS_PER_SESSIONS ) == 0 ) {
			if ( (num_value > 0L) && (num_value <= 65535L) )
				globvec->max_session_conns = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T ) == 0 ) {
			if ( (num_value > 0L) && (num_value <= 65536L) )
				globvec->max_outstanding_r2t = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_WAIT ) == 0 ) {
			if ( (uint32_t) num_value <= 3600UL )
				globvec->default_time_to_wait = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_RETAIN ) == 0 ) {
			if ( (uint32_t) num_value <= 3600UL )
				globvec->default_time_to_retain = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN ) == 0 ) {
			if ( (num_value >= 512L) && (num_value <= (int32_t) ISCSI_MAX_DS_SIZE) )
				globvec->first_burst_len = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN ) == 0 ) {
			if ( (num_value >= 512L) && (num_value <= (int32_t) ISCSI_MAX_DS_SIZE) )
				globvec->max_burst_len = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_INIT_R2T;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_INIT_R2T;
			}
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA;
			}
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_PDU_IN_ORDER ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER;
			}
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_SEQ_IN_ORDER ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER;
			}
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_ERR_RECOVERY_LEVEL ) == 0 ) {
			if ( (uint32_t) num_value <= 2UL )
				globvec->err_recovery_level = num_value;
		}
	} else if ( strcasecmp( section, ISCSI_GLOBALS_SECTION_SCSI ) == 0 ) {
		int32_t num_value = iscsi_config_parse_int( (uint8_t *) value );

		if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_DEVICE_TYPE ) == 0 ) {
			if ( strcasecmp( value, "Sequential" ) == 0 )
				globvec->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_SEQ;
			else if ( strcasecmp( value, "WriteOnce" ) == 0 )
				globvec->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_WORM;
			else if ( strcasecmp( value, "ReadOnlyDirect" ) == 0 )
				globvec->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_RO_DIRECT;
			else if ( strcasecmp( value, "OpticalMemory" ) == 0 )
				globvec->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_OPTICAL;
			else if ( strcasecmp( value, "MediaChanger" ) == 0 )
				globvec->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_CHANGER;
			else
				globvec->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_DIRECT;
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_PHYSICAL_BLOCK_SIZE ) == 0 ) {
			num_value = iscsi_align_pow2_ceil( num_value );

			if ( (num_value >= 256L) && (num_value <= 32768L) ) {
				globvec->scsi_physical_block_size       = num_value;
				globvec->scsi_physical_block_size_shift = iscsi_get_log2_of_pow2( num_value );
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_LOGICAL_BLOCK_SIZE ) == 0 ) {
			num_value = iscsi_align_pow2_ceil( num_value );

			if ( (num_value >= 256L) && (num_value <= 32768L) ) {
				globvec->scsi_logical_block_size       = num_value;
				globvec->scsi_logical_block_size_shift = iscsi_get_log2_of_pow2( num_value );
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_REMOVABLE ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_SCSI_IO_REMOVABLE;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_SCSI_IO_REMOVABLE;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_UNMAP ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_SCSI_IO_UNMAP;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_SCSI_IO_UNMAP;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_NO_ROTATION ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_SCSI_IO_NO_ROTATION;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_SCSI_IO_NO_ROTATION;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_PHYSICAL_READ_ONLY ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_WRITE_PROTECT ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_PROTECT;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_PROTECT;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_WRITE_CACHE ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					globvec->flags |= ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_CACHE;
				else
					globvec->flags &= ~ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_CACHE;
			}
		}
	} else if ( strncasecmp( section, ISCSI_GLOBALS_SECTION_SCSI_DEVICE_PREFIX, ISCSI_STRLEN(ISCSI_GLOBALS_SECTION_SCSI_DEVICE_PREFIX) ) == 0 ) {
		uint8_t *pattern   = (((uint8_t *) section) + ISCSI_STRLEN(ISCSI_GLOBALS_SECTION_SCSI_DEVICE_PREFIX));
		const uint key_len = (uint) (strlen( (char *) pattern ) + 1U);

		if ( key_len == 0U )
			return 0;

		uint8_t *hash_key  = iscsi_hashmap_key_create( pattern, key_len );

		if ( hash_key == NULL ) {
			logadd( LOG_ERROR, "iscsi_config_load_from_ini: Out of memory allocating memory for iSCSI SCSI device INI configuration section key" );

			return 0;
		}

		iscsi_scsi_device_config *scsi_device_config = NULL;
		int rc                                       = iscsi_hashmap_get( globvec->scsi_device_config, hash_key, key_len, (uint8_t **) &scsi_device_config );

		if ( scsi_device_config == NULL ) {
			scsi_device_config = (iscsi_scsi_device_config *) malloc( sizeof(struct iscsi_scsi_device_config) );

			if ( scsi_device_config == NULL ) {
				logadd( LOG_ERROR, "iscsi_config_load_from_ini: Out of memory allocating memory for iSCSI SCSI device configuration" );

				iscsi_hashmap_key_destroy( hash_key );

				return 0;
			}

			scsi_device_config->flags = 0;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_INIT_R2T) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_INIT_R2T;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_IMMEDIATE_DATA;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_DATA_PDU_IN_ORDER;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_DATA_SEQ_IN_ORDER;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_REMOVABLE) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_REMOVABLE;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_UNMAP) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_UNMAP;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_NO_ROTATION) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_NO_ROTATION;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_PROTECT) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_PROTECT;

			if ( (globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_CACHE) != 0 )
				scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_CACHE;

			scsi_device_config->header_digest                  = globvec->header_digest;
			scsi_device_config->data_digest                    = globvec->data_digest;
			scsi_device_config->scsi_device_type               = globvec->scsi_device_type;
			scsi_device_config->max_recv_ds_len                = globvec->max_recv_ds_len;
			scsi_device_config->max_session_conns              = globvec->max_session_conns;
			scsi_device_config->max_outstanding_r2t            = globvec->max_outstanding_r2t;
			scsi_device_config->default_time_to_wait           = globvec->default_time_to_wait;
			scsi_device_config->default_time_to_retain         = globvec->default_time_to_retain;
			scsi_device_config->first_burst_len                = globvec->first_burst_len;
			scsi_device_config->max_burst_len                  = globvec->max_burst_len;
			scsi_device_config->err_recovery_level             = globvec->err_recovery_level;
			scsi_device_config->scsi_physical_block_size       = globvec->scsi_physical_block_size;
			scsi_device_config->scsi_physical_block_size_shift = globvec->scsi_physical_block_size_shift;
			scsi_device_config->scsi_logical_block_size        = globvec->scsi_logical_block_size;
			scsi_device_config->scsi_logical_block_size_shift  = globvec->scsi_logical_block_size_shift;

			rc = iscsi_hashmap_put( globvec->scsi_device_config, hash_key, key_len, (uint8_t *) scsi_device_config );

			if ( rc < 0 ) {
				free( scsi_device_config );
				iscsi_hashmap_key_destroy( hash_key );

				return 0;
			}
		} else {
			iscsi_hashmap_key_destroy( hash_key );
		}

		int32_t num_value = iscsi_config_parse_int( (uint8_t *) value );

		if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST ) == 0 ) {
			scsi_device_config->header_digest = ((strcasecmp( value, "CRC32C" ) == 0) ? ISCSI_DIGEST_SIZE : 0);
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST ) == 0 ) {
			scsi_device_config->data_digest = ((strcasecmp( value, "CRC32C" ) == 0) ? ISCSI_DIGEST_SIZE : 0);
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN ) == 0 ) {
			if ( (num_value >= 512L) && (num_value <= (int32_t) ISCSI_MAX_DS_SIZE) )
				scsi_device_config->max_recv_ds_len = num_value;
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_ISCSI_MAX_CONNECTIONS_PER_SESSIONS ) == 0 ) {
			if ( (num_value > 0L) && (num_value <= 65535L) )
				scsi_device_config->max_session_conns = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T ) == 0 ) {
			if ( (num_value > 0L) && (num_value <= 65536L) )
				scsi_device_config->max_outstanding_r2t = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_WAIT ) == 0 ) {
			if ( (uint32_t) num_value <= 3600UL )
				scsi_device_config->default_time_to_wait = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_RETAIN ) == 0 ) {
			if ( (uint32_t) num_value <= 3600UL )
				scsi_device_config->default_time_to_retain = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN ) == 0 ) {
			if ( (num_value >= 512L) && (num_value <= (int32_t) ISCSI_MAX_DS_SIZE) )
				scsi_device_config->first_burst_len = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN ) == 0 ) {
			if ( (num_value >= 512L) && (num_value <= (int32_t) ISCSI_MAX_DS_SIZE) )
				scsi_device_config->max_burst_len = num_value;
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_FLAGS_INIT_R2T;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_FLAGS_INIT_R2T;
			}
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA;
			}
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_PDU_IN_ORDER ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER;
			}
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_SEQ_IN_ORDER ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER;
			}
		} else if ( strcasecmp( key, (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_ERR_RECOVERY_LEVEL ) == 0 ) {
			if ( (uint32_t) num_value <= 2UL )
				scsi_device_config->err_recovery_level = num_value;
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_DEVICE_TYPE ) == 0 ) {
			if ( strcasecmp( value, "Sequential" ) == 0 )
				scsi_device_config->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_SEQ;
			else if ( strcasecmp( value, "WriteOnce" ) == 0 )
				scsi_device_config->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_WORM;
			else if ( strcasecmp( value, "ReadOnlyDirect" ) == 0 )
				scsi_device_config->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_RO_DIRECT;
			else if ( strcasecmp( value, "OpticalMemory" ) == 0 )
				scsi_device_config->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_OPTICAL;
			else if ( strcasecmp( value, "MediaChanger" ) == 0 )
				scsi_device_config->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_CHANGER;
			else
				scsi_device_config->scsi_device_type = ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_DIRECT;
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_PHYSICAL_BLOCK_SIZE ) == 0 ) {
			num_value = iscsi_align_pow2_ceil( num_value );

			if ( (num_value >= 256L) && (num_value <= 32768L) ) {
				scsi_device_config->scsi_physical_block_size       = num_value;
				scsi_device_config->scsi_physical_block_size_shift = iscsi_get_log2_of_pow2( num_value );
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_LOGICAL_BLOCK_SIZE ) == 0 ) {
			num_value = iscsi_align_pow2_ceil( num_value );

			if ( (num_value >= 256L) && (num_value <= 32768L) ) {
				scsi_device_config->scsi_logical_block_size       = num_value;
				scsi_device_config->scsi_logical_block_size_shift = iscsi_get_log2_of_pow2( num_value );
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_REMOVABLE ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_REMOVABLE;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_REMOVABLE;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_UNMAP ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_UNMAP;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_UNMAP;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_NO_ROTATION ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_NO_ROTATION;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_NO_ROTATION;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_PHYSICAL_READ_ONLY ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_WRITE_PROTECT ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_PROTECT;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_PROTECT;
			}
		} else if ( strcasecmp( key, ISCSI_GLOBALS_SECTION_SCSI_KEY_WRITE_CACHE ) == 0 ) {
			if ( num_value != -2147483648L ) {
				if ( num_value != 0L )
					scsi_device_config->flags |= ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_CACHE;
				else
					scsi_device_config->flags &= ~ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_CACHE;
			}
		}
	}

	return 1;
}

/**
 * @brief Loads iSCSI server configuration from INI file.
 *
 * This function parses the INI configuration file
 * and assigns it to the config section of the iSCSI
 * global vector.
 *
 * @param[in] globvec Pointer to iSCSI global vector where to store
 * the parsed and processed results. May NOT be
 * NULL, so be careful.
 *
 * @return Number of configuration keys parsed or
 * a neagtive error code otherwise.
 */
int iscsi_config_load(iscsi_globals *globvec)
{
	char *name = (char *) iscsi_sprintf_alloc( "%s/%s", _configDir, CONFIG_FILENAME );

	if ( name == NULL )
		return -1;

	if ( !file_isReadable( name ) ) {
		free( name );

		return 0;
	}

	pthread_mutex_lock( &globvec->scsi_device_config_mutex );
	iscsi_hashmap_iterate( globvec->scsi_device_config, iscsi_hashmap_key_destroy_value_callback, NULL );
	ini_parse( name, iscsi_config_load_from_ini, (void *) globvec );
	free( name );

	name = (char *) iscsi_sprintf_alloc( "%s/%s", _configDir, ISCSI_GLOBALS_CONFIG_FILENAME );

	if ( name == NULL ) {
		pthread_mutex_unlock( &globvec->scsi_device_config_mutex );

		return -1;
	}

	if ( !file_isReadable( name ) ) {
		pthread_mutex_unlock( &globvec->scsi_device_config_mutex );
		free( name );

		return 0;
	}

	ini_parse( name, iscsi_config_load_from_ini, (void *) globvec );
	pthread_mutex_unlock( &globvec->scsi_device_config_mutex );
	free( name );

	return 1;
}

/**
 * @brief Finds an iSCSI SCSI device configuration by name using pattern matching.
 *
 * Callback function for each element while iterating
 * through the iSCSI SCSI device configuration hash
 * map.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL creates an
 * empty key assignment.
 * @param[in,out] user_data Pointer to a data structure
 * containing the iSCSI SCSI device configuration and
 * the name to be searched for and may NOT be NULL,
 * so be careful.
 * @retval -1 The SCSI device configuration has been found and
 * stored in the result structure. Therefore, no
 * further searching is needed.
 * @retval -2 An error occured during matching the
 * name.
 * @retval 0 The SCSI device configuration has not been found
 * yet.
 */
int iscsi_config_get_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_scsi_device_config_find *scsi_device_config_find = (iscsi_scsi_device_config_find *) user_data;
	const int rc                                           = fnmatch( (char *) key, (char *) scsi_device_config_find->name, (FNM_PATHNAME | FNM_PERIOD) );

	if ( rc == FNM_NOMATCH )
		return 0;

	if ( rc != 0 )
		return -2;

	scsi_device_config_find->scsi_device_config = (iscsi_scsi_device_config *) value;

	return -1;
}

/**
 * @brief Retrieves a configuration value either from the iSCSI global vector or for a specified SCSI device name.
 *
 * This function uses wildcard matching
 * only if the SCSI device name does NOT
 * have a direct match.
 *
 * @param[in] name Pointer to SCSI configuration name to
 * be retrieved or NULL if the iSCSI
 * global vector configuration should
 * be accessed instead.
 * @param[in] type Type of configuration to be
 * retrieved.
 * @return The requested configuration value or a
 * negative error code otherwise.
 */
int32_t iscsi_config_get(uint8_t *name, const int type)
{
	if ( name != NULL ) {
		const uint key_len = (uint) (strlen( (char *) name ) + 1U);
		uint8_t *hash_key  = iscsi_hashmap_key_create( name, key_len );

		if ( hash_key == NULL ) {
			logadd( LOG_ERROR, "iscsi_config_get: Out of memory allocating memory for iSCSI SCSI device configuration key" );

			return -1L;
		}

		pthread_mutex_lock( &iscsi_globvec->scsi_device_config_mutex );

		iscsi_scsi_device_config *scsi_device_config = NULL;
		int rc                                       = iscsi_hashmap_get( iscsi_globvec->scsi_device_config, hash_key, key_len, (uint8_t **) &scsi_device_config );

		if ( rc < 0 ) {
			iscsi_scsi_device_config_find scsi_device_config_find = {NULL, name};

			rc = iscsi_hashmap_iterate(iscsi_globvec->scsi_device_config, iscsi_config_get_callback, (uint8_t *) &scsi_device_config_find );

			scsi_device_config = scsi_device_config_find.scsi_device_config;

			if ( scsi_device_config != NULL ) {
				iscsi_scsi_device_config *new_scsi_device_config = (iscsi_scsi_device_config *) malloc( sizeof(struct iscsi_scsi_device_config) );

				if ( new_scsi_device_config == NULL ) {
					logadd( LOG_ERROR, "iscsi_config_get: Out of memory allocating memory for new iSCSI SCSI device configuration" );

					pthread_mutex_unlock( &iscsi_globvec->scsi_device_config_mutex );
					iscsi_hashmap_key_destroy( hash_key );

					return -1L;
				}

				memcpy( new_scsi_device_config, scsi_device_config, sizeof(struct iscsi_scsi_device_config) );
				rc = iscsi_hashmap_put( iscsi_globvec->scsi_device_config, hash_key, key_len, (uint8_t *) new_scsi_device_config );

				if ( rc < 0 ) {
					pthread_mutex_unlock( &iscsi_globvec->scsi_device_config_mutex );
					free( new_scsi_device_config );
					iscsi_hashmap_key_destroy( hash_key );

					return -1L;
				}

				scsi_device_config = new_scsi_device_config;
				hash_key           = NULL;
			}
		}

		pthread_mutex_unlock( &iscsi_globvec->scsi_device_config_mutex );

		if ( hash_key != NULL )
			iscsi_hashmap_key_destroy( hash_key );

		if ( scsi_device_config != NULL ) {
			switch ( type ) {
				case ISCSI_GLOBALS_CONFIG_TYPE_HEADER_DIGEST : {
					return scsi_device_config->header_digest;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_DATA_DIGEST : {
					return scsi_device_config->data_digest;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_MAX_RECV_DS_LEN : {
					return scsi_device_config->max_recv_ds_len;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_MAX_SESSION_CONNS : {
					return scsi_device_config->max_session_conns;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_MAX_OUTSTANDING_R2T : {
					return scsi_device_config->max_outstanding_r2t;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_DEFAULT_TIME_TO_WAIT : {
					return scsi_device_config->default_time_to_wait;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_DEFAULT_TIME_TO_RETAIN : {
					return scsi_device_config->default_time_to_retain;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FIRST_BURST_LEN : {
					return scsi_device_config->first_burst_len;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_MAX_BURST_LEN : {
					return scsi_device_config->max_burst_len;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_ERR_RECOVERY_LEVEL : {
					return scsi_device_config->err_recovery_level;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE : {
					return scsi_device_config->scsi_physical_block_size;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_DEVICE_TYPE : {
					return scsi_device_config->scsi_device_type;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE_SHIFT : {
					return scsi_device_config->scsi_physical_block_size_shift;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE : {
					return scsi_device_config->scsi_logical_block_size;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE_SHIFT : {
					return scsi_device_config->scsi_logical_block_size_shift;

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_INIT_R2T : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_INIT_R2T) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_IMMEDIATE_DATA : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_IMMEDIATE_DATA) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_DATA_PDU_IN_ORDER : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_DATA_PDU_IN_ORDER) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_DATA_SEQ_IN_ORDER : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_DATA_SEQ_IN_ORDER) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_REMOVABLE : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_REMOVABLE) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_UNMAP : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_UNMAP) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_NO_ROTATION : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_NO_ROTATION) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_PROTECT : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_PROTECT) != 0) ? 1L : 0L);

					break;
				}
				case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_CACHE : {
					return (((scsi_device_config->flags & ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_CACHE) != 0) ? 1L : 0L);

					break;
				}
				default : {
					return -1L;

					break;
				}
			}
		}
	}

	switch ( type ) {
		case ISCSI_GLOBALS_CONFIG_TYPE_HEADER_DIGEST : {
			return iscsi_globvec->header_digest;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_DATA_DIGEST : {
			return iscsi_globvec->data_digest;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_MAX_RECV_DS_LEN : {
			return iscsi_globvec->max_recv_ds_len;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_MAX_SESSION_CONNS : {
			return iscsi_globvec->max_session_conns;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_MAX_OUTSTANDING_R2T : {
			return iscsi_globvec->max_outstanding_r2t;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_DEFAULT_TIME_TO_WAIT : {
			return iscsi_globvec->default_time_to_wait;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_DEFAULT_TIME_TO_RETAIN : {
			return iscsi_globvec->default_time_to_retain;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FIRST_BURST_LEN : {
			return iscsi_globvec->first_burst_len;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_MAX_BURST_LEN : {
			return iscsi_globvec->max_burst_len;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_ERR_RECOVERY_LEVEL : {
			return iscsi_globvec->err_recovery_level;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_DEVICE_TYPE : {
			return iscsi_globvec->scsi_device_type;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE : {
			return iscsi_globvec->scsi_physical_block_size;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE_SHIFT : {
			return iscsi_globvec->scsi_physical_block_size_shift;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE : {
			return iscsi_globvec->scsi_logical_block_size;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE_SHIFT : {
			return iscsi_globvec->scsi_logical_block_size_shift;

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_INIT_R2T : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_INIT_R2T) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_IMMEDIATE_DATA : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_DATA_PDU_IN_ORDER : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_DATA_SEQ_IN_ORDER : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_REMOVABLE : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_REMOVABLE) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_UNMAP : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_UNMAP) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_NO_ROTATION : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_NO_ROTATION) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_PROTECT : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_PROTECT) != 0) ? 1L : 0L);

			break;
		}
		case ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_CACHE : {
			return (((iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_CACHE) != 0) ? 1L : 0L);

			break;
		}
		default : {
			return -1L;

			break;
		}
	}

	return -1L;
}

/**
 * @brief Extracts a single text key / value pairs out of an iSCSI packet into a hash map.
 *
 * Parses and extracts a specific key and value pair out of an iSCSI packet
 * data stream amd puts the extracted data into a hash map to be used by
 * the iSCSI implementation.
 *
 * @param[in] key_value_pairs Pointer to hash map containing all related keys and pairs.
 * May NOT be NULL, so take caution.
 * @param[in] packet_data Pointer to key / value pair to be parsed. NULL is
 * an illegal value, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @return Number of bytes used by the extracted key / vair pair or
 * a negative value in case of an error. This can be used for
 * incrementing the offset to the next key / value pair.
 */
static int iscsi_parse_text_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *packet_data, const uint32_t len)
{
	const uint key_val_len = (uint) strnlen( (char *) packet_data, len );
	const uint8_t *key_end = memchr( packet_data, '=', key_val_len );

	if ( key_end == NULL ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Key / value separator '=' not found" );

		return -1;
	}

	const uint key_len = (uint) (key_end - packet_data);

	if ( key_len == 0U ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Empty key found which is NOT allowed according to iSCSI specs" );

		return -1;
	}

	if ( key_len > ISCSI_TEXT_KEY_MAX_LEN ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Key value is too large (max 63 bytes)" );

		return -1;
	}

	const uint hash_key_len = (key_len + 1U);
	uint8_t *hash_key = iscsi_hashmap_key_create( packet_data, hash_key_len );

	if ( hash_key == NULL )
		return -1;

	hash_key[key_len] = '\0';

	if ( iscsi_hashmap_contains( key_value_pairs, hash_key, hash_key_len ) ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Forbidden duplicate key discovered" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1;
	}

	const uint val_len = (uint) (strnlen( (char *) (key_end + 1U), (key_val_len - key_len - 1U) ) + 1U);
	const uint max_len = (((strcmp( (char *) hash_key, "CHAP_C" ) == 0) || (strcmp( (char *) hash_key, "CHAP_R" ) == 0)) ? ISCSI_TEXT_VALUE_MAX_LEN : ISCSI_TEXT_VALUE_MAX_SIMPLE_LEN);

	if ( val_len > max_len ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Value length larger than iSCSI specs allow" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1;
	}

	uint8_t *hash_val = (uint8_t *) malloc( ISCSI_ALIGN(val_len, ISCSI_TEXT_VALUE_ALIGN) );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Out of memory allocating memory for value string" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1;
	}

	memcpy( hash_val, (key_end + 1), val_len );

	const int rc = iscsi_hashmap_put( key_value_pairs, hash_key, hash_key_len, hash_val );

	if ( rc < 0 )
		return -1;

	return (int) (hash_key_len + val_len);
}

/**
 * @brief Extracts all text key / value pairs out of an iSCSI packet into a hash map.
 *
 * Parses and extracts all key and value pairs out of iSCSI packet
 * data amd puts the extracted data into a hash map to be used by
 * the iSCSI implementation.
 *
 * @param[in] key_value_pairs Pointer to hash map that should contain all
 * extracted keys and pairs. May NOT be NULL, so take caution.
 * @param[in] packet_data Pointer to first key and value pair to
 * be parsed. NULL is an illegal value here, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @param[in] c_bit Non-zero value of C bit was set in previously.
 * @param[in] partial_pairs Array of partial pair pointers in
 * case C bit was set (multiple iSCSI packets for text data).
 * @retval -1 An error occured during parsing key.
 * @retval 0 Key and value pair was parsed successfully and was added to
 * hash map.
 */
int iscsi_parse_key_value_pairs(iscsi_hashmap *key_value_pairs, const uint8_t *packet_data, uint len, int c_bit, uint8_t **partial_pairs)
{
	if ( len == 0U )
		return 0; // iSCSI specs don't allow zero length

	if ( (partial_pairs != NULL) && (*partial_pairs != NULL) ) { // Strip partial text parameters in case C bit was enabled previously
		uint key_val_pair_len;

		for (key_val_pair_len = 0; (key_val_pair_len < len) && packet_data[key_val_pair_len] != '\0'; key_val_pair_len++) {
		}

		uint8_t *tmp_partial_buf = iscsi_sprintf_alloc( "%s%s", *partial_pairs, (const char *) packet_data );

		if ( tmp_partial_buf == NULL )
			return -1;

		const int rc = iscsi_parse_text_key_value_pair( key_value_pairs, tmp_partial_buf, (uint32_t) (key_val_pair_len + strlen( (char *) *partial_pairs )) );
		free( tmp_partial_buf );

		if ( rc < 0 )
			return -1;

		free( *partial_pairs );
		*partial_pairs = NULL;

		packet_data += (key_val_pair_len + 1);
		len         -= (key_val_pair_len + 1);
	}

	if ( c_bit ) { // Strip partial parameters in case C bit was enabled previousley
		if ( partial_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_parse_key_value_pairs: C bit set but missing partial parameter" );

			return -1;
		}

		uint key_val_pair_len;

		for (key_val_pair_len = (len - 1U); (packet_data[key_val_pair_len] != '\0') && (key_val_pair_len > 0U); key_val_pair_len--) {
		}

		if ( key_val_pair_len != 0U )
			key_val_pair_len++; // NUL char found, don't copy to target buffer'

		*partial_pairs = (uint8_t *) malloc( ((len - key_val_pair_len) + 1U) );

		if ( *partial_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_parse_key_value_pairs: Out of memory allocating partial parameter" );

			return -1;
		}

		memcpy( *partial_pairs, &packet_data[key_val_pair_len], (len - key_val_pair_len) );

		if ( key_val_pair_len != 0U )
			len = (key_val_pair_len - 1U);
		else
			return 0;
	}

	int offset = 0;

	while ( ((uint) offset < len) && (packet_data[offset] != '\0') ) {
		const int rc = iscsi_parse_text_key_value_pair( key_value_pairs, (packet_data + offset), (len - offset) );

		if ( rc < 0 )
			return -1;

		offset += rc;
	}

	return 0;
}

/**
 * @brief Extracts a string from a key and value pair.
 *
 * This function calculates the length of the key
 * for the hash map function and returns the value
 * as string.
 *
 * @param[in] key_value_pairs The hash map containing the key and value pairs to be extracted.
 * @param[in] key The key to retrieve the string value from.
 * @param[out] out_value The string value of the key is stored here.
 * @retval -1 An error occured during value retrieval.
 * 'out value' is unchanged.
 * @retval 0 The value of the key has been successfully
 * stored in the 'out_value'.
 */
static int iscsi_get_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, uint8_t **out_value)
{
	const uint key_len = (uint) (strlen( (char *) key ) + 1U);

	return iscsi_hashmap_get( key_value_pairs, key, key_len, out_value );
}

/**
 * @brief Allocates and adds a string value to a key / value hash map pair.
 *
 * This function allocates memory for a string key
 * and its string value.
 *
 * @param[in] key_value_pairs Pointer to the hash map which should
 * contain the added string key and value pair.
 * NULL is NOT allowed here, so be careful.
 * @param[in] key String containing the key name as string. May
 * NOT be NULL, so take caution.
 * @param[in] value String containing the value to be stored.
 * @return 0 on successful operation, or a negative value on
 * error (memory exhaustion).
 */
static int iscsi_add_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, const uint8_t *value)
{
	const uint key_len = (uint) (strlen( (char *) key ) + 1U);
	uint8_t *hash_key = iscsi_hashmap_key_create( key, key_len );

	if ( hash_key == NULL ) {
		logadd( LOG_ERROR, "iscsi_add_key_value_pair: Out of memory allocating key" );

		return -1;
	}

	const uint val_len = (uint) (strlen( (char *) value ) + 1U);
	uint8_t *hash_val = (uint8_t *) malloc( ISCSI_ALIGN(val_len, ISCSI_TEXT_VALUE_ALIGN) );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_add_key_value_pair: Out of memory allocating string value" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1;
	}

	memcpy( hash_val, value, val_len );

	return iscsi_hashmap_put( key_value_pairs, hash_key, key_len, hash_val );
}

/**
 * @brief Allocates and updates a string value of a key / value hash map pair.
 *
 * This function allocates memory for a string key
 * and its string value.\n
 * If the key does not exist, it will be added as
 * a new one.
 *
 * @param[in] key_value_pairs Pointer to the hash map which should
 * contain the updated string key and value pair.
 * NULL is NOT allowed here, so be careful.
 * @param[in] key String containing the key name as string. May
 * NOT be NULL, so take caution.
 * @param[in] value String containing the value to be stored.
 * @return 0 on successful operation, or a negative value on
 * error (memory exhaustion).
 */
static int iscsi_update_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, const uint8_t *value)
{
	const uint key_len = (uint) (strlen( (char *) key ) + 1U);
	uint8_t *hash_key = iscsi_hashmap_key_create( key, key_len );

	if ( hash_key == NULL ) {
		logadd( LOG_ERROR, "iscsi_update_key_value_pair: Out of memory allocating key" );

		return -1;
	}

	const uint val_len = (uint) (strlen( (char *) value ) + 1U);
	uint8_t *hash_val = (uint8_t *) malloc( ISCSI_ALIGN(val_len, ISCSI_TEXT_VALUE_ALIGN) );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_update_key_value_pair: Out of memory allocating string value" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1;
	}

	memcpy( hash_val, value, val_len );

	return iscsi_hashmap_put_free( key_value_pairs, hash_key, key_len, hash_val, iscsi_hashmap_key_destroy_value_callback, NULL );
}

/**
 * @brief Extracts an integer value from a key and value pair.
 *
 * This function converts a string representation of a
 * key and value pair to an integer value.
 *
 * @param[in] key_value_pairs The hash map containing the key and value pairs to be extracted.
 * @param[in] key The key to retrieve the integer value from.
 * @param[out] out_value The integer value of the key is stored here
 * or 0 in case of an error during string to integer conversion.
 * @retval -1 An error occured during value retrieval.
 * 'out value' is unchanged.
 * @retval 0 The value of the key has been successfully
 * stored in the 'out_value'.
 */
static int iscsi_get_int_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, int32_t *out_value)
{
	uint8_t *str_val;
	int rc = iscsi_get_key_value_pair( key_value_pairs, key, &str_val );

	if ( rc == 0 )
		*out_value = (int32_t) atol( (char *) str_val );

	return rc;
}

/**
 * @brief Allocates and adds an integer value to a key / value hash map pair.
 *
 * This function allocates memory for a string key
 * and its integer representation as string value.
 *
 * @param[in] key_value_pairs Pointer to the hash map which should
 * contain the added integer key and value pair.
 * NULL is NOT allowed here, so be careful.
 * @param[in] key String containing the key name as string. May
 * NOT be NULL, so take caution.
 * @param[in] value Integer containing the value to be stored.
 * @return 0 on successful operation, or a negative value on
 * error (memory exhaustion).
 */
static int iscsi_add_int_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, const int32_t value)
{
	const uint8_t *hash_val = iscsi_sprintf_alloc( "%" PRId32, value );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_add_int_key_value_pair: Out of memory allocating integer value." );

		return -1;
	}

	return iscsi_add_key_value_pair( key_value_pairs, key, hash_val );
}

/**
 * @brief Allocates and updates an integer value of a key / value hash map pair.
 *
 * This function allocates memory for a string key
 * and its integer representation as string value.\n
 * If the key does not exist, it will be added as
 * a new one.
 *
 * @param[in] key_value_pairs Pointer to the hash map which should
 * contain the updated integer key and value pair.
 * NULL is NOT allowed here, so be careful.
 * @param[in] key String containing the key name as string. May
 * NOT be NULL, so take caution.
 * @param[in] value Integer containing the value to be stored.
 * @return 0 on successful operation, or a negative value on
 * error (memory exhaustion).
 */
static int iscsi_update_int_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, const int32_t value)
{
	uint8_t *hash_val = iscsi_sprintf_alloc( "%" PRId32, value );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_update_int_key_value_pair: Out of memory allocating integer value." );

		return -1;
	}

	const int rc = iscsi_update_key_value_pair( key_value_pairs, key, hash_val );

	free( hash_val );

	return rc;
}

/**
 * @brief Extracts a boolean value from a key and value pair.
 *
 * This function converts a string representation of a
 * key and value pair to a boolean value.
 *
 * @param[in] key_value_pairs The hash map containing the key and value pairs to be extracted.
 * @param[in] key The key to retrieve the boolean value from.
 * @param[out] out_value The boolean value of the key is stored here.
 * 'Yes' represents true and any other string results in false.
 * @retval -1 An error occured during value retrieval.
 * 'out value' is unchanged.
 * @retval 0 The value of the key has been successfully
 * stored in the 'out_value'.
 */
static int iscsi_get_bool_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, int32_t *out_value)
{
	uint8_t *value;
	int rc = iscsi_get_key_value_pair( key_value_pairs, key, &value );

	if ( rc == 0 )
		*out_value = (strcasecmp( (char *) value, "Yes" ) == 0);

	return rc;
}

/**
 * @brief Allocates and adds an boolean value to a key / value hash map pair.
 *
 * This function allocates memory for a string key
 * and its integer value.\n
 * The string representation for true is: Yes\n
 * The string representation for false is: No
 *
 * @param[in] key_value_pairs Pointer to the hash map which should
 * contain the added boolean key and value pair.
 * NULL is NOT allowed here, so be careful.
 * @param[in] key String containing the key name as string. May
 * NOT be NULL, so take caution.
 * @param[in] value Boolean containing the value to be stored
 * as string.
 * @return 0 on successful operation, or a negative value on
 * error (memory exhaustion).
 */
static int iscsi_add_bool_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, const int value)
{
	const uint8_t *hash_val = (uint8_t *) ((value != 0) ? "Yes" : "No");

	return iscsi_add_key_value_pair( key_value_pairs, key, hash_val );
}

/**
 * @brief Allocates and updates an boolean value of a key / value hash map pair.
 *
 * This function allocates memory for a string key
 * and its integer value.\n
 * The string representation for true is: Yes\n
 * The string representation for false is: No\n
 * If the key does not exist, it will be added as
 * a new one.
 *
 * @param[in] key_value_pairs Pointer to the hash map which should
 * contain the updated boolean key and value pair.
 * NULL is NOT allowed here, so be careful.
 * @param[in] key String containing the key name as string. May
 * NOT be NULL, so take caution.
 * @param[in] value Boolean containing the value to be stored
 * as string.
 * @return 0 on successful operation, or a negative value on
 * error (memory exhaustion).
 */
static int iscsi_update_bool_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, const int value)
{
	const uint8_t *hash_val = (uint8_t *) ((value != 0) ? "Yes" : "No");

	return iscsi_update_key_value_pair( key_value_pairs, key, hash_val );
}

/**
 * @brief Allocates and initializes an iSCSI task structure.
 *
 * This function also initializes the underlying
 * SCSI task structure with the transfer complete
 * callback function.\n
 * If a parent task is specified, SCSI data
 * is copied over from it.
 *
 * @param[in] conn Pointer to iSCSI connection to associate
 * the task with. May NOT be NULL, so take
 * caution.
 * @param[in] parent Pointer to parent iSCSI task to copy
 * over SCSI task data from.
 * @param[in] callback Callback function to be invoked
 * after data transfer has been completed and
 * may be NULL in case no further action is
 * required.
 * @return Pointer to iSCSI task structure or NULL
 * in case of an error (memory exhaustion).
 */
iscsi_task *iscsi_task_create(iscsi_connection *conn, iscsi_task *parent, iscsi_scsi_task_xfer_complete_callback callback)
{
	iscsi_task *task = (iscsi_task *) malloc( sizeof(struct iscsi_task) );

	if ( task == NULL ) {
		logadd( LOG_ERROR, "iscsi_task_create: Out of memory while allocating iSCSI task" );

		return NULL;
	}

	task->node.succ         = NULL;
	task->node.pred         = NULL;
	task->parent            = parent;
	task->sub_tasks.head    = NULL;
	task->sub_tasks.tail    = NULL;
	task->sub_tasks.pred    = NULL;
	task->conn              = conn;
	task->pdu               = NULL;
	task->pos               = 0UL;
	task->len               = 0UL;
	task->id                = 0ULL;
	task->flags             = 0;
	task->lun_id            = 0;
	task->init_task_tag     = 0UL;
	task->target_xfer_tag   = 0UL;
	task->des_data_xfer_pos = 0UL;
	task->des_data_xfer_len = 0UL;
	task->data_sn           = 0UL;
	task->scsi_data_out_cnt = 0UL;
	task->r2t_len           = 0UL;
	task->r2t_sn            = 0UL;
	task->r2t_next_exp_pos  = 0UL;
	task->r2t_data_sn       = 0UL;
	task->r2t_sn_ack        = 0UL;
	task->r2t_outstanding   = 0UL;

	conn->task_cnt++;

	iscsi_scsi_task_create( &task->scsi_task, callback, iscsi_task_destroy_callback );

	if ( parent != NULL ) {
		parent->scsi_task.ref++;

		task->init_task_tag = parent->init_task_tag;
		task->lun_id        = parent->lun_id;

		task->scsi_task.flags       = parent->scsi_task.flags;
		task->scsi_task.xfer_len    = parent->scsi_task.xfer_len;
		task->scsi_task.lun         = parent->scsi_task.lun;
		task->scsi_task.cdb         = parent->scsi_task.cdb;
		task->scsi_task.target_port = parent->scsi_task.target_port;
		task->scsi_task.init_port   = parent->scsi_task.init_port;

		if ( (task->scsi_task.flags & ISCSI_SCSI_TASK_FLAGS_XFER_READ) != 0 )
			conn->scsi_data_in_cnt++;
	}

	return task;
}

/**
 * @brief Deallocates all resources of the iSCSI task of an iSCSI SCSI task.
 *
 * This callback function is called when the
 * iSCSI SCSI task itself is about to be
 * destroyed in order to free the associated
 * iSCSI task and PDU.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to deallocate
 * its iSCSI task. May NOT be NULL, so ba
 * careful.
 */
void iscsi_task_destroy_callback(iscsi_scsi_task *scsi_task)
{
	if ( scsi_task != NULL ) {
		iscsi_task *task = ISCSI_CONTAINER(iscsi_task, scsi_task, scsi_task);

		if ( task->parent != NULL ) {
			if ( (task->scsi_task.flags & ISCSI_SCSI_TASK_FLAGS_XFER_READ) != 0 )
				task->conn->scsi_data_in_cnt--;

			iscsi_scsi_task_destroy( &task->parent->scsi_task );

			task->parent = NULL;
		}

		if ( task->pdu != NULL ) {
			iscsi_connection_pdu_destroy( task->pdu );

			task->pdu = NULL;
		}

		task->conn->task_cnt--;

		free( task );
	}
}

/**
 * @brief Deallocates resources acquired by iscsi_task_create.
 *
 * This function also frees the embedded SCSI task.
 *
 * @param[in] task Pointer to iSCSI task to deallocate. If
 * set to NULL, this function does nothing.
 */
void iscsi_task_destroy(iscsi_task *task)
{
	if ( task != NULL )
		iscsi_scsi_task_destroy( &task->scsi_task );
}

/**
 * @brief Enqueues an iSCSI task.
 *
 * This function adds an iSCSI task to a
 * SCSI queue.
 *
 * @param[in] conn Pointer to iSCSI connection to enqueue
 * the task to and may NOT be NULL, so be
 * careful.
 * @param[in] task Pointer to iSCSI task to enqueue to the
 * associated device. NULL is not allowed
 * here, take caution.
 */
void iscsi_task_queue(iscsi_connection *conn, iscsi_task *task)
{
	task->flags |= ISCSI_TASK_FLAGS_QUEUED;

	iscsi_device_scsi_task_queue( conn->device, &task->scsi_task );
}

/**
 * @brief Searches an iSCSI task by Target Transfer Tag (TTT).
 *
 * This function searches for an iSCSI task by
 * iterating through the iSCSI connection active
 * Ready To Transfer tasks doubly linked list.
 *
 * @param[in] conn Pointer to iSCSI connection to
 * search in the active Ready To Transfer tasks
 * doubly linked list and may NOT be NULL, so
 * be careful.
 * @param[in] target_xfer_tag Target Transfer Tag (TTT)
 * to be searched for.
 * @return Pointer to found iSCSI task or NULL in
 * case no iSCSI task has a matching Target
 * Transfer Tag (TTT).
 */
static iscsi_task *iscsi_task_find(iscsi_connection *conn, const uint32_t target_xfer_tag)
{
	iscsi_task *task;

	iscsi_list_foreach_node ( &conn->r2t_tasks_active, task ) {
		if ( task->target_xfer_tag == target_xfer_tag )
			return task;
	}

	return NULL;
}

/**
 * @brief Removes all iSCSI SCSI sub tasks of a primary task which completed a read data transfer in case data sequence is in order.
 *
 * This function removes all sub tasks of an iSCSI
 * primary task which have finished their transfers
 * when the data sequence is in order.
 *
 * @param[in] conn Pointer to iSCSI connection of which
 * the data transfer has been finished and
 * may NOT be NULL, so be careful.
 * @param[in] primary_task Pointer to iSCSI primary task
 * of which to remove all sub tasks which have
 * finished the data transfer. NULL is NOT allowed
 * here, so take caution.
 */
static void iscsi_task_xfer_complete_process_read_sub_tasks(iscsi_connection *conn, iscsi_task *primary_task)
{
	iscsi_task *sub_task;
	iscsi_task *tmp;

	iscsi_list_foreach_safe_node ( &primary_task->sub_tasks, sub_task, tmp ) {
		if ( primary_task->des_data_xfer_pos != sub_task->scsi_task.pos )
			break;

		iscsi_list_remove( &sub_task->node );

		primary_task->des_data_xfer_pos += sub_task->scsi_task.len;

		if ( primary_task->des_data_xfer_pos == primary_task->scsi_task.xfer_len )
			iscsi_task_destroy( primary_task );

		iscsi_task_response( conn, sub_task );
		iscsi_task_destroy( sub_task );
	}
}

/**
 * @brief Processes an iSCSI SCSI task which completed a read data transfer.
 *
 * This function post-processes a task upon
 * finish of a read data transfer.
 *
 * @param[in] conn Pointer to iSCSI connection of which
 * the data transfer has been finished and
 * may NOT be NULL, so be careful.
 * @param[in] task Pointer to iSCSI task which finished
 * the data transfer. NULL is NOT allowed
 * here, so take caution.
 * @param[in] primary_task Pointer to iSCSI primary task
 * which finished the data transfer which
 * may NOT be NULL, so be careful.
 */
void iscsi_task_xfer_complete_process_read(iscsi_connection *conn, iscsi_task *task, iscsi_task *primary_task)
{
	if ( task->scsi_task.status != ISCSI_SCSI_STATUS_GOOD ) {
		if ( primary_task->scsi_task.status == ISCSI_SCSI_STATUS_GOOD ) {
			iscsi_task *sub_task;

			iscsi_list_foreach_node ( &primary_task->sub_tasks, sub_task ) {
				iscsi_scsi_task_status_copy( &sub_task->scsi_task, &task->scsi_task );
			}

			iscsi_scsi_task_status_copy( &primary_task->scsi_task, &task->scsi_task );
		}
	} else if ( primary_task->scsi_task.status != ISCSI_SCSI_STATUS_GOOD ) {
		iscsi_scsi_task_status_copy( &task->scsi_task, &primary_task->scsi_task );
	}

	if ( task == primary_task ) {
		primary_task->des_data_xfer_pos = task->scsi_task.len;

		iscsi_task_response( conn, task );
		iscsi_task_destroy( task );
	} else if ( (conn->session->flags & ISCSI_SESSION_FLAGS_DATA_SEQ_IN_ORDER) == 0 ) {
		primary_task->des_data_xfer_pos += task->scsi_task.len;

		if ( primary_task->des_data_xfer_pos == primary_task->scsi_task.xfer_len )
			iscsi_task_destroy(primary_task );

		iscsi_task_response( conn, task );
		iscsi_task_destroy( task );
	} else if ( task->scsi_task.pos != primary_task->des_data_xfer_pos ) {
		iscsi_task *sub_task;

		iscsi_list_foreach_node ( &primary_task->sub_tasks, sub_task ) {
			if ( task->scsi_task.pos < sub_task->scsi_task.pos ) {
				iscsi_list_insert( &primary_task->sub_tasks, &sub_task->node, task->node.pred );

				return;
			}
		}

		iscsi_list_enqueue( &primary_task->sub_tasks, &task->node );
	} else {
		iscsi_list_push( &primary_task->sub_tasks, &task->node );

		iscsi_task_xfer_complete_process_read_sub_tasks( conn, primary_task );
	}
}

/**
 * @brief Adds an iSCSI transfer task to either pending (if maximum is exceeded) or active tasks doubly linked list.
 *
 * This function also sends Ready To Transfer
 * (R2T) packet data to the initiator.
 *
 * @param[in] conn Pointer to iSCSI connection to add the
 * transfer task to. May NOT be NULL, so be
 * careful.
 * @param[in] task Pointer to iSCSI task to add to
 * active or pending doubly linked list.
 * NULL is NOT allowed here, take caution.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_task_xfer_add(iscsi_connection *conn, iscsi_task *task)
{
	const uint32_t xfer_len     = task->scsi_task.xfer_len;
	uint32_t ds_len             = task->pdu->ds_len;
	const uint32_t seg_len      = ISCSI_DEFAULT_MAX_RECV_DS_LEN;
	const uint32_t data_out_req = (uint32_t) (iscsi_is_pow2( seg_len ) ? (((xfer_len - ds_len - 1UL) >> iscsi_get_log2_of_pow2( seg_len )) + 1UL) : (((xfer_len - ds_len - 1UL) / seg_len) + 1UL));

	task->scsi_data_out_cnt = data_out_req;

	if ( conn->r2t_pending >= ISCSI_DEFAULT_MAX_R2T_PER_CONNECTION ) {
		iscsi_list_enqueue( &conn->r2t_tasks_queue, &task->node );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	conn->scsi_data_out_cnt += data_out_req;
	conn->r2t_pending++;

	task->r2t_next_exp_pos = ds_len;
	task->r2t_len          = 0UL;
	task->r2t_sn           = 0UL;

	if ( ++conn->target_xfer_tag == 0xFFFFFFFFUL )
		conn->target_xfer_tag = 0UL;

	task->target_xfer_tag = conn->target_xfer_tag;

	const uint32_t max_burst_len = conn->session->max_burst_len;

	while ( ds_len != xfer_len ) {
		uint32_t len = (xfer_len - ds_len);

		if ( len > max_burst_len )
			len = max_burst_len;

		const int rc = iscsi_r2t_send( conn, task, &task->r2t_sn, ds_len, len, task->target_xfer_tag );

		if ( rc < 0 )
			return rc;

		ds_len += len;

		task->r2t_next_exp_pos = ds_len;

		if ( conn->session->max_outstanding_r2t == ++task->r2t_outstanding )
			break;
	}

	iscsi_list_enqueue( &conn->r2t_tasks_active, &task->node );

	task->flags |= ISCSI_TASK_FLAGS_R2T_ACTIVE;

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Starts queued iSCSI Ready To Transfer (R2T) tasks by moving them from queued doubly linked list to active doubly linked list.
 *
 * This function iterates through all enqueued
 * transfer tasks of an ISCSI connection and moves
 * them into the active transfer tasks doubly
 * linked list until the maximum number of active
 * transfer tasks has been reached.
 *
 * @param[in] conn Pointer to iSCSI connection from where to
 * move the enqueued iSCSI tasks to the active task
 * doubly linked list. May NOT be NULL, so be
 * careful.
 */
static void iscsi_task_xfer_queued_tasks_start(iscsi_connection *conn)
{
	iscsi_task *task;
	iscsi_task *tmp;

	iscsi_list_foreach_safe_node ( &conn->r2t_tasks_queue, task, tmp ) {
		if ( conn->r2t_pending >= ISCSI_DEFAULT_MAX_R2T_PER_CONNECTION )
			return;

		iscsi_list_remove( &task->node );
		iscsi_task_xfer_add( conn, task );
	}
}

/**
 * @brief Deletes an iSCSI task from the active Ready To Transfer (R2T) doubly linked list by Target Transfer Tag (TTT).
 *
 * This function traverses through an iSCSI task's
 * active Ready To Transfer (R2T) doubly linked
 * list in order to find the Target Transfer Tag
 * (TTT) to be deleted.
 *
 * @param[in] conn Pointer to iSCSI connection to
 * search in the active Ready To Transfer
 * (R2T) doubly linked list.
 * @param[in] target_xfer_tag Target Transfer Tag (TTT) to
 * delete the ISCSI task of.
 * @retval true The iSCSI task has been found and
 * deleted successfully.
 * @retval false The iSCSI task does NOT exist and
 * therefore could NOT be deleted.
 */
bool iscsi_task_xfer_del(iscsi_connection *conn, const uint32_t target_xfer_tag)
{
	iscsi_task *task;
	iscsi_task *tmp;

	iscsi_list_foreach_safe_node ( &conn->r2t_tasks_active, task, tmp ) {
		if ( task->target_xfer_tag != target_xfer_tag )
			continue;

		conn->scsi_data_out_cnt -= task->scsi_data_out_cnt;
		conn->r2t_pending--;

		iscsi_list_remove( &task->node );

		task->flags &= ~ISCSI_TASK_FLAGS_R2T_ACTIVE;

		iscsi_task_destroy( task );
		iscsi_task_xfer_queued_tasks_start( conn );

		return true;
	}

	return false;
}

/**
 * @brief Processes an iSCSI SCSI task which completed a non-read data transfer.
 *
 * This function post-processes a task upon
 * finish of a non-read data transfer.
 *
 * @param[in] conn Pointer to iSCSI connection of which
 * the data transfer has been finished and
 * may NOT be NULL, so be careful.
 * @param[in] task Pointer to iSCSI task which finished
 * the data transfer. NULL is NOT allowed
 * here, so take caution.
 * @param[in] primary_task Pointer to iSCSI primary task
 * which finished the data transfer which
 * may NOT be NULL, so be careful.
 */
void iscsi_task_xfer_complete_process_other(iscsi_connection *conn, iscsi_task *task, iscsi_task *primary_task)
{
	primary_task->des_data_xfer_pos += task->scsi_task.len;

	if ( task == primary_task ) {
		iscsi_task_response( conn, task );
		iscsi_task_destroy( task );

		return;
	}

	if ( task->scsi_task.status == ISCSI_SCSI_STATUS_GOOD )
		primary_task->scsi_task.xfer_pos += task->scsi_task.xfer_pos;
	else if ( primary_task->scsi_task.status == ISCSI_SCSI_STATUS_GOOD )
		iscsi_scsi_task_status_copy( &primary_task->scsi_task, &task->scsi_task );

	if ( primary_task->des_data_xfer_pos == primary_task->scsi_task.xfer_len ) {
		if ( (primary_task->flags & ISCSI_TASK_FLAGS_R2T_ACTIVE) != 0 ) {
			iscsi_task_response( conn, primary_task );
			iscsi_task_xfer_del( conn, primary_task->target_xfer_tag );
		} else {
			iscsi_task_response( conn, task );
		}
	}

	iscsi_task_destroy( task );
}

/**
 * @brief Callback function after iSCSI SCSI Data In response has been sent.
 *
 * This function is invoked after the iSCSI
 * SCSI Data In response has been sent to
 * the client via TCP/IP.
 *
 * @param[in] user_data Pointer to iSCSI connection which
 * was used for sending the response.
 */
static void iscsi_connection_pdu_scsi_data_in_complete(uint8_t *user_data)
{
	iscsi_connection *conn = (iscsi_connection *) user_data;

	iscsi_connection_handle_scsi_data_in_queued_tasks( conn );
}

/**
 * @brief Sends a single iSCSI SCSI Data In packet to the client.
 *
 * This function reads the data from the
 * associated DNBD3 image as well and sends
 * it to the initiator.
 *
 * @pararm[in] conn Pointer to iSCSI connection for which the
 * packet should be sent for. May NOT be
 * NULL, so be careful.
 * @pararm[in] task Pointer to iSCSI task which handles the
 * actual SCSI packet data. NULL is NOT
 * allowed here, so take caution.
 * @pararm[in] pos Offset of data to be sent in bytes.
 * @pararm[in] len Length of data to be sent in bytes
 * @pararm[in] res_snt Residual Count.
 * @pararm[in] data_sn Data Sequence Number (DataSN).
 * @pararm[in] flags Flags for this data packet.
 * @return Next Data Sequence Number (DataSN) on success,
 * the same DataSN as passed on error.
 */
static uint32_t iscsi_scsi_data_in_send(iscsi_connection *conn, iscsi_task *task, const uint32_t pos, const uint32_t len, const uint32_t res_cnt, const uint32_t data_sn, const int8_t flags)
{
	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 0U, conn->header_digest, len, conn->data_digest );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_scsi_data_in_send: Out of memory while allocating iSCSI SCSI Data In response PDU" );

		return data_sn;
	}

	response_pdu->task = task;
	task->scsi_task.ref++;

	iscsi_scsi_data_in_response_packet *scsi_data_in_pkt = (iscsi_scsi_data_in_response_packet *) response_pdu->bhs_pkt;

	scsi_data_in_pkt->opcode   = ISCSI_OPCODE_SERVER_SCSI_DATA_IN;
	scsi_data_in_pkt->flags    = (flags & ~(ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_UNDERFLOW | ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_OVERFLOW));
	scsi_data_in_pkt->reserved = 0U;

	iscsi_task *primary_task = ((task->parent != NULL) ? task->parent : task);

	if ( (flags & ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS) != 0 ) {
		if ( (flags & ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL) != 0 ) {
			scsi_data_in_pkt->flags |= (flags & (ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_UNDERFLOW | ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_OVERFLOW));

			if ( (primary_task->pdu->bhs_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 )
				conn->session->max_cmd_sn++;

			iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->res_cnt, res_cnt );
		} else {
			scsi_data_in_pkt->res_cnt = 0UL;
		}

		scsi_data_in_pkt->status = task->scsi_task.status;
		iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->stat_sn, conn->stat_sn++ );
	} else {
		scsi_data_in_pkt->status  = 0U;
		scsi_data_in_pkt->stat_sn = 0UL;
		scsi_data_in_pkt->res_cnt = 0UL;
	}

	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->total_ahs_len, len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	scsi_data_in_pkt->lun             = 0ULL;
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->init_task_tag, task->init_task_tag );
	scsi_data_in_pkt->target_xfer_tag = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->data_sn, data_sn );

	if ( conn->session->err_recovery_level > 0UL )
		primary_task->data_sn = data_sn;

	const uint32_t offset = (task->scsi_task.pos + pos);
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->buf_offset, offset );

	memcpy( response_pdu->ds_cmd_data, (task->scsi_task.buf + pos), len );

	iscsi_connection_pdu_write( conn, response_pdu, iscsi_connection_pdu_scsi_data_in_complete, (uint8_t *) conn );

	return (data_sn + 1UL);
}

/**
 * @brief Handles iSCSI task read (incoming) data.
 *
 * This function handles iSCSI incoming data
 * read buffer for both processed and
 * unprocessed tasks.
 *
 * @param[in] conn Pointer to iSCSI connection of which the
 * incoming data should be handled, may NOT be
 * NULL, so be careful.
 * @param[in] task Pointer to iSCSI task for handling
 * the incoming data. NULL is NOT allowed here,
 * take caution.
 * @return 0 on successful incoming transfer handling,
 * a negative error code otherwise.
 */
static int iscsi_task_xfer_scsi_data_in(iscsi_connection *conn, iscsi_task *task)
{
	if ( task->scsi_task.status != ISCSI_SCSI_STATUS_GOOD )
		return 0;

	const uint32_t pos      = task->scsi_task.xfer_pos;
	uint32_t xfer_len       = task->scsi_task.len;
	const uint32_t seg_len  = conn->max_recv_ds_len;
	uint32_t res_cnt        = 0UL;
	int8_t flags            = 0;

	if ( pos < xfer_len ) {
		res_cnt  = (xfer_len - pos);
		xfer_len = pos;
		flags   |= ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_UNDERFLOW;
	} else if ( pos > xfer_len ) {
		res_cnt  = (pos - xfer_len);
		flags   |= ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_OVERFLOW;
	}

	iscsi_task *primary_task         = ((task->parent != NULL) ? task->parent : task);
	uint32_t data_sn                 = primary_task->data_sn;
	uint32_t max_burst_offset        = 0UL;
	const uint32_t max_burst_len     = conn->session->max_burst_len;
	const uint32_t data_in_seq_count = (uint32_t) (iscsi_is_pow2( max_burst_len ) ? (((xfer_len - 1UL) >> iscsi_get_log2_of_pow2( max_burst_len )) + 1UL) : (((xfer_len - 1UL) / max_burst_len) + 1UL));
	int8_t status                    = 0;

	for ( uint32_t i = 0UL; i < data_in_seq_count; i++ ) {
		uint32_t seq_end = (max_burst_offset + max_burst_len);

		if ( seq_end > xfer_len )
			seq_end = xfer_len;

		for ( uint32_t offset = max_burst_offset; offset < seq_end; offset += seg_len ) {
			uint32_t len = (seq_end - offset);

			if ( len > seg_len )
				len = seg_len;

			flags &= (int8_t) ~(ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS | ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL);

			if ( (offset + len) == seq_end ) {
				flags |= (int8_t) ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL;

				if ( (task->scsi_task.sense_data_len == 0U) && ((offset + len) == xfer_len) && (primary_task->des_data_xfer_pos == primary_task->scsi_task.xfer_len) ) {
					flags  |= (int8_t) ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS;
					status |= flags;
				}
			}

			data_sn = iscsi_scsi_data_in_send( conn, task, offset, len, res_cnt, data_sn, flags );
		}

		max_burst_offset += max_burst_len;
	}

	if ( primary_task != task )
		primary_task->scsi_task.xfer_pos += task->scsi_task.xfer_pos;

	primary_task->data_sn = data_sn;

	return (status & ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS);
}

/**
 * @brief Creates, initializes and sends an iSCSI task reponse PDU.
 *
 * This function also receives any remaining
 * incoming data in case the task is reading.
 *
 * @param[in] conn Pointer to iSCSI connection to handle the
 * task resnponse for and may NOT be NULL,
 * so be careful.
 * @param[in] task Pointer to iSSCI task to create the
 * response PDU from. NULL is NOT allowed
 * here, take caution.
 */
void iscsi_task_response(iscsi_connection *conn, iscsi_task *task)
{
	iscsi_task *primary_task            = ((task->parent != NULL) ? task->parent : task);
	iscsi_pdu *pdu                      = primary_task->pdu;
	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) pdu->bhs_pkt;
	const uint32_t xfer_len             = primary_task->scsi_task.xfer_len;

	if ( (scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_READ) != 0 ) {
		const int rc = iscsi_task_xfer_scsi_data_in( conn, task );

		if ( (rc > 0) || (primary_task->des_data_xfer_pos != primary_task->scsi_task.xfer_len) )
			return;
	}

	const uint32_t ds_len   = ((task->scsi_task.sense_data_len != 0U) ? (task->scsi_task.sense_data_len + offsetof(struct iscsi_scsi_ds_cmd_data, sense_data)) : 0UL);
	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 0U, conn->header_digest, ds_len, conn->data_digest );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_task_response: Out of memory while allocating iSCSI SCSI response PDU" );

		return;
	}

	iscsi_scsi_response_packet *scsi_response_pkt = (iscsi_scsi_response_packet *) response_pdu->bhs_pkt;

	if ( task->scsi_task.sense_data_len != 0U ) {
		iscsi_scsi_ds_cmd_data *ds_cmd_data_pkt = response_pdu->ds_cmd_data;

		iscsi_put_be16( (uint8_t *) &ds_cmd_data_pkt->len, task->scsi_task.sense_data_len );
		memcpy( ds_cmd_data_pkt->sense_data, task->scsi_task.sense_data, task->scsi_task.sense_data_len );

		iscsi_put_be32( (uint8_t *) &scsi_response_pkt->total_ahs_len, ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	} else {
		*(uint32_t *) &scsi_response_pkt->total_ahs_len = 0UL; // TotalAHSLength and DataSegmentLength are always 0, so write in one step.
	}

	response_pdu->task = task;
	task->scsi_task.ref++;

	scsi_response_pkt->opcode   = ISCSI_OPCODE_SERVER_SCSI_RESPONSE;
	scsi_response_pkt->flags    = -0x80;
	scsi_response_pkt->response = ISCSI_SCSI_RESPONSE_CODE_OK;

	const uint32_t pos = primary_task->scsi_task.xfer_pos;

	if ( (xfer_len != 0UL) && (task->scsi_task.status == ISCSI_SCSI_STATUS_GOOD) ) {
		if ( pos < xfer_len ) {
			const uint32_t res_cnt = (xfer_len - pos);

			scsi_response_pkt->flags |= ISCSI_SCSI_RESPONSE_FLAGS_RES_UNDERFLOW;
			iscsi_put_be32( (uint8_t *) &scsi_response_pkt->res_cnt, res_cnt );
		} else if ( pos > xfer_len ) {
			const uint32_t res_cnt = (pos - xfer_len);

			scsi_response_pkt->flags |= ISCSI_SCSI_RESPONSE_FLAGS_RES_OVERFLOW;
			iscsi_put_be32( (uint8_t *) &scsi_response_pkt->res_cnt, res_cnt );
		} else {
			scsi_response_pkt->res_cnt = 0UL;
		}
	} else {
		scsi_response_pkt->res_cnt = 0UL;
	}

	scsi_response_pkt->status    = task->scsi_task.status;
	scsi_response_pkt->reserved  = 0ULL;
	iscsi_put_be32( (uint8_t *) &scsi_response_pkt->init_task_tag, task->init_task_tag );
	scsi_response_pkt->snack_tag = 0UL;
	iscsi_put_be32( (uint8_t *) &scsi_response_pkt->stat_sn, conn->stat_sn++ );

	if ( (scsi_cmd_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 )
		conn->session->max_cmd_sn++;

	iscsi_put_be32( (uint8_t *) &scsi_response_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &scsi_response_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	scsi_response_pkt->exp_data_sn       = 0UL;
	scsi_response_pkt->bidi_read_res_cnt = 0UL;

	iscsi_connection_pdu_write( conn, response_pdu, NULL, NULL );
}

/**
 * @brief Creates and initializes an iSCSI portal group.
 *
 * Specified tag and flags are used for portal group
 * initialization.
 * @param[in] tag Tag to associate with the portal group.
 * @param[in] flags Flags to set for the portal group.
 * @return Pointer to allocated and initialized portal group
 * or NULL in case of memory
 */
iscsi_portal_group *iscsi_portal_group_create(const uint64_t tag, const int flags)
{
	iscsi_portal_group *portal_group = (iscsi_portal_group *) malloc( sizeof(struct iscsi_portal_group) );

	if ( portal_group == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_create: Out of memory allocating iSCSI portal group structure" );

		return NULL;
	}

	portal_group->portals = iscsi_hashmap_create( 0U );

	if ( portal_group->portals == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_create: Out of memory allocating iSCSI portal hash map" );

		free( portal_group );

		return NULL;
	}

	portal_group->ref_count  = 0;
	portal_group->tag        = tag;
	portal_group->flags      = flags;
	portal_group->chap_group = 0L;

	return portal_group;
}

/**
 * @brief iSCSI portal group destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * portal group stored in the hash map managing all
 * iSCSI portal groups.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_portal_group_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_portal_group_destroy( (iscsi_portal_group *) value );

	return 0;
}

/**
 * @brief Deallocates resources acquired by iscsi_portal_group_create.
 *
 * This function frees the associated hash map containing the
 * poptals and the structure itself.
 *
 * @param[in] portal_group Pointer to iSCSI portal group to deallocate.
 * May be NULL in which case this function does nothing.
 */
void iscsi_portal_group_destroy(iscsi_portal_group *portal_group)
{
	if ( portal_group != NULL ) {
		if ( portal_group->portals != NULL ) {
			iscsi_hashmap_iterate( portal_group->portals, iscsi_portal_destroy_callback, NULL );
			iscsi_hashmap_destroy( portal_group->portals );

			portal_group->portals = NULL;
		}

		free( portal_group );
	}
}

/**
 * @brief Adds an iSCSI portal to the iSCSI portal group hash map.
 *
 * This function allocates host:port of iSCSI portal for use
 * as key and sets the portal group in the portal.
 *
 * @param[in] portal_group iSCSI portal group to add portal to. May NOT be NULL,
 * so take caution.
 * @param[in] portal iSCSI portal to add to portal group. NULL is NOT
 * allowed here, so be careful.
 * @retval -1 An error occured during adding the portal,
 * usually caused by memory exhaustion
 * @retval 0 The portal has been added successfully to the
 * portal group.
 */
int iscsi_portal_group_add_portal(iscsi_portal_group *portal_group, iscsi_portal *portal)
{
	uint8_t *tmp_buf = iscsi_sprintf_alloc( "%s:%s", portal->host, portal->port );

	if ( tmp_buf == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_add_portal: Out of memory allocating temporarily key buffer for iSCSI portal" );

		return -1;
	}

	const uint key_len = (uint) (strlen( (char *) tmp_buf ) + 1U);
	uint8_t *key       = iscsi_hashmap_key_create( tmp_buf, key_len );

	free( tmp_buf );

	if ( key == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_add_portal: Out of memory allocating key for iSCSI portal" );

		return -1;
	}

	int rc = iscsi_hashmap_put( portal_group->portals, key, key_len, (uint8_t *) portal );

	if ( rc < 0 ) {
		logadd( LOG_ERROR, "iscsi_portal_group_add_portal: Adding portal to hash map containing iSCSI portal group failed" );

		iscsi_hashmap_key_destroy( key );

		return rc;
	}

	portal->group = portal_group;

	return 0;
}

/**
 * @brief Removes an iSCSI portal from the iSCSI portal group hash map.
 *
 * This function deallocates the hash key used
 * for storing the portal in the portal group
 * as well.
 *
 * @param[in] portal_group iSCSI portal group to remove portal from. May
 * NOT be NULL, so take caution.
 * @param[in] portal iSCSI portal to remove from the portal group.
 * NULL is NOT allowed here, so be careful.
 */
void iscsi_portal_group_del_portal(iscsi_portal_group *portal_group, iscsi_portal *portal)
{
	uint8_t *tmp_buf = iscsi_sprintf_alloc( "%s:%s", portal->host, portal->port );

	if ( tmp_buf == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_del_portal: Out of memory allocating temporarily key buffer for iSCSI portal" );

		return;
	}

	const uint key_len = (uint) (strlen( (char *) tmp_buf ) + 1U);
	uint8_t *key       = iscsi_hashmap_key_create( tmp_buf, key_len );

	free( tmp_buf );

	if ( key == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_del_portal: Out of memory allocating key for iSCSI portal" );

		return;
	}

	if ( iscsi_hashmap_contains( portal_group->portals, key, key_len ) ) {
		portal->group = NULL;

		iscsi_hashmap_remove_free( portal_group->portals, key, key_len, iscsi_hashmap_key_destroy_callback, NULL );
	}

	iscsi_hashmap_key_destroy( key );
}

/**
 * @brief Allocates and initializes an iSCSI portal structure.
 *
 * This function makes a copy of the passed host / IP address
 * and port, but does NOT initialize the socket.
 *
 * @param[in] host Host / IP address of the portal.
 * @param[in] port Port of the portal.
 * @return Pointer to iSCSI portal structure or NULL
 * in case of an error (memory exhausted).
 */
iscsi_portal *iscsi_portal_create(const uint8_t *host, const uint8_t *port)
{
	iscsi_portal *portal = (iscsi_portal *) malloc( sizeof(struct iscsi_portal) );

	if ( portal == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_create: Out of memory allocating iSCSI portal structure" );

		return NULL;
	}

	portal->group = NULL;

	const uint host_len = (uint) (strlen( (char *) host ) + 1U);

	portal->host = (uint8_t *) malloc( host_len );

	if ( portal->host == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_create: Out of memory allocating iSCSI portal host name" );

		return NULL;
	}

	memcpy( portal->host, host, host_len );

	const uint port_len = (uint) (strlen( (char *) port ) + 1U);

	portal->port = (uint8_t *) malloc( port_len );

	if ( portal->port == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_create: Out of memory allocating iSCSI portal port" );

		return NULL;
	}

	memcpy( portal->port, port, port_len );

	portal->sock = -1;

	return portal;
}

/**
 * @brief iSCSI portal destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * portal stored in the iSCSI portal group hash map.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_portal_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_portal_destroy( (iscsi_portal *) value );
	iscsi_hashmap_key_destroy( key );

	return 0;
}

/**
 * @brief Deallocates all resources acquired by iscsi_portal_create.
 *
 * This function frees the memory acquired for host / IP address
 * and port but does NOT remove it from the portal group hash map.
 *
 * @param[in] portal Pointer to iSCSI portal to be deallocated,
 * which may be NULL in which case the function does nothing.
 */
void iscsi_portal_destroy(iscsi_portal *portal)
{
	if ( portal != NULL ) {
		if ( portal->port != NULL ) {
			free( portal->port );

			portal->port = NULL;
		}

		if ( portal->host != NULL ) {
			free( portal->host );

			portal->host = NULL;
		}

		free( portal );
	}
}

/**
 * @brief Allocates and initializes a SCSI task.
 *
 * THis function assocates the callback
 * functions to the SCSI task and sets
 * the reference count to 1.
 *
 * @param[in] scsi_task Pointer to SCSI task. This
 * may NOT be NULL, so be careful.
 * @param[in] xfer_complete_callback Pointer to transfer completed callback
 * function.
 * @param[in] destroy_callback Pointer to SCSI task destruction
 * callback function.
 */
void iscsi_scsi_task_create(iscsi_scsi_task *scsi_task, iscsi_scsi_task_xfer_complete_callback xfer_complete_callback, iscsi_scsi_task_destroy_callback destroy_callback)
{
	scsi_task->node.succ              = NULL;
	scsi_task->node.pred              = NULL;
	scsi_task->lun                    = NULL;
	scsi_task->target_port            = NULL;
	scsi_task->init_port              = NULL;
	scsi_task->cdb                    = NULL;
	scsi_task->xfer_complete_callback = xfer_complete_callback;
	scsi_task->destroy_callback       = destroy_callback;
	scsi_task->io_complete_callback   = NULL;
	scsi_task->io_wait.image          = NULL;
	scsi_task->io_wait.callback       = NULL;
	scsi_task->io_wait.user_data      = NULL;
	scsi_task->sense_data             = NULL;
	scsi_task->buf                    = NULL;
	scsi_task->pos                    = 0UL;
	scsi_task->len                    = 0UL;
	scsi_task->id                     = 0ULL;
	scsi_task->flags                  = 0;
	scsi_task->ref                    = 1UL;
	scsi_task->xfer_pos               = 0UL;
	scsi_task->xfer_len               = 0UL;
	scsi_task->sense_data_len         = 0U;
	scsi_task->status                 = ISCSI_SCSI_STATUS_GOOD;
	scsi_task->task_mgmt_func         = ISCSI_TASK_MGMT_FUNC_REQ_FUNC_ABORT_TASK;
	scsi_task->task_mgmt_response     = ISCSI_TASK_MGMT_FUNC_RESPONSE_FUNC_COMPLETE;
}

/**
 * @brief Deallocates all resources acquired iscsi_scsi_task_create.
 *
 * This function also calls the task destruction
 * callback function if the reference count
 * becomes zero.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to deallocate.
 * This may be NULL in which case nothing
 * happens.
 */
void iscsi_scsi_task_destroy(iscsi_scsi_task *scsi_task)
{
	if ( (scsi_task != NULL) && (--scsi_task->ref == 0UL) ) {
		if ( scsi_task->buf != NULL ) {
			if ( (scsi_task->flags & ISCSI_SCSI_TASK_FLAGS_XFER_WRITE) == 0 )
				free( scsi_task->buf );

			scsi_task->buf = NULL;
		}

		scsi_task->destroy_callback( scsi_task );
	}
}

/**
 * @brief Callback function when an iSCSI SCSI task completed the data transfer.
 *
 * This function post-processes a task upon
 * finish of data transfer.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task which finished
 * the data transfer and may NOT be NULL,
 * so be careful.
 */
void iscsi_scsi_task_xfer_complete(iscsi_scsi_task *scsi_task)
{
	iscsi_task *task = ISCSI_CONTAINER(iscsi_task, scsi_task, scsi_task);

	task->flags &= ~ISCSI_TASK_FLAGS_QUEUED;

	iscsi_task *primary_task = ((task->parent != NULL) ? task->parent : task);
	iscsi_connection *conn   = task->conn;

	if ( (((iscsi_scsi_cmd_packet *) primary_task->pdu->bhs_pkt)->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_READ) != 0 )
		iscsi_task_xfer_complete_process_read( conn, task, primary_task );
	else
		iscsi_task_xfer_complete_process_other( conn, task, primary_task );
}

/**
 * @brief Allocates, if necessary and initializes SCSI sense data for check condition status code.
 *
 * This function is invoked whenever additional
 * SCSI sense data for check condition status
 * code is required for sending to the
 * initiator.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to allocate
 * and assign the SCSI check condition status
 * code sense data for. May NOT be NULL, so
 * be careful.
 * @param[in] sense_key Sense Key (SK).
 * @param[in] asc Additional Sense Code (ASC).
 * @param[in] ascq Additional Sense Code Qualifier (ASCQ).
 */
void iscsi_scsi_task_sense_data_build(iscsi_scsi_task *scsi_task, const uint8_t sense_key, const uint8_t asc, const uint8_t ascq)
{
	iscsi_scsi_sense_data_check_cond_packet *sense_data = (iscsi_scsi_sense_data_check_cond_packet *) scsi_task->sense_data;

	if ( sense_data == NULL ) {
		sense_data = malloc( sizeof(struct iscsi_scsi_sense_data_check_cond_packet) );

		if ( sense_data == NULL ) {
			logadd( LOG_ERROR, "iscsi_scsi_task_sense_data_build: Out of memory allocating iSCSI SCSI conidtion check status code sense data" );

			return;
		}

		scsi_task->sense_data = (iscsi_scsi_sense_data_packet *) sense_data;
	}

	sense_data->sense_data.response_code   = (int8_t) (ISCSI_SCSI_SENSE_DATA_PUT_RESPONSE_CODE(ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_CURRENT_FMT) | ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_VALID);
	sense_data->sense_data.reserved        = 0U;
	sense_data->sense_data.sense_key_flags = ISCSI_SCSI_SENSE_DATA_PUT_SENSE_KEY(sense_key);
	sense_data->sense_data.info            = 0UL; // Zero does not require endianess conversion
	sense_data->sense_data.add_len         = (sizeof(struct iscsi_scsi_sense_data_check_cond_packet) - sizeof(struct iscsi_scsi_sense_data_packet));

	sense_data->cmd_spec_info        = 0UL; // Zero does not require endianess conversion
	sense_data->asc                  = asc;
	sense_data->ascq                 = ascq;
	sense_data->field_rep_unit_code  = 0U;
	sense_data->sense_key_spec_flags = 0U;
	sense_data->sense_key_spec       = 0U; // Zero does not require endianess conversion

	scsi_task->sense_data_len = sizeof(struct iscsi_scsi_sense_data_check_cond_packet);
}

/**
 * @brief Sets an iSCSI SCSI task status code with optional additional details.
 *
 * Sense Key (SK), Additional Sense Code (ASC)
 * and Additional Sense Code Qualifier (ASCQ)
 * are only generated on check condition SCSI
 * status code.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to set the
 * SCSI status and additional details for. May
 * NOT be NULL, so be careful.
 * @param[in] status SCSI status code to be set.
 * @param[in] sense_key Sense Key (SK).
 * @param[in] asc Additional Sense Code (ASC).
 * @param[in] ascq Additional Sense Code Qualifier (ASCQ).
 */
static void iscsi_scsi_task_status_set(iscsi_scsi_task *scsi_task, const uint8_t status, const uint8_t sense_key, const uint8_t asc, const uint8_t ascq)
{
	if ( status == ISCSI_SCSI_STATUS_CHECK_COND )
		iscsi_scsi_task_sense_data_build( scsi_task, sense_key, asc, ascq );

	scsi_task->status = status;
}

/**
 * @brief Copies iSCSI SCSI task sense data and status code.
 *
 * This function allocates, if necessary, a
 * SCSI sense data buffer and copies it over
 * from source or deallocates the sense data
 * buffer in case the source has no sense
 * data.
 *
 * @param[in] dst_scsi_task Pointer to iSCSI SCSI task to copy to.
 * May NOT be NULL, so be careful.
 * @param[in] src_scsi_task Pointer to iSCSI SCSI task to copy from.
 * NULL is NOT allowed here, take caution.
 * @return 0 on successful copy operation, a negative
 * error code otherwise.
 */
int iscsi_scsi_task_status_copy(iscsi_scsi_task *dst_scsi_task, const iscsi_scsi_task *src_scsi_task)
{
	if ( dst_scsi_task->sense_data != NULL )
		free( dst_scsi_task->sense_data );

	if ( src_scsi_task->sense_data != NULL ) {
		dst_scsi_task->sense_data = malloc( src_scsi_task->sense_data_len );

		if ( dst_scsi_task == NULL )
			return -1;

		memcpy( dst_scsi_task->sense_data, src_scsi_task->sense_data, src_scsi_task->sense_data_len );
	} else {
		dst_scsi_task->sense_data = NULL;
	}

	dst_scsi_task->sense_data_len = src_scsi_task->sense_data_len;
	dst_scsi_task->status         = src_scsi_task->status;

	return 0;
}

/**
 * @brief Processes a iSCSI SCSI task with no LUN identifier.
 *
 * This function only generates a SCSI response
 * if the SCSI command is INQUIRY, otherwise
 * a SCSI error will be generated as specified
 * by the SCSI standard.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to process
 * the task with no LUN identifier for. May NOT
 * be NULL, so be careful.
 */
void iscsi_scsi_task_lun_process_none(iscsi_scsi_task *scsi_task)
{
	iscsi_scsi_std_inquiry_data_packet std_inquiry_data_pkt;
	iscsi_scsi_cdb_inquiry *cdb = (iscsi_scsi_cdb_inquiry *) scsi_task->cdb;

	scsi_task->len = scsi_task->xfer_len;

	if ( cdb->cdb.opcode == ISCSI_SCSI_OPCODE_INQUIRY ) {
		uint len = sizeof(struct iscsi_scsi_std_inquiry_data_packet);

		memset( &std_inquiry_data_pkt, 0, len );

		std_inquiry_data_pkt.basic_inquiry.peripheral_type_id = (ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_TYPE(ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_UNKNOWN) | ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_ID(ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_NEVER));
		std_inquiry_data_pkt.basic_inquiry.add_len            = (uint8_t) (len - sizeof(struct iscsi_scsi_basic_inquiry_data_packet));

		const uint alloc_len = iscsi_get_be16(cdb->alloc_len);

		if ( len > alloc_len )
			len = alloc_len;

		memcpy( scsi_task->buf, &std_inquiry_data_pkt, len );

		scsi_task->xfer_pos = len;
		scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;
	} else {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_LU_NOT_SUPPORTED, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		scsi_task->xfer_pos = 0UL;
	}
}

/**
 * @brief Processes a iSCSI SCSI aborted task.
 *
 * This function will generate a SCSI error as
 * specified by the SCSI standard.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to process
 * the task to be aborted. May NOT be NULL, so
 * be careful.
 */
void iscsi_scsi_task_lun_process_abort(iscsi_scsi_task *scsi_task)
{
	iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ABORTED_COMMAND, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
}

/**
 * @brief Allocates and initializes an iSCSI LUN structure for linkage with a DNBD3 image.
 *
 * This function does not set the DNBD3
 * image itself.
 *
 * @param[in] id LUN identifier.
 * @return Pointer to ISCSI device LUN or NULL in case
 * of an error (memory exhaustion).
 */
iscsi_scsi_lun *iscsi_scsi_lun_create(const int lun_id)
{
	iscsi_scsi_lun *lun = (iscsi_scsi_lun *) malloc( sizeof(struct iscsi_scsi_lun) );

	if ( lun == NULL ) {
		logadd( LOG_ERROR, "iscsi_scsi_lun_create: Out of memory allocating iSCSI device LUN" );

		return NULL;
	}

	iscsi_list_create( &lun->tasks );

	if ( pthread_mutex_init( &lun->tasks_mutex, NULL ) != 0 ) {
		logadd( LOG_ERROR, "iscsi_scsi_lun_create: Error while initializing tasks mutex for iSCSI device LUN" );

		return NULL;
	}

	iscsi_list_create( &lun->tasks_pending );

	if ( pthread_mutex_init( &lun->tasks_pending_mutex, NULL ) != 0 ) {
		logadd( LOG_ERROR, "iscsi_scsi_lun_create: Error while initializing pendings tasks mutex for iSCSI device LUN" );

		pthread_mutex_destroy( &lun->tasks_mutex );

		return NULL;
	}

	iscsi_list_create( &lun->tasks_mgmt );

	if ( pthread_mutex_init( &lun->tasks_mgmt_mutex, NULL ) != 0 ) {
		logadd( LOG_ERROR, "iscsi_scsi_lun_create: Error while initializing management tasks mutex for iSCSI device LUN" );

		pthread_mutex_destroy( &lun->tasks_pending_mutex );
		pthread_mutex_destroy( &lun->tasks_mutex );

		return NULL;
	}

	iscsi_list_create( &lun->tasks_mgmt_pending );

	if ( pthread_mutex_init( &lun->tasks_mgmt_pending_mutex, NULL ) != 0 ) {
		logadd( LOG_ERROR, "iscsi_scsi_lun_create: Error while initializing management pending tasks mutex for iSCSI device LUN" );

		pthread_mutex_destroy( &lun->tasks_mgmt_mutex );
		pthread_mutex_destroy( &lun->tasks_pending_mutex );
		pthread_mutex_destroy( &lun->tasks_mutex );

		return NULL;
	}

	lun->pr_regs = iscsi_hashmap_create( 0U );

	if ( lun->pr_regs == NULL ) {
		logadd( LOG_ERROR, "iscsi_scsi_lun_create: Out of memory allocating iSCSI device LUN Persistent Reservation (PR) registrant for I_T nexus hash map" );

		pthread_mutex_destroy( &lun->tasks_mgmt_pending_mutex );
		pthread_mutex_destroy( &lun->tasks_mgmt_mutex );
		pthread_mutex_destroy( &lun->tasks_pending_mutex );
		pthread_mutex_destroy( &lun->tasks_mutex );
		free( lun );

		return NULL;
	}

	lun->pr_reservation.holder = NULL;
	lun->pr_reservation.cr_key = 0ULL;
	lun->pr_reservation.type   = 0;
	lun->pr_reservation.flags  = 0L;

	lun->pr_scsi2_holder.target_port        = NULL;
	lun->pr_scsi2_holder.target_name        = NULL;
	lun->pr_scsi2_holder.init_port          = NULL;
	lun->pr_scsi2_holder.init_name          = NULL;
	lun->pr_scsi2_holder.transport_id       = NULL;
	lun->pr_scsi2_holder.r_key              = 0ULL;
	lun->pr_scsi2_holder.rel_target_port_id = 0U;
	lun->pr_scsi2_holder.transport_id_len   = 0U;

	lun->device = NULL;
	lun->image  = NULL;
	lun->id     = lun_id;
	lun->flags  = 0;
	lun->pr_gen = 0UL;

	return lun;
}

/**
 * @brief iSCSI SCSI LUN destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * SCSI LUN stored in the iSCSI device hash map.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_scsi_lun_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_scsi_lun_destroy( (iscsi_scsi_lun *) value );
	iscsi_hashmap_key_destroy( key );

	return 0;
}

/**
 * @brief Deallocates all resources acquired by iscsi_scsi_lun_create.
 *
 * This function does not deallocate the
 * associated DNBD3 image and therefore
 * just deallocates the associated SCSI
 * tasks.
 *
 * @param[in] lun Pointer to iSCSI device LUN to be freed.
 * May be NULL in which case this function
 * does nothing at all.
 */
void iscsi_scsi_lun_destroy(iscsi_scsi_lun *lun)
{
	if ( lun != NULL ) {
		if ( lun->pr_regs != NULL ) {
			// iscsi_hashmap_iterate( lun->pr_regs, iscsi_scsi_pr_registrant_destroy_callback, NULL );
			iscsi_hashmap_destroy( lun->pr_regs );

			lun->pr_regs = NULL;
		}

		pthread_mutex_destroy( &lun->tasks_mgmt_pending_mutex );
		pthread_mutex_destroy( &lun->tasks_mgmt_mutex );
		pthread_mutex_destroy( &lun->tasks_pending_mutex );
		pthread_mutex_destroy( &lun->tasks_mutex );
		free( lun );
	}
}

/**
 * @brief Converts an internal representation of a LUN identifier to an iSCSI LUN required for packet data.
 *
 * This function needs to be called prior
 * storing the internal SCSI identifier
 * representation in the iSCSI packet.
 *
 * @param[in] lun_id Internal SCSI presentation of LUN
 * identifier to be converted to iSCSI packet data
 * representation.
 * @return iSCSI packet data representation of LUN or
 * 0 in case of an invalid LUN.
 */
uint64_t iscsi_scsi_lun_get_from_scsi(const int lun_id)
{
	uint64_t iscsi_scsi_lun;

	if ( lun_id < 0x100 )
		iscsi_scsi_lun = (uint64_t) (lun_id & 0xFF) << 48ULL;
	else if ( lun_id < 0x4000 )
		iscsi_scsi_lun = (1ULL << 62ULL) | (uint64_t) (lun_id & 0x3FFF) << 48ULL;
	else
		iscsi_scsi_lun = 0ULL;

	return iscsi_scsi_lun;
}

/**
 * @brief Converts an iSCSI LUN from packet data to internal SCSI LUN identifier.
 *
 * This function needs to be called prior
 * storing the iSCSI packet data
 * representation in the structures
 * requiring an internal SCSI  identifier.
 *
 * @param[in] lun iSCSI packet data LUN to be converted
 * to the internal SCSI LUN identifier
 * representation.
 * @return SCSI identifier representation of iSCSI
 * packet data LUN or 0xFFFF in case of
 * an error.
 */
int iscsi_scsi_lun_get_from_iscsi(const uint64_t lun)
{
	int lun_id = (int) (lun >> 62ULL) & 0x03;

	if ( lun_id == 0x00 )
		lun_id = (int) (lun >> 48ULL) & 0xFF;
	else if ( lun_id == 0x01 )
		lun_id = (int) (lun >> 48ULL) & 0x3FFF;
	else
		lun_id = 0xFFFF;

	return lun_id;
}

/**
 * @brief Appends an iSCSI SCSI task to a iSCSI SCSI LUN pending tasks doubly linked list.
 *
 * This function cannot fail.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN to append the
 * task to, may NOT be NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task to be
 * appended. NULL is NOT an allowed value, so take
 * caution.
 */
void iscsi_scsi_lun_task_append(iscsi_scsi_lun *lun, iscsi_scsi_task *scsi_task)
{
	iscsi_list_enqueue( &lun->tasks_pending, &scsi_task->node );
}

/**
 * @brief Executes all iSCSI SCSI pending tasks assigned to a iSCSI SCSI LUN.
 *
 * This function also removes the pending tasks
 * from the hash map of the SCSI LUN.
 *
 * @param[in] lun Pointer to ISCSI SCSI LUN of which the
 * pending tasks should be executed and may NOT
 * be NULL, so be careful.
 */
void iscsi_scsi_lun_tasks_exec(iscsi_scsi_lun *lun)
{
	while ( !iscsi_list_empty( &lun->tasks_pending ) ) {
		iscsi_scsi_task *scsi_task = (iscsi_scsi_task *) iscsi_list_peek( &lun->tasks_pending );

		iscsi_list_remove( &scsi_task->node );
		pthread_mutex_unlock( &lun->tasks_pending_mutex );
		iscsi_scsi_lun_task_run( lun, scsi_task );
		pthread_mutex_lock( &lun->tasks_pending_mutex );
	}
}

/**
 * @brief Checks whether the iSCSI SCSI task requires unit attention.
 *
 * This function parses the SCSI opcode of the
 * SCSI Command Descriptor Block (CDB).
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to check
 * unit attention for which may NOT be NULL,
 * so be careful.
 * @retval true Unit attention is required.
 * @retval false Unit attention is NOT required.
 */
static bool iscsi_scsi_lun_handle_unit_attention(iscsi_scsi_task *scsi_task)
{
	switch ( scsi_task->cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_INQUIRY :
		case ISCSI_SCSI_OPCODE_REPORTLUNS :
		case ISCSI_SCSI_OPCODE_REQUESTSENSE : {
			return false;

			break;
		}
		default : {
			return true;

			break;
		}

	}
}

/**
 * @brief Runs an iSCSI SCSI task for a specified iSCSI SCSI LUN.
 *
 * This function moves the task back to the
 * iSCSI SCSI LUN tasks hash map prior
 * execution.\n
 * Errors are nandled according to the SCSI
 * standard.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN of which the
 * task should be run and may NOT be NULL,
 * so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task to be run.
 * NULL is NOT valid here, take caution.
 */
void iscsi_scsi_lun_task_run(iscsi_scsi_lun *lun, iscsi_scsi_task *scsi_task)
{
	int rc;

	pthread_mutex_lock( &lun->tasks_mutex );
	iscsi_list_enqueue( &lun->tasks, &scsi_task->node );
	pthread_mutex_unlock( &lun->tasks_mutex );

	scsi_task->status = ISCSI_SCSI_STATUS_GOOD;

	if ( (lun->flags & ISCSI_SCSI_LUN_FLAGS_REMOVED) != 0 ) {
		iscsi_scsi_task_lun_process_abort( scsi_task );

		rc = ISCSI_SCSI_TASK_RUN_COMPLETE;
	} else if ( ((lun->flags & ISCSI_SCSI_LUN_FLAGS_RESIZING) != 0) && iscsi_scsi_lun_handle_unit_attention( scsi_task ) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_UNIT_ATTENTION, ISCSI_SCSI_ASC_CAPACITY_DATA_HAS_CHANGED, ISCSI_SCSI_ASCQ_CAPACITY_DATA_HAS_CHANGED );

		lun->flags &= ~ISCSI_SCSI_LUN_FLAGS_RESIZING;

		rc = ISCSI_SCSI_TASK_RUN_COMPLETE;
	} else {
		if ( (lun->pr_reservation.flags & ISCSI_SCSI_PR_RESERVATION_FLAGS_SPC2_RESERVE) != 0 )
			rc = iscsi_scsi_pr_check_scsi2( scsi_task );
		else
			rc = iscsi_scsi_pr_check( scsi_task );

		if ( rc < 0 )
			rc = ISCSI_SCSI_TASK_RUN_COMPLETE;
		else
			rc = iscsi_scsi_emu_exec( scsi_task );
	}

	if ( rc == ISCSI_SCSI_TASK_RUN_COMPLETE )
		iscsi_scsi_lun_task_complete( lun, scsi_task );
}

/**
 * @brief Handles iSCSI SCSI task completition.
 *
 * This function removes the completed task from
 * the iSCSI SCSI LUN task doubly linked list
 * and calls the transfer finished callback
 * function.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN to remove the task
 * from.
 * @param[in] scsi_task Pointer to iSCSI SCSI task to be removed
 * and to invoke the transfer finished callback
 * of and may NOT be NULL, so be careful.
 */
void iscsi_scsi_lun_task_complete(iscsi_scsi_lun *lun, iscsi_scsi_task *scsi_task)
{
	if ( lun != NULL )
		iscsi_list_remove( &scsi_task->node );

	scsi_task->xfer_complete_callback( scsi_task );
}

/**
 * @brief Appends iSCSI SCSI task to pending tasks doubly linked list and / or runs it directly.
 *
 * This function checks whether there are pending
 * task management pending tasks to be executed
 * first.\n
 * If there are pending tasks enqueued, they will
 * be executed prior this new task.\n
 * If this is the only one task, it will be
 * executed immediately.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN which should be
 * checked for pending tasks prior execution. May
 * NOT be NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task to either be
 * enqueued and run or to be run directly.
 */
void iscsi_scsi_lun_task_exec(iscsi_scsi_lun *lun, iscsi_scsi_task *scsi_task)
{
	pthread_mutex_lock( &lun->tasks_mgmt_pending_mutex );

	if ( !iscsi_list_empty( &lun->tasks_mgmt_pending ) ) {
		pthread_mutex_unlock( &lun->tasks_mgmt_pending_mutex );
		pthread_mutex_lock( &lun->tasks_pending_mutex );
		iscsi_scsi_lun_task_append( lun, scsi_task );
		pthread_mutex_unlock( &lun->tasks_pending_mutex );

		return;
	}

	pthread_mutex_unlock( &lun->tasks_mgmt_pending_mutex );
	pthread_mutex_lock( &lun->tasks_pending_mutex );

	if ( !iscsi_list_empty( &lun->tasks_pending ) ) {
		iscsi_scsi_lun_task_append( lun, scsi_task );
		iscsi_scsi_lun_tasks_exec( lun );
		pthread_mutex_unlock( &lun->tasks_pending_mutex );

		return;
	}

	pthread_mutex_unlock( &lun->tasks_pending_mutex );

	iscsi_scsi_lun_task_run( lun, scsi_task );
}

/**
 * @brief Checks if iSCSI SCSI Persistent Reservation (PR) SCSI-2 I_T nexus is holder.
 *
 * This function compares the target and
 * initiator name with the registrant.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN to be
 * checked, may NOT be NULL, so be careful.
 * @param[in] target_port Pointer to iSCSI target port to
 * check for.
 * @param[in] init_port Pointer to iSCSI initiator port to
 * check for.
 * @retval true The iSCSI SCSI Persistent Reservation
 * (PR) SCSI-2 I_T nexus is actually the holder.
 * @retval false The iSCSI SCSI Persistent Reservation
 * (PR) SCSI-2 I_T nexus is NOT the holder.
 */
static inline bool iscsi_scsi_pr_check_scsi2_it_nexus_is_holder(const iscsi_scsi_lun *lun, const iscsi_port *target_port, const iscsi_port *init_port)
{
	const iscsi_scsi_pr_registrant *reg = lun->pr_reservation.holder;

	return ((reg->target_port == target_port) && (reg->init_port == init_port));
}

/**
 * @brief Checks the iSCSI SCSI Persistent Reservation (PR) SCSI-2 reserve of an iSCSI SCSI task.
 *
 * This function also sets the SCSI error
 * code if the check fails.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to be
 * checked for and may NOT be NULL, so
 * be careful.
 * @return 0 on successful check, a negative
 * error code otherwise.
 */
int iscsi_scsi_pr_check_scsi2(iscsi_scsi_task *scsi_task)
{
	const iscsi_scsi_lun *lun = scsi_task->lun;

	switch ( scsi_task->cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_INQUIRY :
		case ISCSI_SCSI_OPCODE_RELEASE6 :
		case ISCSI_SCSI_OPCODE_RELEASE10 : {
			return ISCSI_SCSI_TASK_RUN_COMPLETE;

			break;
		}
		default : {
			break;
		}
	}

	if ( (lun->pr_reservation.holder == NULL) || iscsi_scsi_pr_check_scsi2_it_nexus_is_holder( lun, scsi_task->target_port, scsi_task->init_port ) )
		return ISCSI_SCSI_TASK_RUN_COMPLETE;

	iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

	return ISCSI_SCSI_TASK_RUN_UNKNOWN;
}

/**
 * @brief Finds an iSCSI SCSI Persistent Reservation (PR) registrant by target and initiator port.
 *
 * Callback function for each element while iterating
 * through the iSCSI SCSI LUN Persistent Reservation
 * (PR) registrants hash map.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL creates an
 * empty key assignment.
 * @param[in,out] user_data Pointer to a data structure
 * containing the iSCSI SCSI Persistent Reservation
 * (PR) registrant and the target, as well as the
 * initiator port to be searched for and may NOT be
 * NULL, so be careful.
 * @retval -1 The registrant has been found and stored
 * in the result structure. Therefore, no further
 * searching is needed.
 * @retval 0 The registrant has not been found yet.
 */
int iscsi_scsi_pr_registrant_get_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_scsi_pr_registrant_get_reg *reg_find = (iscsi_scsi_pr_registrant_get_reg *) user_data;
	iscsi_scsi_pr_registrant *reg = (iscsi_scsi_pr_registrant *) value;

	if ( (reg_find->target_port != reg->target_port) || (reg_find->init_port != reg->init_port) )
		return 0;

	reg_find->reg = reg;

	return -1;
}

/**
 * @brief Searches an iSCSI SCSI Persistent Reservation (PR) registrant by target and initiator port.
 *
 * This function searches for an iSCSI SCSI Persistent
 * Reservation (PR) registrant by iterating through
 * the iSCSI SCSI LUN Persistent Reservation (PR)
 * registrants hash map.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN to
 * search in the Persistent Reservation (PR)
 * registrants hash map. May NOT be NULL, so be
 * careful.
 * @param[in] target_port Pointer to iSCSI target port to
 * search for.
 * @param[in] init_port Pointer to iSCSI initiator port to
 * search for.
 * @return Pointer to found iSCSI SCSI Persistent
 * Reservation (PR) registrant or NULL in case no
 * registrant has a matching target and Initiator
 * port.
 */
static iscsi_scsi_pr_registrant *iscsi_scsi_pr_registrant_get(const iscsi_scsi_lun *lun, iscsi_port *target_port, iscsi_port *init_port)
{
	iscsi_scsi_pr_registrant_get_reg reg_find = {NULL, target_port, init_port};

	iscsi_hashmap_iterate( lun->pr_regs, iscsi_scsi_pr_registrant_get_callback, (uint8_t *) &reg_find );

	return reg_find.reg;
}

/**
 * @brief Checks whether iSCSI SCSI Persistent Reservation (PR) reservation type is all registrants or not.
 *
 * This function checks both if write exclusive and
 * exclusive access types.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN to
 * check the Persistent Reservation (PR)
 * reservation's type. May NOT be NULL, so be
 * careful.
 * @retval true The iSCSI SCSI Persistent Reservation (PR)
 * reservation type is set to all registrants.
 * @retval false The iSCSI SCSI Persistent Reservation (PR)
 * reservation type is NOT set to all registrants.
 */
static inline bool iscsi_scsi_pr_check_is_all_type(const iscsi_scsi_lun *lun)
{
	return ((lun->pr_reservation.type == ISCSI_SCSI_PR_RESERVATION_TYPE_WRITE_EXCLUSIVE_ALL_REGS) || (lun->pr_reservation.type == ISCSI_SCSI_PR_RESERVATION_TYPE_EXCLUSIVE_ACCESS_ALL_REGS));
}

/**
 * @brief Checks whether iSCSI SCSI Persistent Reservation (PR) reservation holder is the specified registrant or not.
 *
 * This function also checks if reservation type is
 * all registrants or not.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN to
 * check the Persistent Reservation (PR)
 * reservation holder for. May NOT be NULL, so be
 * careful.
 * @param[in] reg Pointer to iSCSI SCSI Persistent
 * Reservation (PR) registrant to check for.
 * @retval true The iSCSI SCSI Persistent Reservation (PR)
 * reservation holder matches the registrant.
 * @retval false The iSCSI SCSI Persistent Reservation (PR)
 * reservation holder does NOT match the registrant.
 */
static inline bool iscsi_scsi_pr_check_registrant_is_holder(const iscsi_scsi_lun *lun, const iscsi_scsi_pr_registrant *reg)
{
	return (((reg != NULL) && iscsi_scsi_pr_check_is_all_type( lun )) || (lun->pr_reservation.holder == reg));
}

/**
 * @brief Checks the iSCSI SCSI Persistent Reservation (PR) of an iSCSI SCSI task.
 *
 * This function also sets the SCSI error
 * code if the check fails.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to be
 * checked for and may NOT be NULL, so
 * be careful.
 * @return 0 on successful check, a negative
 * error code otherwise.
 */
int iscsi_scsi_pr_check(iscsi_scsi_task *scsi_task)
{
	const iscsi_scsi_lun *lun           = scsi_task->lun;
	const iscsi_scsi_pr_registrant *reg = iscsi_scsi_pr_registrant_get( lun, scsi_task->target_port, scsi_task->init_port );

	if ( (reg == NULL) || ((reg->target_port == scsi_task->target_port) && (reg->init_port == scsi_task->init_port)) )
		return ISCSI_SCSI_TASK_RUN_COMPLETE;

	const iscsi_scsi_cdb *cdb = (iscsi_scsi_cdb *) scsi_task->cdb;
	bool dma_to_device = false;

	switch ( cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_INQUIRY :
		case ISCSI_SCSI_OPCODE_REPORTLUNS :
		case ISCSI_SCSI_OPCODE_REQUESTSENSE :
		case ISCSI_SCSI_OPCODE_LOGSENSE :
		case ISCSI_SCSI_OPCODE_TESTUNITREADY :
		case ISCSI_SCSI_OPCODE_STARTSTOPUNIT :
		case ISCSI_SCSI_OPCODE_READCAPACITY10 :
		case ISCSI_SCSI_OPCODE_PERSISTENT_RESERVE_IN :
		case ISCSI_SCSI_OPCODE_SERVICE_ACTION_IN_16 :
		case ISCSI_SCSI_OPCODE_RESERVE6 :
		case ISCSI_SCSI_OPCODE_RESERVE10 :
		case ISCSI_SCSI_OPCODE_RELEASE6 :
		case ISCSI_SCSI_OPCODE_RELEASE10 : {
			return ISCSI_SCSI_TASK_RUN_COMPLETE;

			break;
		}
		case ISCSI_SCSI_OPCODE_MODESELECT6 :
		case ISCSI_SCSI_OPCODE_MODESELECT10 :
		case ISCSI_SCSI_OPCODE_MODESENSE6 :
		case ISCSI_SCSI_OPCODE_MODESENSE10 :
		case ISCSI_SCSI_OPCODE_LOGSELECT : {
			if ( reg == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return ISCSI_SCSI_TASK_RUN_UNKNOWN;
			}

			return ISCSI_SCSI_TASK_RUN_COMPLETE;

			break;
		}
		case ISCSI_SCSI_OPCODE_PERSISTENT_RESERVE_OUT : {
			const iscsi_scsi_cdb_pr_reserve_out *cdb_pr_reserve_out = (iscsi_scsi_cdb_pr_reserve_out *) cdb;
			const uint8_t action = ISCSI_SCSI_CDB_PR_RESERVE_OUT_GET_ACTION(cdb_pr_reserve_out->action);

			switch ( action ) {
				case ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_REGISTER :
				case ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_REGISTER_IGNORE_EXIST_KEY : {
					return ISCSI_SCSI_TASK_RUN_COMPLETE;

					break;
				}
				case ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_RELEASE :
				case ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_CLEAR :
				case ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_PREEMPT :
				case ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_PREEMPT_ABORT : {
					if ( reg == NULL ) {
						iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

						return ISCSI_SCSI_TASK_RUN_UNKNOWN;
					}

					return ISCSI_SCSI_TASK_RUN_COMPLETE;

					break;
				}
				default : {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return ISCSI_SCSI_TASK_RUN_UNKNOWN;

					break;

				}
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_READ6 :
		case ISCSI_SCSI_OPCODE_READ10 :
		case ISCSI_SCSI_OPCODE_READ12 :
		case ISCSI_SCSI_OPCODE_READ16 : {
			break;
		}
		case ISCSI_SCSI_OPCODE_WRITE6 :
		case ISCSI_SCSI_OPCODE_WRITE10 :
		case ISCSI_SCSI_OPCODE_WRITE12 :
		case ISCSI_SCSI_OPCODE_WRITE16 :
		case ISCSI_SCSI_OPCODE_UNMAP :
		case ISCSI_SCSI_OPCODE_SYNCHRONIZECACHE10 :
		case ISCSI_SCSI_OPCODE_SYNCHRONIZECACHE16 : {
			dma_to_device = true;

			break;
		}
		default : {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			return ISCSI_SCSI_TASK_RUN_UNKNOWN;

			break;
		}
	}

	switch ( lun->pr_reservation.type ) {
		case ISCSI_SCSI_PR_RESERVATION_TYPE_WRITE_EXCLUSIVE : {
			if ( dma_to_device ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return ISCSI_SCSI_TASK_RUN_UNKNOWN;
			}

			break;
		}
		case ISCSI_SCSI_PR_RESERVATION_TYPE_EXCLUSIVE_ACCESS : {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			return ISCSI_SCSI_TASK_RUN_UNKNOWN;

			break;
		}
		case ISCSI_SCSI_PR_RESERVATION_TYPE_WRITE_EXCLUSIVE_REGS_ONLY :
		case ISCSI_SCSI_PR_RESERVATION_TYPE_WRITE_EXCLUSIVE_ALL_REGS : {
			if ( (reg == NULL) && dma_to_device ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return ISCSI_SCSI_TASK_RUN_UNKNOWN;
			}

			break;
		}
		case ISCSI_SCSI_PR_RESERVATION_TYPE_EXCLUSIVE_ACCESS_REGS_ONLY :
		case ISCSI_SCSI_PR_RESERVATION_TYPE_EXCLUSIVE_ACCESS_ALL_REGS : {
			if ( reg == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_RESERVATION_CONFLICT, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return ISCSI_SCSI_TASK_RUN_UNKNOWN;
			}

			break;
		}
		default : {
			break;
		}
	}

	return ISCSI_SCSI_TASK_RUN_COMPLETE;
}

/**
 * @brief Constructs an iSCSI SCSI Persistent Reservation (PR) out parameter list of an iSCSI SCSI task.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to
 * construct Persistent Reservation (PR)
 * out parameter list for. May NOT be NULL,
 * so be careful.
 * @param[in] pr_reserve_out_parameter_list Pointer to iSCSI SCSI Persistent
 * Reservation (PR) out parameter list. NULL
 * is NOT allowed here, take caution.
 * @param[in] cdb_pr_reserve_out Pointer to iSCSI SCSI Command
 * Descriptor Block (CDB) to construct the
 * out data from and may NOT be NULL, so be
 * careful.
 * @param[in] len Length of parameter list in bytes.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
int iscsi_scsi_pr_out(iscsi_scsi_task *scsi_task, iscsi_scsi_pr_reserve_out_parameter_list_packet *pr_reserve_out_parameter_list, const iscsi_scsi_cdb_pr_reserve_out *cdb_pr_reserve_out, const uint len)
{
	// TODO: Implement function.

	return 0;
}

/**
 * @brief Constructs iSCSI SCSI Persistent Reservation (PR) in parameter data of an iSCSI SCSI task.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to
 * construct Persistent Reservation (PR)
 * in parameter data for. May NOT be NULL,
 * so be careful.
 * @param[in] pr_reserve_in_parameter_data Pointer to iSCSI SCSI Persistent
 * Reservation (PR) in parameter data. NULL
 * is NOT allowed here, take caution.
 * @param[in] cdb_pr_reserve_in Pointer to iSCSI SCSI Command
 * Descriptor Block (CDB) to construct the
 * in data from and may NOT be NULL, so be
 * careful.
 * @param[in] len Length of parameter data in bytes.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
int iscsi_scsi_pr_in(iscsi_scsi_task *scsi_task, iscsi_scsi_pr_reserve_in_parameter_data_packet *pr_reserve_in_parameter_data, const iscsi_scsi_cdb_pr_reserve_in *cdb_pr_reserve_in, const uint len)
{
	// TODO: Implement function.

	return 0;
}

/**
 * @brief Reserves an iSCSI SCSI Persistent Reservation (PR) of an iSCSI SCSI task.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to
 * reserve the Persistent Reservation
 * (PR) for. May NOT be NULL, so be
 * careful.
 * @param[in] cdb_pr_reserve_6 Pointer to iSCSI SCSI Command
 * Descriptor Block (CDB) to reserve the
 * data from. NULL is NOT allowed here,
 * take caution.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
int iscsi_scsi_pr_reserve_scsi2(iscsi_scsi_task *scsi_task, const iscsi_scsi_cdb_pr_reserve_6 *cdb_pr_reserve_6)
{
	// TODO: Implement function.

	return 0;
}

/**
 * @brief Releases an iSCSI SCSI Persistent Reservation (PR) of an iSCSI SCSI task.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to
 * release the Persistent Reservation
 * (PR) for. May NOT be NULL, so be
 * careful.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
int iscsi_scsi_pr_release_scsi2(iscsi_scsi_task *scsi_task)
{
	// TODO: Implement function.

	return 0;
}

/**
 * @brief Checks whether an I/O feature is supported by a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties and queries only one I/O
 * feature at once.
 *
 * @param[in] image Pointer to DNBD3 image to check I/O
 * attributes for. May NOT be NULL, so be
 * careful.
 * @param[in] type I/O type to be checked for.
 * @retval true The DNBD3 image supports the I/O feature.
 * @retval false The I/O feature is NOT supported for the
 * DNBD3 image.
 */
static inline bool iscsi_scsi_emu_io_type_is_supported(const dnbd3_image_t *image, const int type)
{
	// TODO: Actually implement this function.

	int32_t flags;

	switch ( type ) {
		case ISCSI_SCSI_EMU_IO_TYPE_REMOVABLE : {
			flags = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_REMOVABLE );

			if ( flags < 0L )
				flags = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_REMOVABLE );

			return (bool) flags;

			break;
		}
		case ISCSI_SCSI_EMU_IO_TYPE_UNMAP : {
			flags = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_UNMAP );

			if ( flags < 0L )
				flags = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_UNMAP );

			return (bool) flags;

			break;
		}
		case ISCSI_SCSI_EMU_IO_TYPE_NO_ROTATION : {
			flags = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_NO_ROTATION );

			if ( flags < 0L )
				flags = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_NO_ROTATION );

			return (bool) flags;

			break;
		}
		case ISCSI_SCSI_EMU_IO_TYPE_PHYSICAL_READ_ONLY : {
			flags = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY );

			if ( flags < 0L )
				flags = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY );

			return (bool) flags;

			break;
		}
		case ISCSI_SCSI_EMU_IO_TYPE_WRITE_PROTECT : {
			flags = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_PROTECT );

			if ( flags < 0L )
				flags = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_PROTECT );

			return (bool) flags;

			break;
		}
		case ISCSI_SCSI_EMU_IO_TYPE_WRITE_CACHE : {
			flags = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_CACHE );

			if ( flags < 0L )
				flags = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_CACHE );

			return (bool) flags;

			break;
		}
		default : {
			return false;

			break;
		}
	}

	return false;
}

/**
 * @brief Retrieves the number of total physical blocks for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the physical size from. May NOT be NULL,
 * so be careful.
 * @return The number of total physical blocks.
 */
static inline uint64_t iscsi_scsi_emu_physical_block_get_count(const dnbd3_image_t *image)
{
	int32_t block_size_shift = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE_SHIFT );

	if ( block_size_shift < 0L )
		block_size_shift = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE_SHIFT );

	return (image->virtualFilesize >> (uint32_t) block_size_shift);
}

/**
 * @brief Retrieves the bit shift of a physical block in bytes for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the physical bit shift size. May NOT
 * be NULL, so be careful.
 * @return The physical block size in bytes as a
 * bit shift count.
 */
static inline uint32_t iscsi_scsi_emu_physical_block_get_size_shift(const dnbd3_image_t *image)
{
	int32_t block_size_shift = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE_SHIFT );

	if ( block_size_shift < 0L )
		block_size_shift = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE_SHIFT );

	return block_size_shift;
}

/**
 * @brief Retrieves the size of a physical block in bytes for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the physical block size. May NOT be NULL,
 * so be careful.
 * @return The physical block size in bytes.
 */
static inline uint32_t iscsi_scsi_emu_physical_block_get_size(const dnbd3_image_t *image)
{
	int32_t block_size = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE );

	if ( block_size < 0L )
		block_size = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE );

	return block_size;
}

/**
 * @brief Retrieves the number of total logical blocks for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the logical size from. May NOT be NULL,
 * so be careful.
 * @return The number of total logical blocks.
 */
static inline uint64_t iscsi_scsi_emu_block_get_count(const dnbd3_image_t *image)
{
	int32_t block_size_shift = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE_SHIFT );

	if ( block_size_shift < 0L )
		block_size_shift = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE_SHIFT );

	return (image->virtualFilesize >> (uint32_t) block_size_shift);
}

/**
 * @brief Retrieves the bit shift of a logical block in bytes for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the logical block bit shift size.
 * May NOT be NULL, so be careful.
 * @return The logical block size in bytes as a
 * bit shift count.
 */
static inline uint32_t iscsi_scsi_emu_block_get_size_shift(const dnbd3_image_t *image)
{
	int32_t block_size_shift = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE_SHIFT );

	if ( block_size_shift < 0L )
		block_size_shift = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE_SHIFT );

	return block_size_shift;
}

/**
 * @brief Retrieves the size of a logical block in bytes for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the logical block size. May NOT be NULL,
 * so be careful.
 * @return The logical block size in bytes.
 */
static inline uint32_t iscsi_scsi_emu_block_get_size(const dnbd3_image_t *image)
{
	int32_t block_size = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE );

	if ( block_size < 0L )
		block_size = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE );

	return block_size;
}

/**
 * @brief Retrieves the bit shift ratio between logical and physical block size for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the ratio between the logical and
 * physical block size. May NOT be
 * NULL, so be careful.
 * @return The ratio between logical and physical
 * block size as a logical bit shift
 * count.
 */
static inline uint32_t iscsi_scsi_emu_block_get_ratio_shift(const dnbd3_image_t *image)
{
	return (iscsi_scsi_emu_physical_block_get_size_shift( image ) - iscsi_scsi_emu_block_get_size_shift( image ));
}

/**
 * @brief Retrieves the ratio between logical and physical block size for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the ratio between the logical and
 * physical block size. May NOT be
 * NULL, so be careful.
 * @return The ratio between logical logical and physical
 * block size.
 */
static inline uint32_t iscsi_scsi_emu_block_get_ratio(const dnbd3_image_t *image)
{
	return (1UL << iscsi_scsi_emu_block_get_ratio_shift( image ));
}

/**
 * @brief Converts offset and length in bytes to block number and length specified by a block size.
 *
 * This function uses bit shifting if
 * the block size is a power of two.
 *
 * @param[out] offset_blocks Pointer where to store the block
 * number. May NOT be NULL, so be
 * careful.
 * @param[out] num_blocks Pointer where to store the number of
 * blocks. NULL is NOT allowed here,
 * so take caution.
 * @param[in] offset_bytes Offset in bytes.
 * @param[in] num_bytes Number of bytes.
 * @param[in] block_size Block size in bytes.
 * @return 0 if specified offset and number of
 * bytes is aligned to block size or a
 * positive value if unaligned.
 */
static uint64_t iscsi_scsi_emu_bytes_to_blocks(uint64_t *offset_blocks, uint64_t *num_blocks, const uint64_t offset_bytes, const uint64_t num_bytes, const uint32_t block_size)
{
	if ( iscsi_is_pow2( block_size ) ) {
		const uint32_t shift = iscsi_get_log2_of_pow2( block_size );

		*offset_blocks = (offset_bytes >> shift);
		*num_blocks    = (num_bytes >> shift);

		return ((offset_bytes - (*offset_blocks << shift)) | (num_bytes - (*num_blocks << shift)));
	}

	*offset_blocks = (offset_bytes / block_size);
	*num_blocks    = (num_bytes / block_size);

	return ((offset_bytes % block_size) | (num_bytes % block_size));
}

/**
 * @brief Enqueues an I/O task in the waiting queue.
 *
 * This function invokes a callback function
 * with optional user data.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task associated
 * to the I/O process in the waiting queue.
 * May NOT be NULL, so be careful.
 * @param[in] callback Pointer to an I/O wait callback
 * function which executes the pending I/O
 * operation. NULL is NOT allowed here, so
 * take caution.
 * @param[in] user_data Pointer to optional user data for
 * the callback function.
 * @retval -1 The I/O task could not be
 * run in the waiting queue.
 * @retval 0 The I/O task has been added
 * successfully in the I/O task waiting
 * queue.
 */
static int iscsi_scsi_emu_queue_io_wait(iscsi_scsi_task *scsi_task, iscsi_scsi_emu_io_wait_callback callback, uint8_t *user_data)
{
	scsi_task->io_wait.image     = scsi_task->lun->image;
	scsi_task->io_wait.callback  = callback;
	scsi_task->io_wait.user_data = user_data;

	return iscsi_scsi_emu_io_queue( &scsi_task->io_wait );
}

/**
 * @brief Converts offset and length specified by a block size to offset and length in bytes.
 *
 * This function uses bit shifting if
 * the block size is a power of two.
 *
 * @param[out] offset_bytes Pointer where to store the block
 * in bytes. May NOT be NULL, so be
 * careful.
 * @param[in] offset_blocks Offset in blocks.
 * @param[in] num_blocks Number of blocks.
 * @param[in] block_size Block size in bytes.
 * @return Number of blocks in bytes.
 */
static uint64_t iscsi_scsi_emu_blocks_to_bytes(uint64_t *offset_bytes, const uint64_t offset_blocks, const uint64_t num_blocks, const uint32_t block_size)
{
	if ( iscsi_is_pow2( block_size ) ) {
		const uint32_t shift = iscsi_get_log2_of_pow2( block_size );

		*offset_bytes = (offset_blocks << shift);

		return (num_blocks << shift);
	}

	*offset_bytes = (offset_blocks * block_size);

	return (num_blocks * block_size);
}

/**
 * @brief Reads a number of blocks from a block offset of a DNBD3 image to a specified buffer.
 *
 * This function enqueues the I/O read
 * process which invokes a callback
 * function when the read operation has
 * been finished.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task which
 * executes the I/O read operation, may
 * NOT be NULL, so be careful.
 * @param[in] buf Pointer to buffer where to store
 * the read data. NULL is NOT allowed
 * here, take caution.
 * @param[in] image Pointer to DNBD3 image to read
 * data from and may NOT be NULL, so
 * be careful.
 * @param[in] offset_blocks Offset in blocks to start reading from.
 * @param[in] num_blocks Number of blocks to read.
 * @param[in] block_size Block size in bytes.
 * @param[in] callback Pointer to callback function to invoke
 * after I/O read operation has been
 * finished. NULL is a prohibited
 * value, so be careful.
 * @param[in] user_data Pointer to user data passed to the
 * callback function.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
int iscsi_scsi_emu_io_block_read(iscsi_scsi_task *scsi_task, uint8_t *buf, dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks, const uint32_t block_size, iscsi_scsi_emu_io_complete_callback callback, uint8_t *user_data)
{
	uint64_t offset_bytes;
	const uint64_t num_bytes                = iscsi_scsi_emu_blocks_to_bytes( &offset_bytes, offset_blocks, num_blocks, block_size );
	const int64_t len                       = pread( image->readFd, buf, (size_t) num_bytes, offset_bytes );
	const bool success                      = ((uint64_t) len == num_bytes);
	iscsi_connection_exec_queue *exec_queue = (iscsi_connection_exec_queue *) malloc( sizeof(struct iscsi_connection_exec_queue) );

	if ( exec_queue == NULL ) {
		logadd( LOG_ERROR, "iscsi_scsi_emu_io_block_read: Out of memory while allocating execution queue for async I/O" );

		return -ENOMEM;
	}

	exec_queue->data.io.callback  = callback;
	exec_queue->data.io.image     = image;
	exec_queue->data.io.user_data = user_data;
	exec_queue->data.io.success   = success;
	exec_queue->type              = ISCSI_CONNECT_EXEC_QUEUE_TYPE_SCSI_EMU_IO;

	iscsi_task *task = ISCSI_CONTAINER(iscsi_task, scsi_task, scsi_task);

	iscsi_list_enqueue( &task->conn->exec_queue, &exec_queue->node );

	return (success ? 0 : -EIO);
}

/**
 * @brief Completes an iSCSI SCSI task after a finished I/O read operation.
 *
 * THis function also sets the SCSI status
 * and error code as required.
 *
 * @param[in] image Pointer to DNBD3 image where
 * the I/O read operation occured and
 * may NOT be NULL, so be careful.
 * @param[in] user_data Pointer to the iSCSI SCSI task
 * responsible for this I/O operation.
 * NULL is NOT allowed here, so take
 * caution.
 * @param[in] success true if the I/O operation has been
 * completed successfully, false otherwise.
 * @return Pointer to passed user data.
 */
uint8_t *iscsi_scsi_emu_block_read_complete_callback(dnbd3_image_t *image, uint8_t *user_data, const bool success)
{
	iscsi_scsi_task *scsi_task = (iscsi_scsi_task *) user_data;

	if ( success )
		scsi_task->status = ISCSI_SCSI_STATUS_GOOD;
	else
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_MEDIUM_ERR, ISCSI_SCSI_ASC_UNRECOVERED_READ_ERR, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

	iscsi_scsi_lun_task_complete( scsi_task->lun, scsi_task );

	return user_data;
}

/**
 * @brief Compares and writes a number of blocks starting from a block offset in a DNBD3 image with specified buffers.
 *
 * This function enqueues the I/O compare
 * and write process which invokes a
 * callback function when the compare and
 * write operation has been finished.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task which
 * executes the I/O compare and write
 * operation, may NOT be NULL, so be
 * careful.
 * @param[in] buf Pointer to buffer which contains
 * the data to be written. NULL is NOT
 * allowed here, take caution.
 * @param[in] cmp_buf Pointer to buffer which contains
 * the data to be compared and may NOT
 * be NULL, so be careful.
 * @param[in] image Pointer to DNBD3 image to write
 * data to. NULL is an illegal value,
 * take caution.
 * @param[in] offset_blocks Offset in blocks to start writing to.
 * @param[in] num_blocks Number of blocks to write.
 * @param[in] block_size Block size in bytes.
 * @param[in] callback Pointer to callback function to invoke
 * after I/O compare and write operation
 * has been finished. NULL is a
 * prohibited value, so be careful.
 * @param[in] user_data Pointer to user data passed to the
 * callback function.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
int iscsi_scsi_emu_io_block_cmp_write(iscsi_scsi_task *scsi_task, uint8_t *buf, uint8_t *cmp_buf, dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks, const uint32_t block_size, iscsi_scsi_emu_io_complete_callback callback, uint8_t *user_data)
{
	// TODO: Implement compare and write I/O.

	return ISCSI_SCSI_TASK_RUN_COMPLETE;
}

/**
 * @brief Completes an iSCSI SCSI task after a finished I/O write operation.
 *
 * THis function also sets the SCSI status
 * and error code as required.
 *
 * @param[in] image Pointer to DNBD3 image where
 * the I/O write operation occured and
 * may NOT be NULL, so be careful.
 * @param[in] user_data Pointer to the iSCSI SCSI task
 * responsible for this I/O operation.
 * NULL is NOT allowed here, so take
 * caution.
 * @param[in] success true if the I/O operation has been
 * completed successfully, false otherwise.
 * @return Pointer to passed user data.
 */
uint8_t *iscsi_scsi_emu_block_write_complete_callback(dnbd3_image_t *image, uint8_t *user_data, const bool success)
{
	iscsi_scsi_task *scsi_task = (iscsi_scsi_task *) user_data;

	free( scsi_task->buf );
	scsi_task->buf = NULL;

	if ( success )
		scsi_task->status = ISCSI_SCSI_STATUS_GOOD;
	else
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_MEDIUM_ERR, ISCSI_SCSI_ASC_WRITE_ERR, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

	iscsi_scsi_lun_task_complete( scsi_task->lun, scsi_task );

	return user_data;
}

/**
 * @brief Writes a number of blocks from a block offset to a DNBD3 image of a specified buffer.
 *
 * This function enqueues the I/O write
 * process which invokes a callback
 * function when the write operation
 * has been finished.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task which
 * executes the I/O write operation, may
 * NOT be NULL, so be careful.
 * @param[in] buf Pointer to buffer which contains
 * the data to be written. NULL is NOT
 * allowed here, take caution.
 * @param[in] image Pointer to DNBD3 image to write
 * data to and may NOT be NULL, so
 * be careful.
 * @param[in] offset_blocks Offset in blocks to start writing to.
 * @param[in] num_blocks Number of blocks to write.
 * @param[in] block_size Block size in bytes.
 * @param[in] callback Pointer to callback function to invoke
 * after I/O write operation has been
 * finished. NULL is a prohibited
 * value, so be careful.
 * @param[in] user_data Pointer to user data passed to the
 * callback function.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
int iscsi_scsi_emu_io_block_write(iscsi_scsi_task *scsi_task, uint8_t *buf, dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks, const uint32_t block_size, iscsi_scsi_emu_io_complete_callback callback, uint8_t *user_data)
{
	uint64_t offset_bytes;
	const uint64_t num_bytes                = iscsi_scsi_emu_blocks_to_bytes( &offset_bytes, offset_blocks, num_blocks, block_size );
	const int64_t len                       = pwrite( image->readFd, buf, (size_t) num_bytes, offset_bytes );
	const bool success                      = ((uint64_t) len == num_bytes);
	iscsi_connection_exec_queue *exec_queue = (iscsi_connection_exec_queue *) malloc( sizeof(struct iscsi_connection_exec_queue) );

	if ( exec_queue == NULL ) {
		logadd( LOG_ERROR, "iscsi_scsi_emu_io_block_read: Out of memory while allocating execution queue for async I/O" );

		return -ENOMEM;
	}

	exec_queue->data.io.callback  = callback;
	exec_queue->data.io.image     = image;
	exec_queue->data.io.user_data = user_data;
	exec_queue->data.io.success   = success;
	exec_queue->type              = ISCSI_CONNECT_EXEC_QUEUE_TYPE_SCSI_EMU_IO;

	iscsi_task *task = ISCSI_CONTAINER(iscsi_task, scsi_task, scsi_task);

	iscsi_list_enqueue( &task->conn->exec_queue, &exec_queue->node );

	return (success ? 0 : -EIO);
}

/**
 * @brief Executes a read or write operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to read from
 * or to write to. May NOT be NULL, so
 * be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this read or write
 * task. NULL is NOT allowed here, take
 * caution.
 * @param[in] lba Logical Block Address (LBA) to start
 * reading from or writing to.
 * @param[in] xfer_len Transfer length in logical blocks.
 * @param[in] flags Flags indicating if a read or write
 * operation is in progress. For a
 * write operation an optional verify
 * can be requested.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_block_read_write(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, const uint64_t lba, const uint32_t xfer_len, const int flags)
{
	scsi_task->xfer_pos = 0UL;

	if ( (scsi_task->flags & (ISCSI_SCSI_TASK_FLAGS_XFER_READ | ISCSI_SCSI_TASK_FLAGS_XFER_WRITE)) == (ISCSI_SCSI_TASK_FLAGS_XFER_READ | ISCSI_SCSI_TASK_FLAGS_XFER_WRITE) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	const uint64_t block_count = iscsi_scsi_emu_block_get_count( image );

	if ( (block_count <= lba) || ((block_count - lba) < xfer_len) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	if ( xfer_len == 0UL ) {
		scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	const uint32_t block_size  = iscsi_scsi_emu_block_get_size( image );
	const bool block_size_pow2 = iscsi_is_pow2( block_size );
	uint32_t block_size_shift;

	if ( block_size_pow2 )
		block_size_shift = iscsi_scsi_emu_block_get_size_shift( image );

	const uint32_t max_xfer_len = (block_size_pow2 ? (ISCSI_SCSI_EMU_MAX_XFER_LEN >> block_size_shift) : (ISCSI_SCSI_EMU_MAX_XFER_LEN / block_size));

	if ( xfer_len > max_xfer_len ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	if ( ((flags & ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE) != 0) && ((block_size_pow2 ? (xfer_len << block_size_shift) : (xfer_len * block_size)) > scsi_task->xfer_len) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	uint64_t offset_blocks;
	uint64_t num_blocks;

	if ( iscsi_scsi_emu_bytes_to_blocks( &offset_blocks, &num_blocks, scsi_task->pos, scsi_task->len, block_size ) != 0ULL ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	offset_blocks += lba;

	int rc;

	if ( (flags & ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE) == 0 ) {
		scsi_task->buf = (uint8_t *) malloc( scsi_task->len );

		if ( scsi_task->buf == NULL ) {
			iscsi_scsi_emu_queue_io_wait( scsi_task, iscsi_scsi_emu_block_resubmit_process_callback, (uint8_t *) scsi_task );

			return ISCSI_SCSI_TASK_RUN_PENDING;
		}

		rc = iscsi_scsi_emu_io_block_read( scsi_task, scsi_task->buf, image, offset_blocks, num_blocks, block_size, iscsi_scsi_emu_block_read_complete_callback, (uint8_t *) scsi_task );
	} else if ( iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_PHYSICAL_READ_ONLY ) || iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_WRITE_PROTECT ) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_DATA_PROTECT, ISCSI_SCSI_ASC_WRITE_PROTECTED, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	} else if ( (flags & ISCSI_SCSI_EMU_BLOCK_FLAGS_VERIFY) != 0 ) {
		if ( scsi_task->len != (block_size + block_size) ) {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			return ISCSI_SCSI_TASK_RUN_COMPLETE;
		}

		uint8_t *cmp_buf = (scsi_task->buf + block_size);

		rc = iscsi_scsi_emu_io_block_cmp_write( scsi_task, scsi_task->buf, cmp_buf, image, offset_blocks, 1ULL, block_size, iscsi_scsi_emu_block_write_complete_callback, (uint8_t *) scsi_task );
	} else {
		rc = iscsi_scsi_emu_io_block_write( scsi_task, scsi_task->buf, image, offset_blocks, num_blocks, block_size, iscsi_scsi_emu_block_write_complete_callback, (uint8_t *) scsi_task );
	}

	if ( rc < 0 ) {
		if ( rc == -ENOMEM ) {
			iscsi_scsi_emu_queue_io_wait( scsi_task, iscsi_scsi_emu_block_resubmit_process_callback, (uint8_t *) scsi_task );

			return ISCSI_SCSI_TASK_RUN_PENDING;
		}

		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	scsi_task->xfer_pos = scsi_task->len;

	return ISCSI_SCSI_TASK_RUN_PENDING;
}

/**
 * @brief Enqueues an I/O wait in the thread pool to execute.
 *
 * This function uses the DNBD3 image
 * name in order to identify the
 * newly created thread.
 *
 * @param[in] io_wait Pointer to I/O wait structure
 * containing the image name, the
 * callback function and optional
 * user data passed to callback. May
 * NOT be NULL, so be careful.
 * @retval -1 An error occured during the
 * thread enqeue operation.
 * @retval 0 The thread has been enqueued
 * successfully.
 */
int iscsi_scsi_emu_io_queue(iscsi_scsi_emu_io_wait *io_wait)
{
	return (threadpool_run( (void *(*)(void *)) io_wait->callback, (void *) io_wait->user_data, io_wait->image->name ) ? 0 : -1);
}

/**
 * @brief Executes a cache synchronization operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to
 * synchronize the cache of. May NOT
 * be NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this cache
 * synchronization. NULL is NOT
 * allowed here, take caution.
 * @param[in] lba Logical Block Address (LBA) to start
 * cache synchronization with.
 * @param[in] xfer_len Synchronization length in logical blocks.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_block_sync(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, const uint64_t lba, const uint32_t xfer_len)
{
	// TODO: Implement SCSI emulation for DNBD3 image.

	return 0;
}

/**
 * @brief Executes a unmap operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to
 * unmap. May NOT be NULL, so be
 * careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this unmap
 * operation. NULL is NOT allowed
 * here, take caution.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_block_unmap(dnbd3_image_t *image, iscsi_scsi_task *scsi_task)
{
	// TODO: Implement SCSI emulation for DNBD3 image.

	return 0;
}

/**
 * @brief Executes a write same operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to write
 * to. May NOT be NULL, so be
 * careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this write task.
 * NULL is NOT allowed here, take
 * caution.
 * @param[in] lba Logical Block Address (LBA) to start
 * writing to.
 * @param[in] xfer_len Transfer length in logical blocks.
 * @param[in] flags SCSI (Command Descriptor Block) CDB flags.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_block_write_same(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, const uint64_t lba, const uint32_t xfer_len, const int flags)
{
	// TODO: Implement SCSI emulation for DNBD3 image.

	return 0;
}

/**
 * @brief Initializes a DNBD3 image for an iSCSI SCSI LUN retrieved from its iSCSI SCSI task and optionally check for read access.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * to retrieve the iSCSI SCSI LUN
 * from in order to initialize the
 * DNBD3 image and also set the SCSI
 * error code. May NOT be NULL, so
 * be careful.
 * @param[in] access Check if read access for DNBD3
 * image is working.
 * @retval true The DNBD3 image has been initialized
 * successfully and is readable.
 * @retval false The DNBD3 image has NOT been
 * successfully and is read is not possible.
 */
static bool iscsi_scsi_emu_image_init(iscsi_scsi_task *scsi_task, const bool access)
{
	// TODO: Handle server and proxy stuff.

	iscsi_scsi_lun *lun = scsi_task->lun;

	if ( lun->image == NULL ) {
		lun->image = image_getOrLoad( (char *) lun->device->name, (uint16_t) lun->id );

		if ( lun->image == NULL ) {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_MANUAL_INTERVENTION_REQUIRED );

			return false;
		}
	}

	if ( access && (!image_ensureOpen( lun->image ) || lun->image->problem.read || (lun->image->virtualFilesize == 0ULL)) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_MANUAL_INTERVENTION_REQUIRED );

		return false;
	}

	return true;
}

/**
 * @brief Executes SCSI block emulation on a DNBD3 image.
 *
 * This function determines the block
 * based SCSI opcode and executes it.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * to process the SCSI block operation
 * for and may NOT be NULL, be careful.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_block_process(iscsi_scsi_task *scsi_task)
{
	iscsi_scsi_lun *lun = scsi_task->lun;
	uint64_t lba;
	uint32_t xfer_len;

	switch ( scsi_task->cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_READ6 : {
			const iscsi_scsi_cdb_read_write_6 *cdb_read_write_6 = (iscsi_scsi_cdb_read_write_6 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be24(cdb_read_write_6->lba);
			xfer_len = cdb_read_write_6->xfer_len;

			if ( xfer_len == 0UL )
				xfer_len = 256UL;

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, 0 );

			break;
		}
		case ISCSI_SCSI_OPCODE_WRITE6 : {
			const iscsi_scsi_cdb_read_write_6 *cdb_read_write_6 = (iscsi_scsi_cdb_read_write_6 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be24(cdb_read_write_6->lba);
			xfer_len = cdb_read_write_6->xfer_len;

			if ( xfer_len == 0UL )
				xfer_len = 256UL;

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE );

			break;
		}
		case ISCSI_SCSI_OPCODE_READ10 : {
			const iscsi_scsi_cdb_read_write_10 *cdb_read_write_10 = (iscsi_scsi_cdb_read_write_10 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be32(cdb_read_write_10->lba);
			xfer_len = iscsi_get_be16(cdb_read_write_10->xfer_len);

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, 0 );

			break;
		}
		case ISCSI_SCSI_OPCODE_WRITE10 : {
			const iscsi_scsi_cdb_read_write_10 *cdb_read_write_10 = (iscsi_scsi_cdb_read_write_10 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be32(cdb_read_write_10->lba);
			xfer_len = iscsi_get_be16(cdb_read_write_10->xfer_len);

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE );

			break;
		}
		case ISCSI_SCSI_OPCODE_READ12 : {
			const iscsi_scsi_cdb_read_write_12 *cdb_read_write_12 = (iscsi_scsi_cdb_read_write_12 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be32(cdb_read_write_12->lba);
			xfer_len = iscsi_get_be32(cdb_read_write_12->xfer_len);

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, 0 );

			break;
		}
		case ISCSI_SCSI_OPCODE_WRITE12 : {
			const iscsi_scsi_cdb_read_write_12 *cdb_read_write_12 = (iscsi_scsi_cdb_read_write_12 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be32(cdb_read_write_12->lba);
			xfer_len = iscsi_get_be32(cdb_read_write_12->xfer_len);

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE );

			break;
		}
		case ISCSI_SCSI_OPCODE_READ16 : {
			const iscsi_scsi_cdb_read_write_16 *cdb_read_write_16 = (iscsi_scsi_cdb_read_write_16 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be64(cdb_read_write_16->lba);
			xfer_len = iscsi_get_be32(cdb_read_write_16->xfer_len);

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, 0 );

			break;
		}
		case ISCSI_SCSI_OPCODE_WRITE16 : {
			const iscsi_scsi_cdb_read_write_16 *cdb_read_write_16 = (iscsi_scsi_cdb_read_write_16 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be64(cdb_read_write_16->lba);
			xfer_len = iscsi_get_be32(cdb_read_write_16->xfer_len);

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE );

			break;
		}
		case ISCSI_SCSI_OPCODE_COMPARE_AND_WRITE : {
			const iscsi_scsi_cdb_cmp_write *cdb_cmp_write = (iscsi_scsi_cdb_cmp_write *) scsi_task->cdb;

			lba      = iscsi_get_be64(cdb_cmp_write->lba);
			xfer_len = cdb_cmp_write->num_blocks;

			if ( ((cdb_cmp_write->flags & (ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_FUA | ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_DPO)) != 0) || ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_GET_WRPROTECT(cdb_cmp_write->flags) ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return ISCSI_SCSI_TASK_RUN_COMPLETE;
			}

			if ( xfer_len != 1UL )  {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return ISCSI_SCSI_TASK_RUN_COMPLETE;
			}

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			return iscsi_scsi_emu_block_read_write( lun->image, scsi_task, lba, xfer_len, (ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE | ISCSI_SCSI_EMU_BLOCK_FLAGS_VERIFY) );

			break;
		}
		case ISCSI_SCSI_OPCODE_READCAPACITY10 : {
			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			iscsi_scsi_read_capacity_10_parameter_data_packet *buf = (iscsi_scsi_read_capacity_10_parameter_data_packet *) malloc( sizeof(struct iscsi_scsi_read_capacity_10_parameter_data_packet) );

			if ( buf == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				return ISCSI_SCSI_TASK_RUN_COMPLETE;
			}

			lba = iscsi_scsi_emu_block_get_count( lun->image ) - 1ULL;

			if ( lba > 0xFFFFFFFFULL )
				buf->lba = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
			else
				iscsi_put_be32( (uint8_t *) &buf->lba, (uint32_t) lba );

			xfer_len = iscsi_scsi_emu_block_get_size( lun->image );

			iscsi_put_be32( (uint8_t *) &buf->block_len, xfer_len );

			uint len = scsi_task->len;

			if ( len > sizeof(struct iscsi_scsi_read_capacity_10_parameter_data_packet) )
				len = sizeof(struct iscsi_scsi_read_capacity_10_parameter_data_packet); // TODO: Check whether scatter data is required

			scsi_task->buf      = (uint8_t *) buf;
			scsi_task->xfer_pos = len;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_SERVICE_ACTION_IN_16 : {
			const iscsi_scsi_cdb_service_action_in_16 *cdb_servce_in_action_16 = (iscsi_scsi_cdb_service_action_in_16 *) scsi_task->cdb;

			switch ( ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_GET_ACTION(cdb_servce_in_action_16->action) ) {
				case ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_READ_CAPACITY_16 : {
					if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
						break;

					iscsi_scsi_service_action_in_16_parameter_data_packet *buf = (iscsi_scsi_service_action_in_16_parameter_data_packet *) malloc( sizeof(struct iscsi_scsi_service_action_in_16_parameter_data_packet) );

					if ( buf == NULL ) {
						iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

						return ISCSI_SCSI_TASK_RUN_COMPLETE;
					}

					lba      = iscsi_scsi_emu_block_get_count( lun->image ) - 1ULL;
					xfer_len = iscsi_scsi_emu_block_get_size( lun->image );

					iscsi_put_be64( (uint8_t *) &buf->lba, lba );
					iscsi_put_be32( (uint8_t *) &buf->block_len, xfer_len );

					buf->flags = 0;

					const uint8_t exponent = (uint8_t) iscsi_scsi_emu_block_get_ratio_shift( lun->image );

					buf->exponents = ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_PUT_LBPPB_EXPONENT((exponent <= ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_MASK) ? exponent : 0U);

					if ( iscsi_scsi_emu_io_type_is_supported( lun->image, ISCSI_SCSI_EMU_IO_TYPE_UNMAP ) )
						iscsi_put_be16( (uint8_t *) &buf->lbp_lalba, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPME );
					else
						buf->lbp_lalba = 0U;

					buf->reserved[0] = 0ULL;
					buf->reserved[1] = 0ULL;

					uint len = cdb_servce_in_action_16->alloc_len;

					if ( len > sizeof(struct iscsi_scsi_service_action_in_16_parameter_data_packet) )
						len = sizeof(struct iscsi_scsi_service_action_in_16_parameter_data_packet); // TODO: Check whether scatter data is required

					scsi_task->buf      = (uint8_t *) buf;
					scsi_task->xfer_pos = len;
					scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

					break;
				}
				default : {
					return ISCSI_SCSI_TASK_RUN_UNKNOWN;

					break;
				}
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_SYNCHRONIZECACHE10 : {
			const iscsi_scsi_cdb_sync_cache_10 *cdb_sync_cache_10 = (iscsi_scsi_cdb_sync_cache_10 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be32(cdb_sync_cache_10->lba);
			xfer_len = iscsi_get_be16(cdb_sync_cache_10->xfer_len);

			if ( xfer_len == 0UL )
				xfer_len = (uint32_t) (iscsi_scsi_emu_block_get_count( lun->image ) - lba);

			return iscsi_scsi_emu_block_sync( lun->image, scsi_task, lba, xfer_len );

			break;
		}
		case ISCSI_SCSI_OPCODE_SYNCHRONIZECACHE16 : {
			const iscsi_scsi_cdb_sync_cache_16 *cdb_sync_cache_16 = (iscsi_scsi_cdb_sync_cache_16 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be64(cdb_sync_cache_16->lba);
			xfer_len = iscsi_get_be32(cdb_sync_cache_16->xfer_len);

			if ( xfer_len == 0UL )
				xfer_len = (uint32_t) (iscsi_scsi_emu_block_get_count( lun->image ) - lba);

			return iscsi_scsi_emu_block_sync( lun->image, scsi_task, lba, xfer_len );

			break;
		}
		case ISCSI_SCSI_OPCODE_UNMAP : {
			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			return iscsi_scsi_emu_block_unmap( lun->image, scsi_task );

			break;
		}
		case ISCSI_SCSI_OPCODE_WRITE_SAME10 : {
			const iscsi_scsi_cdb_write_same_10 *cdb_write_same_10 = (iscsi_scsi_cdb_write_same_10 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be32(cdb_write_same_10->lba);
			xfer_len = iscsi_get_be16(cdb_write_same_10->xfer_len);

			return iscsi_scsi_emu_block_write_same( lun->image, scsi_task, lba, xfer_len, cdb_write_same_10->flags );

			break;
		}
		case ISCSI_SCSI_OPCODE_WRITE_SAME16 : {
			const iscsi_scsi_cdb_write_same_16 *cdb_write_same_16 = (iscsi_scsi_cdb_write_same_16 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			lba      = iscsi_get_be64(cdb_write_same_16->lba);
			xfer_len = iscsi_get_be32(cdb_write_same_16->xfer_len);

			return iscsi_scsi_emu_block_write_same( lun->image, scsi_task, lba, xfer_len, cdb_write_same_16->flags );

			break;
		}
		default : {
			return ISCSI_SCSI_TASK_RUN_UNKNOWN;

			break;
		}
	}

	return ISCSI_SCSI_TASK_RUN_COMPLETE;
}

/**
 * @brief Resubmits an iSCSI SCSI task for execution.
 *
 * This function is invoked if an iSCSI
 * SCSI task needs to be resubmitted in
 * case if a prior execution failed and
 * the failure is recoverable.
 *
 * @param[in] user_data Pointer to user_data which is
 * the iSCSI SCSI task to be executed
 * again. May NOT be NULL, so be
 * careful.
 * @return Pointer to passed user data.
 */
uint8_t *iscsi_scsi_emu_block_resubmit_process_callback(uint8_t *user_data)
{
	iscsi_scsi_task *scsi_task = (iscsi_scsi_task *) user_data;

	iscsi_scsi_emu_block_process( scsi_task );

	return user_data;
}

/**
 * @brief Checks whether provided SCSI CDB allocation length is large enough.
 *
 * This function also sets the SCSI
 * status result code if the allocation
 * size is insufficent.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to set
 * the iSCSI status result code for and
 * may NOT be NULL, so be careful.
 * @param[in] len Actual length in bytes passed to check.
 * @param[in] min_len Minimum length in bytes required.
 * @retval 0 Allocation length is sufficent.
 * @retval -1 Allocation length is insufficent, SCSI status
 * code set.
 */
static int iscsi_scsi_emu_check_len(iscsi_scsi_task *scsi_task, const uint len, const uint min_len)
{
	if ( len >= min_len )
		return 0;

	iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

	return -1;
}

/**
 * @brief Calculates the 64-bit IEEE Extended NAA for a name.
 *
 * @param[out] buf Pointer to 64-bit output buffer for
 * storing the IEEE Extended NAA. May
 * NOT be NULL, so be careful.
 * @param[in] name Pointer to string containing the
 * name to calculate the IEEE Extended
 * NAA for. NULL is NOT allowed here, so
 * take caution.
 */
static inline void iscsi_scsi_emu_naa_ieee_ext_set(uint64_t *buf, const uint8_t *name)
{
	const uint64_t wwn = iscsi_target_node_wwn_get( name );

	iscsi_put_be64( (uint8_t *) buf, wwn );
}

/**
 * @brief Copies a SCSI name string and zero pads until total string length is aligned to DWORD boundary.
 *
 * @param[out] buf Pointer to copy the aligned SCSI
 * string to. May NOT be NULL, so be
 * careful.
 * @param[in] name Pointer to string containing the
 * SCSI name to be copied. NULL is NOT
 * allowed here, so take caution.
 * @return The aligned string length in bytes.
 */
static size_t iscsi_scsi_emu_pad_scsi_name(uint8_t *buf, const uint8_t *name)
{
	size_t len = strlen( (char *) name );

	memcpy( buf, name, len );

	do {
		buf[len++] = '\0';
	} while ( (len & (ISCSI_ALIGN_SIZE - 1)) != 0 );

	return len;
}

/**
 * @brief Fills in a single Vital Product Data (VPD) SCSI Port Designation Descriptor entry of an INQUIRY operation.
 *
 * Callback function for each element while iterating
 * through the iSCSI SCSI device ports hash map.\n
 * The iteration process is aborted when the
 * remaining allocation length is not enough
 * to hold the current VPD SCSI Port Designation
 * Descriptor.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL creates an
 * empty key assignment.
 * @param[in,out] user_data Pointer to a data structure
 * containing the current Vital Product Data
 * (VPD) SCSI Port Designation Descriptor
 * entry, the total length of all VPD SCSI Port
 * Designation Descriptor entries in bytes, the
 * remaining allocation length in bytes. May
 * NOT be NULL, so be careful.
 * @retval -1 Operation failure, ran out of
 * allocation space during traversal.
 * @retval 0 Successful operation, there is enough
 * allocation space to store this
 * reported Vital Product Data (VPD) SCSI Port
 * Designation Descriptor entry.
 */
int iscsi_scsi_emu_primary_inquiry_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_scsi_emu_primary_inquiry_ports_fill *port_report_fill = (iscsi_scsi_emu_primary_inquiry_ports_fill *) user_data;
	iscsi_port *port = (iscsi_port *) value;

	if ( (port->flags & ISCSI_PORT_FLAGS_IN_USE) == 0 )
		return 0;

	const uint port_name_len = (uint) (strlen( (char *) port->name ) + 1U);
	const uint len = (uint) (sizeof(struct iscsi_scsi_vpd_scsi_port_design_dec_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_scsi_target_port_design_dec_inquiry_data_packet) + ISCSI_ALIGN(port_name_len, ISCSI_ALIGN_SIZE));

	port_report_fill->len -= len;

	if ( (int) port_report_fill->len < 0 )
		return -1;

	iscsi_scsi_vpd_scsi_port_design_dec_inquiry_data_packet *vpd_scsi_port_design_desc_inquiry_data_pkt = port_report_fill->port_entry;

	vpd_scsi_port_design_desc_inquiry_data_pkt->reserved        = 0U;
	iscsi_put_be16( (uint8_t *) &vpd_scsi_port_design_desc_inquiry_data_pkt->rel_port_id, port->index );
	vpd_scsi_port_design_desc_inquiry_data_pkt->reserved2       = 0U;
	vpd_scsi_port_design_desc_inquiry_data_pkt->init_port_len   = 0U;
	vpd_scsi_port_design_desc_inquiry_data_pkt->reserved3       = 0U;
	iscsi_put_be16( (uint8_t *) &vpd_scsi_port_design_desc_inquiry_data_pkt->target_desc_len, (uint16_t) (len - sizeof(struct iscsi_scsi_vpd_scsi_port_design_dec_inquiry_data_packet)) );

	iscsi_scsi_vpd_scsi_target_port_design_dec_inquiry_data_packet *vpd_scsi_target_port_design_desc_inquiry_data_pkt = vpd_scsi_port_design_desc_inquiry_data_pkt->target_desc;

	vpd_scsi_target_port_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_ISCSI) | ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8);
	vpd_scsi_target_port_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME) | ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
	vpd_scsi_target_port_design_desc_inquiry_data_pkt->reserved             = 0U;
	vpd_scsi_target_port_design_desc_inquiry_data_pkt->len                  = (uint8_t) iscsi_scsi_emu_pad_scsi_name( vpd_scsi_target_port_design_desc_inquiry_data_pkt->design, port->name );

	port_report_fill->port_entry  = (iscsi_scsi_vpd_scsi_port_design_dec_inquiry_data_packet *) (((uint8_t *) vpd_scsi_port_design_desc_inquiry_data_pkt) + len);
	port_report_fill->alloc_len  += len;

	return 0;
}

/**
 * @brief Executes an inquiry operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to get
 * the inquiry data from. May NOT be
 * NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this inqueiry
 * request. NULL is NOT allowed here,
 * take caution.
 * @param[in] cdb_inquiry Pointer to Command Descriptor
 * Block (CDB) and may NOT be NULL, be
 * careful.
 * @param[in] std_inquiry_data_pkt Pointer to standard inquiry
 * data packet to fill the inquiry
 * data with.
 * @param[in] len Length of inquiry result buffer
 * in bytes.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_primary_inquiry(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, const iscsi_scsi_cdb_inquiry *cdb_inquiry, iscsi_scsi_std_inquiry_data_packet *std_inquiry_data_pkt, const uint len)
{
	if ( len < sizeof(struct iscsi_scsi_std_inquiry_data_packet) ) {
		scsi_task->xfer_pos = 0UL;

		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return -1;
	}

	const int evpd = (cdb_inquiry->lun_flags & ISCSI_SCSI_CDB_INQUIRY_FLAGS_EVPD);
	const uint pc  = cdb_inquiry->page_code;

	if ( (evpd == 0) && (pc != 0U) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return -1;
	}

	iscsi_scsi_lun *lun  = scsi_task->lun;
	iscsi_device *device = lun->device;
	iscsi_port *port     = scsi_task->target_port;

	if ( evpd != 0 ) {
		iscsi_scsi_vpd_page_inquiry_data_packet *vpd_page_inquiry_data_pkt = (iscsi_scsi_vpd_page_inquiry_data_packet *) std_inquiry_data_pkt;
		int32_t scsi_device_type                                           = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_DEVICE_TYPE );
		uint alloc_len;

		if ( scsi_device_type < 0L )
			scsi_device_type = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_DEVICE_TYPE );

		const uint8_t pti = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PUT_PERIPHERAL_TYPE(scsi_device_type) | ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PUT_PERIPHERAL_ID(ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_POSSIBLE);

		vpd_page_inquiry_data_pkt->peripheral_type_id        = pti;
		vpd_page_inquiry_data_pkt->page_code                 = (uint8_t) pc;

		switch ( pc ) {
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SUPPORTED_VPD_PAGES : {
				vpd_page_inquiry_data_pkt->params[0] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SUPPORTED_VPD_PAGES;
				vpd_page_inquiry_data_pkt->params[1] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_UNIT_SERIAL_NUMBER;
				vpd_page_inquiry_data_pkt->params[2] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_DEVICE_ID;
				vpd_page_inquiry_data_pkt->params[3] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_MANAGEMENT_NETWORK_ADDRS;
				vpd_page_inquiry_data_pkt->params[4] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_EXTENDED_INQUIRY_DATA;
				vpd_page_inquiry_data_pkt->params[5] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_MODE_PAGE_POLICY;
				vpd_page_inquiry_data_pkt->params[6] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SCSI_PORTS;
				vpd_page_inquiry_data_pkt->params[7] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_LIMITS;
				vpd_page_inquiry_data_pkt->params[8] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_DEV_CHARS;

				alloc_len = 9U;

				if ( iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_UNMAP ) ) {
					vpd_page_inquiry_data_pkt->params[9] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_THIN_PROVISION;

					alloc_len++;
				}

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_UNIT_SERIAL_NUMBER : {
				const char *name = image->name;

				alloc_len = (uint) strlen( name );

				if ( alloc_len >= (len - sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet)) )
					alloc_len = (uint) ((len - sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet)) - 1U);

				memcpy( vpd_page_inquiry_data_pkt->params, name, alloc_len );
				memset( (vpd_page_inquiry_data_pkt->params + alloc_len), '\0', (len - alloc_len - sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet)) );

				alloc_len++;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_DEVICE_ID : {
				const uint dev_name_len  = (uint) (strlen( (char *) device->name ) + 1U);
				const uint port_name_len = (uint) (strlen( (char *) port->name ) + 1U);

				alloc_len  = (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet)); // 64-bit IEEE NAA Extended
				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet)); // T10 Vendor ID
				alloc_len += (uint) (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + ISCSI_ALIGN(dev_name_len, ISCSI_ALIGN_SIZE)); // SCSI Device Name
				alloc_len += (uint) (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + ISCSI_ALIGN(port_name_len, ISCSI_ALIGN_SIZE)); // SCSI Target Port Name
				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet)); // Relative Target Port
				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet)); // Target Port Group
				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet)); // Logical Unit Group

				if ( len < (alloc_len + sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet)) ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(device->protocol_id);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_NAA) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet);

				iscsi_scsi_emu_naa_ieee_ext_set( (uint64_t *) vpd_page_design_desc_inquiry_data_pkt->desc, (uint8_t *) image->name );

				alloc_len = (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + alloc_len);
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_ASCII) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(device->protocol_id);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_T10_VENDOR_ID) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet *vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->vendor_id, ISCSI_SCSI_STD_INQUIRY_DATA_DISK_VENDOR_ID, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->vendor_id), ' ' );
				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->product_id, image->name, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->product_id), ' ' );
				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->unit_serial_num, image->path, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->unit_serial_num), ' ' );

				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet)));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(device->protocol_id);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_DEVICE) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = (uint8_t) iscsi_scsi_emu_pad_scsi_name( vpd_page_design_desc_inquiry_data_pkt->desc, device->name );

				alloc_len += (uint) (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len);

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(device->protocol_id);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = (uint8_t) iscsi_scsi_emu_pad_scsi_name( vpd_page_design_desc_inquiry_data_pkt->desc, port->name );

				alloc_len += (uint) (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len);

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(device->protocol_id);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_REL_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet *vpd_page_design_desc_rel_target_port_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_rel_target_port_inquiry_data_pkt->reserved = 0U;
				iscsi_put_be16( (uint8_t *) &vpd_page_design_desc_rel_target_port_inquiry_data_pkt->index, port->index );

				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) +  (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet)));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(device->protocol_id);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_TARGET_PORT_GROUP) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet *vpd_page_design_desc_target_port_group_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_target_port_group_inquiry_data_pkt->reserved = 0U;
				vpd_page_design_desc_target_port_group_inquiry_data_pkt->index    = 0U;

				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) +  (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet)));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(device->protocol_id);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LOGICAL_UNIT_GROUP) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet *vpd_page_design_desc_logical_unit_group_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_logical_unit_group_inquiry_data_pkt->reserved = 0U;
				iscsi_put_be16( (uint8_t *) &vpd_page_design_desc_logical_unit_group_inquiry_data_pkt->id, (uint16_t) device->id );

				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet));

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_EXTENDED_INQUIRY_DATA : {
				iscsi_scsi_vpd_page_ext_inquiry_data_packet *vpd_page_ext_inquiry_data_pkt = (iscsi_scsi_vpd_page_ext_inquiry_data_packet *) vpd_page_inquiry_data_pkt;

				alloc_len = (sizeof(iscsi_scsi_vpd_page_ext_inquiry_data_packet) - sizeof(iscsi_scsi_vpd_page_inquiry_data_packet));

				if ( len < (alloc_len + sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet)) ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				vpd_page_ext_inquiry_data_pkt->reserved        = 0U;
				vpd_page_ext_inquiry_data_pkt->page_len        = (uint8_t) alloc_len;
				vpd_page_ext_inquiry_data_pkt->check_flags     = 0;
				vpd_page_ext_inquiry_data_pkt->support_flags   = (ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_SUPPORT_FLAGS_SIMPSUP | ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_SUPPORT_FLAGS_HEADSUP);
				vpd_page_ext_inquiry_data_pkt->support_flags_2 = 0;
				vpd_page_ext_inquiry_data_pkt->luiclr          = 0U;
				vpd_page_ext_inquiry_data_pkt->cbcs            = 0U;
				vpd_page_ext_inquiry_data_pkt->micro_dl        = 0U;
				vpd_page_ext_inquiry_data_pkt->reserved2[0]    = 0ULL;
				vpd_page_ext_inquiry_data_pkt->reserved2[1]    = 0ULL;
				vpd_page_ext_inquiry_data_pkt->reserved2[2]    = 0ULL;
				vpd_page_ext_inquiry_data_pkt->reserved2[3]    = 0ULL;
				vpd_page_ext_inquiry_data_pkt->reserved2[4]    = 0ULL;
				vpd_page_ext_inquiry_data_pkt->reserved2[5]    = 0ULL;
				vpd_page_ext_inquiry_data_pkt->reserved3       = 0UL;
				vpd_page_ext_inquiry_data_pkt->reserved4       = 0U;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_MANAGEMENT_NETWORK_ADDRS : {
				alloc_len = 0U;

				vpd_page_inquiry_data_pkt->alloc_len = 0U;

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_MODE_PAGE_POLICY : {
				iscsi_scsi_vpd_mode_page_policy_desc_inquiry_data_packet *vpd_page_mode_page_policy_desc_inquiry_data_pkt = (iscsi_scsi_vpd_mode_page_policy_desc_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				alloc_len = sizeof(struct iscsi_scsi_vpd_mode_page_policy_desc_inquiry_data_packet);

				vpd_page_mode_page_policy_desc_inquiry_data_pkt->page_code     = ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_MASK;
				vpd_page_mode_page_policy_desc_inquiry_data_pkt->sub_page_code = 0xFFU;
				vpd_page_mode_page_policy_desc_inquiry_data_pkt->flags         = 0U;
				vpd_page_mode_page_policy_desc_inquiry_data_pkt->reserved      = 0U;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SCSI_PORTS : {
				iscsi_scsi_emu_primary_inquiry_ports_fill port_report_fill = {(iscsi_scsi_vpd_scsi_port_design_dec_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params, 0U, (uint) (len - sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet))};
				const int rc = iscsi_hashmap_iterate( device->ports, iscsi_scsi_emu_primary_inquiry_callback, (uint8_t *) &port_report_fill );

				if ( rc < 0 ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				alloc_len = port_report_fill.alloc_len;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_LIMITS : {
				iscsi_scsi_vpd_page_block_limits_inquiry_data_packet *vpd_page_block_limits_inquiry_data_pkt = (iscsi_scsi_vpd_page_block_limits_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				if ( len < (sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_block_limits_inquiry_data_packet)) ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				alloc_len = sizeof(struct iscsi_scsi_vpd_page_block_limits_inquiry_data_packet);

				vpd_page_block_limits_inquiry_data_pkt->flags = 0;

				uint32_t blocks = (ISCSI_SCSI_EMU_MAX_XFER_LEN >> iscsi_scsi_emu_block_get_size_shift( image ));

				if ( blocks > 255UL )
					blocks = 255UL;

				vpd_page_block_limits_inquiry_data_pkt->max_cmp_write_len = (uint8_t) blocks;

				uint32_t optimal_blocks = ISCSI_SCSI_EMU_BLOCK_SIZE >> iscsi_scsi_emu_block_get_size_shift( image );

				if ( optimal_blocks == 0UL )
					optimal_blocks = 1UL;

				iscsi_put_be16( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->optimal_granularity_xfer_len, (uint16_t) optimal_blocks );
				iscsi_put_be32( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->max_xfer_len, blocks );
				iscsi_put_be32( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->optimal_xfer_len, blocks );
				vpd_page_block_limits_inquiry_data_pkt->max_prefetch_len = 0UL;

				if ( iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_UNMAP ) ) {
					iscsi_put_be32( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->max_unmap_lba_cnt, ISCSI_SCSI_EMU_MAX_UNMAP_LBA_COUNT );
					iscsi_put_be32( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->max_unmap_block_desc_cnt, ISCSI_SCSI_EMU_MAX_UNMAP_BLOCK_DESC_COUNT );
				} else {
					vpd_page_block_limits_inquiry_data_pkt->max_unmap_lba_cnt = 0UL;
					vpd_page_block_limits_inquiry_data_pkt->max_unmap_block_desc_cnt = 0UL;
				}

				vpd_page_block_limits_inquiry_data_pkt->optimal_unmap_granularity        = 0UL;
				vpd_page_block_limits_inquiry_data_pkt->unmap_granularity_align_ugavalid = 0UL;
				iscsi_put_be64( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->max_write_same_len, blocks );
				vpd_page_block_limits_inquiry_data_pkt->reserved[0]                      = 0ULL;
				vpd_page_block_limits_inquiry_data_pkt->reserved[1]                      = 0ULL;
				vpd_page_block_limits_inquiry_data_pkt->reserved2                        = 0UL;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_DEV_CHARS : {
				iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet *vpd_page_block_dev_chars_inquiry_data_pkt = (iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				if ( len < (sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet)) ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				alloc_len = sizeof(struct iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet);

				vpd_page_block_dev_chars_inquiry_data_pkt->medium_rotation_rate = (iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_NO_ROTATION ) ? ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_MEDIUM_ROTATION_RATE_NONE : ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_MEDIUM_ROTATION_RATE_NOT_REPORTED);
				vpd_page_block_dev_chars_inquiry_data_pkt->product_type         = ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_PRODUCT_TYPE_NOT_INDICATED;
				vpd_page_block_dev_chars_inquiry_data_pkt->flags                = ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_PUT_NOMINAL_FORM_FACTOR(ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_NOT_REPORTED);
				vpd_page_block_dev_chars_inquiry_data_pkt->support_flags        = 0U;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved[0]          = 0ULL;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved[1]          = 0ULL;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved[2]          = 0ULL;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved[3]          = 0ULL;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved[4]          = 0ULL;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved[5]          = 0ULL;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved2            = 0UL;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved3            = 0U;
				vpd_page_block_dev_chars_inquiry_data_pkt->reserved4            = 0U;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_THIN_PROVISION : {
				if ( !iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_UNMAP ) ) {
					scsi_task->xfer_pos = 0UL;

					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				iscsi_scsi_vpd_page_thin_provision_inquiry_data_packet *vpd_page_thin_provision_inquiry_data_pkt = (iscsi_scsi_vpd_page_thin_provision_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				alloc_len = sizeof(struct iscsi_scsi_vpd_page_thin_provision_inquiry_data_packet);

				vpd_page_thin_provision_inquiry_data_pkt->threshold_exponent = 0U;
				vpd_page_thin_provision_inquiry_data_pkt->flags              = (int8_t) ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_FLAGS_LBPU;
				vpd_page_thin_provision_inquiry_data_pkt->provision_type     = ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PUT_PROVISION_TYPE(ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_THIN_PROVISIONING);
				vpd_page_thin_provision_inquiry_data_pkt->reserved           = 0U;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			default : {
				scsi_task->xfer_pos = 0UL;

				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return -1;

				break;
			}
		}

		return (int) (alloc_len + sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet));
	} else {
		int32_t scsi_device_type = iscsi_config_get( (uint8_t *) image->name, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_DEVICE_TYPE );
		uint alloc_len;

		if ( scsi_device_type < 0L )
			scsi_device_type = iscsi_config_get( NULL, ISCSI_GLOBALS_CONFIG_TYPE_SCSI_DEVICE_TYPE );

		const uint8_t pti = ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_TYPE(scsi_device_type) | ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_ID(ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_POSSIBLE);

		std_inquiry_data_pkt->basic_inquiry.peripheral_type_id        = pti;
		std_inquiry_data_pkt->basic_inquiry.peripheral_type_mod_flags = (int8_t) (iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_REMOVABLE ) ? ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_FLAGS_REMOVABLE_MEDIA : 0);
		std_inquiry_data_pkt->basic_inquiry.version                   = ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_VERSION_ANSI(ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_SPC3);
		std_inquiry_data_pkt->basic_inquiry.response_data_fmt_flags   = ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_RESPONSE_DATA_FMT_FLAGS(ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_SCSI_2) | ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_HISUP;

		std_inquiry_data_pkt->tpgs_flags     = 0U;
		std_inquiry_data_pkt->services_flags = ISCSI_SCSI_STD_INQUIRY_DATA_SERVICES_FLAGS_MULTIP;
		std_inquiry_data_pkt->flags          = ISCSI_SCSI_STD_INQUIRY_DATA_FLAGS_COMMAND_QUEUE;

		iscsi_strcpy_pad( (char *) std_inquiry_data_pkt->vendor_id, ISCSI_SCSI_STD_INQUIRY_DATA_DISK_VENDOR_ID, sizeof(std_inquiry_data_pkt->vendor_id), ' ' );
		iscsi_strcpy_pad( (char *) std_inquiry_data_pkt->product_id, image->name, sizeof(std_inquiry_data_pkt->product_id), ' ' );

		char image_rev[sizeof(std_inquiry_data_pkt->product_rev_level) + 1];

		sprintf( image_rev, "%04" PRIX16, image->rid );
		iscsi_strcpy_pad( (char *) std_inquiry_data_pkt->product_rev_level, image_rev, sizeof(std_inquiry_data_pkt->product_rev_level), ' ' );

		uint add_len = (sizeof(struct iscsi_scsi_std_inquiry_data_packet) - sizeof(struct iscsi_scsi_basic_inquiry_data_packet));
		iscsi_scsi_ext_inquiry_data_packet *ext_inquiry_data_pkt = (iscsi_scsi_ext_inquiry_data_packet *) std_inquiry_data_pkt;

		if ( len >= ISCSI_NEXT_OFFSET(iscsi_scsi_ext_inquiry_data_packet, vendor_spec) ) {
			iscsi_strcpy_pad( (char *) ext_inquiry_data_pkt->vendor_spec, ISCSI_SCSI_EXT_INQUIRY_DATA_VENDOR_SPEC_ID, sizeof(ext_inquiry_data_pkt->vendor_spec), ' ' );

			add_len += sizeof(ext_inquiry_data_pkt->vendor_spec);
		}

		if ( len >= ISCSI_NEXT_OFFSET(iscsi_scsi_ext_inquiry_data_packet, flags) ) {
			ext_inquiry_data_pkt->flags = 0;

			add_len += sizeof(ext_inquiry_data_pkt->flags);
		}

		if ( len >= ISCSI_NEXT_OFFSET(iscsi_scsi_ext_inquiry_data_packet, reserved) ) {
			ext_inquiry_data_pkt->reserved = 0U;

			add_len += sizeof(ext_inquiry_data_pkt->reserved);
		}

		if ( len >= ISCSI_NEXT_OFFSET(iscsi_scsi_ext_inquiry_data_packet, version_desc[0]) ) {
			iscsi_put_be16( (uint8_t *) &ext_inquiry_data_pkt->version_desc[0], ISCSI_SCSI_EXT_INQUIRY_DATA_VERSION_DESC_ISCSI_NO_VERSION );

			add_len += sizeof(ext_inquiry_data_pkt->version_desc[0]);
		}

		if ( len >= ISCSI_NEXT_OFFSET(iscsi_scsi_ext_inquiry_data_packet, version_desc[1]) ) {
			iscsi_put_be16( (uint8_t *) &ext_inquiry_data_pkt->version_desc[1], ISCSI_SCSI_EXT_INQUIRY_DATA_VERSION_DESC_SPC3_NO_VERSION );

			add_len += sizeof(ext_inquiry_data_pkt->version_desc[1]);
		}

		if ( len >= ISCSI_NEXT_OFFSET(iscsi_scsi_ext_inquiry_data_packet, version_desc[2]) ) {
			iscsi_put_be16( (uint8_t *) &ext_inquiry_data_pkt->version_desc[2], ISCSI_SCSI_EXT_INQUIRY_DATA_VERSION_DESC_SBC2_NO_VERSION );

			add_len += sizeof(ext_inquiry_data_pkt->version_desc[2]);
		}

		if ( len >= ISCSI_NEXT_OFFSET(iscsi_scsi_ext_inquiry_data_packet, version_desc[3]) ) {
			iscsi_put_be16( (uint8_t *) &ext_inquiry_data_pkt->version_desc[3], ISCSI_SCSI_EXT_INQUIRY_DATA_VERSION_DESC_SAM2_NO_VERSION );

			add_len += sizeof(ext_inquiry_data_pkt->version_desc[3]);
		}

		if ( len >= ISCSI_NEXT_OFFSET(iscsi_scsi_ext_inquiry_data_packet, version_desc[4]) ) {
			uint alloc_len = (uint) (len - offsetof(iscsi_scsi_ext_inquiry_data_packet, version_desc[4]));

			if ( alloc_len > (sizeof(struct iscsi_scsi_ext_inquiry_data_packet) - offsetof(iscsi_scsi_ext_inquiry_data_packet, version_desc[4])) )
				alloc_len = (sizeof(struct iscsi_scsi_ext_inquiry_data_packet) - offsetof(iscsi_scsi_ext_inquiry_data_packet, version_desc[4]));

			memset( &ext_inquiry_data_pkt->version_desc[4], 0, alloc_len );
			add_len += alloc_len;
		}

		std_inquiry_data_pkt->basic_inquiry.add_len = (uint8_t) add_len;

		return (int) (add_len + sizeof(struct iscsi_scsi_basic_inquiry_data_packet));
	}
}

/**
 * @brief Fills in a single LUN entry of a report LUNs operation on a DNBD3 image.
 *
 * Callback function for each element while iterating
 * through the iSCSI SCSI LUNs hash map.\n
 * The iteration process is aborted when the
 * remaining allocation length is not enough
 * to hold the current LUN.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL creates an
 * empty key assignment.
 * @param[in,out] user_data Pointer to a data structure
 * containing the report LUN list, the
 * current report LUN entry, the total
 * length of all LUN entries in bytes, the
 * remaining allocation length in bytes and
 * the selected report. May NOT be NULL, so
 * be careful.
 * @retval -1 Operation failure, ran out of
 * allocation space during traversal.
 * @retval 0 Successful operation, there is enough
 * allocation space to store this
 * reported LUN entry.
 */
int iscsi_scsi_emu_primary_report_luns_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_scsi_emu_primary_report_luns_fill *lun_report_fill = (iscsi_scsi_emu_primary_report_luns_fill *) user_data;
	iscsi_scsi_lun *scsi_lun = (iscsi_scsi_lun *) value;

	lun_report_fill->alloc_len -= (uint) sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_entry_packet);

	if ( (int) lun_report_fill->alloc_len < 0 )
		return -1;

	lun_report_fill->len += (uint) sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_entry_packet);

	const uint64_t lun = iscsi_scsi_lun_get_from_scsi( scsi_lun->id );
	iscsi_put_be64( (uint8_t *) &lun_report_fill->lun_entry->lun, lun );

	lun_report_fill->lun_entry++;

	return 0;
}

/**
 * @brief Executes a report LUNs operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] lun Pointer to iSCSI SCSI LUN to
 * report the LUNs for. May NOT be
 * NULL, so be careful.
 * @param[in] report_luns_parameter_data_pkt Pointer to report LUNS
 * parameter data packet to fill the
 * LUN data data with.
 * @param[in] len Length of LUN reporting result buffer
 * in bytes.
 * @param[in] select_report Selected report.
 * @return Total length of LUN data on successful
 * operation, a negative error code
 * otherwise.
 */
static int iscsi_scsi_emu_primary_report_luns(iscsi_scsi_lun *lun, iscsi_scsi_report_luns_parameter_data_lun_list_packet *report_luns_parameter_data_pkt, const uint len, const uint select_report)
{
	if ( len < sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_list_packet) )
		return -1;

	switch ( select_report ) {
		case ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_ADDR_METHOD : {
			break;
		}
		case ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_KNOWN : {
			break;
		}
		case ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_ALL : {
			break;
		}
		default : {
			return -1;

			break;
		}
	}

	report_luns_parameter_data_pkt->lun_list_len = 0UL;
	report_luns_parameter_data_pkt->reserved     = 0UL;

	iscsi_scsi_emu_primary_report_luns_fill lun_report_fill = {report_luns_parameter_data_pkt, (iscsi_scsi_report_luns_parameter_data_lun_entry_packet *) (report_luns_parameter_data_pkt + 1), 0U, (uint) (len - sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_list_packet)), select_report };

	pthread_rwlock_rdlock( &lun->device->luns_rwlock );

	const int rc = iscsi_hashmap_iterate( lun->device->luns, iscsi_scsi_emu_primary_report_luns_callback, (uint8_t *) &lun_report_fill );

	pthread_rwlock_unlock( &lun->device->luns_rwlock );

	if ( rc < 0 )
		return -1;

	iscsi_put_be32( (uint8_t *) &report_luns_parameter_data_pkt->lun_list_len, lun_report_fill.len );

	return (int) (lun_report_fill.len + sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_list_packet));
}

/**
 * @brief Initializes a mode sense page or sub page and zero fills the parameter data.
 *
 * This function also sets the correct
 * page length and flags either for
 * the page or sub page. If a sub page
 * is initialized, the sub page code
 * will also be set.
 *
 * @param[in] mode_sense_mode_page_pkt Pointer to mode sense parameter
 * mode page or sub page data packet
 * to initialize. If this is NULL,
 * this function does nothing.
 * @param[in] len Length in bytes to initialize with zeroes.
 * @param[in] page Page code.
 * @param[in] sub_page Sub page code.
 */
static void iscsi_scsi_emu_primary_mode_sense_page_init(iscsi_scsi_mode_sense_mode_page_data_packet *mode_sense_mode_page_pkt, const uint len, const uint page, const uint sub_page)
{
	if ( mode_sense_mode_page_pkt == NULL )
		return;

	if ( sub_page == 0U ) {
		mode_sense_mode_page_pkt->page_code_flags = (uint8_t) ISCSI_SCSI_MODE_SENSE_MODE_PAGE_PUT_PAGE_CODE(page);
		mode_sense_mode_page_pkt->page_len        = (uint8_t) (len - sizeof(struct iscsi_scsi_mode_sense_mode_page_data_packet));

		memset( mode_sense_mode_page_pkt->params, 0, (len - offsetof(struct iscsi_scsi_mode_sense_mode_page_data_packet, params)) );
	} else {
		iscsi_scsi_mode_sense_mode_sub_page_data_packet *mode_sense_mode_sub_page_pkt = (iscsi_scsi_mode_sense_mode_sub_page_data_packet *) mode_sense_mode_page_pkt;

		mode_sense_mode_sub_page_pkt->page_code_flags = (uint8_t) (ISCSI_SCSI_MODE_SENSE_MODE_PAGE_PUT_PAGE_CODE(page) | ISCSI_SCSI_MODE_SENSE_MODE_PAGE_FLAGS_SPF);
		mode_sense_mode_sub_page_pkt->sub_page_code   = (uint8_t) sub_page;
		iscsi_put_be16( (uint8_t *) &mode_sense_mode_sub_page_pkt->page_len, (uint16_t) (len - sizeof(struct iscsi_scsi_mode_sense_mode_sub_page_data_packet)) );

		memset( mode_sense_mode_sub_page_pkt->params, 0, (len - offsetof(struct iscsi_scsi_mode_sense_mode_sub_page_data_packet, params)) );
	}
}

/**
 * @brief Handles a specific mode sense page or sub page.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to get
 * the mode sense data from. May NOT be
 * NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this mode sense
 * task. NULL is NOT allowed here,
 * take caution.
 * @param[in] mode_sense_mode_page_pkt Pointer to mode sense parameter
 * mode page or sub page data packet
 * to process. If this is NULL, only
 * the length of page is calculated.
 * @param[in] pc Page control (PC).
 * @param[in] page Page code.
 * @param[in] sub_page Sub page code.
 * @return Number of bytes occupied or a
 * negative error code otherwise.
 */
static int iscsi_scsi_emu_primary_mode_sense_page(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, iscsi_scsi_mode_sense_mode_page_data_packet *mode_sense_mode_page_pkt, const uint pc, const uint page, const uint sub_page)
{
	uint page_len;
	int len = 0;

	switch ( pc ) {
		case ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_CURRENT_VALUES :
		case ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_CHG_VALUES :
		case ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_DEFAULT_VALUES : {
			break;
		}
		default : {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_SAVING_PARAMETERS_NOT_SUPPORTED, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			return -1;

			break;
		}
	}

	switch ( page ) {
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_FORMAT_DEVICE :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RIGID_DISK_GEOMETRY :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RIGID_DISK_GEOMETRY_2 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_OBSELETE :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_MEDIUM_TYPES_SUPPORTED :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_NOTCH_AND_PARTITION :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_OBSELETE_2 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_2 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_3 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_4 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_5 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_6 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_ENCLOSURE_SERVICES_MGMT :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_7 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_8 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_9 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_PROTOCOL_SPEC_LUN :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_PROTOCOL_SPEC_PORT :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_10 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_11 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_12 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_13 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_2 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_3 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_4 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_5 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_6 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_7 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_8 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_9 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_10 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_11 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_12 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_13 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_14 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_15 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_16 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_17 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_18 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_19 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_20 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_21 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_22 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_23 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_24 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_25 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_26 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_27 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_28 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_29 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_30 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_31 :
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_32 : {
			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_READ_WRITE_ERR_RECOVERY : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(struct iscsi_scsi_mode_sense_read_write_err_recovery_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_DISCONNECT_RECONNECT : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(struct iscsi_scsi_mode_sense_disconnect_reconnect_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VERIFY_ERR_RECOVERY : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(struct iscsi_scsi_mode_sense_verify_err_recovery_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_CACHING : {
			if ( sub_page != 0U )
				break;

			iscsi_scsi_mode_sense_caching_mode_page_data_packet *mode_sense_caching_mode_page_pkt = (iscsi_scsi_mode_sense_caching_mode_page_data_packet *) mode_sense_mode_page_pkt;

			page_len = sizeof(struct iscsi_scsi_mode_sense_caching_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

			if ( (mode_sense_mode_page_pkt != NULL) && iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_WRITE_CACHE ) && (pc != ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_CHG_VALUES) )
				mode_sense_caching_mode_page_pkt->flags |= ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_WCE;

			if ( (mode_sense_mode_page_pkt != NULL) && (pc != ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_CHG_VALUES) )
				mode_sense_caching_mode_page_pkt->flags |= ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_RCD;

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_CONTROL : {
			switch ( sub_page ) {
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL : {
					page_len = sizeof(struct iscsi_scsi_mode_sense_control_mode_page_data_packet);

					iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

					len += page_len;

					break;
				}
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL_EXT : {
					/* Control Extension */

					page_len = sizeof(struct iscsi_scsi_mode_sense_control_ext_mode_page_data_packet);

					iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

					len += page_len;

					break;
				}
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL_ALL : {
					len += iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((mode_sense_mode_page_pkt != NULL) ? (iscsi_scsi_mode_sense_mode_page_data_packet *) (((uint8_t *) mode_sense_mode_page_pkt) + len) : NULL), pc, page, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL );
					len += iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((mode_sense_mode_page_pkt != NULL) ? (iscsi_scsi_mode_sense_mode_page_data_packet *) (((uint8_t *) mode_sense_mode_page_pkt) + len) : NULL), pc, page, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL_EXT );

					break;
				}
				default : {
					break;
				}
			}

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_XOR_CONTROL : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(struct iscsi_scsi_mode_sense_xor_ext_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_POWER_COND : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(struct iscsi_scsi_mode_sense_power_cond_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_INFO_EXCEPTIOS_CONTROL : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(struct iscsi_scsi_mode_sense_info_exceptions_control_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( mode_sense_mode_page_pkt, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES : {
			uint i;

			switch ( sub_page ) {
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_PAGES : {
					for ( i = ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC; i < ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES; i++ ) {
						len += iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((mode_sense_mode_page_pkt != NULL) ? (iscsi_scsi_mode_sense_mode_page_data_packet *) (((uint8_t *) mode_sense_mode_page_pkt) + len) : NULL), pc, i, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_PAGES );
					}

					break;
				}
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_SUB_PAGES : {
					for ( i = ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC; i < ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES; i++ ) {
						len += iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((mode_sense_mode_page_pkt != NULL) ? (iscsi_scsi_mode_sense_mode_page_data_packet *) (((uint8_t *) mode_sense_mode_page_pkt) + len) : NULL), pc, i, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_PAGES );
					}

					for ( i = ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC; i < ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES; i++ ) {
						len += iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((mode_sense_mode_page_pkt != NULL) ? (iscsi_scsi_mode_sense_mode_page_data_packet *) (((uint8_t *) mode_sense_mode_page_pkt) + len) : NULL), pc, i, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_SUB_PAGES );
					}

					break;
				}
				default : {
					break;
				}
			}

			break;
		}
		default : {
			break;
		}
	}

	return len;
}

/**
 * @brief Executes a mode sense operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to get
 * the mode sense data from. May
 * NOT be NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this mode sense
 * task. NULL is NOT allowed here,
 * take caution.
 * @param[in] mode_sense_6_parameter_hdr_data_pkt Pointer to mode sense parameter
 * header data packet to fill the
 * mode sense data with. If this is
 * NULL, only the length of sense
 * data is calculated.
 * @param[in] hdr_len Length of parameter header in bytes.
 * @param[in] block_desc_len Length of LBA parameter block
 * descriptor in bytes.
 * @param[in] long_lba Long Logical Block Address (LONG_LBA) bit.
 * @param[in] pc Page control (PC).
 * @param[in] page_code Page code.
 * @param[in] sub_page_code Sub page code.
 * @return Total length of sense data on successful
 * operation, a negative error code
 * otherwise.
 */
static int iscsi_scsi_emu_primary_mode_sense(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, iscsi_scsi_mode_sense_6_parameter_header_data_packet *mode_sense_6_parameter_hdr_data_pkt, const uint hdr_len, const uint block_desc_len, const uint long_lba, const uint pc, const uint page_code, const uint sub_page_code)
{
	iscsi_scsi_mode_sense_mode_page_data_packet *mode_sense_mode_page_pkt = (iscsi_scsi_mode_sense_mode_page_data_packet *) ((mode_sense_6_parameter_hdr_data_pkt != NULL) ? (((uint8_t *) mode_sense_6_parameter_hdr_data_pkt) + hdr_len + block_desc_len) : NULL);
	const int page_len = iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, mode_sense_mode_page_pkt, pc, page_code, sub_page_code );

	if ( page_len < 0 )
		return -1;

	const uint alloc_len = (hdr_len + block_desc_len + page_len);

	if ( mode_sense_6_parameter_hdr_data_pkt == NULL )
		return alloc_len;

	if ( hdr_len == sizeof(struct iscsi_scsi_mode_sense_6_parameter_header_data_packet) ) {
		mode_sense_6_parameter_hdr_data_pkt->mode_data_len  = (uint8_t) (alloc_len - sizeof(uint8_t));
		mode_sense_6_parameter_hdr_data_pkt->medium_type    = 0U;
		mode_sense_6_parameter_hdr_data_pkt->flags          = (int8_t) ((iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_PHYSICAL_READ_ONLY ) || iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_WRITE_PROTECT )) ? ISCSI_SCSI_MODE_SENSE_6_PARAM_HDR_DATA_FLAGS_WP : 0);
		mode_sense_6_parameter_hdr_data_pkt->block_desc_len = (uint8_t) block_desc_len;
	} else {
		iscsi_scsi_mode_sense_10_parameter_header_data_packet *mode_sense_10_parameter_hdr_data_pkt = (iscsi_scsi_mode_sense_10_parameter_header_data_packet *) mode_sense_6_parameter_hdr_data_pkt;

		iscsi_put_be16( (uint8_t *) &mode_sense_10_parameter_hdr_data_pkt->mode_data_len, (uint16_t) (alloc_len - sizeof(uint16_t)) );
		mode_sense_10_parameter_hdr_data_pkt->medium_type    = 0U;
		mode_sense_10_parameter_hdr_data_pkt->flags          = (int8_t) ((iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_PHYSICAL_READ_ONLY ) || iscsi_scsi_emu_io_type_is_supported( image, ISCSI_SCSI_EMU_IO_TYPE_WRITE_PROTECT )) ? ISCSI_SCSI_MODE_SENSE_10_PARAM_HDR_DATA_FLAGS_WP : 0);
		mode_sense_10_parameter_hdr_data_pkt->long_lba       = (uint8_t) long_lba;
		mode_sense_10_parameter_hdr_data_pkt->reserved       = 0U;
		iscsi_put_be16( (uint8_t *) &mode_sense_10_parameter_hdr_data_pkt->block_desc_len, (uint16_t) block_desc_len );
	}

	const uint64_t num_blocks = iscsi_scsi_emu_block_get_count( image );
	const uint32_t block_size = iscsi_scsi_emu_block_get_size( image );

	if ( block_desc_len == sizeof(struct iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet) ) {
		iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet *lba_parameter_block_desc = (iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet *) (((uint8_t *) mode_sense_6_parameter_hdr_data_pkt) + hdr_len);

		if ( num_blocks > 0xFFFFFFFFULL )
			lba_parameter_block_desc->num_blocks = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
		else
			iscsi_put_be32( (uint8_t *) &lba_parameter_block_desc->num_blocks, (uint32_t) num_blocks );

		lba_parameter_block_desc->reserved = 0U;
		iscsi_put_be24( (uint8_t *) &lba_parameter_block_desc->block_len, block_size );
	} else if ( block_desc_len == sizeof(struct iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet) ) {
		iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet *long_lba_parameter_block_desc = (iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet *) (((uint8_t *) mode_sense_6_parameter_hdr_data_pkt) + hdr_len);

		iscsi_put_be64( (uint8_t *) &long_lba_parameter_block_desc->num_blocks, num_blocks );
		long_lba_parameter_block_desc->reserved = 0UL;
		iscsi_put_be32( (uint8_t *) &long_lba_parameter_block_desc->block_len, block_size );
	}

	return alloc_len;
}

/**
 * @brief Executes SCSI non-block emulation on a DNBD3 image.
 *
 * This function determines the
 * non-block based SCSI opcode and
 * executes it.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * to process the SCSI non-block
 * operation for and may NOT be NULL,
 * be careful.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_primary_process(iscsi_scsi_task *scsi_task)
{
	iscsi_scsi_lun *lun = scsi_task->lun;
	uint alloc_len;
	uint len;
	int rc;

	switch ( scsi_task->cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_INQUIRY : {
			const iscsi_scsi_cdb_inquiry *cdb_inquiry = (iscsi_scsi_cdb_inquiry *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			alloc_len = iscsi_get_be16(cdb_inquiry->alloc_len);
			len       = alloc_len;

			if ( len < ISCSI_DEFAULT_RECV_DS_LEN )
				len = ISCSI_DEFAULT_RECV_DS_LEN;

			iscsi_scsi_std_inquiry_data_packet *std_inquiry_data_pkt = NULL;

			if ( len > 0U ) {
				std_inquiry_data_pkt = (iscsi_scsi_std_inquiry_data_packet *) malloc( len );

				if ( std_inquiry_data_pkt == NULL ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

					break;
				}
			}

			rc = iscsi_scsi_emu_primary_inquiry( lun->image, scsi_task, cdb_inquiry, std_inquiry_data_pkt, len );

			if ( (rc >= 0) && (len > 0U) ) {
				if ( len > alloc_len )
					len = alloc_len;

				scsi_task->buf = (uint8_t *) std_inquiry_data_pkt;

				if ( rc < (int) len )
					memset( (((uint8_t *) std_inquiry_data_pkt) + rc), 0, (len - rc) );

				rc = len;
			}

			if ( rc >= 0 ) {
				scsi_task->xfer_pos = rc;
				scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_REPORTLUNS : {
			const iscsi_scsi_cdb_report_luns *cdb_report_luns = (iscsi_scsi_cdb_report_luns *) scsi_task->cdb;

			alloc_len = iscsi_get_be32(cdb_report_luns->alloc_len);
			rc        = iscsi_scsi_emu_check_len( scsi_task, alloc_len, (sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_list_packet) + sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_entry_packet)) );

			if ( rc < 0 )
				break;

			len = alloc_len;

			if ( len < ISCSI_DEFAULT_RECV_DS_LEN )
				len = ISCSI_DEFAULT_RECV_DS_LEN;

			iscsi_scsi_report_luns_parameter_data_lun_list_packet *report_luns_parameter_data_pkt = NULL;

			if ( len > 0U ) {
				report_luns_parameter_data_pkt = (iscsi_scsi_report_luns_parameter_data_lun_list_packet *) malloc( len );

				if ( report_luns_parameter_data_pkt == NULL ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

					break;
				}
			}

			rc = iscsi_scsi_emu_primary_report_luns( lun, report_luns_parameter_data_pkt, len, cdb_report_luns->select_report );

			if ( rc < 0 ) {
				free( report_luns_parameter_data_pkt );
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				break;
			}

			len = rc;

			if ( len > 0U ) {
				if ( len > alloc_len )
					len = alloc_len;

				scsi_task->buf = (uint8_t *) report_luns_parameter_data_pkt;
			}

			scsi_task->xfer_pos = len;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_MODESELECT6 : {
			const iscsi_scsi_cdb_mode_select_6 *cdb_mode_select_6 = (iscsi_scsi_cdb_mode_select_6 *) scsi_task->cdb;

			alloc_len = cdb_mode_select_6->param_list_len;

			if ( alloc_len == 0U )
				break;

			rc = iscsi_scsi_emu_check_len( scsi_task, alloc_len, sizeof(struct iscsi_scsi_mode_select_6_parameter_list_packet) );

			if ( rc < 0 )
				break;

			len = scsi_task->len;

			if ( alloc_len < sizeof(struct iscsi_scsi_mode_select_6_parameter_list_packet) )
				alloc_len = sizeof(struct iscsi_scsi_mode_select_6_parameter_list_packet);

			rc = iscsi_scsi_emu_check_len( scsi_task, len, alloc_len );

			if ( rc < 0 )
				break;

			scsi_task->xfer_pos = alloc_len;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_MODESELECT10 : {
			const iscsi_scsi_cdb_mode_select_10 *cdb_mode_select_10 = (iscsi_scsi_cdb_mode_select_10 *) scsi_task->cdb;

			alloc_len = iscsi_get_be16(cdb_mode_select_10->param_list_len);

			if ( alloc_len == 0U )
				break;

			rc = iscsi_scsi_emu_check_len( scsi_task, alloc_len, sizeof(struct iscsi_scsi_mode_select_10_parameter_list_packet) );

			if ( rc < 0 )
				break;

			len = scsi_task->len;

			if ( alloc_len < sizeof(struct iscsi_scsi_mode_select_10_parameter_list_packet) )
				alloc_len = sizeof(struct iscsi_scsi_mode_select_10_parameter_list_packet);

			rc = iscsi_scsi_emu_check_len( scsi_task, len, alloc_len );

			if ( rc < 0 )
				break;

			scsi_task->xfer_pos = alloc_len;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_MODESENSE6 : {
			const iscsi_scsi_cdb_mode_sense_6 *cdb_mode_sense_6 = (iscsi_scsi_cdb_mode_sense_6 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			alloc_len = cdb_mode_sense_6->alloc_len;

			const uint block_desc_len = (((cdb_mode_sense_6->flags & ISCSI_SCSI_CDB_MODE_SENSE_6_FLAGS_DBD) == 0) ? sizeof(struct iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet) : 0U);
			const uint pc             = ISCSI_SCSI_CDB_MODE_SENSE_6_GET_PAGE_CONTROL(cdb_mode_sense_6->page_code_control);
			const uint page           = ISCSI_SCSI_CDB_MODE_SENSE_6_GET_PAGE_CODE(cdb_mode_sense_6->page_code_control);
			const uint sub_page       = cdb_mode_sense_6->sub_page_code;

			rc = iscsi_scsi_emu_primary_mode_sense( lun->image, scsi_task, NULL, sizeof(struct iscsi_scsi_mode_sense_6_parameter_header_data_packet), block_desc_len, 0U, pc, page, sub_page );

			if ( rc < 0 )
				break;

			len = rc;

			iscsi_scsi_mode_sense_6_parameter_header_data_packet *mode_sense_6_parameter_hdr_data_pkt = (iscsi_scsi_mode_sense_6_parameter_header_data_packet *) malloc( len );

			if ( mode_sense_6_parameter_hdr_data_pkt == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_emu_primary_mode_sense( lun->image, scsi_task, mode_sense_6_parameter_hdr_data_pkt, sizeof(struct iscsi_scsi_mode_sense_6_parameter_header_data_packet), block_desc_len, 0U, pc, page, sub_page );

			if ( rc < 0 ) {
				free( mode_sense_6_parameter_hdr_data_pkt );
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				break;
			}

			if ( (rc >= 0) && (len > 0U) ) {
				if ( len > alloc_len )
					len = alloc_len;

				scsi_task->buf = (uint8_t *) mode_sense_6_parameter_hdr_data_pkt;
				rc             = len;
			}

			if ( rc >= 0 ) {
				scsi_task->xfer_pos = rc;
				scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_MODESENSE10 : {
			const iscsi_scsi_cdb_mode_sense_10 *cdb_mode_sense_10 = (iscsi_scsi_cdb_mode_sense_10 *) scsi_task->cdb;

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			alloc_len = iscsi_get_be16(cdb_mode_sense_10->alloc_len);

			const uint long_lba       = (((cdb_mode_sense_10->flags & ISCSI_SCSI_CDB_MODE_SENSE_10_FLAGS_LLBAA) != 0) ? ISCSI_SCSI_MODE_SENSE_10_PARAM_HDR_DATA_LONGLBA : 0U);
			const uint block_desc_len = (((cdb_mode_sense_10->flags & ISCSI_SCSI_CDB_MODE_SENSE_10_FLAGS_DBD) == 0) ? ((long_lba != 0) ? sizeof(struct iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet) : sizeof(struct iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet)) : 0U);
			const uint pc10           = ISCSI_SCSI_CDB_MODE_SENSE_10_GET_PAGE_CONTROL(cdb_mode_sense_10->page_code_control);
			const uint page10         = ISCSI_SCSI_CDB_MODE_SENSE_10_GET_PAGE_CODE(cdb_mode_sense_10->page_code_control);
			const uint sub_page10     = cdb_mode_sense_10->sub_page_code;

			rc = iscsi_scsi_emu_primary_mode_sense( lun->image, scsi_task, NULL, sizeof(struct iscsi_scsi_mode_sense_10_parameter_header_data_packet), block_desc_len, long_lba, pc10, page10, sub_page10 );

			if ( rc < 0 )
				break;

			len = rc;

			iscsi_scsi_mode_sense_10_parameter_header_data_packet *mode_sense_10_parameter_hdr_data_pkt = (iscsi_scsi_mode_sense_10_parameter_header_data_packet *) malloc( len );

			if ( mode_sense_10_parameter_hdr_data_pkt == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_emu_primary_mode_sense( lun->image, scsi_task, (iscsi_scsi_mode_sense_6_parameter_header_data_packet *) mode_sense_10_parameter_hdr_data_pkt, sizeof(struct iscsi_scsi_mode_sense_10_parameter_header_data_packet), block_desc_len, long_lba, pc10, page10, sub_page10 );

			if ( rc < 0 ) {
				free( mode_sense_10_parameter_hdr_data_pkt );
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				break;
			}

			if ( (rc >= 0) && (len > 0U) ) {
				if ( len > alloc_len )
					len = alloc_len;

				scsi_task->buf = (uint8_t *) mode_sense_10_parameter_hdr_data_pkt;
				rc             = len;
			}

			if ( rc >= 0 ) {
				scsi_task->xfer_pos = rc;
				scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_REQUESTSENSE : {
			const iscsi_scsi_cdb_req_sense *cdb_req_sense = (iscsi_scsi_cdb_req_sense *) scsi_task->cdb;

			if ( (cdb_req_sense->flags & ISCSI_SCSI_CDB_REQ_SENSE_FLAGS_DESC) != 0 ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				break;
			}

			alloc_len = cdb_req_sense->alloc_len;

			iscsi_scsi_task_sense_data_build( scsi_task, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			len = scsi_task->sense_data_len;

			if ( len > 0U ) {
				iscsi_scsi_sense_data_check_cond_packet *sense_data = (iscsi_scsi_sense_data_check_cond_packet *) malloc( len );

				if ( sense_data == NULL ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

					break;
				}

				memcpy( sense_data, scsi_task->sense_data, len );

				if ( len > alloc_len )
					len = alloc_len;

				scsi_task->buf = (uint8_t *) sense_data;
			}

			scsi_task->xfer_pos = len;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_LOGSELECT :
		case ISCSI_SCSI_OPCODE_LOGSENSE : {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_COMMAND_OPERATION_CODE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			break;
		}
		case ISCSI_SCSI_OPCODE_TESTUNITREADY : {
			if ( !iscsi_scsi_emu_image_init( scsi_task, false ) )
				break;

			scsi_task->xfer_pos = 0UL;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_STARTSTOPUNIT : {
			// TODO: Handle eject image and power saving (suspend and standby) modes.

			if ( !iscsi_scsi_emu_image_init( scsi_task, true ) )
				break;

			scsi_task->xfer_pos = 0UL;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_PERSISTENT_RESERVE_OUT : {
			const iscsi_scsi_cdb_pr_reserve_out *cdb_pr_reserve_out = (iscsi_scsi_cdb_pr_reserve_out *) scsi_task->cdb;

			alloc_len = iscsi_get_be32(cdb_pr_reserve_out->param_list_len);
			rc        = iscsi_scsi_emu_check_len( scsi_task, alloc_len, sizeof(struct iscsi_scsi_pr_reserve_out_parameter_list_packet) );

			if ( rc < 0 )
				break;

			len = scsi_task->len;

			iscsi_scsi_pr_reserve_out_parameter_list_packet *pr_reserve_out_parameter_list = (iscsi_scsi_pr_reserve_out_parameter_list_packet *) malloc( len );

			if ( pr_reserve_out_parameter_list == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			if ( len < sizeof(struct iscsi_scsi_pr_reserve_out_parameter_list_packet) ) {
				free( pr_reserve_out_parameter_list );

				break;
			}

			rc = iscsi_scsi_pr_out( scsi_task, pr_reserve_out_parameter_list, cdb_pr_reserve_out, len );

			if ( rc < 0 ) {
				free( pr_reserve_out_parameter_list );

				break;
			}

			scsi_task->xfer_pos = alloc_len;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			free( pr_reserve_out_parameter_list );

			break;
		}
		case ISCSI_SCSI_OPCODE_PERSISTENT_RESERVE_IN : {
			const iscsi_scsi_cdb_pr_reserve_in *cdb_pr_reserve_in = (iscsi_scsi_cdb_pr_reserve_in *) scsi_task->cdb;

			alloc_len = iscsi_get_be16(cdb_pr_reserve_in->param_list_len);
			len       = alloc_len;

			iscsi_scsi_pr_reserve_in_parameter_data_packet *pr_reserve_in_parameter_data = (iscsi_scsi_pr_reserve_in_parameter_data_packet *) malloc( len );

			if ( pr_reserve_in_parameter_data == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_pr_in( scsi_task, pr_reserve_in_parameter_data, cdb_pr_reserve_in, len );

			if ( (rc >= 0) && (len > 0U) ) {
				if ( len > alloc_len )
					len = alloc_len;

				scsi_task->buf = (uint8_t *) pr_reserve_in_parameter_data;
				rc             = len;
			}

			if ( rc >= 0 ) {
				scsi_task->xfer_pos = rc;
				scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_RESERVE6 : {
			const iscsi_scsi_cdb_pr_reserve_6 *cdb_pr_reserve_6 = (iscsi_scsi_cdb_pr_reserve_6 *) scsi_task->cdb;

			rc = iscsi_scsi_pr_reserve_scsi2( scsi_task, cdb_pr_reserve_6 );

			if ( rc >= 0 ) {
				scsi_task->xfer_pos = rc;
				scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_RESERVE10 : {
			const iscsi_scsi_cdb_pr_reserve_10 *cdb_pr_reserve_10 = (iscsi_scsi_cdb_pr_reserve_10 *) scsi_task->cdb;

			rc = iscsi_scsi_pr_reserve_scsi2( scsi_task, (iscsi_scsi_cdb_pr_reserve_6 *) cdb_pr_reserve_10 );
			rc = iscsi_get_be16(cdb_pr_reserve_10->param_list_len);

			if ( rc >= 0 ) {
				scsi_task->xfer_pos = rc;
				scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_RELEASE6 :
		case ISCSI_SCSI_OPCODE_RELEASE10 : {
			rc = iscsi_scsi_pr_release_scsi2( scsi_task );

			if ( rc >= 0 ) {
				scsi_task->xfer_pos = rc;
				scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;
			}

			break;
		}
		default : {
			return ISCSI_SCSI_TASK_RUN_UNKNOWN;

			break;
		}
	}

	return ISCSI_SCSI_TASK_RUN_COMPLETE;
}

/**
 * @brief Executes the iSCSI SCSI emulation for an iSCSI SCSI task.
 *
 * This function also handles all SCSI emulation
 * tasks for DNBD3 image mapping.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task for which
 * SCSI should be emulated and may NOT be NULL,
 * so be careful.
 * @return 0 on successful SCSI emulation or a
 * negative error code otherwise.
 */
int iscsi_scsi_emu_exec(iscsi_scsi_task *scsi_task)
{
	int rc = iscsi_scsi_emu_block_process( scsi_task );

	if ( rc == ISCSI_SCSI_TASK_RUN_UNKNOWN ) {
		rc = iscsi_scsi_emu_primary_process( scsi_task );

		if ( rc == ISCSI_SCSI_TASK_RUN_UNKNOWN ) {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_COMMAND_OPERATION_CODE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			return ISCSI_SCSI_TASK_RUN_COMPLETE;
		}
	}

	return rc;
}

/**
 * @brief Allocates and initializes an iSCSI port.
 *
 * THis function marks the port in use, but does
 * NOT set a transport ID. Everything else is
 * initialized, however.
 *
 * @param[in] name Pointer to port name. This
 * may NOT be NULL, so be careful.
 * @param[in] id Identifier for this port.
 * @param[in] index Index number for this port.
 * @return Pointer to initialized iSCSI port or NULL
 * in case of memory exhaustion.
 */
iscsi_port *iscsi_port_create(const uint8_t *name, const uint64_t id, const uint16_t index)
{
	iscsi_port *port = (iscsi_port *) malloc( sizeof(struct iscsi_port) );

	if ( port == NULL ) {
		logadd( LOG_ERROR, "iscsi_port_create: Out of memory allocating iSCSI port" );

		return NULL;
	}

	const uint name_len = (uint) (strlen( (char *) name ) + 1UL);

	port->name = (uint8_t *) malloc( name_len );

	if ( port->name == NULL ) {
		logadd( LOG_ERROR, "iscsi_port_create: Out of memory allocating iSCSI port name" );

		free( port );

		return NULL;
	}

	memcpy( port->name, name, name_len );

	port->transport_id     = NULL;
	port->id               = id;
	port->index            = index;
	port->flags            = ISCSI_PORT_FLAGS_IN_USE;
	port->transport_id_len = 0U;

	return port;
}

/**
 * @brief iSCSI port destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * port stored in the iSCSI device hash map.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_port_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_port_destroy( (iscsi_port *) value );

	return 0;
}

/**
 * @brief Deallocates all resources acquired iscsi_port_create.
 *
 * This function also frees the port name and transport ID,
 * if they exist.
 *
 * @param[in] port iSCSI port to deallocate. This may
 * be NULL in which case nothing happens.
 */
void iscsi_port_destroy(iscsi_port *port)
{
	if ( port != NULL ) {
		if ( port->name != NULL ) {
			free( port->name );

			port->name = NULL;
		}

		if ( port->transport_id != NULL ) {
			free( port->transport_id );

			port->transport_id = NULL;
		}

		free( port );
	}
}

/**
 * @brief Retrieves the name of an iSCSI port.
 *
 * This function is just a getter.
 *
 * @param[in] port Pointer to iSCSI port to retrieve
 * the name from and may NOT be NULL, so be
 * careful.
 * @return Pointer to string containing the name
 * of the iSCSI port.
 */
uint8_t *iscsi_port_get_name(const iscsi_port *port)
{
	return port->name;
}

/**
 * @brief Sets the SCSI transport ID of the iSCSI port.
 *
 * This function constructs the SCSI packet data
 * for the SCSI transport id by assigning a name
 * and the Initiator Session ID (ISID).\n
 * Currently, always transport ID format 0x1 will
 * be created.
 *
 * @param[in] Pointer to iSCSI port to assign the
 * SCSI transport ID to. May NOT be NULL, so be
 * careful.
 * @param[in] Pointer to iSCSI name to assign
 * along with the ISID as name.
 * @param[in] Initiator Session ID (ISID).
 * @return 0 if transport ID could be created
 * successfully, a negative error code
 * otherwise.
 */
int iscsi_port_transport_id_set(iscsi_port *port, const uint8_t *name, const uint64_t isid)
{
	uint8_t *tmp_buf = iscsi_sprintf_alloc( "%s,i,0x%12.12" PRIx64, name, isid );

	if ( tmp_buf == NULL ) {
		logadd( LOG_ERROR, "iscsi_port_transport_id_set: Out of memory allocating SCSI transport ID name for iSCSI port" );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	const uint name_len = (uint) (strlen( (char *) tmp_buf ) + 1U);
	const uint len      = ISCSI_ALIGN(name_len, ISCSI_ALIGN_SIZE);

	if ( (len < 20U) || ((len + offsetof(struct iscsi_transport_id, name)) >= 65536U) ) {
		logadd( LOG_ERROR, "iscsi_port_transport_id_set: Out of memory allocating SCSI transport ID for iSCSI port" );

		free( tmp_buf );

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;
	}

	port->transport_id = (iscsi_transport_id *) malloc( sizeof(struct iscsi_transport_id) + len );

	if ( port->transport_id == NULL ) {
		logadd( LOG_ERROR, "iscsi_port_transport_id_set: Out of memory allocating SCSI transport ID for iSCSI port" );

		free( tmp_buf );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	port->transport_id->id       = (ISCSI_TRANSPORT_ID_PUT_PROTOCOL_ID(ISCSI_TRANSPORT_ID_PROTOCOL_ID_ISCSI) | ISCSI_TRANSPORT_ID_PUT_FORMAT(ISCSI_TRANSPORT_ID_PROTOCOL_ID_ISCSI));
	port->transport_id->reserved = 0U;
	iscsi_put_be16( (uint8_t *) &port->transport_id->add_len, (uint16_t) len );

	memcpy( ((uint8_t *) port->transport_id) + offsetof(struct iscsi_transport_id, name), tmp_buf, name_len );
	memset( ((uint8_t *) port->transport_id) + offsetof(struct iscsi_transport_id, name) + name_len, 0, (len - name_len) );

	port->transport_id_len = (uint16_t) (offsetof(struct iscsi_transport_id, name) + len);

	free( tmp_buf );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Creates and initializes an iSCSI device with a maximum number of LUNs.
 *
 * This function creates a virtual SCSI device
 * which links the DNBD3 images to their LUNs.
 *
 * @param[in] name Pointer to name of iSCSI device,
 * may NOT be NULL, so be careful.
 * @param[in] lun_id Initial LUN identifier to create.
 * @param[in] protocol_id Protocol identifier.
 * @return Pointer to iSCSI device or NULL in
 * case of an error.
 */
iscsi_device *iscsi_device_create(const uint8_t *name, const int lun_id, const uint8_t protocol_id)
{
	iscsi_device *device = (iscsi_device *) malloc( sizeof(struct iscsi_device) );

	if ( device == NULL ) {
		logadd( LOG_ERROR, "iscsi_device_create: Out of memory allocating iSCSI device" );

		return NULL;
	}

	const uint len = (uint) (strlen( (char *) name ) + 1U);

	device->name = malloc( len );

	if ( device->name == NULL ) {
		logadd( LOG_ERROR, "iscsi_device_create: Out of memory allocating iSCSI device name" );

		free( device );

		return NULL;
	}

	memcpy( device->name, name, len );

	device->luns = iscsi_hashmap_create( 8U );

	if ( device->luns == NULL ) {
		logadd( LOG_ERROR, "iscsi_device_create: Out of memory allocating iSCSI device LUN hash map" );

		free( device->name );
		free( device );

		return NULL;
	}

	iscsi_scsi_lun *lun = iscsi_scsi_lun_create( lun_id );

	if ( lun == NULL ) {
		logadd( LOG_ERROR, "iscsi_device_create: Out of memory allocating iSCSI device LUN hash map" );

		iscsi_hashmap_destroy( device->luns );
		free( device->name );
		free( device );

		return NULL;
	}

	if ( pthread_rwlock_init( &device->luns_rwlock, NULL ) != 0 ) {
		iscsi_scsi_lun_destroy( lun );
		iscsi_hashmap_destroy( device->luns );
		free( device->name );
		free( device );

		return NULL;
	}

	const uint64_t lun_hash = lun_id;
	uint8_t *hash_key       = iscsi_hashmap_key_create( (uint8_t *) &lun_hash, sizeof(lun_hash) );

	if ( hash_key == NULL ) {
		logadd( LOG_ERROR, "iscsi_device_create: Out of memory allocating iSCSI device LUN hash map" );

		pthread_rwlock_destroy( &device->luns_rwlock );
		iscsi_scsi_lun_destroy( lun );
		iscsi_hashmap_destroy( device->luns );
		free( device->name );
		free( device );

		return NULL;
	}

	const int rc = iscsi_hashmap_put( device->luns, hash_key, sizeof(lun_hash), (uint8_t *) lun );

	if ( rc < 0 ) {
		iscsi_hashmap_key_destroy( hash_key );
		pthread_rwlock_destroy( &device->luns_rwlock );
		iscsi_scsi_lun_destroy( lun );
		iscsi_hashmap_destroy( device->luns );
		free( device->name );
		free( device );

		return NULL;
	}

	lun->device = device;

	device->ports = iscsi_hashmap_create( 0U );

	if ( device->ports == NULL ) {
		logadd( LOG_ERROR, "iscsi_device_create: Out of memory allocating iSCSI device ports hash map" );

		iscsi_hashmap_key_destroy( hash_key );
		pthread_rwlock_destroy( &device->luns_rwlock );
		iscsi_scsi_lun_destroy( lun );
		iscsi_hashmap_destroy( device->luns );
		free( device->name );
		free( device );

		return NULL;
	}

	device->id           = 0;
	device->flags        = 0;
	device->active_conns = 0UL;
	device->protocol_id  = protocol_id;

	return device;
}

/**
 * @brief iSCSI device destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * device stored in the hash map managing all iSCSI
 * devices.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_device_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_device_destroy( (iscsi_device *) value );
	iscsi_hashmap_key_destroy( key );

	return 0;
}

/**
 * @brief Deallocates all resources acquired by iscsi_device_create.
 *
 * This function also frees the associated
 * iSCSI ports, LUNs and the device name.
 *
 * @param[in] device Pointer to iSCSI device to be freed. May
 * be NULL in which case this function does
 * nothing at all.
 */
void iscsi_device_destroy(iscsi_device *device)
{
	if ( device != NULL ) {
		if ( device->ports != NULL ) {
			iscsi_hashmap_iterate( device->ports, iscsi_port_destroy_callback, NULL );
			iscsi_hashmap_destroy( device->ports );

			device->ports = NULL;
		}

		pthread_rwlock_destroy( &device->luns_rwlock );

		if ( device->luns != NULL ) {
			iscsi_hashmap_iterate( device->luns, iscsi_scsi_lun_destroy_callback, NULL );
			iscsi_hashmap_destroy( device->luns );

			device->luns = NULL;
		}

		if ( device->name != NULL ) {
			free( device->name );

			device->name = NULL;
		}

		free( device );
	}
}

/**
 * @brief Gets an iSCSI device being in use by portal group identifier.
 *
 * This function uses the unique portal group
 * identifier in order to get the port.
 *
 * @param[in] device Pointer to iSCSI device to be searched. May
 * NOT be NULL, so take caution.
 * @param[in] id Portal group ID to be searched for.
 * @return Pointer to iSCSI port belonging to the iSCSI
 * portal group ID or NULL if either the portal
 * group ID does not exist or the port is NOT in use.
 */
iscsi_port *iscsi_device_find_port_by_portal_group_tag(const iscsi_device *device, const uint64_t id)
{
	iscsi_port *port;

	if ( iscsi_hashmap_get( device->ports, (uint8_t *) &id, sizeof(id), (uint8_t **) &port ) < 0 )
		return NULL;

	if ( (port == NULL) || ((port->flags & ISCSI_PORT_FLAGS_IN_USE) == 0) )
		return NULL;

	return port;
}

/**
 * @brief Searches an iSCSI LUN by LUN identifier.
 *
 * This function searches for an iSCSI LUN by
 * iterating through the iSCSI device LUN
 * hash map.
 *
 * @param[in] device Pointer to iSCSI device to
 * search in the LUN hash map. May NOT be
 * NULL, so be careful.
 * @param[in] lun_id LUN identifier to be searched
 * for.
 * @return Pointer to found iSCSI LUN or NULL in
 * case no iSCSI LUN has a matching LUN
 * identifier.
 */
iscsi_scsi_lun *iscsi_device_find_lun(iscsi_device *device, const int lun_id)
{
	const uint64_t hash_key = (uint64_t) lun_id;
	iscsi_scsi_lun *lun;

	const int rc = iscsi_hashmap_get( device->luns, (uint8_t *) &hash_key, sizeof(hash_key), (uint8_t **) &lun );

	if ( (rc < 0) || ((lun->flags & ISCSI_SCSI_LUN_FLAGS_REMOVED) != 0) )
		return NULL;

	return lun;
}

/**
 * @brief Creates, initializes and adds an iSCSI target port to an iSCSI device.
 *
 * This function checks whether the iSCSI
 * target port already exists for the
 * device.
 *
 * @param[in] device Pointer to iSCSI device to
 * add the port for. May NOT be NULL, so
 * be careful.
 * @param[in] name Pointer to string containing
 * the name for the iSCSI target port.
 * NULL is NOT allowed here, take caution.
 * @param[in] id Unique iSCSI target port
 * identifier to be used.
 * @return 0 on successful operation, 1 if
 * the port already exists or a
 * negative error code otherwise.
 */
int iscsi_device_port_add(iscsi_device *device, const uint8_t *name, const uint64_t id)
{
	if ( iscsi_hashmap_contains( device->ports, (uint8_t *) &id, sizeof(id) ) )
		return 1;

	iscsi_port *port = iscsi_port_create( name, id, (uint16_t) iscsi_hashmap_size( device->ports ) );

	if ( port == NULL )
		return -1;

	const int rc = iscsi_hashmap_put( device->ports, (uint8_t *) &port->id, sizeof(port->id), (uint8_t *) port );

	if ( rc < 0 ) {
		iscsi_port_destroy( port );

		return -1;
	}

	return 0;
}

/**
 * @brief Enqueues an iSCSI SCSI task to the first LUN of an iSCSI device.
 *
 * This function adds an iSCSI SCSI task
 * with an unique task identifier to the
 * first LUN of an iSCSI device.
 *
 * @param[in] device Pointer to iSCSI device to enqueue
 * the task to and may NOT be NULL, so be
 * careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task to enqueue
 * to the associated device. NULL is not
 * allowed here, take caution.
 */
void iscsi_device_scsi_task_queue(iscsi_device *device, iscsi_scsi_task *scsi_task)
{
	iscsi_scsi_lun_task_exec( scsi_task->lun, scsi_task );
}

/**
 * @brief Checks if an iSCSI target node NAA or EUI hex identifier is valid.
 *
 * This function checks if the NAA or
 * EUI onlycontains only valid
 * hexadecimal characters.
 *
 * @param[in] name Pointer to NAA or EUI name string
 * to be validated, may NOT be NULL, so
 * be careful.
 * @param[in] pos Position of the hexadecimal string
 * to validate.
 * @param[in] len Length of the hexadecimal string
 * to validate.
 * @retval true The NAA or EUI format is valid.
 * @retval false The NAA or EUI format is invalid.
 */
static bool iscsi_target_node_check_hex(const uint8_t *name, const size_t pos, const size_t len)
{
	for ( size_t i = pos; i < len; i++ ) {
		const uint8_t c = name[i];

		if ( (c < '0') || ((c > '9') && (c < 'A')) || ((c > 'F') && (c < 'a')) || (c > 'f') )
			return false;
	}

	return true;
}

/**
 * @brief Checks if an iSCSI target node name is valid.
 *
 * This function checks the maximum allowed
 * length of the target name and also if it
 * contains only valid characters.\n
 * If the target name starts with 'iqn.' it
 * checks for valid 'iqn.YYYY-MM.' pattern.\n
 * If target name starts with 'naa.' or
 * 'eui.' instead, it will check if the
 * 16 follow up characters are a valid
 * hexadecimal string.
 *
 * @param[in] name Pointer to target name string to be
 * validated, may NOT be NULL, so be
 * careful.
 * @return 0 if all checks passed successfully,
 * a negative error code otherwise.
 */
static int iscsi_target_node_check_name(const uint8_t *name)
{
	if ( iscsi_globvec->target_name_check == ISCSI_GLOBALS_TARGET_NAME_CHECK_NONE )
		return 0;

	const size_t len = strlen( (char *) name );

	if ( len > ISCSI_TARGET_NODE_MAX_NAME_LEN )
		return -1;

	if ( (iscsi_globvec->target_name_check == ISCSI_GLOBALS_TARGET_NAME_CHECK_FULL) || (strncasecmp( (char *) name, ISCSI_TARGET_NODE_NAME_IQN_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_IQN_PREFIX) ) == 0) || (strncasecmp( (char *) name, ISCSI_TARGET_NODE_NAME_NAA_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_NAA_PREFIX) ) == 0) || (strncasecmp( (char *) name, ISCSI_TARGET_NODE_NAME_EUI_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_EUI_PREFIX) ) == 0) ) {
		for ( size_t i = 0; i < len; i++ ) {
			const uint8_t c = name[i];

			if ( (c <= 0x2CU) || (c == 0x2FU) || ((c >= 0x3BU && c <= 0x40U)) || ((c >= 0x5BU) && (c <= 0x60U)) || ((c >= 0x7BU) && (c <= 0x7FU)) )
				return -1;
		}
	}

	if ( ((strncasecmp( (char *) name, ISCSI_TARGET_NODE_NAME_IQN_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_IQN_PREFIX) ) == 0) && (!isdigit(name[4]) || !isdigit(name[5]) || !isdigit(name[6]) || !isdigit(name[7]) || (name[8] != '-') || (name[9] < '0') || (name[9] > '1') || ((name[9] == '0') && ((name[10] < '1') && (name[10] > '9'))) || ((name[9] == '1') && ((name[10] < '0') || (name[10] > '2'))) || (name[11] != '.'))) || (((strncasecmp( (char *) name, ISCSI_TARGET_NODE_NAME_NAA_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_NAA_PREFIX) ) == 0) && ((len == (ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_NAA_PREFIX) + 16)) || (len == (ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_NAA_PREFIX) + 32))) && !iscsi_target_node_check_hex( name, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_NAA_PREFIX), len )) || (((strncasecmp( (char *) name, ISCSI_TARGET_NODE_NAME_EUI_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_EUI_PREFIX) ) == 0) && (len == (ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_EUI_PREFIX) + 16))) && !iscsi_target_node_check_hex( name, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_EUI_PREFIX), len ))) )
		return -1;

	return 0;
}

/**
 * @brief Checks if the iSCSI target node flags are valid.
 *
 * This function checks if the set flags
 * are contradicting themselves or are
 * okay.
 *
 * @param[in] flags Target node flags to check.
 * @param[in] chap_group CHAP group to check.
 * @return 0 if flags are valid, a negative
 * error code otherwise.
 */
static int iscsi_target_node_check_flags(const int flags, const int32_t chap_group)
{
	if ( chap_group < 0L )
		return -1;

	if ( (((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_DISABLE) == 0) && ((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_REQUIRE) == 0) && ((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_MUTUAL) == 0)) || // Auto
		 (((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_DISABLE) != 0) && ((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_REQUIRE) == 0) && ((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_MUTUAL) == 0)) || // None
		 (((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_DISABLE) == 0) && ((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_REQUIRE) != 0) && ((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_MUTUAL) == 0)) || // CHAP
		 (((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_DISABLE) == 0) && ((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_REQUIRE) != 0) && ((flags & ISCSI_TARGET_NODE_FLAGS_CHAP_MUTUAL) != 0)) ) // CHAP Mutual
		return 0;

	return -1;
}

/**
 * @brief Creates, initializes and adds a portal group to an iSCSI target node.
 *
 * Callback function for each element while iterating
 * through the iSCSI global vector portal group
 * hash map.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL creates an
 * empty key assignment.
 * @param[in,out] user_data Pointer to the iSCSI target
 * node to be added and may NOT be NULL, so be
 * careful.
 * @retval -1 An error occured during adding the
 * iSCSI portal group to the iSCSI target node.
 * @retval 0 The iSCSI portal group has been
 * added successfully.
 */
int iscsi_target_node_create_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_target_node *target        = (iscsi_target_node *) user_data;
	iscsi_portal_group *portal_group = (iscsi_portal_group *) value;
	uint8_t *port_name = iscsi_sprintf_alloc( "%s,t,0x%4.4" PRIx64, target->device->name, portal_group->tag );

	if ( port_name == NULL )
		return -1;

	const int rc = iscsi_device_port_add( target->device, port_name, (uint64_t) portal_group->tag );

	free( port_name );

	return rc;
}

/**
 * @brief Creates and initializes an iSCSI target node.
 *
 * This function also allocates the underlying SCSI
 * device and always initializes the first LUN.
 *
 * @param[in] name Pointer to IQN name of target node,
 * may NOT be NULL, so be careful.
 * @param[in] alias Pointer to alias of IQN name.
 * @param[in] index Target node index number.
 * @param[in] lun_id LUN identifier to associate with underlying SCSI device.
 * @param[in] queue_depth Maximum queue depth.
 * @param[in] flags Flags for this target node.
 * @param[in] chap_group CHAP group to associate this node with.
 * @param[in] header_digest Header digest size (always MUST be 0 or 4 for now).
 * @param[in] data_digest Data digest size (always MUST be 0 or 4 for now).
 * @return Pointer to iSCSI target node on successful
 * operation or NULL in case of an error.
 */
iscsi_target_node *iscsi_target_node_create(uint8_t *name, const uint8_t *alias, const int index, const int lun_id, const uint queue_depth, const int flags, const int32_t chap_group, const int header_digest, const int data_digest)
{
	if ( (name == NULL) || (iscsi_target_node_check_name( name ) < 0) || (iscsi_target_node_check_flags( flags, chap_group ) < 0) )
		return NULL;

	iscsi_target_node *target = (iscsi_target_node *) malloc( sizeof(struct iscsi_target_node) );

	if ( target == NULL ) {
		logadd( LOG_ERROR, "iscsi_target_node_create: Out of memory allocating iSCSI target node" );

		return NULL;
	}

	const uint name_len = (uint) (strlen( (char *) name ) + 1U);

	target->name = malloc( name_len );

	if ( target->name == NULL ) {
		logadd( LOG_ERROR, "iscsi_target_node_create: Out of memory allocating iSCSI target node name" );

		free( target );

		return NULL;
	}

	memcpy( target->name, name, name_len );

	if ( alias != NULL ) {
		const uint alias_len = (uint) (strlen( (char *) alias ) + 1U);

		target->alias = malloc( alias_len );

		if ( target->alias == NULL ) {
			logadd( LOG_ERROR, "iscsi_target_node_create: Out of memory allocating iSCSI target node alias" );

			free( target->name );
			free( target );

			return NULL;
		}

		memcpy( target->alias, alias, alias_len );
	} else {
		target->alias = NULL;
	}

	dnbd3_image_t *image = iscsi_target_node_image_get( name );

	if ( image == NULL ) {
		if ( target->alias != NULL )
			free( target->alias );

		free( target->name );
		free( target );

		return NULL;
	}

	const uint key_len   = (uint) (strlen( (char *) image->name ) + 1U);
	uint8_t *hash_key    = iscsi_hashmap_key_create( (uint8_t *) image->name, key_len );
	iscsi_device *device = NULL;

	pthread_rwlock_wrlock( &iscsi_globvec->devices_rwlock );
	int rc = iscsi_hashmap_get( iscsi_globvec->devices, hash_key, key_len, (uint8_t **) &device );

	if ( device != NULL ) {
		pthread_rwlock_wrlock( &device->luns_rwlock );

		iscsi_scsi_lun *lun = iscsi_device_find_lun( device, lun_id );

		if ( lun == NULL ) {
			lun = iscsi_scsi_lun_create( lun_id );

			if ( lun == NULL ) {
				logadd( LOG_ERROR, "iscsi_target_node_create: Out of memory allocating iSCSI device LUN hash map" );

				pthread_rwlock_unlock( &device->luns_rwlock );
				pthread_rwlock_unlock( &iscsi_globvec->devices_rwlock );
				iscsi_hashmap_key_destroy( hash_key );

				if ( target->alias != NULL )
					free( target->alias );

				free( target->name );
				free( target );

				return NULL;
			}

			const uint64_t lun_hash = lun_id;
			uint8_t *lun_hash_key   = iscsi_hashmap_key_create( (uint8_t *) &lun_hash, sizeof(lun_hash) );

			if ( lun_hash_key == NULL ) {
				logadd( LOG_ERROR, "iscsi_target_node_create: Out of memory allocating iSCSI device LUN hash map" );

				pthread_rwlock_unlock( &device->luns_rwlock );
				pthread_rwlock_unlock( &iscsi_globvec->devices_rwlock );
				iscsi_scsi_lun_destroy( lun );
				iscsi_hashmap_key_destroy( hash_key );

				if ( target->alias != NULL )
					free( target->alias );

				free( target->name );
				free( target );

				return NULL;
			}

			const int rc = iscsi_hashmap_put( device->luns, lun_hash_key, sizeof(lun_hash), (uint8_t *) lun );

			if ( rc < 0 ) {
				pthread_rwlock_unlock( &device->luns_rwlock );
				pthread_rwlock_unlock( &iscsi_globvec->devices_rwlock );
				iscsi_hashmap_key_destroy( lun_hash_key );
				iscsi_scsi_lun_destroy( lun );
				iscsi_hashmap_key_destroy( hash_key );

				if ( target->alias != NULL )
					free( target->alias );

				free( target->name );
				free( target );

				return NULL;
			}
		}

		pthread_rwlock_unlock( &device->luns_rwlock );
		iscsi_hashmap_key_destroy( hash_key );

		hash_key = NULL;
	} else {
		device = iscsi_device_create( (uint8_t *) image->name, lun_id, ISCSI_TRANSPORT_ID_PROTOCOL_ID_ISCSI );

		if ( device == NULL ) {
			logadd( LOG_ERROR, "iscsi_target_node_create: Out of memory allocating iSCSI target device" );

			pthread_rwlock_unlock( &iscsi_globvec->devices_rwlock );
			iscsi_hashmap_key_destroy( hash_key );

			if ( target->alias != NULL )
				free( target->alias );

			free( target->name );
			free( target );

			return NULL;
		}

		rc = iscsi_hashmap_put( iscsi_globvec->devices, hash_key, key_len, (uint8_t *) device );

		if ( rc < 0 ) {
			pthread_rwlock_unlock( &iscsi_globvec->devices_rwlock );
			iscsi_device_destroy( device );
			iscsi_hashmap_key_destroy( hash_key );

			if ( target->alias != NULL )
				free( target->alias );

			free( target->name );
			free( target );

			return NULL;
		}
	}

	device->active_conns++;

	pthread_rwlock_unlock( &iscsi_globvec->devices_rwlock );

	target->device = device;

	pthread_rwlock_rdlock( &iscsi_globvec->portal_groups_rwlock );
	rc = iscsi_hashmap_iterate( iscsi_globvec->portal_groups, iscsi_target_node_create_callback, (uint8_t *) target );
	pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );

	if ( rc < 0 ) {
		if ( hash_key != NULL ) {
			pthread_rwlock_wrlock( &iscsi_globvec->devices_rwlock );
			iscsi_hashmap_remove( iscsi_globvec->devices, hash_key, key_len );
			pthread_rwlock_unlock( &iscsi_globvec->devices_rwlock );
			iscsi_device_destroy( device );
			iscsi_hashmap_key_destroy( hash_key );
		} else {
			pthread_rwlock_wrlock( &iscsi_globvec->devices_rwlock );

			device->active_conns--;

			pthread_rwlock_unlock( &iscsi_globvec->devices_rwlock );
		}

		if ( target->alias != NULL )
			free( target->alias );

		free( target->name );
		free( target );

		return NULL;
	}

	target->num           = index;
	target->queue_depth   = queue_depth;
	target->flags         = flags;
	target->header_digest = header_digest;
	target->data_digest   = data_digest;
	target->chap_group    = chap_group;
	target->active_conns  = 0UL;

	return target;
}

/**
 * @brief iSCSI target node destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * target node stored in the hash map managing all
 * iSCSI target nodes.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_target_node_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_target_node_destroy( (iscsi_target_node *) value );
	iscsi_hashmap_key_destroy( key );

	return 0;
}

/**
 * @brief Deallocates all resources acquired by iscsi_target_node_create.
 *
 * This function also frees the IQN name,
 * IQN alias and the associated SCSI device.
 *
 * @param[in] target Pointer to iSCSI target node to be freed.
 * May be NULL in which case this function
 * does nothing at all.
 */
void iscsi_target_node_destroy(iscsi_target_node *target)
{
	if ( target != NULL ) {
		if ( target->alias != NULL ) {
			free( target->alias );

			target->alias = NULL;
		}

		if ( target->name != NULL ) {
			free( target->name );

			target->name = NULL;
		}

		free( target );
	}
}

/**
 * @brief Sends a buffer from a source iSCSI IQN to target iSCSI IQNs.
 *
 * This function sends a buffer starting from a
 * specified position to one, multiple or all
 * target IQNs.\n
 * This function also checks the input and output
 * IQN for conforming to iSCSI specifications.
 *
 * @param[in] conn Pointer to iSCSI connection to write the buffer.
 * @param[in] dst_iqn Pointer to string containing the target IQNs,
 * NULL is not allowed here, take caution.
 * @param[in] src_iqn Pointer to string containing the source IQN.
 * May NOT be NULL, so be careful.
 * @param[in] buf Pointer to output buffer.
 * @param[in] pos Position in buffer in bytes to start sending.
 * @param[in] len Length of buffer in bytes.
 * @return The new position of the written data or a
 * negative error code otherwise.
 */
int32_t iscsi_target_node_send(iscsi_connection *conn, const uint8_t *dst_iqn, const uint8_t *src_iqn, uint8_t *buf, const uint32_t pos, const uint32_t len)
{
	// TODO: Implement function.

	return -1;
}

/**
 * @brief Calculates the WWN using 64-bit IEEE Extended NAA for a name.
 *
 * @param[in] name Pointer to string containing the
 * name to calculate the IEEE Extended
 * NAA for. NULL is NOT allowed here, so
 * take caution.
 * @return A 64-bit unsigned integer for
 * storing the IEEE Extended NAA.
 */
uint64_t iscsi_target_node_wwn_get(const uint8_t *name)
{
	uint64_t value      = 0ULL;
	int i               = 0;

	while ( name[i] != '\0' ) {
		value = (value * 131ULL) + name[i++];
	}

	const uint64_t id_a = ((value & 0xFFF000000ULL) << 24ULL);

	return ((value & 0xFFFFFFULL) | 0x2000000347000000ULL | id_a);
}

/**
 * @brief Extracts the DNBD3 image out of an iSCSI IQN string and opens the DNBD3 image.
 *
 * This function uses the : separator as
 * specified by the IQN standard.\n
 * If no colons are in the IQN string,
 * the complete string will be
 * considered the image file name.\n
 * The image file name is assumed
 * before the last colon and is
 * either directly opened or if
 * that fails, a WWN name by
 * IEEE Extended NAA is tried as
 * well.\n
 * The image revision is assumed
 * after the last colon.
 * @param[in] iqn Pointer to iSCSI IQN string. This
 * is not allowed to be NULL, so be careful.
 * @return Pointer to DNBD3 image if successful
 * operation or NULL if failed.
 */
dnbd3_image_t *iscsi_target_node_image_get(uint8_t *iqn)
{
	uint8_t *image_name = iqn;
	uint8_t *image_rev  = NULL;
	uint8_t *tmp        = (uint8_t *) strchr( (char *) iqn, ':' );

	while ( tmp != NULL ) {
		tmp++;

		if ( image_rev != NULL )
			image_name = image_rev;

		image_rev  = tmp;
		tmp        = (uint8_t *) strchr( (char *) tmp, ':' );
	}

	if ( image_rev == NULL )
		image_rev = image_name;

	const uint len = (uint) (image_rev - image_name);

	if ( len > 0U ) {
		tmp = (uint8_t *) malloc( len );

		if ( tmp == NULL ) {
			logadd( LOG_ERROR, "iscsi_target_node_image_get: Out of memory while allocating DNBD3 image name for iSCSI target node" );

			return NULL;
		}

		memcpy( tmp, image_name, (len - 1) );
		tmp[len - 1] = '\0';
	} else {
		tmp = image_name;
	}

	const uint16_t rev   = (uint16_t) ((len > 0U) ? atoi( (char *) image_rev ) : 0);
	dnbd3_image_t *image = image_getOrLoad( (char *) image_name, rev );

	if ( image == NULL ) {
		image = image_getOrLoad( (char *) tmp, rev );

		if ( image == NULL ) {
			if ( strncasecmp( (char *) image_name, ISCSI_TARGET_NODE_NAME_WWN_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_WWN_PREFIX) ) == 0 ) {
				uint64_t wwn = strtoull( (char *) (image_name + ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_WWN_PREFIX)), NULL, 16 );

				image = image_getByWwn( wwn, rev, true );

				if ( image == NULL ) {
					wwn   = strtoull( (char *) (tmp + ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_WWN_PREFIX)), NULL, 16 );
					image = image_getByWwn( wwn, rev, true );
				}
			} else if ( strncasecmp( (char *) image_name, ISCSI_TARGET_NODE_NAME_NAA_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_NAA_PREFIX) ) == 0 ) {
				uint64_t wwn = strtoull( (char *) (image_name + ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_NAA_PREFIX)), NULL, 16 );

				image = image_getByWwn( wwn, rev, true );

				if ( image == NULL ) {
					wwn   = strtoull( (char *) (tmp + ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_NAA_PREFIX)), NULL, 16 );
					image = image_getByWwn( wwn, rev, true );
				}
			} else if ( strncasecmp( (char *) image_name, ISCSI_TARGET_NODE_NAME_EUI_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_EUI_PREFIX) ) == 0 ) {
				uint64_t wwn = (0x2ULL << 60ULL) | (strtoull( (char *) (image_name + ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_EUI_PREFIX)), NULL, 16 ) & 0x0FFFFFFFFFFFFFFFULL);

				image = image_getByWwn( wwn, rev, true );

				if ( image == NULL ) {
					wwn   = (0x2ULL << 60ULL) | (strtoull( (char *) (tmp + ISCSI_STRLEN(ISCSI_TARGET_NODE_NAME_EUI_PREFIX)), NULL, 16 ) & 0x0FFFFFFFFFFFFFFFULL);
					image = image_getByWwn( wwn, rev, true );
				}
			}
		}
	}

	if ( len > 0U )
		free( tmp );

	return image;
}

/**
 * @brief Finds an iSCSI target node by case insensitive name search.
 *
 * Callback function for each element while iterating
 * through the iSCSI target nodes.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL creates an
 * empty key assignment.
 * @param[in,out] user_data Pointer to a data structure
 * containing the iSCSI target node and the name to be
 * searched for and may NOT be NULL, so be careful.
 * @retval -1 The target node has been found and stored
 * in the result structure. Therefore, no further
 * searching is needed.
 * @retval 0 The target node has not been found yet.
 */
int iscsi_target_node_find_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_target_node_find_name *target_find = (iscsi_target_node_find_name *) user_data;
	iscsi_target_node *target                = (iscsi_target_node *) value;

	if ( strcasecmp( (char *) target->name, (char *) target_find->name ) != 0 )
		return 0;

	target_find->target = target;

	return -1;
}

/**
 * @brief Searches an iSCSI target node by name using case insensitive search.
 *
 * This function searches for an iSCSI target node
 * by iterating through the iSCSI global target node
 * hash map.
 *
 * @param[in] target_name Pointer to string containing the name
 * of the iSCSI target node to be searched for.
 * @return Pointer to found iSCSI target node or NULL
 * in case no iSCSI target node has a matching name.
 */
iscsi_target_node *iscsi_target_node_find(uint8_t *target_name)
{
	if ( target_name == NULL )
		return NULL;

	iscsi_target_node_find_name target_find = {NULL, target_name};

	pthread_rwlock_wrlock( &iscsi_globvec->target_nodes_rwlock );
	iscsi_hashmap_iterate( iscsi_globvec->target_nodes, iscsi_target_node_find_callback, (uint8_t *) &target_find );

	iscsi_target_node *target = target_find.target;

	if ( target == NULL ) {
		dnbd3_image_t *image = iscsi_target_node_image_get( target_name );

		if ( image == NULL ) {
			pthread_rwlock_unlock( &iscsi_globvec->target_nodes_rwlock );

			return NULL;
		}

		target = iscsi_target_node_create( target_name, NULL, 0, image->rid, 16U, 0, 0L, 0, 0 );

		if ( target == NULL ) {
			logadd( LOG_ERROR, "iscsi_target_node_find: Out of memory while allocating iSCSI target node" );

			pthread_rwlock_unlock( &iscsi_globvec->target_nodes_rwlock );

			return NULL;
		}

		const uint key_len = (uint) (strlen( (char *) target_name ) + 1U);
		uint8_t *hash_key  = iscsi_hashmap_key_create( target_name, key_len );

		if ( hash_key == NULL ) {
			logadd( LOG_ERROR, "iscsi_target_node_find: Out of memory while allocating iSCSI target node" );

			pthread_rwlock_unlock( &iscsi_globvec->target_nodes_rwlock );
			iscsi_target_node_destroy( target );

			return NULL;
		}

		int rc = iscsi_hashmap_put( iscsi_globvec->target_nodes, (uint8_t *) hash_key, key_len, (uint8_t *) target );

		if ( rc < 0 ) {
			pthread_rwlock_unlock( &iscsi_globvec->target_nodes_rwlock );
			iscsi_hashmap_key_destroy( (uint8_t *) hash_key );
			iscsi_target_node_destroy( target );

			return NULL;
		}
	}

	target->active_conns++;

	pthread_rwlock_unlock( &iscsi_globvec->target_nodes_rwlock );

	return target;
}

/**
 * @brief Retrieves target node redirection address.
 *
 * This function checks whether the target node needs
 * a redirect and is used for informing the client
 * about a necessary redirection.
 *
 * @param[in] conn Pointer to iSCSI connection, may NOT
 * be NULL, so be careful.
 * @param[in] target Pointer to iSCSI target node where
 * NULL is NOT allowed, so take caution.
 * @return Pointer to redirect target address or NULL
 * if no redirection.
 */
uint8_t *iscsi_target_node_get_redirect(iscsi_connection *conn, iscsi_target_node *target)
{
	// TODO: Implement function

	return NULL;
}

/**
 * @brief Checks if target node is accessible.
 *
 * This function checks whether access is possible
 * to a specific iSCSI IQN and IP address.
 *
 * @param[in] conn Pointer to iSCSI connection which
 * may NOT be NULL, so be careful.
 * @param[in] target Pointer to iSCSI target node. NULL
 * is not allowed here, to take caution.
 * @param[in] iqn Pointer to iSCSI IQN string. This
 * is not allowed to be NULL, so be careful.
 * @param[in] adr Pointer to IP address, NULL is not
 * allowed, so take care.
 * @return 0 if access is possible, a negative error
 * code otherwise.
 */
int iscsi_target_node_access(iscsi_connection *conn, iscsi_target_node *target, const uint8_t *iqn, const uint8_t *adr)
{
	// TODO: Implement access check function

	return 0;
}

/**
 * @brief Creates and initializes an iSCSI session.
 *
 * This function creates and initializes all relevant
 * data structures of an ISCSI session.\n
 * Default key and value pairs are created and
 * assigned before they are negotiated at the
 * login phase.
 *
 * @param[in] conn Pointer to iSCSI connection to associate with the session.
 * @param[in] target Pointer to iSCSI target node to assign with the session.
 * @param[in] type Session type to initialize the session with.
 * @return Pointer to initialized iSCSI session or NULL in case an error
 * occured (usually due to memory exhaustion).
 */
iscsi_session *iscsi_session_create(iscsi_connection *conn, iscsi_target_node *target, const int type)
{
	iscsi_session *session = (iscsi_session *) malloc( sizeof(struct iscsi_session) );

	if ( session == NULL ) {
		logadd( LOG_ERROR, "iscsi_session_create: Out of memory allocating iSCSI session" );

		return NULL;
	}

	session->tag   = conn->pg_tag;
	session->flags = 0;

	if ( (iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_INIT_R2T) != 0 )
		session->flags |= ISCSI_SESSION_FLAGS_INIT_R2T;

	if ( (iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA) != 0 )
		session->flags |= ISCSI_SESSION_FLAGS_IMMEDIATE_DATA;

	if ( (iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER) != 0 )
		session->flags |= ISCSI_SESSION_FLAGS_DATA_PDU_IN_ORDER;

	if ( (iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER) != 0 )
		session->flags |= ISCSI_SESSION_FLAGS_DATA_SEQ_IN_ORDER;

	session->conns                  = 1UL;
	session->max_conns              = iscsi_globvec->max_session_conns;
	session->max_outstanding_r2t    = iscsi_globvec->max_outstanding_r2t;
	session->default_time_to_wait   = iscsi_globvec->default_time_to_wait;
	session->default_time_to_retain = iscsi_globvec->default_time_to_retain;
	session->first_burst_len        = iscsi_globvec->first_burst_len;
	session->max_burst_len          = iscsi_globvec->max_burst_len;
	session->err_recovery_level     = iscsi_globvec->err_recovery_level;

	iscsi_list_create( &session->conn_list );
	iscsi_list_enqueue( &session->conn_list, &conn->node );

	session->key_value_pairs = iscsi_hashmap_create( ((sizeof(iscsi_session_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1) );

	if ( session->key_value_pairs == NULL ) {
		logadd( LOG_ERROR, "iscsi_session_create: Out of memory allocating iSCSI session key and value pairs hash map" );

		free( session );

		return NULL;
	}

	session->target                     = target;
	session->isid                       = 0ULL;
	session->tsih                       = 0ULL;
	session->queue_depth                = 0U;
	session->type                       = type;
	session->exp_cmd_sn                 = 0UL;
	session->max_cmd_sn                 = 0UL;
	session->current_text_init_task_tag = 0xFFFFFFFFUL;

	int rc = iscsi_session_init_key_value_pairs( session->key_value_pairs );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS, session->max_conns );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T, session->max_outstanding_r2t );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_WAIT, session->default_time_to_wait );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_RETAIN, session->default_time_to_retain );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN, session->first_burst_len );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, session->max_burst_len );
	rc    |= iscsi_update_bool_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T, (session->flags & ISCSI_SESSION_FLAGS_INIT_R2T) );
	rc    |= iscsi_update_bool_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA, (session->flags & ISCSI_SESSION_FLAGS_IMMEDIATE_DATA) );
	rc    |= iscsi_update_bool_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_PDU_IN_ORDER, (session->flags & ISCSI_SESSION_FLAGS_DATA_PDU_IN_ORDER) );
	rc    |= iscsi_update_bool_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_SEQ_IN_ORDER, (session->flags & ISCSI_SESSION_FLAGS_DATA_SEQ_IN_ORDER) );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_ERR_RECOVERY_LEVEL, session->err_recovery_level );
	rc    |= iscsi_update_int_key_value_pair( conn->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN, conn->max_recv_ds_len );

	if ( rc != 0 ) {
		logadd( LOG_ERROR, "iscsi_session_create: Out of memory adding iSCSI session key and integer value pair" );

		iscsi_hashmap_iterate( session->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( session->key_value_pairs );
		free( session );

		return NULL;
	}

	return session;
}

/**
 * @brief iSCSI session destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * session stored in the hash map managing all iSCSI
 * sessions.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_session_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_session_destroy( (iscsi_session *) value );
	iscsi_hashmap_key_destroy( key );

	return 0;
}

/**
 * @brief Deallocates all resources acquired by iscsi_session_create.
 *
 * This function also frees the associated key and value pairs,
 * the attached connections as well as frees the initiator
 * port.
 *
 * @param[in] session Pointer to iSCSI session to be freed.
 * May be NULL in which case this function does nothing at all.
 */
void iscsi_session_destroy(iscsi_session *session)
{
	if ( session != NULL ) {
		session->tag    = 0ULL;
		session->target = NULL;
		session->type   = ISCSI_SESSION_TYPE_INVALID;

		if ( session->key_value_pairs != NULL ) {
			iscsi_hashmap_iterate( session->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( session->key_value_pairs );

			session->key_value_pairs = NULL;
		}

		iscsi_connection *conn;
		iscsi_connection *tmp;

		iscsi_list_foreach_safe_node ( &session->conn_list, conn, tmp ) {
			iscsi_list_remove( &conn->node );
			iscsi_connection_destroy( conn );
		}

		if ( session->init_port != NULL ) {
			iscsi_port_destroy( session->init_port );

			session->init_port = NULL;
		}

		free( session ); // TODO: Check if potential reusage of session makes sense.
	}
}

/**
 * @brief Initializes a key and value pair hash table with default values.
 *
 * This function is used by iSCSI connections and
 * sessions with default values for required keys.\n
 * The iSCSI global key and value pair allowed
 * values and ranges for fast
 * access
 *
 * @param[in] key_value_pairs Pointer to key and value pair hash map
 * which should store all the default values for
 * its keys and may NOT be NULL, so take caution.
 * @param[in] lut Lookup table to use for initialization.
 * NULL is not allowed here, so be careful.
 * @return 0 on success, a negative error code otherwise.
 */
static int iscsi_init_key_value_pairs(iscsi_hashmap *key_value_pairs, const iscsi_key_value_pair_lut_entry *lut)
{
	for ( uint i = 0U; lut[i].key != NULL; i++ ) {
		const int rc = iscsi_add_key_value_pair( key_value_pairs, lut[i].key, lut[i].value );

		if ( rc < 0 )
			return rc;
	}

	return 0;
}

/**
 * @brief Initializes a key and value pair hash table with default values for an iSCSI session.
 *
 * This function only initializes the default key
 * and value pairs used by iSCSI sessions.
 *
 * @param[in] key_value_pairs Pointer to key and value pair hash map
 * which should store all the default values for
 * its keys and may NOT be NULL, so take caution.
 * @return 0 on success, a negative error code otherwise.
 */
int iscsi_session_init_key_value_pairs(iscsi_hashmap *key_value_pairs)
{
	return iscsi_init_key_value_pairs( key_value_pairs, &iscsi_session_key_value_pair_lut[0] );
}

/**
 * @brief Creates data structure for an iSCSI connection from iSCSI portal and TCP/IP socket.
 *
 * Creates a data structure for incoming iSCSI connection
 * requests from iSCSI packet data.
 *
 * @param[in] portal Pointer to iSCSI portal to associate the
 * connection with.
 * @param[in] sock TCP/IP socket to associate the connection with.
 * @return Pointer to initialized iSCSI connection structure or NULL in
 * case of an error (invalid iSCSI packet data or memory exhaustion).
 */
iscsi_connection *iscsi_connection_create(iscsi_portal *portal, const int sock)
{
	iscsi_connection *conn = (iscsi_connection *) malloc( sizeof(struct iscsi_connection) );

	if ( conn == NULL ) {
		logadd( LOG_ERROR, "iscsi_create_connection: Out of memory while allocating iSCSI connection" );

		return NULL;
	}

	conn->session         = NULL;
	conn->key_value_pairs = iscsi_hashmap_create( ((sizeof(iscsi_connection_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1) );

	if ( conn->key_value_pairs == NULL ) {
		logadd( LOG_ERROR, "iscsi_create_connection: Out of memory while allocating iSCSI login text key / value pair hash map" );

		free( conn );

		return NULL;
	}

	const int rc = iscsi_connection_init_key_value_pairs( conn->key_value_pairs );

	if ( rc < 0 ) {
		iscsi_hashmap_iterate( conn->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( conn->key_value_pairs );
		free( conn );

		return NULL;
	}

	conn->partial_pairs        = NULL;
	conn->text_key_value_pairs = iscsi_hashmap_create( ((sizeof(iscsi_connection_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1) );

	if ( conn->text_key_value_pairs == NULL ) {
		logadd( LOG_ERROR, "iscsi_create_connection: Out of memory while allocating iSCSI text key / value pair hash map" );

		iscsi_hashmap_iterate( conn->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( conn->key_value_pairs );
		free( conn );

		return NULL;
	}

	conn->text_partial_pairs = NULL;
	conn->device             = NULL;
	conn->init_port          = NULL;
	conn->init_name          = NULL;
	conn->init_adr           = NULL;
	conn->target             = NULL;
	conn->target_port        = NULL;
	conn->target_name_short  = NULL;
	conn->portal_host        = NULL;
	conn->portal_port        = NULL;
	conn->pdu_processing     = NULL;

	iscsi_list_create( &conn->scsi_data_in_queued_tasks );

	conn->login_response_pdu = NULL;

	iscsi_list_create( &conn->pdus_write );
	iscsi_list_create( &conn->pdus_snack );
	iscsi_list_create( &conn->r2t_tasks_active );
	iscsi_list_create( &conn->r2t_tasks_queue );

	conn->target_send_total_size   = 0U;
	conn->scsi_data_in_cnt         = 0U;
	conn->scsi_data_out_cnt        = 0U;
	conn->task_cnt                 = 0U;
	conn->r2t_pending              = 0U;
	conn->header_digest            = 0;
	conn->data_digest              = 0;
	conn->id                       = 0;
	conn->sock                     = sock;
	conn->pdu_recv_state           = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_READY;
	conn->flags                    = 0;
	conn->state                    = ISCSI_CONNECT_STATE_INVALID;
	conn->login_phase              = ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION;
	conn->max_recv_ds_len          = ISCSI_DEFAULT_RECV_DS_LEN;
	conn->pg_tag                   = portal->group->tag;
	conn->isid.a                   = 0;
	conn->isid.b                   = 0;
	conn->isid.c                   = 0;
	conn->isid.d                   = 0;
	conn->tsih                     = 0U;
	conn->cid                      = 0U;
	conn->state_negotiated         = 0U;
	conn->session_state_negotiated = 0UL;
	conn->init_task_tag            = 0UL;
	conn->target_xfer_tag          = 0UL;
	conn->auth_chap.phase          = ISCSI_AUTH_CHAP_PHASE_NONE;
	conn->chap_group               = 0L;
	conn->stat_sn                  = 0UL;
	conn->exp_stat_sn              = 0UL;

	iscsi_list_create( &conn->exec_queue );

	conn->stat_iscsi_opcodes = iscsi_hashmap_create( 256U );

	if ( conn->stat_iscsi_opcodes == NULL ) {
		logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing iSCSI global vector iSCSI opcode statistics" );

		iscsi_hashmap_destroy( conn->text_key_value_pairs );
		iscsi_hashmap_iterate( conn->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( conn->key_value_pairs );
		free( conn );

		return NULL;
	}

	conn->stat_scsi_opcodes = iscsi_hashmap_create( 256U );

	if ( conn->stat_scsi_opcodes == NULL ) {
		logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing iSCSI global vector iSCSI SCSI opcode statistics" );

		iscsi_hashmap_destroy( conn->stat_iscsi_opcodes );
		iscsi_hashmap_destroy( conn->text_key_value_pairs );
		iscsi_hashmap_iterate( conn->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( conn->key_value_pairs );
		free( conn );

		return NULL;
	}

	return conn;
}

/**
 * @brief Deallocates all pending iSCSI tasks and PDUs associated with an iSCSI connection.
 *
 * This function only removes tasks which are
 * not enqueued.
 *
 * @param[in] conn Pointer to iSCSI connection of which to
 * deallocate all the tasks and PDUs. May NOT
 * be NULL, so be careful.
 */
static int iscsi_connection_tasks_destroy(iscsi_connection *conn)
{
	iscsi_pdu *pdu;
	iscsi_pdu *tmp_pdu;

	iscsi_list_foreach_safe_node ( &conn->pdus_snack, pdu, tmp_pdu ) {
		iscsi_list_remove( &pdu->node );
		iscsi_connection_pdu_destroy( pdu );
	}

	iscsi_task *task;
	iscsi_task *tmp_task;

	iscsi_list_foreach_safe_node ( &conn->scsi_data_in_queued_tasks, task, tmp_task ) {
		if ( (task->flags & ISCSI_TASK_FLAGS_QUEUED) != 0 )
			continue;

		iscsi_list_remove( &task->node );
		iscsi_task_destroy( task );
	}

	iscsi_list_foreach_safe_node ( &conn->pdus_write, pdu, tmp_pdu ) {
		iscsi_list_remove( &pdu->node );
		iscsi_connection_pdu_destroy( pdu );
	}

	return ((conn->task_cnt != 0) ? -1 : 0);
}

/**
 * @brief iSCSI connection destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * connection stored in the hash map managing all
 * iSCSI connections.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data This argument is not used by
 * this function and should be always NULL for now, as
 * there is a possibility for future usage.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_connection_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_connection_destroy( (iscsi_connection *) value );
	iscsi_hashmap_key_destroy( key );

	return 0;
}

/**
 * @brief Deallocates all resources acquired by iscsi_connection_create.
 *
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
		iscsi_hashmap_iterate( conn->stat_scsi_opcodes, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( conn->stat_scsi_opcodes );
		conn->stat_scsi_opcodes = NULL;

		iscsi_hashmap_iterate( conn->stat_iscsi_opcodes, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( conn->stat_iscsi_opcodes );
		conn->stat_iscsi_opcodes = NULL;

		iscsi_task *task;
		iscsi_task *tmp;

		iscsi_list_foreach_safe_node ( &conn->r2t_tasks_queue, task, tmp ) {
			iscsi_list_remove( &task->node );
			iscsi_task_destroy( task );
		}

		iscsi_list_foreach_safe_node ( &conn->r2t_tasks_active, task, tmp ) {
			iscsi_list_remove( &task->node );
			iscsi_task_destroy( task );
		}

		iscsi_pdu *pdu;
		iscsi_pdu *tmp_pdu;

		iscsi_list_foreach_safe_node ( &conn->pdus_snack, pdu, tmp_pdu ) {
			iscsi_list_remove( &pdu->node );
			iscsi_connection_pdu_destroy( pdu );
		}

		iscsi_list_foreach_safe_node ( &conn->pdus_write, pdu, tmp_pdu ) {
			iscsi_list_remove( &pdu->node );
			iscsi_connection_pdu_destroy( pdu );
		}

		iscsi_list_foreach_safe_node ( &conn->scsi_data_in_queued_tasks, task, tmp ) {
			iscsi_list_remove( &task->node );
			iscsi_task_destroy( task );
		}

		if ( conn->pdu_processing != NULL ) {
			iscsi_connection_pdu_destroy( conn->pdu_processing );

			conn->pdu_processing = NULL;
		}

		if ( conn->portal_port != NULL ) {
			free( conn->portal_port );

			conn->portal_port = NULL;
		}

		if ( conn->portal_host != NULL ) {
			free( conn->portal_host );

			conn->portal_host = NULL;
		}

		if ( conn->target_name_short != NULL ) {
			free( conn->target_name_short );

			conn->target_name_short = NULL;
		}

		if ( conn->init_adr != NULL ) {
			free( conn->init_adr );

			conn->init_adr = NULL;
		}

		if ( conn->init_name != NULL ) {
			free( conn->init_name );

			conn->init_name = NULL;
		}

		if ( conn->text_partial_pairs != NULL ) {
			free( conn->text_partial_pairs );

			conn->text_partial_pairs = NULL;
		}

		if ( conn->text_key_value_pairs != NULL ) {
			iscsi_hashmap_iterate( conn->text_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( conn->text_key_value_pairs );

			conn->text_key_value_pairs = NULL;
		}

		if ( conn->partial_pairs != NULL ) {
			free( conn->partial_pairs );

			conn->partial_pairs = NULL;
		}

		if ( conn->key_value_pairs != NULL ) {
			iscsi_hashmap_iterate( conn->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( conn->key_value_pairs );

			conn->key_value_pairs = NULL;
		}

		free( conn );
	}
}

/**
 * @brief Drops all connections based on matching pattern.
 *
 * @param[in] conn Pointer to iSCSI connection which may
 * NOT be NULL, so be careful.
 * @param[in] conn_match Pointer to match string, NULL is
 * not allowd here, so take caution.
 * @param[in] all Non-zero number indicating removing all
 * connections.
 * @return 0 on success, a negative error code otherwise.
 */
int iscsi_connection_drop(iscsi_connection *conn, const uint8_t *conn_match, const int all)
{
	// TODO: Implement function.

	return 0;
}

/**
 * @brief Schedules an iSCSI connection.
 *
 * @param[in] conn Pointer to ISCSI connection to be
 * scheduled. May NOT be NULL, so be careful.
 */
void iscsi_connection_schedule(iscsi_connection *conn)
{
	// TODO: Implement function.
}

/**
 * @brief Reads data for the specified iSCSI connection from its TCP socket.
 *
 * The TCP socket is marked as non-blocking, so this function
 * may not read all data requested.
 *
 * Returns ISCSI_CONNECT_PDU_READ_ERR_FATAL if the operation
 * indicates a fatal error with the TCP connection (including
 * if the TCP connection was closed unexpectedly).
 *
 * Otherwise returns the number of bytes successfully read.
 */
int32_t iscsi_connection_read(const iscsi_connection *conn, uint8_t *buf, const uint32_t len)
{
	if ( len == 0UL )
		return 0L;

	const int32_t rc = (int32_t) recv( conn->sock, buf, (size_t) len, MSG_WAITALL );

	return ((rc > 0L) ? rc : (int32_t) ISCSI_CONNECT_PDU_READ_ERR_FATAL);
}

/**
 * @brief Writes data for the specified iSCSI connection to its TCP socket.
 *
 * The TCP socket is marked as non-blocking, so this function may not read
 * all data requested.
 *
 * Returns ISCSI_CONNECT_PDU_READ_ERR_FATAL if the operation
 * indicates a fatal error with the TCP connection (including
 * if the TCP connection was closed unexpectedly).
 *
 * Otherwise returns the number of bytes successfully written.
 */
int32_t iscsi_connection_write(const iscsi_connection *conn, uint8_t *buf, const uint32_t len)
{
	if ( len == 0UL )
		return 0L;

	const int32_t rc = (int32_t) sock_sendAll( conn->sock, buf, (size_t) len, ISCSI_CONNECT_SOCKET_WRITE_RETRIES );

	return ((rc > 0L) ? rc : (int32_t) ISCSI_CONNECT_PDU_READ_ERR_FATAL);
}

/**
 * @brief This function handles all queued iSCSI SCSI Data In tasks.
 *
 * This function also creates a sub task
 * if the data transfer length exceeds
 * the maximum allowed chunk size.
 *
 * @param[in] conn Pointer to iSCSI connection of which the
 * queued SCSI Data In tasks should be
 * handled. May NOT be NULL, so be careful.
 * @return 0 on successful task handling, a
 * negative error code otherwise.
 */
int iscsi_connection_handle_scsi_data_in_queued_tasks(iscsi_connection *conn)
{
	while ( !iscsi_list_empty( &conn->scsi_data_in_queued_tasks ) && (conn->scsi_data_in_cnt < ISCSI_DEFAULT_MAX_DATA_IN_PER_CONNECTION) ) {
		iscsi_task *task = (iscsi_task *) iscsi_list_peek( &conn->scsi_data_in_queued_tasks );

		if ( task->pos < task->scsi_task.xfer_len ) {
			const uint32_t len   = (task->scsi_task.xfer_len - task->pos);
			iscsi_task *sub_task = iscsi_task_create( conn, task, iscsi_scsi_task_xfer_complete );

			if ( sub_task == NULL )
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

			sub_task->scsi_task.buf = NULL;
			sub_task->scsi_task.pos = task->pos;

			pthread_rwlock_rdlock( &conn->device->luns_rwlock );

			if ( iscsi_device_find_lun( conn->device, task->lun_id ) == NULL ) {
				pthread_rwlock_unlock( &conn->device->luns_rwlock );

				iscsi_list_remove( &task->node );

				task->pos                   += len;
				sub_task->scsi_task.len      = 0UL;
				sub_task->scsi_task.xfer_len = len;

				iscsi_scsi_task_lun_process_none( &sub_task->scsi_task );
				iscsi_scsi_task_xfer_complete( &sub_task->scsi_task );

				return ISCSI_CONNECT_PDU_READ_OK;
			}

			pthread_rwlock_unlock( &conn->device->luns_rwlock );

			sub_task->scsi_task.len = ((len < ISCSI_DEFAULT_MAX_RECV_DS_LEN) ? len : ISCSI_DEFAULT_MAX_RECV_DS_LEN);
			task->pos              += sub_task->scsi_task.len;

			iscsi_task_queue( conn, sub_task );
		}

		if ( task->pos == task->scsi_task.xfer_len )
			iscsi_list_remove( &task->node );
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Initializes a key and value pair hash table with default values for an iSCSI connection.
 *
 * This function only initializes the default key
 * and value pairs used by iSCSI connectionss.
 *
 * @param[in] key_value_pairs Pointer to key and value pair hash map
 * which should store all the default values for
 * its keys and may NOT be NULL, so take caution.
 * @return 0 on success, a negative error code otherwise.
 */
int iscsi_connection_init_key_value_pairs(iscsi_hashmap *key_value_pairs)
{
	return iscsi_init_key_value_pairs( key_value_pairs, &iscsi_connection_key_value_pair_lut[0] );
}

/**
 * @brief Appends a special key and value pair to DataSegment packet data.
 *
 * This function adds MaxRecvDataSegmentLength,
 * FirstBurstLength and MaxBurstLength, which
 * require special handling to an output
 * DataSegment buffer and truncates if
 * necessary.
 *
 * @param[in] conn Pointer to iSCSI connection to handle the
 * special key and value pair for. NULL is
 * a forbidden value here, so take caution.
 * @param[in] key_value_pair Pointer to special key and value pair
 * containing its attributes.
 * @param[in] key Pointer to special key to be written to
 * output buffer. NULL is NOT allowed,
 * take caution.
 * @param[in] buf Pointer to output buffer to write the
 * special key and value pair to. NULL is
 * prohibited, so be careful.
 * @param[in] pos Position of buffer in bytes to start
 * writing to.
 * @param[in] len Total length of buffer in bytes.
 * @return New buffer position in bytes or a negative
 * error code.
 */
static int32_t iscsi_append_special_key_value_pair_packet(iscsi_connection *conn, iscsi_key_value_pair *key_value_pair, const uint8_t *key, uint8_t *buf, uint32_t pos, const uint32_t len)
{
	if ( key_value_pair == NULL )
		return pos;

	if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_OVERRIDE_DEFAULT) != 0 ) {
		if ( pos >= len )
			return -1L;

		pos += (uint32_t) (snprintf( (char *) (buf + pos), (len - pos), "%s=%" PRId32, key, (uint32_t) ISCSI_DEFAULT_MAX_RECV_DS_LEN ) + 1);
	}

	if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_OTHER_MAX_VALUE) != 0 ) {
		if ( pos >= len )
			return -1L;

		uint8_t *first_burst_len_val = NULL;
		int rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN, &first_burst_len_val );
		uint32_t first_burst_len = ((rc < 0) ? iscsi_globvec->first_burst_len : (uint32_t) atol( (char *) first_burst_len_val ));

		uint8_t *max_burst_len_val;
		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, &max_burst_len_val );
		uint32_t max_burst_len = ((rc < 0) ? iscsi_globvec->max_burst_len : (uint32_t) atol( (char *) max_burst_len_val ));

		if ( first_burst_len > max_burst_len ) {
			first_burst_len = max_burst_len;

			if ( first_burst_len_val != NULL ) {
				sprintf( (char *) first_burst_len_val, "%" PRId32, first_burst_len );
			}
		}

		pos += (uint32_t) (snprintf( (char *) (buf + pos), (len - pos), "%s=%" PRId32, key, first_burst_len ) + 1);
	}

	return pos;
}

/**
 * @brief Appends a key and value pair to DataSegment packet data.
 *
 * This function adds any non-declarative key
 * and value pair to an output DataSegment
 * buffer and truncates if necessary.
 *
 * @param[in] key_value_pair Pointer to key and value pair containing
 * its attributes.
 * @param[in] key Pointer to key to be written to output
 * buffer. NULL is NOT allowed, take caution.
 * @param[in] value Pointer to value of the key that should
 * be written to output buffer which may
 * NOT be NULL, so take caution.
 * @param[in] buf Pointer to output buffer to write the
 * key and value pair to. NULL is
 * prohibited, so be careful.
 * @param[in] pos Position of buffer in bytes to start
 * writing to.
 * @param[in] len Total length of buffer in bytes.
 * @return New buffer position in bytes or a negative
 * error code.
 */
static int32_t iscsi_append_key_value_pair_packet(const iscsi_key_value_pair *key_value_pair, const uint8_t *key, const uint8_t *value, uint8_t *buf, uint32_t pos, const uint32_t len)
{
	if ( (key_value_pair == NULL) || ((key_value_pair->type != ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE) && (key_value_pair->type != ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE)) ) {
		if ( pos >= len )
			return -1L;

		pos += (uint32_t) (snprintf( (char *) (buf + pos), (len - pos), "%s=%s", key, value ) + 1);
	}

	return pos;
}

/**
 * @brief Negotiates key and value pair of list type.
 *
 * This function checks if a key of list type has a
 * valid value according to the iSCSI specification.
 *
 * @param[in] key_value_pair Pointer to key and value pair. May NOT
 * be NULL, so be careful.
 * @param[in] old_value Pointer to string containing the old
 * value. NULL is not allowed, so take caution.
 * @return Pointer to original value, if the value is
 * allowed or NULL otherwise.
 */
static uint8_t *iscsi_negotiate_key_value_pair_list(const iscsi_key_value_pair *key_value_pair, const uint8_t *old_value)
{
	uint8_t *list        = key_value_pair->list_range;
	const uint8_t *value = (uint8_t *) strchr( (char *) old_value, ',' );
	size_t val_len       = ((value != NULL) ? (size_t) (value - old_value) : strlen( (char *) old_value ));

	for ( ;; ) {
		const size_t len  = strlen( (char *) list );

		if ( (val_len == len) && (strncasecmp( (char *) list, (char *) old_value, len ) == 0) )
			return list;

		list += (len + 1);

		if ( list[0] == '\0' ) {
			if ( value == NULL )
				break;

			old_value = value;
			list      = key_value_pair->list_range;
			value     = (uint8_t *) strchr( (char *) ++old_value, ',' );
			val_len   = ((value != NULL) ? (size_t) (value - old_value) : strlen( (char *) old_value ));
		}
	}

	return NULL;
}

/**
 * @brief Negotiates key and value pair of numeric type.
 *
 * This function checks if a key of numeric type has
 * a valid interger value and clamps within the
 * allowed minimum and maximum range according to
 * the iSCSI specification.
 *
 * @param[in] key_value_pair Pointer to key and value pair. May NOT
 * be NULL, so be careful.
 * @param[in] old_value Pointer to string containing the old
 * value. NULL is not allowed, take caution.
 * @param[in] value Pointer to string containing the current
 * value which may NOT be NULL, so be careful.
 * @return Pointer to original value, if the value is
 * allowed or NULL otherwise.
 */
static uint8_t *iscsi_negotiate_key_value_pair_num(const iscsi_key_value_pair *key_value_pair, uint8_t *old_value, uint8_t *value)
{
	int32_t old_int_val = (int32_t) atol( (char *) key_value_pair->value );

	if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_PREVIOUS_VALUE) != 0 )
		old_int_val = (int32_t) atol( (char *) old_value );

	int32_t int_val = (int32_t) atol( (char *) value );

	const uint8_t *range    = key_value_pair->list_range;
	const int32_t range_min = (int32_t) atol( (char *) range );
	const int32_t range_max = (int32_t) atol( (char *) (range + strlen( (char *) range ) + 1) );

	if ( (old_int_val < range_min) || (old_int_val > range_max) )
		return NULL;

	switch ( key_value_pair->type ) {
		case ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN : {
			if ( old_int_val > int_val )
				old_int_val = int_val;

			break;
		}
		case ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MAX : {
			if ( old_int_val < int_val )
				old_int_val = int_val;

			break;
		}
		default : {
			return old_value;

			break;
		}
	}

	sprintf( (char *) old_value, "%" PRId32, old_int_val );

	return old_value;
}

/**
 * @brief Negotiates key and value pair of boolean type.
 *
 * This function checks if a key of boolean type
 * has a valid value according to the iSCSI
 * specification and also applies the boolean
 * OR / AND function to the current value.
 *
 * @param[in] key_value_pair Pointer to key and value pair. May NOT
 * be NULL, so be careful.
 * @param[in] old_value Pointer to string containing the old
 * value. NULL is not allowed, so take caution.
 * @param[in] value Pointer to string containing the
 * current value which may NOT be NULL, so be
 * careful.
 * @param[in] bool_value Pointer to string containing the
 * boolean OR / AND value where NULL is
 * prohibited, so take caution.
 * @param[out] update_key_value_pair Pointer to integer which
 * marks if the key and value pair should be
 * updated. May NOT be NULL, so be careful.
 * @return Pointer to either boolean AND / OR result,
 * default value or NULL in case of invalid
 * boolean value.
 */
static uint8_t *iscsi_negotiate_key_value_pair_bool(const iscsi_key_value_pair *key_value_pair, uint8_t *old_value, uint8_t *value, uint8_t *bool_value, int *update_key_value_pair)
{
	const uint8_t *list_bool_true  = key_value_pair->list_range;
	const uint8_t *list_bool_false = list_bool_true + strlen( (char *) list_bool_true ) + 1UL;

	if ( (strcasecmp( (char *) old_value, (char *) list_bool_true ) != 0) && (strcasecmp( (char *) old_value, (char *) list_bool_false ) != 0) ) {
		*update_key_value_pair = 0;

		return (uint8_t *) "Reject";
	}

	return ((strcasecmp( (char *) value, (char *) bool_value ) == 0) ? bool_value : old_value);
}

/**
 * @brief Negotiates key and value pair of all types.
 *
 * This function determines the key type and
 * calls the suitable negotation handler
 * for checking iSCSI standard compliance.
 *
 * @param[in] key_value_pair Pointer to key and value pair. May NOT
 * be NULL, so be careful.
 * @param[in] old_value Pointer to string containing the old
 * value. NULL is not allowed, so take caution.
 * @param[in] value Pointer to string containing the
 * current value which may NOT be NULL, so be
 * careful.
 * @param[out] update_key_value_pair Pointer to integer which
 * marks if the key and value pair should be
 * updated. NULL is not allowed, take caution.
 * @return Pointer to new negotiated value or NULL
 * in case of an invalid negation status.
 */
static uint8_t *iscsi_negotiate_key_value_pair_all(const iscsi_key_value_pair *key_value_pair, uint8_t *old_value, uint8_t *value, int *update_key_value_pair)
{
	switch ( key_value_pair->type ) {
		case ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST : {
			return iscsi_negotiate_key_value_pair_list( key_value_pair, old_value );

			break;
		}
		case ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN :
		case ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MAX :
		case ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE : {
			return iscsi_negotiate_key_value_pair_num( key_value_pair, old_value, value );

			break;
		}
		case ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND : {
			return iscsi_negotiate_key_value_pair_bool( key_value_pair, old_value, value, key_value_pair->list_range, update_key_value_pair );

			break;
		}
		case ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR : {
			uint8_t *list_bool_true  = key_value_pair->list_range;
			uint8_t *list_bool_false = list_bool_true + strlen( (char *) list_bool_true ) + 1UL;

			return iscsi_negotiate_key_value_pair_bool( key_value_pair, old_value, value, list_bool_false, update_key_value_pair );

			break;
		}
		default : {
			break;
		}
	}

	return key_value_pair->value;
}

/**
 * @brief Negotiates either iSCSI session or connection state.
 *
 * This function checks and sets the state mask
 * of either an iSCSI connection or session
 * key and value pair.
 *
 * @param[in] conn Pointer to iSCSI connection of which to
 * determine the key type. NULL is NOT allowed,
 * so be careful.
 * @param[in] key_value_pair Pointer to key and value pair
 * containing the key and value pair attributes.
 * NULL is NOT allowed, so be careful.
 * @param[in] type Type of key and value pair to negotiate.
 * 0 is iSCSI connection key and value pair,
 * any other value indicates an iSCSI session
 * key and value pair.
 * @return 0 on successful state negotation, a
 * negative error code otherwise.
 */
static int iscsi_negotiate_key_value_pairs_state(iscsi_connection *conn, const iscsi_key_value_pair *key_value_pair, const int type)
{
	if ( type != 0 ) {
		const uint32_t state_mask = (uint32_t) key_value_pair->state_mask;

		if ( ((conn->session_state_negotiated & state_mask) != 0) && ((key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE) == 0) )
			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER_XCHG_NOT_ONCE;

		conn->session_state_negotiated |= state_mask;
	} else {
		const uint16_t state_mask = (uint16_t) key_value_pair->state_mask;

		if ( ((conn->state_negotiated & state_mask) != 0) && ((key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_MULTI_NEGOTIATION) == 0) )
			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER_XCHG_NOT_ONCE;

		conn->state_negotiated |= state_mask;
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Callback which negotiates a single key and value pairs required for session authentication.
 *
 * This function is called for each key and value
 * pair which needs connection or session
 * authentication.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data Pointer to integer value which is
 * 1 is this is discovery, or 0 if not.
 * @return Always returns 0 as this function cannot fail.
 */
int iscsi_negotiate_key_value_pair_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_key_value_pair_packet *key_value_pair_packet = (iscsi_key_value_pair_packet *) user_data;
	iscsi_connection *conn = key_value_pair_packet->conn;
	iscsi_hashmap *key_value_pairs = conn->key_value_pairs;
	iscsi_key_value_pair *key_value_pair = NULL;
	int type = 0;
	int rc = iscsi_hashmap_get( iscsi_globvec->connection_key_value_pairs, key, key_size, (uint8_t **) &key_value_pair);

	if ( rc < 0 ) {
		key_value_pairs = conn->session->key_value_pairs;
		type = 1;

		rc = iscsi_hashmap_get( iscsi_globvec->session_key_value_pairs, key, key_size, (uint8_t **) &key_value_pair);
	}

	if ( (rc == 0) && (key_value_pair->flags & (ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE | ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_SPECIAL_HANDLING)) != 0 )
		return 0;

	int update_key_value_pair = 1;
	uint8_t *conn_sess_val;

	if ( rc < 0 ) {
		conn_sess_val = (uint8_t *) "NotUnderstood";

		update_key_value_pair = 0;
	} else if ( (key_value_pair_packet->discovery != 0) && ((key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE) != 0) ) {
		conn_sess_val = (uint8_t *) "Irrelevant";

		update_key_value_pair = 0;
	} else {
		rc = iscsi_negotiate_key_value_pairs_state( conn, key_value_pair, type );

		if ( rc < 0 )
			return rc;

		rc = iscsi_hashmap_get( key_value_pairs, key, key_size, &conn_sess_val );
	}

	if ( (key_value_pair != NULL) && (key_value_pair->type > ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_UNSPECIFIED) ) {
		if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_PREVIOUS_VALUE) != 0 ) {
			uint8_t *max_burst_len_val;
			uint32_t first_burst_len = (uint32_t) atol( (char *) value );
			uint32_t max_burst_len;

			rc = iscsi_get_key_value_pair( key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, &max_burst_len_val );

			max_burst_len = ((rc < 0) ? iscsi_globvec->max_burst_len : (uint32_t) atol( (char *) max_burst_len_val ));

			if ( (first_burst_len < ISCSI_MAX_DS_SIZE) && (first_burst_len > max_burst_len) )
				sprintf( (char *) value, "%" PRId32, first_burst_len );
		}

		if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE) != 0 )
			update_key_value_pair = 0;

		conn_sess_val = iscsi_negotiate_key_value_pair_all( key_value_pair, value, conn_sess_val, &update_key_value_pair );
	}

	if ( conn_sess_val != NULL ) {
		if ( update_key_value_pair != 0 )
			iscsi_update_key_value_pair( key_value_pairs, key, conn_sess_val );

		key_value_pair_packet->pos = iscsi_append_key_value_pair_packet( key_value_pair, key, conn_sess_val, key_value_pair_packet->buf, key_value_pair_packet->pos, key_value_pair_packet->len );

		if ( (int32_t) key_value_pair_packet->pos < 0L )
			return key_value_pair_packet->pos;

		key_value_pair_packet->pos = iscsi_append_special_key_value_pair_packet( conn, key_value_pair, key, key_value_pair_packet->buf, key_value_pair_packet->pos, key_value_pair_packet->len );

		if ( (int32_t) key_value_pair_packet->pos < 0L )
			return key_value_pair_packet->pos;
	}

	return 0;
}

/**
 * @brief Negotiates all key and value pairs required for session authentication.
 *
 * @param[in] conn Pointer to iSCSI connection to be
 * negotiated, may NOT be NULL, so be careful.
 * @param[in] key_value_pairs Pointer to key and value pair hash map
 * which contains the negotiation pairs. NULL
 * is prohibited, so take caution.
 * @param[in] buf Pointer to output buffer which may NOT
 * be NULL, so be careful.
 * @param[in] pos Number of bytes already written.
 * @param[in] len Length of DataSegment in bytes.
 * @return New buffer length in bytes if all keys
 * could be negotiated, a negative error
 * code otherwise.
 */
int32_t iscsi_negotiate_key_value_pairs(iscsi_connection *conn, iscsi_hashmap *key_value_pairs, uint8_t *buf, const uint32_t pos, const uint32_t len)
{
	if ( pos > len ) {
		buf[len - 1UL] = '\0';

		return len;
	}

	uint8_t *type;
	int rc = iscsi_get_key_value_pair( key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, &type );

	if ( rc < 0 )
		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, &type );

	const int discovery = (((rc == 0) && (strcasecmp( (char *) type, "Discovery" ) == 0)) ? 1 : 0);

	iscsi_key_value_pair_packet key_value_pair_packet = {conn, buf, pos, len, discovery};
	iscsi_hashmap_iterate( key_value_pairs, iscsi_negotiate_key_value_pair_callback, (uint8_t *) &key_value_pair_packet );

	return key_value_pair_packet.pos;
}

/**
 * @brief Copies retrieved key and value pairs into SCSI connection and session structures.
 *
 * This function converts string representations of
 * integer and boolean key and value pairs.
 *
 * @param[in] conn Pointer to iSCSI connection which holds the
 * copies of the key and value pairs.
 * @retval -1 An error occured during the copy process,
 * e.g. memory is exhausted.
 * @retval 0 All key and value pairs were copied successfully.
 */
int iscsi_connection_copy_key_value_pairs(iscsi_connection *conn)
{
	int32_t int_val;

	int rc = iscsi_get_int_key_value_pair( conn->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN, &int_val);

	if ( rc != 0 )
		return rc;

	if ( (int_val <= 0L) || (int_val > (int32_t) ISCSI_DEFAULT_MAX_RECV_DS_LEN) )
		int_val = ISCSI_DEFAULT_MAX_RECV_DS_LEN;

	conn->max_recv_ds_len = int_val;

	uint8_t *value;

	rc = iscsi_get_key_value_pair( conn->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST, &value);

	if ( rc != 0 )
		return rc;

	conn->header_digest = ((strcasecmp( (char *) value, "CRC32C" ) == 0) ? ISCSI_DIGEST_SIZE : 0);

	rc = iscsi_get_key_value_pair( conn->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST, &value);

	if ( rc != 0 )
		return rc;

	conn->data_digest = ((strcasecmp( (char *) value, "CRC32C" ) == 0) ? ISCSI_DIGEST_SIZE : 0);

	rc = iscsi_get_int_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->max_conns = int_val;

	rc = iscsi_get_int_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->max_outstanding_r2t = int_val;

	rc = iscsi_get_int_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->first_burst_len = int_val;

	rc = iscsi_get_int_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->max_burst_len = int_val;

	rc = iscsi_get_bool_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->flags &= ~(ISCSI_SESSION_FLAGS_INIT_R2T | ISCSI_SESSION_FLAGS_IMMEDIATE_DATA);

	if ( int_val != 0L )
		conn->session->flags |= ISCSI_SESSION_FLAGS_INIT_R2T;

	rc = iscsi_get_bool_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA, &int_val);

	if ( rc != 0 )
		return rc;

	if ( int_val != 0L )
		conn->session->flags |= ISCSI_SESSION_FLAGS_IMMEDIATE_DATA;

	return 0;
}

/**
 * @brief Handles stages of CHAP and other authentication methods.
 *
 * This function handles the various stages of the
 * various authentication methods supported by the
 * iSCSI protocol.\n
 * Currently, only CHAP is implemented.
 *
 * @param[in] conn Pointer to iSCSI connection which may NOT
 * be NULL, so be careful.
 * @param[in] key_value_pairs Pointer to hash map containing the
 * authentication key and value pairs. NULL
 * is NOT allowed here, so take caution.
 * @param[in] auth_method Pointer to string containing the
 * authentication method. NULL is forbidden,
 * so be careful.
 * @param[in] buf Pointer to DataSegment buffer. May NOT be
 * NULL, so take caution.
 * @param[in] pos Remaining number of bytes to read.
 * @param[in] len Total number of bytes of DataSegment buffer.
 * @return 0 if authentication methods were handled successfully,
 * a negative error code otherwise.
 */
static int32_t iscsi_connection_auth_key_value_pairs(iscsi_connection *conn, iscsi_hashmap *key_value_pairs, const uint8_t *auth_method, uint8_t *buf, const uint pos, const uint len)
{
	// TODO: Implement CHAP and other authentication methods.

	return 0;
}

/**
 * @brief Checks buffer sizes of an iSCSI connection with it's associated session for consistency.
 *
 * This function ensures that, for example, first
 * burst length does not exceed maximum burst
 * length and that the buffers don't exceed their
 * minimum and maximum allowed values.
 *
 * @param[in] conn Pointer to iSCSI connection which holds the
 * values to be checked for consistency. May NOT be NULL,
 * so take caution.
 * @retval -1 At least one value check failed the consistency check.
 * @retval 0 All consistency checks have passed successfully.
 */
static int iscsi_connection_check_key_value_pairs(iscsi_connection *conn)
{
	if ( (conn->session->first_burst_len > conn->session->max_burst_len) || (conn->session->first_burst_len < 512UL) || (conn->session->max_burst_len < 512UL) || (conn->session->max_burst_len > iscsi_globvec->max_burst_len) || (conn->max_recv_ds_len < 512UL) || (conn->max_recv_ds_len > iscsi_globvec->max_burst_len) )
		return -1;

	return 0;
}

/**
 * @brief Updates iSCSI connection and session values after being retrieved from the client.
 *
 * This function copies the key and value pairs into the
 * internal connection and session structure and checks
 * them for consistency.\n
 * The TCP receive buffer will be adjusted to the new
 * updated value but is never lower than 4KiB and never
 * higher than 8KiB plus header overhead and a factor of
 * 4 for receiving four packets at once.
 *
 * @param[in] conn Pointer to ISCSI connection which should
 * be updated.
 * @retval -1 An error occured, e.g. socket is already closed.
 * @retval 0 All values have been updated successfully and
 * the socket is still alive.
 */
static int iscsi_connection_update_key_value_pairs(iscsi_connection *conn)
{
	int rc = iscsi_connection_copy_key_value_pairs( conn );

	if ( rc < 0 ) {
		if ( conn->state < ISCSI_CONNECT_STATE_EXITING )
			conn->state = ISCSI_CONNECT_STATE_EXITING;

		return rc;
	}

	rc = iscsi_connection_check_key_value_pairs( conn );

	if ( (rc < 0) && (conn->state < ISCSI_CONNECT_STATE_EXITING) )
		conn->state = ISCSI_CONNECT_STATE_EXITING;

	if ( conn->sock < 0 )
		return -1;

	uint recv_buf_len = conn->session->first_burst_len;

	if ( recv_buf_len < 4096U )
		recv_buf_len = 4096U;
	else if ( recv_buf_len > 8192U )
		recv_buf_len = 8192U;

	recv_buf_len  += (uint) (sizeof(struct iscsi_bhs_packet) + ISCSI_MAX_AHS_SIZE + conn->header_digest + conn->data_digest); // BHS + maximum AHS size + header and data digest overhead
	recv_buf_len <<= 2U; // Receive up to four streams at once.

	setsockopt( conn->sock, SOL_SOCKET, SO_RCVBUF, &recv_buf_len, sizeof(recv_buf_len)); // Not being able to set the buffer is NOT fatal, so ignore error.

	return rc;
}

/**
 * @brief Prepares an iSCSI login response PDU and sends it via TCP/IP.
 *
 * This function constructs the login response PDU
 * to be sent via TCP/IP.
 *
 * @param[in] conn Pointer to ISCSI connection to send the TCP/IP
 * packet with. May NOT be NULL, so be
 * careful.
 * @param[in] login_response_pdu Pointer to login response PDU to
 * be sent via TCP/IP. NULL is NOT
 * allowed here, take caution.
 * @param[in] key_value_pairs Pointer to hash map of key and value pairs
 * to be used for login response storage.
 * @param[in] callback Pointer to post processing callback function
 * after sending the TCP/IP packet.
 * @return 0 if the login response has been sent
 * successfully, a negative error code otherwise.
 */
static int iscsi_connection_pdu_login_response(iscsi_connection *conn, iscsi_pdu *login_response_pdu, iscsi_hashmap *key_value_pairs, iscsi_connection_xfer_complete_callback callback)
{
	const uint32_t ds_len = login_response_pdu->ds_len;

	login_response_pdu->ds_len = login_response_pdu->len;

	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) iscsi_connection_pdu_append( login_response_pdu, login_response_pdu->ahs_len, 0, ds_len, 0 );

	login_response_pkt->version_max    = ISCSI_VERSION_MAX;
	login_response_pkt->version_active = ISCSI_VERSION_MAX;

	iscsi_put_be32( (uint8_t *) &login_response_pkt->total_ahs_len, ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	iscsi_put_be32( (uint8_t *) &login_response_pkt->stat_sn, conn->stat_sn++ );

	if ( conn->session != NULL ) {
		iscsi_put_be32( (uint8_t *) &login_response_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
		iscsi_put_be32( (uint8_t *) &login_response_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	} else {
		iscsi_put_be32( (uint8_t *) &login_response_pkt->exp_cmd_sn, login_response_pdu->cmd_sn );
		iscsi_put_be32( (uint8_t *) &login_response_pkt->max_cmd_sn, login_response_pdu->cmd_sn );
	}

	if ( login_response_pkt->status_class != ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS )
		login_response_pkt->flags &= (int8_t) ~(ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT | ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_MASK | ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_MASK );

	iscsi_connection_pdu_write( conn, login_response_pdu, callback, (uint8_t *) conn );

	if ( key_value_pairs != NULL ) {
		iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( key_value_pairs );
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Callback function after login response has been sent.
 *
 * This function is invoked after the login
 * response has been sent to the client via
 * TCP/IP.
 *
 * @param[in] user_data Pointer to iSCSI connection which
 * was used for sending the response.
 */
static void iscsi_connection_pdu_login_err_complete(uint8_t *user_data)
{
	iscsi_connection *conn = (iscsi_connection *) user_data;

	if ( (conn->flags & ISCSI_CONNECT_FLAGS_FULL_FEATURE) != 0 )
		iscsi_connection_update_key_value_pairs( conn );
}

/**
 * @brief Callback function after login response has been sent.
 *
 * This function is invoked after the login
 * response has been sent to the client via
 * TCP/IP.
 *
 * @param[in] user_data Pointer to iSCSI connection which
 * was used for sending the response.
 */
static void iscsi_connection_pdu_login_ok_complete(uint8_t *user_data)
{
	iscsi_connection *conn = (iscsi_connection *) user_data;

	if ( conn->state >= ISCSI_CONNECT_STATE_EXITING )
		return;

	if ( (conn->flags & ISCSI_CONNECT_FLAGS_FULL_FEATURE) != 0 ) {
		iscsi_connection_update_key_value_pairs( conn );

		iscsi_connection_schedule( conn );
	}
}

/**
 * @brief Initializes an iSCSI login response PDU structure.
 *
 * This function initializes the internal login
 * response data structure which is part of the iSCSI
 * login procedure.
 *
 * @param[in] login_response_pdu Pointer to login response PDU, NULL
 * is not an allowed value here, so take caution.
 * @param[in] pdu Pointer to login request PDU from client,
 * may NOT be NULL, so be careful.
 * @return 0 if initialization was successful, a negative error
 * code otherwise.
 */
static int iscsi_connection_pdu_login_response_init(iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu)
{
	iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) pdu->bhs_pkt;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	login_response_pdu->ds_len = 0UL;

	login_response_pkt->opcode = ISCSI_OPCODE_SERVER_LOGIN_RES;
	login_response_pkt->flags  = (int8_t) (login_req_pkt->flags & (ISCSI_LOGIN_REQ_FLAGS_TRANSIT | ISCSI_LOGIN_REQ_FLAGS_CONTINUE | ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_MASK));

	if ( (login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0 )
		login_response_pkt->flags |= (login_req_pkt->flags & ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_MASK);

	login_response_pkt->isid.a        = login_req_pkt->isid.a;
	login_response_pkt->isid.b        = login_req_pkt->isid.b; // Copying over doesn't change endianess.
	login_response_pkt->isid.c        = login_req_pkt->isid.c;
	login_response_pkt->isid.d        = login_req_pkt->isid.d; // Copying over doesn't change endianess.
	login_response_pkt->tsih          = login_req_pkt->tsih; // Copying over doesn't change endianess.'
	login_response_pkt->init_task_tag = login_req_pkt->init_task_tag; // Copying over doesn't change endianess.
	login_response_pkt->reserved      = 0UL;
	login_response_pdu->cmd_sn        = iscsi_get_be32(login_req_pkt->cmd_sn);

	if ( login_response_pkt->tsih != 0U )
		login_response_pkt->stat_sn = login_req_pkt->exp_stat_sn; // Copying over doesn't change endianess.'
	else
		login_response_pkt->stat_sn = 0UL;

	login_response_pkt->reserved2 = 0U;
	login_response_pkt->reserved3 = 0ULL;

	if ( ((login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0) && ((login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_CONTINUE) != 0) ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	} else if ( (ISCSI_VERSION_MIN < login_req_pkt->version_min) || (ISCSI_VERSION_MAX > login_req_pkt->version_max) ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_WRONG_VERSION;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	} else if ( (ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(login_response_pkt->flags) == ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_RESERVED) && ((login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0) ) {
		login_response_pkt->flags        &= (int8_t) ~(ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_MASK | ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT | ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_MASK);
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS;
	login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SUCCESS;

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Saves incoming key / value pairs from the client of a login request PDU.
 *
 * The login response structure has status detail
 * invalid login request type set in case of an error.
 *
 * @param[in] conn Pointer to iSCSI connection
 * used for key and value pair extraction.
 * @param[out] key_value_pairs Pointer to hash map which
 * stores all the parsed key and value pairs.
 * @param[in] login_response_pdu Pointer to iSCSI login response
 * PDU, may NOT be NULL, so be careful.
 * @param[in] pdu Pointer to iSCSI login request packet
 * PDU, may NOT be NULL, so be careful.
 * @retval -1 An error occured during parse of
 * key and value pairs (memory exhaustion).
 * @retval 0 All key and value pairs have been parsed successfully.
 */
int iscsi_connection_save_incoming_key_value_pairs(iscsi_connection *conn, iscsi_hashmap *key_value_pairs, iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu)
{
	iscsi_login_req_packet *login_req_pkt           = (iscsi_login_req_packet *) pdu->bhs_pkt;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
	const int rc = iscsi_parse_key_value_pairs( key_value_pairs, (uint8_t *) pdu->ds_cmd_data, pdu->ds_len, ((login_req_pkt->flags & ISCSI_LOGIN_REQ_FLAGS_CONTINUE) != 0), &conn->partial_pairs );

	if ( rc < 0 ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Extracts the Initiator Session ID (ISID) from packet data into a 64-bit unsigned integer.
 *
 * The ISID is constructed by OR'ing and shifting the
 * four parts a, b, c and d into their proper places
 * with d being in the LSB area.\n
 * Since the ISID is only 48 bit wide, the 16
 * MSB bits are always cleared.
 *
 * @param[in] isid Pointer to the ISID part of packet data.
 * May NOT be NULL, so be careful.
 * @return The 64-bit unsigned integer value representing
 * the Initiator Session ID (ISID).
 */
static inline uint64_t iscsi_connection_get_isid(const iscsi_isid *isid)
{
	return ((uint64_t) isid->a << 40ULL) | ((uint64_t) iscsi_get_be16(isid->b) << 24ULL) | ((uint64_t) isid->c << 16ULL) | (uint64_t) iscsi_get_be16(isid->d);
}

/**
 * @brief Initializes the login response port names.
 *
 * This function extracts the initiator name from the
 * key and value pair and stores the result in
 * the iSCSI connection, as well as a full qualified
 * initiator port name.
 *
 * @param[in] conn Pointer to iSCSI connection where to
 * store the initiator name.
 * @param[in] response_pdu Pointer to response PDU to initialize the
 * port from, NULL is NOT allowed here, so be careful.
 * @param[in] key_value_pairs Pointer to the hash map containing the key
 * and value pair for the initiator name. May NOT be
 * NULL, so take caution.
 * @param[out] init_port_name Pointer to store the full qualified name
 * of the initiator port and may NOT be NULL, so be careful.
 * @return 0 in case the port could be initialized
 * successfully, a negative error code otherwise
 * in which case the status class and detail are
 * set as well.
 */
static int iscsi_connection_login_init_port(iscsi_connection *conn, iscsi_pdu *response_pdu, iscsi_hashmap *key_value_pairs, uint8_t **init_port_name)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) response_pdu->bhs_pkt;
	uint8_t *init_name;
	int rc = iscsi_get_key_value_pair( key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_NAME, &init_name );

	if ( rc != 0 ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	conn->init_name = iscsi_sprintf_alloc( "%s", init_name );

	if ( conn->init_name == NULL ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	*init_port_name = iscsi_sprintf_alloc( "%s,i,0x%12.12" PRIx64, init_name, iscsi_connection_get_isid( &login_response_pkt->isid ) );

	if ( *init_port_name == NULL ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

		free( conn->init_name );
		conn->init_name = NULL;

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Determines the session type of login.
 *
 * This function is used to retrieve the
 * login session type and checks the
 * relevant key and value pair for
 * errors.
 *
 * @param[in] login_response_pdu Pointer to login response PDU,
 * NULL is not allowed, so take caution.
 * @param[in] key_value_pairs Pointer to key and value pairs which
 * contain the session type parameter to be evaluated,
 * which may NOT be NULL, so take caution.
 * @param[out] type Pointer to integer which stores the
 * determined session type and is NOT allowed to be
 * NULL, so be careful.
 * @return 0 on successful operation, a negative error code
 * otherwise. The output session 'type' is unchanged, if
 * an invalid session type value was retrieved.
 */
static int iscsi_connection_login_session_type(iscsi_pdu *login_response_pdu, iscsi_hashmap *key_value_pairs, int *type )
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
	uint8_t *type_str;
	int rc = iscsi_get_key_value_pair( key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, &type_str );

	if ( (rc == 0) && (type_str != NULL) ) {
		if ( strcasecmp( (char *) type_str, "Discovery" ) == 0 ) {
			*type = ISCSI_SESSION_TYPE_DISCOVERY;
		} else if ( strcasecmp( (char *) type_str, "Normal" ) == 0 ) {
			*type = ISCSI_SESSION_TYPE_NORMAL;
		} else {
			*type = ISCSI_SESSION_TYPE_INVALID;

			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}
	} else {
		if ( login_response_pkt->tsih != 0U ) {
			*type = ISCSI_SESSION_TYPE_NORMAL;
		} else {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Checks the target node info and sets login response PDU accordingly.
 *
 * This function also checks if the target node is
 * redirected and if so, sets the response to the
 * client response to the temporarily redirection
 * URL.\n
 * THe accessibility of the target node is
 * also checked.
 *
 * @param[in] conn Pointer to iSCSI connection which may NOT be
 * NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU
 * to set the parameters for. NULL is NOT allowed
 * here, so take caution.
 * @param[in] target_name Pointer to target node name and may
 * NOT be NULL, be careful.
 * @param[out] Pointer where to store the target node belonging
 * to the target name. May NOT be NULL, so take caution.
 * @return 0 if the check was successful or a negative
 * error code otherwise.
 */
static int iscsi_connection_login_check_target(iscsi_connection *conn, iscsi_pdu *login_response_pdu, uint8_t *target_name, iscsi_target_node **target)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	*target = iscsi_target_node_find( target_name );

	if ( *target == NULL ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_NOT_FOUND;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	if ( ((*target)->flags & ISCSI_TARGET_NODE_FLAGS_DESTROYED) != 0 ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_TARGET_REMOVED;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	uint8_t *redirect_adr = iscsi_target_node_get_redirect( conn, *target );

	if ( redirect_adr != NULL ) {
		iscsi_key_value_pair *key_value_pair;
		const int rc = iscsi_hashmap_get( iscsi_globvec->session_key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, strlen( (char *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS ) + 1, (uint8_t **) &key_value_pair);

		if ( rc < 0 ) {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		}

		const int32_t ds_len = iscsi_append_key_value_pair_packet( key_value_pair, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, redirect_adr, (uint8_t *) login_response_pdu->ds_cmd_data, login_response_pdu->ds_len, login_response_pdu->len );

		if ( ds_len < 0L ) {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		}

		login_response_pdu->ds_len        = ds_len;
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_REDIRECT;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_REDIRECT_TEMP;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	if ( iscsi_target_node_access( conn, *target, conn->init_name, conn->init_adr ) < 0 ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_FAIL;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Retrieves iSCSI session by Target Session Identifying Handle (TSIH).
 *
 * This function checks if the TSIH is valid and if so,
 * retrieves the pointer to its iSCSI session structure.
 *
 * @param[in] tsih Target Session Identifying Handle (TSIH).
 * @return Pointer to related iSCSI session or NULL in case
 * the TSIH is invalid or not found.
 */
static iscsi_session *iscsi_session_get_by_tsih(const uint16_t tsih)
{
	if ( tsih == 0U )
		return NULL;

	const uint64_t hash_key = tsih;
	iscsi_session *session;

	pthread_rwlock_rdlock( &iscsi_globvec->sessions_rwlock );

	int rc = iscsi_hashmap_get( iscsi_globvec->sessions, (uint8_t *) &hash_key, sizeof(hash_key), (uint8_t **) &session );

	pthread_rwlock_unlock( &iscsi_globvec->sessions_rwlock );

	return ((rc == 0) ? session : NULL);
}

/**
 * @brief Appends an iSCSI connection to a session.
 *
 * This function checks if the maximum number of
 * connections per session is not exceeded and if
 * there is session spanning.
 * @param[in] conn Pointer to iSCSI connection, may NOT
 * be NULL, so be careful.
 * @param[in] init_port_name Pointer to initiator port name,
 * may NOT be NULL, so take caution.
 * @param[in] tsih Target Session Identifying Handle (TSIH).
 * @return Upper 8 bits of contain status class, lower 8
 * bits status detail. All 16 bits set to zero
 * indicate success.
 */
static uint16_t iscsi_session_append(iscsi_connection *conn, const uint8_t *init_port_name, const uint16_t tsih)
{
	iscsi_session *session = iscsi_session_get_by_tsih( tsih );

	if ( (session == NULL) || (conn->pg_tag != session->tag) || (strcasecmp( (char *) init_port_name, (char *) iscsi_port_get_name( session->init_port ) ) != 0) || (conn->target != session->target) )
		return (ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR << 8U) | ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_NO_SESSION_SPANNING;

	if ( session->conns >= session->max_conns )
		return (ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR << 8U) | ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_TOO_MANY_CONNECTIONS;

	conn->session = session;

	iscsi_list_enqueue( &session->conn_list, &conn->node );

	session->conns++;

	return (ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS << 8U) | ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SUCCESS;
}

/**
 * @brief Checks whether the session is valid.
 *
 * This function also appends the connection
 * to a session if it's valid.'
 *
 * @param[in] conn Pointer to iSCSI connection,
 * may NOT be NULL, so take caution.
 * @param[in] login_response_pdu Pointer to login response PDU,
 * NULL is not allowed, hence be careful.
 * @param[in] init_port_name Pointer to initiator port name.
 * Non-NULL only, so be careful.
 * @param[in] cid Connection ID (CID).
 * @return 0 if valid session, a negative error code
 * otherwise.
 */
static int iscsi_connection_login_check_session(iscsi_connection *conn, iscsi_pdu *login_response_pdu, uint8_t *init_port_name, uint cid)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
	int rc = 0;

	if ( login_response_pkt->tsih != 0U ) {
		rc = iscsi_session_append( conn, init_port_name, iscsi_get_be16(login_response_pkt->tsih) );

		if ( rc != 0 ) {
			login_response_pkt->status_class  = (uint8_t) (rc >> 8U);
			login_response_pkt->status_detail = (uint8_t) rc;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}
	} else if ( (iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_ISID_ALLOW_DUPLICATES) != 0 ) {
		iscsi_connection_drop( conn, init_port_name, 0 );
	}

	return rc;
}

/**
 * @brief Initializes a rejecting login response packet.
 *
 * The login response structure has status detail
 * invalid login request type set.
 *
 * @param[in] login_response_pdu Pointer to iSCSI login response PDU,
 * NULL is an invalid value here, so take caution.
 * @param[in] pdu Pointer to iSCSI login request PDU, may NOT
 * be NULL, so be careful.
 */
void iscsi_connection_login_response_reject(iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	login_response_pkt->opcode                       = ISCSI_OPCODE_SERVER_LOGIN_RES;
	login_response_pkt->flags                        = 0;
	login_response_pkt->version_max                  = ISCSI_VERSION_MAX;
	login_response_pkt->version_active               = ISCSI_VERSION_MAX;
	*(uint32_t *) &login_response_pkt->total_ahs_len = 0UL; // TotalAHSLength and DataSegmentLength are always 0, so write in one step.
	login_response_pkt->isid.a                       = 0U;
	login_response_pkt->isid.b                       = 0U;
	login_response_pkt->isid.c                       = 0U;
	login_response_pkt->isid.d                       = 0U;
	login_response_pkt->tsih                         = 0U;
	login_response_pkt->init_task_tag                = ((iscsi_login_req_packet *) pdu->bhs_pkt)->init_task_tag;
	login_response_pkt->reserved                     = 0UL;
	login_response_pkt->stat_sn                      = 0UL;
	login_response_pkt->exp_cmd_sn                   = 0UL;
	login_response_pkt->max_cmd_sn                   = 0UL;
	login_response_pkt->status_class                 = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
	login_response_pkt->status_detail                = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_INVALID_LOGIN_REQ_TYPE;
	login_response_pkt->reserved2                    = 0U;
	login_response_pkt->reserved3                    = 0ULL;
}

/**
 * @brief Creates an iSCSI PDU structure used by connections.
 *
 * The PDU structure is used for allowing partial
 * reading from the TCP/IP socket and correctly
 * filling the data until everything has been read.
 *
 * @param[in] conn Pointer to connection to link the PDU with.
 * If this is NULL the connection has to be
 * linked later.
 * @param[in] ahs_len Length of AHS packet data to be appended.
 * @param[in] header_digest_size Length of header digest. Currently,
 * only 0, in which case the header digest will
 * be removed, or 4 for CRC32C are allowed.
 * @param[in] ds_len Length of DataSegment packet data to be appended.
 * May not exceed 16MiB - 1 (16777215 bytes).
 * @param[in] data_digest_size Length of optional data digest (0 or
 * 4 for now) to add.
 * @return Pointer to allocated and zero filled PDU or NULL
 * in case of an error (usually memory exhaustion).
 */
iscsi_pdu *iscsi_connection_pdu_create(iscsi_connection *conn, const uint ahs_len, const int header_digest_size, const uint32_t ds_len, const int data_digest_size)
{
	if ( (ahs_len > ISCSI_MAX_AHS_SIZE) || ((header_digest_size != 0) && (header_digest_size != ISCSI_DIGEST_SIZE)) || ((data_digest_size != 0) && data_digest_size != ISCSI_DIGEST_SIZE) || (ds_len > ISCSI_MAX_DS_SIZE) )
		return NULL;

	iscsi_pdu *pdu = (iscsi_pdu *) malloc( sizeof(struct iscsi_pdu) );

	if ( pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_pdu_create: Out of memory while allocating iSCSI PDU" );

		return NULL;
	}

	const uint32_t pkt_ds_len = ISCSI_ALIGN(ds_len, ISCSI_ALIGN_SIZE);
	const uint32_t len        = (uint32_t) (sizeof(struct iscsi_bhs_packet) + (uint32_t) ahs_len + header_digest_size + pkt_ds_len + ((pkt_ds_len != 0UL) ? (uint32_t) data_digest_size : 0UL));
	iscsi_bhs_packet *bhs_pkt = malloc( len );

	if ( bhs_pkt == NULL ) {
		logadd( LOG_ERROR, "iscsi_pdu_create: Out of memory while allocating iSCSI PDU packet data" );

		free( pdu );

		return NULL;
	}

	pdu->node.succ               = NULL;
	pdu->node.pred               = NULL;
	pdu->bhs_pkt                 = bhs_pkt;
	pdu->ahs_pkt                 = ((ahs_len != 0U) ? (iscsi_ahs_packet *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) ) : NULL);
	pdu->header_digest           = ((header_digest_size != 0) ? (iscsi_header_digest *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) + ahs_len) : NULL);
	pdu->ds_cmd_data             = ((pkt_ds_len != 0UL) ? (iscsi_scsi_ds_cmd_data *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) + ahs_len + header_digest_size) : NULL);
	pdu->data_digest             = (((pkt_ds_len != 0uL) && (data_digest_size != 0)) ? (iscsi_data_digest *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) + ahs_len + header_digest_size + ISCSI_ALIGN(pkt_ds_len, ISCSI_ALIGN_SIZE)) : NULL);
	pdu->task                    = NULL;
	pdu->conn                    = conn;
	pdu->xfer_complete_callback  = NULL;
	pdu->xfer_complete_user_data = NULL;
	pdu->flags                   = 0;
	pdu->ref                     = 1UL;
	pdu->bhs_pos                 = 0U;
	pdu->ahs_pos                 = 0U;
	pdu->ahs_len                 = ahs_len;
	pdu->header_digest_pos       = 0U;
	pdu->header_digest_size      = header_digest_size;
	pdu->ds_len                  = pkt_ds_len;
	pdu->pos                     = 0UL;
	pdu->len                     = pkt_ds_len;
	pdu->data_digest_pos         = 0U;
	pdu->data_digest_size        = data_digest_size;
	pdu->task_ref_cnt            = 0U;
	pdu->cmd_sn                  = 0UL;

	if ( pkt_ds_len != 0UL )
		memset( (((uint8_t *) pdu->ds_cmd_data) + ds_len), 0, (pkt_ds_len - ds_len) );

	return pdu;
}

/**
 * @brief Destroys an iSCSI PDU structure used by connections.
 *
 * All associated data which has been read so
 * far will be freed as well.
 *
 * @param[in] pdu Pointer to PDU structure to be deallocated,
 * may be NULL in which case this function
 * does nothing.
 */
void iscsi_connection_pdu_destroy(iscsi_pdu *pdu)
{
	if ( (pdu != NULL) && (--pdu->ref == 0UL) ) {
		if ( pdu->bhs_pkt != NULL ) {
			free( pdu->bhs_pkt );

			pdu->bhs_pkt       = NULL;
			pdu->ahs_pkt       = NULL;
			pdu->header_digest = NULL;
			pdu->ds_cmd_data   = NULL;
			pdu->data_digest   = NULL;
		}

		free( pdu );
	}
}

/**
 * @brief Appends packet data to an iSCSI PDU structure used by connections.
 *
 * This function adjusts the pointers if
 * the packet data size needs to be
 * extended.
 *
 * @param[in] pdu Pointer to iSCSI PDU where to append
 * the packet data to. May NOT be NULL, so
 * be careful.
 * @param[in] ahs_len Length of AHS packet data to be appended.
 * @param[in] header_digest_size Length of header digest. Currently,
 * only 0, in which case the header digest will
 * be removed, or 4 for CRC32C are allowed.
 * @param[in] ds_len Length of DataSegment packet data to be appended.
 * May not exceed 16MiB - 1 (16777215 bytes).
 * @param[in] data_digest_size Length of optional data digest (0 or
 * 4 for now) to add.
 * @return Pointer to allocated and zero filled PDU or NULL
 * in case of an error (usually memory exhaustion).
 */
iscsi_bhs_packet *iscsi_connection_pdu_append(iscsi_pdu *pdu, const uint ahs_len, const int header_digest_size, const uint32_t ds_len, const int data_digest_size)
{
	if ( (ahs_len > ISCSI_MAX_AHS_SIZE) || ((header_digest_size != 0) && (header_digest_size != ISCSI_DIGEST_SIZE)) || ((data_digest_size != 0) && data_digest_size != ISCSI_DIGEST_SIZE) || (ds_len > ISCSI_MAX_DS_SIZE) )
		return NULL;

	if ( (ahs_len != pdu->ahs_len) || (header_digest_size != pdu->header_digest_size) || (ds_len != pdu->ds_len) || (data_digest_size != pdu->data_digest_size) ) {
		iscsi_bhs_packet *bhs_pkt;
		const uint32_t pkt_ds_len = ISCSI_ALIGN(ds_len, ISCSI_ALIGN_SIZE);
		const uint32_t old_len    = (uint32_t) (sizeof(struct iscsi_bhs_packet) + (uint32_t) pdu->ahs_len + pdu->header_digest_size + pdu->ds_len + ((pdu->ds_len != 0UL) ? (uint32_t) pdu->data_digest_size : 0UL));
		const uint32_t new_len    = (uint32_t) (sizeof(struct iscsi_bhs_packet) + (uint32_t) ahs_len + header_digest_size + pkt_ds_len + ((pkt_ds_len != 0UL) ? (uint32_t) data_digest_size : 0UL));

		if ( new_len > old_len ) {
			bhs_pkt = realloc( pdu->bhs_pkt, new_len );

			if ( bhs_pkt == NULL ) {
				logadd( LOG_ERROR, "iscsi_connection_pdu_append: Out of memory while reallocating iSCSI PDU packet data" );

				return NULL;
			}

			pdu->bhs_pkt = bhs_pkt;
		} else {
			bhs_pkt = pdu->bhs_pkt;
		}

		pdu->ahs_pkt            = ((ahs_len != 0U) ? (iscsi_ahs_packet *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) ) : NULL);
		pdu->header_digest      = ((header_digest_size != 0) ? (iscsi_header_digest *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) + ahs_len) : NULL);
		pdu->ds_cmd_data        = ((pkt_ds_len != 0UL) ? (iscsi_scsi_ds_cmd_data *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) + ahs_len + header_digest_size) : NULL);
		pdu->data_digest        = (((pkt_ds_len != 0UL) && (data_digest_size != 0)) ? (iscsi_data_digest *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) + ahs_len + header_digest_size + pkt_ds_len) : NULL);
		pdu->ahs_len            = ahs_len;
		pdu->header_digest_size = header_digest_size;
		pdu->ds_len             = pkt_ds_len;
		pdu->len                = pkt_ds_len;
		pdu->data_digest_size   = data_digest_size;

		if ( pkt_ds_len != 0UL )
			memset( (((uint8_t *) pdu->ds_cmd_data) + ds_len), 0, (pkt_ds_len - ds_len) );
	}

	return pdu->bhs_pkt;
}

/**
 * @brief Frees an iSCSI PDU structure used by using connection callback function.
 *
 * This function frees an iSCSI PDU structure.
 *
 * @param[in] conn Pointer to iSCSI connection to free
 * the PDU from. May NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI PDU structure to be
 * freed. NULL is NOT allowed here, so take
 * caution.
 */
void iscsi_connection_pdu_free(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_connection_xfer_complete_callback callback = pdu->xfer_complete_callback;
	uint8_t *user_data                               = pdu->xfer_complete_user_data;

	pdu->xfer_complete_callback = NULL;

	if ( pdu->task != NULL )
		iscsi_task_destroy( pdu->task );

	iscsi_connection_pdu_destroy( pdu );

	if ( callback != NULL )
		callback( user_data );
}

/**
 * @brief Retrieves the pointer to an specific AHS packet from an iSCSI PDU by index.
 *
 * Gets the pointer of an AHS packet by specified index.
 *
 * @param[in] pdu Pointer to iSCSI PDU of which the
 * AHS packet should be retrieved. May
 * NOT be NULL, so be careful.
 * @param[in] index Zero-based index number of AHS packet to
 * be received.
 * @return The pointer to the AHS packet at specified index on
 * success or NULL in case of an error or if the specific index
 * is out of range.
 */
iscsi_ahs_packet *iscsi_connection_pdu_ahs_packet_get(const iscsi_pdu *pdu, const int index)
{
	iscsi_ahs_packet *ahs_pkt = pdu->ahs_pkt; // First AHS packet

	if ( ahs_pkt == NULL )
		return NULL;

	int count    = index;
	uint ahs_len = pdu->ahs_len;

	while ( (int) ahs_len > 0 ) {
		if ( count-- < 0 )
			return ahs_pkt;

		uint len = iscsi_get_be16(ahs_pkt->len) + offsetof(struct iscsi_ahs_packet, data); // Total length of current AHS packet

		len      = ISCSI_ALIGN(len, ISCSI_ALIGN_SIZE);
		ahs_len -= len;
		ahs_pkt  = (iscsi_ahs_packet *) (((uint8_t *) ahs_pkt) + (len - offsetof(struct iscsi_ahs_packet, data))); // Advance pointer to next AHS packet
	}

	logadd( LOG_ERROR, "iscsi_connection_pdu_ahs_packet_get: Specified index for AHS packet does not exist" );

	return NULL;
}

/**
 * @brief Counts number of AHS packets of an iSCSI PDU.
 *
 * Gets the total number of AHS packets.
 *
 * @param[in] pdu Pointer to iscsi PDU of which the
 * number of AHS packets should be counted.
 * May NOT be NULL, so be careful.
 * @return The number of AHS packets or 0 if no AHS
 * packet data is available.
 */
int iscsi_connection_pdu_ahs_packet_count(const iscsi_pdu *pdu)
{
	const iscsi_ahs_packet *ahs_pkt = pdu->ahs_pkt; // First AHS packet

	if ( ahs_pkt == NULL )
		return 0;

	int count    = 0;
	uint ahs_len = pdu->ahs_len;

	while ( (int) ahs_len > 0 ) {
		uint len = iscsi_get_be16(ahs_pkt->len) + offsetof(struct iscsi_ahs_packet, data); // Total length of current AHS packet

		len      = ISCSI_ALIGN(len, ISCSI_ALIGN_SIZE);
		ahs_len -= len;
		ahs_pkt  = (iscsi_ahs_packet *) (((uint8_t *) ahs_pkt) + (len - offsetof(struct iscsi_ahs_packet, data))); // Advance pointer to next AHS packet
		count++;
	}

	return count;
}

/// CRC32C lookup table. Created with a polynomial reflect value of 0x82F63B78.
static const uint32_t crc32c_lut[] = {
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
 * @brief Calculates digest (CRC32C).
 *
 * Calculates CRC32C with 0x82F63B78 polynomial
 * reflect according to iSCSI specs.\n
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
 * @brief Calculate and store iSCSI header digest (CRC32C).
 *
 * Calculates header digest (CRC32C) with
 * 0x82F63B78 polynomial reflect according
 * to iSCSI specs and stores the result in
 * the iSCSI packet data. This function
 * cannot fail.
 *
 * @param[out] header_digest Pointer to iSCSI header digest
 * packet data to put CRC32C into.
 * May NOT be NULL, so be careful.
 * @param[in] packet_data Pointer to ISCSI BHS packet to
 * calculate CRC32C for. NULL is NOT
 * allowed here, take caution.
 * @param[in] ahs_len AHS segment length in bytes.
 */
void iscsi_connection_pdu_digest_header_update(iscsi_header_digest *header_digest, const iscsi_bhs_packet *packet_data, const uint ahs_len)
{
	const uint32_t crc32c = iscsi_crc32c_update( (uint8_t *) packet_data, (sizeof(struct iscsi_bhs_packet) + ahs_len), ISCSI_CRC32C_INITIAL ) ^ ISCSI_CRC32C_XOR;

	iscsi_put_le32( (uint8_t *) &header_digest->crc32c, crc32c );
}

/**
 * @brief Validates a stored iSCSI header digest (CRC32C) with actual header data.
 *
 * Verifies header digest (CRC32C) with
 * 0x82F63B78 polynomial reflect according
 * to iSCSI specs. This function cannot
 * fail.
 *
 * @param[in] header_digest Pointer to iSCSI header digest
 * packet data to compare CRC32C with.
 * May NOT be NULL, so be careful.
 * @param[in] packet_data Pointer to ISCSI BHS packet to
 * validate CRC32C for. May NOT be NULL,
 * so be careful.
 * @param[in] ahs_len AHS segment length in bytes.
 * @retval true CRC32C matches the stored value.
 * @retval false CRC32C does NOT match the stored value.
 */
bool iscsi_connection_pdu_digest_header_verify(const iscsi_header_digest *header_digest, const iscsi_bhs_packet *packet_data, const uint ahs_len)
{
	const uint32_t crc32c = iscsi_crc32c_update( (uint8_t *) packet_data, (sizeof(struct iscsi_bhs_packet) + ahs_len), ISCSI_CRC32C_INITIAL ) ^ ISCSI_CRC32C_XOR;

	return (iscsi_get_le32(crc32c) == header_digest->crc32c);
}

/**
 * @brief Calculate iSCSI data digest (CRC32C).
 *
 * Calculates data digest (CRC32) with
 * 0x82F63B78 polynomial reflect of a
 * whole DataSegment (CRC32C) according
 * to the iSCSI specs.\n
 * The resulting CRC32C will be stored
 * in the iSCSI packet.
 *
 * @param[out] data_digest Pointer to iSCSI data digest
 * packet data to put CRC32C into.
 * May NOT be NULL, so be careful.
 * @param[in] ds_cmd_data Pointer to iSCSI DataSegment packet to
 * calculate CRC32C for. NULL is NOT
 * allowed here, take caution.
 * @param[in] ds_len Data segment length in bytes.
 */
void iscsi_connection_pdu_digest_data_update(iscsi_data_digest *data_digest, const iscsi_scsi_ds_cmd_data *ds_cmd_data, const uint32_t ds_len)
{
	const uint32_t crc32c = iscsi_crc32c_update( (uint8_t *) ds_cmd_data, ISCSI_ALIGN(ds_len, ISCSI_DIGEST_SIZE), ISCSI_CRC32C_INITIAL ) ^ ISCSI_CRC32C_XOR;

	iscsi_put_le32( (uint8_t *) &data_digest->crc32c, crc32c );
}

/**
 * @brief Validates a stored iSCSI data digest (CRC32C) with actual DataSegment.
 *
 * Verifies data digest (CRC32C) with
 * 0x82F63B78 polynomial reflect according
 * to iSCSI specs. This function cannot
 * fail.
 *
 * @param[out] data_digest Pointer to iSCSI data digest
 * packet data to compare CRC32C with.
 * May NOT be NULL, so be careful.
 * @param[in] ds_cmd_data Pointer to iSCSI DataSegment
 * packet to calculate CRC32C for. May NOT
 * be NULL, so be careful.
 * @param[in] ds_len Data segment length in bytes.
 * @retval true CRC32C matches the stored value.
 * @retval false CRC32C does NOT match the stored value.
 */
bool iscsi_connection_pdu_digest_data_verify(const iscsi_data_digest *data_digest, const iscsi_scsi_ds_cmd_data *ds_cmd_data, const uint32_t ds_len)
{
	const uint32_t crc32c = iscsi_crc32c_update( (uint8_t *) ds_cmd_data, ISCSI_ALIGN(ds_len, ISCSI_DIGEST_SIZE), ISCSI_CRC32C_INITIAL ) ^ ISCSI_CRC32C_XOR;

	return (iscsi_get_le32(crc32c) == data_digest->crc32c);
}

/**
 * @brief Checks whether iSCSI PDU cleanup procedure has to be deferred.
 *
 * This function checks whether the cleanup
 * process of a written PDU has to be
 * deferred to a later stage.
 *
 * @param[in] pdu Pointer to iSCSI PDU to be checked for
 * deferrred cleanup processs.
 * @retval true The PDUs cleanup stage has to be
 * deferred to a later stage.
 * @retval false The PDU can be cleaned up immediately.
 */
static inline bool iscsi_connection_pdu_free_is_deferred(const iscsi_pdu *pdu)
{
	return ((pdu != NULL) && ((pdu->bhs_pkt->opcode == ISCSI_OPCODE_SERVER_READY_XFER) || (pdu->bhs_pkt->opcode == ISCSI_OPCODE_SERVER_SCSI_DATA_IN)));
}

/**
 * @brief Handles iSCSI PDU cleanup after the PDU has been sent via TCP/IP to the client.
 *
 * This function checks whether there are PDU
 * cleanup actions required and either frees
 * the PDU or adds it to the PDU Sequence
 * Number Acknowledgement (SNACK) list.
 *
 * @param[in] user_data Pointer to iSCSI PDU which completed
 * the TCP/IP write. May NOT be NULL, so be
 * careful.
 */
static void iscsi_connection_pdu_write_complete(uint8_t *user_data, int err)
{
	iscsi_pdu *pdu         = (iscsi_pdu *) user_data;
	iscsi_connection *conn = pdu->conn;

	if ( conn->state >= ISCSI_CONNECT_STATE_EXITING )
		return;

	iscsi_list_remove( &pdu->node );

	if ( err != 0 )
		conn->state = ISCSI_CONNECT_STATE_EXITING;

	if ( ((conn->flags & ISCSI_CONNECT_FLAGS_FULL_FEATURE) != 0) && (conn->session->err_recovery_level > 0UL) && iscsi_connection_pdu_free_is_deferred( pdu ) )
		iscsi_list_enqueue( &conn->pdus_snack, &pdu->node );
	else
		iscsi_connection_pdu_free( conn, pdu );
}

/**
 * @brief Writes and sends a response PDU to the client.
 *
 * This function sends a response PDU to the
 * client after being processed by the server.\n
 * If a header or data digest (CRC32C) needs to
 * be calculated, this is done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI server response PDU to send.
 * May NOT be NULL, so be careful.
 * @param[in] callback Callback function to be invoked
 * after TCP/IP packet has been sent successfully.
 * May be NULL in case no further action is required.
 * @param[in,out] user_data Data for the callback
 * function. May be NULL if the callback function
 * doesn't require additional data.
 */
void iscsi_connection_pdu_write(iscsi_connection *conn, iscsi_pdu *pdu, iscsi_connection_xfer_complete_callback callback, uint8_t *user_data)
{
	if ( ISCSI_GET_OPCODE(pdu->bhs_pkt->opcode) != ISCSI_OPCODE_CLIENT_LOGIN_REQ ) {
		if ( pdu->header_digest != NULL )
			iscsi_connection_pdu_digest_header_update( pdu->header_digest, pdu->bhs_pkt, pdu->ahs_len );

		if ( pdu->data_digest != NULL )
			iscsi_connection_pdu_digest_data_update( pdu->data_digest, pdu->ds_cmd_data, pdu->ds_len );
	}

	pdu->xfer_complete_callback  = callback;
	pdu->xfer_complete_user_data = user_data;

	iscsi_list_enqueue( &conn->pdus_write, &pdu->node );

	if ( conn->state >= ISCSI_CONNECT_STATE_EXITING )
		return;

	const uint32_t len                      = (uint) (sizeof(struct iscsi_bhs_packet) + pdu->ahs_len + conn->header_digest + ISCSI_ALIGN(pdu->ds_len, ISCSI_ALIGN_SIZE) + conn->data_digest);
	const int32_t rc                        = iscsi_connection_write( conn, (uint8_t *) pdu->bhs_pkt, len );
	iscsi_connection_exec_queue *exec_queue = (iscsi_connection_exec_queue *) malloc( sizeof(struct iscsi_connection_exec_queue) );

	if ( exec_queue == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_pdu_write: Out of memory while allocating execution queue for PDU write" );

		return;
	}

	exec_queue->data.pdu_write.callback  = iscsi_connection_pdu_write_complete;
	exec_queue->data.pdu_write.user_data = (uint8_t *) pdu;
	exec_queue->data.pdu_write.err       = ((rc == (int32_t) len) ? 0 : -1);
	exec_queue->type                     = ISCSI_CONNECT_EXEC_QUEUE_TYPE_PDU_WRITE;

	iscsi_list_enqueue( &conn->exec_queue, &exec_queue->node );
}

/**
 * @brief Compares if the first iSCSI 32-bit sequence numbers is smaller than the second one.
 *
 * This function almost does the same as an
 * unsigned compare but with special
 * handling for "negative" numbers.
 *
 * @param[in] seq_num First iSCSI sequence number to be compared.
 * @param[in] seq_num_2 Second iSCSI sequence number to be compared.
 * @retval true if first sequence number is smaller than
 * the second one.
 * @retval false if first sequence number is equal or
 * larger than the second one.
 */
static inline int iscsi_seq_num_cmp_lt(const uint32_t seq_num, const uint32_t seq_num_2)
{
	return (seq_num != seq_num_2) && (((seq_num < seq_num_2) && ((seq_num_2 - seq_num) < 2147483648UL)) || ((seq_num > seq_num_2) && ((seq_num - seq_num_2)) > 2147483648UL));
}

/**
 * @brief Compares if the first iSCSI 32-bit sequence numbers is larger than the second one.
 *
 * This function almost does the same as an
 * unsigned compare but with special
 * handling for "negative" numbers.
 *
 * @param[in] seq_num First iSCSI sequence number to be compared.
 * @param[in] seq_num_2 Second iSCSI sequence number to be compared.
 * @retval true if first sequence number is larger than
 * the second one.
 * @retval false if first sequence number is equal or
 * smaller than the second one.
 */
static inline int iscsi_seq_num_cmp_gt(const uint32_t seq_num, const uint32_t seq_num_2)
{
	return (seq_num != seq_num_2) && (((seq_num < seq_num_2) && ((seq_num_2 - seq_num) > 2147483648UL)) || ((seq_num > seq_num_2) && ((seq_num - seq_num_2)) < 2147483648UL));
}

/**
 * @brief Removes an acknowledged PDU from SNACK PDU doubly linked list by ExpStatSN.
 *
 * This function is invoked when ExpStatSN becomes
 * invalid.
 *
 * @param[in] conn Pointer to iSCSI connection to be removed,
 * may NOT be NULL, so be careful.
 * @param[in] exp_stat_sn First ExpStatSN to not to be removed.
 */
void iscsi_connection_pdu_ack_remove(iscsi_connection *conn, const uint32_t exp_stat_sn)
{
	conn->exp_stat_sn = ((exp_stat_sn < conn->stat_sn) ? exp_stat_sn : conn->stat_sn);

	iscsi_pdu *pdu;
	iscsi_pdu *tmp;

	iscsi_list_foreach_safe_node ( &conn->pdus_snack, pdu, tmp ) {
		iscsi_scsi_response_packet *scsi_response_pkt = (iscsi_scsi_response_packet *) pdu->bhs_pkt;
		const uint32_t stat_sn                        = iscsi_get_be32(scsi_response_pkt->stat_sn);

		if ( iscsi_seq_num_cmp_lt( stat_sn, conn->exp_stat_sn ) ) {
			iscsi_list_remove( &pdu->node );
			iscsi_connection_pdu_free( conn, pdu );
		}
	}
}

/**
 * @brief Constructs and sends an iSCSI reject response to the client.
 *
 * This function constructs an reject response PDU with its
 * packet data.\n
 * The original rejected packet data is appended as DataSegment
 * according by iSCSI standard specification.
 *
 * @param[in] conn Pointer to iSCSI connection for reject packet construction.
 * @param[in] pdu Pointer to iSCSI source PDU which contains the rejected packet data.
 * @param[in] reason_code Reason code for rejected packet data.
 * @retval -1 An error occured during reject packet generation,
 * currently only happens on memory exhaustion.
 * @retval 0 Reject packet and PDU constructed and sent successfully to the client.
 */
static int iscsi_connection_handle_reject(iscsi_connection *conn, iscsi_pdu *pdu, const int reason_code)
{
	pdu->flags |= ISCSI_PDU_FLAGS_REJECTED;

	const uint32_t ds_len   = (uint32_t) sizeof(struct iscsi_bhs_packet) + ((uint32_t) pdu->bhs_pkt->total_ahs_len << 2UL);
	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 0U, conn->header_digest, ds_len, conn->data_digest );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_handle_reject: Out of memory while allocating iSCSI reject response PDU" );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_reject_packet *reject_pkt = (iscsi_reject_packet *) response_pdu->bhs_pkt;

	reject_pkt->opcode    = ISCSI_OPCODE_SERVER_REJECT;
	reject_pkt->flags     = -0x80;
	reject_pkt->reason    = (uint8_t) reason_code;
	reject_pkt->reserved  = 0U;
	iscsi_put_be32( (uint8_t *) &reject_pkt->total_ahs_len, ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	reject_pkt->reserved2 = 0ULL;
	reject_pkt->tag       = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
	reject_pkt->reserved3 = 0UL;
	iscsi_put_be32( (uint8_t *) &reject_pkt->stat_sn, conn->stat_sn++ );

	if ( conn->session != NULL ) {
		iscsi_put_be32( (uint8_t *) &reject_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
		iscsi_put_be32( (uint8_t *) &reject_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	} else {
		iscsi_put_be32( (uint8_t *) &reject_pkt->exp_cmd_sn, 1UL );
		iscsi_put_be32( (uint8_t *) &reject_pkt->max_cmd_sn, 1UL );
	}

	reject_pkt->reserved4 = 0ULL;

	memcpy( response_pdu->ds_cmd_data, pdu->bhs_pkt, ds_len );

	iscsi_connection_pdu_write( conn, response_pdu, NULL, NULL );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Updates Command Sequence Number (CmdSN) of an incoming iSCSI PDU request.
 *
 * This function updates the Command Sequence
 * Number (CmdSN) for incoming data sent by
 * the client.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_update_cmd_sn(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_session *session = conn->session;

	if ( session == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) pdu->bhs_pkt;
	const int opcode = ISCSI_GET_OPCODE(scsi_cmd_pkt->opcode);

	pdu->cmd_sn = iscsi_get_be32(scsi_cmd_pkt->cmd_sn);

	if ( session->err_recovery_level == 0UL ) {
		if ( (scsi_cmd_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 ) {
			if ( (iscsi_seq_num_cmp_lt( pdu->cmd_sn, session->exp_cmd_sn ) || iscsi_seq_num_cmp_gt( pdu->cmd_sn, session->max_cmd_sn )) && ((session->type == ISCSI_SESSION_TYPE_NORMAL) && (opcode != ISCSI_OPCODE_CLIENT_SCSI_DATA_OUT)) )
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		} else if ( (pdu->cmd_sn != session->exp_cmd_sn) && (opcode != ISCSI_OPCODE_CLIENT_NOP_OUT) )
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	uint32_t exp_stat_sn = iscsi_get_be32(scsi_cmd_pkt->exp_stat_sn);

	if ( iscsi_seq_num_cmp_gt( exp_stat_sn, conn->stat_sn ) )
		exp_stat_sn = conn->stat_sn;

	if ( session->err_recovery_level > 0UL )
		iscsi_connection_pdu_ack_remove( conn, exp_stat_sn );

	if ( ((scsi_cmd_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0) && (opcode != ISCSI_OPCODE_CLIENT_SCSI_DATA_OUT) )
		session->exp_cmd_sn++;

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI header login request PDU.
 *
 * This function handles login request header
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_login_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	if ( ((conn->flags & ISCSI_CONNECT_FLAGS_FULL_FEATURE) != 0) && (conn->session != NULL) && (conn->session->type == ISCSI_SESSION_TYPE_DISCOVERY) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	const iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) pdu->bhs_pkt;

	pdu->cmd_sn = iscsi_get_be32(login_req_pkt->cmd_sn);

	if ( pdu->ds_len > ISCSI_DEFAULT_RECV_DS_LEN )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	iscsi_pdu *login_response_pdu = iscsi_connection_pdu_create( conn, 0U, 0, ISCSI_DEFAULT_RECV_DS_LEN, 0 );

	if ( login_response_pdu == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	const int rc = iscsi_connection_pdu_login_response_init( login_response_pdu, pdu );

	if ( rc < 0 ) {
		iscsi_connection_pdu_login_response( conn, login_response_pdu, NULL, iscsi_connection_pdu_login_err_complete );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	conn->login_response_pdu = login_response_pdu;

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI header NOP-Out request PDU.
 *
 * This function handles NOP-Out request header
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_nop_out(iscsi_connection *conn, iscsi_pdu *pdu)
{
	if ( conn->session->type == ISCSI_SESSION_TYPE_DISCOVERY )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	if ( pdu->ds_len > ISCSI_DEFAULT_MAX_RECV_DS_LEN )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	iscsi_nop_out_packet *nop_out_pkt = (iscsi_nop_out_packet *) pdu->bhs_pkt;
	const uint32_t init_task_tag   = iscsi_get_be32(nop_out_pkt->init_task_tag);
	const uint32_t target_xfer_tag = iscsi_get_be32(nop_out_pkt->target_xfer_tag);

	if ( (target_xfer_tag != 0xFFFFFFFFUL) && (target_xfer_tag != (uint32_t) conn->id) )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_INVALID_PDU_FIELD ); // TODO: Check if this is the correct error code.

	if ( (init_task_tag == 0xFFFFFFFFUL) && (nop_out_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI header SCSI command request PDU.
 *
 * This function handles SCSI command request
 * header data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_scsi_cmd(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_scsi_cmd_packet *stat_scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) pdu->bhs_pkt;
	uint64_t stat_opcode = (uint64_t) stat_scsi_cmd_pkt->scsi_cdb.opcode;
	uint64_t *stat_value = NULL;
	int stat_rc = iscsi_hashmap_get( conn->stat_scsi_opcodes, (uint8_t *) &stat_opcode, sizeof(stat_opcode), (uint8_t **) &stat_value );

	if ( stat_value == NULL ) {
		stat_value = malloc( sizeof(uint64_t) );

		if ( stat_value != NULL ) {
			uint8_t *stat_key = iscsi_hashmap_key_create( (uint8_t *) &stat_opcode, sizeof(stat_opcode) );

			if ( stat_key != NULL ) {
				*stat_value = 0ULL;

				stat_rc = iscsi_hashmap_put( conn->stat_scsi_opcodes, stat_key, sizeof(stat_opcode), (uint8_t *) stat_value );

				if ( stat_rc < 0 ) {
					iscsi_hashmap_key_destroy( stat_key );
					free( stat_value );
					stat_value = NULL;
				}
			} else {
				free( stat_value );
				stat_value = NULL;
			}
		}
	}

	if ( stat_value != NULL )
		(*stat_value)++;

	if ( conn->session->type != ISCSI_SESSION_TYPE_NORMAL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) pdu->bhs_pkt;

	if ( (scsi_cmd_pkt->flags_task & (ISCSI_SCSI_CMD_FLAGS_TASK_READ | ISCSI_SCSI_CMD_FLAGS_TASK_WRITE)) == (ISCSI_SCSI_CMD_FLAGS_TASK_READ | ISCSI_SCSI_CMD_FLAGS_TASK_WRITE) ) // Bidirectional transfer is not supported
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_task *task = iscsi_task_create( conn, NULL, iscsi_scsi_task_xfer_complete );

	if ( task == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	uint32_t exp_xfer_len = iscsi_get_be32(scsi_cmd_pkt->exp_xfer_len);

	task->scsi_task.buf         = (uint8_t *) pdu->ds_cmd_data;
	task->scsi_task.len         = (uint) (((uint8_t *) pdu->ds_cmd_data) - ((uint8_t *) pdu->bhs_pkt));
	task->scsi_task.cdb         = &scsi_cmd_pkt->scsi_cdb;
	task->scsi_task.xfer_len    = exp_xfer_len;
	task->scsi_task.target_port = conn->target_port;
	task->scsi_task.init_port   = conn->init_port;
	task->init_task_tag         = iscsi_get_be32(scsi_cmd_pkt->init_task_tag);
	task->pdu                   = pdu;
	pdu->ref++;

	const uint64_t lun = iscsi_get_be64(scsi_cmd_pkt->lun);
	const int lun_id   = iscsi_scsi_lun_get_from_iscsi( lun );

	task->lun_id = lun_id;

	pthread_rwlock_rdlock( &conn->device->luns_rwlock );

	task->scsi_task.lun = iscsi_device_find_lun( conn->device, lun_id );

	pthread_rwlock_unlock( &conn->device->luns_rwlock );

	if ( task->scsi_task.lun == NULL ) {
		iscsi_scsi_task_lun_process_none( &task->scsi_task );
		iscsi_scsi_task_xfer_complete( &task->scsi_task );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	if ( ((scsi_cmd_pkt->flags_task & (ISCSI_SCSI_CMD_FLAGS_TASK_READ | ISCSI_SCSI_CMD_FLAGS_TASK_WRITE)) == 0) && (exp_xfer_len > 0UL) ) {
		iscsi_task_destroy( task );

		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_INVALID_PDU_FIELD );
	}

	if ( (scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_READ) != 0 ) {
		task->scsi_task.flags |= ISCSI_SCSI_TASK_FLAGS_XFER_READ;
	} else if ( (scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_WRITE) != 0 ) {
		task->scsi_task.flags |= ISCSI_SCSI_TASK_FLAGS_XFER_WRITE;

		if ( (conn->session->err_recovery_level > 0UL) && (iscsi_r2t_find_pdu_bhs( conn, pdu ) != NULL) ) {
			iscsi_task_response( conn, task );
			iscsi_task_destroy( task );

			return ISCSI_CONNECT_PDU_READ_OK;
		}

		if ( pdu->ds_len > (uint) (sizeof(struct iscsi_bhs_packet) + ISCSI_MAX_AHS_SIZE + conn->header_digest + iscsi_globvec->first_burst_len + conn->data_digest) ) {
			iscsi_task_destroy( task );

			return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );
		}

		if ( pdu->ds_len > exp_xfer_len ) {
			iscsi_task_destroy( task );

			return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );
		}

		if ( (((conn->session->flags & ISCSI_SESSION_FLAGS_IMMEDIATE_DATA) == 0) && (pdu->ds_len > 0UL)) || (pdu->ds_len > conn->session->first_burst_len) ) {
			iscsi_task_destroy( task );

			return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );
		}

		if ( ((scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_FINAL) != 0) && (pdu->ds_len < exp_xfer_len) ) {
			if ( exp_xfer_len > ISCSI_DEFAULT_MAX_RECV_DS_LEN )
				exp_xfer_len = ISCSI_DEFAULT_MAX_RECV_DS_LEN;

			pdu->len = exp_xfer_len;
		}
	}

	pdu->task = task;

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI header task management function request PDU.
 *
 * This function handles task management function
 * request header data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_task_func_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0;
}

/**
 * @brief Handles an incoming iSCSI header text request PDU.
 *
 * This function handles text request header
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_text_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	if ( pdu->ds_len > (uint) (sizeof(struct iscsi_bhs_packet) + ISCSI_MAX_AHS_SIZE + conn->header_digest + iscsi_globvec->first_burst_len + conn->data_digest) )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	iscsi_text_req_packet *text_req_pkt = (iscsi_text_req_packet *) pdu->bhs_pkt;

	const uint32_t init_task_tag = iscsi_get_be32(text_req_pkt->init_task_tag);
	const uint32_t exp_stat_sn   = iscsi_get_be32(text_req_pkt->exp_stat_sn);

	if ( exp_stat_sn != conn->stat_sn )
		conn->stat_sn = exp_stat_sn;

	if ( (text_req_pkt->flags & (ISCSI_TEXT_REQ_FLAGS_CONTINUE | ISCSI_TEXT_REQ_FLAGS_FINAL)) == (ISCSI_TEXT_REQ_FLAGS_CONTINUE | ISCSI_TEXT_REQ_FLAGS_FINAL) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	if ( conn->session->current_text_init_task_tag == 0xFFFFFFFFUL )
		conn->session->current_text_init_task_tag = init_task_tag;
	else
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Searches an iSCSI PDU by Basic Header Segment (BHS) in the Ready To Transfer (R2T) active and queued task hash map.
 *
 * This function searches for an iSCSI PDU by
 * iterating through the iSCSI connection active
 * and queued Ready To Transfer tasks hash map.
 *
 * @param[in] conn Pointer to iSCSI connection to
 * search in the active and queued Ready To
 * Transfer tasks hash map. May NOT be NULL, so
 * be careful.
 * @param[in] pdu Pointer to iSCSI PDU of which
 * the Basic Header Segment (BHS) should be
 * searched for. NULL is NOT allowed here, so
 * take caution.
 * @return Pointer to found iSCSI PDU or NULL in
 * case neither an iSCSI active nor enqueued
 * Ready To Transfer (R2T) task has a matching
 * Basic Header Segment (BHS).
 */
iscsi_pdu *iscsi_r2t_find_pdu_bhs(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_task *task;

	iscsi_list_foreach_node ( &conn->r2t_tasks_active, task ) {
		if ( memcmp( task->pdu->bhs_pkt, pdu->bhs_pkt, sizeof(struct iscsi_bhs_packet) ) == 0 )
			return task->pdu;
	}

	iscsi_list_foreach_node ( &conn->r2t_tasks_queue, task ) {
		if ( memcmp( task->pdu->bhs_pkt, pdu->bhs_pkt, sizeof(struct iscsi_bhs_packet) ) == 0 )
			return task->pdu;
	}

	return NULL;
}

/**
 * @brief Sends an iSCSI Ready To Transfer Sequence Number (R2TSN) packet to the initiator.
 *
 * This function allocates and initializes a
 * Ready To Transfer Sequence Number (R2TSN)
 * packet to be sent to the client.
 *
 * @param[in] conn Pointer to iSCSI connection which
 * maintains the R2TSN, may NOT be NULL,
 * so be careful.
 * @param[in] task Pointer to iSCSI task handling
 * the R2TSN. NULL is NOT allowed here,
 * take caution.
 * @param[in,out] r2t_sn Pointer to 32-bit integer containing
 * the R2TSN which is incremented after
 * storing it in the response packet data.
 * NULL is prohibited, so take caution.
 * @param[in] pos Offset in bytes of transfer data.
 * @param[in] len Length in bytes of transfer data.
 * @param[in] target_xfer_tag Target Transfer Tag (TTT) for data.
 * @return 0 on successful packet sending, a negative
 * error code otherwise.
 */
int iscsi_r2t_send(iscsi_connection *conn, iscsi_task *task, uint32_t *r2t_sn, const uint32_t pos, const uint32_t len, const uint32_t target_xfer_tag)
{
	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 0U, conn->header_digest, 0UL, conn->data_digest );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_r2t_send: Out of memory while allocating iSCSI Ready To Transfer response PDU" );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_r2t_packet *r2t_pkt = (iscsi_r2t_packet *) response_pdu->bhs_pkt;

	r2t_pkt->opcode                       = ISCSI_OPCODE_SERVER_READY_XFER;
	r2t_pkt->flags                        = -0x80;
	r2t_pkt->reserved                     = 0U;
	*(uint32_t *) &r2t_pkt->total_ahs_len = 0UL; // TotalAHSLength and DataSegmentLength are always 0, so write in one step.

	const uint64_t lun = iscsi_scsi_lun_get_from_scsi( task->lun_id );

	iscsi_put_be64( (uint8_t *) &r2t_pkt->lun, lun );
	iscsi_put_be32( (uint8_t *) &r2t_pkt->init_task_tag, task->init_task_tag );
	iscsi_put_be32( (uint8_t *) &r2t_pkt->target_xfer_tag, target_xfer_tag );
	iscsi_put_be32( (uint8_t *) &r2t_pkt->stat_sn, conn->stat_sn );
	iscsi_put_be32( (uint8_t *) &r2t_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &r2t_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	r2t_pkt->data_sn = 0UL;
	iscsi_put_be32( (uint8_t *) &r2t_pkt->r2t_sn, (*r2t_sn)++ );

	task->r2t_data_sn = 0UL;

	iscsi_put_be32( (uint8_t *) &r2t_pkt->buf_offset, (uint32_t) pos );
	iscsi_put_be32( (uint8_t *) &r2t_pkt->des_data_xfer_len, (uint32_t) len );

	response_pdu->task = task;
	task->scsi_task.ref++;

	iscsi_connection_pdu_write( conn, response_pdu, NULL, NULL );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Searches an iSCSI PDU task by Ready To Transfer Sequence Number (R2TSN) and removes it from PDU SNACK doubly linked list.
 *
 * This function searches for an iSCSI PDU task
 * by iterating through the iSCSI connection
 * Sequence Number Acknowledgement (SNACK)
 * and matches the Ready To Transfer Sequence
 * Number (R2TSN).\n
 * If found, the PDU will be removed from the
 * PDU SNACK doubly linked list.
 *
 * @param[in] conn Pointer to iSCSI connection to
 * search in the Sequence Number
 * Acknowledgement (SNACK) hash map. May NOT be
 * NULL, so be careful.
 * @param[in] task Pointer to iSCSI task to search
 * for in the Sequence Number Acknowledgement
 * (SNACK) hash map. NULL is not allowed here,
 * take caution.
 * @param[in] r2t_sn Ready To Transfer Sequence Number
 * (R2TSN) to be searched for.
 * @return Pointer to found iSCSI PDU or NULL in
 * case no iSCSI PDU has a matching Ready To Transfer
 * Sequence Number (R2TSN).
 */
static iscsi_pdu *iscsi_r2t_remove_pdu_from_snack_list(iscsi_connection *conn, iscsi_task *task, const uint32_t r2t_sn)
{
	iscsi_pdu *pdu;

	iscsi_list_foreach_node ( &conn->pdus_snack, pdu ) {
		if ( pdu->bhs_pkt->opcode == ISCSI_OPCODE_SERVER_READY_XFER ) {
			iscsi_r2t_packet *r2t_pkt = (iscsi_r2t_packet *) pdu->bhs_pkt;

			if ( (pdu->task == task) && (iscsi_get_be32(r2t_pkt->r2t_sn) == r2t_sn) ) {
				iscsi_list_remove( &pdu->node );

				return pdu;
			}
		}
	}

	return NULL;
}

/**
 * @brief Resends the Ready To Transfer (R2T) packet data.
 *
 * This function either sends a new R2T packet or
 * resends an already sent one.
 *
 * @param[in] conn Pointer to iSCSI connection to send the
 * R2T packet for, may NOT be NULL, so be careful.
 * @param[in] task Pointer to iSCSI task responsible for
 * sending the R2T packet. NULL is NOT allowed
 * here, take caution.
 * @param[in] r2t_sn_ack R2TSN acknowledged number.
 * @param[in] r2t_sn_send_new 0 resends an already sent
 * R2T packet, any other value will send a new
 * packet.
 * @return 0 if packet was sent successfully, a negative
 * error code otherwise.
 */
static int iscsi_r2t_recovery_send(iscsi_connection *conn, iscsi_task *task, const uint32_t r2t_sn_ack, const int r2t_sn_send_new)
{
	iscsi_pdu *pdu = iscsi_r2t_remove_pdu_from_snack_list( conn, task, r2t_sn_ack );

	if ( pdu == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_r2t_packet *r2t_pkt = (iscsi_r2t_packet *) pdu->bhs_pkt;

	if ( r2t_sn_send_new != 0 ) {
		const uint32_t des_data_xfer_len = r2t_pkt->des_data_xfer_len;

		task->r2t_sn_ack++;

		uint32_t len = (des_data_xfer_len - task->r2t_next_exp_pos);

		if ( len > conn->session->max_burst_len )
			len = conn->session->max_burst_len;

		iscsi_connection_pdu_free( conn, pdu );

		const int rc = iscsi_r2t_send( conn, task, &task->r2t_sn, task->r2t_next_exp_pos, len, task->target_xfer_tag );

		if ( rc < 0 )
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	} else {
		iscsi_put_be32( (uint8_t *) &r2t_pkt->stat_sn, conn->stat_sn );
		iscsi_connection_pdu_write( conn, pdu, NULL, NULL );
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI header SCSI data out PDU.
 *
 * This function handles header SCSI data out
 * sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_scsi_data_out(iscsi_connection *conn, iscsi_pdu *pdu)
{
	if ( conn->session->type == ISCSI_SESSION_TYPE_DISCOVERY )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	if ( pdu->ds_len > ISCSI_DEFAULT_MAX_RECV_DS_LEN )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	iscsi_scsi_data_out_req_packet *scsi_data_out_req_pkt = (iscsi_scsi_data_out_req_packet *) pdu->bhs_pkt;
	const uint32_t target_xfer_tag = iscsi_get_be32(scsi_data_out_req_pkt->target_xfer_tag);

	iscsi_task *task = iscsi_task_find( conn, target_xfer_tag );

	if ( task == NULL )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_INVALID_PDU_FIELD );

	pthread_rwlock_rdlock( &conn->device->luns_rwlock );

	iscsi_scsi_lun *lun = iscsi_device_find_lun( conn->device, task->lun_id );

	pthread_rwlock_unlock( &conn->device->luns_rwlock );

	if ( pdu->ds_len > ISCSI_DEFAULT_MAX_RECV_DS_LEN )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	const uint32_t init_task_tag = iscsi_get_be32(scsi_data_out_req_pkt->init_task_tag);

	if ( task->init_task_tag != init_task_tag )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_INVALID_PDU_FIELD );

	const uint32_t data_sn = iscsi_get_be32(scsi_data_out_req_pkt->data_sn);

	if ( data_sn != task->r2t_data_sn ) {
		if ( conn->session->err_recovery_level > 0UL ) {
			const int rc = iscsi_r2t_recovery_send( conn, task, task->r2t_sn_ack, 1 );

			if ( rc == 0 )
				return ISCSI_CONNECT_PDU_READ_OK;
		}

		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );
	}

	const uint32_t buf_offset = iscsi_get_be32(scsi_data_out_req_pkt->buf_offset);

	if ( buf_offset != task->r2t_next_exp_pos )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	const uint32_t xfer_len = task->scsi_task.xfer_len;

	task->r2t_len           = pdu->ds_len;
	task->r2t_next_exp_pos += pdu->ds_len;
	task->r2t_data_sn++;

	if ( task->r2t_len > conn->session->max_burst_len )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	if ( (int8_t) scsi_data_out_req_pkt->opcode < 0 )
		task->r2t_len = 0UL;

	if ( xfer_len == task->r2t_next_exp_pos ) {
		task->r2t_sn_ack++;
	} else if ( ((int8_t) scsi_data_out_req_pkt->opcode < 0) && (xfer_len > task->r2t_next_exp_pos) ) {
		task->r2t_sn_ack++;

		uint32_t len = (xfer_len - task->r2t_next_exp_pos);

		if ( len > conn->session->max_burst_len )
			len = conn->session->max_burst_len;

		const int rc = iscsi_r2t_send( conn, task, &task->r2t_sn, task->r2t_next_exp_pos, len, task->target_xfer_tag );

		if ( rc < 0 )
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

		task->r2t_next_exp_pos += len;
	}

	if ( lun == NULL )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	if ( task->scsi_task.buf != NULL ) {
		pdu->ds_cmd_data = (iscsi_scsi_ds_cmd_data *) (task->scsi_task.buf + task->len);
		pdu->ds_len      = ISCSI_DEFAULT_MAX_RECV_DS_LEN;
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI header logout request PDU.
 *
 * This function handles logout request header
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_logout_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_logout_req_packet *logout_req_pkt = (iscsi_logout_req_packet *) pdu->bhs_pkt;

	if ( (conn->session != NULL) && (conn->session->type == ISCSI_SESSION_TYPE_DISCOVERY) && (logout_req_pkt->reason_code != ISCSI_LOGOUT_REQ_REASON_CODE_CLOSE_SESSION) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 0U, conn->header_digest, 0UL, conn->data_digest );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_pdu_header_handle_logout_req: Out of memory while allocating iSCSI logout response PDU" );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_logout_response_packet *logout_response_pkt = (iscsi_logout_response_packet *) response_pdu->bhs_pkt;

	logout_response_pkt->opcode = ISCSI_OPCODE_SERVER_LOGOUT_RES;
	logout_response_pkt->flags  = -0x80;

	const uint16_t cid = iscsi_get_be16(logout_req_pkt->cid);

	if ( cid == conn->cid ) {
		conn->flags |= ISCSI_CONNECT_FLAGS_LOGGED_OUT;

		logout_response_pkt->response = ISCSI_LOGOUT_RESPONSE_CLOSED_SUCCESSFULLY;
	} else {
		logout_response_pkt->response = ISCSI_LOGOUT_RESPONSE_CID_NOT_FOUND;
	}

	logout_response_pkt->reserved                     = 0U;
	*(uint32_t *) &logout_response_pkt->total_ahs_len = 0UL; // TotalAHSLength and DataSegmentLength are always 0, so write in one step.
	logout_response_pkt->reserved2                    = 0ULL;
	logout_response_pkt->init_task_tag                = logout_req_pkt->init_task_tag; // Copying over doesn't change endianess.
	logout_response_pkt->reserved3                    = 0UL;
	iscsi_put_be32( (uint8_t *) &logout_response_pkt->stat_sn, conn->stat_sn++ );

	if ( conn->session != NULL ) {
		if ( conn->session->conns == 1UL )
			conn->session->max_cmd_sn++;

		iscsi_put_be32( (uint8_t *) &logout_response_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
		iscsi_put_be32( (uint8_t *) &logout_response_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	} else {
		iscsi_put_be32( (uint8_t *) &logout_response_pkt->exp_cmd_sn, pdu->cmd_sn );
		iscsi_put_be32( (uint8_t *) &logout_response_pkt->max_cmd_sn, pdu->cmd_sn );
	}

	logout_response_pkt->reserved4   = 0UL;
	logout_response_pkt->time_wait   = 0U;
	logout_response_pkt->time_retain = 0U;
	logout_response_pkt->reserved5   = 0UL;

	iscsi_connection_pdu_write( conn, response_pdu, NULL, NULL );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI header SNACK request PDU.
 *
 * This function handles SNACK request header
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_snack_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0;
}

/**
 * @brief Handles an incoming iSCSI header PDU.
 *
 * This function handles all header data sent
 * by the client, including authentication.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle(iscsi_connection *conn, iscsi_pdu *pdu)
{
	if ( pdu == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	const int opcode = ISCSI_GET_OPCODE(pdu->bhs_pkt->opcode);

	if ( opcode == ISCSI_OPCODE_CLIENT_LOGIN_REQ )
		return iscsi_connection_pdu_header_handle_login_req( conn, pdu );

	if ( ((conn->flags & ISCSI_CONNECT_FLAGS_FULL_FEATURE) == 0) && (conn->state == ISCSI_CONNECT_STATE_RUNNING) ) {
		iscsi_pdu *login_response_pdu = iscsi_connection_pdu_create( conn, 0U, 0, 0UL, 0 );

		if ( login_response_pdu == NULL )
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

		iscsi_connection_login_response_reject( login_response_pdu, pdu );
		iscsi_connection_pdu_write( conn, login_response_pdu, NULL, NULL );

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	} else if ( conn->state == ISCSI_CONNECT_STATE_INVALID ) {
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	int rc = iscsi_connection_update_cmd_sn( conn, pdu );

	if ( rc != 0 )
		return rc;

	switch ( opcode ) {
		case ISCSI_OPCODE_CLIENT_NOP_OUT : {
			rc = iscsi_connection_pdu_header_handle_nop_out( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_SCSI_CMD : {
			rc = iscsi_connection_pdu_header_handle_scsi_cmd( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_TASK_FUNC_REQ : {
			rc = iscsi_connection_pdu_header_handle_task_func_req( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_TEXT_REQ : {
			rc = iscsi_connection_pdu_header_handle_text_req( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_SCSI_DATA_OUT : {
			rc = iscsi_connection_pdu_header_handle_scsi_data_out( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_LOGOUT_REQ : {
			rc = iscsi_connection_pdu_header_handle_logout_req( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_SNACK_REQ : {
			rc = iscsi_connection_pdu_header_handle_snack_req( conn, pdu );

			break;
		}
		default : {
			return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

			break;
		}
	}

	if ( rc < 0 )
		logadd( LOG_ERROR, "Fatal error during header handler (opcode 0x%02x) detected for device %s", (int) opcode, (conn->device != NULL ? (char *) conn->device->name : "(null)") );

	return rc;
}

/**
 * @brief Handles an incoming iSCSI payload data NOP-Out request PDU.
 *
 * This function handles NOP-Out request payload
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_nop_out(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_nop_out_packet *nop_out_pkt = (iscsi_nop_out_packet *) pdu->bhs_pkt;
	uint32_t ds_len                   = pdu->ds_len;

	if ( ds_len > conn->max_recv_ds_len )
		ds_len = conn->max_recv_ds_len;

	const uint64_t lun           = iscsi_get_be64(nop_out_pkt->lun);
	const uint32_t init_task_tag = iscsi_get_be32(nop_out_pkt->init_task_tag);

	conn->flags &= ~ISCSI_CONNECT_FLAGS_NOP_OUTSTANDING;

	if ( init_task_tag == 0xFFFFFFFFUL )
		return ISCSI_CONNECT_PDU_READ_OK;

	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 0U, conn->header_digest, ds_len, conn->data_digest );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_pdu_data_handle_nop_out: Out of memory while allocating iSCSI NOP-In response PDU" );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_nop_in_packet *nop_in_pkt = (iscsi_nop_in_packet *) response_pdu->bhs_pkt;

	nop_in_pkt->opcode          = ISCSI_OPCODE_SERVER_NOP_IN;
	nop_in_pkt->flags           = -0x80;
	nop_in_pkt->reserved        = 0U;
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->total_ahs_len, ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	iscsi_put_be64( (uint8_t *) &nop_in_pkt->lun, lun );
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->init_task_tag, init_task_tag );
	nop_in_pkt->target_xfer_tag = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->stat_sn, conn->stat_sn++ );

	if ( (nop_out_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 )
		conn->session->max_cmd_sn++;

	iscsi_put_be32( (uint8_t *) &nop_in_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	nop_in_pkt->reserved2 = 0UL;
	nop_in_pkt->reserved3 = 0ULL;

	if ( ds_len != 0UL )
		memcpy( response_pdu->ds_cmd_data, pdu->ds_cmd_data, ds_len );

	iscsi_connection_pdu_write( conn, response_pdu, NULL, NULL );

	// conn->nop_in_last = iscsi_get_ticks();

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI payload data SCSI read command request PDU.
 *
 * This function handles SCSI read command request
 * payload data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] task Pointer to iSCSI task associated for reading.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_scsi_cmd_read(iscsi_connection *conn, iscsi_task *task)
{
	if ( task->scsi_task.xfer_len <= ISCSI_DEFAULT_MAX_RECV_DS_LEN ) {
		task->parent        = NULL;
		task->scsi_task.buf = NULL;
		task->scsi_task.pos = 0UL;
		task->scsi_task.len = task->scsi_task.xfer_len;

		iscsi_task_queue( conn, task );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	iscsi_list_create( &task->sub_tasks );

	task->pos = 0UL;

	iscsi_list_enqueue( &conn->scsi_data_in_queued_tasks, &task->node );

	return iscsi_connection_handle_scsi_data_in_queued_tasks( conn );
}

/**
 * @brief Creates and submits a sub task for writing.
 *
 * This function is also assigns the task with
 * an iSCSI PDU.
 *
 * @param[in] conn Pointer to iSCSI connection which handles
 * this task. May NOT be NULL, so be caureful.
 * @param[in] task Pointer to iSCSI task which should be the
 * parent of the new sub task. NULL if NOT
 * allowed here, so take caution.
 * @param[in] pdu Pointer to iSCSI PDU which contains
 * the desired buffer length to write. NULL
 * is a prohibited value here, take caution.
 * @param[in] buf Pointer to buffer containing
 * the write data and may NOT be NULL, so
 * be careful.
 * @return 0 on successful sub task submit or a
 * negative error code otherwise.
 */
static int iscsi_task_sub_task_submit_write(iscsi_connection *conn, iscsi_task *task, iscsi_pdu *pdu, uint8_t *buf)
{
	iscsi_task *sub_task = iscsi_task_create( conn, task, iscsi_scsi_task_xfer_complete );

	if ( sub_task == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	sub_task->scsi_task.buf = buf;
	sub_task->scsi_task.pos = task->pos;
	sub_task->scsi_task.len = pdu->ds_len;

	pdu->task = sub_task;
	pdu->ref++;

	task->pos += pdu->ds_len;

	iscsi_task_queue( conn, sub_task );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI payload data SCSI write command request PDU.
 *
 * This function handles SCSI write command
 * request payload data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] task Pointer to iSCSI task associated for reading.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_scsi_cmd_write(iscsi_connection *conn, iscsi_task *task)
{
	iscsi_pdu *pdu                      = task->pdu;
	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) pdu->bhs_pkt;
	const uint32_t xfer_len             = task->scsi_task.xfer_len;

	if ( ((scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_FINAL) != 0) && (pdu->ds_len < xfer_len) ) {
		int rc = iscsi_task_xfer_add( conn, task );

		if ( rc < 0 ) {
			iscsi_task_destroy( task );

			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		}

		if ( pdu->ds_len != 0UL ) {
			rc = iscsi_task_sub_task_submit_write( conn, task, pdu, (uint8_t *) pdu->ds_cmd_data );

			if ( rc < 0 ) {
				iscsi_task_destroy( task );

				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
			}
		}

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	if ( pdu->ds_len == xfer_len ) {
		iscsi_scsi_task *scsi_task = &task->scsi_task;

		scsi_task->buf = (uint8_t *) pdu->ds_cmd_data;
		scsi_task->len = xfer_len;
	}

	iscsi_task_queue( conn, task );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI payload data SCSI command request PDU.
 *
 * This function handles SCSI command request payload
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_scsi_cmd(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_task *task = pdu->task;

	if ( task == NULL )
		return ISCSI_CONNECT_PDU_READ_OK;

	pthread_rwlock_rdlock( &conn->device->luns_rwlock );

	if ( iscsi_device_find_lun( conn->device, task->lun_id ) == NULL ) {
		pthread_rwlock_unlock( &conn->device->luns_rwlock );
		iscsi_scsi_task_lun_process_none( &task->scsi_task );
		iscsi_scsi_task_xfer_complete( &task->scsi_task );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	pthread_rwlock_unlock( &conn->device->luns_rwlock );

	if ( (task->scsi_task.flags & ISCSI_SCSI_TASK_FLAGS_XFER_READ) != 0 ) {
		return iscsi_connection_pdu_data_handle_scsi_cmd_read( conn, task );
	} else if ( (task->scsi_task.flags & ISCSI_SCSI_TASK_FLAGS_XFER_WRITE) != 0 ) {
		return iscsi_connection_pdu_data_handle_scsi_cmd_write( conn, task );
	} else if ( (task->scsi_task.flags & (ISCSI_SCSI_TASK_FLAGS_XFER_READ | ISCSI_SCSI_TASK_FLAGS_XFER_WRITE)) == 0 ) {
		iscsi_task_queue( conn, task );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	pdu->task = NULL;
	iscsi_task_destroy( task );

	return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
}

/**
 * @brief Negotiates connection authentication method (none or CHAP).
 *
 * This function updates the key and value pairs if, and only if
 * CHAP is either disabled or required.
 *
 * @param[in] conn Pointer to iSCSI connection to update the key
 * and value pairs for. May NOT be NULL, so be careful.
 * @return 0 on successful update, a negative error code otherwise.
 */
static int iscsi_connection_chap_negotiate(iscsi_connection *conn)
{
	int rc = 0;

	if ( (conn->flags & ISCSI_CONNECT_FLAGS_CHAP_DISABLE) != 0 )
		rc = iscsi_update_key_value_pair( conn->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD, (uint8_t *) "None" );
	else if ( (conn->flags & ISCSI_CONNECT_FLAGS_CHAP_REQUIRE) != 0 )
		rc = iscsi_update_key_value_pair( conn->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD, (uint8_t *) "CHAP" );

	return rc;
}

/**
 * @brief Discovers iSCSI CHAP authentication session.
 *
 * This function copies over the global CHAP configuration
 * into the iSCSI connection structure and then negotiates.
 *
 * @param[in] conn Pointer to iSCSI connection for iSCSI
 * CHAP authentication discovery. May NOT be
 * NULL, so be careful.
 * @return 0 on successful negotiation, a negative error
 * code otherwise.
 */
static int iscsi_connection_login_session_chap_discovery(iscsi_connection *conn)
{
	conn->flags &= ~(ISCSI_CONNECT_FLAGS_CHAP_DISABLE | ISCSI_CONNECT_FLAGS_CHAP_REQUIRE | ISCSI_CONNECT_FLAGS_CHAP_MUTUAL);

	if ( (iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_CHAP_DISABLE) != 0 )
		conn->flags |= ISCSI_CONNECT_FLAGS_CHAP_DISABLE;

	if ( (iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_CHAP_REQUIRE) != 0 )
		conn->flags |= ISCSI_CONNECT_FLAGS_CHAP_REQUIRE;

	if ( (iscsi_globvec->flags & ISCSI_GLOBALS_FLAGS_CHAP_MUTUAL) != 0 )
		conn->flags |= ISCSI_CONNECT_FLAGS_CHAP_MUTUAL;

	conn->chap_group = iscsi_globvec->chap_group;

	return iscsi_connection_chap_negotiate( conn );
}

/**
 * @brief Negotiates CHAP authentication.
 *
 * This function updates the key and value pairs if, and only if
 * CHAP authentication is either disabled or required in the
 * target node.
 *
 * @param[in] conn Pointer to iSCSI connection to update the key
 * and value pairs for. May NOT be NULL, so be careful.
 * @param[in] target Pointer to iSCSI target node used to check
 * the CHAP authentication. NULL is not allowed here,
 * so take caution.
 * @return 0 on successful update, a negative error code otherwise.
 */
static int iscsi_connection_login_chap_negotiate(iscsi_connection *conn, const iscsi_target_node *target)
{
	conn->flags &= ~(ISCSI_CONNECT_FLAGS_CHAP_DISABLE | ISCSI_CONNECT_FLAGS_CHAP_REQUIRE | ISCSI_CONNECT_FLAGS_CHAP_MUTUAL);

	if ( (target->flags & ISCSI_TARGET_NODE_FLAGS_CHAP_DISABLE) != 0 )
		conn->flags |= ISCSI_CONNECT_FLAGS_CHAP_DISABLE;

	if ( (target->flags & ISCSI_TARGET_NODE_FLAGS_CHAP_REQUIRE) != 0 )
		conn->flags |= ISCSI_CONNECT_FLAGS_CHAP_REQUIRE;

	if ( (target->flags & ISCSI_TARGET_NODE_FLAGS_CHAP_MUTUAL) != 0 )
		conn->flags |= ISCSI_CONNECT_FLAGS_CHAP_MUTUAL;

	conn->chap_group = target->chap_group;

	return iscsi_connection_chap_negotiate( conn );
}

/**
 * @brief Negotiates connection header and data digest (CRC32C).
 *
 * This function updates the key and value pairs if, and only if
 * header and data digests are enabled in the target node.
 *
 * @param[in] conn Pointer to iSCSI connection to update the key
 * and value pairs for. May NOT be NULL, so be careful.
 * @param[in] target Pointer to iSCSI target node used to check
 * the digest status. NULL is not allowed here, so take
 * caution.
 * @return 0 on successful update, a negative error code otherwise.
 */
static int iscsi_connection_login_digest_negotiate(iscsi_connection *conn, const iscsi_target_node *target)
{
	int rc = 0;

	if ( target->header_digest != 0 )
		rc = iscsi_update_key_value_pair( conn->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST, (uint8_t *) "CRC32C" );

	if ( target->data_digest != 0 )
		rc = iscsi_update_key_value_pair( conn->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST, (uint8_t *) "CRC32C" );

	return rc;
}

/**
 * @brief Determines iSCSI session login steps for normal authentication.
 *
 * This function also does related validation checks.
 *
 * @param[in] conn Pointer to iSCSI connection, may NOT be
 * NULL, so take caution.
 * @param[in] login_response_pdu Pointer to login response PDU where
 * NULL is not allowed, so be careful.
 * @param[in] key_value_pairs Pointer to hash map containing the login
 * request key and value pairs and may NOT be NULL, so
 * take caution.
 * @param[in] init_port_name Pointer to iSCSI initiator port name. NULL
 * is NOT an allowed value, so be careful.
 * @param[in] cid Connection ID (CID).
 * @return 0 on successful operation, a negative error code
 * otherwise.
 */
static int iscsi_connection_login_session_normal(iscsi_connection *conn, iscsi_pdu *login_response_pdu, iscsi_hashmap *key_value_pairs, uint8_t *init_port_name, const uint cid)
{
	iscsi_target_node *target = NULL;
	uint8_t *target_name;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
	int rc = iscsi_get_key_value_pair( key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_NAME, &target_name );

	if ( (rc < 0) || (target_name == NULL) ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	const uint8_t *target_name_short = (uint8_t *) strstr( (char *) target_name, ":" );

	conn->target_name_short = iscsi_sprintf_alloc( "%s", ((target_name_short != NULL) ? ++target_name_short : target_name) );

	if ( conn->target_name_short == NULL ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	rc = iscsi_connection_login_check_target( conn, login_response_pdu, target_name, &target );

	if ( rc < 0 )
		return rc;

	conn->device      = target->device;
	conn->target      = target;
	conn->target_port = iscsi_device_find_port_by_portal_group_tag( target->device, conn->pg_tag );

	rc = iscsi_connection_login_check_session( conn, login_response_pdu, init_port_name, cid );

	if ( rc < 0 )
		return rc;

	rc = iscsi_connection_login_chap_negotiate( conn, target );

	if ( rc == 0 )
		rc = iscsi_connection_login_digest_negotiate( conn, target );

	if (rc != 0) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_INVALID_LOGIN_REQ_TYPE;
	}

	return rc;
}

/*
 * This function is used to set the info in the connection data structure
 * return
 * 0: success
 * otherwise: error
 */
static int iscsi_connection_login_set_info(iscsi_connection *conn, iscsi_pdu *login_response_pdu, const uint8_t *init_port_name, const int type, const uint cid)
{
	conn->flags          &= ~ISCSI_CONNECT_FLAGS_AUTH;
	conn->auth_chap.phase = ISCSI_AUTH_CHAP_PHASE_WAIT_A;
	conn->cid             = (uint16_t) cid;

	if ( conn->session == NULL ) {
		iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
		iscsi_target_node *target = conn->target;
		const uint64_t isid = iscsi_connection_get_isid( &login_response_pkt->isid );
		iscsi_port *init_port = iscsi_port_create( init_port_name, isid, 0U );

		if ( init_port == NULL ) {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}

		conn->session = iscsi_session_create( conn, target, type );

		if ( conn->session == NULL ) {
			iscsi_port_destroy( init_port );

			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}

		conn->session->init_port = init_port;
		conn->stat_sn            = iscsi_get_be32(login_response_pkt->stat_sn);
		conn->session->isid      = isid;

		pthread_rwlock_wrlock( &iscsi_globvec->sessions_rwlock );
		iscsi_hashmap_key_create_id( iscsi_globvec->sessions, &conn->session->tsih );

		int rc = iscsi_hashmap_put( iscsi_globvec->sessions, (uint8_t *) &conn->session->tsih, sizeof(conn->session->tsih), (uint8_t *) conn->session );

		pthread_rwlock_unlock( &iscsi_globvec->sessions_rwlock );

		if ( rc < 0 ) {
			iscsi_session_destroy( conn->session );
			conn->session = NULL;

			iscsi_port_destroy( init_port );

			return rc;
		}

		rc = iscsi_port_transport_id_set( conn->session->init_port, conn->init_name, isid );

		if ( rc < 0 ) {
			iscsi_session_destroy( conn->session );
			conn->session = NULL;

			iscsi_port_destroy( init_port );

			return rc;
		}

		conn->session->queue_depth = ((target != NULL) ? target->queue_depth : 1U);
		conn->session->exp_cmd_sn  = login_response_pdu->cmd_sn;
		conn->session->max_cmd_sn  = (uint32_t) (login_response_pdu->cmd_sn + (uint32_t) conn->session->queue_depth - 1UL);
	}

	conn->init_port = conn->session->init_port;

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Sets iSCSI session target info key and value pairs.
 *
 * This function also sets the login response PDU
 * key and value pairs.
 *
 * @param[in] conn Pointer to iSCSI connection of which
 * the target info should be set, may NOT be NULL,
 * so take caution.
 * @param[in] login_response_pdu Pointer to login response PDU and
 * NULL is not allowed here, so be careful.
 * @param[in] type iSCSI session type.
 * @return 0 on successfully setting target info, a
 * negative error code otherwise.
 */
static int iscsi_connection_login_set_target_info(iscsi_connection *conn, iscsi_pdu *login_response_pdu, const int type)
{
	iscsi_target_node *target = conn->target;
	int rc;

	if ( target != NULL ) {
		rc = iscsi_update_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, ((target->alias != NULL) ? target->alias : (uint8_t *) "") );

		if ( rc < 0 )
			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;
	}

	uint8_t *tmp_buf = iscsi_sprintf_alloc( "%s:%s,%" PRIu64, conn->portal_host, conn->portal_port, conn->pg_tag );

	if ( tmp_buf == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	rc = iscsi_update_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, tmp_buf );

	free( tmp_buf );

	if ( rc < 0 )
		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;

	rc = iscsi_update_int_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, (int32_t) conn->pg_tag );

	if ( rc < 0 )
		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;

	if ( target != NULL ) {
		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, &tmp_buf );

		if ( (rc == 0) && (strlen( (char *) tmp_buf ) != 0) ) {
			iscsi_key_value_pair *key_value_pair;
			rc = iscsi_hashmap_get( iscsi_globvec->session_key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, strlen( (char *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS ) + 1, (uint8_t **) &key_value_pair);

			if ( rc < 0 )
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

			const int32_t ds_len = iscsi_append_key_value_pair_packet( key_value_pair, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, tmp_buf, (uint8_t *) login_response_pdu->ds_cmd_data, login_response_pdu->ds_len, login_response_pdu->len );

			if ( ds_len < 0L )
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

			login_response_pdu->len = ds_len;
		}

		if ( type == ISCSI_SESSION_TYPE_DISCOVERY ) {
			rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, &tmp_buf );

			if ( (rc == 0) && (strlen( (char *) tmp_buf ) != 0) ) {
				iscsi_key_value_pair *key_value_pair;
				rc = iscsi_hashmap_get( iscsi_globvec->session_key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, strlen( (char *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS ) + 1, (uint8_t **) &key_value_pair);

				if ( rc < 0 )
					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				const int32_t ds_len = iscsi_append_key_value_pair_packet( key_value_pair, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, tmp_buf, (uint8_t *) login_response_pdu->ds_cmd_data, login_response_pdu->ds_len, login_response_pdu->len );

				if ( ds_len < 0L )
					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				login_response_pdu->ds_len = ds_len;
			}
		}

		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, &tmp_buf );

		if ( rc == 0 ) {
			iscsi_key_value_pair *key_value_pair;
			rc = iscsi_hashmap_get( iscsi_globvec->session_key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, strlen( (char *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG ) + 1, (uint8_t **) &key_value_pair);

			if ( rc < 0 )
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

			const int32_t ds_len = iscsi_append_key_value_pair_packet( key_value_pair, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, tmp_buf, (uint8_t *) login_response_pdu->ds_cmd_data, login_response_pdu->ds_len, login_response_pdu->len );

			if ( ds_len < 0L )
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

			login_response_pdu->ds_len = ds_len;
		}
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles iSCSI connection login phase none.
 *
 * This function negotiates the login phase
 * without a session.
 *
 * @param[in] conn Pointer to iSCSI connection,
 * may NOT be NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU.
 * NULL is not allowed here, so take caution.
 * @param[in] key_value_pairs Pointer to key and value pairs.
 * which may NOT be NULL, so take caution.
 * @param[in] cid Connection ID (CID).
 * @return 0 on success, a negative error code otherwise.
 */
static int iscsi_connection_handle_login_phase_none(iscsi_connection *conn, iscsi_pdu *login_response_pdu, iscsi_hashmap *key_value_pairs, uint cid)
{
	uint8_t *init_port_name = NULL;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	conn->device = NULL;
	conn->target = NULL;

	int rc = iscsi_connection_login_init_port( conn, login_response_pdu, key_value_pairs, &init_port_name );

	if ( rc < 0 ) {
		if ( init_port_name != NULL )
			free( init_port_name );

		return rc;
	}

	int type;

	rc = iscsi_connection_login_session_type( login_response_pdu, key_value_pairs, &type );

	if ( rc < 0 ) {
		free( init_port_name );

		return rc;
	}

	if ( type == ISCSI_SESSION_TYPE_NORMAL ) {
		rc = iscsi_connection_login_session_normal( conn, login_response_pdu, key_value_pairs, init_port_name, cid );
	} else if ( type == ISCSI_SESSION_TYPE_DISCOVERY ) {
		login_response_pkt->tsih = 0U;

		rc = iscsi_connection_login_session_chap_discovery( conn );
	} else {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

		rc = ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	if ( rc < 0 ) {
		free( init_port_name );

		return rc;
	}

	rc = iscsi_connection_login_set_info( conn, login_response_pdu, init_port_name, type, cid );

	free( init_port_name );

	if ( rc < 0 )
		return rc;

	if ( type == ISCSI_SESSION_TYPE_DISCOVERY ) {
		conn->session->max_conns = 1UL;

		rc = iscsi_add_int_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS, conn->session->max_conns );

		if ( rc < 0 )
			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;
	}

	return iscsi_connection_login_set_target_info( conn, login_response_pdu, type );
}

/**
 * @brief Handles the Current Stage (CSG) bit of login response.
 *
 * This function determines the authentication method
 * and processes the various authentication stages.
 *
 * @param[in] conn Pointer to iSCSI connection, may NOT be
 * NULL, so take caution.
 * @param[in] login_response_pdu Pointer to login response PDU.
 * NULL is NOT an allowed value here, so be careful.
 * @param[in] key_value_pairs Pointer to key and value pairs to
 * retrieve authentication details from. This
 * is NOT allowed to be NULL. Be careful!
 * @return 0 if authentication has been handled successfully,
 * a negative error code otherwise.
 */
static int iscsi_connecction_handle_login_response_csg_bit(iscsi_connection *conn, iscsi_pdu *login_response_pdu, iscsi_hashmap *key_value_pairs)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	switch ( ISCSI_LOGIN_RESPONSE_FLAGS_GET_CURRENT_STAGE(login_response_pkt->flags) ) {
		case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION : {
			uint8_t *auth_method;
			const int rc = iscsi_get_key_value_pair( key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD, (uint8_t **) &auth_method );

			if ( rc < 0 ) {
				login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
				login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

				return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
			}

			if ( strcasecmp( (char *) auth_method, "None" ) == 0 ) {
				conn->flags |= ISCSI_CONNECT_FLAGS_AUTH;
			} else {
				const int32_t ds_len = iscsi_connection_auth_key_value_pairs( conn, key_value_pairs, auth_method, (uint8_t *) login_response_pdu->ds_cmd_data, login_response_pdu->ds_len, login_response_pdu->len );

				if ( ds_len < 0L ) {
					login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
					login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

					return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
				}

				login_response_pdu->ds_len = ds_len;

				if ( (conn->flags & ISCSI_CONNECT_FLAGS_AUTH) == 0 )
					login_response_pkt->flags &= (int8_t) ~ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT;
			}

			break;
		}
		case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION : {
			if ( conn->state == ISCSI_CONNECT_STATE_INVALID ) {
				if ( conn->flags & ISCSI_CONNECT_FLAGS_CHAP_REQUIRE ) {
					login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
					login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

					return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
				} else {
					conn->flags |= ISCSI_CONNECT_FLAGS_AUTH;
				}
			}

			if ( (conn->flags & ISCSI_CONNECT_FLAGS_AUTH) == 0 ) {
				login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
				login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

				return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
			}

			break;
		}
		case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FULL_FEATURE_PHASE : {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;

			break;
		}
		default : {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;

			break;
		}
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 *
 * @brief Checks whether the session type is valid.
 *
 * This function also can be used to output
 * debugging info about the session, which
 * is currently not implemented.
 *
 * @param[in] conn Pointer to iSCSI connection to be checked for
 * validity. May NOT be NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU to
 * set status class and detail in case of an error.
 * NULL is not an allowed value here, take caution.
 * @return 0 if the session type is valid, a negative error code
 * otherwise.
 */
static int iscsi_connection_login_session_info_notify(iscsi_connection *conn, iscsi_pdu *login_response_pdu)
{
	if ( (conn->session->type != ISCSI_SESSION_TYPE_NORMAL) && (conn->session->type != ISCSI_SESSION_TYPE_DISCOVERY) ) {
		iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles the Transit (T) bit of login response.
 *
 * This function handles the transitional stages
 * of the authentication process.
 *
 * @param[in] conn Pointer to iSCSI connection, may NOT be
 * NULL, so take caution.
 * @param[in] login_response_pdu Pointer to login response PDU.
 * NULL is NOT an allowed value here, so be careful.
 * @return 0 if transition has been handled successfully,
 * a negative error code otherwise.
 */
static int iscsi_connecction_handle_login_response_t_bit(iscsi_connection *conn, iscsi_pdu *login_response_pdu)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	switch ( ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(login_response_pkt->flags) ) {
		case ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION : {
			conn->login_phase = ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION;

			break;
		}
		case ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION : {
			conn->login_phase = ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION;

			break;
		}
		case ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FULL_FEATURE_PHASE : {
			conn->login_phase = ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FULL_FEATURE_PHASE;

			iscsi_put_be16( (uint8_t *) &login_response_pkt->tsih, (uint16_t) conn->session->tsih );

			const int rc = iscsi_connection_login_session_info_notify( conn, login_response_pdu );

			if ( rc < 0 )
				return rc;

			conn->flags |= ISCSI_CONNECT_FLAGS_FULL_FEATURE;

			break;
		}
		default : {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;

			break;
		}
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles iSCSI connection login response.
 *
 * This function negotiates the login parameters
 * and determines the authentication method.
 *
 * @param[in] conn Pointer to iSCSI connection,
 * may NOT be NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU.
 * NULL is not allowed here, so take caution.
 * @param[in] key_value_pairs Pointer to key and value pairs.
 * which may NOT be NULL, so take caution.
 * @return 0 on success, a negative error code otherwise.
 */
static int iscsi_connecction_handle_login_response(iscsi_connection *conn, iscsi_pdu *login_response_pdu, iscsi_hashmap *key_value_pairs)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
	const int32_t ds_len = iscsi_negotiate_key_value_pairs( conn, key_value_pairs, (uint8_t *) login_response_pdu->ds_cmd_data, login_response_pdu->ds_len, login_response_pdu->len );

	if ( ds_len < 0L ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	login_response_pdu->ds_len = (uint32_t) ds_len;

	int rc = iscsi_connecction_handle_login_response_csg_bit( conn, login_response_pdu, key_value_pairs );

	if ( rc < 0 )
		return rc;

	if ( (login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0 )
		rc = iscsi_connecction_handle_login_response_t_bit( conn, login_response_pdu );

	return rc;
}

/**
 * @brief Handles an incoming iSCSI payload data login request PDU.
 *
 * This function handles login request payload
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_login_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_pdu *login_response_pdu = (iscsi_pdu *) conn->login_response_pdu;

	if ( login_response_pdu == NULL )
		return ISCSI_CONNECT_PDU_READ_OK;

	iscsi_hashmap *key_value_pairs = iscsi_hashmap_create( (((sizeof(iscsi_session_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1) + ((sizeof(iscsi_connection_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1)) );

	if ( key_value_pairs == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) pdu->bhs_pkt;
	uint cid = iscsi_get_be16(login_req_pkt->cid);
	int rc = iscsi_connection_save_incoming_key_value_pairs( conn, key_value_pairs, login_response_pdu, pdu );

	if ( rc < 0 ) {
		iscsi_connection_pdu_login_response( conn, login_response_pdu, NULL, iscsi_connection_pdu_login_err_complete );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	if ( conn->state == ISCSI_CONNECT_STATE_INVALID ) {
		rc = iscsi_connection_handle_login_phase_none( conn, login_response_pdu, key_value_pairs, cid );

		if ( (rc == ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE) || (rc == ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER) ) {
			iscsi_connection_pdu_login_response( conn, login_response_pdu, key_value_pairs, iscsi_connection_pdu_login_err_complete );

			return ISCSI_CONNECT_PDU_READ_OK;
		}
	}

	rc = iscsi_connecction_handle_login_response( conn, login_response_pdu, key_value_pairs );

	if ( rc == ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE ) {
		iscsi_connection_pdu_login_response( conn, login_response_pdu, key_value_pairs, iscsi_connection_pdu_login_err_complete );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	conn->state = ISCSI_CONNECT_STATE_RUNNING;

	iscsi_connection_pdu_login_response( conn, login_response_pdu, key_value_pairs, iscsi_connection_pdu_login_ok_complete );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Callback function after text response has been sent.
 *
 * This function is invoked after the text
 * response has been sent to the client via
 * TCP/IP.
 *
 * @param[in] user_data Pointer to iSCSI connection which
 * was used for sending the response.
 */
static void iscsi_connection_pdu_text_complete(uint8_t *user_data)
{
	iscsi_connection *conn = (iscsi_connection *) user_data;

	iscsi_connection_update_key_value_pairs( conn );
}

/**
 * @brief Handles an incoming iSCSI payload data text request PDU.
 *
 * This function handles text request payload
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_text_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_hashmap *key_value_pairs = iscsi_hashmap_create( (((sizeof(iscsi_session_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1) + ((sizeof(iscsi_connection_key_value_pair_lut) / sizeof(struct iscsi_key_value_pair_lut_entry)) - 1)) );

	if ( key_value_pairs == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_text_req_packet *text_req_pkt = (iscsi_text_req_packet *) pdu->bhs_pkt;
	int rc = iscsi_parse_key_value_pairs( key_value_pairs, (uint8_t *) pdu->ds_cmd_data, pdu->ds_len, ((text_req_pkt->flags & ISCSI_TEXT_REQ_FLAGS_CONTINUE) != 0), &conn->text_partial_pairs );

	if ( rc < 0 ) {
		iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( key_value_pairs );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	if ( (pdu->ds_len == 0UL) && (iscsi_hashmap_size( key_value_pairs ) == 0U) ) {
		iscsi_hashmap *tmp_hashmap = key_value_pairs;
		key_value_pairs            = conn->text_key_value_pairs;
		conn->text_key_value_pairs = tmp_hashmap;
	}

	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 0U, conn->header_digest, conn->max_recv_ds_len, conn->data_digest );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_pdu_data_handle_text_req: Out of memory while allocating iSCSI text response PDU" );

		iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( key_value_pairs );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	response_pdu->ds_len = 0UL;

	int32_t ds_len = iscsi_negotiate_key_value_pairs( conn, key_value_pairs, (uint8_t *) response_pdu->ds_cmd_data, response_pdu->ds_len, response_pdu->len );

	if ( ds_len < 0L ) {
		iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( key_value_pairs );
		iscsi_connection_pdu_destroy( response_pdu );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_text_response_packet *text_response_pkt = (iscsi_text_response_packet *) response_pdu->bhs_pkt;

	text_response_pkt->opcode = ISCSI_OPCODE_SERVER_TEXT_RES;
	text_response_pkt->flags  = 0;

	if ( (text_req_pkt->flags & ISCSI_TEXT_REQ_FLAGS_CONTINUE) != 0 )
		text_response_pkt->flags |= (int8_t) ISCSI_TEXT_RESPONSE_FLAGS_CONTINUE;

	if ( (text_req_pkt->flags & ISCSI_TEXT_REQ_FLAGS_FINAL) != 0 )
		text_response_pkt->flags |= (int8_t) ISCSI_TEXT_RESPONSE_FLAGS_FINAL;

	text_req_pkt->reserved = 0U;

	uint8_t *send_targets_val;
	rc = iscsi_get_key_value_pair( key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_SEND_TARGETS, &send_targets_val );

	if ( rc < 0 ) {
		uint8_t *type_val;
		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, &type_val );

		if ( (rc >= 0) && (type_val != NULL) && (strcasecmp( (char *) type_val, "Discovery" ) == 0) ) {
			iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( key_value_pairs );
			iscsi_connection_pdu_destroy( response_pdu );

			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		}
	} else {
		uint8_t *type_val;
		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, &type_val );

		if ( (rc >= 0) && (type_val != NULL) && (strcasecmp( (char *) type_val, "Discovery" ) == 0) ) {
			if ( send_targets_val[0] == '\0' )
				send_targets_val = (uint8_t *) "ALL";

			ds_len = iscsi_target_node_send( conn, send_targets_val, conn->init_name, (uint8_t *) response_pdu->ds_cmd_data, ds_len, response_pdu->len );
		} else {
			if ( send_targets_val[0] == '\0' )
				send_targets_val = conn->target_port->name;

			if ( strcasecmp( (char *) send_targets_val, "ALL" ) == 0 ) {
				iscsi_key_value_pair *key_value_pair;
				rc = iscsi_hashmap_get( iscsi_globvec->session_key_value_pairs, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_SEND_TARGETS, strlen( (char *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_SEND_TARGETS ) + 1, (uint8_t **) &key_value_pair);

				if ( rc < 0 ) {
					iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
					iscsi_hashmap_destroy( key_value_pairs );
					iscsi_connection_pdu_destroy( response_pdu );

					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
				}

				ds_len = iscsi_append_key_value_pair_packet( key_value_pair, ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_SEND_TARGETS, (uint8_t *) "Reject", (uint8_t *) response_pdu->ds_cmd_data, ds_len, response_pdu->len );
			} else {
				ds_len = iscsi_target_node_send( conn, send_targets_val, conn->init_name, (uint8_t *) response_pdu->ds_cmd_data, ds_len, response_pdu->len );
			}
		}

		if ( conn->target_send_total_size == 0U ) {
			text_response_pkt->flags |= (int8_t) ISCSI_TEXT_RESPONSE_FLAGS_CONTINUE;
			text_response_pkt->flags &= (int8_t) ~ISCSI_TEXT_RESPONSE_FLAGS_FINAL;
		}
	}

	if ( ds_len < 0L ) {
		iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( key_value_pairs );
		iscsi_connection_pdu_destroy( response_pdu );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	if ( conn->target_send_total_size == 0U ) {
		iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( key_value_pairs );
	} else {
		conn->text_key_value_pairs = key_value_pairs;
	}

	text_response_pkt = (iscsi_text_response_packet *) iscsi_connection_pdu_append( response_pdu, response_pdu->ahs_len, conn->header_digest, ds_len, conn->data_digest );

	iscsi_put_be32( (uint8_t *) &text_response_pkt->total_ahs_len, ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	text_response_pkt->lun           = text_req_pkt->lun; // Copying over doesn't change endianess.
	text_response_pkt->init_task_tag = text_req_pkt->init_task_tag; // Copying over doesn't change endianess.

	if ( (text_req_pkt->flags & ISCSI_TEXT_REQ_FLAGS_FINAL) != 0 ) {
		text_response_pkt->target_xfer_tag = 0xFFFFFFFFUL; // Minus one does not require endianess conversion

		conn->session->current_text_init_task_tag = 0xFFFFFFFFUL;
	} else {
		iscsi_put_be32( (uint8_t *) &text_response_pkt->target_xfer_tag, ((uint32_t) conn->id + 1UL) );
	}

	iscsi_put_be32( (uint8_t *) &text_response_pkt->stat_sn, conn->stat_sn++ );

	if ( (text_response_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 )
		conn->session->max_cmd_sn++;

	iscsi_put_be32( (uint8_t *) &text_response_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &text_response_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	text_response_pkt->reserved2[0] = 0ULL;
	text_response_pkt->reserved2[1] = 0ULL;

	iscsi_connection_pdu_write( conn, response_pdu, iscsi_connection_pdu_text_complete, (uint8_t *) conn );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI payload data SCSI data out request PDU.
 *
 * This function handles SCSI data out request
 * payload data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_scsi_data_out(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0;
}

/**
 * @brief Handles an incoming iSCSI payload data PDU.
 *
 * This function handles all payload data sent
 * by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle(iscsi_connection *conn, iscsi_pdu *pdu)
{
	int rc = 0;

	const uint8_t opcode = ISCSI_GET_OPCODE(pdu->bhs_pkt->opcode);

	switch ( opcode ) {
		case ISCSI_OPCODE_CLIENT_NOP_OUT : {
			rc = iscsi_connection_pdu_data_handle_nop_out( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_SCSI_CMD : {
			rc = iscsi_connection_pdu_data_handle_scsi_cmd( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_LOGIN_REQ : {
			rc = iscsi_connection_pdu_data_handle_login_req( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_TEXT_REQ : {
			rc = iscsi_connection_pdu_data_handle_text_req( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_SCSI_DATA_OUT : {
			rc = iscsi_connection_pdu_data_handle_scsi_data_out( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_TASK_FUNC_REQ :
		case ISCSI_OPCODE_CLIENT_LOGOUT_REQ :
		case ISCSI_OPCODE_CLIENT_SNACK_REQ : {
			break;
		}
		default : {
			return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

			break;
		}
	}

	if ( rc < 0 )
		logadd( LOG_ERROR, "Fatal error during payload handler (opcode 0x%02x) detected for device %s", (int) opcode, (conn->device != NULL ? (char *) conn->device->name : "(null)") );

	return rc;
}

/**
 * @brief Retrieves and merges splitted iSCSI PDU data read from TCP/IP socket.
 *
 * This function handles partial reads of data
 * packet.\n
 * Since iSCSI data can span multiple packets, not
 * only by TCP/IP itself, but also by iSCSI protocol
 * specifications, multiple calls are needed in order
 * to be sure that all data packets have been
 * received.
 *
 * @param[in] conn Pointer to iSCSI connection to read TCP/IP data from.
 * @param[in] pdu Pointer to iSCSI PDU to read TCP/IP data into.
 * @retval -1 Fatal error occured during processing the PDU.
 * @retval 0 Read operation was successful and next read is ready.
 * @retval 1 Read operation was successful and PDU was fully processed.
 */
int iscsi_connection_pdu_data_read(iscsi_connection *conn, iscsi_pdu *pdu)
{
	const uint32_t ds_len = pdu->ds_len;

	if ( pdu->pos < ds_len ) {
		const int32_t len = iscsi_connection_read( conn, (((uint8_t *) pdu->ds_cmd_data) + pdu->pos), (ds_len - pdu->pos) );

		if ( len < 0L )
			return len;

		pdu->pos += len;
	}

	if ( pdu->pos < ds_len )
		return ISCSI_CONNECT_PDU_READ_PROCESSED;

	if ( pdu->data_digest != NULL ) {
		if ( (int) pdu->data_digest_pos < pdu->data_digest_size ) {
			const int32_t len = iscsi_connection_read( conn, (((uint8_t *) pdu->data_digest) + pdu->data_digest_pos), (pdu->data_digest_size - pdu->data_digest_pos) );

			if ( len < 0L )
				return len;

			pdu->data_digest_pos += len;

			if ( (int) pdu->data_digest_pos < pdu->data_digest_size )
				return ISCSI_CONNECT_PDU_READ_OK;
		}

		if  ( !iscsi_connection_pdu_digest_data_verify( pdu->data_digest, pdu->ds_cmd_data, ds_len ) )
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Retrieves and merges splitted iSCSI PDU data read from TCP/IP socket.
 *
 * This function handles partial reads of BHS, AHS
 * and DS packet data.\n
 * Since iSCSI data can span multiple packets, not
 * only by TCP/IP itself, but also by iSCSI protocol
 * specifications, multiple calls are needed in order
 * to be sure that all data packets have been
 * received.
 *
 * @param[in] conn Pointer to iSCSI connection to read TCP/IP data from.
 * @retval -1 Fatal error occured during processing the PDU.
 * @retval 0 Read operation was successful and next read is ready.
 * @retval 1 Read operation was successful and PDU was fully processed.
 */
static int iscsi_connection_pdu_read(iscsi_connection *conn)
{
	int prev_recv_state;

	do {
		iscsi_pdu *pdu = conn->pdu_processing;

		prev_recv_state = conn->pdu_recv_state;

		switch ( conn->pdu_recv_state ) {
			case ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_READY : {
				conn->pdu_processing = iscsi_connection_pdu_create( conn, 0U, conn->header_digest, 0UL, conn->data_digest );

				if ( conn->pdu_processing == NULL )
					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR;

				break;
			}
			case ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR : {
				if ( pdu->bhs_pos < sizeof(struct iscsi_bhs_packet) ) {
					const int32_t len = iscsi_connection_read( conn, (((uint8_t *) pdu->bhs_pkt) + pdu->bhs_pos), (sizeof(struct iscsi_bhs_packet) - pdu->bhs_pos) );

					if ( len < 0L ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						break;
					}

					pdu->bhs_pos += len;

					if ( pdu->bhs_pos < sizeof(struct iscsi_bhs_packet) )
						return ISCSI_CONNECT_PDU_READ_OK;
				}

				if ( (conn->flags & ISCSI_CONNECT_FLAGS_LOGGED_OUT) != 0 ) {
					conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

					break;
				}

				iscsi_bhs_packet *bhs_pkt = pdu->bhs_pkt;
				const uint ahs_len        = ((uint) bhs_pkt->total_ahs_len << 2U);
				const uint32_t ds_len     = iscsi_get_be24(bhs_pkt->ds_len);

				bhs_pkt = iscsi_connection_pdu_append( pdu, ahs_len, conn->header_digest, ds_len, conn->data_digest );

				if ( bhs_pkt == NULL )
					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				uint64_t stat_opcode = (uint64_t) ISCSI_GET_OPCODE(bhs_pkt->opcode);
				uint64_t *stat_value = NULL;
				int stat_rc = iscsi_hashmap_get( conn->stat_iscsi_opcodes, (uint8_t *) &stat_opcode, sizeof(stat_opcode), (uint8_t **) &stat_value );

				if ( stat_value == NULL ) {
					stat_value = malloc( sizeof(uint64_t) );

					if ( stat_value != NULL ) {
						uint8_t *stat_key = iscsi_hashmap_key_create( (uint8_t *) &stat_opcode, sizeof(stat_opcode) );

						if ( stat_key != NULL ) {
							*stat_value = 0ULL;

							stat_rc = iscsi_hashmap_put( conn->stat_iscsi_opcodes, stat_key, sizeof(stat_opcode), (uint8_t *) stat_value );

							if ( stat_rc < 0 ) {
								iscsi_hashmap_key_destroy( stat_key );
								free( stat_value );
								stat_value = NULL;
							}
						} else {
							free( stat_value );
							stat_value = NULL;
						}
					}
				}

				if ( stat_value != NULL )
					(*stat_value)++;

				if ( pdu->ahs_pos < ahs_len ) {
					const int32_t len = iscsi_connection_read( conn, (((uint8_t *) pdu->ahs_pkt) + pdu->ahs_pos), (ahs_len - pdu->ahs_pos) );

					if ( len < 0L ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						break;
					}

					pdu->ahs_pos += len;

					if ( pdu->ahs_pos < ahs_len )
						return ISCSI_CONNECT_PDU_READ_OK;
				}

				if ( pdu->header_digest != NULL ) {
					if ( (int) pdu->header_digest_pos < pdu->header_digest_size ) {
						const int32_t len = iscsi_connection_read( conn, (((uint8_t *) pdu->header_digest) + pdu->header_digest_pos), (pdu->header_digest_size - pdu->header_digest_pos) );

						if ( len < 0L ) {
							conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

							break;
						}

						pdu->header_digest_pos += len;

						if ( (int) pdu->header_digest_pos < pdu->header_digest_size )
							return ISCSI_CONNECT_PDU_READ_OK;
					}

					if  ( !iscsi_connection_pdu_digest_header_verify( pdu->header_digest, bhs_pkt, ahs_len ) ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						break;
					}
				}

				conn->pdu_recv_state = ((iscsi_connection_pdu_header_handle( conn, pdu ) < 0) ? ISCSI_CONNECT_PDU_RECV_STATE_ERR : ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_DATA);

				break;
			}
			case ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_DATA : {
				if ( pdu->ds_len != 0UL ) {
					const int len = iscsi_connection_pdu_data_read( conn, pdu );

					if ( len < 0 ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						break;
					} else if ( len > 0 ) {
						return ISCSI_CONNECT_PDU_READ_OK;
					}
				}

				int rc;

				if ( (conn->flags & ISCSI_CONNECT_FLAGS_REJECTED) != 0 )
					rc = 0;
				else
					rc = iscsi_connection_pdu_data_handle( conn, pdu );

				if ( rc == 0 ) {
					iscsi_connection_pdu_destroy( pdu );

					conn->pdu_processing = NULL;
					conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_READY;

					return ISCSI_CONNECT_PDU_READ_PROCESSED;
				} else {
					conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;
				}

				break;
			}
			case ISCSI_CONNECT_PDU_RECV_STATE_ERR : {
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				break;
			}
			default : {
				logadd( LOG_ERROR, "iscsi_connection_pdu_read: Fatal error reading, unknown packet status. Should NEVER happen! Please report this bug to the developer" );

				break;
			}
		}
	} while ( prev_recv_state != conn->pdu_recv_state );

	return 0;
}

#define ISCSI_PDU_HANDLE_COUNT 16

/**
 * @brief Handles incoming PDU data, read up to 16 fragments at once.
 *
 * Until iSCSI processing has been stopped or a
 * complete iSCSI packet has been read, this
 * function will read, parse and process
 * incoming iSCSI protocol data.
 *
 * @param[in] conn Pointer to iSCSI connection to handle.
 * @return Number of proccessed fragments or return
 * code of iscsi_connection_pdu_read in case of a
 * fatal error.
 */
int iscsi_connection_pdu_handle(iscsi_connection *conn)
{
	int i;

	for ( i = 0; i < ISCSI_PDU_HANDLE_COUNT; i++ ) {
		const int rc = iscsi_connection_pdu_read( conn );

		while ( !iscsi_list_empty( &conn->exec_queue ) ) {
			iscsi_connection_exec_queue *exec_queue = (iscsi_connection_exec_queue *) iscsi_list_peek( &conn->exec_queue );

			iscsi_list_remove( &exec_queue->node );

			switch ( exec_queue->type ) {
				case ISCSI_CONNECT_EXEC_QUEUE_TYPE_SCSI_EMU_IO : {
					exec_queue->data.io.callback( exec_queue->data.io.image, exec_queue->data.io.user_data, exec_queue->data.io.success );

					break;
				}
				case ISCSI_CONNECT_EXEC_QUEUE_TYPE_PDU_WRITE : {
					exec_queue->data.pdu_write.callback( exec_queue->data.pdu_write.user_data, exec_queue->data.pdu_write.err );

					break;
				}
				default : {
					break;
				}
			}

			free( exec_queue );
		}

		if ( rc == ISCSI_CONNECT_PDU_READ_OK )
			break;
		else if ( rc == ISCSI_CONNECT_PDU_READ_ERR_FATAL )
			return rc;

		if ( (conn->flags & ISCSI_CONNECT_FLAGS_STOPPED) != 0 )
			break;
	}

	return i;
}

/**
 * @brief Handles an iSCSI connection until connection is closed.
 *
 * This function creates an iSCSI portal group
 * and iSCSI portal with connection data
 * delivered from the DNBD3 client and
 * request data.
 *
 * @param[in] client Pointer to DNBD3 client structure,
 * may NOT be NULL, so be careful.
 * @param[in] request Pointer to DNBD3 request packet data.
 * NULL is not allowed here, take caution.
 * @param[in] len Length of already read DNBD3 request data.
 */
void iscsi_connection_handle(dnbd3_client_t *client, const dnbd3_request_t *request, const int len)
{
	_Static_assert( sizeof(dnbd3_request_t) <= sizeof(struct iscsi_bhs_packet), "DNBD3 request size larger than iSCSI BHS packet data size - Manual intervention required!" );
	sock_setTimeout( client->sock, 1000L * 3600L ); // TODO: Remove after finishing iSCSI implementation

	pthread_rwlock_rdlock( &iscsi_globvec_rwlock );

	if ( iscsi_globvec == NULL )
		return;

	uint64_t *hash_key;
	iscsi_portal_group *portal_group = NULL;

	pthread_rwlock_wrlock( &iscsi_globvec->portal_groups_rwlock );

	int rc = iscsi_hashmap_get( iscsi_globvec->portal_groups, (uint8_t *) &iscsi_globvec->portal_groups->last_insert_id, sizeof(iscsi_globvec->portal_groups->last_insert_id), (uint8_t **) &portal_group );

	if ( portal_group == NULL ) {
		hash_key = (uint64_t *) malloc( sizeof(uint64_t) );

		if ( hash_key == NULL ) {
			logadd( LOG_ERROR, "iscsi_connection_handle: Out of memory while allocating iSCSI portal group" );

			pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return;
		}

		iscsi_hashmap_key_create_id( iscsi_globvec->portal_groups, hash_key );
		portal_group = iscsi_portal_group_create( *hash_key, 0 );

		if ( portal_group == NULL ) {
			logadd( LOG_ERROR, "iscsi_connection_handle: Out of memory while allocating iSCSI portal group" );

			iscsi_hashmap_key_destroy( (uint8_t *) hash_key );
			pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return;
		}

		portal_group->tag = *hash_key;

		iscsi_hashmap_key_destroy( (uint8_t *) hash_key );

		rc = iscsi_hashmap_put( iscsi_globvec->portal_groups, (uint8_t *) &portal_group->tag, sizeof(portal_group->tag), (uint8_t *) portal_group );

		if ( rc < 0 ) {
			iscsi_portal_group_destroy( portal_group );
			pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return;
		}
	}

	pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );
	host_to_string( &client->host, client->hostName, HOSTNAMELEN );

	const uint8_t *port = memchr( client->hostName, ':', HOSTNAMELEN );
	const uint host_len = ((port != NULL) ? (uint) (port++ - (uint8_t *) client->hostName) : (uint) strlen( client->hostName ));
	uint8_t *host       = malloc( (host_len + 1U) );

	if ( host == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_handle: Out of memory while allocating iSCSI portal host name" );

		pthread_rwlock_unlock( &iscsi_globvec_rwlock );

		return;
	}

	memcpy( host, client->hostName, host_len );
	host[host_len] = '\0';

	uint8_t *tmp_buf;

	if ( port != NULL )
		tmp_buf = iscsi_sprintf_alloc( "%s:%s", host, port );
	else
		tmp_buf = iscsi_sprintf_alloc( "%s:%u", host, PORT );

	if ( tmp_buf == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_handle: Out of memory while allocating temporarily iSCSI portal name" );

		free( host );
		pthread_rwlock_unlock( &iscsi_globvec_rwlock );

		return;
	}

	const uint key_len = (uint) (strlen( (char *) tmp_buf ) + 1U);

	hash_key = (uint64_t *) iscsi_hashmap_key_create( tmp_buf, key_len );

	free( tmp_buf );

	if ( hash_key == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_handle: Out of memory while allocating temporarily iSCSI portal name hash key" );

		free( host );
		pthread_rwlock_unlock( &iscsi_globvec_rwlock );

		return;
	}

	iscsi_portal *portal = NULL;

	pthread_rwlock_wrlock( &iscsi_globvec->portal_groups_rwlock );
	rc = iscsi_hashmap_get( portal_group->portals, (uint8_t *) hash_key, key_len, (uint8_t **) &portal );

	if ( portal == NULL ) {
		if ( port == NULL ) {
			port = (uint8_t *) strchr( (char *) hash_key, ':' );
			port++;
		}

		portal = iscsi_portal_create( host, port );

		if ( portal == NULL ) {
			logadd( LOG_ERROR, "iscsi_connection_handle: Out of memory while allocating iSCSI portal" );

			pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );
			iscsi_hashmap_key_destroy( (uint8_t *) hash_key );
			free( host );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return;
		}

		rc = iscsi_portal_group_add_portal( portal_group, portal );

		if ( rc < 0 ) {
			pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );
			iscsi_portal_destroy( portal );
			iscsi_hashmap_key_destroy( (uint8_t *) hash_key );
			free( host );
			pthread_rwlock_unlock( &iscsi_globvec_rwlock );

			return;
		}
	}

	iscsi_hashmap_key_destroy( (uint8_t *) hash_key );
	free( host );

	iscsi_connection *conn = iscsi_connection_create( portal, client->sock );

	if ( conn == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_handle: Out of memory while allocating iSCSI connection" );

		iscsi_portal_group_del_portal( portal_group, portal );
		iscsi_portal_destroy( portal );
		pthread_rwlock_unlock( &iscsi_globvec_rwlock );

		return;
	}

	pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );

	conn->pdu_processing = iscsi_connection_pdu_create( conn, 0U, 0, 0UL, 0 );

	if ( conn->pdu_processing == NULL ) {
		iscsi_connection_destroy( conn );
		pthread_rwlock_wrlock( &iscsi_globvec->portal_groups_rwlock );
		iscsi_portal_group_del_portal( portal_group, portal );
		pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );
		iscsi_portal_destroy( portal );
		pthread_rwlock_unlock( &iscsi_globvec_rwlock );

		return;
	}

	memcpy( conn->pdu_processing->bhs_pkt, request, len );

	conn->pdu_processing->bhs_pos = len;
	conn->pdu_recv_state          = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR;

	logadd( LOG_INFO, "" );
	logadd( LOG_INFO, "iSCSI connection opened for device %s from initiator %s using port %s and portal %s:%s", (conn->device != NULL ? (char *) conn->device->name : "(null)"), (char *) conn->init_name, ((conn->init_port != NULL) ? (char *) conn->init_port->name : "(null)"), (char *) portal->host, (char *) portal->port );

	while ( iscsi_connection_pdu_handle( conn ) >= ISCSI_CONNECT_PDU_READ_OK ) {
	}

	iscsi_hashmap_bucket *stat_bucket;

	logadd( LOG_INFO, "iSCSI connection closed for device %s from initiator %s using port %s and portal %s:%s", (conn->device != NULL ? (char *) conn->device->name : "(null)"), (char *) conn->init_name, ((conn->init_port != NULL) ? (char *) conn->init_port->name : "(null)"), (char *) portal->host, (char *) portal->port );

	iscsi_list_foreach_node ( &conn->stat_iscsi_opcodes->list, stat_bucket ) {
		uint64_t *stat_opcode = (uint64_t *) stat_bucket->value;

		logadd( LOG_INFO, "iSCSI opcode usage statistics for device %s from initiator %s using port %s and portal %s:%s: Opcode 0x%02" PRIX64 " has been received %" PRIu64 " times until connection drop.", (conn->device != NULL ? (char *) conn->device->name : "(null)"), (char *) conn->init_name, ((conn->init_port != NULL) ? (char *) conn->init_port->name : "(null)"), (char *) portal->host, (char *) portal->port, *(uint64_t *) stat_bucket->key, *stat_opcode );
	}

	iscsi_list_foreach_node ( &conn->stat_scsi_opcodes->list, stat_bucket ) {
		uint64_t *stat_opcode = (uint64_t *) stat_bucket->value;

		logadd( LOG_INFO, "iSCSI SCSI CDB opcode usage statistics for device %s from initiator %s using port %s and portal %s:%s: SCSI CDB opcode 0x%02" PRIX64 " has been received %" PRIu64 " times until connection drop.", (conn->device != NULL ? (char *) conn->device->name : "(null)"), (char *) conn->init_name, ((conn->init_port != NULL) ? (char *) conn->init_port->name : "(null)"), (char *) portal->host, (char *) portal->port, *(uint64_t *) stat_bucket->key, *stat_opcode );
	}

	iscsi_session *session = conn->session;

	if ( session != NULL ) {
		pthread_rwlock_wrlock( &iscsi_globvec->sessions_rwlock );
		iscsi_list_remove( &conn->node );

		if ( --session->conns == 0UL ) {
			const uint64_t tsih = session->tsih;

			iscsi_hashmap_remove( iscsi_globvec->sessions, (uint8_t *) &tsih, sizeof(tsih) );
			iscsi_session_destroy( session );
		}

		pthread_rwlock_unlock( &iscsi_globvec->sessions_rwlock );
	}

	iscsi_connection_destroy( conn );

	pthread_rwlock_wrlock( &iscsi_globvec->portal_groups_rwlock );
	iscsi_portal_group_del_portal( portal_group, portal );
	iscsi_portal_destroy( portal );
	pthread_rwlock_unlock( &iscsi_globvec->portal_groups_rwlock );

	pthread_rwlock_unlock( &iscsi_globvec_rwlock );
}
