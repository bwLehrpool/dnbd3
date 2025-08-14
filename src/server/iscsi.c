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
#include <strings.h>
#include <sys/socket.h>
#include <dnbd3/shared/log.h>
#include <time.h>
#include "iscsi.h"

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

/// iSCSI connection negotation key and value pair lookup table.
static const iscsi_key_value_pair_lut_entry iscsi_connection_key_value_pair_lut[] = {
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST, (uint8_t *) "None", (uint8_t *) "CRC32C\0None\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST, (uint8_t *) "None", (uint8_t *) "CRC32C\0None\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN, (uint8_t *) "8192", (uint8_t *) "512\016777215\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_MULTI_NEGOTIATION | ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_OVERRIDE_DEFAULT },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_OF_MARKER, (uint8_t *) "No", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IF_MARKER, (uint8_t *) "No", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_OF_MARK_INT, (uint8_t *) "1", (uint8_t *) "1\0""65535\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IF_MARK_INT, (uint8_t *) "1", (uint8_t *) "1\0""65535\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD, (uint8_t *) "None", (uint8_t *) "CHAP\0None\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_A, (uint8_t *) "5", (uint8_t *) "5\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_N, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_R, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_I, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_C, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE },
	{ NULL, NULL, NULL, ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_INVALID, 0L }
};

/// iSCSI session negotation key and value pair lookup table.
static const iscsi_key_value_pair_lut_entry iscsi_session_key_value_pair_lut[] = {
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS, (uint8_t *) "1", (uint8_t *) "1\065535\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_SEND_TARGETS, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_SPECIAL_HANDLING },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_NAME, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_NAME, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_ALIAS, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, (uint8_t *) "", (uint8_t *) "\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, (uint8_t *) "1", (uint8_t *) "1\0""65535\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T, (uint8_t *) "Yes", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA, (uint8_t *) "Yes", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, (uint8_t *) "262144", (uint8_t *) "512\0""16777215\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE | ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_OTHER_MAX_VALUE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN, (uint8_t *) "65536", (uint8_t *) "512\0""16777215\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE | ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_PREVIOUS_VALUE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_WAIT, (uint8_t *) "2", (uint8_t *) "0\0""3600\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MAX, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_RETAIN, (uint8_t *) "20", (uint8_t *) "0\0""3600\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T, (uint8_t *) "1", (uint8_t *) "1\0""65536\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_PDU_IN_ORDER, (uint8_t *) "Yes", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_SEQ_IN_ORDER, (uint8_t *) "Yes", (uint8_t *) "Yes\0No\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR, ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_ERR_RECOVERY_LEVEL, (uint8_t *) "0", (uint8_t *) "0\0""2\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN, 0L },
	{ (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, (uint8_t *) "Normal", (uint8_t *) "Normal\0Discovery\0", ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE, 0L },
	{ NULL, NULL, NULL, ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_INVALID, 0L }
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
	for ( uint i = 0; lut[i].key != NULL; i++ ) {
		const uint key_len = (uint) strlen( (char *) lut[i].key ) + 1;
		uint8_t *hash_key = iscsi_hashmap_key_create( lut[i].key, key_len );

		if ( hash_key == NULL ) {
			logadd( LOG_ERROR, "iscsi_global_key_value_pair_init: Out of memory allocating key" );

			return -1L;
		}

		iscsi_key_value_pair *key_value_pair = (iscsi_key_value_pair *) malloc( sizeof(struct iscsi_key_value_pair) );

		if ( key_value_pair == NULL ) {
			logadd( LOG_ERROR, "iscsi_global_key_value_pair_init: Out of memory allocating key value pair" );

			iscsi_hashmap_key_destroy( hash_key );

			return -1L;
		}

		key_value_pair->value       = lut[i].value;
		key_value_pair->list_range  = lut[i].list_range;
		key_value_pair->type        = lut[i].type;
		key_value_pair->flags       = lut[i].flags;
		key_value_pair->state_mask  = (1UL << i);

		const int rc = iscsi_hashmap_put( key_value_pairs, hash_key, key_len, (uint8_t *) key_value_pair );

		if ( rc < 0 ) {
			free( key_value_pair );
			iscsi_hashmap_key_destroy( hash_key );

			return rc;
		}
	}

	return 0L;
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
	if ( iscsi_globvec == NULL ) {
		iscsi_globals *globvec = (iscsi_globals *) malloc( sizeof(struct iscsi_globals) );

		if ( globvec == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector" );

			return -1L;
		}

		globvec->devices = iscsi_hashmap_create( 0UL );

		if ( globvec->devices == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector devices hash map" );

			free( globvec );

			return -1L;
		}

		globvec->portal_groups = iscsi_hashmap_create( 0UL );

		if ( globvec->portal_groups == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector portal groups hash map" );

			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );

			return -1L;
		}

		globvec->target_nodes = iscsi_hashmap_create( 0UL );

		if ( globvec->target_nodes == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector target nodes hash map" );

			iscsi_hashmap_destroy( globvec->portal_groups );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );

			return -1L;
		}

		globvec->sessions = iscsi_hashmap_create( 0UL );

		if ( globvec->sessions == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector sessions hash map" );

			iscsi_hashmap_destroy( globvec->target_nodes );
			iscsi_hashmap_destroy( globvec->portal_groups );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );

			return -1L;
		}

		globvec->session_key_value_pairs = iscsi_hashmap_create( 32UL );

		if ( globvec->session_key_value_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector session key and value pairs hash map" );

			iscsi_hashmap_destroy( globvec->sessions );
			iscsi_hashmap_destroy( globvec->target_nodes );
			iscsi_hashmap_destroy( globvec->portal_groups );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );

			return -1L;
		}

		int rc = iscsi_global_key_value_pair_init( globvec->session_key_value_pairs, &iscsi_session_key_value_pair_lut[1] );

		if ( globvec->connection_key_value_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing iSCSI global vector session key and value pairs hash map" );

			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			iscsi_hashmap_destroy( globvec->sessions );
			iscsi_hashmap_destroy( globvec->target_nodes );
			iscsi_hashmap_destroy( globvec->portal_groups );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );

			return -1L;
		}

		globvec->connections = iscsi_hashmap_create( 0UL );

		if ( globvec->connections == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector connections hash map" );

			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			iscsi_hashmap_destroy( globvec->sessions );
			iscsi_hashmap_destroy( globvec->target_nodes );
			iscsi_hashmap_destroy( globvec->portal_groups );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );

			return -1L;
		}

		globvec->connection_key_value_pairs = iscsi_hashmap_create( 32UL );

		if ( globvec->connection_key_value_pairs == NULL ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while allocating iSCSI global vector connection key and value pairs hash map" );

			iscsi_hashmap_destroy( globvec->connections );
			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			iscsi_hashmap_destroy( globvec->sessions );
			iscsi_hashmap_destroy( globvec->target_nodes );
			iscsi_hashmap_destroy( globvec->portal_groups );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );

			return -1L;
		}

		rc = iscsi_global_key_value_pair_init( globvec->connection_key_value_pairs, &iscsi_connection_key_value_pair_lut[0] );

		if ( rc < 0 ) {
			logadd( LOG_ERROR, "iscsi_create: Out of memory while initializing iSCSI global vector connection key and value pairs hash map" );

			iscsi_hashmap_iterate( globvec->connection_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->connection_key_value_pairs );
			iscsi_hashmap_destroy( globvec->connections );
			iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( globvec->session_key_value_pairs );
			iscsi_hashmap_destroy( globvec->sessions );
			iscsi_hashmap_destroy( globvec->target_nodes );
			iscsi_hashmap_destroy( globvec->portal_groups );
			iscsi_hashmap_destroy( globvec->devices );
			free( globvec );

			return -1L;
		}

		globvec->flags        = 0L;
		globvec->max_sessions = 0UL;
		globvec->chap_group   = 0L;

		iscsi_globvec = globvec;
	}

	return 0L;
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
	iscsi_globals *globvec = iscsi_globvec;

	if ( globvec != NULL ) {
		iscsi_globvec = NULL;

		iscsi_hashmap_iterate( globvec->connection_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( globvec->connection_key_value_pairs );
		globvec->connection_key_value_pairs = NULL;

		iscsi_hashmap_destroy( globvec->connections );
		globvec->connections = NULL;

		iscsi_hashmap_iterate( globvec->session_key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( globvec->session_key_value_pairs );
		globvec->session_key_value_pairs = NULL;

		iscsi_hashmap_destroy( globvec->sessions );
		globvec->sessions = NULL;

		iscsi_hashmap_destroy( globvec->target_nodes );
		globvec->target_nodes = NULL;

		iscsi_hashmap_destroy( globvec->portal_groups );
		globvec->portal_groups = NULL;

		iscsi_hashmap_destroy( globvec->devices );
		globvec->devices = NULL;

		free( globvec );
	}
}

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
	uint orig_size = 0;

	if ( buf != NULL )
		orig_size = (uint) strlen( (char *) buf );

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
 * @brief Creates an empty hash map with either specified or default capacity.
 *
 * Creates a ultra hardcore speed optimized empty hash map and
 * allocates enough buckets to hold default capacity elements.\n
 * The speed optimizations require all keys having a size of
 * a multiple of 8 bytes with zero padding. Also the capacity
 * always nas to be a power of two.\n
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

	map->cap_load      = (uint) ((map->capacity * 3UL) >> 2UL); // 75% of capacity
	map->count         = 0;
	map->removed_count = 0;
	map->first         = NULL;
	map->last          = (iscsi_hashmap_bucket *) &map->first;

	return map;
}

/**
 * @brief Deallocates the hash map objects and buckets, not elements. Use iscsi_hashmap_iterate to deallocate the elements themselves.
 *
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
 * @brief Resizes a hash map by doubling its bucket capacity and purges any removed buckets.
 *
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

	map->cap_load      = (uint) ((map->capacity * 3UL) >> 2UL); // 75% of capacity
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
 * @brief Calculates the hash code of data with a specified length.
 *
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
	uint32_t index = hash & (map->capacity - 1);

	for ( ;; ) {
		iscsi_hashmap_bucket *entry = &map->buckets[index];

		if ( (entry->key == NULL && entry->value == NULL) || (entry->key != NULL && entry->key_size == key_size && entry->hash == hash && (memcmp( entry->key, key, key_size ) == 0)) )
			return entry;

		index = (index + 1) & (map->capacity - 1);
	}
}

/**
 * @brief Creates a key suitable for hashmap usage (ensures 8-byte boundary and zero padding).
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
 * @brief Deallocates all resources acquired by iscsi_hashmap_create_key.
 *
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
 * @brief Deallocates all key / value pairs in a hash map by calling free (default destructor).
 *
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

	return 0L;
}

/**
 * @brief Assigns key / value pair to hash map without making copies.
 *
 * Adds a key / value pair to a specified hash map
 * bucket list, if it doesn't exist already. The
 * buckets are resized automatically if required.\n
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
int iscsi_hashmap_put(iscsi_hashmap *map, uint8_t *key, const size_t key_size, uint8_t *value)
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
 * @brief Assigns key / value pair to hash map without making copies.
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
int iscsi_hashmap_get_put(iscsi_hashmap *map, uint8_t *key, const size_t key_size, uint8_t **out_in_value)
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
 * @brief Checks whether a specified key exists.
 *
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
 * @brief Retrieves the value of a specified key.
 *
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
 * @brief Marks an element for removal by setting key and value both to NULL.
 *
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
 * @brief Marks an element for removal by setting key and value both to NULL, but invokes a callback function before actual marking for removal.
 *
 * Removes an element from the bucket list of the hash map.\n
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
 * @param[in,out] user_data Pointer to user specific data
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
 * @brief Retrieves the number of elements of the hash map, ignoring elements marked for removal.
 *
 * Returns the number of elements stored in the specified
 * hash map. Elements marked for removal are not included.
 *
 * @param[in] map Pointer to the hash map to count the
 * number of elements, may NOT be NULL, so take caution.
 * @return Number of elements currently in use by the
 * hash map. Buckets marked for removal are not counted.
 */
uint iscsi_hashmap_size(const iscsi_hashmap *map)
{
	return (map->count - map->removed_count);
}

/**
 * @brief Iterator with callback function invoked on each element which has not been removed.
 *
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
 * @param[in,out] user_data Pointer to user specific data
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
 * @brief Allocate and initialize an iSCSI BHS packet.
 *
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

    bhs_pkt->opcode           = 0; // Initialize everything to zero
    bhs_pkt->opcode_fields[0] = 0;
    bhs_pkt->opcode_fields[1] = 0;
    bhs_pkt->opcode_fields[2] = 0;
	bhs_pkt->total_ahs_len    = 0;
	bhs_pkt->ds_len[0]        = 0;
	bhs_pkt->ds_len[1]        = 0;
	bhs_pkt->ds_len[2]        = 0;
	bhs_pkt->lun_opcode.lun   = 0ULL;
	bhs_pkt->init_task_tag    = 0UL;

	memset( bhs_pkt->opcode_spec_fields, 0, sizeof(bhs_pkt->opcode_spec_fields) );

	return bhs_pkt;
}

/**
 * @brief Free resources allocated by iscsi_create_packet.
 *
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
 * @brief Allocate and initialize an iSCSI AHS packet and append to existing data stream.
 *
 * Constructs and appends an Additional Header Segment (AHS) to already allocated
 * packet data. There is no guarantee that the pointer stays the same. Any references
 * to the old structure need to be updated!\n
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
	const uint32_t new_pkt_size = (uint32_t) (old_pkt_size + iscsi_align(ahs_len, ISCSI_ALIGN_SIZE));

	if ( new_pkt_size > (sizeof(struct iscsi_bhs_packet) + ISCSI_MAX_AHS_SIZE) ) {
		logadd( LOG_ERROR, "iscsi_append_ahs_packet: Total numer of AHS packet size exceeds 255 DWORDs" );

		return NULL;
	}

	packet_data = (iscsi_bhs_packet *) realloc( packet_data, new_pkt_size );

	if ( packet_data == NULL ) {
		logadd( LOG_ERROR, "iscsi_append_ahs_packet: Out of memory while allocating iSCSI AHS packet data for appending" );

		return packet_data;
	}

	iscsi_ahs_packet *ahs_pkt = (iscsi_ahs_packet *) ((uint8_t *) packet_data + old_pkt_size);
	ahs_pkt->len = iscsi_get_be16((uint16_t) ahs_len);
	ahs_pkt->type = 0;
	ahs_pkt->specific = 0;
	memset( ahs_pkt->data, 0, (new_pkt_size - old_pkt_size) - offsetof(struct iscsi_ahs_packet, data) );
	packet_data->total_ahs_len += (uint8_t) ((ahs_len + (ISCSI_ALIGN_SIZE - 1)) >> 2UL);

	return packet_data;
}

/**
 * @brief Counts number of AHS packets in an iSCSI data packet stream.
 *
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
		ahs_pkt = (iscsi_ahs_packet *) (((uint8_t *) ahs_pkt) + (len - offsetof(struct iscsi_ahs_packet, data))); // Advance pointer to next AHS packet
		count++;
	}

	return count;
}

/**
 * @brief Retrieves the pointer to an specific AHS packet by index.
 *
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
		ahs_pkt = (iscsi_ahs_packet *) (((uint8_t *) ahs_pkt) + (len - offsetof(struct iscsi_ahs_packet, data))); // Advance pointer to next AHS packet
	}

	logadd( LOG_ERROR, "iscsi_get_ahs_packet: Specified index for AHS packet does not exist" );

	return NULL;
}

/**
 * @brief Allocate and initialize an iSCSI header digest (CRC32C) and appends it to existing data stream.
 *
 * Constructs and appends an header digest (CRC32C) to already allocated
 * packet data. There is no guarantee that the pointer stays the same.
 * Any references to the old structure need to be updated!\n
 * This function currently throws away any data beyond AHS.
 *
 * @param[in] packet_data Pointer to packet data to append to. If NULL, a Basic
 * Header Segment (BHS) will be created and initialized before adding the
 * header digest.
 * @param[in] header_digest_size Length of header digest. Currently, only
 * 0, in which case the header digest will be removed, or 4 for CRC32C
 * are allowed.
 * @return New pointer to BHS structure with additional header digest attached
 * or NULL in case of an reallocation error or header digest is neither 0 nor 4.
 */
iscsi_bhs_packet *iscsi_append_header_digest_packet(iscsi_bhs_packet *packet_data, const int header_digest_size)
{
	if ( packet_data == NULL ) {
		packet_data = iscsi_create_packet();

		if ( packet_data == NULL )
			return packet_data;
	}

	if ( (header_digest_size != 0) || (header_digest_size != ISCSI_DIGEST_SIZE) ) {
		logadd( LOG_ERROR, "iscsi_append_header_digest_packet: Header digest size MUST be either 0 or 4 bytes" );

		return NULL;
	}

	const uint32_t old_pkt_size = (const uint32_t) sizeof(struct iscsi_bhs_packet) + (packet_data->total_ahs_len << 2UL);
	const uint32_t new_pkt_size = old_pkt_size + header_digest_size;

	packet_data = (iscsi_bhs_packet *) realloc( packet_data, new_pkt_size );

	if ( packet_data == NULL ) {
		logadd( LOG_ERROR, "iscsi_append_header_digest_packet: Out of memory while allocating iSCSI header digest packet data for appending" );

		return packet_data;
	}

	memset( (((uint8_t *) packet_data) + old_pkt_size), 0, header_digest_size );

	return packet_data;
}

/**
 * @brief Allocate and initialize an iSCSI DS packet and append to existing data stream.
 *
 * Constructs and appends DataSegment (DS) to already allocated packet data.\n
 * There is no guarantee that the pointer stays the same. Any references
 * to the old structure need to be updated!\n
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
	const uint32_t new_pkt_size = (uint32_t) (old_pkt_size + header_digest_size + iscsi_align(ds_len, ISCSI_ALIGN_SIZE) + data_digest_size);

	packet_data = (iscsi_bhs_packet *) realloc( packet_data, new_pkt_size );

	if ( packet_data == NULL ) {
		logadd( LOG_ERROR, "iscsi_append_ds_packet: Out of memory while allocating iSCSI DS packet data for appending" );

		return packet_data;
	}

	iscsi_put_be24( (uint8_t *) &packet_data->ds_len, ds_len );
	memset( ((uint8_t *) packet_data) + old_pkt_size, 0, (new_pkt_size - old_pkt_size) );

	return packet_data;
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
 * Calculates CRC32C with 0x82F63B78 polynomial reflect according to iSCSI specs.\n
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
 * @brief Validates a stored iSCSI header digest (CRC32C) with actual header data.
 *
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
 * @brief Calculate iSCSI data digest (CRC32C).
 *
 * Calculates data digest (CRC32) with 0x82F63B78 polynomial reflect
 * of a whole DataSegment (CRC32C) according to the iSCSI specs.\n
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
 * @brief Validates a stored iSCSI data digest (CRC32C) with actual DataSegment.
 *
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
 * @brief Validates a single text key / value pair according to iSCSI specs.
 *
 * Validates an iSCSI protocol key and value pair for compliance
 * with the iSCSI specs.
 *
 * @param[in] packet_data Pointer to key / value pair to be
 * validated. NULL is an illegal value, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @return Number of bytes used by the key / vair pair or
 * a negative value in case of an error. This can be used for
 * incrementing the offset to the next key / value pair.
 */
static int iscsi_validate_text_key_value_pair(const uint8_t *packet_data, const uint32_t len)
{
	const uint key_val_len = (uint) strnlen( (char *) packet_data, len );
	const uint8_t *key_end = memchr( packet_data, '=', key_val_len );

	if ( key_end == NULL )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Missing separator '=' for key / value pair -> invalid iSCSI packet data

	const uint key_len = (uint) (key_end - packet_data);

	if ( key_len == 0 )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Zero length is not allowed -> invalid iSCSI packet data

	if ( key_len > ISCSI_TEXT_KEY_MAX_LEN )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS;

	const uint val_len = (uint) strnlen( (char *) (key_end + 1UL), key_val_len - key_len - 1UL );
	const uint max_len = (memcmp( packet_data, "CHAP_C=", (key_len + 1UL) ) == 0) || (memcmp( packet_data, "CHAP_R=", (key_len + 1UL) ) == 0) ? ISCSI_TEXT_VALUE_MAX_LEN : ISCSI_TEXT_VALUE_MAX_SIMPLE_LEN;

	if ( val_len > max_len )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Value exceeds maximum length -> invalid iSCSI packet data

	return (int) (key_len + 1UL + val_len + 1UL); // Number of bytes for processed key / value pair (+1 for '=' and NUL terminator)
}

/**
 * @brief Validates all text key / value pairs according to iSCSI specs.
 *
 * Validates all iSCSI protocol key and value pairs for
 * compliance with the iSCSI specs.
 *
 * @param[in] packet_data Pointer to first key and value pair to
 * be validated. NULL is an illegal value here, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @return 0 if validation for each text key and value pair was
 * successful, a negative error code in case iSCSI specs
 * are violated.
 */
static int iscsi_validate_key_value_pairs(const uint8_t *packet_data, uint len)
{
	if ( len == 0 )
		return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Zero length is not allowed -> invalid iSCSI packet data

	int offset = 0L;

	while ( ((uint) offset < len) && (packet_data[offset] != '\0') ) {
		const int rc = iscsi_validate_text_key_value_pair( (packet_data + offset), (len - offset) );

		if ( rc < ISCSI_VALIDATE_PACKET_RESULT_OK )
			return rc;

		offset += rc;
	}

	return (iscsi_align(offset, ISCSI_ALIGN_SIZE) != iscsi_align(len, ISCSI_ALIGN_SIZE)) ? ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS : ISCSI_VALIDATE_PACKET_RESULT_OK;
}

/**
 * @brief Check if valid iSCSI packet and validate if necessarily.
 *
 * Checks whether packet data is an iSCSI packet or not.\n
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

			if ( (nop_out_pkt->flags != -0x80) || (nop_out_pkt->reserved != 0) || (nop_out_pkt->reserved2[0] != 0) || (nop_out_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Flags always MUST be 0x80 for now and remaining reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

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

			if ( (task_mgmt_func_req_pkt->func >= 0) || (task_mgmt_func_req_pkt->reserved != 0) || (task_mgmt_func_req_pkt->reserved2 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Function bit 7 always MUST be set and reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_LOGIN_REQ : {
			if ( (packet_data->opcode != (opcode | 0x40)) || (ahs_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bit 6 always MUST be set and AHS MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_login_req_packet *login_req_pkt = (const iscsi_login_req_packet *) packet_data;

			if ( (ISCSI_VERSION_MIN < login_req_pkt->version_min) || (ISCSI_VERSION_MAX > login_req_pkt->version_max) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_UNSUPPORTED_VERSION;

			if ( (ISCSI_LOGIN_REQ_FLAGS_GET_CURRENT_STAGE(login_req_pkt->flags) == ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_RESERVED) || ((ISCSI_LOGIN_REQ_FLAGS_GET_NEXT_STAGE(login_req_pkt->flags) == ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_RESERVED) && ((login_req_pkt->flags & ISCSI_LOGIN_REQ_FLAGS_TRANSIT) != 0)) || ((login_req_pkt->flags < 0) && ((login_req_pkt->flags & ISCSI_LOGIN_REQ_FLAGS_CONTINUE) != 0)) || (login_req_pkt->flags & ~(ISCSI_LOGIN_REQ_FLAGS_CONTINUE | ISCSI_LOGIN_REQ_FLAGS_TRANSIT) != 0) || (login_req_pkt->reserved != 0) || (login_req_pkt->reserved2[0] != 0) || (login_req_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Current Stage (CSG) is set to reserved and Next Stage (NSG) is reserved and T bit is set, if C bit is set, T MUST be cleared and reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			return iscsi_validate_key_value_pairs( ((const uint8_t *) login_req_pkt) + iscsi_align(ds_len, ISCSI_ALIGN_SIZE), ds_len );

			break;
		}
		case ISCSI_CLIENT_TEXT_REQ : {
			if ( (int8_t) packet_data->opcode < 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // MSB always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_text_req_packet *text_req_pkt = (const iscsi_text_req_packet *) packet_data;

			if ( ((text_req_pkt->flags < 0) && ((text_req_pkt->flags & ISCSI_TEXT_REQ_FLAGS_CONTINUE) != 0)) || (text_req_pkt->flags & ~(ISCSI_TEXT_REQ_FLAGS_CONTINUE | ISCSI_TEXT_REQ_FLAGS_FINAL) != 0) || (text_req_pkt->reserved != 0) || (text_req_pkt->reserved2[0] != 0) || (text_req_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // If C bit is set, F MUST be cleared and reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			return iscsi_validate_key_value_pairs( ((const uint8_t *) text_req_pkt) + iscsi_align(ds_len, ISCSI_ALIGN_SIZE), ds_len );

			break;
		}
		case ISCSI_CLIENT_SCSI_DATA_OUT : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_scsi_data_out_req_packet *scsi_data_out_req_pkt = (const iscsi_scsi_data_out_req_packet *) packet_data;

			if ( (scsi_data_out_req_pkt->reserved != 0) || (scsi_data_out_req_pkt->reserved2 != 0) || (scsi_data_out_req_pkt->reserved3 != 0) || (scsi_data_out_req_pkt->reserved4 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_LOGOUT_REQ : {
			if ( (int8_t) packet_data->opcode < 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // MSB always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_logout_req_packet *logout_req_pkt = (const iscsi_logout_req_packet *) packet_data;

			if ( (logout_req_pkt->reason_code >= 0) || (logout_req_pkt->reserved != 0) || (logout_req_pkt->reserved2 != 0) || (logout_req_pkt->reserved3 != 0) || (logout_req_pkt->reserved4[0] != 0) || (logout_req_pkt->reserved4[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reason code always MUST have bit 7 set and Reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_CLIENT_SNACK_REQ : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_snack_req_packet *snack_req_pkt = (const iscsi_snack_req_packet *) packet_data;

			if ( (snack_req_pkt->type >= 0) || (snack_req_pkt->reserved != 0) || (snack_req_pkt->reserved2 != 0) || (snack_req_pkt->reserved3 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bit 7 of type always MUST be set and reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

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

			if ( (nop_in_pkt->flags != -0x80) || (nop_in_pkt->reserved != 0) || (nop_in_pkt->reserved2[0] != 0) || (nop_in_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Flags always MUST be 0x80 for now and remaining reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_SCSI_RESPONSE : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_scsi_response_packet *scsi_response_pkt = (iscsi_scsi_response_packet *) packet_data;

			if ( scsi_response_pkt->flags >= 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Flags always MUST have bit 7 set -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_TASK_FUNC_RES : {
			if ( (packet_data->opcode != opcode) || (ahs_len != 0) || (ds_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared, AHS and DataSegment MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_task_mgmt_func_response_packet *task_mgmt_func_response_pkt = (const iscsi_task_mgmt_func_response_packet *) packet_data;

			if ( (task_mgmt_func_response_pkt->flags != -0x80) || (task_mgmt_func_response_pkt->reserved != 0) || (task_mgmt_func_response_pkt->reserved2 != 0) || (task_mgmt_func_response_pkt->reserved3 != 0) || (task_mgmt_func_response_pkt->reserved4 != 0) || (task_mgmt_func_response_pkt->reserved5 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Flags must be always 0x80 for now and remaining reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_LOGIN_RES : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data is mandatory

			const iscsi_login_response_packet *login_response_pkt = (const iscsi_login_response_packet *) packet_data;

			if ( (ISCSI_VERSION_MIN < login_response_pkt->version_max) || (ISCSI_VERSION_MAX > login_response_pkt->version_max) || (ISCSI_VERSION_MIN < login_response_pkt->version_active) || (ISCSI_VERSION_MAX > login_response_pkt->version_active) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_UNSUPPORTED_VERSION;

			if ( (ISCSI_LOGIN_RESPONSE_FLAGS_GET_CURRENT_STAGE(login_response_pkt->flags) == ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_RESERVED) || ((ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(login_response_pkt->flags) == ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_RESERVED) && ((login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0)) || ((login_response_pkt->flags < 0) && ((login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_CONTINUE) != 0)) || (login_response_pkt->flags & ~(ISCSI_LOGIN_RESPONSE_FLAGS_CONTINUE | ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0) || (login_response_pkt->reserved != 0) || (login_response_pkt->reserved2 != 0) || (login_response_pkt->reserved3 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Current Stage (CSG) is set to reserved and Next Stage (NSG) is reserved and T bit is set, if C bit is set, T MUST be cleared and reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			return iscsi_validate_key_value_pairs( ((const uint8_t *) login_response_pkt) + iscsi_align(ds_len, ISCSI_ALIGN_SIZE), ds_len );

			break;
		}
		case ISCSI_SERVER_TEXT_RES : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_text_response_packet *text_response_pkt = (const iscsi_text_response_packet *) packet_data;

			if ( ((text_response_pkt->flags < 0) && ((text_response_pkt->flags & ISCSI_TEXT_RESPONSE_FLAGS_CONTINUE) != 0)) || (text_response_pkt->flags & ~(ISCSI_TEXT_RESPONSE_FLAGS_CONTINUE | ISCSI_TEXT_RESPONSE_FLAGS_FINAL) != 0) || (text_response_pkt->reserved != 0) || (text_response_pkt->reserved2[0] != 0) || (text_response_pkt->reserved2[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // If C bit is set, F MUST be cleared and reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			return iscsi_validate_key_value_pairs( ((const uint8_t *) text_response_pkt) + iscsi_align(ds_len, ISCSI_ALIGN_SIZE), ds_len );

			break;
		}
		case ISCSI_SERVER_SCSI_DATA_IN : {
			if ( packet_data->opcode != opcode )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode -> invalid iSCSI packet data

			const iscsi_scsi_data_in_response_packet *scsi_data_in_pkt = (const iscsi_scsi_data_in_response_packet *) packet_data;

			if ( scsi_data_in_pkt->reserved != 0 )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Reserved field needs to be zero, but is NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_LOGOUT_RES : {
			if ( (packet_data->opcode != opcode) || (ahs_len != 0) || (ds_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared, AHS and DataSegment MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_logout_response_packet *logout_response_pkt = (const iscsi_logout_response_packet *) packet_data;

			if ( (logout_response_pkt->flags != -0x80) || (logout_response_pkt->reserved != 0) || (logout_response_pkt->reserved2 != 0) || (logout_response_pkt->reserved3 != 0) || (logout_response_pkt->reserved4 != 0) || (logout_response_pkt->reserved5 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Flags must be always 0x80 for now and remaining reserved fields need all to be zero, but are NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_READY_XFER : {
			if ( (packet_data->opcode != opcode) || (ahs_len != 0) || (ds_len != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // AHS and DataSegment MUST be zero according to specs -> invalid iSCSI packet data

			const iscsi_r2t_packet *r2t_pkt = (const iscsi_r2t_packet *) packet_data;

			if ( (r2t_pkt->flags != -0x80) || (r2t_pkt->reserved != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Flags must be always 0x80 for now and remaining reserved field needs to be zero, but is NOT -> invalid iSCSI packet data

			break;
		}
		case ISCSI_SERVER_ASYNC_MSG : {
			if ( (packet_data->opcode != opcode) || (ds_len == 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Bits 6 and 7 always MUST be cleared for this opcode and DataSegment is mandatory -> invalid iSCSI packet data

			const iscsi_async_msg_packet *async_msg_pkt = (const iscsi_async_msg_packet *) packet_data;

			if ( (async_msg_pkt->flags != -0x80) || (async_msg_pkt->tag != 0xFFFFFFFFUL) || (async_msg_pkt->reserved != 0) || (async_msg_pkt->reserved2 != 0) || (async_msg_pkt->reserved3 != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Flags must be always 0x80 for now, remaining reserved fields need all to be zero, but are NOT and tag always MUST be 0xFFFFFFFF -> invalid iSCSI packet data

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

			if ( (reject_pkt->flags != -0x80) || (reject_pkt->tag != 0xFFFFFFFFUL) || (reject_pkt->reserved != 0) || (reject_pkt->reserved2 != 0) || (reject_pkt->reserved3 != 0) || (reject_pkt->reserved4[0] != 0) || (reject_pkt->reserved4[1] != 0) )
				return ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS; // Flags must be always 0x80 for now, remaining reserved fields need all to be zero, but are NOT and tag always MUST be 0xFFFFFFFF -> invalid iSCSI packet data

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
 * @brief Extracts a single text key / value pairs out of an iSCSI packet into a hash map.
 *
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
	const uint key_val_len = (uint) strnlen( (char *) packet_data, len );
	const uint8_t *key_end = memchr( packet_data, '=', key_val_len );

	if ( key_end == NULL ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Key / value separator '=' not found" );

		return -1L;
	}

	const uint key_len = (uint) (key_end - packet_data);

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

	const uint val_len = (uint) strnlen( (char *) (key_end + 1UL), key_val_len - key_len - 1UL );
	const uint max_len = (strcmp( (char *) hash_key, "CHAP_C" ) == 0) || (strcmp( (char *) hash_key, "CHAP_R" ) == 0) ? ISCSI_TEXT_VALUE_MAX_LEN : ISCSI_TEXT_VALUE_MAX_SIMPLE_LEN;

	if ( val_len > max_len ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Value length larger than iSCSI specs allow" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1L;
	}

	uint8_t *hash_val = (uint8_t *) malloc( iscsi_align(val_len + 1UL, ISCSI_HASHMAP_VALUE_ALIGN) );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_parse_text_key_value_pair: Out of memory allocating memory for value string" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1L;
	}

	memcpy( hash_val, key_end + 1, val_len );

	const int rc = iscsi_hashmap_put( pairs, hash_key, hash_key_len, hash_val );

	if ( rc < 0 )
		return -1L;

	return (int) (hash_key_len + val_len + 1UL); // Number of bytes for processed key / value pair (+1 for '=' and NUL terminator)
}

/**
 * @brief Extracts all text key / value pairs out of an iSCSI packet into a hash map.
 *
 * Parses and extracts all key and value pairs out of iSCSI packet
 * data amd puts the extracted data into a hash map to be used by
 * the iSCSI implementation.
 *
 * @param[in] pairs Pointer to hash map that should contain all
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
int iscsi_parse_key_value_pairs(iscsi_hashmap *pairs, const uint8_t *packet_data, uint len, int c_bit, uint8_t **partial_pairs)
{
	if ( len == 0 )
		return 0L; // iSCSI specs don't allow zero length

	if ( (partial_pairs != NULL) && (*partial_pairs != NULL) ) { // Strip partial text parameters in case C bit was enabled previously
		uint key_val_pair_len;

		for (key_val_pair_len = 0; (key_val_pair_len < len) && packet_data[key_val_pair_len] != '\0'; key_val_pair_len++) {
		}

		uint8_t *tmp_partial_buf = iscsi_sprintf_alloc( "%s%s", *partial_pairs, (const char *) packet_data );

		if ( tmp_partial_buf == NULL )
			return -1L;

		const int rc = iscsi_parse_text_key_value_pair( pairs, tmp_partial_buf, (uint32_t) (key_val_pair_len + strlen( (char *) *partial_pairs )) );
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

	while ( ((uint) offset < len) && (packet_data[offset] != '\0') ) {
		const int rc = iscsi_parse_text_key_value_pair( pairs, (packet_data + offset), (len - offset) );

		if ( rc < 0 )
			return -1L;

		offset += rc;
	}

	return 0L;
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
	const uint key_len = (uint) strlen( (char *) key ) + 1;

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
	const uint key_len = (uint) strlen( (char *) key ) + 1;
	uint8_t *hash_key = iscsi_hashmap_key_create( key, key_len );

	if ( hash_key == NULL ) {
		logadd( LOG_ERROR, "iscsi_add_key_value_pair: Out of memory allocating key" );

		return -1L;
	}

	const uint val_len = (uint) strlen( (char *) value ) + 1;
	uint8_t *hash_val = (uint8_t *) malloc( iscsi_align(val_len, ISCSI_HASHMAP_VALUE_ALIGN) );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_add_key_value_pair: Out of memory allocating string value" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1L;
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
	const uint key_len = (uint) strlen( (char *) key ) + 1;
	uint8_t *hash_key = iscsi_hashmap_key_create( key, key_len );

	if ( hash_key == NULL ) {
		logadd( LOG_ERROR, "iscsi_update_key_value_pair: Out of memory allocating key" );

		return -1L;
	}

	const uint val_len = (uint) strlen( (char *) value ) + 1;
	uint8_t *hash_val = (uint8_t *) malloc( iscsi_align(val_len, ISCSI_HASHMAP_VALUE_ALIGN) );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_update_key_value_pair: Out of memory allocating string value" );

		iscsi_hashmap_key_destroy( hash_key );

		return -1L;
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
static int iscsi_add_int_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, const int value)
{
	const uint8_t *hash_val = iscsi_sprintf_alloc( "%d", value );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_add_int_key_value_pair: Out of memory allocating integer value." );

		return -1L;
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
static int iscsi_update_int_key_value_pair(iscsi_hashmap *key_value_pairs, const uint8_t *key, const int value)
{
	const uint8_t *hash_val = iscsi_sprintf_alloc( "%d", value );

	if ( hash_val == NULL ) {
		logadd( LOG_ERROR, "iscsi_update_int_key_value_pair: Out of memory allocating integer value." );

		return -1L;
	}

	return iscsi_update_key_value_pair( key_value_pairs, key, hash_val );
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
		*out_value = (strcasecmp( (char *) value, "Yes" ) == 0) ? true : false;

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
 * @brief Creates and initializes an iSCSI portal group.
 *
 * Specified tag and flags are used for portal group
 * initialization.
 * @param[in] tag Tag to associate with the portal group.
 * @param[in] flags Flags to set for the portal group.
 * @return Pointer to allocated and initialized portal group
 * or NULL in case of memory
 */
iscsi_portal_group *iscsi_portal_group_create(const int tag, const int flags)
{
	iscsi_portal_group *portal_group = (iscsi_portal_group *) malloc( sizeof(struct iscsi_portal_group) );

	if ( portal_group == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_create: Out of memory allocating iSCSI portal group structure" );

		return NULL;
	}

	portal_group->portals = iscsi_hashmap_create( 0UL );

	if ( portal_group->portals == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_create: Out of memory allocating iSCSI portal hash map" );

		free( portal_group );

		return NULL;
	}

	portal_group->ref_count  = 0L;
	portal_group->tag        = tag;
	portal_group->flags      = flags;
	portal_group->chap_group = 0L;

	return portal_group;
}

/**
 * @brief iSCSI portal destructor callback for hash map.
 *
 * Callback function for deallocation of an iSCSI
 * portal stored in the iSCSI portal group hash map.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
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

	return 0L;
}

/**
 * @brief Deallocates resources acquired by iscsi_portal_group_create.
 *
 * This function frees the associated hash map containing the
 * poptals and the structure itself.
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
 * @param[in] iSCSI portal group to add portal to. May NOT be NULL,
 * so take caution.
 * @param[in] iSCSI portal to add to portal group. NULL is NOT
 * allowed here, so be careful.
 * @retval -1 An error occured during adding the portal,
 * usually caused by memory exhaustion
 * @retval 0 The portal has been added successfully to the
 * portal group.
 */
int iscsi_portal_group_add_portal(iscsi_portal_group *portal_group, iscsi_portal *portal)
{
	uint8_t *tmp_buf = iscsi_sprintf_alloc( "%s:%s", portal->host, portal->port );

	if ( tmp_buf == NULL )
		return -1L;

	const uint key_len = (uint) strlen( (char *) tmp_buf ) + 1;
	uint8_t *key = iscsi_hashmap_key_create( tmp_buf, key_len );

	free( tmp_buf );

	if ( key == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_group_add_portal: Out of memory allocating key for iSCSI portal" );

		return -1L;
	}

	int rc = iscsi_hashmap_put( portal_group->portals, key, key_len, (uint8_t *) portal );

	if ( rc < 0 ) {
		logadd( LOG_ERROR, "iscsi_portal_group_add_portal: Adding portal to hash map containing iSCSI portal group failed" );

		iscsi_hashmap_key_destroy( key );

		return rc;
	}

	portal->group = portal_group;

	return 0L;
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

	const uint host_len = (uint) strlen( (char *) host ) + 1;

	portal->host = (uint8_t *) malloc( host_len );

	if ( portal->host == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_create: Out of memory allocating iSCSI portal host name" );

		return NULL;
	}

	memcpy( portal->host, host, host_len );

	const uint port_len = (uint) strlen( (char *) port ) + 1;

	portal->port = (uint8_t *) malloc( port_len );

	if ( portal->port == NULL ) {
		logadd( LOG_ERROR, "iscsi_portal_create: Out of memory allocating iSCSI portal port" );

		return NULL;
	}

	memcpy( portal->port, port, port_len );

	portal->sock = -1L;

	return portal;
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

	const uint name_len = (uint) strlen( (char *) name ) + 1;

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

	const uint name_len = (uint) strlen( (char *) tmp_buf ) + 1;
	const uint len = iscsi_align(name_len, ISCSI_ALIGN_SIZE);

	if ( (len < 20UL) || ((len + offsetof(struct iscsi_transport_id, name)) >= 65536UL) ) {
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

	port->transport_id->id       = (ISCSI_TRANSPORT_ID_FORMAT << 6U) | ISCSI_TRANSPORT_ID_PROTOCOL_ID_ISCSI;
	port->transport_id->reserved = 0U;
	iscsi_put_be16( (uint8_t *) &port->transport_id->add_len, (uint16_t) len );

	memcpy( ((uint8_t *) port->transport_id) + offsetof(struct iscsi_transport_id, name), tmp_buf, name_len );
	memset( ((uint8_t *) port->transport_id) + offsetof(struct iscsi_transport_id, name) + name_len, 0, (name_len & (ISCSI_ALIGN_SIZE - 1)) );

	port->transport_id_len = (uint16_t) (offsetof(struct iscsi_transport_id, name) + len);

	return ISCSI_CONNECT_PDU_READ_OK;
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
 * @brief Finds an iSCSI target node by case insensitive name search.
 *
 * Callback function for each element while iterating
 * through the iSCSI target nodes.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[in] value Value of the key, NULL creates an
 * empty key assignment.
 * @param[in,out] user_data Pointer to a data structure
 * containing the iSCSI target node and the name to be
 * searched for and may NOT be NULL, so be careful.
 * @retval -1 The target node has been found and stored
 * in the result strcuture. Therefore, no further
 * searching is needed.
 * @retval 0 The target node has not been found yet.
 */
int iscsi_target_node_find_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data)
{
	iscsi_target_node_find_name *target_find = (iscsi_target_node_find_name *) user_data;
	iscsi_target_node *target = (iscsi_target_node *) value;

	if ( strcasecmp( (char *) target->name, (char *) target_find->name ) != 0 )
		return 0L;

	target_find->target = target;

	return -1L;
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

	iscsi_hashmap_iterate( iscsi_globvec->target_nodes, iscsi_target_node_find_callback, (uint8_t *) &target_find );

	return target_find.target;
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

	return 0L;
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

	session->max_conns              = ISCSI_SESSION_DEFAULT_MAX_CONNECTIONS;
	session->max_outstanding_r2t    = ISCSI_SESSION_DEFAULT_MAX_OUTSTANDING_R2T;
	session->default_time_to_wait   = ISCSI_SESSION_DEFAULT_TIME_TO_WAIT;
	session->default_time_to_retain = ISCSI_SESSION_DEFAULT_TIME_TO_RETAIN;
	session->first_burst_len        = ISCSI_SESSION_DEFAULT_FIRST_BURST_LEN;
	session->max_burst_len          = ISCSI_SESSION_DEFAULT_MAX_BURST_LEN;
	session->init_r2t               = ISCSI_SESSION_DEFAULT_INIT_R2T;
	session->immediate_data         = ISCSI_SESSION_DEFAULT_IMMEDIATE_DATA;
	session->data_pdu_in_order      = ISCSI_SESSION_DEFAULT_DATA_PDU_IN_ORDER;
	session->data_seq_in_order      = ISCSI_SESSION_DEFAULT_DATA_SEQ_IN_ORDER;
	session->err_recovery_level     = ISCSI_SESSION_DEFAULT_ERR_RECOVERY_LEVEL;
	session->tag                    = conn->pg_tag;

	session->connections = iscsi_hashmap_create( session->max_conns );

	if ( session->connections == NULL ) {
		logadd( LOG_ERROR, "iscsi_session_create: Out of memory allocating iSCSI session connection hash map" );

		free( session );

		return NULL;
	}

	uint8_t *conn_key = iscsi_hashmap_key_create( (uint8_t *) &conn->cid, sizeof(conn->cid) );

	if ( conn_key == NULL ) {
		logadd( LOG_ERROR, "iscsi_session_create: Out of memory allocating iSCSI session connection hash map" );

		iscsi_hashmap_destroy( session->connections );
		free( session );

		return NULL;
	}

	iscsi_hashmap_put( session->connections, conn_key, sizeof(conn->cid), (uint8_t *) conn );

	session->target                     = target;
	session->isid                       = 0LL;
	session->type                       = type;
	session->current_text_init_task_tag = 0xFFFFFFFFUL;

	session->key_value_pairs = iscsi_hashmap_create( 32UL );

	if ( session->key_value_pairs == NULL ) {
		logadd( LOG_ERROR, "iscsi_session_create: Out of memory allocating iSCSI session key and value pairs hash map" );

		iscsi_hashmap_key_destroy( conn_key );
		iscsi_hashmap_destroy( session->connections );
		free( session );

		return NULL;
	}

	int rc = iscsi_session_init_key_value_pairs( session->key_value_pairs );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS, session->max_conns );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T, session->max_outstanding_r2t );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_WAIT, session->default_time_to_wait );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_RETAIN, session->default_time_to_retain );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN, session->first_burst_len );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, session->max_burst_len );
	rc    |= iscsi_update_bool_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA, session->immediate_data );
	rc    |= iscsi_update_bool_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_PDU_IN_ORDER, session->data_pdu_in_order );
	rc    |= iscsi_update_bool_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_SEQ_IN_ORDER, session->data_seq_in_order );
	rc    |= iscsi_update_int_key_value_pair( session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_ERR_RECOVERY_LEVEL, session->err_recovery_level );
	rc    |= iscsi_update_int_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN, conn->max_recv_ds_len );

	if ( rc != 0 ) {
		logadd( LOG_ERROR, "iscsi_session_create: Out of memory adding iSCSI session key and integer value pair" );

		iscsi_hashmap_iterate( session->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
		iscsi_hashmap_destroy( session->key_value_pairs );
		iscsi_hashmap_key_destroy( conn_key );
		iscsi_hashmap_destroy( session->connections );
		free( session );

		return NULL;
	}

	return session;
}

/**
 * @brief Deallocates all resources acquired by iscsi_session_create.
 *
 * This function also frees the associated key and value pairs,
 * the attached connections as well as frees the initator port.
 *
 * @param[in] session iSCSI session to be freed. May be NULL
 * in which case this function does nothing at all.
 */
void iscsi_session_destroy(iscsi_session *session)
{
	if ( session != NULL ) {
		session->tag    = 0L;
		session->target = NULL;
		session->type   = ISCSI_SESSION_TYPE_INVALID;

		if ( session->key_value_pairs != NULL ) {
			iscsi_hashmap_iterate( session->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( session->key_value_pairs );

			session->key_value_pairs = NULL;
		}

		if ( session->connections != NULL ) {
			iscsi_hashmap_iterate( session->connections, iscsi_connection_destroy_callback, NULL );
			iscsi_hashmap_destroy( session->connections );

			session->connections = NULL;
		}

		if ( session->initiator_port != NULL ) {
			iscsi_port_destroy( session->initiator_port );

			session->initiator_port = NULL;
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
	for ( uint i = 0; lut[i].key != NULL; i++ ) {
		const int rc = iscsi_add_key_value_pair( key_value_pairs, lut[i].key, lut[i].value );

		if ( rc < 0 )
			return rc;
	}

	return 0L;
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
	conn->key_value_pairs = iscsi_hashmap_create( 32UL );

	if ( conn->key_value_pairs == NULL ) {
		logadd( LOG_ERROR, "iscsi_create_connection: Out of memory while allocating iSCSI text key / value pair hash map" );

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

	conn->partial_pairs      = NULL;
	conn->device             = NULL;
	conn->init_port          = NULL;
	conn->init_name          = NULL;
	conn->init_adr           = NULL;
	conn->target             = NULL;
	conn->target_port        = NULL;
	conn->target_name_short  = NULL;
	conn->portal_host        = NULL;
	conn->portal_port        = NULL;
	conn->header_digest      = 0L;
	conn->data_digest        = 0L;
    conn->pdu_processing     = NULL;
	conn->login_response_pdu = NULL;
	conn->id                 = 0L;
	conn->sock               = sock;
	conn->pdu_recv_state     = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_READY;
	conn->flags              = 0L;
	conn->state              = ISCSI_CONNECT_STATE_INVALID;
	conn->login_phase        = ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION;
	conn->max_recv_ds_len    = ISCSI_DEFAULT_RECV_DS_LEN;
	conn->pg_tag             = portal->group->tag;
	conn->isid.a             = 0;
	conn->isid.b             = 0;
	conn->isid.c             = 0;
	conn->isid.d             = 0;
	conn->tsih               = 0U;
	conn->cid           	 = 0U;
	conn->init_task_tag      = 0UL;
	conn->auth_chap.phase    = ISCSI_AUTH_CHAP_PHASE_NONE;
	conn->chap_group         = 0L;
	conn->stat_sn            = 0UL;
	conn->exp_stat_sn        = 0UL;

	return conn;
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
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
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

	return 0L;
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
		if ( conn->portal_port != NULL ) {
			free ( conn->portal_port );

			conn->portal_port = NULL;
		}

		if ( conn->portal_host != NULL ) {
			free ( conn->portal_host );

			conn->portal_host = NULL;
		}

		if ( conn->target_name_short != NULL ) {
			free ( conn->target_name_short );

			conn->target_name_short = NULL;
		}

		if ( conn->init_adr != NULL ) {
			free ( conn->init_adr );

			conn->init_adr = NULL;
		}

		if ( conn->init_name != NULL ) {
			free ( conn->init_name );

			conn->init_name = NULL;
		}

		if ( conn->partial_pairs != NULL ) {
			free ( conn->partial_pairs );

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
 * The TCP socket is marked as non-blocking, so this function may not read
 * all data requested.
 *
 * Returns ISCSI_CONNECT_PDU_READ_ERR_FATAL if the operation
 * indicates a fatal error with the TCP connection (including
 * if the TCP connection was closed unexpectedly).
 *
 * Otherwise returns the number of bytes successfully read.
 */
int iscsi_connection_read(const iscsi_connection *conn, uint8_t *buf, const uint len)
{
	if ( len == 0 )
		return 0;

	const int rc = (int) recv( conn->sock, buf, len, MSG_WAITALL );

	return (rc > 0) ? rc : ISCSI_CONNECT_PDU_READ_ERR_FATAL;
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
int iscsi_connection_write(const iscsi_connection *conn, uint8_t *buf, const uint len)
{
	if ( len == 0 )
		return 0;

	const int rc = (int) send( conn->sock, buf, len, 0L );

	return (rc > 0) ? rc : ISCSI_CONNECT_PDU_READ_ERR_FATAL;
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
 * containing its attributes and may NOT
 * be NULL, so be careful.
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
static int iscsi_append_special_key_value_pair_packet(iscsi_connection *conn, iscsi_key_value_pair *key_value_pair, const uint8_t *key, uint8_t *buf, uint pos, const uint len)
{
	if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_OVERRIDE_DEFAULT) != 0 ) {
		if ( (int) (len - pos) < 1L )
			return -1L;

		pos += snprintf( (char *) (buf + pos), (len - pos), "%s=%ld", key, ISCSI_DEFAULT_MAX_RECV_DS_LEN ) + 1;
	}

	if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_OTHER_MAX_VALUE) != 0 ) {
		if ( (int) (len - pos) < 1L )
			return -1L;

		uint8_t *first_burst_len_val = NULL;
		int rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN, &first_burst_len_val );
		uint first_burst_len = (rc < 0) ? ISCSI_SESSION_DEFAULT_FIRST_BURST_LEN : (uint) atol( (char *) first_burst_len_val );

		uint8_t *max_burst_len_val;
		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, &max_burst_len_val );
		uint max_burst_len = (rc < 0) ? ISCSI_SESSION_DEFAULT_MAX_BURST_LEN : (uint) atol( (char *) max_burst_len_val );

		if ( first_burst_len > max_burst_len ) {
			first_burst_len = max_burst_len;

			if ( first_burst_len_val != NULL ) {
				sprintf( (char *) first_burst_len_val, "%d", first_burst_len );
			}
		}

		pos += snprintf( (char *) (buf + pos), (len - pos), "%s=%d", key, first_burst_len ) + 1;
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
 * its attributes and may NOT be NULL, so be
 * careful.
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
static int iscsi_append_key_value_pair_packet(const iscsi_key_value_pair *key_value_pair, const uint8_t *key, const uint8_t *value, uint8_t *buf, uint pos, const uint len)
{
	if ( (key_value_pair->type != ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE) && (key_value_pair->type != ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE) ) {
		if ( (int) (len - pos) < 1L )
			return -1L;

		pos += snprintf( (char *) (buf + pos), (len - pos), "%s=%s", key, value ) + 1;
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
static uint8_t *iscsi_negotiate_key_value_pair_list(const iscsi_key_value_pair *key_value_pair, uint8_t *old_value)
{
	const uint8_t *list = key_value_pair->list_range;

	do {
		if ( strcasecmp( (char *) list, (char *) old_value ) == 0 )
			return old_value;

		list += (strlen( (char *) list ) + 1);
	} while ( list[0] != '\0' );

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
	int old_int_val = (int) atol( (char *) key_value_pair->value );

	if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_PREVIOUS_VALUE) != 0 )
		old_int_val = (int) atol( (char *) old_value );

	int int_val = (int) atol( (char *) value );

	const uint8_t *range = key_value_pair->list_range;
	const int range_min = (int) atol( (char *) range );
	const int range_max = (int) atol( (char *) (range + strlen( (char *) range ) + 1) );

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

	sprintf( (char *) old_value, "%d", old_int_val );

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
	const uint8_t *list_bool_false = list_bool_true + strlen( (char *) list_bool_true ) + 1;

	if ( (strcasecmp( (char *) old_value, (char *) list_bool_true ) == 0) || (strcasecmp( (char *) old_value, (char *) list_bool_false ) == 0) ) {
		*update_key_value_pair = 0L;

		return (uint8_t *) "Reject";
	}

	if ( strcasecmp( (char *) value, (char *) bool_value ) == 0 )
		return bool_value;

	return key_value_pair->value;
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
			uint8_t *list_bool_false = list_bool_true + strlen( (char *) list_bool_true ) + 1;

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
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
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
	int type = 0L;
	int rc = iscsi_hashmap_get( iscsi_globvec->connection_key_value_pairs, key, key_size, (uint8_t **) &key_value_pair);

	if ( rc < 0 ) {
		key_value_pairs = conn->session->key_value_pairs;
		type = 1L;

		rc = iscsi_hashmap_get( iscsi_globvec->session_key_value_pairs, key, key_size, (uint8_t **) &key_value_pair);
	}

	if ( (rc == 0) && (key_value_pair->flags & (ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE | ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_SPECIAL_HANDLING)) != 0 )
		return 0L;

	int update_key_value_pair = 1L;
	uint8_t *conn_sess_val;

	if ( rc < 0 ) {
		conn_sess_val = (uint8_t *) "NotUnderstood";

		update_key_value_pair = 0L;
	} else if ( (key_value_pair_packet->discovery != 0) && ((key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE) != 0) ) {
		conn_sess_val = (uint8_t *) "Irrelevant";

		update_key_value_pair = 0L;
	} else {
		rc = iscsi_negotiate_key_value_pairs_state( conn, key_value_pair, type );

		if ( rc < 0 )
			return rc;

		rc = iscsi_hashmap_get( key_value_pairs, key, key_size, &conn_sess_val );
	}

	if ( (key_value_pair != NULL) && (key_value_pair->type > ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_UNSPECIFIED) ) {
		if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_PREVIOUS_VALUE) != 0 ) {
			uint8_t *max_burst_len_val;
			uint first_burst_len = (uint) atol( (char *) value );
			uint max_burst_len;

			rc = iscsi_get_key_value_pair( key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, &max_burst_len_val );

			max_burst_len = (rc < 0) ? ISCSI_SESSION_DEFAULT_MAX_BURST_LEN : (uint) atol( (char *) max_burst_len_val );

			if ( (first_burst_len < ISCSI_MAX_DS_SIZE) && (first_burst_len > max_burst_len) )
				sprintf( (char *) value, "%d", first_burst_len );
		}

		if ( (key_value_pair->flags & ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE) != 0 )
			update_key_value_pair = 0L;

		conn_sess_val = iscsi_negotiate_key_value_pair_all( key_value_pair, value, conn_sess_val, &update_key_value_pair );
	}

	if ( conn_sess_val != NULL ) {
		if ( update_key_value_pair != 0 )
			iscsi_update_key_value_pair( key_value_pairs, key, conn_sess_val );

		key_value_pair_packet->pos = iscsi_append_key_value_pair_packet( key_value_pair, key, conn_sess_val, key_value_pair_packet->buf, key_value_pair_packet->pos, key_value_pair_packet->len );

		if ( (int) key_value_pair_packet->pos < 0 )
			return key_value_pair_packet->pos;

		key_value_pair_packet->pos = iscsi_append_special_key_value_pair_packet( conn, key_value_pair, key, key_value_pair_packet->buf, key_value_pair_packet->pos, key_value_pair_packet->len );

		if ( (int) key_value_pair_packet->pos < 0 )
			return key_value_pair_packet->pos;
	}

	return 0L;
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
int iscsi_negotiate_key_value_pairs(iscsi_connection *conn, iscsi_hashmap *key_value_pairs, uint8_t *buf, const uint pos, const uint len)
{
	if ( pos > len ) {
		buf[len - 1] = '\0';

		return len;
	}

	uint8_t *type;
	int rc = iscsi_get_key_value_pair( key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, &type );

	if ( rc < 0 )
		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, &type );

	const int discovery = ((rc == 0) && (strcasecmp( (char *) type, "Discovery" ) == 0)) ? 1L : 0L;

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
 * @param[in] conn iSCSI connection which holds the
 * copies of the key and value pairs.
 * @retval -1 An error occured during the copy process,
 * e.g. memory is exhausted.
 * @retval 0 All key and value pairs were copied successfully.
 */
int iscsi_connection_copy_key_value_pairs(iscsi_connection *conn)
{
	int32_t int_val;

	int rc = iscsi_get_int_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN, &int_val);

	if ( rc != 0 )
		return rc;

	if ( (int_val <= 0L) || (int_val > (int32_t) ISCSI_DEFAULT_MAX_RECV_DS_LEN) )
		int_val = ISCSI_DEFAULT_MAX_RECV_DS_LEN;

	conn->max_recv_ds_len = int_val;

	uint8_t *value;

	rc = iscsi_get_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST, &value);

	if ( rc != 0 )
		return rc;

	conn->header_digest = (strcasecmp( (char *) value, "CRC32C" ) == 0) ? ISCSI_DIGEST_SIZE : 0L;

	rc = iscsi_get_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST, &value);

	if ( rc != 0 )
		return rc;

	conn->data_digest = (strcasecmp( (char *) value, "CRC32C" ) == 0) ? ISCSI_DIGEST_SIZE : 0L;

	rc = iscsi_get_int_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->max_conns = int_val;

	rc = iscsi_get_int_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->max_outstanding_r2t = int_val;

	rc = iscsi_get_int_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->first_burst_len = int_val;

	rc = iscsi_get_int_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->max_burst_len = int_val;

	rc = iscsi_get_bool_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->init_r2t = int_val;

	rc = iscsi_get_bool_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA, &int_val);

	if ( rc != 0 )
		return rc;

	conn->session->immediate_data = int_val;

	return 0L;
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
static int iscsi_connection_auth_key_value_pairs(iscsi_connection *conn, iscsi_hashmap *key_value_pairs, const uint8_t *auth_method, uint8_t *buf, const uint pos, const uint len)
{
	// TODO: Implement CHAP and other authentication methods.

	return 0L;
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
	if ( (conn->session->first_burst_len > conn->session->max_burst_len) || (conn->session->first_burst_len < 512) || (conn->session->max_burst_len < 512) || (conn->session->max_burst_len > ISCSI_SESSION_DEFAULT_MAX_BURST_LEN) || (conn->max_recv_ds_len < 512) || (conn->max_recv_ds_len > ISCSI_SESSION_DEFAULT_MAX_BURST_LEN) )
		return -1L;

	return 0L;
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
		return -1L;

	uint recv_buf_len = conn->session->first_burst_len;

	if ( recv_buf_len < 4096 )
		recv_buf_len = 4096UL;
	else if ( recv_buf_len > 8192 )
		recv_buf_len = 8192UL;

	recv_buf_len  += (uint) (sizeof(struct iscsi_bhs_packet) + ISCSI_MAX_AHS_SIZE + conn->header_digest + conn->data_digest); // BHS + maximum AHS size + header and data digest overhead
	recv_buf_len <<= 2UL; // Receive up to four streams at once.

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
 * packet with.
 * @param[in] login_response_pdu Pointer to login response PDU to
 * be sent via TCP/IP.
 * @param[in] key_value_pairs Pointer to hash map of key and value pairs
 * to be used for login response storage.
 * @paran[in] callback Pointer to post processing callback function
 * after sending the TCP/IP packet.
 */
static void iscsi_connection_pdu_login_response(iscsi_connection *conn, iscsi_pdu *login_response_pdu, iscsi_hashmap *key_value_pairs, iscsi_connection_xfer_complete_callback callback)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	login_response_pkt->version_max    = ISCSI_VERSION_MAX;
	login_response_pkt->version_active = ISCSI_VERSION_MAX;

	iscsi_put_be24( (uint8_t *) &login_response_pkt->ds_len, login_response_pdu->ds_len );
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

	iscsi_hashmap_iterate( key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
	iscsi_hashmap_destroy( key_value_pairs );

	iscsi_connection_pdu_write( conn, login_response_pdu, callback, (uint8_t *) conn );
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
static int iscsi_login_response_init(iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu)
{
	iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) pdu->bhs_pkt;
	iscsi_login_response_packet *bhs_pkt  = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	bhs_pkt->opcode = ISCSI_SERVER_LOGIN_RES;

	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) iscsi_append_ds_packet( (iscsi_bhs_packet *) bhs_pkt, pdu->header_digest_size, ISCSI_DEFAULT_RECV_DS_LEN, pdu->data_digest_size );

	if ( login_response_pkt == NULL ) {
		bhs_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
		bhs_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	login_response_pdu->bhs_pkt     = (iscsi_bhs_packet *) login_response_pkt;
	login_response_pdu->ds_cmd_data = (iscsi_ds_cmd_data *) (((uint8_t *) login_response_pkt) + sizeof(struct iscsi_bhs_packet) + pdu->header_digest_size);
	login_response_pdu->ds_len      = ISCSI_DEFAULT_RECV_DS_LEN;

	login_response_pkt->flags |= (int8_t) (login_req_pkt->flags & (ISCSI_LOGIN_REQ_FLAGS_TRANSIT | ISCSI_LOGIN_REQ_FLAGS_CONTINUE | ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_MASK));

	if ( (login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0 )
		login_response_pkt->flags |= (login_req_pkt->flags & ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_MASK);

	login_response_pkt->isid.a        = login_req_pkt->isid.a;
	login_response_pkt->isid.b        = login_req_pkt->isid.b; // Copying over doesn't change endianess.
	login_response_pkt->isid.c        = login_req_pkt->isid.c;
	login_response_pkt->isid.d        = login_req_pkt->isid.d; // Copying over doesn't change endianess.
	login_response_pkt->tsih          = login_req_pkt->tsih; // Copying over doesn't change endianess.'
	login_response_pkt->init_task_tag = login_req_pkt->init_task_tag; // Copying over doesn't change endianess.
	login_response_pdu->cmd_sn        = iscsi_get_be32(login_req_pkt->cmd_sn);

	if ( login_response_pkt->tsih != 0 )
		login_response_pkt->stat_sn = login_req_pkt->exp_stat_sn; // Copying over doesn't change endianess.'

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
	} else {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SUCCESS;
	}

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
 * and value pair for the initator name. May NOT be NULL,
 * so take caution.
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
	int rc = iscsi_get_key_value_pair( key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_NAME, &init_name );

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
	int rc = iscsi_get_key_value_pair( key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE, &type_str );

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
		if ( login_response_pkt->tsih != 0 ) {
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
		if ( iscsi_update_key_value_pair( login_response_pdu->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, redirect_adr ) == 0 ) {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_REDIRECT;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_REDIRECT_TEMP;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}

		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
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
	if ( tsih == 0 )
		return NULL;

	const uint64_t hash_key = tsih;
	iscsi_session *session;
	int rc = iscsi_hashmap_get( iscsi_globvec->sessions, (uint8_t *) &hash_key, sizeof(hash_key), (uint8_t **) &session );

	return (rc == 0) ? session : NULL;
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
 * @param[in] cid Connection ID (CID).
 * @return Upper 8 bits of contain status class, lower 8
 * bits status detail. All 16 bits set to zero
 * indicate success.
 */
static uint16_t iscsi_session_append(iscsi_connection *conn, const uint8_t *init_port_name, const uint16_t tsih, const uint16_t cid)
{
	iscsi_session *session = iscsi_session_get_by_tsih( tsih );

	if ( (session == NULL) || (conn->pg_tag != session->tag) || (strcasecmp( (char *) init_port_name, (char *) iscsi_port_get_name( session->initiator_port ) ) != 0) || (conn->target != session->target) )
		return (ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR << 8U) | ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_NO_SESSION_SPANNING;

	if ( iscsi_hashmap_size( session->connections ) >= session->max_conns )
		return (ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR << 8U) | ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_TOO_MANY_CONNECTIONS;

	conn->session = session;

	uint8_t *conn_key = iscsi_hashmap_key_create( (uint8_t *) &cid, sizeof(cid) );

	if ( conn_key == NULL )
		return (ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR << 8U) | ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

	iscsi_hashmap_put( session->connections, conn_key, sizeof(cid), (uint8_t *) conn );

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
	int rc = 0L;

	if ( login_response_pkt->tsih != 0 ) {
		rc = iscsi_session_append( conn, init_port_name, iscsi_get_be16(login_response_pkt->tsih), (uint16_t) cid );

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
void iscsi_login_response_reject_init(iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	login_response_pkt->opcode         = ISCSI_SERVER_LOGIN_RES;
	login_response_pkt->version_max    = ISCSI_VERSION_MAX;
	login_response_pkt->version_active = ISCSI_VERSION_MAX;
	login_response_pkt->init_task_tag  = ((iscsi_login_req_packet *) pdu->bhs_pkt)->init_task_tag;
	login_response_pkt->status_class   = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
	login_response_pkt->status_detail  = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_INVALID_LOGIN_REQ_TYPE;
}

/**
 * @brief Creates an iSCSI PDU structure used by connections.
 *
 * The PDU structure is used for allowing partial
 * reading from the TCP/IP socket and correctly
 * filling the data until everything has been read.
 *
 * @param[in] conn Pointer to connection to link the PDU with.
 * If this is NULL the connection has to be linked later.
 * @return Pointer to allocated and zero filled PDU or NULL
 * in case of an error (usually memory exhaustion).
 */
iscsi_pdu *iscsi_connection_pdu_create(iscsi_connection *conn)
{
	iscsi_pdu *pdu = (iscsi_pdu *) malloc( sizeof(struct iscsi_pdu) );

	if ( pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_pdu_create: Out of memory while allocating iSCSI PDU" );

		return NULL;
	}

	pdu->bhs_pkt = iscsi_create_packet();

	if ( pdu->bhs_pkt == NULL ) {
		free( pdu );

		return NULL;
	}

	pdu->ahs_pkt                = NULL;
	pdu->header_digest          = NULL;
	pdu->ds_cmd_data            = NULL;
	pdu->data_digest            = NULL;
	pdu->key_value_pairs        = iscsi_hashmap_create( 32UL );

	if ( pdu->key_value_pairs == NULL ) {
		free( pdu );

		return NULL;
	}

	pdu->flags                  = 0L;
	pdu->header_digest_size     = 0L;
	pdu->header_digest_read_len = 0UL;
	pdu->data_digest_size       = 0L;
	pdu->data_digest_read_len   = 0UL;
	pdu->bhs_read_len           = 0UL;
	pdu->ahs_len                = 0UL;
	pdu->ahs_read_len           = 0UL;
	pdu->ds_len                 = 0UL;
	pdu->pos                    = 0UL;
	pdu->conn                   = conn;
	pdu->cmd_sn                 = 0UL;

	return pdu;
}

/**
 * @brief Destroys an iSCSI PDU structure used by connections.
 *
 * All associated data which has been read so
 * far will be freed as well.
 *
 * @param[in] pdu PDU structure to be deallocated, may be NULL
 * in which case this function does nothing.
 */
void iscsi_connection_pdu_destroy(iscsi_pdu *pdu)
{
	if ( pdu != NULL ) {
		if ( pdu->key_value_pairs != NULL ) {
			iscsi_hashmap_iterate( pdu->key_value_pairs, iscsi_hashmap_key_destroy_value_callback, NULL );
			iscsi_hashmap_destroy( pdu->key_value_pairs );

			pdu->key_value_pairs = NULL;
		}

		if ( pdu->bhs_pkt != NULL ) {
			free( pdu->bhs_pkt );

			pdu->bhs_pkt = NULL;
		}

		free( pdu );
	}
}

/**
 * @brief Writes and sends a response PDU to the client.
 *
 * This function sends a response PDU to the
 * client after being processed by the server.\n
 * If a header or data digest (CRC32C) needs to
 * be calculated, this is done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI server response PDU to send.
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
	if ( conn->state >= ISCSI_CONNECT_STATE_EXITING )
		return;

	if ( ISCSI_GET_OPCODE(pdu->bhs_pkt->opcode) != ISCSI_CLIENT_LOGIN_REQ ) {
		if ( conn->header_digest != 0 )
			iscsi_calc_header_digest( pdu->bhs_pkt );

		if ( (conn->data_digest != 0) && (pdu->ds_len != 0) )
			iscsi_calc_data_digest( pdu->bhs_pkt, conn->header_digest );
	}

	const uint len = (uint) (sizeof(struct iscsi_bhs_packet) + pdu->ahs_len + conn->header_digest + iscsi_align(pdu->ds_len, ISCSI_ALIGN_SIZE) + conn->data_digest);

	// TODO: Do the writing in a queue.
	iscsi_connection_write( conn, (uint8_t *) pdu->bhs_pkt, len );

	if ( callback != NULL )
		callback( user_data );
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

	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_handle_reject: Out of memory while allocating iSCSI reject response PDU" );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	const uint32_t ds_len = (uint32_t) sizeof(struct iscsi_bhs_packet) + ((uint32_t) pdu->bhs_pkt->total_ahs_len << 2UL) + conn->header_digest;
	iscsi_reject_packet *reject_pkt = (iscsi_reject_packet *) iscsi_append_ds_packet( response_pdu->bhs_pkt, conn->header_digest, ds_len, conn->data_digest );

	if ( reject_pkt == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_handle_reject: Out of memory while allocating iSCSI reject packet data" );

		iscsi_connection_pdu_destroy( response_pdu );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	response_pdu->bhs_pkt = (iscsi_bhs_packet *) reject_pkt;

	if ( conn->header_digest != 0 ) {
		response_pdu->header_digest      = (iscsi_header_digest *) (((iscsi_bhs_packet *) reject_pkt) + 1);
		response_pdu->header_digest_size = conn->header_digest;
	}

	response_pdu->ds_cmd_data = (iscsi_ds_cmd_data *) (((uint8_t *) reject_pkt) + sizeof(struct iscsi_bhs_packet) + conn->header_digest);
	response_pdu->ds_len      = ds_len;

	if ( conn->data_digest != 0 ) {
		response_pdu->data_digest      = (iscsi_data_digest *) (((uint8_t *) response_pdu->ds_cmd_data) + iscsi_align(ds_len, ISCSI_ALIGN_SIZE));
		response_pdu->data_digest_size = conn->data_digest;
	}

	reject_pkt->opcode = ISCSI_SERVER_REJECT;
	reject_pkt->flags |= -0x80;
	reject_pkt->reason = (uint8_t) reason_code;
	iscsi_put_be24( (uint8_t *) &reject_pkt->ds_len, ds_len );
	reject_pkt->tag    = 0xFFFFFFFFUL;
	iscsi_put_be32( (uint8_t *) &reject_pkt->stat_sn, conn->stat_sn++ );

	if ( conn->session != NULL ) {
		iscsi_put_be32( (uint8_t *) &reject_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
		iscsi_put_be32( (uint8_t *) &reject_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	} else {
		iscsi_put_be32( (uint8_t *) &reject_pkt->exp_cmd_sn, 1 );
		iscsi_put_be32( (uint8_t *) &reject_pkt->max_cmd_sn, 1 );
	}

	memcpy( ((uint8_t *) reject_pkt) + sizeof(struct iscsi_bhs_packet), pdu->bhs_pkt, ds_len );

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
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_update_cmd_sn(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement update CmdSN.

	return 0L;
}

/**
 * @brief Handles an incoming iSCSI header login request PDU.
 *
 * This function handles login request header
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
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

	iscsi_pdu *login_response_pdu = iscsi_connection_pdu_create( conn );

	if ( login_response_pdu == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	const int rc = iscsi_login_response_init( login_response_pdu, pdu );

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
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
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

	if ( (target_xfer_tag != 0xFFFFFFFFUL) && (target_xfer_tag != conn->id) )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_INVALID_PDU_FIELD ); // TODO: Check if this is the correct error code.

	if ( (init_task_tag == 0xFFFFFFFFUL) && (nop_out_pkt->opcode & 0x40) == 0 )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	return 0L;
}

/**
 * @brief Handles an incoming iSCSI header SCSI command request PDU.
 *
 * This function handles SCSI command request
 * header data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_scsi_cmd(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0;
}

/**
 * @brief Handles an incoming iSCSI header task management function request PDU.
 *
 * This function handles task management function
 * request header data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
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
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_text_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0;
}

/**
 * @brief Handles an incoming iSCSI header SCSI data out PDU.
 *
 * This function handles header SCSI data out
 * sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_scsi_data_out(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0;
}

/**
 * @brief Handles an incoming iSCSI header logout request PDU.
 *
 * This function handles logout request header
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle_logout_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0;
}

/**
 * @brief Handles an incoming iSCSI header SNACK request PDU.
 *
 * This function handles SNACK request header
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
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
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_header_handle(iscsi_connection *conn, iscsi_pdu *pdu)
{
	if ( pdu == NULL )
		return -1L;

	const int opcode = ISCSI_GET_OPCODE(pdu->bhs_pkt->opcode);

	if ( opcode == ISCSI_CLIENT_LOGIN_REQ )
		return iscsi_connection_pdu_header_handle_login_req( conn, pdu );

	if ( ((conn->flags & ISCSI_CONNECT_FLAGS_FULL_FEATURE) == 0) && (conn->state == ISCSI_CONNECT_STATE_RUNNING) ) {
		iscsi_pdu *login_response_pdu = iscsi_connection_pdu_create( conn );

		if ( login_response_pdu == NULL )
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

		iscsi_login_response_reject_init( login_response_pdu, pdu );
		iscsi_connection_pdu_write( conn, login_response_pdu, NULL, NULL );

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	} else if ( conn->state == ISCSI_CONNECT_STATE_INVALID ) {
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	int rc = iscsi_connection_update_cmd_sn( conn, pdu );

	if ( rc != 0 )
		return rc;

	switch ( opcode ) {
		case ISCSI_CLIENT_NOP_OUT : {
			rc = iscsi_connection_pdu_header_handle_nop_out( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_SCSI_CMD : {
			rc = iscsi_connection_pdu_header_handle_scsi_cmd( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_TASK_FUNC_REQ : {
			rc = iscsi_connection_pdu_header_handle_task_func_req( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_TEXT_REQ : {
			rc = iscsi_connection_pdu_header_handle_text_req( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_SCSI_DATA_OUT : {
			rc = iscsi_connection_pdu_header_handle_scsi_data_out( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_LOGOUT_REQ : {
			rc = iscsi_connection_pdu_header_handle_logout_req( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_SNACK_REQ : {
			rc = iscsi_connection_pdu_header_handle_snack_req( conn, pdu );

			break;
		}
		default : {
			return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

			break;
		}
	}

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
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_nop_out(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_nop_out_packet *nop_out_pkt = (iscsi_nop_out_packet *) pdu->bhs_pkt;
	uint32_t ds_len = pdu->ds_len;

	if ( ds_len > conn->max_recv_ds_len )
		ds_len = conn->max_recv_ds_len;

	const uint64_t lun           = iscsi_get_be64(nop_out_pkt->lun);
	const uint32_t init_task_tag = iscsi_get_be32(nop_out_pkt->init_task_tag);

	conn->flags &= ~ISCSI_CONNECT_FLAGS_NOP_OUTSTANDING;

	if ( init_task_tag == 0xFFFFFFFFUL )
		return ISCSI_CONNECT_PDU_READ_OK;

	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_pdu_data_handle_nop_out: Out of memory while allocating iSCSI NOP-In response PDU" );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_nop_in_packet *nop_in_pkt = (iscsi_nop_in_packet *) iscsi_append_ds_packet( response_pdu->bhs_pkt, conn->header_digest, ds_len, conn->data_digest );

	if ( nop_in_pkt == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_pdu_data_handle_nop_out: Out of memory while allocating iSCSI NOP-In packet data" );

		iscsi_connection_pdu_destroy( response_pdu );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	response_pdu->bhs_pkt = (iscsi_bhs_packet *) nop_in_pkt;

	if ( conn->header_digest != 0 ) {
		response_pdu->header_digest      = (iscsi_header_digest *) (((iscsi_bhs_packet *) nop_in_pkt) + 1);
		response_pdu->header_digest_size = conn->header_digest;
	}

	response_pdu->ds_cmd_data = (iscsi_ds_cmd_data *) (((uint8_t *) nop_in_pkt) + sizeof(struct iscsi_bhs_packet) + conn->header_digest);
	response_pdu->ds_len      = ds_len;

	if ( conn->data_digest != 0 ) {
		response_pdu->data_digest      = (iscsi_data_digest *) (((uint8_t *) response_pdu->ds_cmd_data) + iscsi_align(ds_len, ISCSI_ALIGN_SIZE));
		response_pdu->data_digest_size = conn->data_digest;
	}

	nop_in_pkt->opcode          = ISCSI_SERVER_NOP_IN;
	nop_in_pkt->flags           = -0x80;
	iscsi_put_be24( (uint8_t *) &nop_in_pkt->ds_len, ds_len );
	iscsi_put_be64( (uint8_t *) &nop_in_pkt->lun, lun );
	nop_in_pkt->target_xfer_tag = 0xFFFFFFFFUL;
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->init_task_tag, init_task_tag );
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->stat_sn, conn->stat_sn++ );

	if ( (nop_out_pkt->opcode & 0x40) == 0 )
		conn->session->max_cmd_sn++;

	iscsi_put_be32( (uint8_t *) &nop_in_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->max_cmd_sn, conn->session->max_cmd_sn );

	iscsi_connection_pdu_write( conn, response_pdu, NULL, NULL );

	// conn->nop_in_last = iscsi_get_ticks();

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
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_scsi_cmd(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0L;
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
	int rc = 0L;

	if ( (conn->flags & ISCSI_CONNECT_FLAGS_CHAP_DISABLE) != 0 )
		rc = iscsi_update_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD, (uint8_t *) "None" );
	else if ( (conn->flags & ISCSI_CONNECT_FLAGS_CHAP_REQUIRE) != 0 )
		rc = iscsi_update_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD, (uint8_t *) "CHAP" );

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
	int rc = 0L;

	if ( target->header_digest != 0 )
		rc = iscsi_update_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST, (uint8_t *) "CRC32C" );

	if ( target->data_digest != 0 )
		rc = iscsi_update_key_value_pair( conn->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST, (uint8_t *) "CRC32C" );

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
	int rc = iscsi_get_key_value_pair( key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_NAME, &target_name );

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

		conn->session->initiator_port = init_port;
		conn->stat_sn                 = iscsi_get_be32(login_response_pkt->stat_sn);
		conn->session->isid           = isid;

		const int rc = iscsi_port_transport_id_set( conn->session->initiator_port, conn->init_name, isid );

		if ( rc < 0 ) {
			iscsi_session_destroy( conn->session );
			conn->session = NULL;

			iscsi_port_destroy( init_port );

			return rc;
		}

		conn->session->queue_depth = (target != NULL) ? target->queue_depth : 1UL;
		conn->session->exp_cmd_sn  = login_response_pdu->cmd_sn;
		conn->session->max_cmd_sn  = login_response_pdu->cmd_sn + conn->session->queue_depth - 1;
	}

	conn->init_port = conn->session->initiator_port;

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
		rc = iscsi_update_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, ((target->alias != NULL) ? target->alias : (uint8_t *) "") );

		if ( rc < 0 )
			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;
	}

	uint8_t *tmp_buf = iscsi_sprintf_alloc( "%s:%s,%d", conn->portal_host, conn->portal_port, conn->pg_tag );

	if ( tmp_buf == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	rc = iscsi_update_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, tmp_buf );

	free( tmp_buf );

	if ( rc < 0 )
		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;

	rc = iscsi_update_int_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, conn->pg_tag );

	if ( rc < 0 )
		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER;

	if ( target != NULL ) {
		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, &tmp_buf );

		if ( (rc == 0) && (strlen( (char *) tmp_buf ) != 0) ) {
			rc = iscsi_update_key_value_pair( login_response_pdu->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS, tmp_buf );

			if ( rc < 0 )
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		}

		if ( type == ISCSI_SESSION_TYPE_DISCOVERY ) {
			rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, &tmp_buf );

			if ( (rc == 0) && (strlen( (char *) tmp_buf ) != 0) ) {
				rc = iscsi_update_key_value_pair( login_response_pdu->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS, tmp_buf );

				if ( rc < 0 )
					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
			}
		}

		rc = iscsi_get_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, &tmp_buf );

		if ( rc == 0 ) {
			rc = iscsi_update_key_value_pair( login_response_pdu->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG, tmp_buf );

			if ( rc < 0 )
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
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
	uint8_t *init_port_name;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	conn->device = NULL;
	conn->target = NULL;

	int rc = iscsi_connection_login_init_port( conn, login_response_pdu, key_value_pairs, &init_port_name );

	if ( rc < 0 )
		return rc;

	int type;

	rc = iscsi_connection_login_session_type( login_response_pdu, key_value_pairs, &type );

	if ( rc < 0 )
		return rc;

	if ( type == ISCSI_SESSION_TYPE_NORMAL ) {
		rc = iscsi_connection_login_session_normal( conn, login_response_pdu, key_value_pairs, init_port_name, cid );
	} else if ( type == ISCSI_SESSION_TYPE_DISCOVERY ) {
		login_response_pkt->tsih = 0U;

		rc = iscsi_connection_login_session_chap_discovery( conn );
	} else {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	if ( rc < 0 )
		return rc;

	rc = iscsi_connection_login_set_info( conn, login_response_pdu, init_port_name, type, cid );

	if ( rc < 0 )
		return rc;

	if ( type == ISCSI_SESSION_TYPE_DISCOVERY ) {
		conn->session->max_conns = 1;

		rc = iscsi_add_int_key_value_pair( conn->session->key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS, conn->session->max_conns );

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

	switch ( ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(login_response_pkt->flags) ) {
		case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION : {
			uint8_t *auth_method;
			const int rc = iscsi_get_key_value_pair( key_value_pairs, (uint8_t *) ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD, (uint8_t **) &auth_method );

			if ( rc < 0 ) {
				login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
				login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

				return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
			}

			if ( strcasecmp( (char *) auth_method, "None" ) == 0 ) {
				conn->flags |= ISCSI_CONNECT_FLAGS_AUTH;
			} else {
				const int ds_len = iscsi_connection_auth_key_value_pairs( conn, key_value_pairs, auth_method, (uint8_t *) login_response_pdu->ds_cmd_data, login_response_pdu->pos, login_response_pdu->ds_len );

				if ( ds_len < 0 ) {
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

			iscsi_put_be16( (uint8_t *) &login_response_pkt->tsih, conn->session->tsih );

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
	const int ds_len = iscsi_negotiate_key_value_pairs( conn, key_value_pairs, (uint8_t *) login_response_pdu->ds_cmd_data, login_response_pdu->pos, login_response_pdu->ds_len );

	if ( ds_len < 0 ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	login_response_pdu->ds_len = (uint) ds_len;

	int rc = iscsi_connecction_handle_login_response_csg_bit( conn, login_response_pdu, key_value_pairs );

	if ( rc < 0 )
		return rc;

	if ( (login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0)
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
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_login_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	iscsi_pdu *login_response_pdu = (iscsi_pdu *) conn->login_response_pdu;

	if ( login_response_pdu == NULL )
		return 0L;

	iscsi_hashmap *key_value_pairs = iscsi_hashmap_create( 32UL );

	if ( key_value_pairs == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) pdu->bhs_pkt;
	uint cid = iscsi_get_be16(login_req_pkt->cid);
	int rc = iscsi_connection_save_incoming_key_value_pairs( conn, key_value_pairs, login_response_pdu, pdu );

	if ( rc < 0 ) {
		iscsi_connection_pdu_login_response( conn, login_response_pdu, NULL, iscsi_connection_pdu_login_err_complete );

		return 0L;
	}

	if ( conn->state == ISCSI_CONNECT_STATE_INVALID ) {
		rc = iscsi_connection_handle_login_phase_none( conn, login_response_pdu, key_value_pairs, cid );

		if ( (rc == ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE) || (rc == ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER) ) {
			iscsi_connection_pdu_login_response( conn, login_response_pdu, key_value_pairs, iscsi_connection_pdu_login_err_complete );

			return 0L;
		}
	}

	rc = iscsi_connecction_handle_login_response( conn, login_response_pdu, key_value_pairs );

	if ( rc == ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE ) {
		iscsi_connection_pdu_login_response( conn, login_response_pdu, key_value_pairs, iscsi_connection_pdu_login_err_complete );

		return 0L;
	}

	conn->state = ISCSI_CONNECT_STATE_RUNNING;

	iscsi_connection_pdu_login_response( conn, login_response_pdu, key_value_pairs, iscsi_connection_pdu_login_ok_complete );

	return 0L;
}

/**
 * @brief Handles an incoming iSCSI payload data text request PDU.
 *
 * This function handles text request payload
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_text_req(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0L;
}

/**
 * @brief Handles an incoming iSCSI payload data SCSI data out request PDU.
 *
 * This function handles SCSI data out request
 * payload data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle_scsi_data_out(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement opcode.

	return 0L;
}

/**
 * @brief Handles an incoming iSCSI payload data PDU.
 *
 * This function handles all payload data sent
 * by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn iSCSI connection to handle. May
 * NOT be NULL, so take caution.
 * @param[in] pdu iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_pdu_data_handle(iscsi_connection *conn, iscsi_pdu *pdu)
{
	int rc = 0;

	const uint8_t opcode = ISCSI_GET_OPCODE(pdu->bhs_pkt->opcode);

	switch ( opcode ) {
		case ISCSI_CLIENT_NOP_OUT : {
			rc = iscsi_connection_pdu_data_handle_nop_out( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_SCSI_CMD : {
			rc = iscsi_connection_pdu_data_handle_scsi_cmd( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_LOGIN_REQ : {
			rc = iscsi_connection_pdu_data_handle_login_req( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_TEXT_REQ : {
			rc = iscsi_connection_pdu_data_handle_text_req( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_SCSI_DATA_OUT : {
			rc = iscsi_connection_pdu_data_handle_scsi_data_out( conn, pdu );

			break;
		}
		case ISCSI_CLIENT_TASK_FUNC_REQ :
		case ISCSI_CLIENT_LOGOUT_REQ :
		case ISCSI_CLIENT_SNACK_REQ : {
			break;
		}
		default : {
			return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

			break;
		}
	}

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
 * @param[in] conn iSCSI connection to read TCP/IP data from.
 * @param[in] pdu iSCSI PDU to read TCP/IP data into.
 * @retval -1 Fatal error occured during processing the PDU.
 * @retval 0 Read operation was successful and next read is ready.
 * @retval 1 Read operation was successful and PDU was fully processed.
 */
int iscsi_connection_pdu_data_read(iscsi_connection *conn, iscsi_pdu *pdu)
{
	// TODO: Implement DS read.

	return 0;
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
 * @param[in] conn iSCSI connection to read TCP/IP data from.
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
				conn->pdu_processing = iscsi_connection_pdu_create( conn );

				if ( conn->pdu_processing == NULL )
					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR;

				break;
			}
			case ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR : {
				if ( pdu->bhs_read_len < sizeof(struct iscsi_bhs_packet) ) {
					const int len = iscsi_connection_read( conn, (((uint8_t *) pdu->bhs_pkt) + pdu->bhs_read_len), (sizeof(struct iscsi_bhs_packet) - pdu->bhs_read_len) );

					if ( len < 0 ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						break;
					}

					pdu->bhs_read_len += len;

					if ( pdu->bhs_read_len < sizeof(struct iscsi_bhs_packet) )
						return ISCSI_CONNECT_PDU_READ_OK;
				}

				if ( (conn->flags & ISCSI_CONNECT_FLAGS_LOGGED_OUT) != 0 ) {
					conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

					break;
				}

				pdu->ds_len  = iscsi_align(pdu->ds_len, ISCSI_ALIGN_SIZE);
				pdu->pos     = pdu->ds_len;

				const uint ahs_len = (uint) pdu->bhs_pkt->total_ahs_len << 2UL;

				if ( pdu->ahs_read_len < ahs_len ) {
					if ( pdu->ahs_pkt == NULL ) {
						pdu->ahs_pkt = (iscsi_ahs_packet *) iscsi_append_ahs_packet( pdu->bhs_pkt, (uint32_t) ahs_len );

						if ( pdu->ahs_pkt == NULL )
							return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

						pdu->ahs_pkt = (iscsi_ahs_packet *) (((iscsi_bhs_packet *) pdu->bhs_pkt) + 1);
					}

					const int len = iscsi_connection_read( conn, (((uint8_t *) pdu->ahs_pkt) + pdu->ahs_read_len), (ahs_len - pdu->ahs_read_len) );

					if ( len < 0 ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						break;
					}

					pdu->ahs_read_len += len;

					if ( pdu->ahs_read_len < ahs_len )
						return ISCSI_CONNECT_PDU_READ_OK;
				}

				if ( conn->header_digest != 0 ) {
					if ( pdu->header_digest == NULL ) {
						pdu->header_digest = (iscsi_header_digest *) iscsi_append_header_digest_packet( pdu->bhs_pkt, ISCSI_DIGEST_SIZE );

						if ( pdu->header_digest == NULL )
							return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

						pdu->header_digest = (iscsi_header_digest *) (((uint8_t *) pdu->bhs_pkt) + sizeof(struct iscsi_bhs_packet) + ahs_len);
					}

					if ( pdu->header_digest_read_len < (uint) conn->header_digest ) {
						const int len = iscsi_connection_read( conn, (((uint8_t *) pdu->header_digest) + pdu->header_digest_read_len), (conn->header_digest - pdu->header_digest_read_len) );

						if ( len < 0 ) {
							conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

							break;
						}

						pdu->header_digest_read_len += len;

						if ( pdu->header_digest_read_len < (uint) conn->header_digest )
							return ISCSI_CONNECT_PDU_READ_OK;
					}

					if  ( iscsi_validate_header_digest( pdu->bhs_pkt ) == 0 ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						break;
					}
				}

				conn->pdu_recv_state = (iscsi_connection_pdu_header_handle( conn, pdu ) < 0L) ? ISCSI_CONNECT_PDU_RECV_STATE_ERR : ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_DATA;

				break;
			}
			case ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_DATA : {
				if ( pdu->ds_len != 0 ) {
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
 * @brief Handle incoming PDU data, read up to 16 fragments at once.
 *
 * Until iSCSI processing has been stopped or a
 * complete iSCSI packet has been read, this
 * function will read, parse and process
 * incoming iSCSI protocol data.
 *
 * @param[in] iSCSI connection to handle.
 * @return Number of proccessed fragments or return
 * code of iscsi_connection_pdu_read in case of a
 * fatal error.
 */
int iscsi_connection_pdu_handle(iscsi_connection *conn)
{
	uint i;

	for ( i = 0; i < ISCSI_PDU_HANDLE_COUNT; i++ ) {
		int rc = iscsi_connection_pdu_read(conn);

		if ( rc == 0 )
			break;
		else if ( rc < 0 )
			return rc;

		if ( (conn->flags & ISCSI_CONNECT_FLAGS_STOPPED) != 0 )
			break;
	}

	return i;
}
