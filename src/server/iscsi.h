/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
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

/**
 * @file iscsi.h
 * @author Sebastian Vater
 * @date 07 Jul 2025
 * @brief iSCSI header for DNBD3.
 *
 * This file contains the header file for the iSCSI
 * implementation according to RFC7143 for dnbd3-server.
 * @see https://www.rfc-editor.org/rfc/rfc7143
 */

#ifndef DNBD3_ISCSI_H_
#define DNBD3_ISCSI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <dnbd3/types.h>
#include <pthread.h>

#include "globals.h"
#include "image.h"

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
     // GCC-compatible compiler, targeting x86/x86-64
     #include <x86intrin.h>
#elif defined(__GNUC__) && defined(__ARM_NEON__)
     // GCC-compatible compiler, targeting ARM with NEON
     #include <arm_neon.h>
#elif defined(__GNUC__) && defined(__IWMMXT__)
     // GCC-compatible compiler, targeting ARM with WMMX
     #include <mmintrin.h>
#elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__))
     // XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX
     #include <altivec.h>
#elif defined(__GNUC__) && defined(__SPE__)
     // GCC-compatible compiler, targeting PowerPC with SPE
     #include <spe.h>
#elif defined(_MSC_VER)
     // Microsoft C/C++-compatible compiler
     #include <intrin.h>
#endif

#if defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER) && defined(__BIG_ENDIAN) && __BYTE_ORDER == __BIG_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define iscsi_get_be16(x) (x)
#define iscsi_get_be24(x) (iscsi_get_be32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_be32(x) (x)
#define iscsi_get_be64(x) (x)

static inline void iscsi_put_be16(uint8_t *data, const uint16_t value)
{
	(*(uint16_t *) data) = value;
}

static inline void iscsi_put_be24(uint8_t *data, const uint32_t value)
{
	data--;

	(*(uint32_t *) data) = (((uint32_t ) *data << 24UL) | (value & 0xFFFFFFUL));
}

static inline void iscsi_put_be32(uint8_t *data, const uint32_t value)
{
	(*(uint32_t *) data) = value;
}

static inline void iscsi_put_be64(uint8_t *data, const uint64_t value)
{
	(*(uint64_t *) data) = value;
}

#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
// GCC or CLang
#define iscsi_get_le16(x) (__builtin_bswap16(x))
#define iscsi_get_le24(x) (iscsi_get_le32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_le32(x) (__builtin_bswap32(x))
#define iscsi_get_le64(x) (__builtin_bswap64(x))
#elif defined(_MSC_VER)
// MSVC
#define iscsi_get_le16(x) (_byteswap_ushort(x))
#define iscsi_get_le24(x) (iscsi_get_le32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_le32(x) (_byteswap_ulong(x))
#define iscsi_get_le64(x) (_byteswap_uint64(x))
#elif defined(__INTEL_COMPILER) || defined(__ECC)
// Intel Compiler
#define iscsi_get_le16(x) (_bswap16(x))
#define iscsi_get_le24(x) (iscsi_get_le32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_le32(x) (_bswap(x))
#define iscsi_get_le64(x) (_bswap64(x))
#else
// Other compilers (use slow conversion method with bit rotation, bit shift and logcal AND)
#define iscsi_get_le16(x) ((((uint16_t) (x)) << 8U) | (((uint16_t) (x)) >> 8U))
#define iscsi_get_le24(x) (iscsi_get_le32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_le32(x) ((((uint32_t) (x) & 0xFFUL) << 24UL) | (((uint32_t) (x) & 0xFF00UL) << 8UL) | (((uint32_t) (x) & 0xFF0000UL) >> 8UL) | (((uint32_t) (x) >> 24UL)))
#define iscsi_get_le64(x) ((uint64_t)((((x) & 0xFFULL) << 56ULL) | (((x) & 0xFF00ULL) << 40ULL) | (((x) & 0xFF0000ull) << 24ULL) | (((x) & 0xFF000000ULL) << 8ULL) | (((x) & 0xFF00000000ULL) >> 8ULL) | (((x) & 0xFF0000000000ULL) >> 24ULL) | (((x) & 0xFF000000000000ULL) >> 40ULL) | (((x) & 0xFF00000000000000ULL) >> 56ULL)))
#endif

static inline void iscsi_put_le16(uint8_t *data, const uint16_t value)
{
	(*(uint16_t *) data) = iscsi_get_le16(value);
}

static inline void iscsi_put_le24(uint8_t *data, const uint32_t value)
{
	data--;

	(*(uint32_t *) data) = ((uint32_t ) *data | (iscsi_get_le32(value) & 0xFFFFFF00UL));
}

static inline void iscsi_put_le32(uint8_t *data, const uint32_t value)
{
	(*(uint32_t *) data) = iscsi_get_le32(value);
}

static inline void iscsi_put_le64(uint8_t *data, const uint64_t value)
{
	(*(uint64_t *) data) = iscsi_get_le64(value);
}
#elif defined(__LITTLE_ENDIAN__) || (defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(__i386__) || defined(__i386) || defined(__x86_64)
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
// GCC or CLang
#define iscsi_get_be16(x) (__builtin_bswap16(x))
#define iscsi_get_be24(x) (iscsi_get_be32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_be32(x) (__builtin_bswap32(x))
#define iscsi_get_be64(x) (__builtin_bswap64(x))
#elif defined(_MSC_VER)
// MSVC
#define iscsi_get_be16(x) (_byteswap_ushort(x))
#define iscsi_get_be24(x) (iscsi_get_be32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_be32(x) (_byteswap_ulong(x))
#define iscsi_get_be64(x) (_byteswap_uint64(x))
#elif defined(__INTEL_COMPILER) || defined(__ECC)
// Intel Compiler
#define iscsi_get_be16(x) (_bswap16(x))
#define iscsi_get_be24(x) (iscsi_get_be32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_be32(x) (_bswap(x))
#define iscsi_get_be64(x) (_bswap64(x))
#else
// Other compilers (use slow conversion method with bit rotation, bit shift and logcal AND)
#define iscsi_get_be16(x) ((((uint16_t) (x)) << 8U) | (((uint16_t) (x)) >> 8U))
#define iscsi_get_be24(x) (iscsi_get_be32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_be32(x) ((((uint32_t) (x) & 0xFFUL) << 24UL) | (((uint32_t) (x) & 0xFF00UL) << 8UL) | (((uint32_t) (x) & 0xFF0000UL) >> 8UL) | (((uint32_t) (x) >> 24UL)))
#define iscsi_get_be64(x) ((uint64_t)((((x) & 0xFFULL) << 56ULL) | (((x) & 0xFF00ULL) << 40ULL) | (((x) & 0xFF0000ull) << 24ULL) | (((x) & 0xFF000000ULL) << 8ULL) | (((x) & 0xFF00000000ULL) >> 8ULL) | (((x) & 0xFF0000000000ULL) >> 24ULL) | (((x) & 0xFF000000000000ULL) >> 40ULL) | (((x) & 0xFF00000000000000ULL) >> 56ULL)))
#endif

static inline void iscsi_put_be16(uint8_t *data, const uint16_t value)
{
	(*(uint16_t *) data) = iscsi_get_be16(value);
}

static inline void iscsi_put_be24(uint8_t *data, const uint32_t value)
{
	data--;

	(*(uint32_t *) data) = ((uint32_t ) *data | (iscsi_get_be32(value) & 0xFFFFFF00UL));
}

static inline void iscsi_put_be32(uint8_t *data, const uint32_t value)
{
	(*(uint32_t *) data) = iscsi_get_be32(value);
}

static inline void iscsi_put_be64(uint8_t *data, const uint64_t value)
{
	(*(uint64_t *) data) = iscsi_get_be64(value);
}

#define iscsi_get_le16(x) (x)
#define iscsi_get_le24(x) (iscsi_get_le32((*(uint32_t *) ((uint8_t *) x - 1))) & 0xFFFFFFUL)
#define iscsi_get_le32(x) (x)
#define iscsi_get_le64(x) (x)

static inline void iscsi_put_le16(uint8_t *data, const uint16_t value)
{
	(*(uint16_t *) data) = value;
}

static inline void iscsi_put_le24(uint8_t *data, const uint32_t value)
{
	data--;

	(*(uint32_t *) data) = (((uint32_t ) *data << 24UL) | (value & 0xFFFFFFUL));
}

static inline void iscsi_put_le32(uint8_t *data, const uint32_t value)
{
	(*(uint32_t *) data) = value;
}

static inline void iscsi_put_le64(uint8_t *data, const uint64_t value)
{
	(*(uint64_t *) data) = value;
}
#else
#error "Unknown CPU endianness"
#endif


/**
 * @brief Checks whether a specified 32-bit integer value is a power of two.
 *
 * This function is used to determine
 * if shift operations can be used for
 * calculating instead of very slow
 * multiplication, division and modulo
 * operations.
 *
 * @param[in] value Value to check for a power of two.
 * @retval true Value is a power of two.
 * @retval false Value is NOT a power of two,
 * hence slow division is required.
 */
static inline bool iscsi_is_pow2(const uint32_t value)
{
	return ((value & (value - 1UL)) == 0UL);
}

/**
 * @brief Rounds up a positive 32-bit integer value to the nearest power of two.
 *
 * This function is used to ensure that
 * a value is always a power of two by
 * rounding up.\n
 * An input value of zero is NOT
 * handled correctly.
 *
 * @param[in] value Positive value to round up to
 * the nearest power of two.
 * @return Rounded up nearest power of two.
 */
static inline uint32_t iscsi_align_pow2_ceil(const uint32_t value)
{
    uint32_t num_value = (value - 1UL); // 1UL << (lg(value - 1UL) + 1UL)

    num_value |= (num_value >>  1UL);
    num_value |= (num_value >>  2UL);
    num_value |= (num_value >>  4UL);
    num_value |= (num_value >>  8UL);
    num_value |= (num_value >> 16UL);

    return ++num_value;
}

/**
 * @brief Calculates the shift factor for a power of two value.
 *
 * This function is used to determine
 * the shift factor to use instead of
 * using very slow multiplication,
 * division and modulo operations.
 *
 * @param[in] value Value to retrieve the
 * the shift factor for. May NOT be
 * zero in which case the result is
 * undefined.
 * @return The shift count to use as a
 * replacement for multiplication
 * and division.
 */
static inline uint32_t iscsi_get_log2_of_pow2(const uint32_t value)
{
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__) || defined(__INTEL_COMPILER) || defined(__ECC)
// GCC, CLang or Intel Compiler
	return (((sizeof(uint32_t) * CHAR_BIT) - 1UL) - (uint32_t) __builtin_clz( value ));
#elif defined(_MSC_VER)
// MSVC
	uint32_t shift;

	_BitScanReverse( &shift, value );

	return (((sizeof(uint32_t) * CHAR_BIT) - 1UL) - shift);
#else
// Other compilers (use slow parallel calculation method with logical OR, bit shift, logcal AND)
	uint32_t shift = ((value & 0xAAAAAAAAUL) != 0UL);

	shift |= ((value & 0xCCCCCCCCUL) != 0UL) << 1UL;
	shift |= ((value & 0xF0F0F0F0UL) != 0UL) << 2UL;
	shift |= ((value & 0xFF00FF00UL) != 0UL) << 3UL;
	shift |= ((value & 0xFFFF0000UL) != 0UL) << 4UL;

	return shift;
#endif
}


/// Determines the container of member b in struct a of type x.
#define ISCSI_CONTAINER(x, a, b) ((x *) (((uint8_t *) (a)) - offsetof(x, b)))

/// Determines the next offset after member b of struct a.
#define ISCSI_NEXT_OFFSET(a, b) (offsetof(struct a, b) + sizeof(((struct a *) 0)->b))


/// Bit sequence manipulation double word (32 bits) mask bits: Gets mask for filtering out a bit range between a and b, b may NOT exceed 30 bits range.
#define ISCSI_BITS_GET_MASK(a, b) (((1U << (a)) - 1U) ^ ((1U << ((b) + 1U)) - 1U))

/// Bit sequence manipulation double word (32 bits) test bits: Tests value x in of a bit range between a and b, b may NOT exceed 30 bits range.
#define ISCSI_BITS_TST(x, a, b) ((x) & ISCSI_BITS_GET_MASK(a, b))

/// Bit sequence manipulation double word (32 bits) clear bits: Clears all bits in range between a and b out of x, b may NOT exceed 30 bits range.
#define ISCSI_BITS_CLR(x, a, b) ((x) & ~ISCSI_BITS_GET_MASK(a, b))

/// Bit sequence manipulation double word (32 bits) set bits: Sets all bits in range between a and b of x, b may NOT exceed 30 bits range.
#define ISCSI_BITS_SET(x, a, b) ((x) | ISCSI_BITS_GET_MASK(a, b))

/// Bit sequence manipulation double word (32 bits) change bits: Flips all bits in range between a and b of x, b may NOT exceed 30 bits range.
#define ISCSI_BITS_CHG(x, a, b) ((x) ^ ISCSI_BITS_GET_MASK(a, b))

/// Bit sequence manipulation double word (32 bits) get bits: Extracts a value x out of a bit range between a and b, b may NOT exceed 30 bits range.
#define ISCSI_BITS_GET(x, a, b) (ISCSI_BITS_TST(x, a, b) >> (a))

/// Bit sequence manipulation double word (32 bits) get bits: Puts a value x into a bit range between a and b, b may NOT exceed 30 bits range.
#define ISCSI_BITS_PUT(x, a, b) (((x) << (a)) & ISCSI_BITS_GET_MASK(a, b))


/// Bit sequence manipulation quad word (64 bits) mask bits: Gets mask for filtering out a bit range between a and b, b may NOT exceed 62 bits range.
#define ISCSI_QBITS_GET_MASK(a, b) (((1ULL << (a)) - 1ULL) ^ ((1ULL << ((b) + 1ULL)) - 1ULL))

/// Bit sequence manipulation quad word (64 bits) test bits: Tests value x in of a bit range between a and b, b may NOT exceed 62 bits range.
#define ISCSI_QBITS_TST(x, a, b) ((x) & ISCSI_QBITS_GET_MASK(a, b))

/// Bit sequence manipulation quad word (64 bits) clear bits: Clears bits in range between a and b out of x, b may NOT exceed 62 bits range.
#define ISCSI_QBITS_CLR(x, a, b) ((x) & ~ISCSI_QBITS_GET_MASK(a, b))

/// Bit sequence manipulation quad word (64 bits) set bits: Sets all bits in range between a and b of x, b may NOT exceed 62 bits range.
#define ISCSI_QBITS_SET(x, a, b) ((x) | ISCSI_QBITS_GET_MASK(a, b))

/// Bit sequence manipulation quad word (64 bits) change bits: Flips all bits in range between a and b of x, b may NOT exceed 62 bits range.
#define ISCSI_QBITS_CHG(x, a, b) ((x) ^ ISCSI_QBITS_GET_MASK(a, b))

/// Bit sequence manipulation quad word (64 bits) get bits: Extracts a value x out of a bit range between a and b, b may NOT exceed 62 bits range.
#define ISCSI_QBITS_GET(x, a, b) (ISCSI_QBITS_TST(x, a, b) >> (a))

/// Bit sequence manipulation quad word (64 bits) get bits: Puts a value x into a bit range between a and b, b may NOT exceed 62 bits range.
#define ISCSI_QBITS_PUT(x, a, b) (((x) << (a)) & ISCSI_QBITS_GET_MASK(a, b))


/// Aligns value x by rounding up, so it's evenly divisable by n.
#define ISCSI_ALIGN(x, n) (((x) + (n) - 1) & ~((n) - 1))


/// Determines the length of a zero terminated string at compile time.
#define ISCSI_STRLEN(x) ((sizeof(x) / sizeof(uint8_t)) - sizeof(uint8_t))


uint8_t *iscsi_vsprintf_append_realloc(char *buf, const char *format, va_list args); // Allocates and appends a buffer and sprintf's it
uint8_t *iscsi_sprintf_append_realloc(char *buf, const char *format, ...); // Allocates and appends a buffer and sprintf's it
uint8_t *iscsi_vsprintf_alloc(const char *format, va_list args); // Allocates a buffer and sprintf's it
uint8_t *iscsi_sprintf_alloc(const char *format, ... ); // Allocates a buffer and sprintf's it
void iscsi_strcpy_pad(char *dst, const char *src, const size_t size, const int pad); // Copies a string with additional padding character to fill in a specified size


/// Shift factor for default capacity.
#define ISCSI_HASHMAP_DEFAULT_CAPACITY_SHIFT 5UL

/// Default capacity is 32 buckets.
#define ISCSI_HASHMAP_DEFAULT_CAPACITY (1UL << (ISCSI_HASHMAP_DEFAULT_CAPACITY_SHIFT))

/// Number of bits to shift left when resizing.
#define ISCSI_HASHMAP_RESIZE_SHIFT 1UL

/// Key data shift value for alignment enforcement.
#define ISCSI_HASHMAP_KEY_ALIGN_SHIFT 3UL

/// Key data size MUST be multiple of 8 bytes by now.
#define ISCSI_HASHMAP_KEY_ALIGN (1UL << (ISCSI_HASHMAP_KEY_ALIGN_SHIFT))


/// Initial hash code.
#define ISCSI_HASHMAP_HASH_INITIAL 0x811C9DC5UL

/// Value to multiply hash code with.
#define ISCSI_HASHMAP_HASH_MUL     0xBF58476D1CE4E5B9ULL


typedef struct iscsi_node iscsi_node;


/**
 * @brief Doubly linked list node structure.
 *
 * This structure is used by the iSCSI doubly linked list
 * implementation in order to maintain the elements.
 */
typedef struct iscsi_node {
    /// Successor node in node list. Must be first element.
    iscsi_node *succ;

    /// Predecessor node in node list. Must be second element.
    iscsi_node *pred;
} iscsi_node;


/**
 * @brief Doubly linked list structure.
 *
 * This structure is used by the iSCSI doubly linked list
 * implementation in order to maintain the elements.
 */
typedef struct iscsi_list {
    /// Head of linked list. Must be first element.
    iscsi_node *head;

    /// Tail of linked list. Must be second element and always be NULL.
    iscsi_node *tail;

    /// Tail predecessor of linked list. Must be third element.
    iscsi_node *pred;
} iscsi_list;


/// foreach( ( list => entry ) usage style forward iterator over all nodes in a doubly linked list.
#define iscsi_list_foreach(list, entry) for ( (entry) = (list)->head; (entry)->succ != NULL; (entry) = (entry)->succ )

/// foreach( ( list => (typeof(entry)) as field ) usage style forward iterator over all nodes in a doubly linked list embedded into another structure with default node field name.
#define iscsi_list_foreach_field(list, entry, field) for ( (entry) = (__typeof__(entry)) (list)->head; (__typeof__(entry)) (entry)->field.succ != NULL; (entry) = (__typeof__(entry)) (entry)->field.succ )

/// foreach( ( list => (typeof(entry)) entry->node.succ ) usage style forward iterator over all nodes in a doubly linked list embedded into another structure with default node field name.
#define iscsi_list_foreach_node(list, entry) iscsi_list_foreach_field(list, entry, node)

/// foreach( ( list => entry ) usage style forward iterator over all nodes in a doubly linked list.
#define iscsi_list_foreach_safe(list, entry, tmp) for ( (entry) = (list)->head; ((entry)->succ != NULL) && ((tmp) = (entry)->succ, true); (entry) = (tmp) )

/// foreach( ( list => (typeof(entry)) as field ) usage style forward iterator over all nodes in a doubly linked list embedded into another structure with default node field name.
#define iscsi_list_foreach_safe_field(list, entry, field, tmp) for ( (entry) = (__typeof__(entry)) (list)->head; ((entry)->field.succ != NULL) && ((tmp) = (__typeof__(entry)) (entry)->field.succ, true); (entry) = (tmp) )

/// foreach( ( list => (typeof(entry)) entry->node.succ ) usage style forward iterator over all nodes in a doubly linked list embedded into another structure with default node field name.
#define iscsi_list_foreach_safe_node(list, entry, tmp) iscsi_list_foreach_safe_field(list, entry, node, tmp)


/**
 * @brief Initializes a doubly linked list for usage.
 *
 * This function sets the head of the list to
 * the pointer of the list's tail, the tail
 * itself to NULL and the predecessor to the
 * pointer of the list's head.
 *
 * @param[in] list Pointer to idoubly linked list to
 * initialize. May NOT be NULL, so be careful.
 * */
static inline void iscsi_list_create(iscsi_list *list)
{
	list->head = (iscsi_node *) &list->tail;
	list->tail = NULL;
	list->pred = (iscsi_node *) &list->head;
}

/**
 * @brief Clears an already initialized doubly linked list.
 *
 * This function sets the head of the list to
 * the pointer of the list's tail and the
 * predecessor to the pointer of the list's
 * head.
 *
 * @param[in] list Pointer to idoubly linked list to
 * initialize. May NOT be NULL, so be careful.
 * */
static inline void iscsi_list_clear(iscsi_list *list)
{
	list->head = (iscsi_node *) &list->tail;
	list->pred = (iscsi_node *) &list->head;
}

/**
 * @brief Adds a node at the head of a doubly linked list.
 *
 * This function sets the head of the list to
 * the node and adjusts the list and node
 * pointers accordingly.
 *
 * @param[in] list Pointer to doubly linked list to add to
 * the head. May NOT be NULL, so be careful.
 * @param[in] node Pointer to node to add to the head of
 * the list. NULL is NOT allowed here, take
 * caution.
 */
static inline void iscsi_list_push(iscsi_list *list, iscsi_node *node)
{
	iscsi_node *head = list->head;

	list->head = node;
	head->pred = node;

	node->succ = head;
	node->pred = (iscsi_node *) &list->head;
}

/**
 * @brief Adds a node at the tail of a doubly linked list.
 *
 * This function sets the tail of the list to
 * the node and adjusts the list and node
 * pointers accordingly.
 *
 * @param[in] list Pointer to doubly linked list to add to
 * the tail. May NOT be NULL, so be careful.
 * @param[in] node Pointer to node to add to the tail of
 * the list. NULL is NOT allowed here, take
 * caution.
 */
static inline void iscsi_list_enqueue(iscsi_list *list, iscsi_node *node)
{
	iscsi_node *tail = list->pred;

	list->pred = node;
	tail->succ = node;

	node->succ = (iscsi_node *) &list->tail;
	node->pred = tail;
}

/**
 * @brief Inserts a node into a doubly linked list before an already existing node.
 *
 * This function sets the successor of the
 * new node to the successor of the
 * existing predecessor node and the
 * predecessor of the new node to the
 * the existing predecessor node itself
 * and adjusts the list pointers
 * accordingly.
 *
 * @param[in] list Pointer to doubly linked list to insert the
 * node into. May NOT be NULL, so be careful.
 * @param[in] node Pointer to node to be inserted into the
 * list. NULL is NOT allowed here, take
 * caution.
 * @param[in] pred Pointer to node which should be the
 * previous node of the new inserted node.
 * May be NULL in which case the new node
 * is inserted at the head of the list.
 */
static inline void iscsi_list_insert(iscsi_list *list, iscsi_node *node, iscsi_node *pred)
{
	if ( pred == NULL ) {
		iscsi_node *head = list->head;

		list->head = node;
		head->pred = node;

		node->succ = head;
		node->pred = (iscsi_node *) &list->head;

		return;
	}

	iscsi_node *tail = pred->succ;

	if ( tail == NULL ) {
		tail       = pred->pred;

		node->succ = pred;
		node->pred = tail;

		pred->pred = node;
		tail->succ = node;

		return;
	}

	node->succ = tail;
	node->pred = pred;

	tail->pred = node;
	pred->succ = node;
}

/**
 * @brief Removes the node from the head of a doubly linked list.
 *
 * This function sets the head of the list to
 * its successor and adjusts the list and
 * node pointers accordingly.
 *
 * @param[in] list Pointer to doubly linked list to remove the
 * head from. May NOT be NULL, so be careful.
 */
static inline void iscsi_list_pop(iscsi_list *list)
{
	iscsi_node *head = list->head;
	iscsi_node *node = head->succ;

	if ( node == NULL )
		return;

	list->head = node;

	node->pred = (iscsi_node *) &list->head;
}

/**
 * @brief Removes the node from the tail of a doubly linked list.
 *
 * This function sets the tail of the list to
 * its predecessor and adjusts the list and
 * node pointers accordingly.
 *
 * @param[in] list Pointer to doubly linked list to remove the
 * tail from. May NOT be NULL, so be careful.
 */
static inline void iscsi_list_dequeue(iscsi_list *list)
{
	iscsi_node *tail = list->pred;
	iscsi_node *node = tail->pred;

	if ( node == NULL )
		return;

	list->pred = node;

	node->succ = (iscsi_node *) &list->tail;
}

/**
 * @brief Removes a specified node from a doubly linked list.
 *
 * This function sets the successor of the
 * node's predecessor and the predecessor
 * of the node's successor by adjusting
 * the list and node pointers accordingly.
 *
 * @param[in] node Pointer to node to be removed from
 * the list. May NOT be NULL, so
 * be careful.
 */
static inline void iscsi_list_remove(iscsi_node *node)
{
	iscsi_node *succ = node->succ;
	iscsi_node *pred = node->pred;

	pred->succ = succ;
	succ->pred = pred;
}

/**
 * @brief Checks whether a doubly linked list is empty.
 *
 * Whenever this function returns false,
 * iscsi_list_peek will return a pointer
 * to the first node in the list.
 *
 * @param[in] list Pointer to doubly linked list to check if
 * empty. May NOT be NULL, so be careful.
 * @retval true The doubly linked list is empty.
 * @retval false The doubly linked list contains nodes.
 */
static inline bool iscsi_list_empty(const iscsi_list *list)
{
	return (list->head->succ == NULL);
}

/**
 * @brief Gets the node from the head of a doubly linked list.
 *
 * This function returns NULL if the list is
 * empty.
 *
 * @param[in] list Pointer to doubly linked list to get the
 * head from. May NOT be NULL, so be careful.
 * @return Pointer to doubly linked list node of the
 * head or NULL if the list is empty.
 */
static inline iscsi_node *iscsi_list_peek(const iscsi_list *list)
{
	iscsi_node *head = list->head;

	return (head->succ != NULL) ? head : NULL;
}


/**
 * @brief Hash map bucket containing key, value and hash code.
 *
 * This structure is used by the iSCSI hash map implementation
 * in order to maintain the elements.
 */
typedef struct iscsi_hashmap_bucket {
    /// Next bucket, MUST be first element.
	iscsi_node node;

    /// Data used as key, MUST be aligned to 8 bytes and zero padded.
	uint8_t *key;

    /// Size of key.
	size_t key_size;

    /// Hash code for the key.
	uint32_t hash;

    /// Associate4d value to the key, NULL is allowed.
	uint8_t *value;
} iscsi_hashmap_bucket;

/**
 * @brief Hash map containing an expandable list of buckets
 *
 * This structure is used by the ultra performant hash map
 * implementation. It uses a linked list allowing fast
 * insertions. Elements can be removed.
 */
typedef struct iscsi_hashmap {
    /// Linked list containing the hash map buckets.
	iscsi_hashmap_bucket *buckets;

    /// Doubly linked list for fast insertion.
    iscsi_list list;

    /// Last inserted unique identifier (primary key).
	uint64_t last_insert_id;

    /// Current bucket capacity, MUST be a power of two.
    uint capacity;

    /// Current capacity threshold triggering resize operation.
	uint cap_load;

	/// Current count of buckets.
	uint count;
} iscsi_hashmap;

/**
 * @brief Callback for iterating over map, freeing and removing entries. user_data is free for personal use.
 *
 * Callback function. This is a pointer to a
 * function for various purposes like iterating
 * through a hash map. It is also used for replacing
 * already existing keys or for key removal.
 *
 * @param[in] key Pointer to zero padded key. NULL is
 * an invalid pointer here, so be careful.
 * @param[in] key_size Number of bytes for the key, MUST
 * be a multiple of 8 bytes which is NOT checked, so
 * be careful.
 * @param[in] value Value of the key, NULL is allowed.
 * @param[in,out] user_data User data to be used by the
 * callback function. User data can be modified if
 * desired and may also be NULL if the callback
 * function handles this case. See the documentation
 * of the callback implementation for details.
 * @return A negative result indicates as fatal error,
 * 0 means successful operation and a positive value
 * indicates a non-fatal error or a warning.
 */
typedef int (*iscsi_hashmap_callback)(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data);

iscsi_hashmap *iscsi_hashmap_create(const uint capacity); // Creates an empty hash map with either specified or default capacity
void iscsi_hashmap_destroy(iscsi_hashmap *map); // Deallocates the hash map objects and buckets, not elements
                                                // Use iscsi_hashmap_iterate to deallocate the elements themselves

uint8_t *iscsi_hashmap_key_create(const uint8_t *data, const size_t len); // Creates a key suitable for hashmap usage (ensures 8-byte boundary and zero padding)
void iscsi_hashmap_key_create_id(iscsi_hashmap *map, uint64_t *key); // Creates an unique key identifier suitable for hashmap usage (ensures 8-byte boundary and zero padding)
void iscsi_hashmap_key_destroy(uint8_t *key); // Deallocates all resources acquired by iscsi_hashmap_create_key
int iscsi_hashmap_key_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Deallocates a key in a hash map
int iscsi_hashmap_destroy_value_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Deallocates a value in a hash map
int iscsi_hashmap_key_destroy_value_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Deallocates a key / value pair in a hash map by calling free (default destructor)

int iscsi_hashmap_put(iscsi_hashmap *map, uint8_t *key, const size_t key_size, uint8_t *value); // Assigns key / value pair to hash map at the tail of doubly linked list without making copies
int iscsi_hashmap_get_put(iscsi_hashmap *map, uint8_t *key, const size_t key_size, uint8_t **out_in_value); // Assigns key / value pair to hash map at the tail of doubly linked list without making copies
int iscsi_hashmap_put_free(iscsi_hashmap *map, uint8_t *key, const size_t key_size, uint8_t *value, iscsi_hashmap_callback callback, uint8_t *user_data); // Assigns key / value pair to hash map without making copies with callback function in case the key already exists
bool iscsi_hashmap_contains(iscsi_hashmap *map, const uint8_t *key, const size_t key_size); // Checks whether a specified key exists
int iscsi_hashmap_get(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t **out_value); // Retrieves the value of a specified key

void iscsi_hashmap_remove(iscsi_hashmap *map, const uint8_t *key, const size_t key_size); // Removes an element both from the doubly linked list and by setting the key to NULL
void iscsi_hashmap_remove_free(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, iscsi_hashmap_callback callback, uint8_t *user_data); // Removes an element both from the doubly linked list and by setting the key to NULL and invokes a callback function before actual removal

uint iscsi_hashmap_size(const iscsi_hashmap *map); // Retrieves the number of elements of the hash map

int iscsi_hashmap_iterate(iscsi_hashmap *map, iscsi_hashmap_callback callback, uint8_t *user_data); // Iterator with callback function invoked on each element


/* iSCSI protocol stuff (all WORD/DWORD/QWORD values are big endian by default
   unless specified otherwise). */

/// iSCSI Basic Header Segment (BHS) size.
#define ISCSI_BHS_SIZE 48UL

/// iSCSI Advanced Header Segment (AHS) maximum allowed size.
#define ISCSI_MAX_AHS_SIZE (255UL << 2UL)

/// iSCSI DataSegment maximum allowed size.
#define ISCSI_MAX_DS_SIZE 16777215UL

/// iSCSI packet data alignment (BHS, AHS and DataSegment).
#define ISCSI_ALIGN_SIZE 4UL

/// iSCSI header and data digest size (CRC32C).
#define ISCSI_DIGEST_SIZE 4UL


/// iSCSI Default receive DataSegment (DS) size in bytes.
#define ISCSI_DEFAULT_RECV_DS_LEN 8192UL

/// iSCSI default maximum DataSegment receive length in bytes.
#define ISCSI_DEFAULT_MAX_RECV_DS_LEN 65536UL


/// iSCSI default maximum Ready To Transfer (R2T) active tasks.
#define ISCSI_DEFAULT_MAX_R2T_PER_CONNECTION 4UL

/// iSCSI default maximum DataSegment receive length in bytes.
#define ISCSI_DEFAULT_MAX_DATA_IN_PER_CONNECTION 64UL

/// iSCSI default maximum DataSegment send length in bytes.
#define ISCSI_DEFAULT_MAX_DATA_OUT_PER_CONNECTION 16UL


/// Current minimum iSCSI protocol version supported by this implementation.
#define ISCSI_VERSION_MIN 0

/// Current maximum iSCSI protocol version supported by this implementation.
#define ISCSI_VERSION_MAX 0


/// CRC32C initial constant for header and data digest.
#define ISCSI_CRC32C_INITIAL      0xFFFFFFFFUL

/// CRC32C initial constant for header and data digest.
#define ISCSI_CRC32C_XOR          0xFFFFFFFFUL


/// iSCSI initiator (client) command opcode: NOP-Out.
#define ISCSI_OPCODE_CLIENT_NOP_OUT        0x00

/// iSCSI initiator (client) command opcode: SCSI Command (encapsulates a SCSI Command Descriptor Block).
#define ISCSI_OPCODE_CLIENT_SCSI_CMD       0x01

/// iSCSI initiator (client) command opcode: SCSI Task Management Function Request.
#define ISCSI_OPCODE_CLIENT_TASK_FUNC_REQ  0x02

/// iSCSI initiator (client) command opcode: Login Request.
#define ISCSI_OPCODE_CLIENT_LOGIN_REQ      0x03

/// iSCSI initiator (client) command opcode: Text Request.
#define ISCSI_OPCODE_CLIENT_TEXT_REQ       0x04

/// iSCSI initiator (client) command opcode: SCSI Data-Out (for write operations).
#define ISCSI_OPCODE_CLIENT_SCSI_DATA_OUT  0x05

/// iSCSI initiator (client) command opcode: Logout Request.
#define ISCSI_OPCODE_CLIENT_LOGOUT_REQ     0x06

/// iSCSI initiator (client) command opcode: Selective Negative / Sequence Number Acknowledgment (SNACK) Request.
#define ISCSI_OPCODE_CLIENT_SNACK_REQ      0x10

/// iSCSI initiator (client) command opcode: Vendor-specific code #1.
#define ISCSI_OPCODE_CLIENT_VENDOR_CODE1   0x1C

/// iSCSI initiator (client) command opcode: Vendor-specific code #2.
#define ISCSI_OPCODE_CLIENT_VENDOR_CODE2   0x1D

/// iSCSI initiator (client) command opcode: Vendor-specific code #3.
#define ISCSI_OPCODE_CLIENT_VENDOR_CODE3   0x1E

/// First iSCSI initiator (client) command opcode.
#define ISCSI_OPCODE_CLIENT_FIRST          0x00

/// Last iSCSI initiator (client) command opcode.
#define ISCSI_OPCODE_CLIENT_LAST           0x1F


/// iSCSI target (server) command opcode: NOP-In.
#define ISCSI_OPCODE_SERVER_NOP_IN         0x20

/// iSCSI target (server) command opcode: SCSI Response - contains SCSI status and possibly sense information or other response information.
#define ISCSI_OPCODE_SERVER_SCSI_RESPONSE  0x21

/// iSCSI target (server) command opcode: SCSI Task Management Function Response.
#define ISCSI_OPCODE_SERVER_TASK_FUNC_RES  0x22

/// iSCSI target (server) command opcode: Login Response.
#define ISCSI_OPCODE_SERVER_LOGIN_RES      0x23

/// iSCSI target (server) command opcode: Text Response.
#define ISCSI_OPCODE_SERVER_TEXT_RES       0x24

/// iSCSI target (server) command opcode: SCSI Data-In (for read operations).
#define ISCSI_OPCODE_SERVER_SCSI_DATA_IN   0x25

/// iSCSI target (server) command opcode: Logout Response.
#define ISCSI_OPCODE_SERVER_LOGOUT_RES     0x26

/// iSCSI target (server) command opcode: Ready To Transfer (R2T) - sent by target when it is ready to receive data.
#define ISCSI_OPCODE_SERVER_READY_XFER     0x31

/// iSCSI target (server) command opcode: Asynchronous Message - sent by target to indicate certain special conditions.
#define ISCSI_OPCODE_SERVER_ASYNC_MSG      0x32

/// iSCSI target (server) command opcode: Vendor-specific code #1.
#define ISCSI_OPCODE_SERVER_VENDOR_CODE1   0x3C

/// iSCSI target (server) command opcode: Vendor-specific code #2.
#define ISCSI_OPCODE_SERVER_VENDOR_CODE2   0x3D

/// iSCSI target (server) command opcode: Vendor-specific code #3.
#define ISCSI_OPCODE_SERVER_VENDOR_CODE3   0x3E

/// iSCSI target (server) command opcode: Reject.
#define ISCSI_OPCODE_SERVER_REJECT         0x3F


/// First iSCSI target (server) command opcode.
#define ISCSI_OPCODE_SERVER_FIRST          0x20

/// Last iSCSI target (server) command opcode.
#define ISCSI_OPCODE_SERVER_LAST           0x3F


/// iSCSI opcode bit mask (bits 0-5 used).
#define ISCSI_OPCODE_MASK           0x3F

/// Macro which extracts iSCSI packet data opcode out of opcode byte.
#define ISCSI_GET_OPCODE(x) ((x) & ISCSI_OPCODE_MASK)

/// iSCSI opcode flags (I) Immediate bit: For Request PDUs, the I bit set to 1 is an immediate delivery marker.
#define ISCSI_OPCODE_FLAGS_IMMEDIATE (1 << 6L)


/**
 * @brief iSCSI Basic Header Segment packet data.
 *
 * This structure contains the basic iSCSI packet
 * data and is shared among all opcodes. This has
 * to be used before the opcode of the packet data
 * has been determined.
 */
typedef struct __attribute__((packed)) iscsi_bhs_packet {
    /// Command opcode.
    uint8_t opcode;

    /// Opcode-specific fields.
    uint8_t opcode_fields[3];

    /// Total length of AHS (Advanced Header Segment).
    uint8_t total_ahs_len;

    /// Length of Data Segment.
    uint8_t ds_len[3];

    union {
        /// SCSI LUN bit mask.
        uint64_t lun;

        /// Opcode-specific fields.
        uint8_t opcode_spec[8];
    } lun_opcode;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /// Opcode-specific fields.
    uint8_t opcode_spec_fields[28];
} iscsi_bhs_packet;


/// iSCSI AHS type: Extended Command Descriptor Block (CDB).
#define ISCSI_AHS_TYPE_EXT_CDB_PACKET                   0x01

/// iSCSI AHS type: Bidirectional Read Expected Data Transfer Length.
#define ISCSI_AHS_TYPE_BIDI_READ_EXP_XFER_AHS_PACKET    0x02


/**
 * @brief iSCSI Advanced Header Segment packet data.
 *
 * This structure contains the advanced iSCSI packet
 * data and is shared among all opcodes. This has
 * to be used before the opcode of the packet data
 * has been determined.
 */
typedef struct __attribute__((packed)) iscsi_ahs_packet {
    /// AHSLength.
    uint16_t len;

    /// AHSType.
    uint8_t type;

    /// AHS-Specific.
    uint8_t specific;

    /// AHS-Specific data.
    uint8_t data[0];
} iscsi_ahs_packet;


/**
 * @brief iSCSI Extended CDB AHS packet data structure.
 *
 * This type of AHS MUST NOT be used if the CDBLength is less than 17.
 * The length includes the reserved byte 3.
 */
typedef struct __attribute__((packed)) iscsi_ext_cdb_ahs_packet {
    /// AHSLength: AHSLength - (CDBLength - 15).
    uint16_t len;

    // AHSType: Identifier (always 1 according to iSCSI specifications).
    uint8_t type;

    /// Reserved for future usage, always MUST be 0.
    uint8_t reserved;

    /// ExtendedCDB.
    uint8_t data[0];
} iscsi_ext_cdb_ahs_packet;

/**
 * @brief iSCSI Bidirectional Read Expected Data Transfer Length AHS packet data structure.
 *
 * This structure is used to determine the bidirectional read
 * expected data transfer length.
 */
typedef struct __attribute__((packed)) iscsi_bidi_read_exp_xfer_ahs_packet {
    /// AHSLength: Always 5 according to iSCSI specifications for now.
    uint16_t len;

    /// AHSType: Always 2 according to iSCSI specifications for now.
    uint8_t type; // Identifier (always 0x02 according to specs)

    /// Reserved for future usage, always MUST be 0.
    uint8_t reserved;

    /// Bidirectional Read Expected Data Transfer Length.
    uint32_t bidi_read_exp_xfer_len;
} iscsi_bidi_read_exp_xfer_ahs_packet;


/**
 * @brief DataSegment Error: Unexpected unsolicited data.
 *
 * Certain iSCSI conditions result in the command being terminated at
 * the target (response code of Command Completed at Target) with a SCSI
 * CHECK CONDITION Status as outlined in the following definitions
 * (Sense key: Aborted Command 0x0B).
 */
#define ISCSI_DS_ERROR_UNEXPECTED_UNSOLICITED_DATA_ASC  0x0C

/**
 * @brief DataSegment Error: Unexpected unsolicited data.
 *
 * Certain iSCSI conditions result in the command being terminated at
 * the target (response code of Command Completed at Target) with a SCSI
 * CHECK CONDITION Status as outlined in the following definitions
 * (Sense key: Aborted Command 0x0B).
 */
#define ISCSI_DS_ERROR_UNEXPECTED_UNSOLICITED_DATA_ASCQ 0x0C


/**
 * @brief DataSegment Error: Incorrect amount of data.
 *
 * Certain iSCSI conditions result in the command being terminated at
 * the target (response code of Command Completed at Target) with a SCSI
 * CHECK CONDITION Status as outlined in the following definitions
 * (Sense key: Aborted Command 0x0B).
 */
#define ISCSI_DS_ERROR_INCORRECT_AMOUNT_OF_DATA_ASC  0x0C

/**
 * @brief DataSegment Error: Incorrect amount of data.
 *
 * Certain iSCSI conditions result in the command being terminated at
 * the target (response code of Command Completed at Target) with a SCSI
 * CHECK CONDITION Status as outlined in the following definitions
 * (Sense key: Aborted Command 0x0B).
 */
#define ISCSI_DS_ERROR_INCORRECT_AMOUNT_OF_DATA_ASCQ 0x0D


/**
 * @brief DataSegment Error: Protocol Service CRC error.
 *
 * Certain iSCSI conditions result in the command being terminated at
 * the target (response code of Command Completed at Target) with a SCSI
 * CHECK CONDITION Status as outlined in the following definitions
 * (Sense key: Aborted Command 0x0B).
 */
#define ISCSI_DS_ERROR_PROTOCOL_SERVICE_CRC_ERROR_ASC  0x47

/**
 * @brief DataSegment Error: Protocol Service CRC error.
 *
 * Certain iSCSI conditions result in the command being terminated at
 * the target (response code of Command Completed at Target) with a SCSI
 * CHECK CONDITION Status as outlined in the following definitions
 * (Sense key: Aborted Command 0x0B).
 */
#define ISCSI_DS_ERROR_PROTOCOL_SERVICE_CRC_ERROR_ASCQ 0x05


/**
 * @brief DataSegment Error: Selective Negative / Sequence Number Acknowledgment (SNACK) rejected.
 *
 * Certain iSCSI conditions result in the command being terminated at
 * the target (response code of Command Completed at Target) with a SCSI
 * CHECK CONDITION Status as outlined in the following definitions
 * (Sense key: Aborted Command 0x0B).
 */
#define ISCSI_DS_ERROR_SNACK_REJECTED_ASC  0x11

/**
 * @brief DataSegment Error: Selective Negative / Sequence Number Acknowledgment (SNACK) rejected.
 *
 * Certain iSCSI conditions result in the command being terminated at
 * the target (response code of Command Completed at Target) with a SCSI
 * CHECK CONDITION Status as outlined in the following definitions
 * (Sense key: Aborted Command 0x0B).
 */
#define ISCSI_DS_ERROR_SNACK_REJECTED_ASCQ 0x13


/**
 * @brief iSCSI header digest in case CRC32C has been negotiated.
 *
 * Optional header and data digests protect the integrity of the header
 * and data, respectively. The digests, if present, are located,
 * respectively, after the header and PDU-specific data and cover,
 * respectively, the header and the PDU data, each including the padding
 * bytes, if any.
 *
 * The existence and type of digests are negotiated during the Login
 * Phase.
 */
typedef struct __attribute__((packed)) iscsi_header_digest {
    /// Header digest is a CRC32C for ensuring integrity.
    uint32_t crc32c;
} iscsi_header_digest;

/**
 * @brief iSCSI data digest in case CRC32C has been negotiated.
 *
 * Optional header and data digests protect the integrity of the header
 * and data, respectively. The digests, if present, are located,
 * respectively, after the header and PDU-specific data and cover,
 * respectively, the header and the PDU data, each including the padding
 * bytes, if any.
 *
 * The existence and type of digests are negotiated during the Login
 * Phase.
 */
typedef struct __attribute__((packed)) iscsi_data_digest {
    /// Data digest is a CRC32C for ensuring integrity.
    uint32_t crc32c;
} iscsi_data_digest;


/**
 * @brief iSCSI SCSI CDB packet data structure.
 *
 * There are 16 bytes in the CDB field to accommodate the commonly used
 * CDBs. Whenever the CDB is larger than 16 bytes, an Extended CDB AHS
 * MUST be used to contain the CDB spillover.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb {
    /// SCSI opcode.
    uint8_t opcode;

    /// Additional op-code specific data.
    uint8_t data[0];
} iscsi_scsi_cdb;


/// iSCSI SCSI Command Descriptor Block (CDB) for INQUIRY command flags: Enable Vital Product Data (EVPD).
#define ISCSI_SCSI_CDB_INQUIRY_FLAGS_EVPD  (1 << 0)

/// iSCSI SCSI Command Descriptor Block (CDB) for INQUIRY command flags: Command Support Data (CMDDT).
#define ISCSI_SCSI_CDB_INQUIRY_FLAGS_CMDDT (1 << 1)


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI INQUIRY command.
 *
 * There are 6 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_inquiry {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Logical Unit Number (LUN), CMMDT and EVPD.
    uint8_t lun_flags;

    /// Page code.
    uint8_t page_code;

    /// Allocation length in bytes.
    uint16_t alloc_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_inquiry;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI READ(6) and WRITE(6) commands.
 *
 * There are 6 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_read_write_6 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Logical Block Address (LBA).
    uint8_t lba[3];

    /// Transfer length in bytes.
    uint8_t xfer_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_read_write_6;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI READ(10) and WRITE(10) commands.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_read_write_10 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Logical Block Address (LBA).
    uint32_t lba;

    /// Group number.
    int8_t group_num;

    /// Transfer length in bytes.
    uint16_t xfer_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_read_write_10;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI READ(12) and WRITE(12) commands.
 *
 * There are 12 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_read_write_12 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Logical Block Address (LBA).
    uint32_t lba;

    /// Transfer length in bytes.
    uint32_t xfer_len;

    /// Restricted for MMC-6 and group number.
    int8_t restrict_group_num;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_read_write_12;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI READ(16) and WRITE(16) commands.
 *
 * There are 16 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_read_write_16 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Logical Block Address (LBA).
    uint64_t lba;

    /// Transfer length in bytes.
    uint32_t xfer_len;

    /// Restricted for MMC-6 and group number.
    int8_t restrict_group_num;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_read_write_16;


/// iSCSI SCSI Command Descriptor Block (CDB) for REPORT LUNS command select report: Logical unit with addressing method.
#define ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_ADDR_METHOD 0x00

/// iSCSI SCSI Command Descriptor Block (CDB) for REPORT LUNS command select report: Well known logical unit.
#define ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_KNOWN       0x01

/// iSCSI SCSI Command Descriptor Block (CDB) for REPORT LUNS command select report: Logical unit.
#define ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_ALL         0x02


/**
 * @brief iSCSI SCSI CDB packet data structure for REPORT LUNS command.
 *
 * There are 12 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_report_luns {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Select report.
    uint8_t select_report;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved2;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved3;

    /// Allocation length in bytes.
    uint32_t alloc_len;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved4;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_report_luns;


/// iSCSI SCSI Command Descriptor Block (CDB) for COMPARE AND WRITE command flags: Force Unit Access (FUA).
#define ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_FUA                  (1 << 3L)

/// iSCSI SCSI Command Descriptor Block (CDB) for COMPARE AND WRITE command flags: Disable Page Out (DPO).
#define ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_DPO                  (1 << 4L)

/// iSCSI SCSI Command Descriptor Block (CDB) for COMPARE AND WRITE command write protect flags: First bit of the three bits.
#define ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_FIRST_BIT  5

/// iSCSI SCSI Command Descriptor Block (CDB) for COMPARE AND WRITE command write protect flags: Last bit of the three bits.
#define ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_LAST_BIT   ((ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_FIRST_BIT) + 3 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for COMPARE AND WRITE command write protect flags: Bit mask.
#define ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_MASK       (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_FIRST_BIT, ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for COMPARE AND WRITE command write protect flags: Extracts the write protect bits.
#define ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_GET_WRPROTECT(x)     (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_FIRST_BIT, ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for COMPARE AND WRITE command write protect flags: Stores into the write protect bits.
#define ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_PUT_WRPROTECT(x)     (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_FIRST_BIT, ISCSI_SCSI_CDB_CMP_WRITE_FLAGS_WRPROTECT_LAST_BIT))


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI COMPARE AND WRITE command.
 *
 * There are 16 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_cmp_write {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Logical Block Address (LBA).
    uint64_t lba;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved2;

    /// Number of blocks in bytes.
    uint8_t num_blocks;

    /// Restricted for MMC-6 and group number.
    int8_t restrict_group_num;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_cmp_write;


/// iSCSI SCSI Command Descriptor Block (CDB) for SERVICE ACTION IN(16) command service action: READ CAPACITY(16).
#define ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_READ_CAPACITY_16 0x10

/// iSCSI SCSI Command Descriptor Block (CDB) for SERVICE ACTION IN(16) command service action: READ LONG(16).
#define ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_READ_LONG_16     0x11

/// iSCSI SCSI Command Descriptor Block (CDB) for SERVICE ACTION IN(16) command service action: First bit of the five bits.
#define ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_FIRST_BIT        0

/// iSCSI SCSI Command Descriptor Block (CDB) for SERVICE ACTION IN(16) command service action: Last bit of the five bits.
#define ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_LAST_BIT         ((ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_FIRST_BIT) + 5 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for SERVICE ACTION IN(16) command service action: Bit mask.
#define ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_MASK             (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for SERVICE ACTION IN(16) command service action: Extracts the service action bits.
#define ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_GET_ACTION(x)           (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for SERVICE ACTION IN(16) command service action: Stores into the service action bits.
#define ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_PUT_ACTION(x)           (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_LAST_BIT))


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI SERVICE IN ACTION(16) command.
 *
 * There are 16 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_service_action_in_16 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Service action.
    uint8_t action;

    /// Logical Block Address (LBA), obselete by now.
    uint64_t lba;

    /// Allocation length in bytes.
    uint32_t alloc_len;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_service_action_in_16;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI SYNCHRONIZE CACHE(10) command.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_sync_cache_10 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Logical Block Address (LBA).
    uint32_t lba;

    /// Group number.
    int8_t group_num;

    /// Transfer length in bytes.
    uint16_t xfer_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_sync_cache_10;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI SYNCHRONIZE CACHE(16) command.
 *
 * There are 16 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_sync_cache_16 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Logical Block Address (LBA).
    uint64_t lba;

    /// Transfer length in bytes.
    uint32_t xfer_len;

    /// Group number.
    int8_t group_num;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_sync_cache_16;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI WRITE SAME(10) command.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_write_same_10 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Logical Block Address (LBA).
    uint32_t lba;

    /// Group number.
    int8_t group_num;

    /// Transfer length in bytes.
    uint16_t xfer_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_write_same_10;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI WRITE SAME(16) command.
 *
 * There are 16 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_write_same_16 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Logical Block Address (LBA).
    uint64_t lba;

    /// Transfer length in bytes.
    uint32_t xfer_len;

    /// Group number.
    int8_t group_num;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_write_same_16;


/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SELECT(6) command flags: Save Pages (SP).
#define ISCSI_SCSI_CDB_MODE_SELECT_6_FLAGS_SP  (1 << 0)

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SELECT(6) command flags: Revert To Defaults (RTD).
#define ISCSI_SCSI_CDB_MODE_SELECT_6_FLAGS_RTD (1 << 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SELECT(6) command flags: Page Format (PF).
#define ISCSI_SCSI_CDB_MODE_SELECT_6_FLAGS_PF  (1 << 4)


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI MODE SELECT(6) command.
 *
 * There are 6 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_mode_select_6 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved;

    /// Parameter list length in bytes.
    uint8_t param_list_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_mode_select_6;


/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SELECT(10) command flags: Save Pages (SP).
#define ISCSI_SCSI_CDB_MODE_SELECT_10_FLAGS_SP  (1 << 0)

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SELECT(10) command flags: Page Format (PF).
#define ISCSI_SCSI_CDB_MODE_SELECT_10_FLAGS_PF  (1 << 4)


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI MODE SELECT(10) command.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_mode_select_10 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0 for now).
    uint32_t reserved;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved2;

    /// Parameter list length in bytes.
    uint16_t param_list_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_mode_select_10;


/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command flags: Disable Block Descriptors (DBD).
#define ISCSI_SCSI_CDB_MODE_SENSE_6_FLAGS_DBD (1 << 3)


/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page code: First bit of the six bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_FIRST_BIT         0

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page code: Last bit of the six bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_LAST_BIT          ((ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_FIRST_BIT) + 6 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page code: Bit mask.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_MASK              (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page code: Extracts the page code bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_GET_PAGE_CODE(x)            (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page code: Stores into the page code bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PUT_PAGE_CODE(x)            (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: Current values.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_CURRENT_VALUES 0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: Changeable values.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_CHG_VALUES     0x1

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: Default values.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_DEFAULT_VALUES 0x2

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: Saved values.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_SAVED_VALUES   0x3

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: First bit of the two bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_FIRST_BIT      6

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: Last bit of the two bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_LAST_BIT       ((ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_FIRST_BIT) + 2 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: Bit mask.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_MASK           (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: Extracts the page control bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_GET_PAGE_CONTROL(x)         (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(6) command page control: Stores into the page control bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_6_PUT_PAGE_CONTROL(x)         (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_LAST_BIT))


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI MODE SENSE(6) command.
 *
 * There are 6 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_mode_sense_6 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Page code and page control.
    uint8_t page_code_control;

    /// Sub page code.
    uint8_t sub_page_code;

    /// Allocation length in bytes.
    uint8_t alloc_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_mode_sense_6;


/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command flags: Disable Block Descriptors (DBD).
#define ISCSI_SCSI_CDB_MODE_SENSE_10_FLAGS_DBD   (1 << 3)

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command flags: Long LBA Accepted (LLBAA).
#define ISCSI_SCSI_CDB_MODE_SENSE_10_FLAGS_LLBAA (1 << 4)


/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page code: First bit of the six bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_FIRST_BIT         0

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page code: Last bit of the six bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_LAST_BIT          ((ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_FIRST_BIT) + 6 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page code: Bit mask.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_MASK              (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page code: Extracts the page code bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_GET_PAGE_CODE(x)            (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page code: Stores into the page code bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PUT_PAGE_CODE(x)            (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: Current values.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_CURRENT_VALUES 0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: Changeable values.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_CHG_VALUES     0x1

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: Default values.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_DEFAULT_VALUES 0x2

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: Saved values.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_SAVED_VALUES   0x3

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: First bit of the two bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_FIRST_BIT      6

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: Last bit of the two bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_LAST_BIT       ((ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_FIRST_BIT) + 2 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: Bit mask.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_MASK           (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: Extracts the page control bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_GET_PAGE_CONTROL(x)         (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for MODE SENSE(10) command page control: Stores into the page control bits.
#define ISCSI_SCSI_CDB_MODE_SENSE_10_PUT_PAGE_CONTROL(x)         (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_FIRST_BIT, ISCSI_SCSI_CDB_MODE_SENSE_10_PAGE_CONTROL_LAST_BIT))


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI MODE SENSE(10) command.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_mode_sense_10 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Page code and page control.
    uint8_t page_code_control;

    /// Sub page code.
    uint8_t sub_page_code;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved2;

    /// Allocation length in bytes.
    uint16_t alloc_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_mode_sense_10;


/// iSCSI SCSI Command Descriptor Block (CDB) for REQUEST SENSE command flags: Descriptor Format (DESC).
#define ISCSI_SCSI_CDB_REQ_SENSE_FLAGS_DESC (1 << 0)


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI REQUEST SENSE command.
 *
 * There are 6 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_req_sense {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved;

    /// Allocation length in bytes.
    uint8_t alloc_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_req_sense;


/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags: Reply immediately after CDB check (IMMED).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_EXEC_FLAGS_IMMED (1 << 0)


/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Process the START and LOEJ bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_PROC_START_LOEJ_BITS 0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Cause the logical unit to transition to the active power condition (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_ACTIVE               0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Cause the logical unit to transition to the idle_a power condition (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_IDLE_A               0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Cause the logical unit to transition to the idle_b power condition (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_IDLE_B               0x1

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Cause the logical unit to transition to the idle_c power condition (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_IDLE_C               0x2

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Cause the logical unit to transition to the standby_z power condition (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_STANDBY_Z            0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Cause the logical unit to transition to the standby_b power condition (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_STANDBY_Y            0x1

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Initialize and start all of the idle and standby condition timers that are enabled (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_LU_CONTROL           0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Force the idle_a condition timer to be set to zero (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FORCE_IDLE_A_0       0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Force the idle_b condition timer to be set to zero (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FORCE_IDLE_B_0       0x1

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Force the idle_c condition timer to be set to zero (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FORCE_IDLE_C_0       0x2

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Force the standby_z condition timer to be set to zero (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FORCE_STANDBY_Z_0    0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Force the standby_y condition timer to be set to zero (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FORCE_STANDBY_Y_0    0x1

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: First bit of the four bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FIRST_BIT            0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Last bit of the four bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_LAST_BIT             ((ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Bit mask.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_MASK                 (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FIRST_BIT, ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Extracts the power condition modifier bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_GET_POWER_COND_MOD(x)               (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FIRST_BIT, ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution power condition modifier: Stores into the power condition modifier bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_PUT_POWER_COND_MOD(x)               (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_FIRST_BIT, ISCSI_SCSI_CDB_START_STOP_UNIT_POWER_COND_MOD_LAST_BIT))


/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags: START.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_START                      (1 << 0)

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags: LOad EJect (LOEJ).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_LOEJ                       (1 << 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags: Do not flush caches until a power condition that prevents accessing the medium is entered (NO_FLUSH).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_NO_FLUSH                   (1 << 2)

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Process the START and LOEJ bits (START_VALID).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_START_VALID     0x0

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Cause the logical unit to transition to the active power condition (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_ACTIVE          0x1

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Cause the logical unit to transition to the idle_a to idle_c power conditions (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_IDLE            0x2

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Cause the logical unit to transition to the standby_z and standby_y power conditions (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_STANDBY         0x3

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Obselete.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_OBSELETE        0x5

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Initialize and start all of the idle and standby condition timers that are enabled (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_LU_CONTROL      0x7

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Force the idle_a to idle_c condition timers to be set to zero (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_FORCE_IDLE_0    0xA

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Force the standby_z and standby_y condition timers to be set to zero (see SPC5).
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_FORCE_STANDBY_0 0xB

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: First bit of the four bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_FIRST_BIT       4

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Last bit of the four bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_LAST_BIT        ((ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_FIRST_BIT) + 8 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Bit mask.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_MASK            (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_FIRST_BIT, ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Extracts the power condition bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_GET_POWER_COND(x)          (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_FIRST_BIT, ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for START STOP UNIT command execution flags power condition: Stores into the power condition bits.
#define ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_PUT_POWER_COND(x)          (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_FIRST_BIT, ISCSI_SCSI_CDB_START_STOP_UNIT_FLAGS_POWER_COND_LAST_BIT))


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI START STOP UNIT command.
 *
 * There are 6 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_start_stop_unit {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Execution flags.
    int8_t exec_flags;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Power condition modifier.
    uint8_t power_cond_mod;

    /// Flags.
    int8_t flags;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_start_stop_unit;


/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Register - Register a reservation key without making a reservation.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_REGISTER                  0x00

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Reserve - Create a persistent reservation of the specified scope and type.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_RESERVE                   0x01

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Release - Releases the selected reservation for the requesting initiator.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_RELEASE                   0x02

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Clear – Clears all reservations keys and all persistent reservations.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_CLEAR                     0x03

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Preempt – Preempt reservations from another initiator.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_PREEMPT                   0x04

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Preempt reservations from another initiator and abort all tasks for all initiators with the specified reservation key.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_PREEMPT_ABORT             0x05

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Register and Ignore Existing Key – Register a new reservation key and discard existing reservation key.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_REGISTER_IGNORE_EXIST_KEY 0x06

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Register and Move Registers - Registers a reservation key for another I_T nexus and moves the persistent reservation to that I-T nexus.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_REGISTER_MOVE_REGS        0x07

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: First bit of the five bits.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_FIRST_BIT                 0

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Last bit of the five bits.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_LAST_BIT                  ((ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_FIRST_BIT) + 5 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Bit mask.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_MASK                      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Extracts the service action bits.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_GET_ACTION(x)                    (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE OUT command service action: Stores into the service action bits.
#define ISCSI_SCSI_CDB_PR_RESERVE_OUT_PUT_ACTION(x)                    (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_PR_RESERVE_OUT_ACTION_LAST_BIT))


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI PERSISTENT RESERVE OUT command.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_pr_reserve_out {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Service action.
    uint8_t action;

    /// Scope and reservation type.
    uint8_t scope_type;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved;

    /// Parameter list length in bytes.
    uint32_t param_list_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_pr_reserve_out;


/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: Read keys - Reads all registered reservation keys (i.e. registrations) as described in SPC5.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_READ_KEYS                0x00

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: Read reservations - Reads the current persistent reservations as described in SPC5.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_READ_RESERVATIONS        0x01

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: Report capabilities - Returns capability information.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_READ_REPORT_CAPABILITIES 0x02

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: Read full status – Reads complete information about all registrations and the persistent reservations, if any.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_READ_FULL_STATUS         0x03

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: First bit of the five bits.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_FIRST_BIT                0

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: Last bit of the five bits.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_LAST_BIT                 ((ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_FIRST_BIT) + 5 - 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: Bit mask.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_MASK                     (ISCSI_BITS_GET_MASK(ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: Extracts the service action bits.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_GET_ACTION(x)                   (ISCSI_BITS_GET((x), ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_LAST_BIT))

/// iSCSI SCSI Command Descriptor Block (CDB) for PERSISTENT RESERVE IN command service action: Stores into the service action bits.
#define ISCSI_SCSI_CDB_PR_RESERVE_IN_PUT_ACTION(x)                   (ISCSI_BITS_PUT((x), ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_FIRST_BIT, ISCSI_SCSI_CDB_PR_RESERVE_IN_ACTION_LAST_BIT))


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI PERSISTENT RESERVE IN command.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_pr_reserve_in {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Service action.
    uint8_t action;

    /// Reserved for future usage (always MUST be 0 for now).
    uint32_t reserved;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved2;

    /// Parameter list length in bytes.
    uint16_t param_list_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_pr_reserve_in;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI RESERVE(6) command.
 *
 * There are 6 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_pr_reserve_6 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved_obselete;

    /// Obselete byte.
    uint8_t obselete;

    /// Obselete word.
    uint16_t obselete2;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_pr_reserve_6;


/// iSCSI SCSI Command Descriptor Block (CDB) for RESERVE(10) command flags: Long identifier larger than 255 (LONGID).
#define ISCSI_SCSI_CDB_RESERVE_10_FLAGS_LONGID (1 << 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for RESERVE(10) command flags: Third-party reservation (3RDPTY).
#define ISCSI_SCSI_CDB_RESERVE_10_FLAGS_3RDPTY (1 << 4)


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI RESERVE(10) command.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_pr_reserve_10 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Obselete.
    uint8_t obselete;

    /// Third-party device identifier.
    uint8_t third_party_dev_id;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved2;

    /// Parameter list length in bytes.
    uint16_t param_list_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_pr_reserve_10;


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI RELEASE(6) command.
 *
 * There are 6 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_pr_release_6 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved_obselete;

    /// Obselete byte.
    uint8_t obselete;

    /// Obselete word.
    uint16_t obselete2;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_pr_release_6;


/// iSCSI SCSI Command Descriptor Block (CDB) for RELEASE(10) command flags: Long identifier larger than 255 (LONGID).
#define ISCSI_SCSI_CDB_RELEASE_10_FLAGS_LONGID (1 << 1)

/// iSCSI SCSI Command Descriptor Block (CDB) for RELEASE(10) command flags: Third-party reservation (3RDPTY).
#define ISCSI_SCSI_CDB_RELEASE_10_FLAGS_3RDPTY (1 << 4)


/**
 * @brief iSCSI SCSI CDB packet data structure for SCSI RELEASE(10) command.
 *
 * There are 10 bytes in the CDB field for this command.
 */
typedef struct __attribute__((packed)) iscsi_scsi_cdb_pr_release_10 {
    /// SCSI opcode.
    iscsi_scsi_cdb cdb;

    /// Flags.
    int8_t flags;

    /// Obselete.
    uint8_t obselete;

    /// Third-party device identifier.
    uint8_t third_party_dev_id;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved2;

    /// Parameter list length in bytes.
    uint16_t param_list_len;

    /// Control.
    uint8_t control;
} iscsi_scsi_cdb_pr_release_10;


/**
 * @brief iSCSI SCSI DataSegment Command packet structure.
 *
 * iSCSI targets MUST support and enable Autosense. If Status is CHECK
 * CONDITION (0x02), then the data segment MUST contain sense data for
 * the failed command.
 *
 * For some iSCSI responses, the response data segment MAY contain some
 * response-related information (e.g., for a target failure, it may
 * contain a vendor-specific detailed description of the failure).
 */
typedef struct __attribute__((packed)) iscsi_scsi_ds_cmd_data {
    /// SenseLength: This field indicates the length of Sense Data.
    uint16_t len;

    /// The Sense Data contains detailed information about a CHECK CONDITION. SPC3 specifies the format and content of the Sense Data.
    uint8_t sense_data[0];

    /// Response Data.
    uint8_t res_data[0];
} iscsi_scsi_ds_cmd_data;


/// iSCSI SCSI Basic Inquiry Data peripheral type: Direct access device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_DIRECT    0x00

/// iSCSI SCSI Basic Inquiry Data peripheral type: Sequential access device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_SEQ       0x01

/// iSCSI SCSI Basic Inquiry Data peripheral type: Printer device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_PRINTER   0x02

/// iSCSI SCSI Basic Inquiry Data peripheral type: Processor device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_PROCESSOR 0x03

/// iSCSI SCSI Basic Inquiry Data peripheral type: Write once device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_WORM      0x04

/// iSCSI SCSI Basic Inquiry Data peripheral type: Read only direct access (e.g. CD-ROM) device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_RO_DIRECT 0x05

/// iSCSI SCSI Basic Inquiry Data peripheral type: Scanner device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_SCANNER   0x06

/// iSCSI SCSI Basic Inquiry Data peripheral type: Optical memory device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_OPTICAL   0x07

/// iSCSI SCSI Basic Inquiry Data peripheral type: Medium changer device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_CHANGER   0x08

/// iSCSI SCSI Basic Inquiry Data peripheral type: Communications device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_COMM      0x09

/// iSCSI SCSI Basic Inquiry Data peripheral type: Unknown or no device.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_UNKNOWN   0x1F

/// iSCSI SCSI Basic Inquiry Data peripheral type: First bit of the five bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT 0

/// iSCSI SCSI Basic Inquiry Data peripheral type: Last bit of the five bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT  ((ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT) + 5 - 1)

/// iSCSI SCSI Basic Inquiry Data peripheral type: Bit mask.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data peripheral type: Extracts the peripheral device type bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_GET_PERIPHERAL_TYPE(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data peripheral type: Stores into the peripheral device type bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_TYPE(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: The specified peripheral device type is currently connected to this logical unit, or connection state could not be determined.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_POSSIBLE    0x0

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: The target is capable of supporting the specified peripheral device type on this logical unit, but not connected.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_SUPPORTED   0x1

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: The target is not capable of supporting a physical device on this logical unit.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_NEVER       0x3

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: Vendor specific.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_VENDOR_UNIQ 0x4

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: First bit of the three bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT   5

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: Last bit of the three bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT    ((ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT) + 3 - 1)

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: Bit mask.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_MASK        (ISCSI_BITS_GET_MASK(ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: Extracts the peripheral device identifier bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_GET_PERIPHERAL_ID(x)      (ISCSI_BITS_GET((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: Stores into the peripheral device identifier bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_ID(x)      (ISCSI_BITS_PUT((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))


/// iSCSI SCSI Basic Inquiry Data peripheral type modifier: First bit of the seven bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_FIRST_BIT             0

/// iSCSI SCSI Basic Inquiry Data peripheral type modifier: Last bit of the seven bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_LAST_BIT              ((ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_FIRST_BIT) + 7 - 1)

/// iSCSI SCSI Basic Inquiry Data peripheral type modifier: Bit mask.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_MASK                  (ISCSI_BITS_GET_MASK(ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: Extracts the peripheral type modifier bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_GET_PERIPHERAL_TYPE_MOD(x)                (ISCSI_BITS_GET((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data peripheral identifier: Stores into the peripheral type modifier bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_TYPE_MOD(x)                (ISCSI_BITS_PUT((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data peripheral type modifier: Removable media.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_MOD_FLAGS_REMOVABLE_MEDIA (1 << 7)


/// iSCSI SCSI Basic Inquiry Data ANSI version: None.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_NONE       0x0

/// iSCSI SCSI Basic Inquiry Data ANSI version: SPC.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_SPC        0x3

/// iSCSI SCSI Basic Inquiry Data ANSI version: SPC2.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_SPC2       0x4

/// iSCSI SCSI Basic Inquiry Data ANSI version: SPC3.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_SPC3       0x5

/// iSCSI SCSI Basic Inquiry Data ANSI version: SPC4.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_SPC4       0x6

/// iSCSI SCSI Basic Inquiry Data ANSI version: SPC5.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_SPC5       0x7

/// iSCSI SCSI Basic Inquiry Data ANSI version: First bit of the three bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_FIRST_BIT  0

/// iSCSI SCSI Basic Inquiry Data ANSI version: Last bit of the three bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_LAST_BIT   ((ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_FIRST_BIT) + 3 - 1)

/// iSCSI SCSI Basic Inquiry Data ANSI version: Bit mask.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_MASK       (ISCSI_BITS_GET_MASK(ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data ANSI version: Extracts the ANSI version bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_GET_VERSION_ANSI(x)     (ISCSI_BITS_GET((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data ANSI version: Stores into the ANSI version bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_VERSION_ANSI(x)     (ISCSI_BITS_PUT((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ANSI_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data ECMA version: First bit of the three bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_FIRST_BIT  3

/// iSCSI SCSI Basic Inquiry Data ECMA version: Last bit of the three bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_LAST_BIT   ((ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_FIRST_BIT) + 3 - 1)

/// iSCSI SCSI Basic Inquiry Data ECMA version: Bit mask.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_MASK       (ISCSI_BITS_GET_MASK(ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data ECMA version: Extracts the ECMA version bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_GET_VERSION_ECMA(x)     (ISCSI_BITS_GET((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data ECMA version: Stores into the ECMA version bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_VERSION_ECMA(x)     (ISCSI_BITS_PUT((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ECMA_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data ISO version: First bit of the two bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_FIRST_BIT   6

/// iSCSI SCSI Basic Inquiry Data ISO version: Last bit of the two bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_LAST_BIT   ((ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_FIRST_BIT) + 2 - 1)

/// iSCSI SCSI Basic Inquiry Data ISO version: Bit mask.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_MASK        (ISCSI_BITS_GET_MASK(ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data ISO version: Extracts the ISO version bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_GET_VERSION_ISO(x)      (ISCSI_BITS_GET((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data ISO version: Stores into the ISO version bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_VERSION_ISO(x)      (ISCSI_BITS_PUT((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_VERSION_ISO_LAST_BIT))


/// iSCSI SCSI Basic Inquiry Data response data format flags: This structure complies with SCSI-1 specifications.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_LEVEL_0                0x00

/// iSCSI SCSI Basic Inquiry Data response data format flags: This structure complies with CCS pseudo specifications.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_CCS                    0x01

/// iSCSI SCSI Basic Inquiry Data response data format flags: This structure complies with SCSI-2/3 specifications.
#define	ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_SCSI_2                 0x02

/// iSCSI SCSI Basic Inquiry Data response data format flags: First bit of the four bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_FIRST_BIT              0

/// iSCSI SCSI Basic Inquiry Data response data format flags: Last bit of the four bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_LAST_BIT              ((ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI Basic Inquiry Data response data format flags: Bit mask.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_MASK                  (ISCSI_BITS_GET_MASK(ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data response data format flags: Extracts the response data format flags bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_GET_RESPONSE_DATA_FMT_FLAGS(x)                (ISCSI_BITS_GET((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data response data format flags: Stores into the response data format flags bits.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_RESPONSE_DATA_FMT_FLAGS(x)                (ISCSI_BITS_PUT((x), ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_FIRST_BIT, ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_LAST_BIT))

/// iSCSI SCSI Basic Inquiry Data response data format flags: Hierarchical Support.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_HISUP                 (1 << 4)

/// iSCSI SCSI Basic Inquiry Data response data format flags: Normal ACA Supported.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_NORMACA               (1 << 5)

/// iSCSI SCSI Basic Inquiry Data response data format flags: TERMINATE I/O PROCESS message device support.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_TERMINATE_IO_PROC_MSG (1 << 6)

/// iSCSI SCSI Basic Inquiry Data response data format flags: Asynchronous Event Notification device support.
#define ISCSI_SCSI_BASIC_INQUIRY_DATA_RESPONSE_DATA_FMT_FLAGS_ASYNC_EVENT_NOTIFY    (1 << 7)


/**
 * @brief iSCSI SCSI basic inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * cleared.
 */
typedef struct __attribute__((packed)) iscsi_scsi_basic_inquiry_data_packet {
    /// Peripheral device type and qualifier.
    uint8_t peripheral_type_id;

    /// Peripheral device type modifier and removable media bit.
    int8_t peripheral_type_mod_flags;

    /// ANSI-Approved, ECMA and ISO version.
    uint8_t version;

    /// Response data format, HISUP, NORMACA, AENC and TrmIOP flags.
    int8_t response_data_fmt_flags;

    /// Additional length in bytes.
    uint8_t add_len;
} iscsi_scsi_basic_inquiry_data_packet;


/// iSCSI SCSI Standard Inquiry Data vendor identifier for disk.
#define ISCSI_SCSI_STD_INQUIRY_DATA_DISK_VENDOR_ID "UNI FRBG"


/// iSCSI SCSI Standard Inquiry Data TPGS flags: Protect.
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_PROTECT        (1 << 0)

/// iSCSI SCSI Standard Inquiry Data TPGS flags: Third-Party Copy (3PC).
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_3PC            (1 << 3)

/// iSCSI SCSI Standard Inquiry Data TPGS flags: First bit of the two bits.
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_FIRST_BIT 4

/// iSCSI SCSI Standard Inquiry Data TPGS flags: Last bit of the two bits.
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_LAST_BIT  ((ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_FIRST_BIT) + 2 - 1)

/// iSCSI SCSI Standard Inquiry Data TPGS flags: Bit mask.
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_FIRST_BIT, ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_LAST_BIT))

/// iSCSI SCSI Standard Inquiry Data TPGS flags: Extracts the Target Port Group Support (TPGS) bits.
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_GET_TPGS(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_FIRST_BIT, ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_LAST_BIT))

/// iSCSI SCSI Standard Inquiry Data TPGS flags: Stores into the Target Port Group Support (TPGS) bits.
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_PUT_TPGS(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_FIRST_BIT, ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_TPGS_LAST_BIT))

/// iSCSI SCSI Standard Inquiry Data TPGS flags: Access Controls Coordinator (ACC).
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_ACC            (1 << 6)

/// iSCSI SCSI Standard Inquiry Data TPGS flags: SCC Supported (SCCS).
#define ISCSI_SCSI_STD_INQUIRY_DATA_TPGS_FLAGS_SCCS           (1 << 7)


/// iSCSI SCSI Standard Inquiry Data services flags: Multi Port (MULTIP).
#define ISCSI_SCSI_STD_INQUIRY_DATA_SERVICES_FLAGS_MULTIP  (1 << 4)

/// iSCSI SCSI Standard Inquiry Data services flags: VS.
#define ISCSI_SCSI_STD_INQUIRY_DATA_SERVICES_FLAGS_VS      (1 << 5)

/// iSCSI SCSI Standard Inquiry Data services flags: Enclosure Services (ENCSERV).
#define ISCSI_SCSI_STD_INQUIRY_DATA_SERVICES_FLAGS_ENCSERV (1 << 6)


/// iSCSI SCSI Standard Inquiry Data flags: Device responds with soft reset instead of hard reset to reset condition.
#define ISCSI_SCSI_STD_INQUIRY_DATA_FLAGS_SOFT_RESET    (1 << 0)

/// iSCSI SCSI Standard Inquiry Data flags: Device supports tagged command queueing.
#define ISCSI_SCSI_STD_INQUIRY_DATA_FLAGS_COMMAND_QUEUE (1 << 1)

/// iSCSI SCSI Standard Inquiry Data flags: Device supports linked commands for this logical unit.
#define ISCSI_SCSI_STD_INQUIRY_DATA_FLAGS_LINKED_CMDS   (1 << 3)

/// iSCSI SCSI Standard Inquiry Data flags: Device supports synchronous data transfers.
#define ISCSI_SCSI_STD_INQUIRY_DATA_FLAGS_SYNC          (1 << 4)

/// iSCSI SCSI Standard Inquiry Data flags: Device supports 16-bit wide data transfers.
#define ISCSI_SCSI_STD_INQUIRY_DATA_FLAGS_WIDE_16_BIT   (1 << 5)

/// iSCSI SCSI Standard Inquiry Data flags: Device supports 32-bit wide data transfers.
#define ISCSI_SCSI_STD_INQUIRY_DATA_FLAGS_WIDE_32_BIT   (1 << 6)

/// iSCSI SCSI Standard Inquiry Data flags: Device supports relative addressing mode of this logical unit.
#define ISCSI_SCSI_STD_INQUIRY_DATA_FLAGS_REL_ADDR      (1 << 7)


/**
 * @brief iSCSI SCSI standard inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * cleared.
 */
typedef struct __attribute__((packed)) iscsi_scsi_std_inquiry_data_packet {
    /// iSCSI SCSI basic inquiry data packet.
    iscsi_scsi_basic_inquiry_data_packet basic_inquiry;

    /// PROTECT, 3PC, TPGS, ACC and SCCS.
    uint8_t tpgs_flags;

    /// MULTIP, VS and ENCSERV.
    int8_t services_flags;

    /// Flags.
    int8_t flags;

    /// Vendor identification.
    uint8_t vendor_id[8];

    /// Product identification.
    uint8_t product_id[16];

    /// Product revision level.
    uint8_t product_rev_level[4];
} iscsi_scsi_std_inquiry_data_packet;


/// iSCSI SCSI Extended Inquiry Data vendor specific.
#define ISCSI_SCSI_EXT_INQUIRY_DATA_VENDOR_SPEC_ID "UNI FREIBURG DNBD3"


/// iSCSI SCSI Extended Inquiry Data version descriptor: iSCSI (no version claimed).
#define ISCSI_SCSI_EXT_INQUIRY_DATA_VERSION_DESC_ISCSI_NO_VERSION 0x0960

/// iSCSI SCSI Extended Inquiry Data version descriptor: SPC3 (no version claimed).
#define ISCSI_SCSI_EXT_INQUIRY_DATA_VERSION_DESC_SPC3_NO_VERSION  0x0300

/// iSCSI SCSI Extended Inquiry Data version descriptor: SBC2 (no version claimed).
#define ISCSI_SCSI_EXT_INQUIRY_DATA_VERSION_DESC_SBC2_NO_VERSION  0x0320

/// iSCSI SCSI Extended Inquiry Data version descriptor: SAM2 (no version claimed).
#define ISCSI_SCSI_EXT_INQUIRY_DATA_VERSION_DESC_SAM2_NO_VERSION  0x0040


/**
 * @brief iSCSI SCSI extended inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * cleared.
 */
typedef struct __attribute__((packed)) iscsi_scsi_ext_inquiry_data_packet {
    /// iSCSI SCSI standard inquiry data packet.
    iscsi_scsi_std_inquiry_data_packet std_inquiry;

    /// Vendor specific.
    uint8_t vendor_spec[20];

    /// Flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved;

    /// Version descriptors.
    uint16_t version_desc[8];

    /// Reserved for future usage (always MUST be 0).
    uint64_t reserved2[2];

    /// Reserved for future usage (always MUST be 0).
    uint32_t reserved3;

    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved4;
} iscsi_scsi_ext_inquiry_data_packet;


/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Direct access device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_DIRECT    0x00

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Sequential access device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_SEQ       0x01

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Printer device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_PRINTER   0x02

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Processor device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_PROCESSOR 0x03

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Write once device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_WORM      0x04

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Read only direct access (e.g. CD-ROM) device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_RO_DIRECT 0x05

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Scanner device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_SCANNER   0x06

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Optical memory device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_OPTICAL   0x07

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Medium changer device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_CHANGER   0x08

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Communications device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_COMM      0x09

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Unknown or no device.
#define	ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_UNKNOWN   0x1F

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: First bit of the five bits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT 0

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Last bit of the five bits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT  ((ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT) + 5 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Extracts the peripheral device type bits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_GET_PERIPHERAL_TYPE(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral type: Stores into the peripheral device type bits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PUT_PERIPHERAL_TYPE(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: The specified peripheral device type is currently connected to this logical unit, or connection state could not be determined.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_POSSIBLE    0x0

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: The target is capable of supporting the specified peripheral device type on this logical unit, but not connected.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_SUPPORTED   0x1

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: The target is not capable of supporting a physical device on this logical unit.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_NEVER       0x3

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: Vendor specific.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_VENDOR_UNIQ 0x4

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: First bit of the three bits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT   5

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: Last bit of the three bits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT    ((ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT) + 3 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_MASK        (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: Extracts the peripheral device identifier bits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_GET_PERIPHERAL_ID(x)      (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data peripheral identifier: Stores into the peripheral device identifier bits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PUT_PERIPHERAL_ID(x)      (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))


/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Supported VPD pages.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SUPPORTED_VPD_PAGES      0x00

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Unit serial number.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_UNIT_SERIAL_NUMBER       0x80

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Device identification.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_DEVICE_ID                0x83

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Software interface identification.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SOFTWARE_IFACE_ID        0x84

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Management network addresses.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_MANAGEMENT_NETWORK_ADDRS 0x85

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Extended inquiry data.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_EXTENDED_INQUIRY_DATA    0x86

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Mode page policy.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_MODE_PAGE_POLICY         0x87

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: SCSI ports.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SCSI_PORTS               0x88

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Block limits.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_LIMITS             0xB0

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Block device characteristics.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_DEV_CHARS          0xB1

/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Thin provisioning.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_THIN_PROVISION           0xB2


/// iSCSI SCSI Vital Product Data (VPD) Page Inquiry Data page code: Maximum serial string length in bytes.
#define ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_MAX_SERIAL_STRING        32


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_inquiry_data_packet {
    /// Peripheral device type and qualifier.
    uint8_t peripheral_type_id;

    /// Page code.
    uint8_t page_code;

    /// Allocation length in bytes.
    uint16_t alloc_len;

    /// Parameters.
    uint8_t params[0];
} iscsi_scsi_vpd_page_inquiry_data_packet;


/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: iSCSI.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_ISCSI     0x05

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: First bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT 0

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: Last bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT  ((ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: Extracts the protocol identifier bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_GET_PROTOCOL_ID(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: Stores into the protocol identifier bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: Binary encoding.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY       0x01

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: ASCII encoding.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_ASCII        0x02

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: UTF-8 encoding.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8         0x03

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: First bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT    4

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: Last bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT     ((ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT) + 8 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_MASK         (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: Extracts the protocol identifier bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_GET_CODE_SET(x)       (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: Stores into the protocol identifier bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(x)       (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT))


/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: Vendor specific.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_VENDOR_SPEC        0x00

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: T10 vendor identifier.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_T10_VENDOR_ID      0x01

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: EUI64.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_EUI64              0x02

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: NAA.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_NAA                0x03

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: Relative target port.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_REL_TARGET_PORT    0x04

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: Target port group.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_TARGET_PORT_GROUP  0x05

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: Logical unit group.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LOGICAL_UNIT_GROUP 0x06

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: MD5 logical unit.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_MD5_LOGICAL_UNIT   0x07

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: SCSI name.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME          0x08

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: First bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT          0

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: Last bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LAST_BIT           ((ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_MASK               (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: Extracts the type bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_GET_TYPE(x)             (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags type: Stores into the type bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(x)             (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags association: Logical unit.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT      0x0

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags association: Target port.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT       0x1

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags association: Target device.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_DEVICE     0x2

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags association: First bit of the two bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT         4

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags association: Last bit of the two bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LAST_BIT          ((ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT) + 6 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags association: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_MASK              (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags association: Extracts the association bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_GET_ASSOC(x)            (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags association: Stores into the association bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(x)            (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data flags: Protocol Identifier Valid (PIV).
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV                     (1 << 7)


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_design_desc_inquiry_data_packet {
    /// Protocol identifier and code set.
    uint8_t protocol_id_code_set;

    /// Flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved;

    /// Length in bytes.
    uint8_t len;

    /// Designation descriptor.
    uint8_t desc[0];
} iscsi_scsi_vpd_page_design_desc_inquiry_data_packet;


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor IEEE NAA Extended Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet {
    /// IEEE NAA Extended.
    uint64_t ieee_naa_ext;
} iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet;


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor T10 Vendor ID Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet {
    /// Vendor identification.
    uint8_t vendor_id[8];

    /// Product identification.
    uint8_t product_id[16];

    /// Unit serial number.
    uint8_t unit_serial_num[32];
} iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet;


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Relative Target Port Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet {
    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved;

    /// Port index.
    uint16_t index;
} iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet;


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Target Port Group Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet {
    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved;

    /// Port group index.
    uint16_t index;
} iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet;


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Logical Unit Group Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet {
    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved;

    /// Logical unit identifier.
    uint16_t id;
} iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet;


/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Direct access device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_DIRECT    0x00

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Sequential access device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_SEQ       0x01

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Printer device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_PRINTER   0x02

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Processor device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_PROCESSOR 0x03

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Write once device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_WORM      0x04

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Read only direct access (e.g. CD-ROM) device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_RO_DIRECT 0x05

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Scanner device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_SCANNER   0x06

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Optical memory device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_OPTICAL   0x07

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Medium changer device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_CHANGER   0x08

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Communications device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_COMM      0x09

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Unknown or no device.
#define	ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_UNKNOWN   0x1F

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: First bit of the five bits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT 0

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Last bit of the five bits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT  ((ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT) + 5 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Extracts the peripheral device type bits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_GET_PERIPHERAL_TYPE(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral type: Stores into the peripheral device type bits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PUT_PERIPHERAL_TYPE(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: The specified peripheral device type is currently connected to this logical unit, or connection state could not be determined.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_POSSIBLE    0x0

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: The target is capable of supporting the specified peripheral device type on this logical unit, but not connected.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_SUPPORTED   0x1

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: The target is not capable of supporting a physical device on this logical unit.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_NEVER       0x3

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: Vendor specific.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_VENDOR_UNIQ 0x4

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: First bit of the three bits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT   5

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: Last bit of the three bits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT    ((ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT) + 3 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_MASK        (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: Extracts the peripheral device identifier bits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_GET_PERIPHERAL_ID(x)      (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data peripheral identifier: Stores into the peripheral device identifier bits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PUT_PERIPHERAL_ID(x)      (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PERIPHERAL_ID_LAST_BIT))


/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Supported VPD pages.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_SUPPORTED_VPD_PAGES      0x00

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Unit serial number.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_UNIT_SERIAL_NUMBER       0x80

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Device identification.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_DEVICE_ID                0x83

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Software interface identification.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_SOFTWARE_IFACE_ID        0x84

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Management network addresses.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_MANAGEMENT_NETWORK_ADDRS 0x85

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Extended inquiry data.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_EXTENDED_INQUIRY_DATA    0x86

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Mode page policy.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_MODE_PAGE_POLICY         0x87

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: SCSI ports.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_SCSI_PORTS               0x88

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Block limits.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_BLOCK_LIMITS             0xB0

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Block device characteristics.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_BLOCK_DEV_CHARS          0xB1

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data page code: Thin provisioning.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_PAGE_CODE_THIN_PROVISION           0xB2


/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data check flags: RFTG check.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_CHECK_FLAGS_RFTG_CHK (1 << 0)

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data check flags: APTG check.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_CHECK_FLAGS_APTG_CHK (1 << 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data check flags: GRD check.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_CHECK_FLAGS_GRD_CHK  (1 << 2)


/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data support flags: SIMP support.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_SUPPORT_FLAGS_SIMPSUP   (1 << 0)

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data support flags: ORD support.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_SUPPORT_FLAGS_ORDSUP    (1 << 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data support flags: HEAD support.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_SUPPORT_FLAGS_HEADSUP   (1 << 2)

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data support flags: PRIOR support.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_SUPPORT_FLAGS_PRIOR_SUP (1 << 3)

/// iSCSI SCSI Vital Product Data (VPD) Page Extended Inquiry Data support flags: GROUP support.
#define ISCSI_SCSI_VPD_PAGE_EXT_INQUIRY_DATA_SUPPORT_FLAGS_GROUP_SUP (1 << 4)


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Extended Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_ext_inquiry_data_packet {
    /// Peripheral device type and qualifier.
    uint8_t peripheral_type_id;

    /// Page code.
    uint8_t page_code;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved;

    /// Page length in bytes.
    uint8_t page_len;

    /// Check flags.
    int8_t check_flags;

    /// Support flags.
    int8_t support_flags;

    /// More support flags.
    int8_t support_flags_2;

    /// LUICLR.
    uint8_t luiclr;

    /// CBCS.
    uint8_t cbcs;

    /// Micro DL.
    uint8_t micro_dl;

    /// Reserved for future usage (always MUST be 0).
    uint64_t reserved2[6];

    /// Reserved for future usage (always MUST be 0).
    uint32_t reserved3;

    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved4;
} iscsi_scsi_vpd_page_ext_inquiry_data_packet;


/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data policy page code: First bit of the six bits.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_FIRST_BIT 0

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data policy page code: Last bit of the six bits.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_LAST_BIT  ((ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_FIRST_BIT) + 6 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data policy page code: Bit mask.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data policy page code: Extracts the policy page code bits.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_GET_POLICY_PAGE_CODE(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data policy page code: Stores into the policy page code bits.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_PUT_POLICY_PAGE_CODE(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_POLICY_PAGE_CODE_LAST_BIT))


/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data flags mode page policy: First bit of the two bits.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_FIRST_BIT 0

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data flags mode page policy: Last bit of the two bits.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_LAST_BIT  ((ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_FIRST_BIT) + 2 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data flags mode page policy: Bit mask.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_FIRST_BIT, ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data flags mode page policy: Extracts the mode page policy bits.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_GET_MODE_PAGE_POLICY(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_FIRST_BIT, ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data flags mode page policy: Stores into the mode page policy bits.
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_PUT_MODE_PAGE_POLICY(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_FIRST_BIT, ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MODE_PAGE_POLICY_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry Data flag: Multiple Logical Units Share (MLUS).
#define ISCSI_SCSI_VPD_MODE_PAGE_POLICY_DESC_INQUIRY_DATA_FLAGS_MLUS                        (1 << 7)


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Mode Page Policy Descriptor Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_mode_page_policy_desc_inquiry_data_packet {
    /// Policy page code.
    uint8_t page_code;

    /// Policy sub page code.
    uint8_t sub_page_code;

    /// Policy flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved;
} iscsi_scsi_vpd_mode_page_policy_desc_inquiry_data_packet;


/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data protocol identifier: iSCSI.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_ISCSI     0x05

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data protocol identifier: First bit of the four bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT 0

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data protocol identifier: Last bit of the four bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT  ((ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data protocol identifier: Bit mask.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data protocol identifier: Extracts the protocol identifier bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_GET_PROTOCOL_ID(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data protocol identifier: Stores into the protocol identifier bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data code set: Binary encoding.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY       0x01

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data code set: ASCII encoding.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_ASCII        0x02

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data code set: UTF-8 encoding.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8         0x03

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data code set: First bit of the four bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT    4

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data code set: Last bit of the four bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT     ((ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT) + 8 - 1)

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data code set: Bit mask.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_MASK         (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data code set: Extracts the protocol identifier bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_GET_CODE_SET(x)       (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data code set: Stores into the protocol identifier bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(x)       (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT))


/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: Vendor specific.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_VENDOR_SPEC        0x00

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: T10 vendor identifier.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_T10_VENDOR_ID      0x01

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: EUI64.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_EUI64              0x02

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: NAA.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_NAA                0x03

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: Relative target port.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_REL_TARGET_PORT    0x04

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: Target port group.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_TARGET_PORT_GROUP  0x05

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: Logical unit group.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LOGICAL_UNIT_GROUP 0x06

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: MD5 logical unit.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_MD5_LOGICAL_UNIT   0x07

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: SCSI name.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME          0x08

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: First bit of the four bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT          0

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: Last bit of the four bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LAST_BIT           ((ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: Bit mask.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_MASK               (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: Extracts the type bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_GET_TYPE(x)             (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags type: Stores into the type bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(x)             (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags association: Logical unit.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT      0x0

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags association: Target port.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT       0x1

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags association: Target device.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_DEVICE     0x2

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags association: First bit of the two bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT         4

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags association: Last bit of the two bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LAST_BIT          ((ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT) + 6 - 1)

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags association: Bit mask.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_MASK              (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags association: Extracts the association bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_GET_ASSOC(x)            (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags association: Stores into the association bits.
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(x)            (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_FIRST_BIT, ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data flags: Protocol Identifier Valid (PIV).
#define ISCSI_SCSI_VPD_SCSI_TARGET_PORT_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV                     (1 << 7)


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) SCSI Target Port Designation Descriptor Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_scsi_target_port_design_dec_inquiry_data_packet {
    /// Protocol identifier and code set.
    uint8_t protocol_id_code_set;

    /// Flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved;

    /// Length in bytes.
    uint8_t len;

    /// Designator.
    uint8_t design[0];
} iscsi_scsi_vpd_scsi_target_port_design_dec_inquiry_data_packet;


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) SCSI Port Designation Descriptor Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_scsi_port_design_dec_inquiry_data_packet {
    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved;

    /// Relative port identifier.
    uint16_t rel_port_id;

    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved2;

    /// Initiator port length in bytes.
    uint16_t init_port_len;

    /// Initiator port identifier.
    uint16_t init_port_id[0];

    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved3;

    /// SCSI Target Port Designation Descriptor length in bytes.
    uint16_t target_desc_len;

    /// SCSI Target Port Designation Descriptor.
    iscsi_scsi_vpd_scsi_target_port_design_dec_inquiry_data_packet target_desc[0];
} iscsi_scsi_vpd_scsi_port_design_dec_inquiry_data_packet;


/**
 * @brief iSCSI SCSI command INQUIRY Vital Product Data (VPD) SCSI Port Designation Descriptor entry fill.
 *
 * This structure is used by iterating through
 * all iSCSI device ports in order to fill in
 * the INQUIRY Vital Product Data (VPD) SCSI
 * Port Designation Descriptor structure.
 */
typedef struct iscsi_scsi_emu_primary_inquiry_ports_fill {
    /// Pointer to current Vital Product Data (VPD) SCSI Port Designation Descriptor entry packet data.
    iscsi_scsi_vpd_scsi_port_design_dec_inquiry_data_packet *port_entry;

    /// Total length of Vital Product Data (VPD) SCSI Port Designation Descriptor entry packet data in bytes.
    uint alloc_len;

    /// Total remaining allocation length for packet data in bytes.
    uint len;
} iscsi_scsi_emu_primary_inquiry_ports_fill;


/// iSCSI SCSI Vital Product Data (VPD) Page Block Limits Inquiry data UNMAP Granularity Alignment: First bit of the thirty one bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_FIRST_BIT 0L

/// iSCSI SCSI Vital Product Data (VPD) Page Block Limits Inquiry data UNMAP Granularity Alignment: Last bit of the thirty one bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_LAST_BIT  ((ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_FIRST_BIT) + 31L - 1L)

/// iSCSI SCSI Vital Product Data (VPD) Page Block Limits Inquiry data UNMAP Granularity Alignment: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Limits Inquiry data UNMAP Granularity Alignment: Extracts the UNMAP granularity alignment bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_GET_UNMAP_GRANULARITY_ALIGN(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Limits Inquiry data UNMAP Granularity Alignment: Stores into the UNMAP granularity alignment bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_PUT_UNMAP_GRANULARITY_ALIGN(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Limits Inquiry data UNMAP Granularity Alignment: UNMAP Granularity Alignment Valid (UGVALID).
#define ISCSI_SCSI_VPD_PAGE_BLOCK_LIMITS_INQUIRY_DATA_UNMAP_GRANULARITY_ALIGN_UGAVALID  (1L << 31L)


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Block Limits Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_block_limits_inquiry_data_packet {
    /// Flags.
    int8_t flags;

    /// Maximum COMPARE AND WRITE length in logical blocks.
    uint8_t max_cmp_write_len;

    /// Optimal transfer length granularity in logical blocks.
    uint16_t optimal_granularity_xfer_len;

    /// Maximum transfer length in logical blocks.
    uint32_t max_xfer_len;

    /// Optimal transfer length in logical blocks.
    uint32_t optimal_xfer_len;

    /// Maximum prefetch length in logical blocks.
    uint32_t max_prefetch_len;

    /// Maximum UNMAP LBA count in LBAs.
    uint32_t max_unmap_lba_cnt;

    /// Maximum UNMAP block descriptor count in block descriptors.
    uint32_t max_unmap_block_desc_cnt;

    /// Optimal UNMAP granularity in logical blocks.
    uint32_t optimal_unmap_granularity;

    /// UNMAP granularity alignment (first LBA) and UGAVALID bit.
    uint32_t unmap_granularity_align_ugavalid;

    /// Maximum WRITE SAME length in logical blocks.
    uint64_t max_write_same_len;

    /// Reserved for future usage (always MUST be 0).
    uint64_t reserved[2];

    /// Reserved for future usage (always MUST be 0).
    uint32_t reserved2;
} iscsi_scsi_vpd_page_block_limits_inquiry_data_packet;

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data medium rotation rate: Medium rotation rate is not reported.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_MEDIUM_ROTATION_RATE_NOT_REPORTED 0x0000

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data medium rotation rate: Non-rotating medium (e.g., solid state).
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_MEDIUM_ROTATION_RATE_NONE         0x0001


/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data product type: Not indicated.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_PRODUCT_TYPE_NOT_INDICATED       0x00

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data product type: Not specified first value.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_PRODUCT_TYPE_NOT_SPECIFIED_FIRST 0xF0

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data product type: Not specified last value.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_PRODUCT_TYPE_NOT_SPECIFIED_LAST  0xFF


/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: Nominal form factor is not reported.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_NOT_REPORTED 0x0

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: 5.25 inch.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_525_INCH     0x1

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: 3.5 inch.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_35_INCH      0x2

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: 2.5 inch.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_25_INCH      0x3

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: 1.8 inch.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_18_INCH      0x4

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: Less than 1.8 inch.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_LT_18_INCH   0x5

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: First bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_FIRST_BIT    0

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: Last bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_LAST_BIT     ((ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_MASK         (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: Extracts the nominal form factor bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_GET_NOMINAL_FORM_FACTOR(x)       (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags nominal form factor: Stores into the nominal form factor bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_PUT_NOMINAL_FORM_FACTOR(x)       (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Cryptographic Erase REQuired (WACEREQ): First bit of the two bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_FIRST_BIT                4

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Cryptographic Erase REQuired (WACEREQ): Last bit of the two bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_LAST_BIT                 ((ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_FIRST_BIT) + 6 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Cryptographic Erase REQuired (WACEREQ): Bit mask.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_MASK                     (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Cryptographic Erase REQuired (WACEREQ): Extracts the Write After Block Erase REQuired (WACEREQ) bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_GET_WACEREQ(x)                   (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Cryptographic Erase REQuired (WACEREQ): Stores into the Write After Block Erase REQuired (WACEREQ) bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_PUT_WACEREQ(x)                   (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WACEREQ_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Block Erase REQuired (WABEREQ): First bit of the two bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_FIRST_BIT                6

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Block Erase REQuired (WABEREQ): Last bit of the two bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_LAST_BIT                 ((ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_FIRST_BIT) + 8 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Block Erase REQuired (WABEREQ): Bit mask.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_MASK                     (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Block Erase REQuired (WABEREQ): Extracts the Write After Block Erase REQuired (WABEREQ) bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_GET_WABEREQ(x)                   (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data flags Write After Block Erase REQuired (WABEREQ): Stores into the Write After Block Erase REQuired (WABEREQ) bits.
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_PUT_WABEREQ(x)                   (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_WABEREQ_LAST_BIT))


/// iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data support flags: Verify Byte Check Unmapped LBA Supported (VBULS).
#define ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_SUPPORT_FLAGS_VBULS (1 << 0)


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Block Device Characteristics Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet {
    /// Medium rotation rate.
    uint16_t medium_rotation_rate;

    /// Product type.
    uint8_t product_type;

    /// Flags.
    int8_t flags;

    /// Support flags.
    uint8_t support_flags;

    /// Reserved for future usage (always MUST be 0).
    uint64_t reserved[6];

    /// Reserved for future usage (always MUST be 0).
    uint32_t reserved2;

    /// Reserved for future usage (always MUST be 0).
    uint16_t reserved3;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved4;
} iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet;


/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data flags: Descriptor Present (DP).
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_FLAGS_DP      (1 << 0)

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data flags: Anchor Supported (ANC_SUP).
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_FLAGS_ANC_SUP (1 << 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data flags: Logical Block Provisioning Read Zeros (LBPRZ).
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_FLAGS_LBPRZ   (1 << 2)

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data flags: Logical Block Provisioning WRITE SAME(10) (LBPWS10).
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_FLAGS_LBPWS10 (1 << 5)

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data flags: Logical Block Provisioning WRITE SAME (LBPWS).
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_FLAGS_LBPWS   (1 << 6)

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data flags: Logical Block Provisioning UNMAP (LBPU).
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_FLAGS_LBPU    (1 << 7)


/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data provision type: The device server does NOT report a provisioning type.
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_PROVISIONING_NOT_REPORTED 0x0

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data provision type: The logical unit is resource provisioned (see SBC3).
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_RESOURCE_PROVISIONING     0x1

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data provision type: The logical unit is thin provisioned (see SBC3).
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_THIN_PROVISIONING         0x2

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data provision type: First bit of the three bits.
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_FIRST_BIT                 0

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data provision type: Last bit of the three bits.
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_LAST_BIT                  ((ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_FIRST_BIT) + 3 - 1)

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data provision type: Bit mask.
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_MASK                      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data provision type: Extracts the provision type bits.
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_GET_PROVISION_TYPE(x)                    (ISCSI_BITS_GET((x), ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_LAST_BIT))

/// iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data provision type: Stores into the provision type bits.
#define ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PUT_PROVISION_TYPE(x)                    (ISCSI_BITS_PUT((x), ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_FIRST_BIT, ISCSI_SCSI_VPD_PAGE_THIN_PROVISION_INQUIRY_DATA_PROVISION_TYPE_LAST_BIT))


/**
 * @brief iSCSI SCSI Vital Product Data (VPD) Page Thin Provision Inquiry data packet.
 *
 * This structure is used by the SCSI INQUIRY command
 * in order to fill in the result if the EVPD bit is
 * set.
 */
typedef struct __attribute__((packed)) iscsi_scsi_vpd_page_thin_provision_inquiry_data_packet {
    /// Threshold exponent.
    uint8_t threshold_exponent;

    /// Flags.
    int8_t flags;

    /// Provision type.
    uint8_t provision_type;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved;

    /// Provision group descriptors.
    uint8_t provision_group_desc[0];
} iscsi_scsi_vpd_page_thin_provision_inquiry_data_packet;


/**
 * @brief iSCSI SCSI Sense Event data packet.
 *
 * For a SCSI event, this data accompanies the report in the data
 * segment and identifies the condition.
 *
 * For an iSCSI event, additional vendor-unique data MAY accompany the
 * Async event. Initiators MAY ignore the data when not understood,
 * while processing the rest of the PDU.
 *
 * If the DataSegmentLength is not 0, the format of the DataSegment is
 * as follows:
 */
typedef struct __attribute__((packed)) iscsi_scsi_sense_event_data_packet {
    /**
     * @brief SenseLength.
     *
     * This is the length of Sense Data. When the Sense Data field is empty
     * (e.g., the event is not a SCSI event), SenseLength is 0.
     */
    uint16_t sense_len;

    /// Sense Data.
    uint16_t sense_data[0];

    /// iSCSI Event Data.
    uint16_t event_data[0];
} iscsi_scsi_sense_event_data_packet;


/// iSCSI SCSI sense data response code: Current format.
#define ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_CURRENT_FMT  0x70

/// iSCSI SCSI sense data response code: Deferred format.
#define ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_DEFERRED_FMT 0x71

/// iSCSI SCSI sense data response code: First bit of the seven bits.
#define ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_FIRST_BIT    0

/// iSCSI SCSI sense data response code: Last bit of the seven bits.
#define ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_LAST_BIT     ((ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_FIRST_BIT) + 7 - 1)

/// iSCSI SCSI sense data response code: Bit mask.
#define ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_MASK         (ISCSI_BITS_GET_MASK(ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_LAST_BIT))

/// iSCSI SCSI sense data response code: Extracts the response code bits.
#define ISCSI_SCSI_SENSE_DATA_GET_RESPONSE_CODE(x)       (ISCSI_BITS_GET((x), ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_LAST_BIT))

/// iSCSI SCSI sense data response code: Stores into the response code bits.
#define ISCSI_SCSI_SENSE_DATA_PUT_RESPONSE_CODE(x)       (ISCSI_BITS_PUT((x), ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_LAST_BIT))

/// iSCSI SCSI sense data response code: Valid.
#define ISCSI_SCSI_SENSE_DATA_RESPONSE_CODE_VALID        (1 << 7)


/// iSCSI SCSI sense data sense key: First bit of the four bits.
#define ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FIRST_BIT   0

/// iSCSI SCSI sense data sense key: Last bit of the four bits.
#define ISCSI_SCSI_SENSE_DATA_SENSE_KEY_LAST_BIT   ((ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI sense data sense key: Bit mask.
#define ISCSI_SCSI_SENSE_DATA_SENSE_KEY_MASK (ISCSI_BITS_GET_MASK(ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_SENSE_KEY_LAST_BIT))

/// iSCSI SCSI sense data sense key: Extracts the Sense Key (SK) bits.
#define ISCSI_SCSI_SENSE_DATA_GET_SENSE_KEY(x) (ISCSI_BITS_GET((x), ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_SENSE_KEY_LAST_BIT))

/// iSCSI SCSI sense data sense key: Stores into the Sense Key (SK) bits.
#define ISCSI_SCSI_SENSE_DATA_PUT_SENSE_KEY(x) (ISCSI_BITS_PUT((x), ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_SENSE_KEY_LAST_BIT))

// iSCSI SCSI sense data sense key flags: ILI.
#define ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FLAGS_ILI      (1 << 5)

// iSCSI SCSI sense data sense key flags: EOM.
#define ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FLAGS_EOM      (1 << 6)

// iSCSI SCSI sense data sense key flags: FILEMARK.
#define ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FLAGS_FILEMARK (1 << 7)


/**
 * @brief iSCSI SCSI basic sense data packet data.
 *
 * This is the basic SCSI sense data shared by
 * all SCSI sense data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_sense_data_packet {
    /// Response code.
    int8_t response_code;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved;

    /// Sense key and flags.
    int8_t sense_key_flags;

    /// Information.
    uint32_t info;

    /// Additional sense length in bytes.
    uint8_t add_len;
} iscsi_scsi_sense_data_packet;

/// iSCSI SCSI maximum sense data length.
#define ISCSI_SCSI_MAX_SENSE_DATA_LEN (sizeof(struct iscsi_scsi_sense_data_packet) + 255U)


/// iSCSI SCSI sense data check condition sense key specific: First bit of the six bits.
#define ISCSI_SCSI_SENSE_DATA_CHECK_COND_SENSE_KEY_SPEC_FIRST_BIT   0

/// iSCSI SCSI sense data check condition sense key specific: Last bit of the six bits.
#define ISCSI_SCSI_SENSE_DATA_CHECK_COND_SENSE_KEY_SPEC_LAST_BIT   ((ISCSI_SCSI_SENSE_DATA_CHECK_COND_SENSE_KEY_SPEC_FIRST_BIT) + 6 - 1)

/// iSCSI SCSI sense data check condition sense key specific: Bit mask.
#define ISCSI_SCSI_SENSE_DATA_CHECK_COND_SENSE_KEY_SPEC_MASK       (ISCSI_BITS_GET_MASK(ISCSI_SCSI_SENSE_DATA_CHECK_COND_SENSE_KEY_SPEC_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_CHECK_COND_SENSE_KEY_SPEC_LAST_BIT))

/// iSCSI SCSI sense data check condition sense key specific: Extracts the sense key specific bits.
#define ISCSI_SCSI_SENSE_DATA_CHECK_COND_GET_SENSE_KEY_SPEC(x)     (ISCSI_BITS_GET((x), ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_SENSE_KEY_LAST_BIT))

/// iSCSI SCSI sense data check condition sense key specific: Stores into the sense key specific bits.
#define ISCSI_SCSI_SENSE_DATA_CHECK_COND_PUT_SENSE_KEY_SPEC(x)     (ISCSI_BITS_PUT((x), ISCSI_SCSI_SENSE_DATA_SENSE_KEY_FIRST_BIT, ISCSI_SCSI_SENSE_DATA_SENSE_KEY_LAST_BIT))

// iSCSI SCSI sense data check condition sense key specific flags: SKSV.
#define ISCSI_SCSI_SENSE_DATA_CHECK_COND_SENSE_KEY_SPEC_FLAGS_SKSV (1 << 7)


/**
 * @brief iSCSI SCSI sense data check condition packet data.
 *
 * This is the additional SCSI sense data used by
 * the check condition status code.
 */
typedef struct __attribute__((packed)) iscsi_scsi_sense_data_check_cond_packet {
    /// Basic SCSI sense data packet.
    iscsi_scsi_sense_data_packet sense_data;

    /// Information.
    uint32_t cmd_spec_info;

    /// Additional Sense Code (ASC).
    uint8_t asc;

    /// Additional Sense Code Qualifier (ASCQ).
    uint8_t ascq;

    /// Field replaceable unit code.
    uint8_t field_rep_unit_code;

    /// Sense key specific.
    uint8_t sense_key_spec_flags;

    /// Sense key specific.
    uint16_t sense_key_spec;
} iscsi_scsi_sense_data_check_cond_packet;


/**
 * @brief iSCSI SCSI command READ CAPACITY(10) parameter data packet data.
 *
 * This returns the Logical Block Address (LBA)
 * and block length in bytes.
 */
typedef struct __attribute__((packed)) iscsi_scsi_read_capacity_10_parameter_data_packet {
    /// Last valid Logical Block Address (LBA).
    uint32_t lba;

    /// Block length in bytes.
    uint32_t block_len;
} iscsi_scsi_read_capacity_10_parameter_data_packet;


/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data flags: Protection enabled (PROT_EN).
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROT_EN                 (1 << 0)

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection type flags: First bit of the three bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_FIRST_BIT  1

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection type flags: Last bit of the three bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_LAST_BIT   ((ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_FIRST_BIT) + 3 - 1)

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection type flags: Bit mask.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_MASK       (ISCSI_BITS_GET_MASK(ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection type flags: Extracts the protection type bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_GET_PROTECT_TYPE(x)     (ISCSI_BITS_GET((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection type flags: Stores into the protection type bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PUT_PROTECT_TYPE(x)     (ISCSI_BITS_PUT((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PROTECT_TYPE_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data RC basis flags: First bit of the two bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_FIRST_BIT      4

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data RC basis flags: Last bit of the two bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_LAST_BIT       ((ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_FIRST_BIT) + 2 - 1)

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data RC basis flags: Bit mask.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_MASK           (ISCSI_BITS_GET_MASK(ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data RC basis flags: Extracts the RC basis bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_GET_RC_BASIS(x)         (ISCSI_BITS_GET((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data RC basis flags: Stores into the RC basis bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_PUT_RC_BASIS(x)         (ISCSI_BITS_PUT((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_FLAGS_RC_BASIS_LAST_BIT))


/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data logical blocks per physical block exponent: First bit of the four bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_FIRST_BIT 0

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data logical blocks per physical block exponent: Last bit of the four bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_LAST_BIT ((ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data logical blocks per physical block exponent: Bit mask.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_MASK     (ISCSI_BITS_GET_MASK(ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data logical blocks per physical block exponent: Extracts the logical blocks per physical block bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_GET_LBPPB_EXPONENT(x)   (ISCSI_BITS_GET((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data logical blocks per physical block exponent: Stores into the logical blocks per physical block bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_PUT_LBPPB_EXPONENT(x)   (ISCSI_BITS_PUT((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection information intervals exponent: First bit of the four bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_FIRST_BIT  4

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection information intervals exponent: Last bit of the four bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_LAST_BIT   ((ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection information intervals exponent: Bit mask.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_MASK       (ISCSI_BITS_GET_MASK(ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection information intervals exponent: Extracts the protection information intervals bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_GET_P_I_EXPONENT(x)     (ISCSI_BITS_GET((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter data protection information intervals exponent: Stores into the protection information intervals bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_PUT_P_I_EXPONENT(x)     (ISCSI_BITS_PUT((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_P_I_EXPONENT_LAST_BIT))


/// iSCSI SCSI command SERVICE ACTION IN(16) parameter logical block provisioning Lowest Aligned Logical Block Address (LALBA): First bit of the fourteen bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_FIRST_BIT 0

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter logical block provisioning Lowest Aligned Logical Block Address (LALBA): Last bit of the fourteen bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_LAST_BIT  ((ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_FIRST_BIT) + 14 - 1)

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter logical block provisioning Lowest Aligned Logical Block Address (LALBA): Bit mask.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_MASK      (ISCSI_BITS_GET_MASK(ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter logical block provisioning Lowest Aligned Logical Block Address (LALBA): Extracts the Lowest Aligned Logical Block Address (LALBA) bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_GET_LABLA(x)    (ISCSI_BITS_GET((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter logical block provisioning Lowest Aligned Logical Block Address (LALBA): Stores into the Lowest Aligned Logical Block Address (LALBA) bits.
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_PUT_LABLA(x)    (ISCSI_BITS_PUT((x), ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_FIRST_BIT, ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LALBA_LAST_BIT))

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter logical block provisioning: Logical Block Provisioning Read Zeros (LBPRZ).
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPRZ           (1 << 14)

/// iSCSI SCSI command SERVICE ACTION IN(16) parameter logical block provisioning: Logical Block Provisioning Management Enabled (LBPME).
#define ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPME           (1 << 15)


/**
 * @brief iSCSI SCSI command SERVICE ACTION IN(16) parameter data packet data.
 *
 * This returns the Logical Block Address (LBA),
 * block length in bytes and LBP information.
 */
typedef struct __attribute__((packed)) iscsi_scsi_service_action_in_16_parameter_data_packet {
    /// Last valid Logical Block Address (LBA).
    uint64_t lba;

    /// Block length in bytes.
    uint32_t block_len;

    /// Flags: RC_BASIS, P_TYPE and PROT_EN.
    int8_t flags;

    /// P_I_EXPONENT and logical blocks per physical block exponent.
    uint8_t exponents;

    /// Logical Block Provisioning Management Enabled (LBPME), Logical Block Provisioning Read Zeros (LBPRZ) and Lowest Aligned Logical Block Address (LALBA).
    uint16_t lbp_lalba;

    /// Reserved for future usage (always MUST be 0 for now).
    uint64_t reserved[2];
} iscsi_scsi_service_action_in_16_parameter_data_packet;


/**
 * @brief iSCSI SCSI command REPORT LUNS parameter data LUN list packet data.
 *
 * This returns the number of entries in the
 * LUN list in bytes.
 */
typedef struct __attribute__((packed)) iscsi_scsi_report_luns_parameter_data_lun_list_packet {
    /// Number of LUN's following this packet in bytes.
    uint32_t lun_list_len;

    /// Reserved for future usage (always MUST be 0 for now).
    uint32_t reserved;
} iscsi_scsi_report_luns_parameter_data_lun_list_packet;


/**
 * @brief iSCSI SCSI command REPORT LUNS parameter data LUN entry packet data.
 *
 * This returns a single LUN entry of the
 * LUN list.
 */
typedef struct __attribute__((packed)) iscsi_scsi_report_luns_parameter_data_lun_entry_packet {
    /// Logical Unit Number (LUN).
    uint64_t lun;
} iscsi_scsi_report_luns_parameter_data_lun_entry_packet;


/**
 * @brief iSCSI SCSI command REPORT LUNS parameter data LUN entry fill.
 *
 * This structure is used by iterating through
 * all iSCSI LUNs in order to fill in the
 * REPORT LUNS parameter data structure.
 */
typedef struct iscsi_scsi_emu_primary_report_luns_fill {
    /// Pointer to LUN list packet data.
    iscsi_scsi_report_luns_parameter_data_lun_list_packet *lun_list;

    /// Pointer to current LUN entry packet data.
    iscsi_scsi_report_luns_parameter_data_lun_entry_packet *lun_entry;

    /// Total length of LUN entry packet data in bytes.
    uint32_t len;

    /// Total remaining allocation length for packet data in bytes.
    uint alloc_len;

    /// Select report.
    uint select_report;
} iscsi_scsi_emu_primary_report_luns_fill;


/**
 * @brief iSCSI SCSI command MODE SELECT(6) parameter list packet data.
 *
 * This returns 32-bit vendor specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_select_6_parameter_list_packet {
    /// Vendor specific data.
    uint32_t vendor_data;
} iscsi_scsi_mode_select_6_parameter_list_packet;


/**
 * @brief iSCSI SCSI command MODE SELECT(10) parameter list packet data.
 *
 * This returns 64-bit vendor specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_select_10_parameter_list_packet {
    /// Vendor specific data.
    uint64_t vendor_data;
} iscsi_scsi_mode_select_10_parameter_list_packet;


/// iSCSI SCSI command MODE SENSE(6) parameter header data flags: DPO and FUA support (DPOFUA).
#define ISCSI_SCSI_MODE_SENSE_6_PARAM_HDR_DATA_FLAGS_DPOFUA (1 << 4)

/// iSCSI SCSI command MODE SENSE(6) parameter header data flags: Write Protect (WP).
#define ISCSI_SCSI_MODE_SENSE_6_PARAM_HDR_DATA_FLAGS_WP     (1 << 7)


/**
 * @brief iSCSI SCSI command MODE SENSE(6) parameter header packet data.
 *
 * This returns the mode parameter header
 * data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_6_parameter_header_data_packet {
    /// Mode data length in bytes.
    uint8_t mode_data_len;

    /// Medium type.
    uint8_t medium_type;

    /// Flags.
    int8_t flags;

    /// Block descriptor length in bytes.
    uint8_t block_desc_len;
} iscsi_scsi_mode_sense_6_parameter_header_data_packet;


/// iSCSI SCSI command MODE SENSE(10) parameter header data flags: DPO and FUA support (DPOFUA).
#define ISCSI_SCSI_MODE_SENSE_10_PARAM_HDR_DATA_FLAGS_DPOFUA (1 << 4)

/// iSCSI SCSI command MODE SENSE(10) parameter header data flags: Write Protect (WP).
#define ISCSI_SCSI_MODE_SENSE_10_PARAM_HDR_DATA_FLAGS_WP     (1 << 7)


/// iSCSI SCSI command MODE SENSE(10) parameter header data Long Logical Block Address (LONGLBA).
#define ISCSI_SCSI_MODE_SENSE_10_PARAM_HDR_DATA_LONGLBA (1 << 0)


/**
 * @brief iSCSI SCSI command MODE SENSE(10) parameter header packet data.
 *
 * This returns the mode parameter header
 * data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_10_parameter_header_data_packet {
    /// Mode data length in bytes.
    uint16_t mode_data_len;

    /// Medium type.
    uint8_t medium_type;

    /// Flags.
    int8_t flags;

    /// Long Logical Block Address (LONGLBA).
    uint8_t long_lba;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Block descriptor length in bytes.
    uint16_t block_desc_len;
} iscsi_scsi_mode_sense_10_parameter_header_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) short LBA mode parameter block descriptor packet data.
 *
 * This returns the short Logical Block
 * Address (LBA) mode parameter block
 * descriptor data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet {
    /// Number of blocks in logical blocks.
    uint32_t num_blocks;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Logical blcok length in bytes.
    uint8_t block_len[3];
} iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(10) long LBA mode parameter block descriptor packet data.
 *
 * This returns the long Logical Block
 * Address (LBA) mode parameter block
 * descriptor data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet {
    /// Number of blocks in logical blocks.
    uint64_t num_blocks;

    /// Reserved for future usage (always MUST be 0 for now).
    uint32_t reserved;

    /// Logical blcok length in bytes.
    uint32_t block_len;
} iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet;


/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC                   0x00

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Read/Write error recovery.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_READ_WRITE_ERR_RECOVERY       0x01

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Disconnect / Reconnect.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_DISCONNECT_RECONNECT          0x02

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Format device.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_FORMAT_DEVICE                 0x03

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Rigid disk geometry.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RIGID_DISK_GEOMETRY           0x04

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Rigid disk geometry.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RIGID_DISK_GEOMETRY_2         0x05

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED                      0x06

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Verify error recovery.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VERIFY_ERR_RECOVERY           0x07

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Caching.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_CACHING                       0x08

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Obselete.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_OBSELETE                      0x09

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Control.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_CONTROL                       0x0A

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Medium types supported.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_MEDIUM_TYPES_SUPPORTED        0x0B

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Notch and partition.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_NOTCH_AND_PARTITION           0x0C

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Obselete.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_OBSELETE_2                    0x0D

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_2                    0x0E

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_3                    0x0F

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: XOR control.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_XOR_CONTROL                   0x10

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_4                    0x11

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_5                    0x12

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_6                    0x13

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Enclosure services management.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_ENCLOSURE_SERVICES_MGMT       0x14

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_7                    0x15

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_8                    0x16

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_9                    0x17

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Protocol specific LUN.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_PROTOCOL_SPEC_LUN             0x18

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Protocol specific Port.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_PROTOCOL_SPEC_PORT            0x19

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Power condition.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_POWER_COND                    0x1A

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_10                   0x1B

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Informational exceptions control.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_INFO_EXCEPTIOS_CONTROL        0x1C

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_11                   0x1D

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_12                   0x1E

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Reserved.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_RESERVED_13                   0x1F

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_2                 0x20

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_3                 0x21

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_4                 0x22

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_5                 0x23

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_6                 0x24

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_7                 0x25

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_8                 0x26

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_9                 0x27

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_10                0x28

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_11                0x29

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_12                0x2A

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_13                0x2B

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_14                0x2C

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_15                0x2D

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_16                0x2E

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_17                0x2F

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_18                0x30

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_19                0x31

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_20                0x32

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_21                0x33

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_22                0x34

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_23                0x35

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_24                0x36

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_25                0x37

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_26                0x38

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_27                0x39

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_28                0x3A

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_29                0x3B

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_30                0x3C

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_31                0x3D

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Vendor specific.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC_32                0x3E

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Report all mode pages.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES         0x3F

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode sub page code: Control.
#define ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL                   0x00

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode sub page code: Control extension.
#define ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL_EXT               0x01

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode sub page code: All sub pages.
#define ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL_ALL               0xFF

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode sub page code: Report all mode pages.
#define ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_PAGES     0x00

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode sub page code: Report all mode pages and sub pages.
#define ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_SUB_PAGES 0xFF

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: First bit of the six bits.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_FIRST_BIT                     0

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Last bit of the six bits.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_LAST_BIT                      ((ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_FIRST_BIT) + 6 - 1)

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Bit mask.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_MASK                          (ISCSI_BITS_GET_MASK(ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Extracts the page code bits.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_GET_PAGE_CODE(x)                   (ISCSI_BITS_GET((x), ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page code: Stores into the page code bits.
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_PUT_PAGE_CODE(x)                   (ISCSI_BITS_PUT((x), ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_FIRST_BIT, ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_LAST_BIT))

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page flags: Sub Page Format (SPF).
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_FLAGS_SPF                          (1 << 6)

/// iSCSI SCSI command MODE SENSE(10) parameter header data flags: Parameters Saveable (PS).
#define ISCSI_SCSI_MODE_SENSE_MODE_PAGE_FLAGS_PS                           (1 << 7)


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_mode_page_data_packet {
    /// Page code and flags.
    int8_t page_code_flags;

    /// Page length in bytes.
    uint8_t page_len;

    /// Mode parameters.
    uint8_t params[0];
} iscsi_scsi_mode_sense_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode sub page packet data.
 *
 * This returns mode sub page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_mode_sub_page_data_packet {
    /// Page code and flags.
    int8_t page_code_flags;

    /// Sub page code.
    uint8_t sub_page_code;

    /// Page length in bytes.
    uint16_t page_len;

    /// Mode parameters.
    uint8_t params[0];
} iscsi_scsi_mode_sense_mode_sub_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) read/write error recovery mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_read_write_err_recovery_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_page_data_packet mode_page;

    /// Flags.
    int8_t flags;

    /// Read retry count.
    uint8_t read_retry_cnt;

    /// Obselete.
    uint8_t obselete[3];

    /// Restricted for MMC-6.
    uint8_t restrict_mmc_6;

    /// Write_retry count.
    uint8_t write_retry_cnt;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Recovery time limit.
    uint16_t recovery_time_limit;
} iscsi_scsi_mode_sense_read_write_err_recovery_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) disconnect / reconnect mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_disconnect_reconnect_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_page_data_packet mode_page;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved;

    /// Bus inactivity time limit.
    uint16_t bus_inactivity_time_limit;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved2;

    /// Maximum connect time limit.
    uint16_t max_connect_time_limit;

    /// Maximum burst size.
    uint16_t max_burst_size;

    /// Restricted.
    uint8_t restricted;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved3;

    /// First burst size.
    uint16_t first_burst_size;
} iscsi_scsi_mode_sense_disconnect_reconnect_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) verify error recovery mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_verify_err_recovery_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_page_data_packet mode_page;

    /// Flags.
    int8_t flags;

    /// Verify retry count.
    uint8_t verify_retry_cnt;

    /// Obselete.
    uint8_t obselete;

    /// Head offset count.
    uint8_t head_offset_cnt;

    /// Data strobe offset count.
    uint8_t data_strobe_offset_cnt;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Write retry count.
    uint8_t write_retry_cnt;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved2;

    /// Verify_recovery time limit.
    uint16_t verify_recovery_time_limit;
} iscsi_scsi_mode_sense_verify_err_recovery_mode_page_data_packet;


/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page flags: READ Cache Disable (RCD).
#define ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_RCD  (1 << 0)

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page flags: Multiplication factor (MF).
#define ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_MF   (1 << 1)

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page flags: Write Cache Enable (WCE).
#define ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_WCE  (1 << 2)

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page flags: Size Enable (SIZE).
#define ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_SIZE (1 << 3)

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page flags: Discontinuity (DISC).
#define ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_DISC (1 << 4)

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page flags: Caching Analysis Permitted (CAP).
#define ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_CAP  (1 << 5)

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page flags: Abort Prefetch (ABPF).
#define ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_ABPF (1 << 6)

/// iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page flags: Initiator Control (IC).
#define ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_IC   (1 << 7)


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) caching mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_caching_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_page_data_packet mode_page;

    /// Flags.
    int8_t flags;

    /// Retention priority.
    uint8_t retention_pri;

    /// Disable prefetch transfer length.
    uint16_t disable_prefetch_xfer_len;

    /// Minimum prefetch.
    uint16_t min_prefetch;

    /// Maximum prefetch.
    uint16_t max_prefetch;

    /// Maximum prefetch ceiling.
    uint16_t max_prefetch_ceil;

    /// Cache flags.
    int8_t cache_flags;

    /// Number of cache segments.
    uint8_t num_cache_segs;

    /// Cache segment size.
    uint16_t cache_seg_size;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Obselete.
    uint8_t obselete[3];
} iscsi_scsi_mode_sense_caching_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) control mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_control_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_page_data_packet mode_page;

    /// Flags.
    int8_t flags;

    /// Queue flags.
    int8_t queue_flags;

    /// Control flags.
    int8_t control_flags;

    /// Application task flags.
    int8_t app_task_flags;

    /// Ready AER holdoff period.
    uint16_t ready_aer_holdoff_period;

    /// Busy timeout period.
    uint16_t busy_timeout_period;

    /// Extended self-test completition time.
    uint16_t ext_self_test_complete_time;
} iscsi_scsi_mode_sense_control_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) control extension mode sub page packet data.
 *
 * This returns mode sub page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_control_ext_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_sub_page_data_packet mode_sub_page;

    /// Flags.
    int8_t flags;

    /// Initial command priority.
    uint8_t init_cmd_pri;

    /// Maximum sense data length in bytes.
    uint8_t max_sense_data_len;

    /// Reserved for future usage (always MUST be 0 for now).
    uint64_t reserved[3];

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved2;
} iscsi_scsi_mode_sense_control_ext_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) XOR extension mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_xor_ext_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_page_data_packet mode_page;

    /// Flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Maximum XOR write size in logical blocks.
    uint32_t max_xor_write_size;

    /// Reserved for future usage (always MUST be 0 for now).
    uint32_t reserved2;

    /// Maximum regenerate size in logical blocks.
    uint32_t max_regenerate_size;

    /// Reserved for future usage (always MUST be 0 for now).
    uint32_t reserved3;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved4;

    /// Rebuild delay.
    uint16_t rebuild_delay;
} iscsi_scsi_mode_sense_xor_ext_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) power condition mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_power_cond_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_page_data_packet mode_page;

    /// Flags.
    int8_t flags;

    /// Idle and standby flags.
    int8_t idle_standby_flags;

    /// idle_a condition timer.
    uint32_t idle_a_cond_timer;

    /// standby_z condition timer.
    uint32_t standby_z_cond_timer;

    /// idle_b condition timer.
    uint32_t idle_b_cond_timer;

    /// idle_c condition timer.
    uint32_t idle_c_cond_timer;

    /// standby_y condition timer.
    uint32_t standby_y_cond_timer;

    /// Reserved for future usage (always MUST be 0 for now).
    uint64_t reserved;

    /// Reserved for future usage (always MUST be 0 for now).
    uint32_t reserved2;

    /// Reserved for future usage (always MUST be 0 for now).
    uint16_t reserved3;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved4;

    /// Check Condition From (CCF) flags.
    int8_t ccf_flags;
} iscsi_scsi_mode_sense_power_cond_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) informational exceptions control mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_info_exceptions_control_mode_page_data_packet {
    /// Mode page.
    iscsi_scsi_mode_sense_mode_page_data_packet mode_page;

    /// Flags.
    int8_t flags;

    /// Method Of Reporting Informational Exceptions (MRIE) flags.
    uint8_t mrie;

    /// Interval timer.
    uint32_t interval_timer;

    /// Report count.
    uint32_t report_cnt;
} iscsi_scsi_mode_sense_info_exceptions_control_mode_page_data_packet;


/**
 * @brief iSCSI SCSI command PERSISTENT RESERVE OUT parameter list packet data.
 *
 * This returns persistent storage specific data
 * like the reservation and service action keys.
 */
typedef struct __attribute__((packed)) iscsi_scsi_pr_reserve_out_parameter_list_packet {
    /// Reservation key.
    uint64_t r_key;

    /// Service action reservation key.
    uint64_t sa_key;

    /// Obselete.
    uint32_t obselete;

    /// Flags.
    int8_t flags;

    /// Reserved for future usage (always MUST be 0 for now).
    uint8_t reserved;

    /// Obselete.
    uint16_t obselete2;

} iscsi_scsi_pr_reserve_out_parameter_list_packet;


/**
 * @brief iSCSI SCSI command PERSISTENT RESERVE IN parameter data packet data.
 *
 * This returns persistent storage specific data
 * like the reservation and service action keys.
 */
typedef struct __attribute__((packed)) iscsi_scsi_pr_reserve_in_parameter_data_packet {
    /// Persistent Reservations (PR) Generation.
    uint32_t pr_gen;

    /// Additional length in bytes.
    uint32_t add_len;
} iscsi_scsi_pr_reserve_in_parameter_data_packet;


/// SCSI command opcode (embedded in iSCSI protocol): TEST UNIT READY.
#define ISCSI_SCSI_OPCODE_TESTUNITREADY          0x00

/// SCSI command opcode (embedded in iSCSI protocol): REQUEST SENSE.
#define ISCSI_SCSI_OPCODE_REQUESTSENSE           0x03

/// SCSI command opcode (embedded in iSCSI protocol): READ(6).
#define ISCSI_SCSI_OPCODE_READ6                  0x08

/// SCSI command opcode (embedded in iSCSI protocol): WRITE(6).
#define ISCSI_SCSI_OPCODE_WRITE6                 0x0A

/// SCSI command opcode (embedded in iSCSI protocol): INQUIRY.
#define ISCSI_SCSI_OPCODE_INQUIRY                0x12

/// SCSI command opcode (embedded in iSCSI protocol): MODE SELECT(6).
#define ISCSI_SCSI_OPCODE_MODESELECT6            0x15

/// SCSI command opcode (embedded in iSCSI protocol): RESERVE(6).
#define ISCSI_SCSI_OPCODE_RESERVE6               0x16

/// SCSI command opcode (embedded in iSCSI protocol): RELEASE(6).
#define ISCSI_SCSI_OPCODE_RELEASE6               0x17

/// SCSI command opcode (embedded in iSCSI protocol): MODE SENSE(6).
#define ISCSI_SCSI_OPCODE_MODESENSE6             0x1A

/// SCSI command opcode (embedded in iSCSI protocol): START STOP UNIT.
#define ISCSI_SCSI_OPCODE_STARTSTOPUNIT          0x1B

/// SCSI command opcode (embedded in iSCSI protocol): PREVENT ALLOW MEDIUM REMOVAL.
#define ISCSI_SCSI_OPCODE_PREVENTALLOW           0x1E

/// SCSI command opcode (embedded in iSCSI protocol): READ CAPACITY(10).
#define ISCSI_SCSI_OPCODE_READCAPACITY10         0x25

/// SCSI command opcode (embedded in iSCSI protocol): READ(10).
#define ISCSI_SCSI_OPCODE_READ10                 0x28

/// SCSI command opcode (embedded in iSCSI protocol): WRITE(10).
#define ISCSI_SCSI_OPCODE_WRITE10                0x2A

/// SCSI command opcode (embedded in iSCSI protocol): WRITE AND VERIFY(10).
#define ISCSI_SCSI_OPCODE_WRITE_VERIFY10         0x2E

/// SCSI command opcode (embedded in iSCSI protocol): VERIFY(10).
#define ISCSI_SCSI_OPCODE_VERIFY10               0x2F

/// SCSI command opcode (embedded in iSCSI protocol): PRE-FETCH(10).
#define ISCSI_SCSI_OPCODE_PREFETCH10             0x34

/// SCSI command opcode (embedded in iSCSI protocol): SYNCHRONIZE CACHE(10).
#define ISCSI_SCSI_OPCODE_SYNCHRONIZECACHE10     0x35

/// SCSI command opcode (embedded in iSCSI protocol): READ DEFECT DATA(10).
#define ISCSI_SCSI_OPCODE_READ_DEFECT_DATA10     0x37

/// SCSI command opcode (embedded in iSCSI protocol): WRITE SAME(10).
#define ISCSI_SCSI_OPCODE_WRITE_SAME10           0x41

/// SCSI command opcode (embedded in iSCSI protocol): UNMAP.
#define ISCSI_SCSI_OPCODE_UNMAP                  0x42

/// SCSI command opcode (embedded in iSCSI protocol): READ TOC/PMA/ATIP.
#define ISCSI_SCSI_OPCODE_READTOC                0x43

/// SCSI command opcode (embedded in iSCSI protocol): SANITIZE.
#define ISCSI_SCSI_OPCODE_SANITIZE               0x48

/// SCSI command opcode (embedded in iSCSI protocol): LOG SELECT.
#define ISCSI_SCSI_OPCODE_LOGSELECT              0x4C

/// SCSI command opcode (embedded in iSCSI protocol): LOG SENSE.
#define ISCSI_SCSI_OPCODE_LOGSENSE               0x4D

/// SCSI command opcode (embedded in iSCSI protocol): MODE SELECT(10).
#define ISCSI_SCSI_OPCODE_MODESELECT10           0x55

/// SCSI command opcode (embedded in iSCSI protocol): RESERVE(10).
#define ISCSI_SCSI_OPCODE_RESERVE10              0x56

/// SCSI command opcode (embedded in iSCSI protocol): RELEASE(10).
#define ISCSI_SCSI_OPCODE_RELEASE10              0x57

/// SCSI command opcode (embedded in iSCSI protocol): MODE SENSE(10).
#define ISCSI_SCSI_OPCODE_MODESENSE10            0x5A

/// SCSI command opcode (embedded in iSCSI protocol): PERSISTENT RESERVE IN.
#define ISCSI_SCSI_OPCODE_PERSISTENT_RESERVE_IN  0x5E

/// SCSI command opcode (embedded in iSCSI protocol): PERSISTENT RESERVE OUT.
#define ISCSI_SCSI_OPCODE_PERSISTENT_RESERVE_OUT 0x5F

/// SCSI command opcode (embedded in iSCSI protocol): Third-party Copy OUT.
#define ISCSI_SCSI_OPCODE_EXTENDED_COPY          0x83

/// SCSI command opcode (embedded in iSCSI protocol): Third-party Copy IN.
#define ISCSI_SCSI_OPCODE_RECEIVE_COPY_RESULTS   0x84

/// SCSI command opcode (embedded in iSCSI protocol): READ(16).
#define ISCSI_SCSI_OPCODE_READ16                 0x88

/// SCSI command opcode (embedded in iSCSI protocol): COMPARE AND WRITE.
#define ISCSI_SCSI_OPCODE_COMPARE_AND_WRITE      0x89

/// SCSI command opcode (embedded in iSCSI protocol): WRITE(16).
#define ISCSI_SCSI_OPCODE_WRITE16                0x8A

/// SCSI command opcode (embedded in iSCSI protocol): ORWRITE.
#define ISCSI_SCSI_OPCODE_ORWRITE                0x8B

/// SCSI command opcode (embedded in iSCSI protocol): WRITE AND VERIFY(16).
#define ISCSI_SCSI_OPCODE_WRITE_VERIFY16         0x8E

/// SCSI command opcode (embedded in iSCSI protocol): VERIFY(16).
#define ISCSI_SCSI_OPCODE_VERIFY16               0x8F

/// SCSI command opcode (embedded in iSCSI protocol): PRE-FETCH(16).
#define ISCSI_SCSI_OPCODE_PREFETCH16             0x90

/// SCSI command opcode (embedded in iSCSI protocol): SYNCHRONIZE CACHE(16).
#define ISCSI_SCSI_OPCODE_SYNCHRONIZECACHE16     0x91

/// SCSI command opcode (embedded in iSCSI protocol): WRITE SAME(16).
#define ISCSI_SCSI_OPCODE_WRITE_SAME16           0x93

/// SCSI command opcode (embedded in iSCSI protocol): WRITE ATOMIC(16).
#define ISCSI_SCSI_OPCODE_WRITE_ATOMIC16         0x9C

/// SCSI command opcode (embedded in iSCSI protocol): SERVICE ACTION IN(16).
#define ISCSI_SCSI_OPCODE_SERVICE_ACTION_IN_16   0x9E

/// SCSI command opcode (embedded in iSCSI protocol): REPORT LUNS.
#define ISCSI_SCSI_OPCODE_REPORTLUNS             0xA0

/// SCSI command opcode (embedded in iSCSI protocol): MAINTENANCE IN.
#define ISCSI_SCSI_OPCODE_MAINTENANCE_IN         0xA3

/// SCSI command opcode (embedded in iSCSI protocol): READ(12).
#define ISCSI_SCSI_OPCODE_READ12                 0xA8

/// SCSI command opcode (embedded in iSCSI protocol): WRITE(12).
#define ISCSI_SCSI_OPCODE_WRITE12                0xAA

/// SCSI command opcode (embedded in iSCSI protocol): WRITE AND VERIFY(12).
#define ISCSI_SCSI_OPCODE_WRITE_VERIFY12         0xAE

/// SCSI command opcode (embedded in iSCSI protocol): VERIFY(12).
#define ISCSI_SCSI_OPCODE_VERIFY12               0xAF

/// SCSI command opcode (embedded in iSCSI protocol): READ DEFECT DATA(12).
#define ISCSI_SCSI_OPCODE_READ_DEFECT_DATA12     0xB7


/**
 * @brief iSCSI SCSI command flags: No unsolicited data.
 *
 * (F) is set to 1 when no unsolicited SCSI Data-Out PDUs
 * follow this PDU. When F = 1 for a write and if Expected
 * Data Transfer Length is larger than the
 * DataSegmentLength, the target may solicit additional data
 * through R2T.
 */
#define ISCSI_SCSI_CMD_FLAGS_TASK_NO_UNSOLICITED_DATA   (1 << 7)


/// SCSI SCSI command flags: Final.
#define ISCSI_SCSI_CMD_FLAGS_FINAL                      (1 << 7)

/**
 * @brief iSCSI SCSI command flags: Expected input data.
 *
 * (R) is set to 1 when the command is expected to input data.
 */
#define ISCSI_SCSI_CMD_FLAGS_TASK_READ                  (1 << 6)

/**
 * @brief iSCSI SCSI command flags: Expected output data.
 *
 * (W) is set to 1 when the command is expected to output data.
 */
#define ISCSI_SCSI_CMD_FLAGS_TASK_WRITE                 (1 << 5)


/// SCSI command flags task attribute: Untagged.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_UNTAGGED         0x0

/// SCSI command flags task attribute: Simple.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_SIMPLE           0x1

/// SCSI command flags task attribute: Ordered.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_ORDERED          0x2

/// SCSI command flags task attribute: Head of queue.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_HEAD_QUEUE       0x3

/// SCSI command flags task attribute: ACA.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_ACA              0x4

/// SCSI command flags task attribute: Reserved.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_RESERVED_1       0x5

/// SCSI command flags task attribute: Reserved.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_RESERVED_2       0x6

/// SCSI command flags task attribute: Reserved.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_RESERVED_3       0x7

/// SCSI command flags Task Attributes (ATTR) are encoded in the first three LSBs.
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_MASK             0x7


/**
 * @brief iSCSI Flag and Task Attributes for SCSI command packet data.
 *
 * Flags and Task Attributes:
 * At least one of the W and F bits MUST be set to 1.\n
 * Either or both of R and W MAY be 1 when the Expected Data Transfer
 * Length and/or the Bidirectional Read Expected Data Transfer Length
 * are 0, but they MUST NOT both be 0 when the Expected Data Transfer
 * Length and/or Bidirectional Read Expected Data Transfer Length are
 * not 0 (i.e., when some data transfer is expected, the transfer
 * direction is indicated by the R and/or W bit).
 */
typedef struct __attribute__((packed)) iscsi_scsi_cmd_packet {
    /// Always 1 according to the iSCSI specification.
    uint8_t opcode;

    /// Flags and Task Attributes.
    int8_t flags_task;

    /// Reserved for future usage, MUST always be 0.
    uint16_t reserved;

    /// Total length of AHS.
    uint8_t total_ahs_len;

    /// Length of DataSegment.
    uint8_t ds_len[3];

    /// SCSI LUN bit mask.
    uint64_t lun;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /**
     * @brief Expected Data Transfer Length.
     *
     * For unidirectional operations, the Expected Data Transfer Length
     * field contains the number of bytes of data involved in this SCSI
     * operation. For a unidirectional write operation (W flag set to 1 and
     * R flag set to 0), the initiator uses this field to specify the number
     * of bytes of data it expects to transfer for this operation. For a
     * unidirectional read operation (W flag set to 0 and R flag set to 1),
     * the initiator uses this field to specify the number of bytes of data
     * it expects the target to transfer to the initiator. It corresponds
     * to the SAM-2 byte count.\n
     * For bidirectional operations (both R and W flags are set to 1), this
     * field contains the number of data bytes involved in the write
     * transfer. For bidirectional operations, an additional header segment
     * MUST be present in the header sequence that indicates the
     * Bidirectional Read Expected Data Transfer Length. The Expected Data
     * Transfer Length field and the Bidirectional Read Expected Data
     * Transfer Length field correspond to the SAM-2 byte count.
     * If the Expected Data Transfer Length for a write and the length of
     * the immediate data part that follows the command (if any) are the
     * same, then no more data PDUs are expected to follow. In this case,
     * the F bit MUST be set to 1.\n
     * If the Expected Data Transfer Length is higher than the
     * FirstBurstLength (the negotiated maximum amount of unsolicited data
     * the target will accept), the initiator MUST send the maximum amount
     * of unsolicited data OR ONLY the immediate data, if any.
     * Upon completion of a data transfer, the target informs the initiator
     * (through residual counts) of how many bytes were actually processed
     * (sent and/or received) by the target.
     */
    uint32_t exp_xfer_len;

    /// The CmdSN enables ordered delivery across multiple connections in a single session.
    uint32_t cmd_sn;

    /// Command responses up to ExpStatSN - 1 (modulo 2**32) have been received (acknowledges status) on the connection.
    uint32_t exp_stat_sn;

    /**
     * @brief SCSI Command Descriptor Block (CDB).
     *
     * There are 16 bytes in the CDB field to accommodate the commonly used
     * CDBs. Whenever the CDB is larger than 16 bytes, an Extended CDB AHS
     * MUST be used to contain the CDB spillover.
     */
    iscsi_scsi_cdb scsi_cdb;

    /// Optional AHS packet data.
    iscsi_ahs_packet ahs;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /// Optional data segment, command data.
    iscsi_scsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_scsi_cmd_packet;


/**
 * @brief SCSI response flags: Residual Underflow.
 *
 * (U) set for Residual Underflow. In this case, the Residual
 * Count indicates the number of bytes that were not
 * transferred out of the number of bytes that were expected
 * to be transferred. For a bidirectional operation, the
 * Residual Count contains the residual for the write
 * operation.
 *
 * Bits O and U and bits o and u are mutually exclusive (i.e., having
 * both o and u or O and U set to 1 is a protocol error).
 *
 * For a response other than "Command Completed at Target", bits 3-6
 * MUST be 0.
 */
#define ISCSI_SCSI_RESPONSE_FLAGS_RES_UNDERFLOW   (1 << 1)

/**
 * @brief SCSI response flags: Residual Overflow.
 *
 * (O) set for Residual Overflow. In this case, the Residual
 * Count indicates the number of bytes that were not
 * transferred because the initiator's Expected Data
 * Transfer Length was not sufficient. For a bidirectional
 * operation, the Residual Count contains the residual for
 * the write operation.
 *
 * Bits O and U and bits o and u are mutually exclusive (i.e., having
 * both o and u or O and U set to 1 is a protocol error).
 *
 * For a response other than "Command Completed at Target", bits 3-6
 * MUST be 0.
 */
#define ISCSI_SCSI_RESPONSE_FLAGS_RES_OVERFLOW    (1 << 2)

/**
 * @brief SCSI response flags: Bidirectional Read Residual Underflow.
 *
 * (u) set for Bidirectional Read Residual Underflow. In this
 * case, the Bidirectional Read Residual Count indicates the
 * number of bytes that were not transferred to the
 * initiator out of the number of bytes expected to be
 * transferred.
 *
 * Bits O and U and bits o and u are mutually exclusive (i.e., having
 * both o and u or O and U set to 1 is a protocol error).
 *
 * For a response other than "Command Completed at Target", bits 3-6
 * MUST be 0.
 */
#define ISCSI_SCSI_RESPONSE_FLAGS_BIDI_READ_RES_UNDERFLOW   (1 << 3)

/**
 * @brief SCSI response flags: Bidirectional Read Residual Overflow.
 *
 + (o) set for Bidirectional Read Residual Overflow. In this
 * case, the Bidirectional Read Residual Count indicates the
 * number of bytes that were not transferred to the
 * initiator because the initiator's Bidirectional Read
 * Expected Data Transfer Length was not sufficient.
 *
 * Bits O and U and bits o and u are mutually exclusive (i.e., having
 * both o and u or O and U set to 1 is a protocol error).
 *
 * For a response other than "Command Completed at Target", bits 3-6
 * MUST be 0.
 */
#define ISCSI_SCSI_RESPONSE_FLAGS_BIDI_READ_RES_OVERFLOW    (1 << 4)

/**
 * @brief SCSI status response code: Good.
 *
 * The Status field is used to report the SCSI status of the command (as
 * specified in SAM2) and is only valid if the response code is
 * Command Completed at Target.
 *
 * If a SCSI device error is detected while data from the initiator is
 * still expected (the command PDU did not contain all the data and the
 * target has not received a data PDU with the Final bit set), the
 * target MUST wait until it receives a data PDU with the F bit set in
 * the last expected sequence before sending the Response PDU.
 */
#define ISCSI_SCSI_RESPONSE_STATUS_GOOD          0x00

/**
 * @brief SCSI status response code: Check condition.
 *
 * The Status field is used to report the SCSI status of the command (as
 * specified in SAM2) and is only valid if the response code is
 * Command Completed at Target.
 *
 * If a SCSI device error is detected while data from the initiator is
 * still expected (the command PDU did not contain all the data and the
 * target has not received a data PDU with the Final bit set), the
 * target MUST wait until it receives a data PDU with the F bit set in
 * the last expected sequence before sending the Response PDU.
 */
#define ISCSI_SCSI_RESPONSE_STATUS_CHECK_COND    0x02

/**
 * @brief SCSI status response code: Busy.
 *
 * The Status field is used to report the SCSI status of the command (as
 * specified in SAM2) and is only valid if the response code is
 * Command Completed at Target.
 *
 * If a SCSI device error is detected while data from the initiator is
 * still expected (the command PDU did not contain all the data and the
 * target has not received a data PDU with the Final bit set), the
 * target MUST wait until it receives a data PDU with the F bit set in
 * the last expected sequence before sending the Response PDU.
 */
#define ISCSI_SCSI_RESPONSE_STATUS_BUSY          0x08

/**
 * @brief SCSI status response code: Residual conflict.
 *
 * The Status field is used to report the SCSI status of the command (as
 * specified in SAM2) and is only valid if the response code is
 * Command Completed at Target.
 *
 * If a SCSI device error is detected while data from the initiator is
 * still expected (the command PDU did not contain all the data and the
 * target has not received a data PDU with the Final bit set), the
 * target MUST wait until it receives a data PDU with the F bit set in
 * the last expected sequence before sending the Response PDU.
 */
#define ISCSI_SCSI_RESPONSE_STATUS_RES_CONFLICT  0x18

/**
 * @brief SCSI status response code: Task set full.
 *
 * The Status field is used to report the SCSI status of the command (as
 * specified in SAM2) and is only valid if the response code is
 * Command Completed at Target.
 *
 * If a SCSI device error is detected while data from the initiator is
 * still expected (the command PDU did not contain all the data and the
 * target has not received a data PDU with the Final bit set), the
 * target MUST wait until it receives a data PDU with the F bit set in
 * the last expected sequence before sending the Response PDU.
 */
#define ISCSI_SCSI_RESPONSE_STATUS_TASK_SET_FULL 0x28

/**
 * @brief SCSI status response code: ACA active.
 *
 * The Status field is used to report the SCSI status of the command (as
 * specified in SAM2) and is only valid if the response code is
 * Command Completed at Target.
 *
 * If a SCSI device error is detected while data from the initiator is
 * still expected (the command PDU did not contain all the data and the
 * target has not received a data PDU with the Final bit set), the
 * target MUST wait until it receives a data PDU with the F bit set in
 * the last expected sequence before sending the Response PDU.
 */
#define ISCSI_SCSI_RESPONSE_STATUS_ACA_ACTIVE    0x30

/**
 * @brief SCSI status response code: Task aborted.
 *
 * The Status field is used to report the SCSI status of the command (as
 * specified in SAM2) and is only valid if the response code is
 * Command Completed at Target.
 *
 * If a SCSI device error is detected while data from the initiator is
 * still expected (the command PDU did not contain all the data and the
 * target has not received a data PDU with the Final bit set), the
 * target MUST wait until it receives a data PDU with the F bit set in
 * the last expected sequence before sending the Response PDU.
 */
#define ISCSI_SCSI_RESPONSE_STATUS_TASK_ABORTED  0x40


/// SCSI response code: Command Completed at Target.
#define ISCSI_SCSI_RESPONSE_CODE_OK              0x00

/// SCSI response code: Target Failure.
#define ISCSI_SCSI_RESPONSE_CODE_FAIL            0x01

/// SCSI response code: First vendor specific response code.
#define ISCSI_SCSI_RESPONSE_CODE_VENDOR_FIRST    0x80

/// SCSI response code: Last vendor specific response code.
#define ISCSI_SCSI_RESPONSE_CODE_VENDOR_LAST     0xFF

/**
 * @brief iSCSI SCSI command response packet data.
 *
 * The Response field is used to report a service response. The mapping
 * of the response code into a SCSI service response code value, if
 * needed, is outside the scope of this document. However, in symbolic
 * terms, response value 0x00 maps to the SCSI service response (see
 */
typedef struct __attribute__((packed)) iscsi_scsi_response_packet {
    /// Always 0x21 according to specification.
    uint8_t opcode;

    /// Flags.
    int8_t flags;

    /// This field contains the iSCSI service response.
    uint8_t response;

    /// The Status field is used to report the SCSI status of the command (as specified in SAM2) and is only valid if the response code is Command Completed at Target.
    uint8_t status;

    /// Total AHS length.
    uint8_t total_ahs_len;

    /// Data segment length.
    uint8_t ds_len[3];

    /// Reserved for future usage. Always MUST be 0.
    uint64_t reserved;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /**
     * @brief Copy of the last accepted Selective Negative / Sequence Number Acknowledgment (SNACK) tag.
     *
     * This field contains a copy of the SNACK Tag of the last SNACK Tag
     * accepted by the target on the same connection and for the command for
     * which the response is issued. Otherwise, it is reserved and should
     * be set to 0.\n
     * After issuing a R-Data SNACK, the initiator must discard any SCSI
     * status unless contained in a SCSI Response PDU carrying the same
     * SNACK Tag as the last issued R-Data SNACK for the SCSI command on the
     * current connection.
     */
    uint32_t snack_tag;

    /**
     * @brief StatSN - Status Sequence Number.
     *
     * The StatSN is a sequence number that the target iSCSI layer generates
     * per connection and that in turn enables the initiator to acknowledge
     * status reception. The StatSN is incremented by 1 for every
     * response/status sent on a connection, except for responses sent as a
     * result of a retry or SNACK. In the case of responses sent due to a
     * retransmission request, the StatSN MUST be the same as the first time
     * the PDU was sent, unless the connection has since been restarted.
     */
    uint32_t stat_sn;

    /**
     * @brief ExpCmdSN - Next Expected CmdSN from This Initiator.
     *
     * The ExpCmdSN is a sequence number that the target iSCSI returns to
     * the initiator to acknowledge command reception. It is used to update
     * a local variable with the same name. An ExpCmdSN equal to
     * MaxCmdSN + 1 indicates that the target cannot accept new commands.
     */
    uint32_t exp_cmd_sn;

    /**
     * @brief MaxCmdSN - Maximum CmdSN from This Initiator.
     *
     * The MaxCmdSN is a sequence number that the target iSCSI returns to
     * the initiator to indicate the maximum CmdSN the initiator can send.
     * It is used to update a local variable with the same name. If the
     * MaxCmdSN is equal to ExpCmdSN - 1, this indicates to the initiator
     * that the target cannot receive any additional commands. When the
     * MaxCmdSN changes at the target while the target has no pending PDUs
     * to convey this information to the initiator, it MUST generate a
     * NOP-In to carry the new MaxCmdSN.
     */
    uint32_t max_cmd_sn;

    /**
     * @brief ExpDataSN or Reserved.
     *
     * This field indicates the number of Data-In (read) PDUs the target has
     * sent for the command.\n
     * This field MUST be 0 if the response code is not Command Completed at
     * Target or the target sent no Data-In PDUs for the command.
     */
    uint32_t exp_data_sn;

    /**
     * @brief Bidirectional Read Residual Count or Reserved.
     *
     * The Bidirectional Read Residual Count field MUST be valid in the case
     * where either the u bit or the o bit is set. If neither bit is set,
     * the Bidirectional Read Residual Count field is reserved. Targets may
     * set the Bidirectional Read Residual Count, and initiators may use it
     * when the response code is Command Completed at Target. If the o bit
     * is set, the Bidirectional Read Residual Count indicates the number of
     * bytes that were not transferred to the initiator because the
     * initiator's Bidirectional Read Expected Data Transfer Length was not
     * sufficient. If the u bit is set, the Bidirectional Read Residual
     * Count indicates the number of bytes that were not transferred to the
     * initiator out of the number of bytes expected to be transferred.
     */
    uint32_t bidi_read_res_cnt;

    /**
     * @brief Residual Count or Reserved.
     *
     * The Residual Count field MUST be valid in the case where either the U
     * bit or the O bit is set. If neither bit is set, the Residual Count
     * field MUST be ignored on reception and SHOULD be set to 0 when
     * sending. Targets may set the residual count, and initiators may use
     * it when the response code is Command Completed at Target (even if the
     * status returned is not GOOD). If the O bit is set, the Residual
     * Count indicates the number of bytes that were not transferred because
     * the initiator's Expected Data Transfer Length was not sufficient. If
     * the U bit is set, the Residual Count indicates the number of bytes
     * that were not transferred out of the number of bytes expected to be
     * transferred.
     */
    uint32_t res_cnt;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /// Optional data segment, command data.
    iscsi_scsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_scsi_response_packet;


/// Task management request function: ABORT TASK: aborts the task identified by the Referenced Task Tag field.
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_ABORT_TASK         0x01

/// Task management request function: ABORT TASK SET: aborts all tasks issued via this session on the LU.
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_ABORT_TASK_SET     0x02

/// Task management request function: CLEAR ACA - clears the Auto Contingent Allegiance condition.
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_CLEAR_ACA          0x03

/// Task management request function: CLEAR TASK SET - aborts all tasks in the appropriate task set as defined by the TST field in the Control mode page (see SPC3).
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_CLEAR_TASK_SET     0x04

/// Task management request function: LOGICAL UNIT RESET.
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_LOGICAL_UNIT_RESET 0x05

/// Task management request function: TARGET WARM RESET.
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_TARGET_WARM_RESET  0x06

/// Task management request function: TARGET COLD RESET.
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_TARGET_COLD_RESET  0x07

/// Task management request function: TASK REASSIGN - reassigns connection allegiance for the task identified by the Initiator Task Tag field to this connection, thus resuming the iSCSI exchanges for the task.
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_TASK_REASSIGN      0x08


/**
 * @brief iSCSI Task Management Function Request packet data.
 *
 * This structure is used to explicity control the execution of one
 * or more tasks (iSCSI and SCSI).
 */
typedef struct __attribute__((packed)) iscsi_task_mgmt_func_req_packet {
    /// Always 2 according to iSCSI specification.
    uint8_t opcode;

    /**
     * @brief Function.
     *
     * The task management functions provide an initiator with a way to
     * explicitly control the execution of one or more tasks (SCSI and iSCSI
     * tasks). The task management function codes are listed below. For a
     * more detailed description of SCSI task management, see SAM2.
     */
    int8_t func;

    /// Reserved fot future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength (MUST be 0 for this PDU).
    uint8_t total_ahs_len;

    /// DataSegmentLength (MUST be 0 for this PDU).
    uint8_t ds_len[3];

    /**
     * @brief Logical Unit Number (LUN) or Reserved.
     *
     * This field is required for functions that address a specific LU
     * (ABORT TASK, CLEAR TASK SET, ABORT TASK SET, CLEAR ACA, LOGICAL UNIT
     * RESET) and is reserved in all others
     */
    uint64_t lun;

    /**
     * @brief Initiator Task Tag (ITT).
     *
     * This is the Initiator Task Tag of the task to be aborted for the
     * ABORT TASK function or reassigned for the TASK REASSIGN function.
     * For all the other functions, this field MUST be set to the reserved
     * value 0xFFFFFFFF.
     */
    uint32_t init_task_tag;

    /// Referenced task tag or 0xFFFFFFFF.
    uint32_t ref_task_tag;

    /// CmdSN.
    uint32_t cmd_sn;

    /// ExpStatSN
    uint32_t exp_stat_sn;

    /**
     * @brief RefCmdSN or Reserved.
     *
     * If an ABORT TASK is issued for a task created by an immediate
     * command, then the RefCmdSN MUST be that of the task management
     * request itself (i.e., the CmdSN and RefCmdSN are equal).\n
     * For an ABORT TASK of a task created by a non-immediate command, the
     * RefCmdSN MUST be set to the CmdSN of the task identified by the
     * Referenced Task Tag field. Targets must use this field when the task
     * identified by the Referenced Task Tag field is not with the target.
     * Otherwise, this field is reserved.
     */
    uint32_t ref_cmd_sn;

    /**
     * @brief ExpDataSN or Reserved.
     *
     * For recovery purposes, the iSCSI target and initiator maintain a data
     * acknowledgment reference number - the first input DataSN number
     * unacknowledged by the initiator. When issuing a new command, this
     * number is set to 0. If the function is TASK REASSIGN, which
     * establishes a new connection allegiance for a previously issued read
     * or bidirectional command, the ExpDataSN will contain an updated data
     * acknowledgment reference number or the value 0; the latter indicates
     * that the data acknowledgment reference number is unchanged. The
     * initiator MUST discard any data PDUs from the previous execution that
     * it did not acknowledge, and the target MUST transmit all Data-In PDUs
     * (if any) starting with the data acknowledgment reference number. The
     * number of retransmitted PDUs may or may not be the same as the
     * original transmission, depending on if there was a change in
     * MaxRecvDataSegmentLength in the reassignment. The target MAY also
     * send no more Data-In PDUs if all data has been acknowledged.
     * The value of ExpDataSN MUST be 0 or higher than the DataSN of the
     * last acknowledged Data-In PDU, but not larger than DataSN + 1 of the
     * last Data-IN PDU sent by the target. Any other value MUST be ignored
     * by the target.
     * For other functions, this field is reserved
     */
    uint32_t exp_data_sn;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;
} iscsi_task_mgmt_func_req_packet;


/// Task management function response: Function complete.
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_FUNC_COMPLETE               0x00

/// Task management function response: Task does not exist.
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_TASK_NO_EXIST               0x01

/// Task management function response: LUN does not exist.
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_LUN_NO_EXIST                0x02

/// Task management function response: Task still allegiant.
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_TASK_ALLEGIANT              0x03

/// Task management function response: Task allegiance reassignment not supported.
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_TASK_UNSUPPORTED_ALLEGIANCE 0x04

/// Task management function response: Task management function not supported.
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_TASK_UNSUPPORTED_MGMT       0x05

/// Task management function response: Function authorization failed.
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_FUNC_AUTH_FAILED            0x06

/// Task management function response: Function rejected.
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_FUNC_REJECTED               0xFF


/**
 * @brief iSCSI Task Management Function Response packet data.
 *
 * For the functions ABORT TASK, ABORT TASK SET, CLEAR ACA, CLEAR TASK
 * SET, LOGICAL UNIT RESET, TARGET COLD RESET, TARGET WARM RESET, and
 * TASK REASSIGN, the target performs the requested task management
 * function and sends a task management response back to the initiator.
 * For TASK REASSIGN, the new connection allegiance MUST ONLY become
 * effective at the target after the target issues the task management
 * response.
 */
typedef struct __attribute__((packed)) iscsi_task_mgmt_func_response_packet {
    /// Always 0x22 according to specification.
    uint8_t opcode;

    /// Reserved for future usage (always MUST be 0x80 for now).
    int8_t flags;

    /**
     * @brief Function response.
     *
     * For the TARGET COLD RESET and TARGET WARM RESET functions, the target
     * cancels all pending operations across all LUs known to the issuing
     * initiator. For the TARGET COLD RESET function, the target MUST then
     * close all of its TCP connections to all initiators (terminates all
     * sessions).\n
     * The mapping of the response code into a SCSI service response code
     * value, if needed, is outside the scope of this document. However, in
     * symbolic terms, Response values 0 and 1 map to the SCSI service
     * response of FUNCTION COMPLETE. Response value 2 maps to the SCSI
     * service response of INCORRECT LOGICAL UNIT NUMBER. All other
     * Response values map to the SCSI service response of FUNCTION
     * REJECTED. If a Task Management Function Response PDU does not arrive
     * before the session is terminated, the SCSI service response is
     * SERVICE DELIVERY OR TARGET FAILURE.\n
     * The response to ABORT TASK SET and CLEAR TASK SET MUST only be issued
     * by the target after all of the commands affected have been received
     * by the target, the corresponding task management functions have been
     * executed by the SCSI target, and the delivery of all responses
     * delivered until the task management function completion has been
     * confirmed (acknowledged through the ExpStatSN) by the initiator on
     * all connections of this session.\n
     * For the ABORT TASK function,\n
     * -# if the Referenced Task Tag identifies a valid task leading to a
     *    successful termination, then targets must return the "Function
     *    complete" response.
     * -# if the Referenced Task Tag does not identify an existing task
     *    but the CmdSN indicated by the RefCmdSN field in the Task
     *    Management Function Request is within the valid CmdSN window
     *    and less than the CmdSN of the Task Management Function Request
     *    itself, then targets must consider the CmdSN as received and
     *    return the "Function complete" response.
     * -# if the Referenced Task Tag does not identify an existing task
     *    and the CmdSN indicated by the RefCmdSN field in the Task
     *    Management Function Request is outside the valid CmdSN window,
     *    then targets must return the "Task does not exist" response
     */
    uint8_t response;

    /// Reserved for future usage, always MUST be 0.
    uint8_t reserved;

    /// TotalAHSLength (MUST be 0 for this PDU).
    uint8_t total_ahs_len;

    /// DataSegmentLength (MUST be 0 for this PDU).
    uint8_t ds_len[3];

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved3;

    /// StatSN.
    uint32_t stat_sn;

    /// ExpCmdSN.
    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved4;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved5;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;
} iscsi_task_mgmt_func_response_packet;

/// SCSI data out / in flags: Immediately process transfer.
#define ISCSI_SCSI_DATA_OUT_DATA_IN_FLAGS_IMMEDIATE (1 << 7)

/**
 * @brief iSCSI SCSI Data Out request packet data.
 *
 * THis structure is used by iSCSI for SCSI data output
 * requests, i.e. write operations.
 */
typedef struct __attribute__((packed)) iscsi_scsi_data_out_req_packet {
    /// Always 2 according to iSCSI specification.
    uint8_t opcode;

    /// Flags.
    int8_t flags;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /**
     * @brief DataSegmentLength.
     *
     * This is the data payload length of a SCSI Data-In or SCSI Data-Out
     * PDU. The sending of 0-length data segments should be avoided, but
     * initiators and targets MUST be able to properly receive 0-length data
     * segments.\n
     * The data segments of Data-In and Data-Out PDUs SHOULD be filled to
     * the integer number of 4-byte words (real payload), unless the F bit
     * is set to 1.
     */
    uint8_t ds_len[3];

    /**
     * @brief Logical Unit Number (LUN) or Reserved.
     *
     * If the Target Transfer Tag is provided, then the LUN field MUST hold a
     * valid value and be consistent with whatever was specified with the command;
     * otherwise, the LUN field is reserved.
     */
    uint64_t lun;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /**
     * @brief Target Transfer Tag or 0xFFFFFFFF.
     *
     * On outgoing data, the Target Transfer Tag is provided to the target
     * if the transfer is honoring an R2T. In this case, the Target
     * Transfer Tag field is a replica of the Target Transfer Tag provided
     * with the R2T.\n
     * The Target Transfer Tag values are not specified by this protocol,
     * except that the value 0xFFFFFFFF is reserved and means that the
     * Target Transfer Tag is not supplied.
     */
    uint32_t target_xfer_tag;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved2;

    /// ExpStatSN.
    uint32_t exp_stat_sn;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved3;

    /**
     * @brief DataSN.
     *
     * For output (write) data PDUs, the DataSN is the Data-Out PDU number
     * within the current output sequence. Either the current output
     * sequence is identified by the Initiator Task Tag (for unsolicited
     * data) or it is a data sequence generated for one R2T (for data
     * solicited through R2T).
     */
    uint32_t data_sn;

    /**
     * @brief Buffer Offset.
     *
     * The Buffer Offset field contains the offset of this PDU payload data
     * within the complete data transfer. The sum of the buffer offset and
     * length should not exceed the expected transfer length for the
     * command.\n
     * The order of data PDUs within a sequence is determined by
     * DataPDUInOrder. When set to Yes, it means that PDUs have to be in
     * increasing buffer offset order and overlays are forbidden.\n
     * The ordering between sequences is determined by DataSequenceInOrder.
     * When set to Yes, it means that sequences have to be in increasing
     * buffer offset order and overlays are forbidden.
     */
    uint32_t buf_offset;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved4;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /// Data segment.
    iscsi_scsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_scsi_data_out_req_packet;

/**
 * @brief SCSI Data In reponse flags: Status.
 *
 * (S) set to indicate that the Command Status field
 * contains status. If this bit is set to 1, the
 * F bit MUST also be set to 1.
 */
#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS        (1 << 0)

/**
 * @brief SCSI Data In reponse flags: Residual Underflow.
 *
 * (U) set for Residual Underflow. In this case, the Residual
 * Count indicates the number of bytes that were not
 * transferred out of the number of bytes that were expected
 * to be transferred. For a bidirectional operation, the
 * Residual Count contains the residual for the write
 * operation.
 */
#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_UNDERFLOW (1 << 1)

/**
 * @brief SCSI Data In reponse flags: Residual Overflow.
 *
 * (O) set for Residual Overflow. In this case, the Residual
 * Count indicates the number of bytes that were not
 * transferred because the initiator's Expected Data
 * Transfer Length was not sufficient. For a bidirectional
 * operation, the Residual Count contains the residual for
 * the write operation.
 */
#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_OVERFLOW  (1 << 2)

/**
 * @brief SCSI Data In reponse flags: ACK.
 *
 * (A) for sessions with ErrorRecoveryLevel=1 or higher, the target sets
 * this bit to 1 to indicate that it requests a positive acknowledgment
 * from the initiator for the data received. The target should use the
 * A bit moderately; it MAY only set the A bit to 1 once every
 * MaxBurstLength bytes, or on the last Data-In PDU that concludes the
 * entire requested read data transfer for the task from the target's
 * perspective, and it MUST NOT do so more frequently. The target MUST
 * NOT set to 1 the A bit for sessions with ErrorRecoveryLevel=0. The
 * initiator MUST ignore the A bit set to 1 for sessions with
 * ErrorRecoveryLevel=0.\n
 * On receiving a Data-In PDU with the A bit set to 1 on a session with
 * ErrorRecoveryLevel greater than 0, if there are no holes in the read
 * data until that Data-In PDU, the initiator MUST issue a SNACK of type
 * DataACK, except when it is able to acknowledge the status for the
 * task immediately via the ExpStatSN on other outbound PDUs if the
 * status for the task is also received. In the latter case
 * (acknowledgment through the ExpStatSN), sending a SNACK of type
 * DataACK in response to the A bit is OPTIONAL, but if it is done, it
 * must not be sent after the status acknowledgment through the
 * ExpStatSN. If the initiator has detected holes in the read data
 * prior to that Data-In PDU, it MUST postpone issuing the SNACK of type
 * DataACK until the holes are filled. An initiator also MUST NOT
 * acknowledge the status for the task before those holes are filled. A
 * status acknowledgment for a task that generated the Data-In PDUs is
 * considered by the target as an implicit acknowledgment of the Data-In
 * PDUs if such an acknowledgment was requested by the target.
 */
#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_ACK           (1 << 6)

/**
 * @brief SCSI Data In reponse flags: Final.
 *
 * (F) for outgoing data, this bit is 1 for the last PDU of unsolicited
 * data or the last PDU of a sequence that answers an R2T.
 * For incoming data, this bit is 1 for the last input (read) data PDU
 * of a sequence. Input can be split into several sequences, each
 * having its own F bit. Splitting the data stream into sequences does
 * not affect DataSN counting on Data-In PDUs. It MAY be used as a
 * "change direction" indication for bidirectional operations that need
 * such a change.\n
 * DataSegmentLength MUST NOT exceed MaxRecvDataSegmentLength for the
 * direction it is sent, and the total of all the DataSegmentLength of
 * all PDUs in a sequence MUST NOT exceed MaxBurstLength (or
 * FirstBurstLength for unsolicited data). However, the number of
 * individual PDUs in a sequence (or in total) may be higher than the
 * ratio of MaxBurstLength (or FirstBurstLength) to
 * MaxRecvDataSegmentLength (as PDUs may be limited in length by the
 * capabilities of the sender). Using a DataSegmentLength of 0 may
 * increase beyond what is reasonable for the number of PDUs and should
 * therefore be avoided.\n
 * For bidirectional operations, the F bit is 1 for both the end of the
 * input sequences and the end of the output sequences
 */
#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL         (1 << 7)

/**
 * @brief iSCSI SCSI Data In response packet data.
 *
 * THis structure is used by iSCSI for SCSI data input
 * responses, i.e. read operations.
 */
typedef struct __attribute__((packed)) iscsi_scsi_data_in_response_packet {
    /// Always 0x25 according to iSCSI specification.
    uint8_t opcode;

    /// Incoming data flags. The fields StatSN, Status, and Residual Count only have meaningful content if the S bit is set to 1.
    int8_t flags;

    /// Rserved for future usage, always MUST be 0.
    uint8_t reserved;

    /**
     * @brief Status or Reserved.
     *
     * Status can accompany the last Data-In PDU if the command did not end
     * with an exception (i.e., the status is "good status" - GOOD,
     * CONDITION MET, or INTERMEDIATE-CONDITION MET). The presence of
     * status (and of a residual count) is signaled via the S flag bit.
     * Although targets MAY choose to send even non-exception status in
     * separate responses, initiators MUST support non-exception status in
     * Data-In PDUs.
     */
    uint8_t status;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /**
     * @brief DataSegmentLength.
     *
     * This is the data payload length of a SCSI Data-In or SCSI Data-Out
     * PDU. The sending of 0-length data segments should be avoided, but
     * initiators and targets MUST be able to properly receive 0-length data
     * segments.\n
     * The data segments of Data-In and Data-Out PDUs SHOULD be filled to
     * the integer number of 4-byte words (real payload), unless the F bit
     * is set to 1.
     */
    uint8_t ds_len[3];

    /**
     * @brief Logical Unit Number (LUN) or Reserved.
     *
     * If the Target Transfer Tag is provided, then the LUN field MUST hold a
     * valid value and be consistent with whatever was specified with the command;
     * otherwise, the LUN field is reserved.
     */
    uint64_t lun;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /**
     * @brief Target Transfer Tag or 0xFFFFFFFF.
     *
     * On incoming data, the Target Transfer Tag and LUN MUST be provided by
     * the target if the A bit is set to 1; otherwise, they are reserved.
     * The Target Transfer Tag and LUN are copied by the initiator into the
     * SNACK of type DataACK that it issues as a result of receiving a SCSI
     * Data-In PDU with the A bit set to 1.\n
     * The Target Transfer Tag values are not specified by this protocol,
     * except that the value 0xFFFFFFFF is reserved and means that the
     * Target Transfer Tag is not supplied.
     */
    uint32_t target_xfer_tag;

    /// StatSN.
    uint32_t stat_sn;

    /// ExpCmdSN.

    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /**
     * @brief DataSN.
     *
     * For input (read) or bidirectional Data-In PDUs, the DataSN is the
     * input PDU number within the data transfer for the command identified
     * by the Initiator Task Tag.\n
     * R2T and Data-In PDUs, in the context of bidirectional commands, share
     * the numbering sequence.
     */
    uint32_t data_sn;

    /**
     * @brief Buffer Offset.
     *
     * The Buffer Offset field contains the offset of this PDU payload data
     * within the complete data transfer. The sum of the buffer offset and
     * length should not exceed the expected transfer length for the
     * command.\n
     * The order of data PDUs within a sequence is determined by
     * DataPDUInOrder. When set to Yes, it means that PDUs have to be in
     * increasing buffer offset order and overlays are forbidden.\n
     * The ordering between sequences is determined by DataSequenceInOrder.
     * When set to Yes, it means that sequences have to be in increasing
     * buffer offset order and overlays are forbidden.
     */
    uint32_t buf_offset;

    /// Residual Count or Reserved.
    uint32_t res_cnt;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /// Data segment.
    iscsi_scsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_scsi_data_in_response_packet;

/**
 * @brief iSCSI Ready To Transfer packet data.
 *
 * When an initiator has submitted a SCSI command with data that passes
 * from the initiator to the target (write), the target may specify
 * which blocks of data it is ready to receive. The target may request
 * that the data blocks be delivered in whichever order is convenient
 * for the target at that particular instant. This information is
 * passed from the target to the initiator in the Ready To Transfer
 * (R2T) PDU.
 *
 * In order to allow write operations without an explicit initial R2T,
 * the initiator and target MUST have negotiated the key InitialR2T to
 * No during login.
 *
 * An R2T MAY be answered with one or more SCSI Data-Out PDUs with a
 * matching Target Transfer Tag. If an R2T is answered with a single
 * Data-Out PDU, the buffer offset in the data PDU MUST be the same as
 * the one specified by the R2T, and the data length of the data PDU
 * MUST be the same as the Desired Data Transfer Length specified in the
 * R2T. If the R2T is answered with a sequence of data PDUs, the buffer
 * offset and length MUST be within the range of those specified by the
 * R2T, and the last PDU MUST have the F bit set to 1. If the last PDU
 * (marked with the F bit) is received before the Desired Data Transfer
 * Length is transferred, a target MAY choose to reject that PDU with
 * the "Protocol Error" reason code. DataPDUInOrder governs the
 * Data-Out PDU ordering. If DataPDUInOrder is set to Yes, the buffer
 * offsets and lengths for consecutive PDUs MUST form a continuous
 * non-overlapping range, and the PDUs MUST be sent in increasing offset
 * order.
 *
 * The target may send several R2T PDUs. It therefore can have a number
 * of pending data transfers. The number of outstanding R2T PDUs is
 * limited by the value of the negotiated key MaxOutstandingR2T. Within
 * a task, outstanding R2Ts MUST be fulfilled by the initiator in the
 * order in which they were received.
 *
 * R2T PDUs MAY also be used to recover Data-Out PDUs. Such an R2T
 * (Recovery-R2T) is generated by a target upon detecting the loss of
 * one or more Data-Out PDUs due to:
 *
 *    - Digest error
 *
 *    - Sequence error
 *
 *    - Sequence reception timeout
 *
 * A Recovery-R2T carries the next unused R2TSN but requests part of or
 * the entire data burst that an earlier R2T (with a lower R2TSN) had
 * already requested.
 *
 * DataSequenceInOrder governs the buffer offset ordering in consecutive
 * R2Ts. If DataSequenceInOrder is Yes, then consecutive R2Ts MUST
 * refer to continuous non-overlapping ranges, except for Recovery-R2Ts.
 */
typedef struct __attribute__((packed)) iscsi_r2t_packet {
    /// Always 0x31 according to iSCSI specification.
    uint8_t opcode;

    /// Reserved for future usage (always MUST be 0x80 for now).
    int8_t flags;

    /// Reserved for future usage, always MUST be 0 for now.
    uint16_t reserved;

    /// TotalAHSLength, MUST be 0 for this PDU.
    uint8_t total_ahs_len;

    /// DataSegmentLength, MUST be 0 0 for this PDU.
    uint8_t ds_len[3];

    /// Logical Unit Number (LUN) or Reserved.
    uint64_t lun;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /// Target Transfer Tag (TTT).
    uint32_t target_xfer_tag;

    /// The StatSN field will contain the next StatSN. The StatSN for this connection is not advanced after this PDU is sent.
    uint32_t stat_sn;

    /// ExpCmdSN.
    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /// DataSN.
    uint32_t data_sn;

    /// Ready To Transfer Sequence Number (R2TSN) is the R2T PDU input PDU number within the command identified by the Initiator Task Tag. For bidirectional commands, R2T and Data-In PDUs share the input PDU numbering sequence.
    uint32_t r2t_sn;

    /**
     * @brief Buffer Offset.
     *
     * The target therefore also specifies a buffer offset that indicates
     * the point at which the data transfer should begin, relative to the
     * beginning of the total data transfer.
     */
    uint32_t buf_offset;

    /**
     * @brief Desired Data Transfer Length.
     *
     * The target specifies how many bytes it wants the initiator to send
     * because of this R2T PDU. The target may request the data from the
     * initiator in several chunks, not necessarily in the original order of
     * the data. The Desired Data Transfer Length MUST NOT be 0 and MUST NOT
     * exceed MaxBurstLength.
     */
    uint32_t des_data_xfer_len;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;
} iscsi_r2t_packet;


/**
 * @brief SCSI Asynchronous Message Event: SCSI Async Event.
 *
 * A SCSI asynchronous event is reported in the sense data.
 * Sense Data that accompanies the report, in the data
 * segment, identifies the condition. The sending of a
 * SCSI event ("asynchronous event reporting" in SCSI
 * terminology) is dependent on the target support for SCSI
 * asynchronous event reporting as indicated in the
 * standard INQUIRY data. Its use may be enabled by
 * parameters in the SCSI Control mode page.
 */
#define ISCSI_ASYNC_MSG_EVENT_SCSI_ASYNC_EVENT    0x00

/**
 * @brief SCSI Asynchronous Message Event: Logout Request.
 *
 * The target requests Logout. This Async Message MUST
 * be sent on the same connection as the one requesting
 * to be logged out. The initiator MUST honor this request
 * by issuing a Logout as early as possible but no later
 * than Parameter3 seconds. The initiator MUST send a Logout
 * with a reason code of "close the connection" OR "close the
 * session" to close all the connections. Once this message is
 * received, the initiator SHOULD NOT issue new iSCSI commands on
 * the connection to be logged out. The target MAY reject any
 * new I/O requests that it receives after this message with the
 * reason code "Waiting for Logout". If the initiator does not
 * log out in Parameter3 seconds, the target should send an Async
 * PDU with iSCSI event code "Dropped the connection" if possible
 * or simply terminate the transport connection. Parameter1 and
 * Parameter2 are reserved.
 */
#define ISCSI_ASYNC_MSG_EVENT_LOGOUT_REQUEST      0x01

/**
 * @brief SCSI Asynchronous Message Event: Connection Drop Notification.
 *
 * The target indicates that it will drop the connection.
 * The Parameter1 field indicates the CID of the connection that
 * is going to be dropped.\n
 * The Parameter2 field (Time2Wait) indicates, in seconds, the
 * minimum time to wait before attempting to reconnect or
 * reassign.\n
 * The Parameter3 field (Time2Retain) indicates the maximum time
 * allowed to reassign commands after the initial wait (in
 * Parameter2).\n
 * If the initiator does not attempt to reconnect and/or reassign
 * the outstanding commands within the time specified by
 * Parameter3, or if Parameter3 is 0, the target will terminate
 * all outstanding commands on this connection. In this case, no
 * other responses should be expected from the target for the
 * outstanding commands on this connection.\n
 * A value of 0 for Parameter2 indicates that reconnect can be
 * attempted immediately.
 */
#define ISCSI_ASYNC_MSG_EVENT_CONNECT_DROP_NOTIFY 0x02

/**
 * @brief SCSI Asynchronous Message Event: Session Drop Notification.
 *
 * The target indicates that it will drop all the connections
 * of this session.\n
 * The Parameter1 field is reserved.\n
 * The Parameter2 field (Time2Wait) indicates, in seconds, the
 * minimum time to wait before attempting to reconnect.\n
 * The Parameter3 field (Time2Retain) indicates the maximum time
 * allowed to reassign commands after the initial wait (in
 * Parameter2).\n
 * If the initiator does not attempt to reconnect and/or reassign
 * the outstanding commands within the time specified by
 * Parameter3, or if Parameter3 is 0, the session is terminated.\n
 * In this case, the target will terminate all outstanding
 * commands in this session; no other responses should be
 * expected from the target for the outstanding commands in this
 * session. A value of 0 for Parameter2 indicates that reconnect
 * can be attempted immediately.
 */
#define ISCSI_ASYNC_MSG_EVENT_SESSION_DROP_NOTIFY 0x03

/**
 * @brief SCSI Asynchronous Message Event: Negotiation Request.
 *
 * The target requests parameter negotiation on this connection.
 * The initiator MUST honor this request by issuing a Text
 * Request (that can be empty) on the same connection as early
 * as possible, but no later than Parameter3 seconds, unless a
 * Text Request is already pending on the connection, or by
 * issuing a Logout Request. If the initiator does not issue a
 * Text Request, the target may reissue the Asynchronous Message
 * requesting parameter negotiation.
 */
#define ISCSI_ASYNC_MSG_EVENT_NEGOTIATION_REQUEST 0x04

/**
 * @brief SCSI Asynchronous Message Event: Task Termination.
 *
 * All active tasks for a LU with a matching LUN field in the
 * Async Message PDU are being terminated. The receiving
 * initiator iSCSI layer MUST respond to this message by
 * taking the following steps, in order:
 * - Stop Data-Out transfers on that connection for all active
 *   TTTs for the affected LUN quoted in the Async Message PDU.
 * - Acknowledge the StatSN of the Async Message PDU via a
 *   NOP-Out PDU with ITT=0xFFFFFFFF (i.e., non-ping flavor),
 *   while copying the LUN field from the Async Message to
 *   NOP-Out.
 * This value of AsyncEvent, however, MUST NOT be used on an
 * iSCSI session unless the new TaskReporting text key was
 * negotiated to FastAbort on the session.
 */
#define ISCSI_ASYNC_MSG_EVENT_TASK_TERMINATION    0x05

/// SCSI Asynchronous Message Event: First vendor-specific iSCSI event. The AsyncVCode details the vendor code, and data MAY accompany the report.
#define ISCSI_ASYNC_MSG_EVENT_VENDOR_FIRST        0xF8

/// SCSI Asynchronous Message Event: Last vendor-specific iSCSI event. The AsyncVCode details the vendor code, and data MAY accompany the report.
#define ISCSI_ASYNC_MSG_EVENT_VENDOR_LAST         0xFF

/**
 * @brief iSCSI Asynchronous Message packet data.
 *
 * An Asynchronous Message may be sent from the target to the initiator
 * without corresponding to a particular command. The target specifies
 * the reason for the event and sense data.\n
 * Some Asynchronous Messages are strictly related to iSCSI, while
 * others are related to SCSI
 */
typedef struct __attribute__((packed)) iscsi_async_msg_packet {
    /// Always 0x32 according to iSCSI specification.
    uint8_t opcode;

    /// Reserved for future usage (always MUST be 0x80 for now).
    int8_t flags;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength, MUST be 0 for this PDU.
    uint8_t total_ahs_len;

    /// DataSegmentLength, MUST be 0 0 for this PDU.
    uint8_t ds_len[3];

    /// The LUN field MUST be valid if AsyncEvent is 0. Otherwise, this field is reserved.
    uint64_t lun;

    /// Tag (always 0xFFFFFFFF for now).
    uint32_t tag;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved2;

    /**
     * @brief StatSN.
     *
     * The StatSN counts this PDU as an acknowledgeable event (the StatSN is
     * advanced), which allows for initiator and target state synchronization.
     */
    uint32_t stat_sn;

    /// ExpCmdSN.
    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /// AsyncEvent.
    uint8_t async_event;

    /// AsyncVCode is a vendor-specific detail code that is only valid if the AsyncEvent field indicates a vendor-specific event. Otherwise, it is reserved.
    uint8_t async_vcode;

    /// Parameter1 or Reserved.
    uint16_t param_1;

    /// Parameter2 or Reserved.
    uint16_t param_2;

    /// Parameter3 or Reserved.
    uint16_t param_3;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved3;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /// Data segment.
    iscsi_scsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_async_msg_packet;


/**
 * @brief Text Request flags: Continue.
 *
 * (C) When set to 1, this bit indicates that the text (set of key=value
 * pairs) in this Text Request is not complete (it will be continued on
 * subsequent Text Requests); otherwise, it indicates that this Text
 * Request ends a set of key=value pairs. A Text Request with the C bit
 * set to 1 MUST have the F bit set to 0.
 */
#define ISCSI_TEXT_REQ_FLAGS_CONTINUE (1 << 6)

/**
 * @brief Text Request flags: Final.
 *
 * (F) When set to 1, this bit indicates that this is the last or only Text
 * Request in a sequence of Text Requests; otherwise, it indicates that
 * more Text Requests will follow.
 */
#define ISCSI_TEXT_REQ_FLAGS_FINAL    (1 << 7)

/**
 * @brief iSCSI Text Request packet data.
 *
 * The Text Request is provided to allow for the exchange of information
 * and for future extensions. It permits the initiator to inform a
 * target of its capabilities or request some special operations.
 *
 * An initiator MUST NOT have more than one outstanding Text Request on
 * a connection at any given time.
 *
 * On a connection failure, an initiator must either explicitly abort
 * any active allegiant text negotiation task or cause such a task to be
 * implicitly terminated by the target.
 */
typedef struct __attribute__((packed)) iscsi_text_req_packet {
    /// Always 0x04 according to iSCSI specification.
    uint8_t opcode;

    /// Text request flags.
    int8_t flags;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /// DataSegmentLength.
    uint8_t ds_len[3];

    /// Logical Unit Number (LUN) or Reserved.
    uint64_t lun;

    /**
     * @brief Initiator Task Tag (ITT).
     *
     * This is the initiator-assigned identifier for this Text Request. If
     * the command is sent as part of a sequence of Text Requests and
     * responses, the Initiator Task Tag MUST be the same for all the
     * requests within the sequence (similar to linked SCSI commands). The
     * I bit for all requests in a sequence also MUST be the same.
     */
    uint32_t init_task_tag;

    /**
     * @brief Target Transfer Tag (TTT).
     *
     * When the Target Transfer Tag is set to the reserved value 0xFFFFFFFF,
     * it tells the target that this is a new request, and the target resets
     * any internal state associated with the Initiator Task Tag (resets the
     * current negotiation state).\n
     * The target sets the Target Transfer Tag in a Text Response to a value
     * other than the reserved value 0xFFFFFFFF whenever it indicates that
     * it has more data to send or more operations to perform that are
     * associated with the specified Initiator Task Tag. It MUST do so
     * whenever it sets the F bit to 0 in the response. By copying the
     * Target Transfer Tag from the response to the next Text Request, the
     * initiator tells the target to continue the operation for the specific
     * Initiator Task Tag. The initiator MUST ignore the Target Transfer
     * Tag in the Text Response when the F bit is set to 1.\n
     * This mechanism allows the initiator and target to transfer a large
     * amount of textual data over a sequence of text-command/text-response
     * exchanges or to perform extended negotiation sequences.\n
     * If the Target Transfer Tag is not 0xFFFFFFFF, the LUN field MUST be
     * sent by the target in the Text Response.\n
     * A target MAY reset its internal negotiation state if an exchange is
     * stalled by the initiator for a long time or if it is running out of
     * resources.\n
     * Long Text Responses are handled as shown in the following example:\n
     * @verbatim
     *    I->T Text SendTargets=All (F = 1, TTT = 0xFFFFFFFF)
     *    T->I Text <part 1> (F = 0, TTT = 0x12345678)
     *    I->T Text <empty> (F = 1, TTT = 0x12345678)
     *    T->I Text <part 2> (F = 0, TTT = 0x12345678)
     *    I->T Text <empty> (F = 1, TTT = 0x12345678)
     *    ...
     *    T->I Text <part n> (F = 1, TTT = 0xFFFFFFFF)
     * @endverbatim
     */
    uint32_t target_xfer_tag;

    /// CmdSN.
    uint32_t cmd_sn;

    /// ExpStatSN.
    uint32_t exp_stat_sn;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2[2];

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /**
     * @brief Data segment.
     *
     * The data lengths of a Text Request MUST NOT exceed the iSCSI target
     * MaxRecvDataSegmentLength (a parameter that is negotiated per
     * connection and per direction).\n
     * A key=value pair can span Text Request or Text Response boundaries.
     * A key=value pair can start in one PDU and continue on the next. In
     * other words, the end of a PDU does not necessarily signal the end of
     * a key=value pair.\n
     * The target responds by sending its response back to the initiator.
     * The response text format is similar to the request text format. The
     * Text Response MAY refer to key=value pairs presented in an earlier
     * Text Request, and the text in the request may refer to earlier
     * responses.\n
     * Text operations are usually meant for parameter setting/negotiations
     * but can also be used to perform some long-lasting operations.
     */
    iscsi_scsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_text_req_packet;


/**
 * @brief Text Response flags: Continue.
 *
 * (C) When set to 1, this bit indicates that the text (set of key=value
 * pairs) in this Text Response is not complete (it will be continued on
 * subsequent Text Responses); otherwise, it indicates that this Text
 * Response ends a set of key=value pairs. A Text Response with the
 * C bit set to 1 MUST have the F bit set to 0.
 */
#define ISCSI_TEXT_RESPONSE_FLAGS_CONTINUE (1 << 6)

/**
 * @brief Text Response flags: Final.
 *
 * (F) When set to 1, in response to a Text Request with the Final bit set
 * to 1, the F bit indicates that the target has finished the whole
 * operation. Otherwise, if set to 0 in response to a Text Request with
 * the Final Bit set to 1, it indicates that the target has more work to
 * do (invites a follow-on Text Request). A Text Response with the
 * F bit set to 1 in response to a Text Request with the F bit set to 0
 * is a protocol error.\n
 * A Text Response with the F bit set to 1 MUST NOT contain key=value
 * pairs that may require additional answers from the initiator.
 * A Text Response with the F bit set to 1 MUST have a Target Transfer
 * Tag field set to the reserved value 0xFFFFFFFF.\n
 * A Text Response with the F bit set to 0 MUST have a Target Transfer
 * Tag field set to a value other than the reserved value 0xFFFFFFFF.
 */
#define ISCSI_TEXT_RESPONSE_FLAGS_FINAL    (1 << 7)

/**
 * @brief iSCSI Text Response packet data.
 *
 * The Text Response PDU contains the target's responses to the
 * initiator's Text Request. The format of the Text field matches that
 * of the Text Request.
 */
typedef struct __attribute__((packed)) iscsi_text_response_packet {
    /// Always 0x24 according to iSCSI specification.
    uint8_t opcode;

    /// Text response flags.
    int8_t flags;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /// DataSegmentLength.
    uint8_t ds_len[3];

    /// Logical Unit Number (LUN) or Reserved.
    uint64_t lun;

    /// The Initiator Task Tag matches the tag used in the initial Text Request.
    uint32_t init_task_tag;

    /**
     * @brief Target Transfer Tag (TTT).
     *
     * When a target has more work to do (e.g., cannot transfer all the
     * remaining text data in a single Text Response or has to continue the
     * negotiation) and has enough resources to proceed, it MUST set the
     * Target Transfer Tag to a value other than the reserved value
     * 0xFFFFFFFF. Otherwise, the Target Transfer Tag MUST be set to
     * 0xFFFFFFFF.\n
     * When the Target Transfer Tag is not 0xFFFFFFFF, the LUN field may be
     * significant.\n
     * The initiator MUST copy the Target Transfer Tag and LUN in its next
     * request to indicate that it wants the rest of the data.\n
     * When the target receives a Text Request with the Target Transfer Tag
     * set to the reserved value 0xFFFFFFFF, it resets its internal
     * information (resets state) associated with the given Initiator Task
     * Tag (restarts the negotiation).\n
     * When a target cannot finish the operation in a single Text Response
     * and does not have enough resources to continue, it rejects the Text
     * Request with the appropriate Reject code.\n
     * A target may reset its internal state associated with an Initiator
     * Task Tag (the current negotiation state) as expressed through the
     * Target Transfer Tag if the initiator fails to continue the exchange
     * for some time. The target may reject subsequent Text Requests with
     * the Target Transfer Tag set to the "stale" value.
     */
    uint32_t target_xfer_tag;

    /// StatSN. The target StatSN variable is advanced by each Text Response sent.
    uint32_t stat_sn;

    /// ExpCmdSN.
    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2[2];

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /**
     * @brief Data segment.
     *
     * The data lengths of a Text Response MUST NOT exceed the iSCSI
     * initiator MaxRecvDataSegmentLength (a parameter that is negotiated
     * per connection and per direction).\n
     * The text in the Text Response Data is governed by the same rules as
     * the text in the Text Request Data.\n
     * Although the initiator is the requesting party and controls the
     * request-response initiation and termination, the target can offer
     * key=value pairs of its own as part of a sequence and not only in
     * response to the initiator.
     */
    iscsi_scsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_text_response_packet;


/**
 * @brief iSCSI Initiator Session ID (ISID) type: OUI-Format.
 *
 * A and B: 22-bit OUI
 * (the I/G and U/L bits are omitted)
 * C and D: 24-bit Qualifier.
 */
#define ISCSI_ISID_TYPE_FORMAT_OUI       0x0

/**
 * @brief iSCSI Initiator Session ID (ISID) type: EN: Format (IANA Enterprise Number).
 *
 * A: Reserved
 * B and C: EN (IANA Enterprise Number)
 * D: Qualifier
 */
#define ISCSI_ISID_TYPE_FORMAT_EN        0x1

/**
 * @brief iSCSI Initiator Session ID (ISID) type: Random.
 *
 * A: Reserved
 * B and C: Random
 * D: Qualifier
 */
#define ISCSI_ISID_TYPE_FORMAT_RANDOM    0x2

/// iSCSI Initiator Session ID (ISID) type format: First bit of the two bits.
#define ISCSI_ISID_TYPE_FORMAT_FIRST_BIT 6

/// iSCSI Initiator Session ID (ISID) type format: Last bit of the two bits.
#define ISCSI_ISID_TYPE_FORMAT_LAST_BIT  ((ISCSI_ISID_TYPE_FORMAT_FIRST_BIT) + 2 - 1)

/// iSCSI Initiator Session ID (ISID) type format: Bit mask.
#define ISCSI_ISID_TYPE_FORMAT_MASK      (ISCSI_BITS_GET_MASK(ISCSI_ISID_TYPE_FORMAT_FIRST_BIT, ISCSI_ISID_TYPE_FORMAT_LAST_BIT))

/// iSCSI Initiator Session ID (ISID) type format: Extracts the type format.
#define ISCSI_ISID_GET_TYPE_FORMAT(x)    (ISCSI_BITS_GET((x), ISCSI_ISID_TYPE_FORMAT_FIRST_BIT, ISCSI_ISID_TYPE_FORMAT_LAST_BIT))

/// iSCSI Initiator Session ID (ISID) type format: Stores into the type format.
#define ISCSI_ISID_PUT_TYPE_FORMAT(x)    (ISCSI_BITS_PUT((x), ISCSI_ISID_TYPE_FORMAT_FIRST_BIT, ISCSI_ISID_TYPE_FORMAT_LAST_BIT))


/**
 * @brief iSCSI Initiator Session ID (ISID) packet data.
 *
 * This is an initiator-defined component of the session identifier and
 * is structured as follows:
 *
 * For the T field values 00b and 01b, a combination of A and B (for
 * 00b) or B and C (for 01b) identifies the vendor or organization whose
 * component (software or hardware) generates this ISID. A vendor or
 * organization with one or more OUIs, or one or more Enterprise
 * Numbers, MUST use at least one of these numbers and select the
 * appropriate value for the T field when its components generate ISIDs.
 * An OUI or EN MUST be set in the corresponding fields in network byte
 * order (byte big-endian).
 *
 * If the T field is 10b, B and C are set to a random 24-bit unsigned
 * integer value in network byte order (byte big-endian).
 *
 * The Qualifier field is a 16-bit or 24-bit unsigned integer value that
 * provides a range of possible values for the ISID within the selected
 * namespace. It may be set to any value within the constraints
 * specified in the iSCSI protocol.
 *
 * If the ISID is derived from something assigned to a hardware adapter
 * or interface by a vendor as a preset default value, it MUST be
 * configurable to a value assigned according to the SCSI port behavior
 * desired by the system in which it is installed. The resultant ISID
 * MUST also be persistent over power cycles, reboot, card swap, etc.
 */
typedef struct __attribute__((packed)) iscsi_isid {
    /// Meaning depends on T bit, either 22-bit OUI or reserved.
    uint8_t a;

    /// Meaning depends on T bit, either 22-bit OUI, EN (IANA Enterprise Number) or random.
    uint16_t b;

    /// Meaning depends on T bit, either 24-bit Qualifier, EN (IANA Enterprise Number) or random.
    uint8_t c;

    /// Meaning depends on T bit, either 24-bit Qualifier or Qualifier.
    uint16_t d;
} iscsi_isid;


/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Session type.
 *
 * @verbatim
 * Use: LO, Declarative, Any-Stage
 * Senders: Initiator
 * Scope: SW
 * SessionType=<Discovery|Normal>
 * Default is Normal.
 * @endverbatim
 * The initiator indicates the type of session it wants to create. The
 * target can either accept it or reject it.\n
 * A Discovery session indicates to the target that the only purpose of
 * this session is discovery. The only requests a target accepts in
 * this type of session are a Text Request with a SendTargets key and a
 * Logout Request with reason "close the session".\n
 * The Discovery session implies MaxConnections = 1 and overrides both
 * the default and an explicit setting. ErrorRecoveryLevel MUST be 0
 * (zero) for Discovery sessions.\n
 * Depending on the type of session, a target may decide on resources to
 * allocate, the security to enforce, etc., for the session. If the
 * SessionType key is thus going to be offered as "Discovery", it SHOULD
 * be offered in the initial Login Request by the initiator.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE            ((const uint8_t *) "SessionType\0\0\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Initiator name.
 *
 * @verbatim
 * Use: IO, Declarative, Any-Stage
 * Senders: Initiator
 * Scope: SW
 * InitiatorName=<iSCSI-name-value>
 * Examples:
 *    InitiatorName=iqn.1992-04.de.uni-freiburg.bwlehrpool:qcow2.5003
 *    InitiatorName=iqn.2001-02.de.uni-freiburg.matrix:basty.eduroam
 *    InitiatorName=naa.52004567BA64678D
 * @endverbatim
 * The initiator of the TCP connection MUST provide this key to the
 * remote endpoint at the first login of the Login Phase for every
 * connection. The InitiatorName key enables the initiator to identify
 * itself to the remote endpoint.\n
 * The InitiatorName MUST NOT be redeclared within the Login Phase.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_NAME          ((const uint8_t *) "InitiatorName\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Target name.
 *
 * @verbatim
 * Use: IO by initiator, FFPO by target - only as response to a
 * SendTargets, Declarative, Any-Stage
 * Senders: Initiator and target
 * Scope: SW
 * TargetName=<iSCSI-name-value>
 * Examples:
 *    TargetName=iqn.1993-11.de.uni-freiburg:diskarrays.sn.5003
 *    TargetName=eui.020000023B040506
 *    TargetName=naa.62004567BA64678D0123456789ABCDEF
 * @endverbatim
 * The initiator of the TCP connection MUST provide this key to the
 * remote endpoint in the first Login Request if the initiator is not
 * establishing a Discovery session. The iSCSI Target Name specifies
 * the worldwide unique name of the target.\n
 * The TargetName key may also be returned by the SendTargets Text
 * Request (which is its only use when issued by a target).\n
 * The TargetName MUST NOT be redeclared within the Login Phase.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_NAME             ((const uint8_t *) "TargetName\0\0\0\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Target address.
 *
 * @verbatim
 * Use: ALL, Declarative, Any-Stage
 * Senders: Target
 * Scope: SW
 * TargetAddress=domainname[:port][,portal-group-tag]
 * @endverbatim
 * The domainname can be specified as either a DNS host name, a dotted-
 * decimal IPv4 address, or a bracketed IPv6 address as specified in
 * RFC3986.\n
 * If the TCP port is not specified, it is assumed to be the IANA-
 * assigned default port for iSCSI.\n
 * If the TargetAddress is returned as the result of a redirect status
 * in a Login Response, the comma and portal-group-tag MUST be omitted.
 * If the TargetAddress is returned within a SendTargets response, the
 * portal-group-tag MUST be included.\n
 * @verbatim
 * Examples:
 *    TargetAddress=10.0.0.1:5003,1
 *    TargetAddress=[1080:0:0:0:8:800:200C:417A],65
 *    TargetAddress=[1080::8:800:200C:417A]:5003,1
 *    TargetAddress=gitlab.uni-freiburg.de,443
 * @endverbatim
 * The formats for the port and portal-group-tag are the same as the one
 * specified in TargetPortalGroupTag.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS          ((const uint8_t *) "TargetAddress\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Initiator alias.
 *
 * @verbatim
 * Use: ALL, Declarative, Any-Stage
 * Senders: Initiator
 * Scope: SW
 * InitiatorAlias=<iSCSI-local-name-value>
 * Examples:
 *    InitiatorAlias=Web Server 5
 *    InitiatorAlias=matrix.uni-freiburg.de
 *    InitiatorAlias=Matrix Server
 * @endverbatim
 * If an initiator has been configured with a human-readable name or
 * description, it SHOULD be communicated to the target during a Login
 * Request PDU. If not, the host name can be used instead. This string
 * is not used as an identifier, nor is it meant to be used for
 * authentication or authorization decisions. It can be displayed by
 * the target's user interface in a list of initiators to which it is
 * connected.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_ALIAS         ((const uint8_t *) "InitiatorAlias\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Target alias.
 *
 * @verbatim
 * Use: ALL, Declarative, Any-Stage
 * Senders: Target
 * Scope: SW
 * TargetAlias=<iSCSI-local-name-value>
 * Examples:
 *    TargetAlias=Bob-s Disk
 *    TargetAlias=Database Server 1 Log Disk
 *    TargetAlias=Web Server 3 Disk 20
 * @endverbatim
 * If a target has been configured with a human-readable name or
 * description, this name SHOULD be communicated to the initiator during
 * a Login Response PDU if SessionType=Normal. This string is not used
 * as an identifier, nor is it meant to be used for authentication or
 * authorization decisions. It can be displayed by the initiator's user
 * interface in a list of targets to which it is connected.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS            ((const uint8_t *) "TargetAlias\0\0\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Target portal group tag.
 *
 * @verbatim
 * Use: IO by target, Declarative, Any-Stage
 * Senders: Target
 * Scope: SW
 * TargetPortalGroupTag=<16-bit-binary-value>
 * Example:
 *    TargetPortalGroupTag=1
 * @endverbatim
 * The TargetPortalGroupTag key is a 16-bit binary-value that uniquely
 * identifies a portal group within an iSCSI target node. This key
 * carries the value of the tag of the portal group that is servicing
 * the Login Request. The iSCSI target returns this key to the
 * initiator in the Login Response PDU to the first Login Request PDU
 * that has the C bit set to 0 when TargetName is given by the
 * initiator.\n
 * SAM2 notes in its informative text that the TPGT value should be
 * non-zero; note that this is incorrect. A zero value is allowed as a
 * legal value for the TPGT. This discrepancy currently stands
 * corrected in SAM4.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG ((const uint8_t *) "TargetPortalGroupTag\0\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Authentication method.
 *
 * @verbatim
 * Use: During Login - Security Negotiation
 * Senders: Initiator and target
 * Scope: connection
 * AuthMethod = <list-of-values>
 * @endverbatim
 * The main item of security negotiation is the authentication method
 * (AuthMethod).\n
 * The authentication methods that can be used (appear in the list-of-
 * values) are either vendor-unique methods or those listed in the
 * following table:
 * Name | Description
 * :--- | :---------------------------------------------------------------
 * KRB5 | Kerberos V5 - defined in RFC4120
 * SRP  | Secure Remote Password - defined in RFC2945
 * CHAP | Challenge Handshake Authentication Protocol - defined in RFC1994
 * None | No authentication
 *
 * The AuthMethod selection is followed by an "authentication exchange"
 * specific to the authentication method selected.\n
 * The authentication method proposal may be made by either the
 * initiator or the target. However, the initiator MUST make the first
 * step specific to the selected authentication method as soon as it is
 * selected. It follows that if the target makes the authentication
 * method proposal, the initiator sends the first key(s) of the exchange
 * together with its authentication method selection.\n
 * The authentication exchange authenticates the initiator to the target
 * and, optionally, the target to the initiator. Authentication is
 * OPTIONAL to use but MUST be supported by the target and initiator.
 * The initiator and target MUST implement CHAP. All other
 * authentication methods are OPTIONAL.\n
 * Private or public extension algorithms MAY also be negotiated for
 * authentication methods. Whenever a private or public extension
 * algorithm is part of the default offer (the offer made in the absence
 * of explicit administrative action), the implementer MUST ensure that
 * CHAP is listed as an alternative in the default offer and "None" is
 * not part of the default offer.\n
 * Extension authentication methods MUST be named using one of the
 * following two formats:
 *    -# Z-reversed.vendor.dns_name.do_something=
 *    -# New public key with no name prefix constraints
 *
 * Authentication methods named using the Z- format are used as private
 * extensions. New public keys must be registered with IANA using the
 * IETF Review process RFC5226. New public extensions for
 * authentication methods MUST NOT use the Z# name prefix.\n
 * For all of the public or private extension authentication methods,
 * the method-specific keys MUST conform to the format specified for
 * standard-label.\n
 * To identify the vendor for private extension authentication methods,
 * we suggest using the reversed DNS-name as a prefix to the proper
 * digest names.\n
 * The part of digest-name following Z- MUST conform to the format for
 * standard-label.\n
 * Support for public or private extension authentication methods is
 * OPTIONAL.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD             ((const uint8_t *) "AuthMethod\0\0\0\0\0")


/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Kerberos V5 (KRB5): KRB_AP_REQ.
 *
 * For KRB5 (Kerberos V5) (see RFC4120 and RFC1964), the initiator MUST use:
 * @verbatim
 *    KRB_AP_REQ=<KRB_AP_REQ>
 * @endverbatim
 * where KRB_AP_REQ is the client message as defined in RFC4120.
 * The default principal name assumed by an iSCSI initiator or target
 * (prior to any administrative configuration action) MUST be the iSCSI
 * Initiator Name or iSCSI Target Name, respectively, prefixed by the
 * string "iscsi/".\n
 * If the initiator authentication fails, the target MUST respond with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator has selected the mutual authentication option (by setting
 * MUTUAL-REQUIRED in the ap-options field of the KRB_AP_REQ), the
 * target MUST reply with:
 * @verbatim
 *    KRB_AP_REP=<KRB_AP_REP>
 * @endverbatim
 * where KRB_AP_REP is the server's response message as defined in
 * RFC4120.\n
 * If mutual authentication was selected and target authentication
 * fails, the initiator MUST close the connection.\n
 * KRB_AP_REQ and KRB_AP_REP are binary-values, and their binary length
 * (not the length of the character string that represents them in
 * encoded form) MUST NOT exceed 65536 bytes. Hex or Base64 encoding
 * may be used for KRB_AP_REQ and KRB_AP_REP.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_KRB_AP_REQ ((const uint8_t *) "KRB_AP_REQ\0\0\0\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Kerberos V5 (KRB5): KRB_AP_REP.
 *
 * For KRB5 (Kerberos V5) (see RFC4120 and RFC1964), the initiator MUST use:
 * @verbatim
 *    KRB_AP_REQ=<KRB_AP_REQ>
 * @endverbatim
 * where KRB_AP_REQ is the client message as defined in RFC4120.
 * The default principal name assumed by an iSCSI initiator or target
 * (prior to any administrative configuration action) MUST be the iSCSI
 * Initiator Name or iSCSI Target Name, respectively, prefixed by the
 * string "iscsi/".\n
 * If the initiator authentication fails, the target MUST respond with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator has selected the mutual authentication option (by setting
 * MUTUAL-REQUIRED in the ap-options field of the KRB_AP_REQ), the
 * target MUST reply with:
 * @verbatim
 *    KRB_AP_REP=<KRB_AP_REP>
 * @endverbatim
 * where KRB_AP_REP is the server's response message as defined in
 * RFC4120.\n
 * If mutual authentication was selected and target authentication
 * fails, the initiator MUST close the connection.\n
 * KRB_AP_REQ and KRB_AP_REP are binary-values, and their binary length
 * (not the length of the character string that represents them in
 * encoded form) MUST NOT exceed 65536 bytes. Hex or Base64 encoding
 * may be used for KRB_AP_REQ and KRB_AP_REP.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_KRB_AP_REP ((const uint8_t *) "KRB_AP_REP\0\0\0\0\0")


/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Secure Remote Password (SRP): SRP_U.
 *
 * For SRP RFC2945, the initiator MUST use:
 * @verbatim
 *    SRP_U=<U> TargetAuth=Yes or TargetAuth=No
 * @endverbatim
 * The target MUST answer with a Login reject with the "Authorization
 * Failure" status or reply with:
 * @verbatim
 *    SRP_GROUP=<G1,G2...> SRP_s=<s>
 * @endverbatim
 * where G1,G2... are proposed groups, in order of preference.
 * The initiator MUST either close the connection or continue with:
 * @verbatim
 *    SRP_A=<A>
 *    SRP_GROUP=<G>
 * @endverbatim
 * where G is one of G1,G2... that were proposed by the target.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *     SRP_B=<B>
 * @endverbatim
 * The initiator MUST close the connection or continue with:
 * @verbatim
 *     SRP_M=<M>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator sent TargetAuth=Yes in the first message (requiring target
 * authentication), the target MUST reply with:
 * @verbatim
 *     SRP_HM=<H(A | M | K)>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where U, s, A, B, M, and H(A | M | K) are defined in RFC2945 (using
 * the SHA1 hash function, such as SRP-SHA1) and
 * G,Gn ("Gn" stands for G1,G2...) are identifiers of SRP groups
 * specified in RFC3723.\n
 * G, Gn, and U are text strings; s,A,B,M, and H(A | M | K) are
 * binary-values. The length of s,A,B,M and H(A | M | K) in binary form
 * (not the length of the character string that represents them in
 * encoded form) MUST NOT exceed 1024 bytes. Hex or Base64 encoding may
 * be used for s,A,B,M and H(A | M | K).\n
 * For the SRP_GROUP, all the groups specified in RFC3723 up to
 * 1536 bits (i.e. SRP-768, SRP-1024, SRP-1280, SRP-1536) must be
 * supported by initiators and targets. To guarantee interoperability,
 * targets MUST always offer "SRP-1536" as one of the proposed groups.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_U     ((const uint8_t *) "SRP_U\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Secure Remote Password (SRP): SRP_GROUP.
 *
 * For SRP RFC2945, the initiator MUST use:
 * @verbatim
 *    SRP_U=<U> TargetAuth=Yes or TargetAuth=No
 * @endverbatim
 * The target MUST answer with a Login reject with the "Authorization
 * Failure" status or reply with:
 * @verbatim
 *    SRP_GROUP=<G1,G2...> SRP_s=<s>
 * @endverbatim
 * where G1,G2... are proposed groups, in order of preference.
 * The initiator MUST either close the connection or continue with:
 * @verbatim
 *    SRP_A=<A>
 *    SRP_GROUP=<G>
 * @endverbatim
 * where G is one of G1,G2... that were proposed by the target.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *     SRP_B=<B>
 * @endverbatim
 * The initiator MUST close the connection or continue with:
 * @verbatim
 *     SRP_M=<M>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator sent TargetAuth=Yes in the first message (requiring target
 * authentication), the target MUST reply with:
 * @verbatim
 *     SRP_HM=<H(A | M | K)>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where U, s, A, B, M, and H(A | M | K) are defined in RFC2945 (using
 * the SHA1 hash function, such as SRP-SHA1) and
 * G,Gn ("Gn" stands for G1,G2...) are identifiers of SRP groups
 * specified in RFC3723.\n
 * G, Gn, and U are text strings; s,A,B,M, and H(A | M | K) are
 * binary-values. The length of s,A,B,M and H(A | M | K) in binary form
 * (not the length of the character string that represents them in
 * encoded form) MUST NOT exceed 1024 bytes. Hex or Base64 encoding may
 * be used for s,A,B,M and H(A | M | K).\n
 * For the SRP_GROUP, all the groups specified in RFC3723 up to
 * 1536 bits (i.e. SRP-768, SRP-1024, SRP-1280, SRP-1536) must be
 * supported by initiators and targets. To guarantee interoperability,
 * targets MUST always offer "SRP-1536" as one of the proposed groups.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_GROUP ((const uint8_t *) "SRP_GROUP\0\0\0\0\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Secure Remote Password (SRP): SRP_A.
 *
 * For SRP RFC2945, the initiator MUST use:
 * @verbatim
 *    SRP_U=<U> TargetAuth=Yes or TargetAuth=No
 * @endverbatim
 * The target MUST answer with a Login reject with the "Authorization
 * Failure" status or reply with:
 * @verbatim
 *    SRP_GROUP=<G1,G2...> SRP_s=<s>
 * @endverbatim
 * where G1,G2... are proposed groups, in order of preference.
 * The initiator MUST either close the connection or continue with:
 * @verbatim
 *    SRP_A=<A>
 *    SRP_GROUP=<G>
 * @endverbatim
 * where G is one of G1,G2... that were proposed by the target.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *     SRP_B=<B>
 * @endverbatim
 * The initiator MUST close the connection or continue with:
 * @verbatim
 *     SRP_M=<M>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator sent TargetAuth=Yes in the first message (requiring target
 * authentication), the target MUST reply with:
 * @verbatim
 *     SRP_HM=<H(A | M | K)>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where U, s, A, B, M, and H(A | M | K) are defined in RFC2945 (using
 * the SHA1 hash function, such as SRP-SHA1) and
 * G,Gn ("Gn" stands for G1,G2...) are identifiers of SRP groups
 * specified in RFC3723.\n
 * G, Gn, and U are text strings; s,A,B,M, and H(A | M | K) are
 * binary-values. The length of s,A,B,M and H(A | M | K) in binary form
 * (not the length of the character string that represents them in
 * encoded form) MUST NOT exceed 1024 bytes. Hex or Base64 encoding may
 * be used for s,A,B,M and H(A | M | K).\n
 * For the SRP_GROUP, all the groups specified in RFC3723 up to
 * 1536 bits (i.e. SRP-768, SRP-1024, SRP-1280, SRP-1536) must be
 * supported by initiators and targets. To guarantee interoperability,
 * targets MUST always offer "SRP-1536" as one of the proposed groups.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_A     ((const uint8_t *) "SRP_A\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Secure Remote Password (SRP): SRP_B.
 *
 * For SRP RFC2945, the initiator MUST use:
 * @verbatim
 *    SRP_U=<U> TargetAuth=Yes or TargetAuth=No
 * @endverbatim
 * The target MUST answer with a Login reject with the "Authorization
 * Failure" status or reply with:
 * @verbatim
 *    SRP_GROUP=<G1,G2...> SRP_s=<s>
 * @endverbatim
 * where G1,G2... are proposed groups, in order of preference.
 * The initiator MUST either close the connection or continue with:
 * @verbatim
 *    SRP_A=<A>
 *    SRP_GROUP=<G>
 * @endverbatim
 * where G is one of G1,G2... that were proposed by the target.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *     SRP_B=<B>
 * @endverbatim
 * The initiator MUST close the connection or continue with:
 * @verbatim
 *     SRP_M=<M>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator sent TargetAuth=Yes in the first message (requiring target
 * authentication), the target MUST reply with:
 * @verbatim
 *     SRP_HM=<H(A | M | K)>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where U, s, A, B, M, and H(A | M | K) are defined in RFC2945 (using
 * the SHA1 hash function, such as SRP-SHA1) and
 * G,Gn ("Gn" stands for G1,G2...) are identifiers of SRP groups
 * specified in RFC3723.\n
 * G, Gn, and U are text strings; s,A,B,M, and H(A | M | K) are
 * binary-values. The length of s,A,B,M and H(A | M | K) in binary form
 * (not the length of the character string that represents them in
 * encoded form) MUST NOT exceed 1024 bytes. Hex or Base64 encoding may
 * be used for s,A,B,M and H(A | M | K).\n
 * For the SRP_GROUP, all the groups specified in RFC3723 up to
 * 1536 bits (i.e. SRP-768, SRP-1024, SRP-1280, SRP-1536) must be
 * supported by initiators and targets. To guarantee interoperability,
 * targets MUST always offer "SRP-1536" as one of the proposed groups.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_B     ((const uint8_t *) "SRP_B\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Secure Remote Password (SRP): SRP_M.
 *
 * For SRP RFC2945, the initiator MUST use:
 * @verbatim
 *    SRP_U=<U> TargetAuth=Yes or TargetAuth=No
 * @endverbatim
 * The target MUST answer with a Login reject with the "Authorization
 * Failure" status or reply with:
 * @verbatim
 *    SRP_GROUP=<G1,G2...> SRP_s=<s>
 * @endverbatim
 * where G1,G2... are proposed groups, in order of preference.
 * The initiator MUST either close the connection or continue with:
 * @verbatim
 *    SRP_A=<A>
 *    SRP_GROUP=<G>
 * @endverbatim
 * where G is one of G1,G2... that were proposed by the target.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *     SRP_B=<B>
 * @endverbatim
 * The initiator MUST close the connection or continue with:
 * @verbatim
 *     SRP_M=<M>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator sent TargetAuth=Yes in the first message (requiring target
 * authentication), the target MUST reply with:
 * @verbatim
 *     SRP_HM=<H(A | M | K)>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where U, s, A, B, M, and H(A | M | K) are defined in RFC2945 (using
 * the SHA1 hash function, such as SRP-SHA1) and
 * G,Gn ("Gn" stands for G1,G2...) are identifiers of SRP groups
 * specified in RFC3723.\n
 * G, Gn, and U are text strings; s,A,B,M, and H(A | M | K) are
 * binary-values. The length of s,A,B,M and H(A | M | K) in binary form
 * (not the length of the character string that represents them in
 * encoded form) MUST NOT exceed 1024 bytes. Hex or Base64 encoding may
 * be used for s,A,B,M and H(A | M | K).\n
 * For the SRP_GROUP, all the groups specified in RFC3723 up to
 * 1536 bits (i.e. SRP-768, SRP-1024, SRP-1280, SRP-1536) must be
 * supported by initiators and targets. To guarantee interoperability,
 * targets MUST always offer "SRP-1536" as one of the proposed groups.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_M     ((const uint8_t *) "SRP_M\0\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Secure Remote Password (SRP): SRP_HM.
 *
 * For SRP RFC2945, the initiator MUST use:
 * @verbatim
 *    SRP_U=<U> TargetAuth=Yes or TargetAuth=No
 * @endverbatim
 * The target MUST answer with a Login reject with the "Authorization
 * Failure" status or reply with:
 * @verbatim
 *    SRP_GROUP=<G1,G2...> SRP_s=<s>
 * @endverbatim
 * where G1,G2... are proposed groups, in order of preference.
 * The initiator MUST either close the connection or continue with:
 * @verbatim
 *    SRP_A=<A>
 *    SRP_GROUP=<G>
 * @endverbatim
 * where G is one of G1,G2... that were proposed by the target.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *     SRP_B=<B>
 * @endverbatim
 * The initiator MUST close the connection or continue with:
 * @verbatim
 *     SRP_M=<M>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator sent TargetAuth=Yes in the first message (requiring target
 * authentication), the target MUST reply with:
 * @verbatim
 *     SRP_HM=<H(A | M | K)>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where U, s, A, B, M, and H(A | M | K) are defined in RFC2945 (using
 * the SHA1 hash function, such as SRP-SHA1) and
 * G,Gn ("Gn" stands for G1,G2...) are identifiers of SRP groups
 * specified in RFC3723.\n
 * G, Gn, and U are text strings; s,A,B,M, and H(A | M | K) are
 * binary-values. The length of s,A,B,M and H(A | M | K) in binary form
 * (not the length of the character string that represents them in
 * encoded form) MUST NOT exceed 1024 bytes. Hex or Base64 encoding may
 * be used for s,A,B,M and H(A | M | K).\n
 * For the SRP_GROUP, all the groups specified in RFC3723 up to
 * 1536 bits (i.e. SRP-768, SRP-1024, SRP-1280, SRP-1536) must be
 * supported by initiators and targets. To guarantee interoperability,
 * targets MUST always offer "SRP-1536" as one of the proposed groups.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_HM    ((const uint8_t *) "SRP_HM\0")


/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Challenge Handshake Authentication Protocol (CHAP): CHAP_A.
 *
 * For CHAP RFC1994, the initiator MUST use:
 * @verbatim
 *    CHAP_A=<A1,A2...>
 * @endverbatim
 * where A1,A2... are proposed algorithms, in order of preference.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *    CHAP_A=<A>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * where A is one of A1,A2... that were proposed by the initiator.
 * The initiator MUST continue with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * or, if it requires target authentication, with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator required target authentication, the target MUST either
 * answer with a Login reject with "Authentication Failure" or reply
 * with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where N, (A,A1,A2), I, C, and R are (correspondingly) the Name,
 * Algorithm, Identifier, Challenge, and Response as defined in
 * RFC1994.\n
 * N is a text string; A,A1,A2, and I are numbers; C and R are
 * binary-values. Their binary length (not the length of the character
 * string that represents them in encoded form) MUST NOT exceed
 * 1024 bytes. Hex or Base64 encoding may be used for C and R.\n
 * For the Algorithm, as stated in [RFC1994], one value is required to
 * be implemented:
 * @verbatim
 *    5     (CHAP with MD5)
 * @endverbatim
 * To guarantee interoperability, initiators MUST always offer it as one
 * of the proposed algorithms.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_A ((const uint8_t *) "CHAP_A\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Challenge Handshake Authentication Protocol (CHAP): CHAP_I.
 *
 * For CHAP RFC1994, the initiator MUST use:
 * @verbatim
 *    CHAP_A=<A1,A2...>
 * @endverbatim
 * where A1,A2... are proposed algorithms, in order of preference.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *    CHAP_A=<A>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * where A is one of A1,A2... that were proposed by the initiator.
 * The initiator MUST continue with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * or, if it requires target authentication, with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator required target authentication, the target MUST either
 * answer with a Login reject with "Authentication Failure" or reply
 * with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where N, (A,A1,A2), I, C, and R are (correspondingly) the Name,
 * Algorithm, Identifier, Challenge, and Response as defined in
 * RFC1994.\n
 * N is a text string; A,A1,A2, and I are numbers; C and R are
 * binary-values. Their binary length (not the length of the character
 * string that represents them in encoded form) MUST NOT exceed
 * 1024 bytes. Hex or Base64 encoding may be used for C and R.\n
 * For the Algorithm, as stated in [RFC1994], one value is required to
 * be implemented:
 * @verbatim
 *    5     (CHAP with MD5)
 * @endverbatim
 * To guarantee interoperability, initiators MUST always offer it as one
 * of the proposed algorithms.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_I ((const uint8_t *) "CHAP_I\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Challenge Handshake Authentication Protocol (CHAP): CHAP_C.
 *
 * For CHAP RFC1994, the initiator MUST use:
 * @verbatim
 *    CHAP_A=<A1,A2...>
 * @endverbatim
 * where A1,A2... are proposed algorithms, in order of preference.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *    CHAP_A=<A>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * where A is one of A1,A2... that were proposed by the initiator.
 * The initiator MUST continue with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * or, if it requires target authentication, with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator required target authentication, the target MUST either
 * answer with a Login reject with "Authentication Failure" or reply
 * with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where N, (A,A1,A2), I, C, and R are (correspondingly) the Name,
 * Algorithm, Identifier, Challenge, and Response as defined in
 * RFC1994.\n
 * N is a text string; A,A1,A2, and I are numbers; C and R are
 * binary-values. Their binary length (not the length of the character
 * string that represents them in encoded form) MUST NOT exceed
 * 1024 bytes. Hex or Base64 encoding may be used for C and R.\n
 * For the Algorithm, as stated in [RFC1994], one value is required to
 * be implemented:
 * @verbatim
 *    5     (CHAP with MD5)
 * @endverbatim
 * To guarantee interoperability, initiators MUST always offer it as one
 * of the proposed algorithms.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_C ((const uint8_t *) "CHAP_C\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Challenge Handshake Authentication Protocol (CHAP): CHAP_N.
 *
 * For CHAP RFC1994, the initiator MUST use:
 * @verbatim
 *    CHAP_A=<A1,A2...>
 * @endverbatim
 * where A1,A2... are proposed algorithms, in order of preference.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *    CHAP_A=<A>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * where A is one of A1,A2... that were proposed by the initiator.
 * The initiator MUST continue with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * or, if it requires target authentication, with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator required target authentication, the target MUST either
 * answer with a Login reject with "Authentication Failure" or reply
 * with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where N, (A,A1,A2), I, C, and R are (correspondingly) the Name,
 * Algorithm, Identifier, Challenge, and Response as defined in
 * RFC1994.\n
 * N is a text string; A,A1,A2, and I are numbers; C and R are
 * binary-values. Their binary length (not the length of the character
 * string that represents them in encoded form) MUST NOT exceed
 * 1024 bytes. Hex or Base64 encoding may be used for C and R.\n
 * For the Algorithm, as stated in [RFC1994], one value is required to
 * be implemented:
 * @verbatim
 *    5     (CHAP with MD5)
 * @endverbatim
 * To guarantee interoperability, initiators MUST always offer it as one
 * of the proposed algorithms.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_N ((const uint8_t *) "CHAP_N\0")

/**
 * @brief Key used during SecurityNegotiation stage of Login Phase: Challenge Handshake Authentication Protocol (CHAP): CHAP_R.
 *
 * For CHAP RFC1994, the initiator MUST use:
 * @verbatim
 *    CHAP_A=<A1,A2...>
 * @endverbatim
 * where A1,A2... are proposed algorithms, in order of preference.
 * The target MUST answer with a Login reject with the "Authentication
 * Failure" status or reply with:
 * @verbatim
 *    CHAP_A=<A>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * where A is one of A1,A2... that were proposed by the initiator.
 * The initiator MUST continue with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * or, if it requires target authentication, with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 *    CHAP_I=<I>
 *    CHAP_C=<C>
 * @endverbatim
 * If the initiator authentication fails, the target MUST answer with a
 * Login reject with "Authentication Failure" status. Otherwise, if the
 * initiator required target authentication, the target MUST either
 * answer with a Login reject with "Authentication Failure" or reply
 * with:
 * @verbatim
 *    CHAP_N=<N>
 *    CHAP_R=<R>
 * @endverbatim
 * If the target authentication fails, the initiator MUST close the
 * connection:\n
 * where N, (A,A1,A2), I, C, and R are (correspondingly) the Name,
 * Algorithm, Identifier, Challenge, and Response as defined in
 * RFC1994.\n
 * N is a text string; A,A1,A2, and I are numbers; C and R are
 * binary-values. Their binary length (not the length of the character
 * string that represents them in encoded form) MUST NOT exceed
 * 1024 bytes. Hex or Base64 encoding may be used for C and R.\n
 * For the Algorithm, as stated in [RFC1994], one value is required to
 * be implemented:
 * @verbatim
 *    5     (CHAP with MD5)
 * @endverbatim
 * To guarantee interoperability, initiators MUST always offer it as one
 * of the proposed algorithms.
 */
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_R ((const uint8_t *) "CHAP_R\0")

/* Login/Text Operational Text Keys

   Some session-specific parameters MUST only be carried on the leading
   connection and cannot be changed after the leading connection login
   (e.g., MaxConnections - the maximum number of connections). This
   holds for a single connection session with regard to connection
   restart. The keys that fall into this category have the "use: LO"
   (Leading Only).

   Keys that can only be used during login have the "use: IO"
   (Initialize Only), while those that can be used in both the Login
   Phase and Full Feature Phase have the "use: ALL".

   Keys that can only be used during the Full Feature Phase use FFPO
   (Full Feature Phase Only).

   Keys marked as Any-Stage may also appear in the SecurityNegotiation
   stage, while all other keys described in this section are
   operational keys.

   Keys that do not require an answer are marked as Declarative.

   Key scope is indicated as session-wide (SW) or connection-only (CO).

   "Result function", wherever mentioned, states the function that can
   be applied to check the validity of the responder selection.
   "Minimum" means that the selected value cannot exceed the offered
   value. "Maximum" means that the selected value cannot be lower than
   the offered value. "AND" means that the selected value must be a
   possible result of a Boolean "and" function with an arbitrary Boolean
   value (e.g., if the offered value is No the selected value must be
   No). "OR" means that the selected value must be a possible result of
   a Boolean "or" function with an arbitrary Boolean value (e.g., if the
   offered value is Yes the selected value must be Yes).
*/

/**
 * @brief Login/Text Operational Session Text Key: Header digest.
 *
 * @verbatim
 * Use: IO
 * Senders: Initiator and target
 * Scope: CO
 * HeaderDigest = <list-of-values>
 * Default is None for HeaderDigest.
 * @endverbatim
 * Digests enable the checking of end-to-end, non-cryptographic data
 * integrity beyond the integrity checks provided by the link layers and
 * the covering of the whole communication path, including all elements
 * that may change the network-level PDUs, such as routers, switches,
 * and proxies.\n
 * The following table lists cyclic integrity checksums that can be
 * negotiated for the digests and MUST be implemented by every iSCSI
 * initiator and target. These digest options only have error detection
 * significance.
 * Name   | Description | Generator
 * :----- | :---------- | :----------
 * CRC32C | 32-bit CRC  | 0x11EDC6F41
 * None   | no digest   ||
 *
 * The generator polynomial G(x) for this digest is given in hexadecimal
 * notation (e.g. "0x3b" stands for 0011 1011, and the polynomial is
 * x**5 + x**4 + x**3 + x + 1).\n
 * When the initiator and target agree on a digest, this digest MUST be
 * used for every PDU in the Full Feature Phase.\n
 * Padding bytes, when present in a segment covered by a CRC, SHOULD be
 * set to 0 and are included in the CRC.\n
 * The CRC MUST be calculated by a method that produces the same results
 * as the following process:
 * - The PDU bits are considered as the coefficients of a polynomial
 *   M(x) of degree n - 1; bit 7 of the lowest numbered byte is
 *   considered the most significant bit (x**n - 1), followed by bit 6
 *   of the lowest numbered byte through bit 0 of the highest numbered
 *   byte (x**0).
 * - The most significant 32 bits are complemented.
 * - The polynomial is multiplied by x**32, then divided by G(x). The
 *   generator polynomial produces a remainder R(x) of degree <= 31.
 * - The coefficients of R(x) are formed into a 32-bit sequence.
 * - The bit sequence is complemented, and the result is the CRC.
 * - The CRC bits are mapped into the digest word. The x**31
 *   coefficient is mapped to bit 7 of the lowest numbered byte of the
 *   digest, and the mapping continues with successive coefficients and
 *   bits so that the x**24 coefficient is mapped to bit 0 of the lowest
 *   numbered byte. The mapping continues further with the x**23
 *   coefficient mapped to bit 7 of the next byte in the digest until
 *   the x**0 coefficient is mapped to bit 0 of the highest numbered
 *   byte of the digest.
 * - Computing the CRC over any segment (data or header) extended to
 *   include the CRC built using the generator 0x11edc6f41 will always
 *   get the value 0x1c2d19ed as its final remainder (R(x)). This value
 *   is given here in its polynomial form (i.e., not mapped as the
 *   digest word).
 *
 * For a discussion about selection criteria for the CRC, see RFC3385.\n
 * For a detailed analysis of the iSCSI polynomial, see Castagnoli93.\n
 * Private or public extension algorithms MAY also be negotiated for
 * digests. Whenever a private or public digest extension algorithm is
 * part of the default offer (the offer made in the absence of explicit
 * administrative action), the implementer MUST ensure that CRC32C is
 * listed as an alternative in the default offer and "None" is not part
 * of the default offer.\n
 * Extension digest algorithms MUST be named using one of the following
 * two formats:
 *    1. Y-reversed.vendor.dns_name.do_something=
 *    2. New public key with no name prefix constraints
 *
 * Digests named using the Y- format are used for private purposes
 * (unregistered). New public keys must be registered with IANA using
 * the IETF Review process (RFC5226). New public extensions for
 * digests MUST NOT use the Y# name prefix.\n
 * For private extension digests, to identify the vendor we suggest
 * using the reversed DNS-name as a prefix to the proper digest names.\n
 * The part of digest-name following Y- MUST conform to the format for
 * standard-label specified.\n
 * Support for public or private extension digests is OPTIONAL.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST ((const uint8_t *) "HeaderDigest\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Data digest.
 *
 * @verbatim
 * Use: IO
 * Senders: Initiator and target
 * Scope: CO
 * DataDigest = <list-of-values>
 * Default is None for DataDigest.
 * @endverbatim
 * Digests enable the checking of end-to-end, non-cryptographic data
 * integrity beyond the integrity checks provided by the link layers and
 * the covering of the whole communication path, including all elements
 * that may change the network-level PDUs, such as routers, switches,
 * and proxies.\n
 * The following table lists cyclic integrity checksums that can be
 * negotiated for the digests and MUST be implemented by every iSCSI
 * initiator and target. These digest options only have error detection
 * significance.
 * Name   | Description | Generator
 * :----- | :---------- | :----------
 * CRC32C | 32-bit CRC  | 0x11EDC6F41
 * None   | no digest   ||
 *
 * The generator polynomial G(x) for this digest is given in hexadecimal
 * notation (e.g. "0x3b" stands for 0011 1011, and the polynomial is
 * x**5 + x**4 + x**3 + x + 1).\n
 * When the initiator and target agree on a digest, this digest MUST be
 * used for every PDU in the Full Feature Phase.\n
 * Padding bytes, when present in a segment covered by a CRC, SHOULD be
 * set to 0 and are included in the CRC.\n
 * The CRC MUST be calculated by a method that produces the same results
 * as the following process:
 * - The PDU bits are considered as the coefficients of a polynomial
 *   M(x) of degree n - 1; bit 7 of the lowest numbered byte is
 *   considered the most significant bit (x**n - 1), followed by bit 6
 *   of the lowest numbered byte through bit 0 of the highest numbered
 *   byte (x**0).
 * - The most significant 32 bits are complemented.
 * - The polynomial is multiplied by x**32, then divided by G(x). The
 *   generator polynomial produces a remainder R(x) of degree <= 31.
 * - The coefficients of R(x) are formed into a 32-bit sequence.
 * - The bit sequence is complemented, and the result is the CRC.
 * - The CRC bits are mapped into the digest word. The x**31
 *   coefficient is mapped to bit 7 of the lowest numbered byte of the
 *   digest, and the mapping continues with successive coefficients and
 *   bits so that the x**24 coefficient is mapped to bit 0 of the lowest
 *   numbered byte. The mapping continues further with the x**23
 *   coefficient mapped to bit 7 of the next byte in the digest until
 *   the x**0 coefficient is mapped to bit 0 of the highest numbered
 *   byte of the digest.
 * - Computing the CRC over any segment (data or header) extended to
 *   include the CRC built using the generator 0x11edc6f41 will always
 *   get the value 0x1c2d19ed as its final remainder (R(x)). This value
 *   is given here in its polynomial form (i.e., not mapped as the
 *   digest word).
 *
 * For a discussion about selection criteria for the CRC, see RFC3385.\n
 * For a detailed analysis of the iSCSI polynomial, see Castagnoli93.\n
 * Private or public extension algorithms MAY also be negotiated for
 * digests. Whenever a private or public digest extension algorithm is
 * part of the default offer (the offer made in the absence of explicit
 * administrative action), the implementer MUST ensure that CRC32C is
 * listed as an alternative in the default offer and "None" is not part
 * of the default offer.\n
 * Extension digest algorithms MUST be named using one of the following
 * two formats:
 *    1. Y-reversed.vendor.dns_name.do_something=
 *    2. New public key with no name prefix constraints
 *
 * Digests named using the Y- format are used for private purposes
 * (unregistered). New public keys must be registered with IANA using
 * the IETF Review process (RFC5226). New public extensions for
 * digests MUST NOT use the Y# name prefix.\n
 * For private extension digests, to identify the vendor we suggest
 * using the reversed DNS-name as a prefix to the proper digest names.\n
 * The part of digest-name following Y- MUST conform to the format for
 * standard-label specified.\n
 * Support for public or private extension digests is OPTIONAL.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST   ((const uint8_t *) "DataDigest\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: New connections.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * Irrelevant when: SessionType=Discovery
 * MaxConnections=<numerical-value-from-1-to-65535>
 * Default is 1.
 * @endverbatim
 * Result function is Minimum.\n
 * The initiator and target negotiate the maximum number of connections
 * requested/acceptable.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS ((const uint8_t *) "MaxConnections\0")

/**
 * @brief Login/Text Operational Session Text Key: Send targets.
 *
 * @verbatim
 * Use: FFPO
 * Senders: Initiator
 * Scope: SW
 * @endverbatim
 * The text in this appendix is a normative part of this document.\n
 * To reduce the amount of configuration required on an initiator, iSCSI
 * provides the SendTargets Text Request. The initiator uses the
 * SendTargets request to get a list of targets to which it may have
 * access, as well as the list of addresses (IP address and TCP port) on
 * which these targets may be accessed.\n
 * To make use of SendTargets, an initiator must first establish one of
 * two types of sessions. If the initiator establishes the session
 * using the key "SessionType=Discovery", the session is a Discovery
 * session, and a target name does not need to be specified. Otherwise,
 * the session is a Normal operational session. The SendTargets command
 * MUST only be sent during the Full Feature Phase of a Normal or
 * Discovery session.\n
 * A system that contains targets MUST support Discovery sessions on
 * each of its iSCSI IP address-port pairs and MUST support the
 * SendTargets command on the Discovery session. In a Discovery
 * session, a target MUST return all path information (IP address-port
 * pairs and Target Portal Group Tags) for the targets on the target
 * Network Entity that the requesting initiator is authorized to access.\n
 * A target MUST support the SendTargets command on operational
 * sessions; these will only return path information about the target to
 * which the session is connected and do not need to return information
 * about other target names that may be defined in the responding
 * system.\n
 * An initiator MAY make use of the SendTargets command as it sees fit.\n
 * A SendTargets command consists of a single Text Request PDU. This
 * PDU contains exactly one text key and value. The text key MUST be
 * SendTargets. The expected response depends upon the value, as well
 * as whether the session is a Discovery session or an operational
 * session.\n
 * The value must be one of:
 * @verbatim
 *    All
 *       The initiator is requesting that information on all relevant
 *       targets known to the implementation be returned. This value
 *       MUST be supported on a Discovery session and MUST NOT be
 *       supported on an operational session.
 *    <iSCSI-target-name>
 *       If an iSCSI Target Name is specified, the session should
 *       respond with addresses for only the named target, if possible.
 *       This value MUST be supported on Discovery sessions. A
 *       Discovery session MUST be capable of returning addresses for
 *       those targets that would have been returned had value=All been
 *       designated.
 *    <nothing>
 *       The session should only respond with addresses for the target
 *       to which the session is logged in. This MUST be supported on
 *       operational sessions and MUST NOT return targets other than the
 *       one to which the session is logged in.
 * @endverbatim
 * The response to this command is a Text Response that contains a list
 * of zero or more targets and, optionally, their addresses. Each
 * target is returned as a target record. A target record begins with
 * the TargetName text key, followed by a list of TargetAddress text
 * keys, and bounded by the end of the Text Response or the next
 * TargetName key, which begins a new record. No text keys other than
 * TargetName and TargetAddress are permitted within a SendTargets
 * response.\n
 * A Discovery session MAY respond to a SendTargets request with its
 * complete list of targets, or with a list of targets that is based on
 * the name of the initiator logged in to the session.\n
 * A SendTargets response MUST NOT contain target names if there are no
 * targets for the requesting initiator to access.\n
 * Each target record returned includes zero or more TargetAddress
 * fields.\n
 * Each target record starts with one text key of the form:
 * @verbatim
 *    TargetName=<target-name-goes-here>
 * @endverbatim
 * followed by zero or more address keys of the form:
 * @verbatim
 * TargetAddress=<hostname-or-ipaddress>[:<tcp-port>],
 *    <portal-group-tag>
 * @endverbatim
 * The hostname-or-ipaddress contains a domain name, IPv4 address, or
 * IPv6 address (RFC4291), as specified for the TargetAddress key.\n
 * A hostname-or-ipaddress duplicated in TargetAddress responses for a
 * given node (the port is absent or equal) would probably indicate that
 * multiple address families are in use at once (IPv6 and IPv4).\n
 * Each TargetAddress belongs to a portal group, identified by its
 * numeric Target Portal Group Tag. The iSCSI Target Name, together with
 * this tag, constitutes the SCSI port identifier; the tag only needs to
 * be unique within a given target's name list of addresses.\n
 * Multiple-connection sessions can span iSCSI addresses that belong to
 * the same portal group.\n
 * Multiple-connection sessions cannot span iSCSI addresses that belong
 * to different portal groups.\n
 * If a SendTargets response reports an iSCSI address for a target, it
 * SHOULD also report all other addresses in its portal group in the
 * same response.\n
 * A SendTargets Text Response can be longer than a single Text Response
 * PDU and makes use of the long Text Responses as specified.\n
 * After obtaining a list of targets from the Discovery session, an
 * iSCSI initiator may initiate new sessions to log in to the discovered
 * targets for full operation. The initiator MAY keep the Discovery
 * session open and MAY send subsequent SendTargets commands to discover
 * new targets.\n
 * Examples:\n
 * This example is the SendTargets response from a single target that
 * has no other interface ports.\n
 * The initiator sends a Text Request that contains:
 * @verbatim
 *    SendTargets=All
 * @endverbatim
 * The target sends a Text Response that contains:
 * @verbatim
 *    TargetName=iqn.1993-11.de.uni-freiburg:diskarray.sn.8675309
 * @endverbatim
 * All the target had to return in this simple case was the target name.\n
 * It is assumed by the initiator that the IP address and TCP port for
 * this target are the same as those used on the current connection to
 * the default iSCSI target.\n
 * The next example has two internal iSCSI targets, each accessible via
 * two different ports with different IP addresses. The following is
 * the Text Response:
 * @verbatim
 *    TargetName=iqn.1993-11.de.uni-freiburg:diskarray.sn.8675309
 *    TargetAddress=10.1.0.45:5300,1
 *    TargetAddress=10.1.1.45:5300,2
 *    TargetName=iqn.1993-11.de.uni-freiburg:diskarray.sn.1234567
 *    TargetAddress=10.1.0.45:5300,1
 *    TargetAddress=10.1.1.45:5300,2
 * @endverbatim
 * Both targets share both addresses; the multiple addresses are likely
 * used to provide multi-path support. The initiator may connect to
 * either target name on either address. Each of the addresses has its
 * own Target Portal Group Tag; they do not support spanning multiple-
 * connection sessions with each other. Keep in mind that the Target
 * Portal Group Tags for the two named targets are independent of one
 * another; portal group "1" on the first target is not necessarily the
 * same as portal group "1" on the second target.\n
 * In the above example, a DNS host name or an IPv6 address could have
 * been returned instead of an IPv4 address.\n
 * The next Text Response shows a target that supports spanning sessions
 * across multiple addresses and further illustrates the use of the
 * Target Portal Group Tags:
 * @verbatim
 *    TargetName=iqn.1993-11.de.uni-freiburg:diskarray.sn.8675309
 *    TargetAddress=10.1.0.45:5300,1
 *    TargetAddress=10.1.1.46:5300,1
 *    TargetAddress=10.1.0.47:5300,2
 *    TargetAddress=10.1.1.48:5300,2
 *    TargetAddress=10.1.1.49:5300,3
 * @endverbatim
 * In this example, any of the target addresses can be used to reach the
 * same target. A single-connection session can be established to any
 * of these TCP addresses. A multiple-connection session could span
 * addresses .45 and .46 or .47 and .48 but cannot span any other
 * combination. A TargetAddress with its own tag (.49) cannot be
 * combined with any other address within the same session.\n
 * This SendTargets response does not indicate whether .49 supports
 * multiple connections per session; it is communicated via the
 * MaxConnections text key upon login to the target.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_SEND_TARGETS ((const uint8_t *) "SendTargets\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Initial Ready To Transfer.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * Irrelevant when: SessionType=Discovery
 * InitialR2T=<boolean-value>
 * Examples:
 *    I->InitialR2T=No
 *    T->InitialR2T=No
 * Default is Yes.
 * @endverbatim
 * Result function is OR.\n
 * The InitialR2T key is used to turn off the default use of R2T for
 * unidirectional operations and the output part of bidirectional
 * commands, thus allowing an initiator to start sending data to a
 * target as if it has received an initial R2T with Buffer
 * Offset=Immediate Data Length and Desired Data Transfer
 * Length=(min(FirstBurstLength, Expected Data Transfer Length) -
 * Received Immediate Data Length).\n
 * The default action is that R2T is required, unless both the initiator
 * and the target send this key-pair attribute specifying InitialR2T=No.
 * Only the first outgoing data burst (immediate data and/or separate
 * PDUs) can be sent unsolicited (i.e., not requiring an explicit R2T).
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T ((const uint8_t *) "InitialR2T\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Immediate data.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * Irrelevant when: SessionType=Discovery
 * ImmediateData=<boolean-value>
 * Default is Yes.
 * @endverbatim
 * Result function is AND.\n
 * The initiator and target negotiate support for immediate data. To
 * turn immediate data off, the initiator or target must state its
 * desire to do soImmediateData can be turned on if both the
 * initiator and target have ImmediateData=Yes.\n
 * If ImmediateData is set to Yes and InitialR2T is set to Yes
 * (default), then only immediate data are accepted in the first burst.
 * If ImmediateData is set to No and InitialR2T is set to Yes, then the
 * initiator MUST NOT send unsolicited data and the target MUST reject
 * unsolicited data with the corresponding response code.\n
 * If ImmediateData is set to No and InitialR2T is set to No, then the
 * initiator MUST NOT send unsolicited immediate data but MAY send one
 * unsolicited burst of Data-OUT PDUs.\n
 * If ImmediateData is set to Yes and InitialR2T is set to No, then the
 * initiator MAY send unsolicited immediate data and/or one unsolicited
 * burst of Data-OUT PDUs.\n
 * The following table is a summary of unsolicited data options:
 * InitialR2T | ImmediateData | Unsolicited Data-Out PDUs | ImmediateData
 * :--------- | :------------ | :------------------------ | :------------
 * | No       | No            | Yes                       | No          |
 * | No       | Yes           | Yes                       | Yes         |
 * | Yes      | No            | No                        | No          |
 * | Yes      | Yes           | No                        | Yes         |
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA ((const uint8_t *) "ImmediateData\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Maximum receive DataSegmentLength.
 *
 * @verbatim
 * Use: ALL, Declarative
 * Senders: Initiator and target
 * Scope: CO
 * MaxRecvDataSegmentLength=<numerical-value-512-to-(2**24 - 1)>
 * Default is 8192 bytes.
 * @endverbatim
 * The initiator or target declares the maximum data segment length in
 * bytes it can receive in an iSCSI PDU.\n
 * The transmitter (initiator or target) is required to send PDUs with a
 * data segment that does not exceed MaxRecvDataSegmentLength of the
 * receiver.\n
 * A target receiver is additionally limited by MaxBurstLength for
 * solicited data and FirstBurstLength for unsolicited dataAn
 * initiator MUST NOT send solicited PDUs exceeding MaxBurstLength nor
 * unsolicited PDUs exceeding FirstBurstLength (or FirstBurstLength-
 * Immediate Data Length if immediate data were sent).
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN ((const uint8_t *) "MaxRecvDataSegmentLength\0\0\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Maximum burst length.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * Irrelevant when: SessionType=Discovery
 * MaxBurstLength=<numerical-value-512-to-(2**24 - 1)>
 * Default is 262144 (256 KB).
 * @endverbatim
 * Result function is Minimum.\n
 * The initiator and target negotiate the maximum SCSI data payload in
 * bytes in a Data-In or a solicited Data-Out iSCSI sequence. A
 * sequence consists of one or more consecutive Data-In or Data-Out PDUs
 * that end with a Data-In or Data-Out PDU with the F bit set to 1.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN ((const uint8_t *) "MaxBurstLength\0")

/**
 * @brief Login/Text Operational Session Text Key: First burst length.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * Irrelevant when: SessionType=Discovery
 * Irrelevant when: ( InitialR2T=Yes and ImmediateData=No )
 * FirstBurstLength=<numerical-value-512-to-(2**24 - 1)>
 * Default is 65536 (64 KB).
 * @endverbatim
 * Result function is Minimum.\n
 * The initiator and target negotiate the maximum amount in bytes of
 * unsolicited data an iSCSI initiator may send to the target during the
 * execution of a single SCSI command. This covers the immediate data
 * (if any) and the sequence of unsolicited Data-Out PDUs (if any) that
 * follow the command.\n
 * FirstBurstLength MUST NOT exceed MaxBurstLength.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN ((const uint8_t *) "FirstBurstLength\0\0\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Default time to wait.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * DefaultTime2Wait=<numerical-value-0-to-3600>
 * Default is 2.
 * @endverbatim
 * Result function is Maximum.\n
 * The initiator and target negotiate the minimum time, in seconds, to
 * wait before attempting an explicit/implicit logout or an active task
 * reassignment after an unexpected connection termination or a
 * connection reset.\n
 * A value of 0 indicates that logout or active task reassignment can be
 * attempted immediately.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_WAIT ((const uint8_t *) "DefaultTime2Wait\0\0\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Default time to retain.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * DefaultTime2Retain=<numerical-value-0-to-3600>
 * Default is 20.
 * @endverbatim
 * Result function is Minimum.\n
 * The initiator and target negotiate the maximum time, in seconds,
 * after an initial wait (Time2Wait), before which an active task
 * reassignment is still possible after an unexpected connection
 * termination or a connection reset.\n
 * This value is also the session state timeout if the connection in
 * question is the last LOGGED_IN connection in the session.\n
 * A value of 0 indicates that connection/task state is immediately
 * discarded by the target.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_RETAIN ((const uint8_t *) "DefaultTime2Retain\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Maximum outstanding Ready To Transfer.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * MaxOutstandingR2T=<numerical-value-from-1-to-65535>
 * Irrelevant when: SessionType=Discovery
 * Default is 1.
 * @endverbatim
 * Result function is Minimum.\n
 * The initiator and target negotiate the maximum number of outstanding
 * R2Ts per task, excluding any implied initial R2T that might be part
 * of that task. An R2T is considered outstanding until the last data
 * PDU (with the F bit set to 1) is transferred or a sequence reception
 * timeout is encountered for that data sequence.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T ((const uint8_t *) "MaxOutstandingR2T\0\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Data Protocol Data Unit (PDU) in order.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * Irrelevant when: SessionType=Discovery
 * DataPDUInOrder=<boolean-value>
 * Default is Yes.
 * @endverbatim
 * Result function is OR.\n
 * "No" is used by iSCSI to indicate that the data PDUs within sequences
 * can be in any order. "Yes" is used to indicate that data PDUs within
 * sequences have to be at continuously increasing addresses and
 * overlays are forbidden.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_PDU_IN_ORDER ((const uint8_t *) "DataPDUInOrder\0")

/**
 * @brief Login/Text Operational Session Text Key: Data sequence in order.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * Irrelevant when: SessionType=Discovery
 * DataSequenceInOrder=<boolean-value>
 * Default is Yes.
 * @endverbatim
 * Result function is OR.\n
 * A data sequence is a sequence of Data-In or Data-Out PDUs that end
 * with a Data-In or Data-Out PDU with the F bit set to 1. A Data-Out
 * sequence is sent either unsolicited or in response to an R2T.\n
 * Sequences cover an offset-range.\n
 * If DataSequenceInOrder is set to No, data PDU sequences may be
 * transferred in any order.\n
 * If DataSequenceInOrder is set to Yes, data sequences MUST be
 * transferred using continuously non-decreasing sequence offsets (R2T
 * buffer offset for writes, or the smallest SCSI Data-In buffer offset
 * within a read data sequence).\n
 * If DataSequenceInOrder is set to Yes, a target may retry at most the
 * last R2T, and an initiator may at most request retransmission for the
 * last read data sequence. For this reason, if ErrorRecoveryLevel is
 * not 0 and DataSequenceInOrder is set to Yes, then MaxOutstandingR2T
 * MUST be set to 1.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_SEQ_IN_ORDER ((const uint8_t *) "DataSequenceInOrder\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Error recovery level.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * ErrorRecoveryLevel=<numerical-value-0-to-2>
 * Default is 0.
 * @endverbatim
 * Result function is Minimum.\n
 * The initiator and target negotiate the recovery level supported.
 * Recovery levels represent a combination of recovery capabilities.
 * Each recovery level includes all the capabilities of the lower
 * recovery levels and adds some new ones to them.\n
 * In the description of recovery mechanisms, certain recovery classes
 * are specified.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_ERR_RECOVERY_LEVEL ((const uint8_t *) "ErrorRecoveryLevel\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: X reversed vendor.
 *
 * @verbatim
 * Use: ALL
 * Senders: Initiator and target
 * Scope: specific key dependent
 * X-reversed.vendor.dns_name.do_something=
 * @endverbatim
 * Keys with this format are used for private extension purposes. These
 * keys always start with X- if unregistered with IANA (private). New
 * public keys (if registered with IANA via an IETF Review RFC5226) no
 * longer have an X# name prefix requirement; implementers may propose
 * any intuitive unique name.\n
 * For unregistered keys, to identify the vendor we suggest using the
 * reversed DNS-name as a prefix to the key-proper.\n
 * The part of key-name following X- MUST conform to the format for
 * key-name.\n
 * Vendor-specific keys MUST ONLY be used in Normal sessions.\n
 * Support for public or private extension keys is OPTIONAL.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_PRIV_EXT_KEY_FMT ((const uint8_t *) "X-reversed.vendor\0\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: Task reporting.
 *
 * @verbatim
 * Use: LO
 * Senders: Initiator and target
 * Scope: SW
 * Irrelevant when: SessionType=Discovery
 * TaskReporting=<list-of-values>
 * Default is RFC3720.
 * @endverbatim
 * This key is used to negotiate the task completion reporting semantics
 * from the SCSI target. The following table describes the semantics
 * that an iSCSI target MUST support for respective negotiated key
 * values. Whenever this key is negotiated, at least the RFC3720 and
 * ResponseFence values MUST be offered as options by the negotiation
 * originator.
 * Name            | Description
 * :-------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------
 * | RFC3720       | RFC 3720-compliant semantics. Response fencing is not guaranteed, and fast completion of multi-task aborting is not supported.
 * | ResponseFence | Response Fence semantics MUST be supported in reporting task completions.
 * | FastAbort     | Updated fast multi-task abort semantics defined in MUST be supported. Support for the Response. Fence is implied - i.e., semantics MUST be supported as well.
 *
 * When TaskReporting is not negotiated to FastAbort, the
 * standard multi-task abort semantics MUST be used.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_TASK_REPORTING ((const uint8_t *) "TaskReporting\0\0")

/**
 * @brief Login/Text Operational Session Text Key: X Node architecture.
 *
 * @verbatim
 * Use: LO, Declarative
 * Senders: Initiator and target
 * Scope: SW
 * X#NodeArchitecture=<list-of-values>
 * Default is None.
 * Examples:
 *    X#NodeArchitecture=ExampleOS/v1234,ExampleInc_SW_Initiator/1.05a
 *    X#NodeArchitecture=ExampleInc_HW_Initiator/4010,Firmware/2.0.0.5
 *    X#NodeArchitecture=ExampleInc_SW_Initiator/2.1,CPU_Arch/i686
 * @endverbatim
 * This document does not define the structure or content of the list of
 * values.\n
 * The initiator or target declares the details of its iSCSI node
 * architecture to the remote endpoint. These details may include, but
 * are not limited to, iSCSI vendor software, firmware, or hardware
 * versions; the OS version; or hardware architecture. This key may be
 * declared on a Discovery session or a Normal session.\n
 * The length of the key value (total length of the list-of-values) MUST
 * NOT be greater than 255 bytes.\n
 * X#NodeArchitecture MUST NOT be redeclared during the Login Phase.\n
 * Functional behavior of the iSCSI node (this includes the iSCSI
 * protocol logic - the SCSI, iSCSI, and TCP/IP protocols) MUST NOT
 * depend on the presence, absence, or content of the X#NodeArchitecture
 * key. The key MUST NOT be used by iSCSI nodes for interoperability or
 * for exclusion of other nodes. To ensure proper use, key values
 * SHOULD be set by the node itself, and there SHOULD NOT be provisions
 * for the key values to contain user-defined text.\n
 * Nodes implementing this key MUST choose one of the following
 * implementation options:\n
 * - only transmit the key,
 * - only log the key values received from other nodes, or
 * - both transmit and log the key values.
 *
 * Each node choosing to implement transmission of the key values MUST
 * be prepared to handle the response of iSCSI nodes that do not
 * understand the key.\n
 * Nodes that implement transmission and/or logging of the key values
 * may also implement administrative mechanisms that disable and/or
 * change the logging and key transmission details.\n
 * Thus, a valid behavior for this key may be that a node is completely
 * silent (the node does not transmit any key value and simply discards
 * any key values it receives without issuing a NotUnderstood response).
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_X_NODE_ARCH ((const uint8_t *) "X#NodeArchitecture\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: IFMarker (obseleted).
 *
 * This document obsoletes the following keys defined in RFC3720:\n
 * IFMarker, OFMarker, OFMarkInt, and IFMarkInt. However, iSCSI
 * mplementations compliant to this document may still receive these
 * obsoleted keys - i.e., in a responder role - in a text negotiation.\n
 * When an IFMarker or OFMarker key is received, a compliant iSCSI
 * implementation SHOULD respond with the constant "Reject" value. The
 * implementation MAY alternatively respond with a "No" value.\n
 * However, the implementation MUST NOT respond with a "NotUnderstood"
 * value for either of these keys.\n
 * When an IFMarkInt or OFMarkInt key is received, a compliant iSCSI
 * implementation MUST respond with the constant "Reject" value. The
 * implementation MUST NOT respond with a "NotUnderstood" value for
 * either of these keys.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IF_MARKER   ((const uint8_t *) "IFMarker\0\0\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: OFMarker (obseleted).
 *
 * This document obsoletes the following keys defined in RFC3720:\n
 * IFMarker, OFMarker, OFMarkInt, and IFMarkInt. However, iSCSI
 * mplementations compliant to this document may still receive these
 * obsoleted keys - i.e., in a responder role - in a text negotiation.\n
 * When an IFMarker or OFMarker key is received, a compliant iSCSI
 * implementation SHOULD respond with the constant "Reject" value. The
 * implementation MAY alternatively respond with a "No" value.\n
 * However, the implementation MUST NOT respond with a "NotUnderstood"
 * value for either of these keys.\n
 * When an IFMarkInt or OFMarkInt key is received, a compliant iSCSI
 * implementation MUST respond with the constant "Reject" value. The
 * implementation MUST NOT respond with a "NotUnderstood" value for
 * either of these keys.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_OF_MARKER   ((const uint8_t *) "OFMarker\0\0\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: OFMarkInt (obseleted).
 *
 * This document obsoletes the following keys defined in RFC3720:\n
 * IFMarker, OFMarker, OFMarkInt, and IFMarkInt. However, iSCSI
 * mplementations compliant to this document may still receive these
 * obsoleted keys - i.e., in a responder role - in a text negotiation.\n
 * When an IFMarker or OFMarker key is received, a compliant iSCSI
 * implementation SHOULD respond with the constant "Reject" value. The
 * implementation MAY alternatively respond with a "No" value.\n
 * However, the implementation MUST NOT respond with a "NotUnderstood"
 * value for either of these keys.\n
 * When an IFMarkInt or OFMarkInt key is received, a compliant iSCSI
 * implementation MUST respond with the constant "Reject" value. The
 * implementation MUST NOT respond with a "NotUnderstood" value for
 * either of these keys.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_OF_MARK_INT ((const uint8_t *) "OFMarkInt\0\0\0\0\0\0")

/**
 * @brief Login/Text Operational Session Text Key: IFMarkInt (obseleted).
 *
 * This document obsoletes the following keys defined in RFC3720:\n
 * IFMarker, OFMarker, OFMarkInt, and IFMarkInt. However, iSCSI
 * mplementations compliant to this document may still receive these
 * obsoleted keys - i.e., in a responder role - in a text negotiation.\n
 * When an IFMarker or OFMarker key is received, a compliant iSCSI
 * implementation SHOULD respond with the constant "Reject" value. The
 * implementation MAY alternatively respond with a "No" value.\n
 * However, the implementation MUST NOT respond with a "NotUnderstood"
 * value for either of these keys.\n
 * When an IFMarkInt or OFMarkInt key is received, a compliant iSCSI
 * implementation MUST respond with the constant "Reject" value. The
 * implementation MUST NOT respond with a "NotUnderstood" value for
 * either of these keys.
 */
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IF_MARK_INT ((const uint8_t *) "IFMarkInt\0\0\0\0\0\0")


/// Login request Next Stage (NSG) flags: SecurityNegotiation.
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION          0x0

/// Login request Next Stage (NSG) flags: LoginOperationalNegotiation.
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1

/// Login request Next Stage (NSG) flags: Reserved for future usage, may NOT be used.
#define ISCSI_LOGIN_REQ_FLAGS_BEXT_STAGE_RESERVED                      0x2

/// Login request Next Stage (NSG) flags: FullFeaturePhase.
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_FULL_FEATURE_PHASE            0x3

/**
 * @brief Login request flags: Next Stage (NSG): First bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with a specific stage in the session (SecurityNegotiation,\n
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move. The Next Stage value is only
 * valid when the T bit is 1; otherwise, it is reserved.
 */
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_FIRST_BIT                     0

/**
 * @brief Login request flags: Next Stage (NSG): Last bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with a specific stage in the session (SecurityNegotiation,\n
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move. The Next Stage value is only
 * valid when the T bit is 1; otherwise, it is reserved.
 */
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_LAST_BIT                      ((ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_FIRST_BIT) + 2 - 1)

/// Login request flags: Next Stage (NSG): Bit mask.
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_MASK                          (ISCSI_BITS_GET_MASK(ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_FIRST_BIT, ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_LAST_BIT))

/// Login request flags: Extracts the Next Stage (NSG) bits.
#define ISCSI_LOGIN_REQ_FLAGS_GET_NEXT_STAGE(x)                        (ISCSI_BITS_GET((x), ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_FIRST_BIT, ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_LAST_BIT))

/// Login request flags: Stores into the Next Stage (NSG) bits.
#define ISCSI_LOGIN_REQ_FLAGS_PUT_NEXT_STAGE(x)                        (ISCSI_BITS_PUT((x), ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_FIRST_BIT, ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_LAST_BIT))


/// Login request Current Stage (CSG) flags: SecurityNegotiation.
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION          0x0

/// Login request Current Stage (CSG) flags: LoginOperationalNegotiation.
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1

/// Login request Current Stage (CSG) flags: Reserved for future usage, may NOT be used.
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_RESERVED                      0x2

/// Login request Current Stage (CSG) flags: FullFeaturePhase.
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_FULL_FEATURE_PHASE            0x3

/**
 * @brief Login request flags: Current Stage (CSG): First bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with aspecific stage in the session (SecurityNegotiation,
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move.
 */
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_FIRST_BIT                     2

/**
 * @brief Login request flags: Current Stage (CSG): Last bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with aspecific stage in the session (SecurityNegotiation,
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move.
 */
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_LAST_BIT                      ((ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_FIRST_BIT) + 2 - 1)

/// Login request flags: Current Stage (CSG): Bit mask.
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_MASK                          (ISCSI_BITS_GET_MASK(ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_FIRST_BIT, ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_LAST_BIT))

/// Login request flags: Extracts the Current Stage (CSG) bits.
#define ISCSI_LOGIN_REQ_FLAGS_GET_CURRENT_STAGE(x)                        (ISCSI_BITS_GET((x), ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_FIRST_BIT, ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_LAST_BIT))

/// Login request flags: Stores into the Current Stage (CSG) bits.
#define ISCSI_LOGIN_REQ_FLAGS_PUT_CURRENT_STAGE(x)                        (ISCSI_BITS_PUT((x), ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_FIRST_BIT, ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_LAST_BIT))


/**
 * @brief Login request flags: Continue.
 *
 * (C) When set to 1, this bit indicates that the text (set of key=value
 * pairs) in this Login Request is not complete (it will be continued on
 * subsequent Login Requests); otherwise, it indicates that this Login
 * Request ends a set of key=value pairs. A Login Request with the
 * C bit set to 1 MUST have the T bit set to 0.
 */
#define ISCSI_LOGIN_REQ_FLAGS_CONTINUE (1 << 6)

/**
 * @brief Login request flags: Transmit.
 *
 * (T) When set to 1, this bit indicates that the initiator is ready to
 * transit to the next stage.\n
 * If the T bit is set to 1 and the NSG is set to FullFeaturePhase, then
 * this also indicates that the initiator is ready for the Login
 * Final-Response.
 */
#define ISCSI_LOGIN_REQ_FLAGS_TRANSIT  (1 << 7)


/**
 * @brief iSCSI Login Request packet data.
 *
 * After establishing a TCP connection between an initiator and a
 * target, the initiator MUST start a Login Phase to gain further access
 * to the target's resources.
 *
 * The Login Phase consists of a sequence of Login Requests and Login
 * Responses that carry the same Initiator Task Tag.
 *
 * Login Requests are always considered as immediate.
 */
typedef struct __attribute__((packed)) iscsi_login_req_packet {
    /// Always 0x03 according to iSCSI specification.
    uint8_t opcode;

    /// Login request flags.
    int8_t flags;

    /**
     * @brief Version-max indicates the maximum version number supported.
     *
     * All Login Requests within the Login Phase MUST carry the same
     * Version-max. Currently, this is always 0.\n
     * The target MUST use the value presented with the first Login Request.
     */
    uint8_t version_max;

    /**
     * @brief Version-min indicates the minimum version number supported.
     *
     * All Login Requests within the Login Phase MUST carry the same
     * Version-min. The target MUST use the value presented with the first
     * Login Request. Always 0 for now.
     */
    uint8_t version_min;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /// DataSegmentLength.
    uint8_t ds_len[3];

    /// Initiator Session ID (ISID).
    iscsi_isid isid;

    /**
     * @brief Target Session Identifying Handle (TSIH).
     *
     * The TSIH must be set in the first Login Request. The reserved value
     * 0 MUST be used on the first connection for a new session. Otherwise,
     * the TSIH sent by the target at the conclusion of the successful login
     * of the first connection for this session MUST be used. The TSIH
     * identifies to the target the associated existing session for this new
     * connection.\n
     * All Login Requests within a Login Phase MUST carry the same TSIH.
     * The target MUST check the value presented with the first Login
     * Request.
     */
    uint16_t tsih;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /**
     * @brief Connection ID (CID).
     *
     * The CID provides a unique ID for this connection within the session.\n
     * All Login Requests within the Login Phase MUST carry the same CID.
     * The target MUST use the value presented with the first Login Request.\n
     * A Login Request with a non-zero TSIH and a CID equal to that of an
     * existing connection implies a logout of the connection followed by a
     * login.
     */
    uint16_t cid;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /**
     * @brief CmdSN.
     *
     * The CmdSN is either the initial command sequence number of a session
     * (for the first Login Request of a session - the "leading" login) or
     * the command sequence number in the command stream if the login is for
     * a new connection in an existing session.\n
     * Examples:
     * - Login on a leading connection: If the leading login carries the
     *   CmdSN 123, all other Login Requests in the same Login Phase carry
     *   the CmdSN 123, and the first non-immediate command in the Full
     *   Feature Phase also carries the CmdSN 123.
     * - Login on other than a leading connection: If the current CmdSN at
     *   the time the first login on the connection is issued is 500, then
     *   that PDU carries CmdSN=500. Subsequent Login Requests that are
     *   needed to complete this Login Phase may carry a CmdSN higher than
     *   500 if non-immediate requests that were issued on other connections
     *   in the same session advance the CmdSN.
     *
     * If the Login Request is a leading Login Request, the target MUST use
     * the value presented in the CmdSN as the target value for the
     * ExpCmdSN.
     */
    uint32_t cmd_sn;

    /**
     * @brief ExpStatSN.
     *
     * For the first Login Request on a connection, this is the ExpStatSN
     * for the old connection, and this field is only valid if the Login
     * Request restarts a connection.\n
     * For subsequent Login Requests, it is used to acknowledge the Login
     * Responses with their increasing StatSN values.
     */
    uint32_t exp_stat_sn;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2[2];

    /**
     * @brief Data segment - Login Parameters in Text Request Format.
     *
     * The initiator MUST provide some basic parameters in order
     * to enable the target to determine if the initiator may use
     * the target's resources and the initial text parameters for the security exchange
     */
    iscsi_scsi_ds_cmd_data ds_cmd_data;
} iscsi_login_req_packet;


/// Login response Next Stage (NSG) flags: SecurityNegotiation.
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION          0x0

/// Login response Next Stage (NSG) flags: LoginOperationalNegotiation.
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1

/// Login response Next Stage (NSG) flags: Reserved for future usage, may NOT be used.
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_RESERVED                      0x2

/// Login response Next Stage (NSG) flags: FullFeaturePhase.
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FULL_FEATURE_PHASE            0x3

/**
 * @brief Login response flags: Next Stage (NSG): First bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with a specific stage in the session (SecurityNegotiation,
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move The Next Stage value is only
 * valid when the T bit is 1; otherwise, it is reserved.
 */
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FIRST_BIT                     0

/**
 * @brief Login response flags: Next Stage (NSG): Last bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with a specific stage in the session (SecurityNegotiation,
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move The Next Stage value is only
 * valid when the T bit is 1; otherwise, it is reserved.
 */
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LAST_BIT                      ((ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FIRST_BIT) + 2 - 1)

/// Login response flags: Next Stage (NSG): Bit mask.
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_MASK                          (ISCSI_BITS_GET_MASK(ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FIRST_BIT, ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LAST_BIT))

/// Login response flags: Extracts the Next Stage (NSG) bits.
#define ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(x)                        (ISCSI_BITS_GET((x), ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FIRST_BIT, ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LAST_BIT))

/// Login response flags: Stores into the Next Stage (NSG) bits.
#define ISCSI_LOGIN_RESPONSE_FLAGS_PUT_NEXT_STAGE(x)                        (ISCSI_BITS_PUT((x), ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FIRST_BIT, ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LAST_BIT))


/// Login response Current Stage (CSG) flags: SecurityNegotiation.
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION          0x0

/// Login response Current Stage (CSG) flags: LoginOperationalNegotiation.
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1

/// Login response Current Stage (CSG) flags: Reserved for future usage, may NOT be used.
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_RESERVED                      0x2

/// Login response Current Stage (CSG) flags: FullFeaturePhase.
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FULL_FEATURE_PHASE            0x3

/**
 * @brief Login response flags: Current Stage (CSG): First bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with aspecific stage in the session (SecurityNegotiation,
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move.
 */
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FIRST_BIT                     2

/**
 * @brief Login response flags: Current Stage (CSG): First bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with aspecific stage in the session (SecurityNegotiation,
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move.
 */
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LAST_BIT                      ((ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FIRST_BIT) + 2 - 1)

/// Login request flags: Current Stage (CSG): Bit mask.
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_MASK                          (ISCSI_BITS_GET_MASK(ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FIRST_BIT, ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LAST_BIT))

/// Login request flags: Extracts the Current Stage (CSG) bits.
#define ISCSI_LOGIN_RESPONSE_FLAGS_GET_CURRENT_STAGE(x)                        (ISCSI_BITS_GET((x), ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FIRST_BIT, ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LAST_BIT))

/// Login request flags: Stores into the Current Stage (CSG) bits.
#define ISCSI_LOGIN_RESPONSE_FLAGS_PUT_CURRENT_STAGE(x)                        (ISCSI_BITS_PUT((x), ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FIRST_BIT, ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LAST_BIT))


/**
 * @brief Login response flags: Continue.
 *
 * (C) When set to 1, this bit indicates that the text (set of key=value
 * pairs) in this Login Response is not complete (it will be continued
 * on subsequent Login Responses); otherwise, it indicates that this
 * Login Response ends a set of key=value pairs. A Login Response with
 * the C bit set to 1 MUST have the T bit set to 0.
 */
#define ISCSI_LOGIN_RESPONSE_FLAGS_CONTINUE      (1 << 6)

/**
 * @brief Login response flags: Transmit.
 *
 * (T) The T bit is set to 1 as an indicator of the end of the stage. If
 * the T bit is set to 1 and the NSG is set to FullFeaturePhase, then
 * this is also the Login Final-Response. A T bit of 0 indicates a
 * "partial" response, which means "more negotiation needed".\n
 * A Login Response with the T bit set to 1 MUST NOT contain key=value
 * pairs that may require additional answers from the initiator within
 * the same stage.\n
 * If the Status-Class is 0, the T bit MUST NOT be set to 1 if the T bit
 * in the request was set to 0.
 */
#define ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT       (1 << 7)


/**
 * @brief Login response status class: Success.
 *
 * Indicates that the iSCSI target successfully received, understood,
 * and accepted the request. The numbering fields (StatSN, ExpCmdSN,
 * MaxCmdSN) are only valid if Status-Class is 0.
 */
#define ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS 0x00

/**
 * @brief Login response status details: Success.
 *
 * Login is proceeding OK. If the response T bit is set to 1 in both the
 * request and the matching response, and the NSG is set to
 * FullFeaturePhase in both the request and the matching response, the
 * Login Phase is finished, and the initiator may proceed to issue SCSI
 * commands.
 */
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SUCCESS 0x00


/**
 * @brief Login response status class: Redirection.
 *
 * Indicates that the initiator must take further action
 * to complete the request. This is usually due to the
 * target moving to a different address. All of the redirection
 * Status-Class responses MUST return one or more text key
 * parameters of the type "TargetAddress", which indicates the
 * target's new address. A redirection response MAY be issued by
 * a target prior to or after completing a security negotiation if
 * a security negotiation is required. A redirection SHOULD be
 * accepted by an initiator, even without having the target
 * complete a security negotiation if any security negotiation is
 * required, and MUST be accepted by the initiator after the
 * completion of the security negotiation if any security
 * negotiation is required.
 */
#define ISCSI_LOGIN_RESPONSE_STATUS_CLASS_REDIRECT 0x01

/**
 * @brief Login response status details: Temporarily redirected.
 *
 * The requested iSCSI Target Name (ITN) has temporarily moved
 * to the address provided.
 */
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_REDIRECT_TEMP 0x01

/**
 * @brief Login response status details: Permanently redirected.
 *
 * The requested ITN has permanently moved to the address provided.
 */
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_REDIRECT_PERM 0x02


/**
 * @brief Login response status class: Initiator Error (not a format error).
 *
 * Indicates that the initiator most likely caused the error.\n
 * This MAY be due to a request for a resource for which the
 * initiator does not have permission. The request should
 * not be tried again.
 */
#define ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR 0x02

/// Login response status details: Miscellaneous iSCSI initiator errors.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC                   0x00

/// Login response status details: The initiator could not be successfully authenticated or target authentication is not supported.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR               0x01

/// Login response status details: The initiator is not allowed access to the given target.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_FAIL              0x02

/// Login response status details: The requested iSCSI Target Name (ITN) does not exist at this address.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_NOT_FOUND              0x03

/// Login response status details: The requested ITN has been removed, and no forwarding address is provided.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_TARGET_REMOVED         0x04

/// Login response status details: The requested iSCSI version range is not supported by the target.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_WRONG_VERSION          0x05

/// Login response status details: Too many connections on this Session ID (SSID).
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_TOO_MANY_CONNECTIONS   0x06

/// Login response status details: Missing parameters (e.g. iSCSI Initiator Name and/or Target Name).
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER      0x07

/// Login response status details: Target does not support session spanning to this connection (address).
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_NO_SESSION_SPANNING    0x08

/// Login response status details: Target does not support this type of session or not from this initiator.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_SESSION_NO_SUPPORT     0x09

/// Login response status details: Attempt to add a connection to a non-existent session.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_SESSION_NO_EXIST       0x0A

/// Login response status details: Invalid request type during login.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_INVALID_LOGIN_REQ_TYPE 0x0B


/**
 * @brief Login response status class: Target Error.
 *
 * Indicates that the target sees no errors in the
 * initiator's Login Request but is currently incapable of
 * fulfilling the request. The initiator may retry the same Login
 * Request later.
 */
#define ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR 0x03

/// Login response status details: Target hardware or software error.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_TARGET_ERROR        0x00

/// Login response status details: The iSCSI service or target is not currently operational.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_SERVICE_UNAVAILABLE 0x01

/// The target has insufficient session, connection, or other resources.
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES    0x02


/**
 * @brief iSCSI Login Response packet data.
 *
 * The Login Response indicates the progress and/or end of the Login
 * Phase.
 */
typedef struct __attribute__((packed)) iscsi_login_response_packet {
    /// Always 0x23 according to iSCSI specification.
    uint8_t opcode;

    /// Login response flags.
    int8_t flags;

    /**
     * @brief This is the highest version number supported by the target.
     *
     * All Login Responses within the Login Phase MUST carry the same
     * Version-max.
     */
    uint8_t version_max;

    /**
     * @brief Version-active indicates the highest version supported by the target and initiator.
     *
     * If the target does not support a version within the
     * range specified by the initiator, the target rejects the login and
     * this field indicates the lowest version supported by the target.
     * All Login Responses within the Login Phase MUST carry the same
     * Version-active.\n
     * The initiator MUST use the value presented as a response to the first
     * Login Request.
     */
    uint8_t version_active;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /// DataSegmentLength.
    uint8_t ds_len[3];

    /// Initiator Session ID (ISID).
    iscsi_isid isid;

    /**
     * @brief Target Session Identifying Handle (TSIH).
     *
     * The TSIH is the target-assigned session-identifying handle. Its
     * internal format and content are not defined by this protocol, except
     * for the value 0, which is reserved. With the exception of the Login
     * Final-Response in a new session, this field should be set to the TSIH
     * provided by the initiator in the Login Request. For a new session,
     * the target MUST generate a non-zero TSIH and ONLY return it in the
     * Login Final-Response.
     */
    uint16_t tsih;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved;

    /**
     * @brief StatSN.
     *
     * For the first Login Response (the response to the first Login
     * Request), this is the starting status sequence number for the
     * connection. The next response of any kind - including the next
     * Login Response, if any, in the same Login Phase - will carry this
     * number + 1. This field is only valid if the Status-Class is 0.
     */
    uint32_t stat_sn;

    /// ExpCmdSN.
    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /**
     * @brief Status-class.
     *
     * Status-class (see above for details). If the Status-Class is
     * not 0, the initiator and target MUST close the TCP connection
     * If the target wishes to reject the Login Request for more than one
     * reason, it should return the primary reason for the rejection.
     */
    uint8_t status_class;

    /// Status-detail.
    uint8_t status_detail;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved2;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved3;

    /**
     * @brief Data segment - Login Parameters in Text Request Format.
     *
     * The target MUST provide some basic parameters in order to enable the
     * initiator to determine if it is connected to the correct port and the
     * initial text parameters for the security exchange.\n
     * All the rules specified for Text Responses also hold for Login
     * Responses.
     */
    iscsi_scsi_ds_cmd_data ds_cmd_data;
} iscsi_login_response_packet;


/// Logout request reason code: Close the session. All commands associated with the session (if any) are terminated.
#define ISCSI_LOGOUT_REQ_REASON_CODE_CLOSE_SESSION              0x00

/// Logout request reason code: Close the connection. All commands associated with the connection (if any) are terminated.
#define ISCSI_LOGOUT_REQ_REASON_CODE_CLOSE_CONNECTION           0x01

/// Logout request reason code: Remove the connection for recovery. The connection is closed, and all commands associated with it, if any, are to be prepared for a new allegiance.
#define ISCSI_LOGOUT_REQ_REASON_CODE_REMOVE_CONNECTION_RECOVERY 0x02


/**
 * @brief Logout request implicit reason code: Session reinstatement.
 *
 * The entire logout discussion in this section is also applicable for
 * an implicit Logout realized by way of a connection reinstatement or
 * session reinstatement. When a Login Request performs an implicit
 * Logout, the implicit Logout is performed as if having the reason
 * codes specified below:
 */
#define ISCSI_LOGOUT_REQ_REASON_CODE_IMPLICIT_SESSION_REINSTATEMENT      0x00

/**
 * @brief Logout request implicit reason code: Connection reinstatement when the operational ErrorRecoveryLevel < 2.
 *
 * The entire logout discussion in this section is also applicable for
 * an implicit Logout realized by way of a connection reinstatement or
 * session reinstatement. When a Login Request performs an implicit
 * Logout, the implicit Logout is performed as if having the reason
 * codes specified below:
 */
#define ISCSI_LOGOUT_REQ_REASON_CODE_IMPLICIT_CONNECTION_REINSTATEMENT   0x01

/**
 * @brief Logout request implicit reason code: Connection reinstatement when the operational ErrorRecoveryLevel = 2.
 *
 * The entire logout discussion in this section is also applicable for
 * an implicit Logout realized by way of a connection reinstatement or
 * session reinstatement. When a Login Request performs an implicit
 * Logout, the implicit Logout is performed as if having the reason
 * codes specified below:
 */
#define ISCSI_LOGOUT_REQ_REASON_CODE_IMPLICIT_CONNECTION_REINSTATEMENT_2 0x02


/**
 * @brief iSCSI Logout Request packet data.
 *
 * The Logout Request is used to perform a controlled closing of a
 * connection.
 *
 * An initiator MAY use a Logout Request to remove a connection from a
 * session or to close an entire session.
 *
 * After sending the Logout Request PDU, an initiator MUST NOT send any
 * new iSCSI requests on the closing connection. If the Logout Request
 * is intended to close the session, new iSCSI requests MUST NOT be sent
 * on any of the connections participating in the session.
 *
 * When receiving a Logout Request with the reason code "close the
 * connection" or "close the session", the target MUST terminate all
 * pending commands, whether acknowledged via the ExpCmdSN or not, on
 * that connection or session, respectively.
 *
 * When receiving a Logout Request with the reason code "remove the
 * connection for recovery", the target MUST discard all requests not
 * yet acknowledged via the ExpCmdSN that were issued on the specified
 * connection and suspend all data/status/R2T transfers on behalf of
 * pending commands on the specified connection.
 *
 * The target then issues the Logout Response and half-closes the TCP
 * connection (sends FIN). After receiving the Logout Response and
 * attempting to receive the FIN (if still possible), the initiator MUST
 * completely close the logging-out connection. For the terminated
 * commands, no additional responses should be expected.
 *
 * A Logout for a CID may be performed on a different transport
 * connection when the TCP connection for the CID has already been
 * terminated. In such a case, only a logical "closing" of the iSCSI
 * connection for the CID is implied with a Logout.
 *
 * All commands that were not terminated or not completed (with status)
 * and acknowledged when the connection is closed completely can be
 * reassigned to a new connection if the target supports connection
 * recovery.
 *
 * If an initiator intends to start recovery for a failing connection,
 * it MUST use the Logout Request to "clean up" the target end of a
 * failing connection and enable recovery to start, or use the Login
 * Request with a non-zero TSIH and the same CID on a new connection for
 * the same effect. In sessions with a single connection, the
 * connection can be closed and then a new connection reopened. A
 * connection reinstatement login can be used for recovery.
 *
 * A successful completion of a Logout Request with the reason code
 * "close the connection" or "remove the connection for recovery"
 * results at the target in the discarding of unacknowledged commands
 * received on the connection being logged out. These are commands that
 * have arrived on the connection being logged out but that have not
 * been delivered to SCSI because one or more commands with a smaller
 * CmdSN have not been received by iSCSI. The resulting holes in the
 * command sequence numbers will have to be handled by appropriate
 * recovery, unless the session is also closed.
 */
typedef struct __attribute__((packed)) iscsi_logout_req_packet {
    /// Always 6 according to iSCSI specification.
    uint8_t opcode;

    /**
     * @brief Reason code.
     *
     * A target implicitly terminates the active tasks due to the iSCSI
     * protocol in the following cases:
     * -# When a connection is implicitly or explicitly logged out with
     *    the reason code "close the connection" and there are active
     *    tasks allegiant to that connection.
     * -# When a connection fails and eventually the connection state
     *    times out and there are active tasks allegiant to that
     *    connection
     * -# When a successful recovery Logout is performed while there are
     *    active tasks allegiant to that connection and those tasks
     *    eventually time out after the Time2Wait and Time2Retain periods
     *    without allegiance reassignment
     * -# When a connection is implicitly or explicitly logged out with
     *    the reason code "close the session" and there are active tasks
     *    in that session
     *
     * If the tasks terminated in any of the above cases are SCSI tasks,
     * they must be internally terminated as if with CHECK CONDITION status.
     * This status is only meaningful for appropriately handling the
     * internal SCSI state and SCSI side effects with respect to ordering,
     * because this status is never communicated back as a terminating
     * status to the initiator. However, additional actions may have to be
     * taken at the SCSI level, depending on the SCSI context as defined by
     * the SCSI standards (e.g., queued commands and ACA; UA for the next
     * command on the I_T nexus in cases a), b), and c) above). After the
     * tasks are terminated, the target MUST report a Unit Attention condition
     * on the next command processed on any connection for each affected
     * I_T_L nexus with the status of CHECK CONDITION, the ASC/ASCQ value
     * of 0x47 / 0x7F ("SOME COMMANDS CLEARED BY ISCSI PROTOCOL EVENT"), etc.
     */
    int8_t reason_code;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength (MUST be 0 for this PDU).
    uint8_t total_ahs_len;

    /// DataSegmentLength (MUST be 0 for this PDU).
    uint8_t ds_len[3];

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /**
     * @brief Connection ID (CID).
     *
     * This is the connection ID of the connection to be closed (including
     * closing the TCP stream). This field is only valid if the reason code
     * is not "close the session".
     */
    uint16_t cid;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved3;

    /// CmdSN.
    uint32_t cmd_sn;

    /// This is the last ExpStatSN value for the connection to be closed.
    uint32_t exp_stat_sn;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved4[2];

    /// Optional header digest.
    iscsi_header_digest hdr_digest;
} iscsi_logout_req_packet;


/// Logout response - response code: Connection or session closed successfully.
#define ISCSI_LOGOUT_RESPONSE_CLOSED_SUCCESSFULLY               0x00

/// Logout response - response code: Connection ID (CID) not found.
#define ISCSI_LOGOUT_RESPONSE_CID_NOT_FOUND                     0x01

/// Logout response - response code: Connection recovery is not supported (i.e., the Logout reason code was "remove the connection for recovery" and the target does not support it as indicated by the operational ErrorRecoveryLevel).
#define ISCSI_LOGOUT_RESPONSE_CONNECTION_RECOVERY_NOT_SUPPORTED 0x02

/// Logout response - response code: Cleanup failed for various reasons.
#define ISCSI_LOGOUT_RESPONSE_CLEANUP_FAILED                    0x03

/**
 * @brief iSCSI Logout Response packet data.
 *
 * The Logout Response is used by the target to indicate if the cleanup
 * operation for the connection(s) has completed.
 *
 * After Logout, the TCP connection referred by the CID MUST be closed
 * at both ends (or all connections must be closed if the logout reason
 * was session close).
 */
typedef struct __attribute__((packed)) iscsi_logout_response_packet {
    /// Always 0x26 according to iSCSI specification.
    uint8_t opcode;

    /// Reserved for future usage (always MUST be 0x80 for now).
    int8_t flags;

    /// Response.
    uint8_t response;

    /// Reserved for future usage, always MUST be 0.
    uint8_t reserved;

    /// TotalAHSLength (MUST be 0 for this PDU).
    uint8_t total_ahs_len;

    /// DataSegmentLength (MUST be 0 for this PDU).
    uint8_t ds_len[3];

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved3;

    /// StatSN.
    uint32_t stat_sn;

    /// ExpCmdSN.
    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved4;

    /**
     * @brief Time2Wait.
     *
     * If the Logout response code is 0 and the operational
     * ErrorRecoveryLevel is 2, this is the minimum amount of time, in
     * seconds, to wait before attempting task reassignment. If the Logout
     * response code is 0 and the operational ErrorRecoveryLevel is less
     * than 2, this field is to be ignored.\n
     * This field is invalid if the Logout response code is 1.\n
     * If the Logout response code is 2 or 3, this field specifies the
     * minimum time to wait before attempting a new implicit or explicit
     * logout.\n
     * If Time2Wait is 0, the reassignment or a new Logout may be attempted
     * immediately.
     */
    uint16_t time_wait;

    /**
     * @brief Time2Retain.
     *
     * If the Logout response code is 0 and the operational
     * ErrorRecoveryLevel is 2, this is the maximum amount of time, in
     * seconds, after the initial wait (Time2Wait) that the target waits for
     * the allegiance reassignment for any active task, after which the task
     * state is discarded. If the Logout response code is 0 and the
     * operational ErrorRecoveryLevel is less than 2, this field is to be
     * ignored.\n
     * This field is invalid if the Logout response code is 1.\n
     * If the Logout response code is 2 or 3, this field specifies the
     * maximum amount of time, in seconds, after the initial wait
     * (Time2Wait) that the target waits for a new implicit or explicit
     * logout.\n
     * If it is the last connection of a session, the whole session state is
     * discarded after Time2Retain.\n
     * If Time2Retain is 0, the target has already discarded the connection
     * (and possibly the session) state along with the task states. No
     * reassignment or Logout is required in this case.
     */
    uint16_t time_retain;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved5;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;
} iscsi_logout_response_packet;


/// Selective Negative / Sequence Number Acknowledgment (SNACK) request: Data/R2T SNACK: requesting retransmission of one or more Data-In or R2T PDUs.
#define ISCSI_SNACK_REQ_TYPE_DATA_R2T_SNACK 0x00

/// Selective Negative / Sequence Number Acknowledgment (SNACK) request:
#define ISCSI_SNACK_REQ_TYPE_STATUS_SNACK   0x01 // Status SNACK: requesting retransmission of one or more
                                                 // numbered responses

/**
 * @brief Selective Negative / Sequence Number Acknowledgment (SNACK) request: DataACK: positively acknowledges Data-In PDUs.
 *
 * If an initiator operates at ErrorRecoveryLevel 1 or higher, it MUST
 * issue a SNACK of type DataACK after receiving a Data-In PDU with the
 * A bit set to 1. However, if the initiator has detected holes in the
 * input sequence, it MUST postpone issuing the SNACK of type DataACK
 * until the holes are filled. An initiator MAY ignore the A bit if it
 * deems that the bit is being set aggressively by the target (i.e.,
 * before the MaxBurstLength limit is reached).\n
 * The DataACK is used to free resources at the target and not to
 * request or imply data retransmission.\n
 * An initiator MUST NOT request retransmission for any data it had
 * already acknowledged
 */
#define ISCSI_SNACK_REQ_TYPE_DATA_ACK       0x02

/**
 * @brief Selective Negative / Sequence Number Acknowledgment (SNACK) request: R-Data SNACK: requesting retransmission of Data-In PDUs with possible resegmentation and status tagging.
 *
 * If the initiator MaxRecvDataSegmentLength changed between the
 * original transmission and the time the initiator requests
 * retransmission, the initiator MUST issue a R-Data SNACK.\n
 * With R-Data SNACK, the initiator indicates that it discards all the
 * unacknowledged data and expects the target to resend it. It also
 * expects resegmentation. In this case, the retransmitted Data-In PDUs
 * MAY be different from the ones originally sent in order to reflect
 * changes in MaxRecvDataSegmentLength. Their DataSN starts with the
 * BegRun of the last DataACK received by the target if any was received;
 * otherwise, it starts with 0 and is increased by 1 for each resent
 * Data-In PDU.\n
 * A target that has received a R-Data SNACK MUST return a SCSI Response
 * that contains a copy of the SNACK Tag field from the R-Data SNACK in
 * the SCSI Response SNACK Tag field as its last or only Response. For
 * example, if it has already sent a response containing another value
 * in the SNACK Tag field or had the status included in the last Data-In
 * PDU, it must send a new SCSI Response PDU. If a target sends more
 * than one SCSI Response PDU due to this rule, all SCSI Response PDUs
 * must carry the same StatSN. If an initiator attempts to recover a lost
 * SCSI Response when more than one response has been sent, the
 * target will send the SCSI Response with the latest content known to
 * the target, including the last SNACK Tag for the command.\n
 * For considerations in allegiance reassignment of a task to a
 * connection with a different MaxRecvDataSegmentLength.
 */
#define ISCSI_SNACK_REQ_TYPE_R_DATA_SNACK   0x03


/**
 * @brief iSCSI SNACK Request packet data.
 *
 * If the implementation supports ErrorRecoveryLevel greater than zero,
 * it MUST support all SNACK types.
 *
 * The SNACK is used by the initiator to request the retransmission of
 * numbered responses, data, or R2T PDUs from the target. The SNACK
 * Request indicates the numbered responses or data "runs" whose
 * retransmission is requested, where the run starts with the first
 * StatSN, DataSN, or R2TSN whose retransmission is requested and
 * indicates the number of Status, Data, or R2T PDUs requested,
 * including the first. 0 has special meaning when used as a starting
 * number and length:
 *
 *    - When used in RunLength, it means all PDUs starting with the
 *      initial.
 *
 *    - When used in both BegRun and RunLength, it means all
 *      unacknowledged PDUs.
 *
 * The numbered response(s) or R2T(s) requested by a SNACK MUST be
 * delivered as exact replicas of the ones that the target transmitted
 * originally, except for the fields ExpCmdSN, MaxCmdSN, and ExpDataSN,
 * which MUST carry the current values. R2T(s)requested by SNACK MUST
 * also carry the current value of the StatSN.
 *
 * The numbered Data-In PDUs requested by a Data SNACK MUST be delivered
 * as exact replicas of the ones that the target transmitted originally,
 * except for the fields ExpCmdSN and MaxCmdSN, which MUST carry the
 * current values; and except for resegmentation.
 *
 * Any SNACK that requests a numbered response, data, or R2T that was
 * not sent by the target or was already acknowledged by the initiator
 * MUST be rejected with a reason code of "Protocol Error".
 */
typedef struct __attribute__((packed)) iscsi_snack_req_packet {
    /// Always 0x10 according to iSCSI specification.
    uint8_t opcode;

    /**
     * @brief Type.
     *
     * Data/R2T SNACK, Status SNACK, or R-Data SNACK for a command MUST
     * precede status acknowledgment for the given command.
     */
    int8_t type;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /// DataSegmentLength.
    uint8_t ds_len[3];

    /// LUN or Reserved.
    uint64_t lun;

    /**
     * @brief Initiator Task Tag (ITT).
     *
     * For a Status SNACK and DataACK, the Initiator Task Tag MUST be set to
     * the reserved value 0xFFFFFFFF. In all other cases, the Initiator
     * Task Tag field MUST be set to the Initiator Task Tag of the
     * referenced command.
     */
    uint32_t init_task_tag;

    /**
     * @brief Target Transfer Tag (TTT).
     *
     * For a R-Data SNACK, this field MUST contain a value that is different
     * from 0 or 0xFFFFFFFF and is unique for the task (identified by the
     * Initiator Task Tag). This value MUST be copied by the iSCSI target
     * in the last or only SCSI Response PDU it issues for the command.\n
     * For DataACK, the Target Transfer Tag MUST contain a copy of the
     * Target Transfer Tag and LUN provided with the SCSI Data-In PDU with
     * the A bit set to 1.\n
     * In all other cases, the Target Transfer Tag field MUST be set to the
     * reserved value 0xFFFFFFFF.
     */
    uint32_t target_xfer_snack_tag;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved2;

    /// ExpStatSN.
    uint32_t exp_stat_sn;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved3;

    /**
     * @brief BegRun.
     *
     * This field indicates the DataSN, R2TSN, or StatSN of the first PDU
     * whose retransmission is requested (Data/R2T and Status SNACK), or the
     * next expected DataSN (DataACK SNACK).\n
     * A BegRun of 0, when used in conjunction with a RunLength of 0, means
     * "resend all unacknowledged Data-In, R2T or Response PDUs".
     * BegRun MUST be 0 for a R-Data SNACK.
     */
    uint32_t beg_run;

    /**
     * @brief RunLength.
     *
     * This field indicates the number of PDUs whose retransmission is
     * requested.\n
     * A RunLength of 0 signals that all Data-In, R2T, or Response PDUs
     * carrying the numbers equal to or greater than BegRun have to be
     * resent.\n
     * The RunLength MUST also be 0 for a DataACK SNACK in addition to a
     * R-Data SNACK.
     */
    uint32_t run_len;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;
} iscsi_snack_req_packet;


/// iSCSI Reject packet data: Reserved, original PDU can't be resent.
#define ISCSI_REJECT_REASON_RESERVED                    0x01

/**
 * @brief iSCSI Reject packet data: Data (payload) digest error, original PDU can be resent.
 *
 * For iSCSI, Data-Out PDU retransmission is only done if the
 * target requests retransmission with a recovery R2T. However,
 * if this is the data digest error on immediate data, the
 * initiator may choose to retransmit the whole PDU, including
 * the immediate data.
 */
#define ISCSI_REJECT_REASON_DATA_DIGEST_ERR             0x02

/// iSCSI Reject reason packet data: SNACK Reject (original PDU can be resent).
#define ISCSI_REJECT_REASON_SNACK_REJECT                0x03

/// iSCSI Reject reason packet data: Protocol Error (e.g., SNACK Request for a status that was already acknowledged). Original PDU can't be resent.
#define ISCSI_REJECT_REASON_PROTOCOL_ERR                0x04

/// iSCSI Reject reason packet data: Command not supported (original PDU can't be resent).
#define ISCSI_REJECT_REASON_COMMAND_NOT_SUPPORTED       0x05

/// iSCSI Reject reason packet data: Immediate command reject - too many immediate commands (original PDU can be resent).
#define ISCSI_REJECT_REASON_TOO_MANY_IMMEDIATE_COMMANDS 0x06

/// iSCSI Reject reason packet data: Task in progress (original PDU can't be resent).
#define ISCSI_REJECT_REASON_TASK_IN_PROGRESS            0x07

/// iSCSI Reject reason packet data: Invalid data ack (original PDU can't be resent).
#define ISCSI_REJECT_REASON_INVALID_DATA_ACK            0x08

/**
 * @brief iSCSI Reject reason packet data: Invalid PDU field, original PDU can't be resent.
 *
 * A target should use this reason code for all invalid values
 * of PDU fields that are meant to describe a task, a response,
 * or a data transfer. Some examples are invalid TTT/ITT,
 * buffer offset, LUN qualifying a TTT, and an invalid sequence
 * number in a SNACK.
 */
#define ISCSI_REJECT_REASON_INVALID_PDU_FIELD           0x09

/// iSCSI Reject reason packet data: Long op reject - Can't generate Target Transfer Tag - out of resources. Original PDU can be resent later.
#define ISCSI_REJECT_REASON_OUT_OF_RESOURCES            0x0A

/**
 * @brief iSCSI Reject reason packet data: Deprecated; MUST NOT be used.
 *
 * Reason code 0x0B is deprecated and MUST NOT be used by
 * implementations. An implementation receiving reason code
 * 0x0B MUST treat it as a negotiation failure that terminates
 * the Login Phase and the TCP connection.
 */
#define ISCSI_REJECT_REASON_DEPRECATED                  0x0B

/// iSCSI Reject reason packet data: Waiting for Logout, original PDU can't be resent.
#define ISCSI_REJECT_REASON_WAITING_FOR_LOGOUT          0x0C

/**
 * @brief iSCSI Reject packet data.
 *
 * This structure will be received or sent, if an iSCSI
 * packet was rejected or has been rejected for some reason.
 */
typedef struct __attribute__((packed)) iscsi_reject_packet {
    /// Always 0x3F according to iSCSI specification.
    uint8_t opcode;

    /// Reserved for future usage (always MUST be 0x80 for now).
    int8_t flags;

    /**
     * @brief Reject reason.
     *
     * In all the cases in which a pre-instantiated SCSI task is terminated
     * because of the reject, the target MUST issue a proper SCSI command
     * response with CHECK CONDITION. In these cases in which a status for
     * the SCSI task was already sent before the reject, no additional
     * status is required. If the error is detected while data from the
     * initiator is still expected (i.e., the command PDU did not contain
     * all the data and the target has not received a Data-Out PDU with the
     * Final bit set to 1 for the unsolicited data, if any, and all
     * outstanding R2Ts, if any), the target MUST wait until it receives
     * the last expected Data-Out PDUs with the F bit set to 1 before
     * sending the Response PDU.
     */
    uint8_t reason;

    /// Reserved for future usage, always MUST be 0.
    uint8_t reserved;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /// DataSegmentLength.
    uint8_t ds_len[3];

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2;

    /// Always 0xFFFFFFFF for now.
    uint32_t tag;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved3;

    /**
     * @brief StatSN.
     *
     * This field carries its usual value and is not related to the
     * rejected command. The StatSN is advanced after a Reject.
     */
    uint32_t stat_sn;

    /**
     * @brief ExpCmdSN.
     *
     * This field carries its usual value and is not related to the
     * rejected command.
     */
    uint32_t exp_cmd_sn;

    /**
     * @brief MaxCmdSN.
     *
     * This field carries its usual value and is not related to the
     * rejected command.
     */
    uint32_t max_cmd_sn;

    /**
     * @brief DataSN / Ready To Transfer Sequence Number (R2TSN) or Reserved.
     *
     * This field is only valid if the rejected PDU is a Data/R2T SNACK and
     * the Reject reason code is "Protocol Error". The DataSN/R2TSN is the
     * next Data/R2T sequence number that the target would send for the
     * task, if any.
     */
    uint32_t data_r2t_sn;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved4;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /**
     * @brief Complete Header of Bad PDU.
     *
     * The target returns the header (not including the digest) of the
     * PDU in error as the data of the response.
     */
    iscsi_bhs_packet bad_pdu_hdr;

    /// Vendor-specific data (if any).
    uint8_t vendor_data[0];

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_reject_packet;

/**
 * @brief iSCSI NOP-Out packet data.
 *
 * NOP-Out may be used by an initiator as a "ping request" to verify
 * that a connection/session is still active and all its components are
 * operational. The NOP-In response is the "ping echo".
 *
 * A NOP-Out is also sent by an initiator in response to a NOP-In.
 *
 * A NOP-Out may also be used to confirm a changed ExpStatSN if another
 * PDU will not be available for a long time.
 *
 * Upon receipt of a NOP-In with the Target Transfer Tag set to a valid
 * value (not the reserved value 0xffffffff), the initiator MUST respond
 * with a NOP-Out. In this case, the NOP-Out Target Transfer Tag MUST
 * contain a copy of the NOP-In Target Transfer Tag. The initiator
 *
 * SHOULD NOT send a NOP-Out in response to any other received NOP-In,
 * in order to avoid lengthy sequences of NOP-In and NOP-Out PDUs sent
 * in response to each other.
 */
typedef struct __attribute__((packed)) iscsi_nop_out_packet {
    /// Always 0x00 according to iSCSI specification.
    uint8_t opcode;

    /// Reserved for future usage (always MUST be 0x80 for now).
    int8_t flags;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength.
    uint8_t total_ahs_len;

    /// DataSegmentLength.
    uint8_t ds_len[3];

    /// LUN or Reserved.
    uint64_t lun;

    /**
     * @brief Initiator Task Tag (ITT).
     *
     * The NOP-Out MUST have the Initiator Task Tag set to a valid value
     * only if a response in the form of a NOP-In is requested (i.e., the
     * NOP-Out is used as a ping request). Otherwise, the Initiator Task
     * Tag MUST be set to 0xFFFFFFFF.\n
     * When a target receives the NOP-Out with a valid Initiator Task Tag,
     * it MUST respond with a NOP-In Response.\n
     * If the Initiator Task Tag contains 0xFFFFFFFF, the I bit MUST be set
     * to 1, and the CmdSN is not advanced after this PDU is sent.
     */
    uint32_t init_task_tag;

    /**
     * @brief Target Transfer Tag (TTT).
     *
     * The Target Transfer Tag is a target-assigned identifier for the
     * operation.\n
     * The NOP-Out MUST only have the Target Transfer Tag set if it is
     * issued in response to a NOP-In with a valid Target Transfer Tag. In
     * this case, it copies the Target Transfer Tag from the NOP-In PDU.\n
     * Otherwise, the Target Transfer Tag MUST be set to 0xFFFFFFFF.\n
     * When the Target Transfer Tag is set to a value other than 0xFFFFFFFF,
     * the LUN field MUST also be copied from the NOP-In.
     */
    uint32_t target_xfer_tag;

    /// CmdSN.
    uint32_t cmd_sn;

    /// ExpStatSN.
    uint32_t exp_stat_sn;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved2[2];

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /**
     * @brief DataSegment - Ping Data (optional).
     *
     * Ping data is reflected in the NOP-In Response. The length of the
     * reflected data is limited to MaxRecvDataSegmentLength. The length of
     * ping data is indicated by the DataSegmentLength. 0 is a valid value
     * for the DataSegmentLength and indicates the absence of ping data.
     */
    iscsi_scsi_ds_cmd_data ds_ping_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_nop_out_packet;


/**
 * @brief iSCSI NOP-In packet data.
 *
 * NOP-In is sent by a target as either a response to a NOP-Out, a
 * "ping" to an initiator, or a means to carry a changed ExpCmdSN and/or
 * MaxCmdSN if another PDU will not be available for a long time (as
 * determined by the target).
 *
 * When a target receives the NOP-Out with a valid Initiator Task Tag
 * (not the reserved value 0xFFFFFFFF), it MUST respond with a NOP-In
 * with the same Initiator Task Tag that was provided in the NOP-Out
 * request. It MUST also duplicate up to the first
 * MaxRecvDataSegmentLength bytes of the initiator-provided Ping Data.
 * For such a response, the Target Transfer Tag MUST be 0xFFFFFFFF.
 *
 * The target SHOULD NOT send a NOP-In in response to any other received
 * NOP-Out in order to avoid lengthy sequences of NOP-In and NOP-Out
 * PDUs sent in response to each other.
 *
 * Otherwise, when a target sends a NOP-In that is not a response to a
 * NOP-Out received from the initiator, the Initiator Task Tag MUST be
 * set to 0xFFFFFFFF, and the data segment MUST NOT contain any data
 * (DataSegmentLength MUST be 0).
 */
typedef struct __attribute__((packed)) iscsi_nop_in_packet {
    /// Always 0x20 according to iSCSI specification.
    uint8_t opcode;

    /// Reserved for future usage (always MUST be 0x80 for now).
    int8_t flags;

    /// Reserved for future usage, always MUST be 0.
    uint16_t reserved;

    /// TotalAHSLength
    uint8_t total_ahs_len;

    /// DataSegmentLength.
    uint8_t ds_len[3];

    /// A LUN MUST be set to a correct value when the Target Transfer Tag is valid (not the reserved value 0xFFFFFFFF).
    uint64_t lun;

    /// Initiator Task Tag (ITT) or 0xFFFFFFFF.
    uint32_t init_task_tag;

    /**
     * @brief Target Transfer Tag (TTT).
     *
     * If the target is responding to a NOP-Out, this field is set to the
     * reserved value 0xFFFFFFFF.\n
     * If the target is sending a NOP-In as a ping (intending to receive a
     * corresponding NOP-Out), this field is set to a valid value (not the
     * reserved value 0xFFFFFFFF).\n
     * If the target is initiating a NOP-In without wanting to receive a
     * corresponding NOP-Out, this field MUST hold the reserved value
     * 0xFFFFFFFF.
     */
    uint32_t target_xfer_tag;

    /**
     * @brief StatSN.
     *
     * The StatSN field will always contain the next StatSN. However, when
     * the Initiator Task Tag is set to 0xFFFFFFFF, the StatSN for the
     * connection is not advanced after this PDU is sent.
     */
    uint32_t stat_sn;

    /// ExpCmdSN.
    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved2;

    /// Reserved for future usage, always MUST be 0.
    uint64_t reserved3;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /// DataSegment - Return Ping Data.
    iscsi_scsi_ds_cmd_data ds_ping_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_nop_in_packet;


/// iSCSI SCSI transport ID protocol identifier: iSCSI.
#define ISCSI_TRANSPORT_ID_PROTOCOL_ID_ISCSI     0x05

/// iSCSI SCSI transport ID protocol identifier: First bit of the four bits.
#define ISCSI_TRANSPORT_ID_PROTOCOL_ID_FIRST_BIT 0

/// iSCSI SCSI transport ID protocol identifier: Last bit of the four bits.
#define ISCSI_TRANSPORT_ID_PROTOCOL_ID_LAST_BIT  ((ISCSI_TRANSPORT_ID_PROTOCOL_ID_FIRST_BIT) + 4 - 1)

/// iSCSI SCSI transport ID protocol identifier: Bit mask.
#define ISCSI_TRANSPORT_ID_PROTOCOL_ID_MASK      (ISCSI_BITS_GET_MASK(ISCSI_TRANSPORT_ID_PROTOCOL_ID_FIRST_BIT, ISCSI_TRANSPORT_ID_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI transport ID protocol identifier: Extracts the protocol identifier bits.
#define ISCSI_TRANSPORT_ID_GET_PROTOCOL_ID(x)    (ISCSI_BITS_GET((x), ISCSI_TRANSPORT_ID_PROTOCOL_ID_FIRST_BIT, ISCSI_TRANSPORT_ID_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI transport ID protocol identifier: Stores into the protocol identifier bits.
#define ISCSI_TRANSPORT_ID_PUT_PROTOCOL_ID(x)    (ISCSI_BITS_PUT((x), ISCSI_TRANSPORT_ID_PROTOCOL_ID_FIRST_BIT, ISCSI_TRANSPORT_ID_PROTOCOL_ID_LAST_BIT))

/// iSCSI SCSI transport ID format.
#define ISCSI_TRANSPORT_ID_FORMAT                0x01

/// iSCSI SCSI transport ID format: First bit of the two bits.
#define ISCSI_TRANSPORT_ID_FORMAT_FIRST_BIT      6

/// iSCSI SCSI transport ID format: Last bit of the two bits.
#define ISCSI_TRANSPORT_ID_FORMAT_LAST_BIT       ((ISCSI_TRANSPORT_ID_FORMAT_FIRST_BIT) + 2 - 1)

/// iSCSI SCSI transport ID format: Bit mask.
#define ISCSI_TRANSPORT_ID_FORMAT_MASK           (ISCSI_BITS_GET_MASK(ISCSI_TRANSPORT_ID_FORMAT_FIRST_BIT, ISCSI_TRANSPORT_ID_FORMAT_LAST_BIT))

/// iSCSI SCSI transport ID format: Extracts the format bits.
#define ISCSI_TRANSPORT_ID_GET_FORMAT(x)         (ISCSI_BITS_GET((x), ISCSI_TRANSPORT_ID_FORMAT_FIRST_BIT, ISCSI_TRANSPORT_ID_FORMAT_LAST_BIT))

/// iSCSI SCSI transport ID format: Stores into the format bits.
#define ISCSI_TRANSPORT_ID_PUT_FORMAT(x)         (ISCSI_BITS_PUT((x), ISCSI_TRANSPORT_ID_FORMAT_FIRST_BIT, ISCSI_TRANSPORT_ID_FORMAT_LAST_BIT))


/**
 * @brief iSCSI SCSI Transport ID structure.
 *
 * This structure handles the iSCSI SCSI transport
 * identifier data.
 */
typedef struct __attribute__((packed)) iscsi_transport_id {
    /// First 4 bits are protocol ID and last 2 bits are format.
    uint8_t id;

    /// Reserved for future usage (always MUST be 0).
    uint8_t reserved;

    /// Additional length of name.
    uint16_t add_len;

    /// Name.
    uint8_t name[0];
} iscsi_transport_id;


/// Maximum length of a key according to iSCSI specifications.
#define ISCSI_TEXT_KEY_MAX_LEN          63U

/// Maximum length of value for a simple key type.
#define ISCSI_TEXT_VALUE_MAX_SIMPLE_LEN 255U

/// Maximum length of value for a normal key.
#define ISCSI_TEXT_VALUE_MAX_LEN        8192U

/// Value data shift value for key value alignment enforcement.
#define ISCSI_TEXT_VALUE_ALIGN_SHIFT    4UL

/// Value alignment size is a multiple of 16 bytes for a key value for having work space when changing string representation of integer values.
#define ISCSI_TEXT_VALUE_ALIGN          (1UL << (ISCSI_TEXT_VALUE_ALIGN_SHIFT))


/// iSCSI text key=value pair type: Invalid.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_INVALID         -1

/// iSCSI text key=value pair type: Unspecified type.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_UNSPECIFIED      0

/// iSCSI text key=value pair type: List.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST             1

/// iSCSI text key=value pair type: Numerical minimum.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN          2

/// iSCSI text key=value pair type: Numerical maximum.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MAX          3

/// iSCSI text key=value pair type: Numerical declarative.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE  4

/// iSCSI text key=value pair type: Declarative.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE      5

/// iSCSI text key=value pair type: Boolean OR.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR          6

/// iSCSI text key=value pair type: Boolean AND.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND         7


/// iSCSI key value pair flags: Discovery ignored.
#define ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_DISCOVERY_IGNORE    (1 << 0)

/// iSCSI key value pair flags: Multi negotiation.
#define ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_MULTI_NEGOTIATION   (1 << 1)

/// iSCSI key value pair flags: Target declarative.
#define ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_TARGET_DECLARATIVE  (1 << 2)

/// iSCSI key value pair flags: CHAP type.
#define ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_CHAP_TYPE           (1 << 3)

/// iSCSI key value pair flags: Requires special handling.
#define ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_SPECIAL_HANDLING    (1 << 4)

/// iSCSI key value pair flags: Use previous default value.
#define ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_PREVIOUS_VALUE  (1 << 5)

/// iSCSI key value pair flags: Override with default value.
#define ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_OVERRIDE_DEFAULT    (1 << 6)

/// iSCSI key value pair flags: Uses maximum value depending on secondary key.
#define ISCSI_TEXT_KEY_VALUE_PAIR_FLAGS_USE_OTHER_MAX_VALUE (1 << 7)


/**
 * @brief iSCSI connection and session lookup table entry, used for allowed key values and determining key type.
 *
 * This structure is shared by the iSCSI session
 * and the iSCSI connection lookup table.
 */
typedef struct iscsi_key_value_pair_lut_entry {
    /// Name of key.
    const uint8_t *key;

    /// Default value of the key, always in string representation.
    uint8_t *value;

    /// NUL separated list of allowed string values. If key type is numeric: NUL separated minimum and maximum integer range. End is marked with another NUL.
    uint8_t *list_range;

    /// Type of key and value pair.
    const int type;

    /// Flags indicating special key attributes.
    const int flags;
} iscsi_key_value_pair_lut_entry;


/**
 * @brief iSCSI Text / Login extracted key=value pair.
 *
 * This structure is used for accessing key and value
 * pairs which have been extracted from either the
 * Text or Login packet data.
 */
typedef struct iscsi_key_value_pair {
    /// Value of the key which is stored in the hash map.
	uint8_t *value;

    /// NUL separated list of allowed string values. If key type is numeric: NUL separated minimum and maximum integer range. End is marked with another NUL.
    uint8_t *list_range;

    /// Type of key and value pair.
    int type;

    /// Flags indicating special key attributes.
    int flags;

    /// State bit mask.
	uint state_mask;
} iscsi_key_value_pair;

typedef struct iscsi_connection iscsi_connection;

/**
 * @brief iSCSI Text / Login key=value packet data construction helper.
 *
 * This structure is used to store the key=value plus NUL terminator
 * pairs for sending as DataSegment packet data to the client.
 */
typedef struct iscsi_key_value_pair_packet {
    /// Associated iSCSI connection.
    iscsi_connection *conn;

    /// Current text buffer containing multiple key=value + NUL terminator pairs.
    uint8_t *buf;

    /// Position of output buffer for next write.
    uint32_t pos;

    /// Current length of buffer including final NUL terminator without iSCSI zero padding.
    uint32_t len;

    /// Discovery mode.
    int discovery;
} iscsi_key_value_pair_packet;

int iscsi_parse_key_value_pairs(iscsi_hashmap *key_value_pairs, const uint8_t *packet_data, uint len, int c_bit, uint8_t **partial_pairs); // Extracts all text key / value pairs out of an iSCSI packet into a hash map


/// iSCSI main global data: INI configuration filename.
#define ISCSI_GLOBALS_CONFIG_FILENAME "iscsi.conf"


/// iSCSI main global data: iSCSI INI configuration iSCSI section identifier string.
#define ISCSI_GLOBALS_SECTION_ISCSI              "iscsi"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI               "scsi"


/// iSCSI main global data: iSCSI INI configuration iSCSI section target name check key identifier string.
#define ISCSI_GLOBALS_SECTION_ISCSI_KEY_TARGET_NAME_CHECK        "TargetNameCheck"

/// iSCSI main global data: iSCSI INI configuration iSCSI section maximum number of sessions allowed key identifier string.
#define ISCSI_GLOBALS_SECTION_ISCSI_KEY_MAX_SESSIONS             "MaxSessions"

/// iSCSI main global data: iSCSI INI configuration iSCSI section maximum number of connections per session allowed key identifier string.
#define ISCSI_GLOBALS_SECTION_ISCSI_MAX_CONNECTIONS_PER_SESSIONS "MaxConnectionsPerSession"


/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section device type key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_DEVICE_TYPE         "DeviceType"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section physical block size key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_PHYSICAL_BLOCK_SIZE "PhysicalBlockSize"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section logical block size key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_LOGICAL_BLOCK_SIZE  "LogicalBlockSize"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section removable device key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_REMOVABLE           "Removable"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section UNMAP support device key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_UNMAP               "UNMAP"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section no rotation device key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_NO_ROTATION         "NoRotation"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section physical read only device key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_PHYSICAL_READ_ONLY  "PhysicalReadOnly"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section write protected device key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_WRITE_PROTECT       "WriteProtect"

/// iSCSI main global data: iSCSI INI configuration iSCSI SCSI section write cache supported device key identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_KEY_WRITE_CACHE         "WriteCache"


/// iSCSI main global data: iSCSI SCSI device specific INI configuration section prefix identifier string.
#define ISCSI_GLOBALS_SECTION_SCSI_DEVICE_PREFIX "scsi-device-"


/// iSCSI main global data config type: iHeader digest (CRC32), always MUST be 0 or 4 for now.
#define ISCSI_GLOBALS_CONFIG_TYPE_HEADER_DIGEST                     0

/// iSCSI main global data config type: Data digest (CRC32), always MUST be 0 or 4 for now.
#define ISCSI_GLOBALS_CONFIG_TYPE_DATA_DIGEST                       1

/// iSCSI main global data config type: Maximum receive DataSegment length in bytes.
#define ISCSI_GLOBALS_CONFIG_TYPE_MAX_RECV_DS_LEN                   2

/// iSCSI main global data config type: Maximum number of connections per session.
#define ISCSI_GLOBALS_CONFIG_TYPE_MAX_SESSION_CONNS                 3

/// iSCSI main global data config type: Ready to transfer maximum outstanding value.
#define ISCSI_GLOBALS_CONFIG_TYPE_MAX_OUTSTANDING_R2T               4

/// iSCSI main global data config type: Default time to wait.
#define ISCSI_GLOBALS_CONFIG_TYPE_DEFAULT_TIME_TO_WAIT              5

/// iSCSI main global data config type: Default time to retain.
#define ISCSI_GLOBALS_CONFIG_TYPE_DEFAULT_TIME_TO_RETAIN            6

/// iSCSI main global data config type: First burst length.
#define ISCSI_GLOBALS_CONFIG_TYPE_FIRST_BURST_LEN                   7

/// iSCSI main global data config type: Maximum burst length.
#define ISCSI_GLOBALS_CONFIG_TYPE_MAX_BURST_LEN                     8

/// iSCSI main global data config type: Error recovery level.
#define ISCSI_GLOBALS_CONFIG_TYPE_ERR_RECOVERY_LEVEL                9

/// iSCSI main global data config type: SCSI emulation for device type.
#define ISCSI_GLOBALS_CONFIG_TYPE_SCSI_DEVICE_TYPE                 10

/// iSCSI main global data config type: SCSI emulation for physical block size.
#define ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE         11

/// iSCSI main global data config type: SCSI emulation for physical block size shift count.
#define ISCSI_GLOBALS_CONFIG_TYPE_SCSI_PHYSICAL_BLOCK_SIZE_SHIFT   12

/// iSCSI main global data config type: SCSI emulation for logical block size.
#define ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE          13

/// iSCSI main global data config type: SCSI emulation for logical block size shift count.
#define ISCSI_GLOBALS_CONFIG_TYPE_SCSI_LOGICAL_BLOCK_SIZE_SHIFT    14

/// iSCSI main global data config type: Initial ready to transfer.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_INIT_R2T                   15

/// iSCSI main global data config type: Immediate data.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_IMMEDIATE_DATA             16

/// iSCSI main global data config type: Data PDU in order.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_DATA_PDU_IN_ORDER          17

/// iSCSI main global data config type: Data sequence in order.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_DATA_SEQ_IN_ORDER          18

/// iSCSI main global data config type: SCSI emulation for I/O removable device.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_REMOVABLE          19

/// iSCSI main global data config type: SCSI emulation for I/O UNMAP supporting device.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_UNMAP              20

/// iSCSI main global data config type: SCSI emulation for I/O non-rotating device.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_NO_ROTATION        21

/// iSCSI main global data config type: SCSI emulation for I/O physical read only device.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY 22

/// iSCSI main global data config type: SCSI emulation for I/O write protected device.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_PROTECT      23

/// iSCSI main global data config type: SCSI emulation for I/O write cache device.
#define ISCSI_GLOBALS_CONFIG_TYPE_FLAGS_SCSI_IO_WRITE_CACHE        24


/// iSCSI main global data SCSI device configuration flags: Initial ready to transfer.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_INIT_R2T                   (1 << 0)

/// iSCSI main global data SCSI device configuration flags: Immediate data.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_IMMEDIATE_DATA             (1 << 1)

/// iSCSI main global data SCSI device configuration flags: Data PDU in order.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_DATA_PDU_IN_ORDER          (1 << 2)

/// iSCSI main global data SCSI device configuration flags: Data sequence in order.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_DATA_SEQ_IN_ORDER          (1 << 3)

/// iSCSI main global data SCSI device configuration flags: SCSI emulation for I/O removable device.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_REMOVABLE          (1 << 4)

/// iSCSI main global data SCSI device configuration flags: SCSI emulation for I/O UNMAP supporting device.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_UNMAP              (1 << 5)

/// iSCSI main global data SCSI device configuration flags: SCSI emulation for I/O non-rotating device.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_NO_ROTATION        (1 << 6)

/// iSCSI main global data SCSI device configuration flags: SCSI emulation for I/O physical read only device.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY (1 << 7)

/// iSCSI main global data SCSI device configuration flags: SCSI emulation for I/O write protected device.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_PROTECT      (1 << 8)

/// iSCSI main global data SCSI device configuration flags: SCSI emulation for I/O write cache device.
#define ISCSI_GLOBALS_SCSI_DEVICE_CONFIG_FLAGS_SCSI_IO_WRITE_CACHE        (1 << 9)


/**
 * @brief iSCSI main global data SCSI device configuration.
 *
 * This structure is used for specific SCSI device
 * configuration which are matched using wildcard
 * patterns which are stored in the hash map key.
 */
typedef struct iscsi_scsi_device_config {
    /// SCSI device configuration flags.
    int flags;

    /// iHeader digest (CRC32), always MUST be 0 or 4 for now.
	int header_digest;

    /// Data digest (CRC32), always MUST be 0 or 4 for now.
	int data_digest;

    /// SCSI emulation: Device type.
    uint scsi_device_type;

    /// Maximum receive DataSegment length in bytes.
    uint32_t max_recv_ds_len;

    /// Maximum number of connections per session.
    uint32_t max_session_conns;

    /// Ready to transfer maximum outstanding value.
    uint32_t max_outstanding_r2t;

    /// Default time to wait.
    uint32_t default_time_to_wait;

    /// Default time to retain.
    uint32_t default_time_to_retain;

    /// First burst length.
    uint32_t first_burst_len;

    /// Maximum burst length.
    uint32_t max_burst_len;

    /// Error recovery level.
    uint32_t err_recovery_level;

    /// SCSI emulation: Physical block size.
    uint32_t scsi_physical_block_size;

    /// SCSI emulation: Physical block size shift count.
    uint32_t scsi_physical_block_size_shift;

    /// SCSI emulation: Logical block size.
    uint32_t scsi_logical_block_size;

    /// SCSI emulation: Logical block size shift count.
    uint32_t scsi_logical_block_size_shift;
} iscsi_scsi_device_config;


/**
 * @brief iSCSI SCSI device configuration search by name.
 *
 * This structure is used by iterating through
 * all iSCSI SCSI device configurations and
 * uses wildcard matching in order to retrieve
 * the correct SCSI configuration for a
 * specified device name.
 */
typedef struct iscsi_scsi_device_config_find {
    /// Found iSCSI SCSI device configuration is stored here, should be initialized to NULL.
    iscsi_scsi_device_config *scsi_device_config;

    /// The name to be searched for is stored here.
    uint8_t *name;
} iscsi_scsi_device_config_find;


/// iSCSI main global data flags: Allow duplicate ISIDs.
#define ISCSI_GLOBALS_FLAGS_ISID_ALLOW_DUPLICATES      (1 << 0)

/// iSCSI main global data flags: CHAP authentication is disabled.
#define ISCSI_GLOBALS_FLAGS_CHAP_DISABLE               (1 << 1)

/// iSCSI main global data flags: CHAP authentication is required.
#define ISCSI_GLOBALS_FLAGS_CHAP_REQUIRE               (1 << 2)

/// iSCSI main global data flags: CHAP authentication is mutual.
#define ISCSI_GLOBALS_FLAGS_CHAP_MUTUAL                (1 << 3)

/// iSCSI main global data flags: Initial ready to transfer.
#define ISCSI_GLOBALS_FLAGS_INIT_R2T                   (1 << 4)

/// iSCSI main global data flags: Immediate data.
#define ISCSI_GLOBALS_FLAGS_IMMEDIATE_DATA             (1 << 5)

/// iSCSI main global data flags: Data PDU in order.
#define ISCSI_GLOBALS_FLAGS_DATA_PDU_IN_ORDER          (1 << 6)

/// iSCSI main global data flags: Data sequence in order.
#define ISCSI_GLOBALS_FLAGS_DATA_SEQ_IN_ORDER          (1 << 7)

/// iSCSI main global data flags: SCSI emulation for I/O removable device.
#define ISCSI_GLOBALS_FLAGS_SCSI_IO_REMOVABLE          (1 << 8)

/// iSCSI main global data flags: SCSI emulation for I/O UNMAP supporting device.
#define ISCSI_GLOBALS_FLAGS_SCSI_IO_UNMAP              (1 << 9)

/// iSCSI main global data flags: SCSI emulation for I/O non-rotating device.
#define ISCSI_GLOBALS_FLAGS_SCSI_IO_NO_ROTATION        (1 << 10)

/// iSCSI main global data flags: SCSI emulation for I/O physical read only device.
#define ISCSI_GLOBALS_FLAGS_SCSI_IO_PHYSICAL_READ_ONLY (1 << 11)

/// iSCSI main global data flags: SCSI emulation for I/O write protected device.
#define ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_PROTECT      (1 << 12)

/// iSCSI main global data flags: SCSI emulation for I/O write cache device.
#define ISCSI_GLOBALS_FLAGS_SCSI_IO_WRITE_CACHE        (1 << 13)


/// iSCSI main global data target name validation check level: None, allow everything.
#define ISCSI_GLOBALS_TARGET_NAME_CHECK_NONE    0

/// iSCSI main global data target name validation check level: Relaxed, check for maximum target name length and if target name starts with 'iqn.', 'naa.' or 'eui.' also check if target name only contains allowed characters.
#define ISCSI_GLOBALS_TARGET_NAME_CHECK_RELAXED 1

/// iSCSI main global data target name validation check level: Full, check for maximum target name length and always check target name only contains allowed characters.
#define ISCSI_GLOBALS_TARGET_NAME_CHECK_FULL    2


/// iSCSI main global data: Default maximum number of connections.
#define ISCSI_GLOBALS_DEFAULT_MAX_CONNECTIONS     1UL

/// iSCSI main global data: Default maximum number of outstanding ready to transfers.
#define ISCSI_GLOBALS_DEFAULT_MAX_OUTSTANDING_R2T 1UL

/// iSCSI main global data: Default time to wait in seconds.
#define ISCSI_GLOBALS_DEFAULT_TIME_TO_WAIT        2UL

/// iSCSI main global data: Default time to retain in seconds.
#define ISCSI_GLOBALS_DEFAULT_TIME_TO_RETAIN      20UL

/// iSCSI main global data: First burst length in bytes.
#define ISCSI_GLOBALS_DEFAULT_FIRST_BURST_LEN     ISCSI_DEFAULT_RECV_DS_LEN

/// iSCSI main global data: Maximum burst length in bytes.
#define ISCSI_GLOBALS_DEFAULT_MAX_BURST_LEN       (ISCSI_DEFAULT_MAX_RECV_DS_LEN * ISCSI_DEFAULT_MAX_DATA_OUT_PER_CONNECTION)

/// iSCSI main global data: Default error recovery level.
#define ISCSI_GLOBALS_DEFAULT_ERR_RECOVERY_LEVEL  0UL


/**
 * @brief This is the main global iSCSI structure which manages all global data.
 *
 * All iSCSI portal groups, target nodes, sessions and
 * connections are stored here for global access.
 */
typedef struct iscsi_globals {
    /// Hash map containing all iSCSI devices.
    iscsi_hashmap *devices;

    /// Read/write lock for hash map containing all iSCSI devices. MUST be initialized with iscsi_create before any iSCSI functions are used.
    pthread_rwlock_t devices_rwlock;

    /// Hash map containing all registered iSCSI portal groups.
    iscsi_hashmap *portal_groups;

    /// Read/write lock for hash map containing all iSCSI portal_groups. MUST be initialized with iscsi_create before any iSCSI functions are used.
    pthread_rwlock_t portal_groups_rwlock;

    /// iSCSI target nodes.
    iscsi_hashmap *target_nodes;

    /// Read/write lock for hash map containing all iSCSI target nodes. MUST be initialized with iscsi_create before any iSCSI functions are used.
    pthread_rwlock_t target_nodes_rwlock;

    /// Hash map containing all iSCSI sessions.
    iscsi_hashmap *sessions;

    /// Read/write lock for hash map containing all iSCSI sessions. MUST be initialized with iscsi_create before any iSCSI functions are used.
    pthread_rwlock_t sessions_rwlock;

    /// Hash map containing session key and value pair types and allowed values or ranges.
    iscsi_hashmap *session_key_value_pairs;

    /// Hash map containing connection key and value pair types and allowed values or ranges.
    iscsi_hashmap *connection_key_value_pairs;

    /// Hash map containing iSCSI SCSI device specific configuration.
    iscsi_hashmap *scsi_device_config;

    /// Mutex for hash map containing iSCSI SCSI device specific configuration.
    pthread_mutex_t scsi_device_config_mutex;

    /// Global flags.
    int flags;

    /// Target name validation check level.
    int target_name_check;

    /// Maximum number of allowed sessions.
    uint max_sessions;

    /// iHeader digest (CRC32), always MUST be 0 or 4 for now.
	int header_digest;

    /// Data digest (CRC32), always MUST be 0 or 4 for now.
	int data_digest;

    /// SCSI emulation: Device type.
    uint scsi_device_type;

    /// Maximum receive DataSegment length in bytes.
    uint32_t max_recv_ds_len;

    /// Maximum number of connections per session.
    uint32_t max_session_conns;

    /// Ready to transfer maximum outstanding value.
    uint32_t max_outstanding_r2t;

    /// Default time to wait.
    uint32_t default_time_to_wait;

    /// Default time to retain.
    uint32_t default_time_to_retain;

    /// First burst length.
    uint32_t first_burst_len;

    /// Maximum burst length.
    uint32_t max_burst_len;

    /// Error recovery level.
    uint32_t err_recovery_level;

    /// CHAP group id.
    int32_t chap_group;

    /// SCSI emulation: Physical block size.
    uint32_t scsi_physical_block_size;

    /// SCSI emulation: Physical block size shift count.
    uint32_t scsi_physical_block_size_shift;

    /// SCSI emulation: Logical block size.
    uint32_t scsi_logical_block_size;

    /// SCSI emulation: Logical block size shift count.
    uint32_t scsi_logical_block_size_shift;
} iscsi_globals;


/// Reference to iSCSI global vector. MUST be initialized with iscsi_create before any iSCSI functions are used.
extern iscsi_globals *iscsi_globvec;

/// Read/write lock for iSCSI global vector. MUST be initialized with iscsi_create before any iSCSI functions are used.
extern pthread_rwlock_t iscsi_globvec_rwlock;


int iscsi_create(); // Allocates and initializes the iSCSI global vector structure
void iscsi_destroy(); // Deallocates all resources acquired by iscsi_create

int iscsi_config_load(iscsi_globals *globvec); // Loads iSCSI server configuration from INI file
int iscsi_config_get_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Finds an iSCSI SCSI device configuration by name using pattern matching
int32_t iscsi_config_get(uint8_t *name, const int type); // Retrieves a configuration value either from the iSCSI global vector or for a specified SCSI device name


/**
 * @brief iSCSI portal group: Private portal group if set, public otherwise.
 *
 * When redirecting logins, there are two portal group types: public and
 * private.\n
 * Public portal groups return their portals during discovery session.
 * A redirection private portal may also be specified for non-discovery
 * logins.\n
 * Private portal groups instead do not return their portals during
 * the discovery session.
 */
#define ISCSI_PORTAL_GROUP_PRIVATE      (1 << 0)

/// iSCSI portal group: CHAP authentication is disabled.
#define ISCSI_PORTAL_GROUP_CHAP_DISABLE (1 << 1)

/// iSCSI portal group: CHAP authentication is required.
#define ISCSI_PORTAL_GROUP_CHAP_REQUIRE (1 << 2)

/// iSCSI portal group: CHAP authentication is mutual.
#define ISCSI_PORTAL_GROUP_CHAP_MUTUAL  (1 << 3)


/**
 * @brief iSCSI portal group.
 *
 * Portal groups are either public or private and also are used
 * by CHAP authentication.
 */
typedef struct iscsi_portal_group {
    /// Hash map containing all portals associated with this iSCSI group.
    iscsi_hashmap *portals;

    /// Tag value for this portal group.
    uint64_t tag;

    /// Reference count.
    int ref_count;

    /// Portal group flags.
    int flags;

    /// CHAP group id.
    int32_t chap_group;
} iscsi_portal_group;


/**
 * @brief iSCSI portal.
 *
 * iSCSI portals manage the host / IP address and port, as well
 * as the associated connections.
 */
typedef struct iscsi_portal {
    /// Group this portal belongs to.
	iscsi_portal_group *group;

    /// Hostname / IP address of the portal.
    uint8_t *host;

    /// Port of the portal.
    uint8_t *port;

    /// TCP/IP socket for the portal.
    int sock;
} iscsi_portal;


iscsi_portal_group *iscsi_portal_group_create(const uint64_t tag, const int flags); // Creates and initializes an iSCSI portal group
int iscsi_portal_group_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI portal group destructor callback for hash map
void iscsi_portal_group_destroy(iscsi_portal_group *portal_group); // Deallocates resources acquired by iscsi_portal_group_create
int iscsi_portal_group_add_portal(iscsi_portal_group *portal_group, iscsi_portal *portal); // Adds an iSCSI portal to the iSCSI portal group hash map
void iscsi_portal_group_del_portal(iscsi_portal_group *portal_group, iscsi_portal *portal); // Removes an iSCSI portal from the iSCSI portal group hash map

iscsi_portal *iscsi_portal_create(const uint8_t *host, const uint8_t *port); // Allocates and initializes an iSCSI portal structure
int iscsi_portal_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI portal destructor callback for hash map
void iscsi_portal_destroy(iscsi_portal *portal);


/// iSCSI SCSI status code: Good.
#define ISCSI_SCSI_STATUS_GOOD                  0x00

/// iSCSI SCSI status code: Check condition.
#define ISCSI_SCSI_STATUS_CHECK_COND            0x02

/// iSCSI SCSI status code: Condition met.
#define ISCSI_SCSI_STATUS_COND_MET              0x04

/// iSCSI SCSI status code: Busy.
#define ISCSI_SCSI_STATUS_BUSY                  0x08

/// iSCSI SCSI status code: Intermediate.
#define ISCSI_SCSI_STATUS_INTERMEDIATE          0x10

/// iSCSI SCSI status code: Intermediate condition met.
#define ISCSI_SCSI_STATUS_INTERMEDIATE_COND_MET 0x14

/// iSCSI SCSI status code: Reservation conflict.
#define ISCSI_SCSI_STATUS_RESERVATION_CONFLICT  0x18

/// iSCSI SCSI status code: Obselete.
#define ISCSI_SCSI_STATUS_OBSELETE              0x22

/// iSCSI SCSI status code: Task set full.
#define ISCSI_SCSI_STATUS_TASK_SET_FULL         0x28

/// iSCSI SCSI status code: ACA active.
#define ISCSI_SCSI_STATUS_ACA_ACTIVE            0x30

/// iSCSI SCSI status code: Task aborted.
#define ISCSI_SCSI_STATUS_TASK_ABORTED          0x40


/// iSCSI SCSI sense key: No sense.
#define ISCSI_SCSI_SENSE_KEY_NO_SENSE        0x00

/// iSCSI SCSI sense key: Recovered error.
#define ISCSI_SCSI_SENSE_KEY_RECOVERED_ERR   0x01

/// iSCSI SCSI sense key: Not ready.
#define ISCSI_SCSI_SENSE_KEY_NOT_READY       0x02

/// iSCSI SCSI sense key: Medium error.
#define ISCSI_SCSI_SENSE_KEY_MEDIUM_ERR      0x03

/// iSCSI SCSI sense key: Hardware error.
#define ISCSI_SCSI_SENSE_KEY_HARDWARE_ERR    0x04

/// iSCSI SCSI sense key: Illegal request.
#define ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ     0x05

/// iSCSI SCSI sense key: Unit attention.
#define ISCSI_SCSI_SENSE_KEY_UNIT_ATTENTION  0x06

/// iSCSI SCSI sense key: Data protect.
#define ISCSI_SCSI_SENSE_KEY_DATA_PROTECT    0x07

/// iSCSI SCSI sense key: Blank check.
#define ISCSI_SCSI_SENSE_KEY_BLANK_CHECK     0x08

/// iSCSI SCSI sense key: Vendor specific.
#define ISCSI_SCSI_SENSE_KEY_VENDOR_SPECIFIC 0x09

/// iSCSI SCSI sense key: Copy aborted.
#define ISCSI_SCSI_SENSE_KEY_COPY_ABORTED    0x0A

/// iSCSI SCSI sense key: Aborted command.
#define ISCSI_SCSI_SENSE_KEY_ABORTED_COMMAND 0x0B

/// iSCSI SCSI sense key: Volume overflow.
#define ISCSI_SCSI_SENSE_KEY_VOLUME_OVERFLOW 0x0D

/// iSCSI SCSI sense key: Miscompare.
#define ISCSI_SCSI_SENSE_KEY_MISCOMPARE      0x0E


/// iSCSI SCSI Additional Sense Code (ASC): No additional sense.
#define ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE                0x00

/// iSCSI SCSI Additional Sense Code (ASC): Peripheral device write fault.
#define ISCSI_SCSI_ASC_PERIPHERAL_DEVICE_WRITE_FAULT      0x03

/// iSCSI SCSI Additional Sense Code (ASC): Logical unit not ready.
#define ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY             0x04

/// iSCSI SCSI Additional Sense Code (ASC): Warning.
#define ISCSI_SCSI_ASC_WARNING                            0x0B

/// iSCSI SCSI Additional Sense Code (ASC): Write error.
#define ISCSI_SCSI_ASC_WRITE_ERR                          0x0C

/// iSCSI SCSI Additional Sense Code (ASC): Block guard check failed.
#define ISCSI_SCSI_ASC_LOGICAL_BLOCK_GUARD_CHECK_FAIL     0x10

/// iSCSI SCSI Additional Sense Code (ASC): Block application tag checdk failed.
#define ISCSI_SCSI_ASC_LOGICAL_BLOCK_APP_TAG_CHECK_FAIL   0x10

/// iSCSI SCSI Additional Sense Code (ASC): Block reference tag check failed.
#define ISCSI_SCSI_ASC_LOGICAL_BLOCK_REF_TAG_CHECK_FAIL   0x10

/// iSCSI SCSI Additional Sense Code (ASC): Unrecovered read error.
#define ISCSI_SCSI_ASC_UNRECOVERED_READ_ERR               0x11

/// iSCSI SCSI Additional Sense Code (ASC): Miscompare during verify operation.
#define ISCSI_SCSI_ASC_MISCOMPARE_DURING_VERIFY_OPERATION 0x1D

/// iSCSI SCSI Additional Sense Code (ASC): Invalid command operation code.
#define ISCSI_SCSI_ASC_INVALID_COMMAND_OPERATION_CODE     0x20

/// iSCSI SCSI Additional Sense Code (ASC): Access denied.
#define ISCSI_SCSI_ASC_ACCESS_DENIED                      0x20

/// iSCSI SCSI Additional Sense Code (ASC): Logical block address out of range.
#define ISCSI_SCSI_ASC_LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE 0x21

/// iSCSI SCSI Additional Sense Code (ASC): Invalid field in CDB.
#define ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB               0x24

/// iSCSI SCSI Additional Sense Code (ASC): Logical unit not supported.
#define ISCSI_SCSI_ASC_LU_NOT_SUPPORTED                   0x25

/// iSCSI SCSI Additional Sense Code (ASC): Write protected.
#define ISCSI_SCSI_ASC_WRITE_PROTECTED                    0x27

/// iSCSI SCSI Additional Sense Code (ASC): Data has changed.
#define ISCSI_SCSI_ASC_CAPACITY_DATA_HAS_CHANGED          0x2A

/// iSCSI SCSI Additional Sense Code (ASC): Format command failed.
#define ISCSI_SCSI_ASC_FORMAT_COMMAND_FAIL                0x31

/// iSCSI SCSI Additional Sense Code (ASC): Saving parameters not supported.
#define ISCSI_SCSI_ASC_SAVING_PARAMETERS_NOT_SUPPORTED    0x39

/// iSCSI SCSI Additional Sense Code (ASC): Internal target failure.
#define ISCSI_SCSI_ASC_INTERNAL_TARGET_FAIL               0x44


/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Cause not reportable.
#define ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE             0x00

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Becoming ready.
#define ISCSI_SCSI_ASCQ_BECOMING_READY                   0x01

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Format command failed.
#define ISCSI_SCSI_ASCQ_FORMAT_COMMAND_FAIL              0x01

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Block guard check failed.
#define ISCSI_SCSI_ASCQ_LOGICAL_BLOCK_GUARD_CHECK_FAIL   0x01

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Block application tag check failed.
#define ISCSI_SCSI_ASCQ_LOGICAL_BLOCK_APP_TAG_CHECK_FAIL 0x02

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): No access rights.
#define ISCSI_SCSI_ASCQ_NO_ACCESS_RIGHTS                 0x02

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Manual intervention required.
#define ISCSI_SCSI_ASCQ_MANUAL_INTERVENTION_REQUIRED     0x03

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Block reference tag check failed.
#define ISCSI_SCSI_ASCQ_LOGICAL_BLOCK_REF_TAG_CHECK_FAIL 0x03

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Power loss expected.
#define ISCSI_SCSI_ASCQ_POWER_LOSS_EXPECTED              0x08

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Invalid logical unit identifier.
#define ISCSI_SCSI_ASCQ_INVALID_LU_IDENTIFIER            0x09

/// iSCSI SCSI Additional Sense Code Qualifier (ASCQ): Capacity data has changed.
#define ISCSI_SCSI_ASCQ_CAPACITY_DATA_HAS_CHANGED        0x09


typedef struct iscsi_port iscsi_port;


/**
 * @brief iSCSI SCSI Persistent Reservation (PR) registrant with I_T nexus.
 *
 * I_T nexus is a nexus which exists between an initiator and a
 * target.
 */
typedef struct iscsi_scsi_pr_registrant {
    /// Target iSCSI port.
    iscsi_port *target_port;

    /// Target iSCSI port name.
    uint8_t *target_name;

    /// Initiator iSCSI port.
    iscsi_port *init_port;

    /// Initiator iSCSI port name.
    uint8_t *init_name;

    /// Transport ID.
    iscsi_transport_id *transport_id;

    /// Reservation key.
    uint64_t r_key;

    /// Relative target port identifier.
    uint16_t rel_target_port_id;

    /// Transport ID length.
    uint16_t transport_id_len;
} iscsi_scsi_pr_registrant;


/// iSCSI SCSI Persistent Reservation (PR) reservation type: Write exclusive.
#define ISCSI_SCSI_PR_RESERVATION_TYPE_WRITE_EXCLUSIVE            0x01

/// iSCSI SCSI Persistent Reservation (PR) reservation type: Exclusive access.
#define ISCSI_SCSI_PR_RESERVATION_TYPE_EXCLUSIVE_ACCESS           0x03

/// iSCSI SCSI Persistent Reservation (PR) reservation type: Write exclusive - registrants only.
#define ISCSI_SCSI_PR_RESERVATION_TYPE_WRITE_EXCLUSIVE_REGS_ONLY  0x05

/// iSCSI SCSI Persistent Reservation (PR) reservation type: Exclusive access - registrants only.
#define ISCSI_SCSI_PR_RESERVATION_TYPE_EXCLUSIVE_ACCESS_REGS_ONLY 0x06

/// iSCSI SCSI Persistent Reservation (PR) reservation type: Write exclusive - all registrants.
#define ISCSI_SCSI_PR_RESERVATION_TYPE_WRITE_EXCLUSIVE_ALL_REGS   0x07

/// iSCSI SCSI Persistent Reservation (PR) reservation type: Exclusive access - all registrants.
#define ISCSI_SCSI_PR_RESERVATION_TYPE_EXCLUSIVE_ACCESS_ALL_REGS  0x08


/// iSCSI SCSI Persistent Reservation (PR) reservation flags: SPC2 reserve.
#define ISCSI_SCSI_PR_RESERVATION_FLAGS_SPC2_RESERVE (1L << 0L)


/**
 * @brief iSCSI SCSI Persistent Reservation (PR) reservation with LU_SCOPE.
 *
 * LU_SCOPE means that Persistent Reservation (PR) scope
 * applies to the full logical unit.
 */
typedef struct iscsi_scsi_pr_reservation {
    /// Registrant for this reservation.
    iscsi_scsi_pr_registrant *holder;

    /// Current reservation key.
    uint64_t cr_key;

    /// Reservation type.
    int type;

    /// Reservation flags.
    int32_t flags;
} iscsi_scsi_pr_reservation;


/**
 * @brief iSCSI SCSI Persistent Reservation (PR) registrant search by target and initiator port.
 *
 * This structure is used by iterating through
 * all iSCSI LUN Persistent Reservation (PR)
 * registrant's finding by target and initiator
 * port.
 */
typedef struct iscsi_scsi_pr_registrant_get_reg {
    /// Found iSCSI SCSI Persistent Reservation (PR) registrant is stored here, should be initialized to NULL.
    iscsi_scsi_pr_registrant *reg;

    /// The target port to be searched for is stored here.
    iscsi_port *target_port;

    /// The initiator port to be searched for is stored here.
    iscsi_port *init_port;
} iscsi_scsi_pr_registrant_get_reg;


/// iSCSI SCSI task run: Unknown.
#define ISCSI_SCSI_TASK_RUN_UNKNOWN  -1

/// iSCSI SCSI task run: Completed.
#define ISCSI_SCSI_TASK_RUN_COMPLETE  0

/// iSCSI SCSI task run: Pending.
#define ISCSI_SCSI_TASK_RUN_PENDING   1


typedef struct iscsi_scsi_task iscsi_scsi_task;
typedef struct iscsi_scsi_lun iscsi_scsi_lun;


/**
 * @brief Callback when iSCSI SCSI transfer task completed.
 *
 * This function is invoked when an iSCSI task
 * finished a transfer.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task which
 * completed the transfer and may NOT be NULL,
 * so be careful.
 */
typedef void (*iscsi_scsi_task_xfer_complete_callback)(iscsi_scsi_task *scsi_task);

/**
 * @brief Callback when iSCSI SCSI transfer task destruction.
 *
 * This function is invoked when an iSCSI task
 * needs to be destroyed.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task which
 * is about to be destroyed and may NOT be
 * NULL, so be careful.
 */
typedef void (*iscsi_scsi_task_destroy_callback)(iscsi_scsi_task *scsi_task);

/**
 * @brief Callback for I/O operation completion.
 *
 * This function is invoked when an I/O operation
 * has been completed.
 *
 * @param[in] image Pointer to DNBD3 image which completed the
 * I/O operation.
 * @param[in] user_data Pointer to user data.
 * @param[in] success true if I/O completed successfully or false
 * if it failed instead.
 * @return Pointer to passed user data.
 */
typedef uint8_t *(*iscsi_scsi_emu_io_complete_callback)(dnbd3_image_t *image, uint8_t *user_data, const bool success);

/**
 * @brief Callback for I/O wait operation.
 *
 * This function is invoked when an I/O
 * operation needs waiting.
 *
 * @param[in] user_data Pointer to user data.
 * @return Pointer to passed user data.
 */
typedef uint8_t *(*iscsi_scsi_emu_io_wait_callback)(uint8_t *user_data);


typedef struct iscsi_scsi_emu_io_wait {
    /// I/O task wait callback associated DNBD3 image.
    dnbd3_image_t *image;

    /// I/O task wait callback function.
    iscsi_scsi_emu_io_wait_callback callback;

    /// I/O task wait callback user data.
    uint8_t *user_data;
} iscsi_scsi_emu_io_wait;


/// iSCSI SCSI task flags: Read.
#define ISCSI_SCSI_TASK_FLAGS_XFER_READ  (1 << 0)

/// iSCSI SCSI task flags: Write.
#define ISCSI_SCSI_TASK_FLAGS_XFER_WRITE (1 << 1)


/**
 * @brief iSCSI SCSI Task.
 *
 * This structure is used for the iSCSI SCSI
 * layer task management.
 */
typedef struct iscsi_scsi_task {
    /// Doubly linked list node, MUST be first element.
    iscsi_node node;

    /// SCSI LUN associated with this task.
    iscsi_scsi_lun *lun;

    /// Target iSCSI port.
    iscsi_port *target_port;

    /// Initiator iSCSI port.
    iscsi_port *init_port;

    /// SCSI Command Descriptor Block (CDB).
    iscsi_scsi_cdb *cdb;

    /// SCSI sense data.
    iscsi_scsi_sense_data_packet *sense_data;

    /// Transfer complete callback function.
    iscsi_scsi_task_xfer_complete_callback xfer_complete_callback;

    /// Task destruction callback function.
    iscsi_scsi_task_destroy_callback destroy_callback;

    /// I/O task complete callback function.
    iscsi_scsi_emu_io_complete_callback io_complete_callback;

    /// I/O task wait.
    iscsi_scsi_emu_io_wait io_wait;

    /// Output buffer.
    uint8_t *buf;

    /// Position of buffer in bytes.
    uint32_t pos;

    /// Length of buffer in bytes.
    uint32_t len;

    /// Unique identifier for this task.
    uint64_t id;

    /// Flags.
    int flags;

    /// Reference counter.
    uint32_t ref;

    /// Transfer position in bytes.
    uint32_t xfer_pos;

    /// Transfer length in bytes.
    uint32_t xfer_len;

    /// Sense data length.
    uint8_t sense_data_len;

    /// iSCSI SCSI status code.
    uint8_t status;

    /// Task management function.
    uint8_t task_mgmt_func;

    /// Task management response code.
    uint8_t task_mgmt_response;
} iscsi_scsi_task;


/// iSCSI SCSI emulation physical block size in bytes.
#define ISCSI_SCSI_EMU_PHYSICAL_BLOCK_SIZE 4096UL

/// iSCSI SCSI emulation logical block size in bytes.
#define ISCSI_SCSI_EMU_BLOCK_SIZE          512UL


/// iSCSI SCSI emulation maximum tansfer length in logical blocks.
#define ISCSI_SCSI_EMU_MAX_XFER_LEN        (ISCSI_DEFAULT_MAX_RECV_DS_LEN * ISCSI_DEFAULT_MAX_DATA_OUT_PER_CONNECTION)

/// iSCSI SCSI emulation maximum UNMAP LBA count in LBAs.
#define ISCSI_SCSI_EMU_MAX_UNMAP_LBA_COUNT (ISCSI_DEFAULT_MAX_RECV_DS_LEN * ISCSI_DEFAULT_MAX_DATA_IN_PER_CONNECTION)

/// iSCSI SCSI emulation maximum UNMAP block descriptor count in block descriptors.
#define ISCSI_SCSI_EMU_MAX_UNMAP_BLOCK_DESC_COUNT 256UL


/// iSCSI SCSI emulation I/O type: Removable.
#define ISCSI_SCSI_EMU_IO_TYPE_REMOVABLE          (1 << 0)

/// iSCSI SCSI emulation I/O type: Unmap.
#define ISCSI_SCSI_EMU_IO_TYPE_UNMAP              (1 << 1)

/// iSCSI SCSI emulation I/O type: Non-rotating medium (e.g., solid state).
#define ISCSI_SCSI_EMU_IO_TYPE_NO_ROTATION        (1 << 2)

/// iSCSI SCSI emulation I/O type: Physical read only device.
#define ISCSI_SCSI_EMU_IO_TYPE_PHYSICAL_READ_ONLY (1 << 3)

/// iSCSI SCSI emulation I/O type: Device is (temporarily) write protected.
#define ISCSI_SCSI_EMU_IO_TYPE_WRITE_PROTECT      (1 << 4)

/// iSCSI SCSI emulation I/O type: Write cache available.
#define ISCSI_SCSI_EMU_IO_TYPE_WRITE_CACHE        (1 << 5)


/// iSCSI SCSI emulation block flags: Write operation.
#define ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE  (1 << 0)

/// iSCSI SCSI emulation block flags: Verify operation.
#define ISCSI_SCSI_EMU_BLOCK_FLAGS_VERIFY (1 << 1)


void iscsi_scsi_task_create(iscsi_scsi_task *scsi_task, iscsi_scsi_task_xfer_complete_callback xfer_complete_callback, iscsi_scsi_task_destroy_callback destroy_callback); // Allocates and initializes a SCSI task
void iscsi_scsi_task_destroy(iscsi_scsi_task *scsi_task); // Deallocates all resources acquired iscsi_scsi_task_create

void iscsi_scsi_task_xfer_complete(iscsi_scsi_task *scsi_task); // Callback function when an iSCSI SCSI task completed the data transfer

void iscsi_scsi_task_sense_data_check_cond_build(iscsi_scsi_task *scsi_task, const uint8_t sense_key, const uint8_t asc, const uint8_t ascq); // Allocates, if necessary and initializes SCSI sense data for check condition status code
int iscsi_scsi_task_status_copy(iscsi_scsi_task *dst_scsi_task, const iscsi_scsi_task *src_scsi_task); // Copies iSCSI SCSI task sense data and status code
void iscsi_scsi_task_lun_process_none(iscsi_scsi_task *scsi_task); // Processes a iSCSI SCSI task with no LUN identifier
void iscsi_scsi_task_lun_process_abort(iscsi_scsi_task *scsi_task); // Processes a iSCSI SCSI aborted task

iscsi_scsi_lun *iscsi_scsi_lun_create(const int lun_id); // Allocates and initializes an iSCSI LUN structure for linkage with a DNBD3 image
int iscsi_scsi_lun_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI SCSI LUN destructor callback for hash map
void iscsi_scsi_lun_destroy(iscsi_scsi_lun *lun); // Deallocates all resources acquired by iscsi_scsi_lun_create

uint64_t iscsi_scsi_lun_get_from_scsi(const int lun_id); // Converts an internal representation of a LUN identifier to an iSCSI LUN required for packet data
int iscsi_scsi_lun_get_from_iscsi(const uint64_t lun); // Converts an iSCSI LUN from packet data to internal SCSI LUN identifier

void iscsi_scsi_lun_task_append(iscsi_scsi_lun *lun, iscsi_scsi_task *scsi_task); // Appends an iSCSI SCSI task to a iSCSI SCSI LUN pending tasks doubly linked list
void iscsi_scsi_lun_tasks_exec(iscsi_scsi_lun *lun); // Executes all iSCSI SCSI pending tasks assigned to a iSCSI SCSI LUN
void iscsi_scsi_lun_task_run(iscsi_scsi_lun *lun, iscsi_scsi_task *scsi_task); // Runs an iSCSI SCSI task for a specified iSCSI SCSI LUN
void iscsi_scsi_lun_task_complete(iscsi_scsi_lun *lun, iscsi_scsi_task *scsi_task); // Handles iSCSI SCSI task completition
void iscsi_scsi_lun_task_exec(iscsi_scsi_lun *lun, iscsi_scsi_task *scsi_task); // Appends iSCSI SCSI task to pending tasks doubly linked list and / or runs it directly

int iscsi_scsi_pr_check_scsi2(iscsi_scsi_task *scsi_task); // Checks the iSCSI SCSI Persistent Reservation (PR) SCSI-2 reserve of an iSCSI SCSI task
int iscsi_scsi_pr_registrant_get_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Finds an iSCSI SCSI Persistent Reservation (PR) registrant by target and initiator port
int iscsi_scsi_pr_check(iscsi_scsi_task *scsi_task); // Checks the iSCSI SCSI Persistent Reservation (PR) of an iSCSI SCSI task
int iscsi_scsi_pr_out(iscsi_scsi_task *scsi_task, iscsi_scsi_pr_reserve_out_parameter_list_packet *pr_reserve_out_parameter_list, const iscsi_scsi_cdb_pr_reserve_out *cdb_pr_reserve_out, const uint len); // Constructs an iSCSI SCSI Persistent Reservation (PR) out parameter list of an iSCSI SCSI task
int iscsi_scsi_pr_in(iscsi_scsi_task *scsi_task, iscsi_scsi_pr_reserve_in_parameter_data_packet *pr_reserve_in_parameter_data, const iscsi_scsi_cdb_pr_reserve_in *cdb_pr_reserve_in, const uint len); // Constructs iSCSI SCSI Persistent Reservation (PR) in parameter data of an iSCSI SCSI task
int iscsi_scsi_pr_reserve_scsi2(iscsi_scsi_task *scsi_task, const iscsi_scsi_cdb_pr_reserve_6 *cdb_pr_reserve_6); // Reserves an iSCSI SCSI Persistent Reservation (PR) of an iSCSI SCSI task
int iscsi_scsi_pr_release_scsi2(iscsi_scsi_task *scsi_task); // Releases an iSCSI SCSI Persistent Reservation (PR) of an iSCSI SCSI task

int iscsi_scsi_emu_io_block_read(iscsi_scsi_task *scsi_task, uint8_t *buf, dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks, const uint32_t block_size, iscsi_scsi_emu_io_complete_callback callback, uint8_t *user_data); // Reads a number of blocks from a block offset of a DNBD3 image to a specified buffer
uint8_t *iscsi_scsi_emu_block_read_complete_callback(dnbd3_image_t *image, uint8_t *user_data, const bool success); // Completes an iSCSI SCSI task after a finished I/O read operation
int iscsi_scsi_emu_io_block_cmp_write(iscsi_scsi_task *scsi_task, uint8_t *buf, uint8_t *cmp_buf, dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks, const uint32_t block_size, iscsi_scsi_emu_io_complete_callback callback, uint8_t *user_data); // Compares and writes a number of blocks starting from a block offset in a DNBD3 image with specified buffers
uint8_t *iscsi_scsi_emu_block_write_complete_callback(dnbd3_image_t *image, uint8_t *user_data, const bool success); // Completes an iSCSI SCSI task after a finished I/O write operation
int iscsi_scsi_emu_io_block_write(iscsi_scsi_task *scsi_task, uint8_t *buf, dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks, const uint32_t block_size, iscsi_scsi_emu_io_complete_callback callback, uint8_t *user_data); // Writes a number of blocks from a block offset to a DNBD3 image of a specified buffer
int iscsi_scsi_emu_io_queue(iscsi_scsi_emu_io_wait *io_wait); // Enqueues an I/O wait in the thread pool to execute
uint8_t *iscsi_scsi_emu_block_resubmit_process_callback(uint8_t *user_data); // Resubmits an iSCSI SCSI task for execution

int iscsi_scsi_emu_primary_inquiry_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Fills in a single Vital Product Data (VPD) SCSI Port Designation Descriptor entry of an INQUIRY operation
int iscsi_scsi_emu_exec(iscsi_scsi_task *scsi_task); // Executes the iSCSI SCSI emulation for an iSCSI SCSI task


/// iSCSI port flags: In use.
#define ISCSI_PORT_FLAGS_IN_USE (1 << 0)


/**
 * @brief iSCSI port.
 *
 * This structure maintains the transport ID,
 * name, identifiers and index of an ISCSI
 * port.
 */
typedef struct iscsi_port {
    /// Transport ID.
    iscsi_transport_id *transport_id;

    /// Name.
    uint8_t *name;

    /// Identifier.
    uint64_t id;

    /// Flags.
    int flags;

    /// Index.
    uint16_t index;

    /// Transport ID length.
    uint16_t transport_id_len;
} iscsi_port;


iscsi_port *iscsi_port_create(const uint8_t *name, const uint64_t id, const uint16_t index); // Allocates and initializes an iSCSI port
int iscsi_port_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI port destructor callback for hash map
void iscsi_port_destroy(iscsi_port *port); // Deallocates all resource acquired iscsi_port_create

uint8_t *iscsi_port_get_name(const iscsi_port *port); // Retrieves the name of an iSCSI port

int iscsi_port_transport_id_set(iscsi_port *port, const uint8_t *name, const uint64_t isid); // Sets the SCSI transport ID of the iSCSI port


/// iSCSI SCSI LUN flags: Removed.
#define ISCSI_SCSI_LUN_FLAGS_REMOVED  (1 << 0)

/// iSCSI SCSI LUN flags: Resizing.
#define ISCSI_SCSI_LUN_FLAGS_RESIZING (1 << 1)


typedef struct iscsi_device iscsi_device;


/**
 * @brief iSCSI SCSI LUN.
 *
 * This structure managesw the SCSI
 * LUNs attached to an iSCSI device
 * and associates a disk image file.
 */
typedef struct iscsi_scsi_lun {
    /// Doubly linked list containing associated tasks with this LUN.
    iscsi_list tasks;

    /// Mutex for accessing the associated tasks through multiple threads.
    pthread_mutex_t tasks_mutex;

    /// Doubly linked list containing associated pending tasks with this LUN.
    iscsi_list tasks_pending;

    /// Mutex for accessing the associated pending tasks through multiple threads.
    pthread_mutex_t tasks_pending_mutex;

    /// Doubly linked list containing associated management tasks with this LUN.
    iscsi_list tasks_mgmt;

    /// Mutex for accessing the associated management tasks through multiple threads.
    pthread_mutex_t tasks_mgmt_mutex;

    /// Doubly linked list containing associated management pending tasks with this LUN.
    iscsi_list tasks_mgmt_pending;

    /// Mutex for accessing the associated management pending tasks through multiple threads.
    pthread_mutex_t tasks_mgmt_pending_mutex;

    /// Doubly linked list containg Persistent Reservation (PR) registrant for I_T nexus.
    iscsi_hashmap *pr_regs;

    /// Persistent Reservation (PR) for the LUN.
    iscsi_scsi_pr_reservation pr_reservation;

    /// Persistent Reservation (PR) holder for SPC2 RESERVE(6) and RESERVE(10).
    iscsi_scsi_pr_registrant pr_scsi2_holder;

    /// iSCSI device which belongs to this LUN.
    iscsi_device *device;

    /// Assocated DNBD3 image for this LUN.
    dnbd3_image_t *image;

    /// LUN identifier (always MUST be between 0 and 7).
    int id;

    /// Flags.
    int flags;

    /// Persistent Reservation (PR) generation.
    uint32_t pr_gen;
} iscsi_scsi_lun;


/// iSCSI device flags: Allocated.
#define ISCSI_DEVICE_FLAGS_ALLOCATED (1 << 0)

/// iSCSI device flags: Removed.
#define ISCSI_DEVICE_FLAGS_REMOVED   (1 << 1)


/**
 * @brief iSCSI device.
 *
 * This structure managesw the SCSI
 * devices and associates the
 * disk image files with them.
 */
typedef struct iscsi_device {
    /// Name of device.
    uint8_t *name;

    /// LUNs associated with this device.
    iscsi_hashmap *luns;

    /// Read/write lock for hash map containing all LUNs associated with this device. MUST be initialized with iscsi_create before any iSCSI functions are used.
    pthread_rwlock_t luns_rwlock;

    /// Ports associated with this device.
    iscsi_hashmap *ports;

    /// Device identifier.
    int id;

    /// Flags.
    int flags;

    /// Number of active connections for this device.
	uint32_t active_conns;

    /// Protocol identifier.
    uint8_t protocol_id;
} iscsi_device;


/// iSCSI target node maximum length.
#define ISCSI_TARGET_NODE_MAX_NAME_LEN 223U


/// iSCSI target node IQN identifier prefix string.
#define ISCSI_TARGET_NODE_NAME_IQN_PREFIX "iqn."

/// iSCSI target node IEEE NAA identifier prefix string.
#define ISCSI_TARGET_NODE_NAME_NAA_PREFIX "naa."

/// iSCSI target node EUI identifier prefix string.
#define ISCSI_TARGET_NODE_NAME_EUI_PREFIX "eui."


/// iSCSI target node WWN identifier prefix string.
#define ISCSI_TARGET_NODE_NAME_WWN_PREFIX "wwn-0x"


/// iSCSI target node flags: CHAP authentication disabled.
#define ISCSI_TARGET_NODE_FLAGS_CHAP_DISABLE  (1 << 0)

/// iSCSI target node flags: CHAP authentication required.
#define ISCSI_TARGET_NODE_FLAGS_CHAP_REQUIRE  (1 << 1)

/// iSCSI target node flags: CHAP authentication mutual.
#define ISCSI_TARGET_NODE_FLAGS_CHAP_MUTUAL   (1 << 2)

/// iSCSI target node flags: Destroyed.
#define ISCSI_TARGET_NODE_FLAGS_DESTROYED     (1 << 3)


/**
 * @brief iSCSI target node.
 *
 * This structure maintains the name, alias,
 * associated device and connection data
 * for a specific iSCSI target node.
 */
typedef struct iscsi_target_node {
    /// Name of target node.
    uint8_t *name;

    /// Alias name of target node.
    uint8_t *alias;

    /// Associated iSCSI device.
    iscsi_device *device;

    /// Target node number.
    uint num;

    /// Queue depth.
    uint queue_depth;

    /// Flags.
    int flags;

    /// Header digest size (always MUST be 0 or 4 for now).
    int header_digest;

    /// Data digest size (always MUST be 0 or 4 for now).
    int data_digest;

    /// CHAP group ID.
    int32_t chap_group;

    /// Number of active connections for this target node.
	uint32_t active_conns;
} iscsi_target_node;


/**
 * @brief iSCSI target node search by name.
 *
 * This structure is used by iterating through
 * all iSCSI target nodes finding by name.
 */
typedef struct iscsi_target_node_find_name {
    /// Found iSCSI target node is stored here, should be initialized to NULL.
    iscsi_target_node *target;

    /// The name of the target node to search for.
    uint8_t *name;
} iscsi_target_node_find_name;


/// iSCSI authentication CHAP phase: None.
#define ISCSI_AUTH_CHAP_PHASE_NONE    0

/// iSCSI authentication CHAP phase: Wait A.
#define ISCSI_AUTH_CHAP_PHASE_WAIT_A  1

/// iSCSI authentication CHAP phase: Wait NR.
#define ISCSI_AUTH_CHAP_PHASE_WAIT_NR 2

/// iSCSI authentication CHAP phase: End.
#define ISCSI_AUTH_CHAP_PHASE_END     3


/**
 * @brief iSCSI CHAP authentication data structure.
 *
 * This structure maintains all data required for
 * CHAP authentication method.
 */
typedef struct iscsi_auth_chap {
    /// CHAP phase.
    int phase;
} iscsi_auth_chap;


/// iSCSI session flags: Initial ready to transfer.
#define ISCSI_SESSION_FLAGS_INIT_R2T          (1 << 0)

/// iSCSI session flags: Immediate data.
#define ISCSI_SESSION_FLAGS_IMMEDIATE_DATA    (1 << 1)

/// iSCSI session flags: Data PDU in order.
#define ISCSI_SESSION_FLAGS_DATA_PDU_IN_ORDER (1 << 2)

/// iSCSI session flags: Data sequence in order.
#define ISCSI_SESSION_FLAGS_DATA_SEQ_IN_ORDER (1 << 3)


/// iSCSI session type: Invalid.
#define ISCSI_SESSION_TYPE_INVALID   0

/// iSCSI session type: Normal.
#define ISCSI_SESSION_TYPE_NORMAL    1

/// iSCSI session type: Discovery.
#define ISCSI_SESSION_TYPE_DISCOVERY 2


/**
 * @brief iSCSI session.
 *
 * This structure manages an iSCSI session and
 * stores the key / value pairs from the
 * login phase.
 */
typedef struct iscsi_session {
    /// List of iSCSI connections associated with this session.
    iscsi_list conn_list;

    /// Initiator port.
    iscsi_port *init_port;

    /// Hash map of login key / value pairs negotiated with this session.
    iscsi_hashmap *key_value_pairs;

    /// iSCSI target node.
    iscsi_target_node *target;

    /// Portal group tag.
    uint64_t tag;

    /// Initiator Session ID (ISID).
    uint64_t isid;

    /// Target Session Identifying Handle (TSIH).
    uint64_t tsih;

    /// Flags (extracted from key and value pairs).
    int flags;

    /// Queue depth.
    uint queue_depth;

    /// iSCSI session type.
    int type;

    /// Number of active connections linked to this session.
    uint32_t conns;

    /// Maximum number of connections.
    uint32_t max_conns;

    /// Ready to transfer maximum outstanding value.
    uint32_t max_outstanding_r2t;

    /// Default time to wait.
    uint32_t default_time_to_wait;

    /// Default time to retain.
    uint32_t default_time_to_retain;

    /// First burst length.
    uint32_t first_burst_len;

    /// Maximum burst length.
    uint32_t max_burst_len;

    /// Error recovery level.
    uint32_t err_recovery_level;

    /// ExpCmdSN.
    uint32_t exp_cmd_sn;

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /// Current text Initiator Task Tag (ITT).
    uint32_t current_text_init_task_tag;
} iscsi_session;


typedef struct iscsi_pdu iscsi_pdu;


/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Packet parsed successfully.
#define ISCSI_CONNECT_PDU_READ_OK                                 0

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Packet processed successfully.
#define ISCSI_CONNECT_PDU_READ_PROCESSED                          1

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Fatail error during packet parsing.
#define ISCSI_CONNECT_PDU_READ_ERR_FATAL                         -1

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Login error response.
#define ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE                -2

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Login parameter error.
#define ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER               -3

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Login parameter not exchanged once error.
#define ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER_XCHG_NOT_ONCE -4


/// iSCSI connection flags: Stopped.
#define ISCSI_CONNECT_FLAGS_STOPPED         (1 << 0)

/// iSCSI connection flags: Rejected.
#define ISCSI_CONNECT_FLAGS_REJECTED        (1 << 1)

/// iSCSI connection flags: Logged out.
#define ISCSI_CONNECT_FLAGS_LOGGED_OUT      (1 << 2)

/// iSCSI connection flags: Full feature.
#define ISCSI_CONNECT_FLAGS_FULL_FEATURE    (1 << 3)

/// iSCSI connection flags: CHAP authentication is disabled.
#define ISCSI_CONNECT_FLAGS_CHAP_DISABLE    (1 << 4)

/// iSCSI connection flags: CHAP authentication is required.
#define ISCSI_CONNECT_FLAGS_CHAP_REQUIRE    (1 << 5)

/// iSCSI connection flags: CHAP authentication is mutual.
#define ISCSI_CONNECT_FLAGS_CHAP_MUTUAL     (1 << 6)

/// iSCSI connection flags: Authenticated.
#define ISCSI_CONNECT_FLAGS_AUTH            (1 << 7)

/// iSCSI connection flags: Oustanding NOP.
#define ISCSI_CONNECT_FLAGS_NOP_OUTSTANDING (1 << 8)


/// Ready to wait for PDU.
#define ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_READY 0

/// Active connection waiting for any PDU header.
#define ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR   1

/// Active connection waiting for data.
#define ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_DATA  2

/// Active connection does not wait for data.
#define ISCSI_CONNECT_PDU_RECV_STATE_ERR            3


/// iSCSI connection state: Invalid.
#define ISCSI_CONNECT_STATE_INVALID 0

/// iSCSI connection state: Running.
#define ISCSI_CONNECT_STATE_RUNNING 1

/// iSCSI connection state: Exiting.
#define ISCSI_CONNECT_STATE_EXITING 2

/// iSCSI connection state: Invalid.
#define ISCSI_CONNECT_STATE_EXITED  3


/// Number of attempts for writing to iSCSI connection socket.
#define ISCSI_CONNECT_SOCKET_WRITE_RETRIES 3


/**
 * @brief iSCSI incoming connection.
 *
 * This structure is used for maintaining incoming iSCSI
 * connections. Negiotiated text key=value pairs are
 * stored here, status of the connection, session
 * and iSCSI portals.
 */
typedef struct iscsi_connection {
    /// Doubly linked list node, MUST be first element.
    iscsi_node node;

    /// iSCSI session associated with this connection.
    iscsi_session *session;

    /// Hash map containing login text key / value pairs associated to this connection.
    iscsi_hashmap *key_value_pairs;

    /// Temporarily storage for partially received login parameter.
    uint8_t *partial_pairs;

    /// Hash map containing text key / value pairs associated to this connection.
    iscsi_hashmap *text_key_value_pairs;

    /// Temporarily storage for partially received text parameter.
    uint8_t *text_partial_pairs;

    /// iSCSI device.
    iscsi_device *device;

    /// iSCSI initiator port.
    iscsi_port *init_port;

    /// Initiator name.
    uint8_t *init_name;

    //// Initiator IP address.
    uint8_t *init_adr;

    /// iSCSI target node.
    iscsi_target_node *target;

    /// iSCSI target port.
    iscsi_port *target_port;

    /// iSCSI target short name.
    uint8_t *target_name_short;

    /// iSCSI portal host name.
    uint8_t *portal_host;

    /// iSCSI portal host port.
    uint8_t *portal_port;

    /// Current PDU being processed.
    iscsi_pdu *pdu_processing;

    /// Login response PDU.
    iscsi_pdu *login_response_pdu;

    /// Doubly linked list containing enqueued SCSI Data In tasks.
    iscsi_list scsi_data_in_queued_tasks;

    /// Doubly linked list containing writing PDU's associated with this connection.
    iscsi_list pdus_write;

    /// Doubly linked list containing SNACK PDU's associated with this connection.
    iscsi_list pdus_snack;

    /// Doubly linked list containing active Ready To Transfer (R2T) tasks.
    iscsi_list r2t_tasks_active;

    /// Doubly linked list containing queued Ready To Transfer (R2T) tasks.
    iscsi_list r2t_tasks_queue;

    /// iSCSI SendTargets total number of bytes completed.
    uint target_send_total_size;

    /// iSCSI SCSI Data In count.
    uint scsi_data_in_cnt;

    /// iSCSI SCSI Data Out count.
    uint scsi_data_out_cnt;

    /// iSCSI tasks pending count.
    uint task_cnt;

    /// Pending Ready To Transfer (R2T) tasks.
    uint r2t_pending;

    /// iSCSI connection contains a header digest (CRC32), always MUST be 0 or 4 for now.
    int header_digest;

    /// iSCSI connection contains a data digest (CRC32), always MUST be 0 or 4 for now.
    int data_digest;

    /// Internal connection identifier (key of iSCSI global vector hash map).
    int id;

    /// Connected TCP/IP socket.
    int sock;

    /// iSCSI connection receiving state.
    int pdu_recv_state;

    /// iSCSI connection flags.
    int flags;

    /// iSCSI connection state.
    int state;

    /// iSCSI connection login phase.
    int login_phase;

    /// Maximum receive DataSegment length in bytes.
    uint32_t max_recv_ds_len;

    /// Portal group tag.
    uint64_t pg_tag;

    /// Initiator Session ID (ISID).
    iscsi_isid isid;

    /// Target Session Identifying Handle (TSIH).
    uint16_t tsih;

    /// Connection ID (CID).
    uint16_t cid;

    /// Bit mask for connection state key negotiation.
    uint16_t state_negotiated;

    /// Bit mask for session state key negotiation.
    uint32_t session_state_negotiated;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /// Targer Transfer Tag (TTT).
    uint32_t target_xfer_tag;

    /// CHAP authentication.
    iscsi_auth_chap auth_chap;

    /// CHAP group id.
    int32_t chap_group;

    /// StatSN.
    uint32_t stat_sn;

    /// ExpStatSN.
    uint32_t exp_stat_sn;

    /// Execution queue to run to invoke callback functions after asynchronous I/O has been finished.
    iscsi_list exec_queue;

    // TODO: Remove after test finish
    iscsi_hashmap *stat_iscsi_opcodes;

    // TODO: Remove after test finish
    iscsi_hashmap *stat_scsi_opcodes;
} iscsi_connection;


/**
 * @brief iSCSI transfer completed callback function.
 *
 * This function is invoked when the response PDU
 * write to the TCP/IP socket has been completed.
 *
 * @param[in] user_data Pointer to user data.
 */
typedef void (*iscsi_connection_xfer_complete_callback)(uint8_t *user_data);


/**
 * @brief Callback for iSCSI connection write TCP/IP write operation completion.
 *
 * This function is invoked when the sending
 * TCP/IP transfer has been finished.
 *
 * @param[in] user_data Pointer to user data.
 * @param[in] err 0 if I/O completed successfully or an
 * error code indicating the problem.
 */
typedef void (*iscsi_connection_write_complete_callback)(uint8_t *user_data, int err);


/// iSCSI connection asynchronous execution queue: SCSI emulation I/O.
#define ISCSI_CONNECT_EXEC_QUEUE_TYPE_SCSI_EMU_IO 0U

/// iSCSI connection asynchronous execution queue: PDU write I/O.
#define ISCSI_CONNECT_EXEC_QUEUE_TYPE_PDU_WRITE   1U


/**
 * @brief iSCSI connection execution queue.
 *
 * This structure is used for invoking the
 * callback functions after processing has
 * been completed.\n
 * Currently, PDU writes and SCSI emulation
 * invoke I/O callbacks after finishing
 * their operations.
 */
typedef struct iscsi_connection_exec_queue {
    /// Doubly linked list node, MUST be first element.
    iscsi_node node;

    /**
     * @union data
     * @brief Invokes callback functions with arguments based on the execution queue type.
     *
     * This union contains the arguments needed
     * for their respective callback functions
     * of the completion process.
     */
    union {
        /**
         * @brief PDU write completion callback and arguments.
         *
         * For PDU write completion type, two arguments
         * are passed.
         */
        struct {
            /// Callback function to invoke after PDU write completion process has been completed.
            iscsi_connection_write_complete_callback callback;

            /// User data to be passed to the PDU write completion process callback function.
            uint8_t *user_data;

            /// Error code to be passed to the PDU write completion process callback function.
            int err;
        } pdu_write;

        /**
         * @brief I/O completion callback and arguments.
         *
         * For I/O completion type, three arguments
         * are passed.
         */
        struct {
            /// Callback function to invoke after I/O process has been completed.
            iscsi_scsi_emu_io_complete_callback callback;

            /// DNBD3 image to be passed to the I/O completion process callback function.
            dnbd3_image_t *image;

            /// User data to be passed to the I/O completion process callback function.
            uint8_t *user_data;

            /// Successful state passed to the I/O completion process callback function.
            bool success;
        } io;
    } data;

    /// Type of completion callback.
    uint type;
} iscsi_connection_exec_queue;


typedef struct iscsi_task iscsi_task;


/// iSCSI PDU flags: Rejected.
#define ISCSI_PDU_FLAGS_REJECTED (1 << 0)


/**
 * @brief This structure is used to partially read PDU data.
 *
 * Since TCP/IP packets can be fragmented, this
 * structure is needed which maintains reading
 * and filling the BHS, AHS and DS properly.
 */
typedef struct iscsi_pdu {
    /// Doubly linked list node, MUST be first element.
    iscsi_node node;

    /// iSCSI Basic Header Segment (BHS) packet data.
    iscsi_bhs_packet *bhs_pkt;

    /// iSCSI Advanced Header Segment (AHS) packet data for fast access and is straight after BHS packet in memory.
    iscsi_ahs_packet *ahs_pkt;

    /// Header digest (CRC32C) packet data for fast access and is straight after BHS and AHS packet in memory.
    iscsi_header_digest *header_digest;

    /// iSCSI DataSegment (DS) packet data for fast access and is straight after BHS, AHS and header digest packet in memory.
    iscsi_scsi_ds_cmd_data *ds_cmd_data;

    /// Data digest (CRC32C) packet data for fast access and is straight after BHS, AHS, header digest and DataSegment packet in memory.
    iscsi_data_digest *data_digest;

    /// iSCSI task handling this PDU.
    iscsi_task *task;

    /// Associated iSCSI connection.
    iscsi_connection *conn;

    /// Transfer complete callback function.
    iscsi_connection_xfer_complete_callback xfer_complete_callback;

    /// Transfer complete callback user data (arguments).
    uint8_t *xfer_complete_user_data;

    /// Flags.
    int flags;

    /// Reference counter.
    uint32_t ref;

    /// Bytes of Basic Header Segment (BHS) already read.
    uint bhs_pos;

    /// Bytes of Advanced Header Segment (AHS) already read.
    uint ahs_pos;

    /// AHSLength.
    uint ahs_len;

    /// Bytes of header digest (CRC32C) already read.
    uint header_digest_pos;

    /// Header digest size (always 0 or 4 for now).
    int header_digest_size;

    /// DataSegmentLength.
    uint32_t ds_len;

    /// Position of DataSegment buffer for next operation.
    uint32_t pos;

    /// Allocated DataSegment buffer length.
    uint32_t len;

    /// Bytes of data digest (CRC32C) already read.
    uint data_digest_pos;

    /// Data digest size (always 0 or 4 for now).
    int data_digest_size;

    /// Tasks referenced by this PDU counter.
    uint task_ref_cnt;

    /// CmdSN.
    uint32_t cmd_sn;
} iscsi_pdu;


/// iSCSI task flags: Ready To Transfer is active.
#define ISCSI_TASK_FLAGS_R2T_ACTIVE (1 << 0)

/// iSCSI task flags: Task is enqueued in SCSI layer.
#define ISCSI_TASK_FLAGS_QUEUED     (1 << 1)


/**
 * @brief This structure is used for iSCSI task management.
 *
 * This structure maintains the iSCSI task handling
 * including the underlying SCSI layer.
 */
typedef struct iscsi_task {
    /// Doubly linked list node, MUST be first element.
    iscsi_node node;

    /// Underlying SCSI task structure.
    iscsi_scsi_task scsi_task;

    /// Parent iSCSI task.
    iscsi_task *parent;

    /// Sub tasks doubly linked list for splitted data transfers.
    iscsi_list sub_tasks;

    /// Associated iSCSI connection.
    iscsi_connection *conn;

    /// Associated iSCSI PDU.
    iscsi_pdu *pdu;

    /// Buffer position in bytes.
    uint32_t pos;

    /// Buffer length in bytes.
    uint32_t len;

    /// Unique identifier for this task.
    uint64_t id;

    /// Flags.
    int flags;

    /// LUN identifier associated with this task (always MUST be between 0 and 7), used for hot removal tracking.
    int lun_id;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /// Target Transfer Tag (TTT).
    uint32_t target_xfer_tag;

    /// Desired number of bytes completed.
    uint32_t des_data_xfer_pos;

    /// Desired data transfer length.
    uint32_t des_data_xfer_len;

    /// SCSI Data In Data Sequence Number (DataSN).
    uint32_t data_sn;

    /// SCSI Data Out count.
    uint32_t scsi_data_out_cnt;

    /// Length in bytes of R2T, used for ensuring that R2T burst does not exceed MaxBurstLength.
    uint32_t r2t_len;

    /// Ready To Transfer Sequence Number (R2TSN).
    uint32_t r2t_sn;

    /// Next expected Ready To Transfer offset is used for receiving the Data-OUT PDU.
    uint32_t r2t_next_exp_pos;

    /// Ready To Transfer DataSN, used for next sequence of a R2TSN.
    uint32_t r2t_data_sn;

    /// Next R2TSN to be acknowledged.
    uint32_t r2t_sn_ack;

    /// Outstanding Ready To Transfer (R2T) count.
    uint32_t r2t_outstanding;
} iscsi_task;


iscsi_task *iscsi_task_create(iscsi_connection *conn, iscsi_task *parent, iscsi_scsi_task_xfer_complete_callback callback); // Allocates and initializes an iSCSI task structure
void iscsi_task_destroy_callback(iscsi_scsi_task *scsi_task); // Deallocates all resources of the iSCSI task of an iSCSI SCSI task
void iscsi_task_destroy(iscsi_task *task); // Deallocates resources acquired by iscsi_task_create

void iscsi_task_queue(iscsi_connection *conn, iscsi_task *task); // Enqueues an iSCSI task

void iscsi_task_xfer_complete_process_read(iscsi_connection *conn, iscsi_task *task, iscsi_task *primary_task); // Processes an iSCSI SCSI task which completed a read data transfer
bool iscsi_task_xfer_del(iscsi_connection *conn, const uint32_t target_xfer_tag); // Deletes an iSCSI task from the active Ready To Transfer (R2T) doubly linked list by Target Transfer Tag (TTT)
void iscsi_task_xfer_complete_process_other(iscsi_connection *conn, iscsi_task *task, iscsi_task *primary_task); // Processes an iSCSI SCSI task which completed a non-read data transfer

void iscsi_task_response(iscsi_connection *conn, iscsi_task *task); // Creates, initializes and sends an iSCSI task reponse PDU.

iscsi_device *iscsi_device_create(const uint8_t *name, const int lun_id, const uint8_t protocol_id); // Creates and initializes an iSCSI device with a maximum number of LUNs
int iscsi_device_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI device destructor callback for hash map
void iscsi_device_destroy(iscsi_device *device); // Deallocates all resources acquired by iscsi_device_create

iscsi_port *iscsi_device_find_port_by_portal_group_tag(const iscsi_device *device, const uint64_t id); // Gets an iSCSI device being in use by portal group identifier
iscsi_scsi_lun *iscsi_device_find_lun(iscsi_device *device, const int lun_id); // Searches an iSCSI LUN by LUN identifier

int iscsi_device_port_add(iscsi_device *device, const uint8_t *name, const uint64_t id); // Creates, initializes and adds an iSCSI target port to an iSCSI device

void iscsi_device_scsi_task_queue(iscsi_device *device, iscsi_scsi_task *scsi_task); // Enqueues an iSCSI SCSI task to the first LUN of an iSCSI device

int iscsi_target_node_create_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Creates, initializes and adds a portal group to an iSCSI target node
iscsi_target_node *iscsi_target_node_create(uint8_t *name, const uint8_t *alias, const int index, const int lun_id, const uint queue_depth, const int flags, const int32_t chap_group, const int header_digest, const int data_digest); // Creates and initializes an iSCSI target node
int iscsi_target_node_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI target node destructor callback for hash map
void iscsi_target_node_destroy(iscsi_target_node *target); // Deallocates all resources acquired by iscsi_target_node_create

int32_t iscsi_target_node_send(iscsi_connection *conn, const uint8_t *dst_iqn, const uint8_t *src_iqn, uint8_t *buf, const uint32_t pos, const uint32_t len); // Sends a buffer from a source iSCSI IQN to target iSCSI IQNs
uint64_t iscsi_target_node_wwn_get(const uint8_t *name); // Calculates the WWN using 64-bit IEEE Extended NAA for a name
dnbd3_image_t *iscsi_target_node_image_get(uint8_t *iqn); // Extracts the DNBD3 image out of an iSCSI IQN string and opens the DNBD3 image
int iscsi_target_node_find_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Finds an iSCSI target node by case insensitive name search
iscsi_target_node *iscsi_target_node_find(uint8_t *target_name); // Searches an iSCSI target node by name using case insensitive search

uint8_t *iscsi_target_node_get_redirect(iscsi_connection *conn, iscsi_target_node *target); // Retrieves target node redirection address
int iscsi_target_node_access(iscsi_connection *conn, iscsi_target_node *target, const uint8_t *iqn, const uint8_t *adr); // Checks if target node is accessible

iscsi_session *iscsi_session_create(iscsi_connection *conn, iscsi_target_node *target, const int type); // Creates and initializes an iSCSI session
int iscsi_session_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI session destructor callback for hash map
void iscsi_session_destroy(iscsi_session *session); // Deallocates all resources acquired by iscsi_session_create

int iscsi_session_init_key_value_pairs(iscsi_hashmap *key_value_pairs); // Initializes a key and value pair hash table with default values

iscsi_connection *iscsi_connection_create(iscsi_portal *portal, const int sock); // Creates data structure for an iSCSI connection from iSCSI portal and TCP/IP socket
int iscsi_connection_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI connection destructor callback for hash map
void iscsi_connection_destroy(iscsi_connection *conn); // Deallocates all resources acquired by iscsi_connection_create

int iscsi_connection_drop(iscsi_connection *conn, const uint8_t *conn_match, const int all); // Drops all connections based on matching pattern
void iscsi_connection_schedule(iscsi_connection *conn); // Schedules an iSCSI connection

int32_t iscsi_connection_read(const iscsi_connection *conn, uint8_t *buf, const uint32_t len); // Reads data for the specified iSCSI connection from its TCP socket
int32_t iscsi_connection_write(const iscsi_connection *conn, uint8_t *buf, const uint32_t len); // Writes data for the specified iSCSI connection to its TCP socket
int iscsi_connection_handle_scsi_data_in_queued_tasks(iscsi_connection *conn); // This function handles all queued iSCSI SCSI Data In tasks

int iscsi_connection_init_key_value_pairs(iscsi_hashmap *key_value_pairs); // Initializes a key and value pair hash table with default values for an iSCSI connection
int32_t iscsi_negotiate_key_value_pairs(iscsi_connection *conn, iscsi_hashmap *key_value_pairs, uint8_t *buf, const uint32_t pos, const uint32_t len); // Negotiates all key and value pairs required for session authentication
int iscsi_connection_copy_key_value_pairs(iscsi_connection *conn); // Copies retrieved key and value pairs into SCSI connection and session structures
int iscsi_connection_save_incoming_key_value_pairs(iscsi_connection *conn, iscsi_hashmap *key_value_pairs, iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu); // Saves incoming key / value pairs from the client of a login request PDU
void iscsi_connection_login_response_reject(iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu); // Initializes a rejecting login response packet
iscsi_pdu *iscsi_connection_pdu_create(iscsi_connection *conn, const uint ahs_len, const int header_digest_size, const uint32_t ds_len, const int data_sigest_size ); // Creates an iSCSI PDU structure used by connections
void iscsi_connection_pdu_destroy(iscsi_pdu *pdu); // Destroys an iSCSI PDU structure used by connections
void iscsi_connection_pdu_free(iscsi_connection *conn, iscsi_pdu *pdu); // Frees an iSCSI PDU structure used by using connection callback function

iscsi_bhs_packet *iscsi_connection_pdu_append(iscsi_pdu *pdu, const uint ahs_len, const int header_digest_size, const uint32_t ds_len, const int data_digest_size); // Appends packet data to an iSCSI PDU structure used by connections
iscsi_ahs_packet *iscsi_connection_pdu_ahs_packet_get(const iscsi_pdu *pdu, const int index); // Retrieves the pointer to an specific AHS packet from an iSCSI PDU by index
int iscsi_connection_pdu_ahs_packet_count(const iscsi_pdu *pdu); // Counts number of AHS packets of an iSCSI PDU

void iscsi_connection_pdu_digest_header_update(iscsi_header_digest *header_digest, const iscsi_bhs_packet *packet_data, const uint ahs_len); // Calculate and store iSCSI header digest (CRC32C)
bool iscsi_connection_pdu_digest_header_verify(const iscsi_header_digest *header_digest, const iscsi_bhs_packet *packet_data, const uint ahs_len); // Validates a stored iSCSI header digest (CRC32C) with actual header data
void iscsi_connection_pdu_digest_data_update(iscsi_data_digest *data_digest, const iscsi_scsi_ds_cmd_data *ds_cmd_data, const uint32_t ds_len); // Calculate iSCSI data digest (CRC32C)
bool iscsi_connection_pdu_digest_data_verify(const iscsi_data_digest *data_digest, const iscsi_scsi_ds_cmd_data *ds_cmd_data, const uint32_t ds_len); // Validates a stored iSCSI data digest (CRC32C) with actual DataSegment

void iscsi_connection_pdu_ack_remove(iscsi_connection *conn, const uint32_t exp_stat_sn); // Removes an acknowledged PDU from SNACK PDU doubly linked list by ExpStatSN

iscsi_pdu *iscsi_r2t_find_pdu_bhs(iscsi_connection *conn, iscsi_pdu *pdu); // Searches an iSCSI PDU by Basic Header Segment (BHS) in the Ready To Transfer (R2T) active and queued task doubly linked list
int iscsi_r2t_send(iscsi_connection *conn, iscsi_task *task, uint32_t *r2t_sn, const uint32_t pos, const uint32_t len, const uint32_t target_xfer_tag); // Sends an iSCSI Ready To Transfer Sequence Number (R2TSN) packet to the initiator

int iscsi_connection_read_data(iscsi_connection *conn, int len, void *buf);
int iscsi_connection_read_iov_data(iscsi_connection *conn, struct iovec *iov, int iov_count);
void iscsi_connection_pdu_write(iscsi_connection *conn, iscsi_pdu *pdu, iscsi_connection_xfer_complete_callback callback, uint8_t *user_data);

int iscsi_connection_pdu_handle(iscsi_connection *conn); // Handles incoming PDU data, read up to 16 fragments at once
void iscsi_connection_handle(dnbd3_client_t *client, const dnbd3_request_t *request, const int len); // Handles an iSCSI connection until connection is closed

#ifdef __cplusplus
}
#endif

#endif /* DNBD3_ISCSI_H_ */
