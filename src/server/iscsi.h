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

#include <inttypes.h>

#if defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER) && defined(__BIG_ENDIAN) && __BYTE_ORDER == __BIG_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define iscsi_get_be16(x) (x)
#define iscsi_get_be24(x) ((x) & 0xFFFFFFUL)
#define iscsi_get_be32(x) (x)
#define iscsi_get_be64(x) (x)

static inline void iscsi_put_be16(uint8_t *data, const uint16_t val)
{
	(*(uint16_t *) data) = val;
}

static inline void iscsi_put_be24(uint8_t *data, const uint32_t val)
{
	(*(uint16_t *) data) = (uint16_t) (val >> 8U);
	data[2] = (uint8_t) val;
}

static inline void iscsi_put_be32(uint8_t *data, const uint32_t val)
{
	(*(uint32_t *) *data) = val;
}

static inline void iscsi_put_be64(uint8_t *data, const uint64_t val)
{
	(*(uint64_t *) data) = val;
}
#elif defined(__LITTLE_ENDIAN__) || (defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(__i386__) || defined(__i386) || defined(__x86_64)
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
// GCC or CLang
#define iscsi_get_be16(x) (__builtin_bswap16(x))
#define iscsi_get_be24(x) (iscsi_get_be32(x) & 0xFFFFFFUL)
#define iscsi_get_be32(x) (__builtin_bswap32(x))
#define iscsi_get_be64(x) (__builtin_bswap64(x))
#elif defined(_MSC_VER)
#include <intrin.h>
// MVSC
#define iscsi_get_be16(x) (_byteswap_ushort(x))
#define iscsi_get_be32(x) (_byteswap_ulong(x))
#define iscsi_get_be64(x) (_byteswap_uint64(x))
#else
// Other compilers (use slow conversion method with bit rotation, bit shift and logcal AND)
#define iscsi_get_be16(x) ((((uint16_t) (x)) << 8U) | (((uint16_t) (x)) >> 8U))
#define iscsi_get_be32(x) ((((uint32_t) (x) & 0xFFUL) << 24UL) | (((uint32_t) (x) & 0xFF00UL) << 8UL) | (((uint32_t) (x) & 0xFF0000UL) >> 8UL) | (((uint32_t) (x) >> 24UL)))
#define iscsi_get_be64(x) ((uint64_t)((((x) & 0xFFULL) << 56ULL) | (((x) & 0xFF00ULL) << 40ULL) | (((x) & 0xFF0000ull) << 24ULL) | (((x) & 0xFF000000ULL) << 8ULL) | (((x) & 0xFF00000000ULL) >> 8ULL) | (((x) & 0xFF0000000000ULL) >> 24ULL) | (((x) & 0xFF000000000000ULL) >> 40ULL) | (((x) & 0xFF00000000000000ULL) >> 56ULL)))
#endif
static inline void iscsi_put_be16(uint8_t *data, const uint16_t val)
{
	data[0] = (uint8_t) (val >> 8U);
	data[1] = (uint8_t) val;
}

static inline void iscsi_put_be24(uint8_t *data, const uint32_t val)
{
	data[0] = (uint8_t) (val >> 16UL);
	data[1] = (uint8_t) (val >> 8UL);
	data[2] = (uint8_t) val;
}

static inline void iscsi_put_be32(uint8_t *data, const uint32_t val)
{
	data[0] = (uint8_t) (val >> 24UL);
	data[1] = (uint8_t) (val >> 16UL);
	data[2] = (uint8_t) (val >> 8UL);
	data[3] = (uint8_t) val;
}

static inline void iscsi_put_be64(uint8_t *data, const uint64_t val)
{
	data[0] = (uint8_t) (val >> 56ULL);
	data[1] = (uint8_t) (val >> 48ULL);
	data[2] = (uint8_t) (val >> 40ULL);
	data[3] = (uint8_t) (val >> 32ULL);
	data[4] = (uint8_t) (val >> 24ULL);
	data[5] = (uint8_t) (val >> 16ULL);
	data[6] = (uint8_t) (val >> 8ULL);
	data[7] = (uint8_t) val;
}
#else
#error "Unknown CPU endianness"
#endif

/// Aligns value x by rounding up, so it's evenly divisable by n.
#define iscsi_align(x, n) (((x) + (n) - 1) & ~((n) - 1))

uint8_t *iscsi_vsprintf_append_realloc(char *buf, const char *format, va_list args); // Allocates and appends a buffer and sprintf's it
uint8_t *iscsi_sprintf_append_realloc(char *buf, const char *format, ...); // Allocates and appends a buffer and sprintf's it
uint8_t *iscsi_vsprintf_alloc(const char *format, va_list args); // Allocates a buffer and sprintf's it
uint8_t *iscsi_sprintf_alloc(const char *format, ... ); // Allocates a buffer and sprintf's it

/// Shift factor for default capacity.
#define ISCSI_HASHMAP_DEFAULT_CAPACITY_SHIFT 5UL

/// Default capacity is 32 buckets.
#define ISCSI_HASHMAP_DEFAULT_CAPACITY (1UL << (ISCSI_HASHMAP_DEFAULT_CAPACITY_SHIFT))

/// Number of bits to shift left when resizing.
#define ISCSI_HASHMAP_RESIZE_SHIFT 1UL

/// Key data shift value for alignment enforcement.
#define ISCSI_HASHMAP_KEY_ALIGN_SHIFT 3UL

/// Key data size must be multiple of 8 bytes by now.
#define ISCSI_HASHMAP_KEY_ALIGN (1UL << (ISCSI_HASHMAP_KEY_ALIGN_SHIFT))

/// Initial hash code.
#define ISCSI_HASHMAP_HASH_INITIAL 0x811C9DC5UL

/// Value to multiply hash code with.
#define ISCSI_HASHMAP_HASH_MUL 0xBF58476D1CE4E5B9ULL

/**
 * @brief Hash map bucket containing key, value and hash code.
 *
 * This structure is used by the iSCSI hash map implementation
 * in order to maintain the elements.
 */
typedef struct iscsi_hashmap_bucket {
    /// Next bucket, must be first element.
	struct iscsi_hashmap_bucket *next;

    /// Data used as key, must be aligned to 8 bytes and zero padded.
	uint8_t *key;

    /// Size of key, must be a multiple of 8 bytes.
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
 * insertions. Elements can be removed and are marked for
 * deletion until a resize operation is necessary.
 */
typedef struct iscsi_hashmap {
    /// Linked list containing the hash map buckets.
	iscsi_hashmap_bucket *buckets;

    /// Current bucket capacity, MUST be a power of two.
    uint capacity;

    /// Current capacity threshold triggering resize operation.
	uint cap_load; // Capacity load threshold before next resize

	/// Current count of buckets including ones marked for removal.
	uint count;

    /// Number of buckets marked for removal.
    uint removed_count;

    /// First linked list bucket for fast insertion.
    iscsi_hashmap_bucket *first;

    /// Last linked list bucket for faster traversion.
	iscsi_hashmap_bucket *last;
} iscsi_hashmap;

/**
 * @brief A Callback for iterating over map, freeing and removing entries. user_data is free for personal use.
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
typedef int (*iscsi_hashmap_callback)(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // A Callback for iterating over map, freeing and removing entries.
                                                                                                                // user_data is free for personal use

iscsi_hashmap *iscsi_hashmap_create(const uint capacity); // Creates an empty hash map with either specified or default capacity
void iscsi_hashmap_destroy(iscsi_hashmap *map); // Deallocates the hash map objects and buckets, not elements
                                                // Use iscsi_hashmap_iterate to deallocate the elements themselves
uint8_t *iscsi_hashmap_key_create(const uint8_t *data, const size_t len); // Creates a key suitable for hashmap usage (ensures 8-byte boundary and zero padding)
void iscsi_hashmap_key_destroy(uint8_t *key); // Deallocates all resources acquired by iscsi_hashmap_create_key
int iscsi_hashmap_key_destroy_value_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Deallocates all key / value pairs in a hash map by calling free (default destructor)
int iscsi_hashmap_put(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t *value); // Assigns key / value pair to hash map without making copies
int iscsi_hashmap_get_put(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t **out_in_value); // Assigns key / value pair to hash map without making copies
int iscsi_hashmap_put_free(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t *value, iscsi_hashmap_callback callback, uint8_t *user_data); // Assigns key / value pair to hash map without making copies
                                                                                                                                                                // with callback function in case the key already exists
int iscsi_hashmap_contains(iscsi_hashmap *map, const uint8_t *key, const size_t key_size); // Checks whether a specified key exists
int iscsi_hashmap_get(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t **out_value); // Retrieves the value of a specified key
void iscsi_hashmap_remove(iscsi_hashmap *map, const uint8_t *key, const size_t key_size); // Marks an element for removal by setting key and value both to NULL
void iscsi_hashmap_remove_free(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, iscsi_hashmap_callback callback, uint8_t *user_data); // Marks an element for removal by setting key and value both to NULL,
                                                                                                                                                    // but invokes a callback function before actual marking for removal.
int iscsi_hashmap_size(iscsi_hashmap *map); // Retrieves the number of elements of the hash map, ignoring elements marked for removal
int iscsi_hashmap_iterate(iscsi_hashmap *map, iscsi_hashmap_callback callback, uint8_t *user_data); // Iterator with callback function invoked on each element which has not been removed

/* iSCSI protocol stuff (all WORD/DWORD/QWORD values are big endian by default
   unless specified otherwise). */

/// iSCSI Basic Header Segment size.
#define ISCSI_BHS_SIZE 48UL

/// iSCSI header and data digest size (CRC32C).
#define ISCSI_DIGEST_SIZE 4UL

/// iSCSI packet data alignment (BHS, AHS and DataSegment).
#define ISCSI_ALIGN_SIZE 4UL

/// Current minimum iSCSI protocol version supported by this implementation.
#define ISCSI_VERSION_MIN 0

/// Current maximum iSCSI protocol version supported by this implementation.
#define ISCSI_VERSION_MAX 0


/// CRC32C initial constant for header and data digest.
#define ISCSI_CRC32C_INITIAL      0xFFFFFFFFUL

/// CRC32C initial constant for header and data digest.
#define ISCSI_CRC32C_XOR          0xFFFFFFFFUL


/// iSCSI initiator (client) command opcode: NOP-Out.
#define ISCSI_CLIENT_NOP_OUT        0x00

/// iSCSI initiator (client) command opcode: SCSI Command (encapsulates a SCSI Command Descriptor Block).
#define ISCSI_CLIENT_SCSI_CMD       0x01

/// iSCSI initiator (client) command opcode: SCSI Task Management Function Request.
#define ISCSI_CLIENT_TASK_FUNC_REQ  0x02

/// iSCSI initiator (client) command opcode: Login Request.
#define ISCSI_CLIENT_LOGIN_REQ      0x03

/// iSCSI initiator (client) command opcode: Text Request.
#define ISCSI_CLIENT_TEXT_REQ       0x04

/// iSCSI initiator (client) command opcode: SCSI Data-Out (for write operations).
#define ISCSI_CLIENT_SCSI_DATA_OUT  0x05

/// iSCSI initiator (client) command opcode: Logout Request.
#define ISCSI_CLIENT_LOGOUT_REQ     0x06

/// iSCSI initiator (client) command opcode: Selective Negative / Sequence Number Acknowledgment (SNACK) Request.
#define ISCSI_CLIENT_SNACK_REQ      0x10

/// iSCSI initiator (client) command opcode: Vendor-specific code #1.
#define ISCSI_CLIENT_VENDOR_CODE1   0x1C

/// iSCSI initiator (client) command opcode: Vendor-specific code #2.
#define ISCSI_CLIENT_VENDOR_CODE2   0x1D

/// iSCSI initiator (client) command opcode: Vendor-specific code #3.
#define ISCSI_CLIENT_VENDOR_CODE3   0x1E

/// First iSCSI initiator (client) command opcode.
#define ISCSI_CLIENT_FIRST_OPCODE   0x00

/// Last iSCSI initiator (client) command opcode.
#define ISCSI_CLIENT_LAST_OPCODE    0x1F


/// iSCSI target (server) command opcode: NOP-In.
#define ISCSI_SERVER_NOP_IN         0x20

/// iSCSI target (server) command opcode: SCSI Response - contains SCSI status and possibly sense information or other response information.
#define ISCSI_SERVER_SCSI_RESPONSE  0x21

/// iSCSI target (server) command opcode: SCSI Task Management Function Response.
#define ISCSI_SERVER_TASK_FUNC_RES  0x22

/// iSCSI target (server) command opcode: Login Response.
#define ISCSI_SERVER_LOGIN_RES      0x23

/// iSCSI target (server) command opcode: Text Response.
#define ISCSI_SERVER_TEXT_RES       0x24

/// iSCSI target (server) command opcode: SCSI Data-In (for read operations).
#define ISCSI_SERVER_SCSI_DATA_IN   0x25

/// iSCSI target (server) command opcode: Logout Response.
#define ISCSI_SERVER_LOGOUT_RES     0x26

/// iSCSI target (server) command opcode: Ready To Transfer (R2T) - sent by target when it is ready to receive data.
#define ISCSI_SERVER_READY_XFER     0x31

/// iSCSI target (server) command opcode: Asynchronous Message - sent by target to indicate certain special conditions.
#define ISCSI_SERVER_ASYNC_MSG      0x32

/// iSCSI target (server) command opcode: Vendor-specific code #1.
#define ISCSI_SERVER_VENDOR_CODE1   0x3C

/// iSCSI target (server) command opcode: Vendor-specific code #2.
#define ISCSI_SERVER_VENDOR_CODE2   0x3D

/// iSCSI target (server) command opcode: Vendor-specific code #3.
#define ISCSI_SERVER_VENDOR_CODE3   0x3E

/// iSCSI target (server) command opcode: Reject.
#define ISCSI_SERVER_REJECT         0x3F


/// First iSCSI target (server) command opcode.
#define ISCSI_SERVER_FIRST_OPCODE   0x20

/// Last iSCSI target (server) command opcode.
#define ISCSI_SERVER_LAST_OPCODE    0x3F


/// iSCSI opcode bit mask (bits 0-5 used).
#define ISCSI_OPCODE_MASK           0x3F

/// Macro which extracts iSCSI packet data opcode out of opcode byte
#define ISCSI_GET_OPCODE(x) ((x) & ISCSI_OPCODE_MASK)

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
 * @brief iSCSI CDB packet data structure.
 *
 * There are 16 bytes in the CDB field to accommodate the commonly used
 * CDBs. Whenever the CDB is larger than 16 bytes, an Extended CDB AHS
 * MUST be used to contain the CDB spillover.
 */
typedef struct __attribute__((packed)) iscsi_cdb {
    uint8_t data[16];
} iscsi_cdb;

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
    /// AHSLength: Always 5 according to ISCSI specifications for now.
    uint16_t len;

    /// AHSType: Always 2 according to ISCSI specifications for now.
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
 * @brief iSCSI DataSegment Command packet structure.
 *
 * iSCSI targets MUST support and enable Autosense. If Status is CHECK
 * CONDITION (0x02), then the data segment MUST contain sense data for
 * the failed command.
 *
 * For some iSCSI responses, the response data segment MAY contain some
 * response-related information (e.g., for a target failure, it may
 * contain a vendor-specific detailed description of the failure).
 */
typedef struct __attribute__((packed)) iscsi_ds_cmd_data {
    /// SenseLength: This field indicates the length of Sense Data.
    uint16_t len;

    /// The Sense Data contains detailed information about a CHECK CONDITION. SPC3 specifies the format and content of the Sense Data.
    uint8_t sense_data[0];

    /// Response Data.
    uint8_t res_data[0];
} iscsi_ds_cmd_data;

/// SCSI command opcode (embedded in iSCSI protocol): TEST UNIT READY.
#define ISCSI_SCSI_OPCODE_TESTUNITREADY          0x00

/// SCSI command opcode (embedded in iSCSI protocol): READ(6).
#define ISCSI_SCSI_OPCODE_READ6                  0x08

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

/// SCSI command opcode (embedded in iSCSI protocol): MODE SELECT(10).
#define ISCSI_SCSI_OPCODE_MODESELECT10           0x55

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
#define ISCSI_SCSI_OPCODE_SERVICE_ACTION_IN      0x9E

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
    iscsi_cdb scsi_cdb;

    /// Optional AHS packet data.
    iscsi_ahs_packet ahs;

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /// Optional data segment, command data.
    iscsi_ds_cmd_data ds_cmd_data;

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
    iscsi_ds_cmd_data ds_cmd_data;

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

    /// Reserved for future usage (must be always 0x80 for now).
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
    iscsi_ds_cmd_data ds_cmd_data;

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
    iscsi_ds_cmd_data ds_cmd_data;

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

    /// Reserved for future usage (must be always 0x80 for now).
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

    /// Reserved for future usage (must be always 0x80 for now).
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
    iscsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_async_msg_packet;


/**
 * @brief iSCSI Sense Event data packet.
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
typedef struct __attribute__((packed)) iscsi_sense_event_data_packet {
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
} iscsi_sense_event_data_packet;


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
    iscsi_ds_cmd_data ds_cmd_data;

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
    iscsi_ds_cmd_data ds_cmd_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_text_response_packet;

/// Initiator Session ID (ISID) type: Two bits - The T field identifies the format and usage of A, B, C, and D.
#define ISCSI_ISID_TYPE_BITS (1 << 6)

/**
 * @brief Initiator Session ID (ISID) type: OUI-Format.
 *
 * A and B: 22-bit OUI
 * (the I/G and U/L bits are omitted)
 * C and D: 24-bit Qualifier.
 */
#define ISCSI_ISID_TYPE_FORMAT_OUI    0x0

/**
 * @brief Initiator Session ID (ISID) type: EN: Format (IANA Enterprise Number).
 *
 * A: Reserved
 * B and C: EN (IANA Enterprise Number)
 * D: Qualifier
 */
#define ISCSI_ISID_TYPE_FORMAT_EN     0x1

/**
 * @brief Initiator Session ID (ISID) type: Random.
 *
 * A: Reserved
 * B and C: Random
 * D: Qualifier
 */
#define ISCSI_ISID_TYPE_FORMAT_RANDOM 0x2

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_SESSION_TYPE            "SessionType"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_NAME          "InitiatorName"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_NAME             "TargetName"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ADDRESS          "TargetAddress"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_INITIATOR_ALIAS         "InitiatorAlias"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_ALIAS            "TargetAlias"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_TARGET_PORTAL_GROUP_TAG "TargetPortalGroupTag"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD             "AuthMethod"


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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_KRB_AP_REQ "KRB_AP_REQ"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_KRB_AP_REP "KRB_AP_REP"


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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_U     "SRP_U"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_GROUP "SRP_GROUP"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_A     "SRP_A"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_B     "SRP_B"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_M     "SRP_M"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_SRP_SRP_HM    "SRP_HM"


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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_A "CHAP_A"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_I "CHAP_I"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_C "CHAP_C"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_N "CHAP_N"

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
#define ISCSI_LOGIN_AUTH_SECURITY_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_R "CHAP_R"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_HEADER_DIGEST "HeaderDigest"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_DIGEST   "DataDigest"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_CONNECTIONS "MaxConnections"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_SEND_TARGETS "SendTargets"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_INITIAL_R2T "InitialR2T"

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
 * The initiator and target negotiate support for immediate dataTo
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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IMMEDIATE_DATA "ImmediateData"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_RECV_DS_LEN "MaxRecvDataSegmentLength"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_BURST_LEN "MaxBurstLength"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_FIRST_BURST_LEN "FirstBurstLength"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_WAIT "DefaultTime2Wait"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DEFAULT_TIME_RETAIN "DefaultTime2Retain"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_MAX_OUTSTANDING_R2T "MaxOutstandingR2T"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_PDU_IN_ORDER "DataPDUInOrder"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_DATA_SEQ_IN_ORDER "DataSequenceInOrder"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_ERR_RECOVERY_LEVEL "ErrorRecoveryLevel"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_PRIV_EXT_KEY_FMT "X-reversed.vendor"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_TASK_REPORTING "TaskReporting"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_X_NODE_ARCH "X#NodeArchitecture"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IF_MARKER   "IFMarker"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_OF_MARKER   "OFMarker"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_OF_MARK_INT "OFMarkInt"

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
#define ISCSI_LOGIN_AUTH_SESSION_TEXT_KEY_IF_MARK_INT "IFMarkInt"


/// Login request flags: SecurityNegotiation.
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION          0x0

/// Login request flags: LoginOperationalNegotiation.
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1

/// Login request flags: FullFeaturePhase.
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
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE    (1 << 0)

/// Login request flags: Extracts the Next Stage (NSG) bits.
#define ISCSI_LOGIN_REQS_FLAGS_GET_NEXT_STAGE(x) ((x) & 3)


/// Login request flags: SecurityNegotiation.
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION          0x0

/// Login request flags: LoginOperationalNegotiation.
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1

/// Login request flags: FullFeaturePhase.
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_FULL_FEATURE_PHASE            0x3

/**
 * @brief Login request flags: Current Stage (CSG): First bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with aspecific stage in the session (SecurityNegotiation,
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move.
 */
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE (1 << 2)

/// Login request flags: Extracts the Current Stage (CSG) bits.
#define ISCSI_LOGIN_REQS_FLAGS_GET_CURRENT_STAGE(x) (((x) >> 2) & 3)


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
#define ISCSI_LOGIN_REQ_FLAGS_TRANSMIT (1 << 7)


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
    iscsi_ds_cmd_data ds_cmd_data;
} iscsi_login_req_packet;


/// Login response flags: SecurityNegotiation.
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION          0x0

/// Login response flags: LoginOperationalNegotiation.
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1

/// Login response flags: FullFeaturePhase.
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
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE    (1 << 0)

/// Login response flags: Extracts the Next Stage (NSG) bits.
#define ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(x) ((x) & 3)

/// Login response flags: SecurityNegotiation.
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION          0x0

/// Login response flags: LoginOperationalNegotiation.
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1

/// Login response flags: FullFeaturePhase.
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FULL_FEATURE_PHASE            0x3

/**
 * @brief Login response flags: Current Stage (CSG): First bit of the two bits.
 *
 * The Login negotiation requests and responses are associated
 * with aspecific stage in the session (SecurityNegotiation,
 * LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
 * next stage to which they want to move.
 */
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE (1 << 2)

/// Login response flags: Extracts the Current Stage (CSG) bits.
#define ISCSI_LOGIN_RESPONSE_FLAGS_GET_CURRENT_STAGE(x) (((x) >> 2) & 3)

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
#define ISCSI_LOGIN_RESPONSE_FLAGS_TRANSMIT      (1 << 7)


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
    iscsi_ds_cmd_data ds_cmd_data;
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

    /// Reserved for future usage (must be always 0x80 for now).
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

    /// Reserved for future usage (must be always 0x80 for now).
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
    uint32_t data_r2tsn_sn;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved4[2];

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

    /// Reserved for future usage (must be always 0x80 for now).
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
    iscsi_ds_cmd_data ds_ping_data;

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

    /// Reserved for future usage (must be always 0x80 for now).
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
    uint32_t exp_cmd_sn; // ExpCmdSN

    /// MaxCmdSN.
    uint32_t max_cmd_sn;

    /// Reserved for future usage, always MUST be 0.
    uint32_t reserved2[3];

    /// Optional header digest.
    iscsi_header_digest hdr_digest;

    /// DataSegment - Return Ping Data.
    iscsi_ds_cmd_data ds_ping_data;

    /// Optional data digest.
    iscsi_data_digest data_digest;
} iscsi_nop_in_packet;


/// iSCSI packet validation return code from iscsi_validate_packet function: Validation successful -> iSCSI packet recognized and compliance to protocol specification.
#define ISCSI_VALIDATE_PACKET_RESULT_OK                         0L

/// iSCSI packet validation return code from iscsi_validate_packet function: Validation failed -> No packet data specified.
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_NO_DATA             -1L

/// iSCSI packet validation return code from iscsi_validate_packet function: Validation failed -> Packet size smaller than smallest possible iSCSI packet.
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_SIZE_TOO_SMALL      -2L

/// iSCSI packet validation return code from iscsi_validate_packet function: Validation failed -> Packet size doesn't match calculated lengths from BHS.
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_SIZE_MISMATCH       -3L

/// iSCSI packet validation return code from iscsi_validate_packet function: Validation failed -> iSCSI protocol version not supported yet.
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_UNSUPPORTED_VERSION -4L

/// iSCSI packet validation return code from iscsi_validate_packet function: Validation failed -> Valid opcode but violates iSCSI protocol specification.
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS      -5L

/// iSCSI packet validation return code from iscsi_validate_packet function: Validation failed -> Invalid opcode according to iSCSI protocol specification.
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_INVALID_OPCODE      -6L

/// iSCSI packet validation return code from iscsi_validate_packet function: Validation failed -> CRC32C check failed for header (BHS and/or AHS).
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_CRC32C_HDR_DIGEST   -7L

/// iSCSI packet validation return code from iscsi_validate_packet function: Validation failed -> CRC32C check failed for data segment.
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_CRC32C_DATA_DIGEST  -8L


iscsi_bhs_packet *iscsi_create_packet(); // Allocate and initialize an iSCSI BHS packet
void iscsi_destroy_packet(iscsi_bhs_packet *packet_data); // Free resources allocated by iscsi_create_packet
iscsi_bhs_packet *iscsi_append_ahs_packet(iscsi_bhs_packet *packet_data, const uint32_t ahs_len); // Allocate and initialize an iSCSI AHS packet and append to existing data stream
int iscsi_get_ahs_packets(const iscsi_bhs_packet *packet_data); // Counts number of AHS packets in an iSCSI data packet stream
iscsi_ahs_packet *iscsi_get_ahs_packet(const iscsi_bhs_packet *packet_data, const int index); // Retrieves the pointer to an specific AHS packet by index
iscsi_bhs_packet *iscsi_append_ds_packet(iscsi_bhs_packet *packet_data, const int header_digest_size, const uint32_t ds_len, const int data_digest_size); // Allocate and initialize an iSCSI DS packet and append to existing data stream
void iscsi_calc_header_digest(const iscsi_bhs_packet *packet_data); // Calculate and store iSCSI header digest (CRC32C)
int iscsi_validate_header_digest(const iscsi_bhs_packet *packet_data); // Validates a stored iSCSI header digest (CRC32C) with actual header data
void iscsi_calc_data_digest(const iscsi_bhs_packet *packet_data, const int header_digest_size); // Calculate iSCSI data digest (CRC32C)
int iscsi_validate_data_digest(const iscsi_bhs_packet *packet_data, const int header_digest_size); // Validates a stored iSCSI data digest (CRC32C) with actual DataSegment
int iscsi_validate_packet(const struct iscsi_bhs_packet *packet_data, const uint32_t len, const int header_digest_size, const int data_digest_size); // Check if valid iSCSI packet and validate if necessarily


/// Maximum length of a key according to iSCSI specifications.
#define ISCSI_TEXT_KEY_MAX_LEN 63UL

/// Maximum length of value for a simple key type.
#define ISCSI_TEXT_VALUE_MAX_SIMPLE_LEN 255UL

/// Maximum length of value for a normal key.
#define ISCSI_TEXT_VALUE_MAX_LEN        8192UL

/// iSCSI text key=value pair type: Invalid.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_INVALID         -1L

/// iSCSI text key=value pair type: Unspecified type.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_UNSPECIFIED      0L

/// iSCSI text key=value pair type: List.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST             1L

/// iSCSI text key=value pair type: Numerical minimum.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN          2L

/// iSCSI text key=value pair type: Numerical maximum.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MAX          3L

/// iSCSI text key=value pair type: Numerical declarative.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE  4L

/// iSCSI text key=value pair type: Declarative.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE      5L

/// iSCSI text key=value pair type: Boolean OR.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR          6L

/// iSCSI text key=value pair type: Boolean AND.
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND         7L


/**
 * @brief iSCSI Text / Login extracted key=value pair.
 *
 * This structure is used for accessing key and value
 * pairs which have been extracted from either the
 * Text or Login packet data.
 */
typedef struct iscsi_key_value_pair {
    /// Type of key and value pair.
	int type;

    /// State index.
	int state_index;

    /// Value of the key which is stored in the hash map.
	uint8_t *value;
} iscsi_key_value_pair;

/**
 * @brief iSCSI Text / Login key=value packet data construction helper.
 *
 * This structure is used to store the key=value plus NUL terminator
 * pairs for sending as DataSegment packet data to the client.
 */
typedef struct iscsi_key_value_pair_packet {
    /// Current text buffer containing multiple key=value + NUL terminator pairs.
    uint8_t *buf;

    /// Current length of buffer including final NUL terminator without iSCSI zero padding.
    uint len;
} iscsi_key_value_pair_packet;

int iscsi_parse_key_value_pairs(iscsi_hashmap *pairs, const uint8_t *packet_data, uint len, int cbit, uint8_t **partial_pair); // Extracts all text key / value pairs out of an iSCSI packet into a hash map
int iscsi_create_key_value_pair_packet_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Creates a single partial iSCSI packet stream out of a single text key and value pair
iscsi_key_value_pair_packet *iscsi_create_key_value_pairs_packet(const iscsi_hashmap *pairs); // Creates a properly aligned iSCSI packet DataSegment out of a hash map containing text key and value pairs

/**
 * @brief iSCSI incoming connection.
 *
 * This structure is used for maintaining incoming iSCSI
 * connections. Negiotiated text key=value pairs are
 * stored here, status of the connection, session
 * and iSCSI portals.
 */
typedef struct iscsi_connection {
    /// Hash map containing text key / value pairs associated to this connection.
    iscsi_hashmap *key_value_pairs;

    /// iSCSI connection contains a header digest (CRC32), always MUST be 0 or 4 for now.
    int header_digest;

    /// iSCSI connection contains a data digest (CRC32), always MUST be 0 or 4 for now.
    int data_digest;

    int8_t flags;

    /// Initiator Session ID (ISID).
    iscsi_isid isid;

    /// Target Session Identifying Handle (TSIH).
    uint16_t tsih;

    /// Initiator Task Tag (ITT).
    uint32_t init_task_tag;

    /// Connection ID (CID).
    uint16_t cid;

    /// CmdSN.
    uint32_t cmd_sn;

    /// ExpStatSN.
    uint32_t exp_stat_sn;
} iscsi_connection;

iscsi_connection *iscsi_connection_create(const iscsi_login_req_packet *login_req_pkt); // Creates data structure for an iSCSI connection request
void iscsi_connection_destroy(iscsi_connection *conn); // Deallocates all resources acquired by iscsi_connection_create
int iscsi_connection_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI connection destructor callback for hash map

#endif /* DNBD3_ISCSI_H_ */
