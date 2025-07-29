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

// Align a value so that it's evenly divisable by n
#define iscsi_align(x, n) (((x) + (n) - 1) & ~((n) - 1))

uint8_t *iscsi_vsprintf_append_realloc(char *buf, const char *format, va_list args); // Allocates and appends a buffer and sprintf's it
uint8_t *iscsi_sprintf_append_realloc(char *buf, const char *format, ...); // Allocates and appends a buffer and sprintf's it
uint8_t *iscsi_vsprintf_alloc(const char *format, va_list args); // Allocates a buffer and sprintf's it
uint8_t *iscsi_sprintf_alloc(const char *format, ... ); // Allocates a buffer and sprintf's it

#define ISCSI_HASHMAP_DEFAULT_CAPACITY_SHIFT 5UL // Shift factor for default capacity
#define ISCSI_HASHMAP_DEFAULT_CAPACITY (1UL << (ISCSI_HASHMAP_DEFAULT_CAPACITY_SHIFT)) // Default capacity is 32 buckets
#define ISCSI_HASHMAP_RESIZE_SHIFT 1UL // Number of bits to shift left when resizing
#define ISCSI_HASHMAP_KEY_ALIGN_SHIFT 3UL // Key data shift value for alignment enforcement
#define ISCSI_HASHMAP_KEY_ALIGN (1UL << (ISCSI_HASHMAP_KEY_ALIGN_SHIFT)) // Key data size must be multiple of 8 bytes by now
#define ISCSI_HASHMAP_HASH_INITIAL 0x811C9DC5UL // Initial hash code
#define ISCSI_HASHMAP_HASH_MUL 0xBF58476D1CE4E5B9ULL // Value to multiply hash code with

typedef struct iscsi_hashmap_bucket {
	struct iscsi_hashmap_bucket *next; // Must be first element

	uint8_t *key; // Data used as key, zero padding
	size_t key_size; // Size of key, must be a multiple of 8 bytes
	uint32_t hash; // Hash code
	uint8_t *value; // Value
} iscsi_hashmap_bucket;

typedef struct iscsi_hashmap {
	iscsi_hashmap_bucket *buckets; // Hashmap buckets
	uint capacity; // Current capacity in elements
	uint cap_load; // Capacity load threshold before next resize
	uint count; // Number of buckets
	uint removed_count; // Number of removed buckets
	iscsi_hashmap_bucket *first; // First bucket of linked list
	iscsi_hashmap_bucket *last; // Last bucket, allows faster traversion
} iscsi_hashmap;

/**
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
 * @return A negative result indicates as fatal error,
 * 0 means successful operation and a positive value
 * indicates a non-fatal error or a warning.
 */
typedef int (*iscsi_hashmap_callback)(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // A Callback for iterating over map, freeing and removing entries.
                                                                                                                // user_data is free for personal use

iscsi_hashmap *hashmap_create(const uint capacity); // Creates an empty hash map with default capacity specified as above
void iscsi_hashmap_destroy(iscsi_hashmap *map); // Deallocates the hash map objects and buckets, not elements.
                                                // Use iscsi_hashmap_iterate to deallocate the elements themselves
uint8_t *iscsi_hashmap_key_create(const uint8_t *data, const size_t len); // Creates a key suitable for hashmap usage (ensures 8-byte boundary and zero padding)
void iscsi_hashmap_key_destroy(uint8_t *key); // Deallocates all resources acquired by iscsi_hashmap_create_key
int iscsi_hashmap_key_destroy_value_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Deallocates all key / value pairs in a hash map by calling free (default destructor)
int iscsi_hashmap_put(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t *value); // Assigns key / value pair to hash map without making copies
int iscsi_hashmap_get_put(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t **out_in_value); // Assigns key / value pair to hash map without making copies
int iscsi_hashmap_put_free(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t *value, iscsi_hashmap_callback callback, uint8_t *user_data); // Assigns key / value pair to hash map without making copies
                                                                                                                                                                // with callback function in case the key already exists
int iscsi_hashmap_contains(iscsi_hashmap *map, const uint8_t *key, const size_t key_size); // Checks whether a specified key exists
int iscsi_hashmap_get(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, uint8_t **out_val); // Retrieves the value of a specified key
void iscsi_hashmap_remove(iscsi_hashmap *map, const uint8_t *key, const size_t key_size); // Marks an element for removal by setting key and value both to NULL
void iscsi_hashmap_remove_free(iscsi_hashmap *map, const uint8_t *key, const size_t key_size, iscsi_hashmap_callback callback, uint8_t *user_data); // Marks an element for removal by setting key and value both to NULL,
                                                                                                                                                    // but invokes a callback function before actual marking for removal.
int iscsi_hashmap_size(iscsi_hashmap *map); // Retrieves the number of elements of the hash map, ignoring elements marked for removal
int iscsi_hashmap_iterate(iscsi_hashmap *map, iscsi_hashmap_callback callback, uint8_t *user_data); // Iterator with callback function invoked on each element which has not been removed

/* iSCSI protocol stuff (all WORD/DWORD/QWORD values are big endian by default
   unless specified otherwise). */

#define ISCSI_BHS_SIZE 48UL // iSCSI Basic Header Segment size
#define ISCSI_DIGEST_SIZE 4UL // iSCSI header and data digest size (CRC32C)
#define ISCSI_ALIGN_SIZE 4UL // iSCSI packet data alignment (BHS, AHS and DS)

#define ISCSI_VERSION_MIN 0 // Current minimum iSCSI protocol version supported by this implementation
#define ISCSI_VERSION_MAX 0 // Current maximum iSCSI protocol version supported by this implementation

// CRC32C constants for header and data digest
#define ISCSI_CRC32C_INITIAL      0xFFFFFFFFUL
#define ISCSI_CRC32C_XOR          0xFFFFFFFFUL

// iSCSI initiator (client) command opcodes
#define ISCSI_CLIENT_NOP_OUT        0x00 // NOP-Out
#define ISCSI_CLIENT_SCSI_CMD       0x01 // SCSI Command (encapsulates a SCSI Command Descriptor Block)
#define ISCSI_CLIENT_TASK_FUNC_REQ  0x02 // SCSI Task Management Function Request
#define ISCSI_CLIENT_LOGIN_REQ      0x03 // Login Request
#define ISCSI_CLIENT_TEXT_REQ       0x04 // Text Request
#define ISCSI_CLIENT_SCSI_DATA_OUT  0x05 // SCSI Data-Out (for write operations)
#define ISCSI_CLIENT_LOGOUT_REQ     0x06 // Logout Request
#define ISCSI_CLIENT_SNACK_REQ      0x10 // SNACK Request
#define ISCSI_CLIENT_VENDOR_CODE1   0x1C // Vendor-specific code #1
#define ISCSI_CLIENT_VENDOR_CODE2   0x1D // Vendor-specific code #2
#define ISCSI_CLIENT_VENDOR_CODE3   0x1E // Vendor-specific code #3

#define ISCSI_CLIENT_FIRST_OPCODE   0x00 // First client opcode value
#define ISCSI_CLIENT_LAST_OPCODE    0x1F // Last client opcode value

// iSCSI target (server) command opcodes
#define ISCSI_SERVER_NOP_IN         0x20 // NOP-In
#define ISCSI_SERVER_SCSI_RESPONSE  0x21 // SCSI Response - contains SCSI status and possibly sense information or other response information
#define ISCSI_SERVER_TASK_FUNC_RES  0x22 // SCSI Task Management Function Response
#define ISCSI_SERVER_LOGIN_RES      0x23 // Login Response
#define ISCSI_SERVER_TEXT_RES       0x24 // Text Response
#define ISCSI_SERVER_SCSI_DATA_IN   0x25 // SCSI Data-In (for read operations)
#define ISCSI_SERVER_LOGOUT_RES     0x26 // Logout Response
#define ISCSI_SERVER_READY_XFER     0x31 // Ready To Transfer (R2T) - sent by target when it is ready to receive data
#define ISCSI_SERVER_ASYNC_MSG      0x32 // Asynchronous Message - sent by target to indicate certain special conditions
#define ISCSI_SERVER_VENDOR_CODE1   0x3C // Vendor-specific code #1
#define ISCSI_SERVER_VENDOR_CODE2   0x3D // Vendor-specific code #2
#define ISCSI_SERVER_VENDOR_CODE3   0x3E // Vendor-specific code #3
#define ISCSI_SERVER_REJECT         0x3F // Reject

#define ISCSI_SERVER_FIRST_OPCODE   0x20 // First client opcode value
#define ISCSI_SERVER_LAST_OPCODE    0x3F // Last client opcode value

#define ISCSI_OPCODE_MASK           0x3F // ISCSI opcode bit mask (bits 0-5 used)
#define ISCSI_GET_OPCODE(x) ((x) & ISCSI_OPCODE_MASK) // Funky macro to get iSCSI packet opcode

typedef struct __attribute__((packed)) iscsi_bhs_packet {
    uint8_t opcode; // Command opcode (see above)
    uint8_t opcode_fields[3]; // Opcode-specific fields
    uint8_t total_ahs_len; // Total AHS length
    uint8_t ds_len[3]; // Data segment length
    union {
        uint64_t lun; // LUN bitmask
        uint8_t opcode_spec[8];  // Opcode-specific fields
    } lun_opcode;
    uint32_t init_task_tag; // Initiator task tag
    uint8_t opcode_spec_fields[28];
} iscsi_bhs_packet;

#define ISCSI_AHS_TYPE_EXT_CDB_PACKET                   0x01    // Command Descriptor Block (CDB)
#define ISCSI_AHS_TYPE_BIDI_READ_EXP_XFER_AHS_PACKET    0x02

typedef struct __attribute__((packed)) iscsi_ahs_packet {
    uint16_t len; // AHSLength
    uint8_t type; // AHSType
    uint8_t specific; // AHS-Specific
    uint8_t data[0]; // AHS-Specific data
} iscsi_ahs_packet;

/* There are 16 bytes in the CDB field to accommodate the commonly used
   CDBs.  Whenever the CDB is larger than 16 bytes, an Extended CDB AHS
   MUST be used to contain the CDB spillover.
*/
typedef struct __attribute__((packed)) iscsi_cdb {
    uint8_t data[16];
} iscsi_cdb;

/* This type of AHS MUST NOT be used if the CDBLength is less than 17.
   The length includes the reserved byte 3.
*/
typedef struct __attribute__((packed)) iscsi_ext_cdb_ahs_packet {
    uint16_t len; // AHSLength - (CDBLength - 15)
    uint8_t type; // Identifier (always 0x01 according to specs)
    uint8_t reserved; // Reserved for future usage
    uint8_t data[0]; // ExtendedCDB
} iscsi_ext_cdb_ahs_packet;

typedef struct __attribute__((packed)) iscsi_bidi_read_exp_xfer_ahs_packet {
    uint16_t len; // Always 0x0005 according to specs
    uint8_t type; // Identifier (always 0x02 according to specs)
    uint8_t reserved; // Reserved for future usage
    uint32_t bidi_read_exp_xfer_len; // Bidirectional Read Expected Data Transfer Length
} iscsi_bidi_read_exp_xfer_ahs_packet;

/* Certain iSCSI conditions result in the command being terminated at
   the target (response code of Command Completed at Target) with a SCSI
   CHECK CONDITION Status as outlined in the following definitions
   (Sense key: Aborted Command 0x0B):
*/
#define ISCSI_DS_ERROR_UNEXPECTED_UNSOLICITED_DATA_ASC  0x0C // Unexpected unsolicited data
#define ISCSI_DS_ERROR_UNEXPECTED_UNSOLICITED_DATA_ASCQ 0x0C

#define ISCSI_DS_ERROR_INCORRECT_AMOUNT_OF_DATA_ASC  0x0C // Incorrect amount of data
#define ISCSI_DS_ERROR_INCORRECT_AMOUNT_OF_DATA_ASCQ 0x0D

#define ISCSI_DS_ERROR_PROTOCOL_SERVICE_CRC_ERROR_ASC  0x47 // Protocol Service CRC error
#define ISCSI_DS_ERROR_PROTOCOL_SERVICE_CRC_ERROR_ASCQ 0x05

#define ISCSI_DS_ERROR_SNACK_REJECTED_ASC  0x11 // SNACK rejected
#define ISCSI_DS_ERROR_SNACK_REJECTED_ASCQ 0x13

/* Optional header and data digests protect the integrity of the header
   and data, respectively.  The digests, if present, are located,
   respectively, after the header and PDU-specific data and cover,
   respectively, the header and the PDU data, each including the padding
   bytes, if any.

   The existence and type of digests are negotiated during the Login
   Phase.
*/
typedef struct __attribute__((packed)) iscsi_header_digest {
    uint32_t crc32c; // Header digest is a CRC32C for ensuring integrity
} iscsi_header_digest;

typedef struct __attribute__((packed)) iscsi_data_digest {
    uint32_t crc32c; // Data digest is a CRC32C for ensuring integrity
} iscsi_data_digest;

/* iSCSI targets MUST support and enable Autosense. If Status is CHECK
   CONDITION (0x02), then the data segment MUST contain sense data for
   the failed command.

   For some iSCSI responses, the response data segment MAY contain some
   response-related information (e.g., for a target failure, it may
   contain a vendor-specific detailed description of the failure).
*/

typedef struct __attribute__((packed)) iscsi_ds_cmd_data {
    uint16_t len; // SenseLength - This field indicates the length of Sense Data.
    uint8_t sense_data[0]; // The Sense Data contains detailed information about a CHECK CONDITION.
                     // SPC3 specifies the format and content of the Sense Data.
    uint8_t res_data[0]; // Response Data
} iscsi_ds_cmd_data;

// SCSI command opcodes (embedded in iSCSI protocol)
#define SCSI_OPCODE_TESTUNITREADY          0x00 // TEST UNIT READY
#define SCSI_OPCODE_READ6                  0x08 // READ(6)
#define SCSI_OPCODE_INQUIRY                0x12 // INQUIRY
#define SCSI_OPCODE_MODESELECT6            0x15 // MODE SELECT(6)
#define SCSI_OPCODE_RESERVE6               0x16 // RESERVE(6)
#define SCSI_OPCODE_RELEASE6               0x17 // RELEASE(6)
#define SCSI_OPCODE_MODESENSE6             0x1A // MODE SENSE(6)
#define SCSI_OPCODE_STARTSTOPUNIT          0x1B // START STOP UNIT
#define SCSI_OPCODE_PREVENTALLOW           0x1E // PREVENT ALLOW MEDIUM REMOVAL
#define SCSI_OPCODE_READCAPACITY10         0x25 // READ CAPACITY(10)
#define SCSI_OPCODE_READ10                 0x28 // READ(10)
#define SCSI_OPCODE_WRITE10                0x2A // WRITE(10)
#define SCSI_OPCODE_WRITE_VERIFY10         0x2E // WRITE AND VERIFY(10)
#define SCSI_OPCODE_VERIFY10               0x2F // VERIFY(10)
#define SCSI_OPCODE_PREFETCH10             0x34 // PRE-FETCH(10)
#define SCSI_OPCODE_SYNCHRONIZECACHE10     0x35 // SYNCHRONIZE CACHE(10)
#define SCSI_OPCODE_READ_DEFECT_DATA10     0x37 // READ DEFECT DATA(10)
#define SCSI_OPCODE_WRITE_SAME10           0x41 // WRITE SAME(10)
#define SCSI_OPCODE_UNMAP                  0x42 // UNMAP
#define SCSI_OPCODE_READTOC                0x43 // READ TOC/PMA/ATIP
#define SCSI_OPCODE_SANITIZE               0x48 // SANITIZE
#define SCSI_OPCODE_MODESELECT10           0x55 // MODE SELECT(10)
#define SCSI_OPCODE_MODESENSE10            0x5A // MODE SENSE(10)
#define SCSI_OPCODE_PERSISTENT_RESERVE_IN  0x5E // PERSISTENT RESERVE IN
#define SCSI_OPCODE_PERSISTENT_RESERVE_OUT 0x5F // PERSISTENT RESERVE OUT
#define SCSI_OPCODE_EXTENDED_COPY          0x83 // Third-party Copy OUT
#define SCSI_OPCODE_RECEIVE_COPY_RESULTS   0x84 // Third-party Copy IN
#define SCSI_OPCODE_READ16                 0x88 // READ(16)
#define SCSI_OPCODE_COMPARE_AND_WRITE      0x89 // COMPARE AND WRITE
#define SCSI_OPCODE_WRITE16                0x8A // WRITE(16)
#define SCSI_OPCODE_ORWRITE                0x8B // ORWRITE
#define SCSI_OPCODE_WRITE_VERIFY16         0x8E // WRITE AND VERIFY(16)
#define SCSI_OPCODE_VERIFY16               0x8F // VERIFY(16)
#define SCSI_OPCODE_PREFETCH16             0x90 // PRE-FETCH(16)
#define SCSI_OPCODE_SYNCHRONIZECACHE16     0x91 // SYNCHRONIZE CACHE(16)
#define SCSI_OPCODE_WRITE_SAME16           0x93 // WRITE SAME(16)
#define SCSI_OPCODE_WRITE_ATOMIC16         0x9C // WRITE ATOMIC(16)
#define SCSI_OPCODE_SERVICE_ACTION_IN      0x9E // SERVICE ACTION IN(16)
#define SCSI_OPCODE_REPORTLUNS             0xA0 // REPORT LUNS
#define SCSI_OPCODE_MAINTENANCE_IN         0xA3 // MAINTENANCE IN
#define SCSI_OPCODE_READ12                 0xA8 // READ(12)
#define SCSI_OPCODE_WRITE12                0xAA // WRITE(12)
#define SCSI_OPCODE_WRITE_VERIFY12         0xAE // WRITE AND VERIFY(12)
#define SCSI_OPCODE_VERIFY12               0xAF // VERIFY(12)
#define SCSI_OPCODE_READ_DEFECT_DATA12     0xB7 // READ DEFECT DATA(12)

#define ISCSI_SCSI_CMD_FLAGS_TASK_NO_UNSOLICITED_DATA   (1 << 7)   // (F) is set to 1 when no unsolicited SCSI Data-Out PDUs
                                                                   // follow this PDU. When F = 1 for a write and if Expected
                                                                   // Data Transfer Length is larger than the
                                                                   // DataSegmentLength, the target may solicit additional data
                                                                   // through R2T.
#define ISCSI_SCSI_CMD_FLAGS_TASK_READ                  (1 << 6)   // (R) is set to 1 when the command is expected to input data
#define ISCSI_SCSI_CMD_FLAGS_TASK_WRITE                 (1 << 5)   // (W) is set to 1 when the command is expected to output data

#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_UNTAGGED         0x0         // Untagged task attribute
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_SIMPLE           0x1         // Simple task attribute
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_ORDERED          0x2         // Ordered task attribute
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_HEAD_QUEUE       0x3         // Head of queue task attribute
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_ACA              0x4         // ACA task attribute
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_RESERVED_1       0x5         // ACA task attribute
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_RESERVED_2       0x6         // ACA task attribute
#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_RESERVED_3       0x7         // ACA task attribute

/* Flags and Task Attributes:
   At least one of the W and F bits MUST be set to 1.
   Either or both of R and W MAY be 1 when the Expected Data Transfer
   Length and/or the Bidirectional Read Expected Data Transfer Length
   are 0, but they MUST NOT both be 0 when the Expected Data Transfer
   Length and/or Bidirectional Read Expected Data Transfer Length are
   not 0 (i.e., when some data transfer is expected, the transfer
   direction is indicated by the R and/or W bit).
*/

#define ISCSI_SCSI_CMD_FLAGS_TASK_ATTR_MASK             0x7         // Task Attributes (ATTR) are encoded in the first three LSBs'

typedef struct __attribute__((packed)) iscsi_scsi_cmd_packet {
    uint8_t opcode; // Always 0x01 according to specification (see above)
    int8_t flags_task; // Flags and Task Attributes
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // Total AHS length
    uint8_t ds_len[3]; // Data segment length
    uint64_t lun; // LUN bitmask
    uint32_t init_task_tag; // Initiator task tag
    uint32_t exp_xfer_len; // Expected Data Transfer Length
                           // For unidirectional operations, the Expected Data Transfer Length
                           // field contains the number of bytes of data involved in this SCSI
                           // operation. For a unidirectional write operation (W flag set to 1 and
                           // R flag set to 0), the initiator uses this field to specify the number
                           // of bytes of data it expects to transfer for this operation. For a
                           // unidirectional read operation (W flag set to 0 and R flag set to 1),
                           // the initiator uses this field to specify the number of bytes of data
                           // it expects the target to transfer to the initiator. It corresponds
                           // to the SAM-2 byte count.
                           // For bidirectional operations (both R and W flags are set to 1), this
                           // field contains the number of data bytes involved in the write
                           // transfer. For bidirectional operations, an additional header segment
                           // MUST be present in the header sequence that indicates the
                           // Bidirectional Read Expected Data Transfer Length. The Expected Data
                           // Transfer Length field and the Bidirectional Read Expected Data
                           // Transfer Length field correspond to the SAM-2 byte count.
                           // If the Expected Data Transfer Length for a write and the length of
                           // the immediate data part that follows the command (if any) are the
                           // same, then no more data PDUs are expected to follow. In this case,
                           // the F bit MUST be set to 1.
                           // If the Expected Data Transfer Length is higher than the
                           // FirstBurstLength (the negotiated maximum amount of unsolicited data
                           // the target will accept), the initiator MUST send the maximum amount
                           // of unsolicited data OR ONLY the immediate data, if any.
                           // Upon completion of a data transfer, the target informs the initiator
                           // (through residual counts) of how many bytes were actually processed
                           // (sent and/or received) by the target.
    uint32_t cmd_sn; // The CmdSN enables ordered delivery across multiple connections in a single session
    uint32_t exp_stat_sn; // Command responses up to ExpStatSN - 1 (modulo 2**32) have been
                          // received (acknowledges status) on the connection.
    struct iscsi_cdb scsi_cdb; // SCSI Command Descriptor Block (CDB)
                               // There are 16 bytes in the CDB field to accommodate the commonly used
                               // CDBs. Whenever the CDB is larger than 16 bytes, an Extended CDB AHS
                               // MUST be used to contain the CDB spillover.
    struct iscsi_ahs_packet ahs; // Optional AHS packet data
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_ds_cmd_data ds_cmd_data; // Optional data segment, command data
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_scsi_cmd_packet;

#define ISCSI_SCSI_RESPONSE_FLAGS_RES_UNDERFLOW   (1 << 1)           // (U) set for Residual Underflow. In this case, the Residual
                                                                     // Count indicates the number of bytes that were not
                                                                     // transferred out of the number of bytes that were expected
                                                                     // to be transferred. For a bidirectional operation, the
                                                                     // Residual Count contains the residual for the write
                                                                     // operation.

#define ISCSI_SCSI_RESPONSE_FLAGS_RES_OVERFLOW    (1 << 2)           // (O) set for Residual Overflow. In this case, the Residual
                                                                     // Count indicates the number of bytes that were not
                                                                     // transferred because the initiator's Expected Data
                                                                     // Transfer Length was not sufficient. For a bidirectional
                                                                     // operation, the Residual Count contains the residual for
                                                                     // the write operation.

#define ISCSI_SCSI_RESPONSE_FLAGS_BIDI_READ_RES_UNDERFLOW   (1 << 3) // (u) set for Bidirectional Read Residual Underflow. In this
                                                                     // case, the Bidirectional Read Residual Count indicates the
                                                                     // number of bytes that were not transferred to the
                                                                     // initiator out of the number of bytes expected to be
                                                                     // transferred.

#define ISCSI_SCSI_RESPONSE_FLAGS_BIDI_READ_RES_OVERFLOW    (1 << 4) // (o) set for Bidirectional Read Residual Overflow. In this
                                                                     // case, the Bidirectional Read Residual Count indicates the
                                                                     // number of bytes that were not transferred to the
                                                                     // initiator because the initiator's Bidirectional Read
                                                                     // Expected Data Transfer Length was not sufficient.

/* Bits O and U and bits o and u are mutually exclusive (i.e., having
   both o and u or O and U set to 1 is a protocol error).

   For a response other than "Command Completed at Target", bits 3-6
   MUST be 0.
*/

#define ISCSI_SCSI_RESPONSE_STATUS_GOOD             0x00
#define ISCSI_SCSI_RESPONSE_STATUS_CHECK_COND       0x02
#define ISCSI_SCSI_RESPONSE_STATUS_BUSY             0x08
#define ISCSI_SCSI_RESPONSE_STATUS_RES_CONFLICT     0x18
#define ISCSI_SCSI_RESPONSE_STATUS_TASK_SET_FULL    0x28
#define ISCSI_SCSI_RESPONSE_STATUS_ACA_ACTIVE       0x30
#define ISCSI_SCSI_RESPONSE_STATUS_TASK_ABORTED     0x40

/* The Status field is used to report the SCSI status of the command (as
   specified in SAM2) and is only valid if the response code is
   Command Completed at Target.

   If a SCSI device error is detected while data from the initiator is
   still expected (the command PDU did not contain all the data and the
   target has not received a data PDU with the Final bit set), the
   target MUST wait until it receives a data PDU with the F bit set in
   the last expected sequence before sending the Response PDU.
*/

#define ISCSI_SCSI_RESPONSE_CODE_OK                 0x00 // Command Completed at Target
#define ISCSI_SCSI_RESPONSE_CODE_FAIL               0x01 // Target Failure
#define ISCSI_SCSI_RESPONSE_CODE_VENDOR_FIRST       0x80 // First vendor specific response code
#define ISCSI_SCSI_RESPONSE_CODE_VENDOR_LAST        0xFF // Last vendor specific response code

/* The Response field is used to report a service response. The mapping
   of the response code into a SCSI service response code value, if
   needed, is outside the scope of this document. However, in symbolic
   terms, response value 0x00 maps to the SCSI service response (see
*/
typedef struct __attribute__((packed)) iscsi_scsi_response_packet {
    uint8_t opcode; // Always 0x21 according to specification (see above)
    int8_t flags; // Flags (see above)
    uint8_t response; // This field contains the iSCSI service response.
    uint8_t status; // The Status field is used to report the SCSI status of the command (as
                    // specified in SAM2) and is only valid if the response code is
                    // Command Completed at Target. See above for codes.
    uint8_t total_ahs_len; // Total AHS length
    uint8_t ds_len[3]; // Data segment length
    uint64_t reserved; // Reserved for future usage
    uint32_t init_task_tag; // Initiator task tag
    uint32_t snack_tag; // This field contains a copy of the SNACK Tag of the last SNACK Tag
                        // accepted by the target on the same connection and for the command for
                        // which the response is issued. Otherwise, it is reserved and should
                        // be set to 0.
                        // After issuing a R-Data SNACK, the initiator must discard any SCSI
                        // status unless contained in a SCSI Response PDU carrying the same
                        // SNACK Tag as the last issued R-Data SNACK for the SCSI command on the
                        // current connection.
    uint32_t stat_sn; // StatSN - Status Sequence Number
                      // The StatSN is a sequence number that the target iSCSI layer generates
                      // per connection and that in turn enables the initiator to acknowledge
                      // status reception. The StatSN is incremented by 1 for every
                      // response/status sent on a connection, except for responses sent as a
                      // result of a retry or SNACK. In the case of responses sent due to a
                      // retransmission request, the StatSN MUST be the same as the first time
                      // the PDU was sent, unless the connection has since been restarted.
    uint32_t exp_cmd_sn; // ExpCmdSN - Next Expected CmdSN from This Initiator
                         // The ExpCmdSN is a sequence number that the target iSCSI returns to
                         // the initiator to acknowledge command reception. It is used to update
                         // a local variable with the same name. An ExpCmdSN equal to
                         // MaxCmdSN + 1 indicates that the target cannot accept new commands.
    uint32_t max_cmd_sn; // MaxCmdSN - Maximum CmdSN from This Initiator
                         // The MaxCmdSN is a sequence number that the target iSCSI returns to
                         // the initiator to indicate the maximum CmdSN the initiator can send.
                         // It is used to update a local variable with the same name. If the
                         // MaxCmdSN is equal to ExpCmdSN - 1, this indicates to the initiator
                         // that the target cannot receive any additional commands. When the
                         // MaxCmdSN changes at the target while the target has no pending PDUs
                         // to convey this information to the initiator, it MUST generate a
                         // NOP-In to carry the new MaxCmdSN.
    uint32_t exp_data_sn; // ExpDataSN or Reserved
                          // This field indicates the number of Data-In (read) PDUs the target has
                          // sent for the command.
                          // This field MUST be 0 if the response code is not Command Completed at
                          // Target or the target sent no Data-In PDUs for the command.
    uint32_t bidi_read_res_cnt; // Bidirectional Read Residual Count or Reserved
                                // The Bidirectional Read Residual Count field MUST be valid in the case
                                // where either the u bit or the o bit is set. If neither bit is set,
                                // the Bidirectional Read Residual Count field is reserved. Targets may
                                // set the Bidirectional Read Residual Count, and initiators may use it
                                // when the response code is Command Completed at Target. If the o bit
                                // is set, the Bidirectional Read Residual Count indicates the number of
                                // bytes that were not transferred to the initiator because the
                                // initiator's Bidirectional Read Expected Data Transfer Length was not
                                // sufficient. If the u bit is set, the Bidirectional Read Residual
                                // Count indicates the number of bytes that were not transferred to the
                                // initiator out of the number of bytes expected to be transferred.
    uint32_t res_cnt; // Residual Count or Reserved
                      // The Residual Count field MUST be valid in the case where either the U
                      // bit or the O bit is set. If neither bit is set, the Residual Count
                      // field MUST be ignored on reception and SHOULD be set to 0 when
                      // sending. Targets may set the residual count, and initiators may use
                      // it when the response code is Command Completed at Target (even if the
                      // status returned is not GOOD). If the O bit is set, the Residual
                      // Count indicates the number of bytes that were not transferred because
                      // the initiator's Expected Data Transfer Length was not sufficient. If
                      // the U bit is set, the Residual Count indicates the number of bytes
                      // that were not transferred out of the number of bytes expected to be
                      // transferred.
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_ds_cmd_data ds_cmd_data; // Optional data segment, command data
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_scsi_response_packet;

#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_ABORT_TASK         0x01 // ABORT TASK - aborts the task identified by the Referenced Task Tag field
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_ABORT_TASK_SET     0x02 // ABORT TASK SET - aborts all tasks issued via this session on the LU
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_CLEAR_ACA          0x03 // CLEAR ACA - clears the Auto Contingent Allegiance condition
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_CLEAR_TASK_SET     0x04 // CLEAR TASK SET - aborts all tasks in the appropriate task set
                                                              // as defined by the TST field in the Control mode page
                                                              // (see SPC3)
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_LOGICAL_UNIT_RESET 0x05 // LOGICAL UNIT RESET
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_TARGET_WARM_RESET  0x06 // TARGET WARM RESET
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_TARGET_COLD_RESET  0x07 // TARGET COLD RESET
#define ISCSI_TASK_MGMT_FUNC_REQ_FUNC_TASK_REASSIGN      0x08 // TASK REASSIGN - reassigns connection allegiance for the task
                                                              // identified by the Initiator Task Tag field to this connection,
                                                              // thus resuming the iSCSI exchanges for the task

typedef struct __attribute__((packed)) iscsi_task_mgmt_func_req_packet {
    uint8_t opcode; // Always 0x02 according to specification (see above)
    uint8_t func; // Function.
                  // The task management functions provide an initiator with a way to
                  // explicitly control the execution of one or more tasks (SCSI and iSCSI
                  // tasks). The task management function codes are listed below. For a
                  // more detailed description of SCSI task management, see SAM2.
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength (MUST be 0 for this PDU)
    uint8_t ds_len[3]; // DataSegmentLength (MUST be 0 for this PDU)
    uint64_t lun; // Logical Unit Number (LUN) or Reserved
                  // This field is required for functions that address a specific LU
                  // (ABORT TASK, CLEAR TASK SET, ABORT TASK SET, CLEAR ACA, LOGICAL UNIT
                  // RESET) and is reserved in all others
    uint32_t init_task_tag; // Initiator task tag
                            // This is the Initiator Task Tag of the task to be aborted for the
                            // ABORT TASK function or reassigned for the TASK REASSIGN function.
                            // For all the other functions, this field MUST be set to the reserved
                            // value 0xFFFFFFFF
    uint32_t ref_task_tag; // Referenced task tag or 0xFFFFFFFF
    uint32_t cmd_sn; // CmdSN
    uint32_t exp_stat_sn; // ExpStatSN
    uint32_t ref_cmd_sn; // RefCmdSN or Reserved
                         // If an ABORT TASK is issued for a task created by an immediate
                         // command, then the RefCmdSN MUST be that of the task management
                         // request itself (i.e., the CmdSN and RefCmdSN are equal).
                         // For an ABORT TASK of a task created by a non-immediate command, the
                         // RefCmdSN MUST be set to the CmdSN of the task identified by the
                         // Referenced Task Tag field. Targets must use this field when the task
                         // identified by the Referenced Task Tag field is not with the target.
                         // Otherwise, this field is reserved
    uint32_t exp_data_sn; // ExpDataSN or Reserved
                          // For recovery purposes, the iSCSI target and initiator maintain a data
                          // acknowledgment reference number - the first input DataSN number
                          // unacknowledged by the initiator. When issuing a new command, this
                          // number is set to 0. If the function is TASK REASSIGN, which
                          // establishes a new connection allegiance for a previously issued read
                          // or bidirectional command, the ExpDataSN will contain an updated data
                          // acknowledgment reference number or the value 0; the latter indicates
                          // that the data acknowledgment reference number is unchanged. The
                          // initiator MUST discard any data PDUs from the previous execution that
                          // it did not acknowledge, and the target MUST transmit all Data-In PDUs
                          // (if any) starting with the data acknowledgment reference number. The
                          // number of retransmitted PDUs may or may not be the same as the
                          // original transmission, depending on if there was a change in
                          // MaxRecvDataSegmentLength in the reassignment. The target MAY also
                          // send no more Data-In PDUs if all data has been acknowledged.
                          // The value of ExpDataSN MUST be 0 or higher than the DataSN of the
                          // last acknowledged Data-In PDU, but not larger than DataSN + 1 of the
                          // last Data-IN PDU sent by the target. Any other value MUST be ignored
                          // by the target.
                          // For other functions, this field is reserved
    uint64_t reserved2; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
} iscsi_task_mgmt_func_req_packet;

#define ISCSI_TASK_MGMT_FUNC_RESPONSE_FUNC_COMPLETE               0x00 // Function complete
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_TASK_NO_EXIST               0x01 // Task does not exist
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_LUN_NO_EXIST                0x02 // LUN does not exist
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_TASK_ALLEGIANT              0x03 // Task still allegiant
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_TASK_UNSUPPORTED_ALLEGIANCE 0x04 // Task allegiance reassignment not supported
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_TASK_UNSUPPORTED_MGMT       0x05 // Task management function not supported
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_FUNC_AUTH_FAILED            0x06 // Function authorization failed
#define ISCSI_TASK_MGMT_FUNC_RESPONSE_FUNC_REJECTED               0xFF // Function rejected

/* For the functions ABORT TASK, ABORT TASK SET, CLEAR ACA, CLEAR TASK
   SET, LOGICAL UNIT RESET, TARGET COLD RESET, TARGET WARM RESET, and
   TASK REASSIGN, the target performs the requested task management
   function and sends a task management response back to the initiator.
   For TASK REASSIGN, the new connection allegiance MUST ONLY become
   effective at the target after the target issues the task management
   response.
*/
typedef struct __attribute__((packed)) iscsi_task_mgmt_func_response_packet {
    uint8_t opcode; // Always 0x22 according to specification (see above)
    uint8_t flags; // Reserved for future usage
    uint8_t response; // Function response (see above)
                      // For the TARGET COLD RESET and TARGET WARM RESET functions, the target
                      // cancels all pending operations across all LUs known to the issuing
                      // initiator. For the TARGET COLD RESET function, the target MUST then
                      // close all of its TCP connections to all initiators (terminates all
                      // sessions).
                      // The mapping of the response code into a SCSI service response code
                      // value, if needed, is outside the scope of this document. However, in
                      // symbolic terms, Response values 0 and 1 map to the SCSI service
                      // response of FUNCTION COMPLETE. Response value 2 maps to the SCSI
                      // service response of INCORRECT LOGICAL UNIT NUMBER. All other
                      // Response values map to the SCSI service response of FUNCTION
                      // REJECTED. If a Task Management Function Response PDU does not arrive
                      // before the session is terminated, the SCSI service response is
                      // SERVICE DELIVERY OR TARGET FAILURE.
                      // The response to ABORT TASK SET and CLEAR TASK SET MUST only be issued
                      // by the target after all of the commands affected have been received
                      // by the target, the corresponding task management functions have been
                      // executed by the SCSI target, and the delivery of all responses
                      // delivered until the task management function completion has been
                      // confirmed (acknowledged through the ExpStatSN) by the initiator on
                      // all connections of this session.
                      // For the ABORT TASK function,
                      // a) if the Referenced Task Tag identifies a valid task leading to a
                      //    successful termination, then targets must return the "Function
                      //    complete" response.
                      // b) if the Referenced Task Tag does not identify an existing task
                      //    but the CmdSN indicated by the RefCmdSN field in the Task
                      //    Management Function Request is within the valid CmdSN window
                      //    and less than the CmdSN of the Task Management Function Request
                      //    itself, then targets must consider the CmdSN as received and
                      //    return the "Function complete" response.
                      // c) if the Referenced Task Tag does not identify an existing task
                      //    and the CmdSN indicated by the RefCmdSN field in the Task
                      //    Management Function Request is outside the valid CmdSN window,
                      //    then targets must return the "Task does not exist" response
    uint8_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength (MUST be 0 for this PDU)
    uint8_t ds_len[3]; // DataSegmentLength (MUST be 0 for this PDU)
    uint64_t reserved2; // Reserved for future usage
    uint32_t init_task_tag; // Initiator task tag
    uint32_t reserved3; // Reserved for future usage
    uint32_t stat_sn; // StatSN
    uint32_t exp_cmd_sn; // ExpCmdSN
    uint32_t max_cmd_sn; // MaxCmdSN
    uint32_t reserved4; // Reserved for future usage
    uint64_t reserved5; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
} iscsi_task_mgmt_func_response_packet;

#define ISCSI_SCSI_DATA_OUT_DATA_IN_FLAGS_IMMEDIATE   (1 << 7) // Immediately process transfer

typedef struct __attribute__((packed)) iscsi_scsi_data_out_req_packet {
    uint8_t opcode; // Always 0x02 according to specification (see above)
    int8_t flags; // Flags (see above)
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength (MUST be 0 for this PDU)
    uint8_t ds_len[3]; // DataSegmentLength (MUST be 0 for this PDU)
    uint64_t lun; // Logical Unit Number (LUN) or Reserved
    uint32_t init_task_tag; // Initiator task tag
    uint32_t target_xfer_tag; // Target transfer tag or 0xFFFFFFFF
    uint32_t reserved2; // Reserved for future usage
    uint32_t exp_stat_sn; // ExpStatSN
    uint32_t reserved3; // Reserved for future usage
    uint32_t data_sn; // DataSN
    uint32_t buf_offset; // Buffer offset
    uint32_t reserved4; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_scsi_data_out_req_packet;

#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS        (1 << 0) // (S) set to indicate that the Command Status field
                                                                 // contains status. If this bit is set to 1, the
                                                                 // F bit MUST also be set to 1

#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_UNDERFLOW (1 << 1) // (U) set for Residual Underflow. In this case, the Residual
                                                                 // Count indicates the number of bytes that were not
                                                                 // transferred out of the number of bytes that were expected
                                                                 // to be transferred. For a bidirectional operation, the
                                                                 // Residual Count contains the residual for the write
                                                                 // operation.

#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_OVERFLOW  (1 << 2) // (O) set for Residual Overflow. In this case, the Residual
                                                                 // Count indicates the number of bytes that were not
                                                                 // transferred because the initiator's Expected Data
                                                                 // Transfer Length was not sufficient. For a bidirectional
                                                                 // operation, the Residual Count contains the residual for
                                                                 // the write operation.

#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_ACK           (1 << 6) // (A) for sessions with ErrorRecoveryLevel=1 or higher, the target sets
                                                                 // this bit to 1 to indicate that it requests a positive acknowledgment
                                                                 // from the initiator for the data received. The target should use the
                                                                 // A bit moderately; it MAY only set the A bit to 1 once every
                                                                 // MaxBurstLength bytes, or on the last Data-In PDU that concludes the
                                                                 // entire requested read data transfer for the task from the target's
                                                                 // perspective, and it MUST NOT do so more frequently. The target MUST
                                                                 // NOT set to 1 the A bit for sessions with ErrorRecoveryLevel=0. The
                                                                 // initiator MUST ignore the A bit set to 1 for sessions with
                                                                 // ErrorRecoveryLevel=0.
                                                                 // On receiving a Data-In PDU with the A bit set to 1 on a session with
                                                                 // ErrorRecoveryLevel greater than 0, if there are no holes in the read
                                                                 // data until that Data-In PDU, the initiator MUST issue a SNACK of type
                                                                 // DataACK, except when it is able to acknowledge the status for the
                                                                 // task immediately via the ExpStatSN on other outbound PDUs if the
                                                                 // status for the task is also received. In the latter case
                                                                 // (acknowledgment through the ExpStatSN), sending a SNACK of type
                                                                 // DataACK in response to the A bit is OPTIONAL, but if it is done, it
                                                                 // must not be sent after the status acknowledgment through the
                                                                 // ExpStatSN. If the initiator has detected holes in the read data
                                                                 // prior to that Data-In PDU, it MUST postpone issuing the SNACK of type
                                                                 // DataACK until the holes are filled. An initiator also MUST NOT
                                                                 // acknowledge the status for the task before those holes are filled. A
                                                                 // status acknowledgment for a task that generated the Data-In PDUs is
                                                                 // considered by the target as an implicit acknowledgment of the Data-In
                                                                 // PDUs if such an acknowledgment was requested by the target

#define ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL         (1 << 7) // (F) for outgoing data, this bit is 1 for the last PDU of unsolicited
                                                                 // data or the last PDU of a sequence that answers an R2T.
                                                                 // For incoming data, this bit is 1 for the last input (read) data PDU
                                                                 // of a sequence. Input can be split into several sequences, each
                                                                 // having its own F bit. Splitting the data stream into sequences does
                                                                 // not affect DataSN counting on Data-In PDUs. It MAY be used as a
                                                                 // "change direction" indication for bidirectional operations that need
                                                                 // such a change.
                                                                 // DataSegmentLength MUST NOT exceed MaxRecvDataSegmentLength for the
                                                                 // direction it is sent, and the total of all the DataSegmentLength of
                                                                 // all PDUs in a sequence MUST NOT exceed MaxBurstLength (or
                                                                 // FirstBurstLength for unsolicited data). However, the number of
                                                                 // individual PDUs in a sequence (or in total) may be higher than the
                                                                 // ratio of MaxBurstLength (or FirstBurstLength) to
                                                                 // MaxRecvDataSegmentLength (as PDUs may be limited in length by the
                                                                 // capabilities of the sender). Using a DataSegmentLength of 0 may
                                                                 // increase beyond what is reasonable for the number of PDUs and should
                                                                 // therefore be avoided.
                                                                 // For bidirectional operations, the F bit is 1 for both the end of the
                                                                 // input sequences and the end of the output sequences

typedef struct __attribute__((packed)) iscsi_scsi_data_in_response_packet {
    uint8_t opcode; // Always 0x25 according to specification (see above)
    int8_t flags; // Incoming data flags (see above)
                  // The fields StatSN, Status, and Residual Count only have meaningful
                  // content if the S bit is set to 1
    uint8_t reserved; // Rserved for future usage
    uint8_t status; // Status or Reserved
                    // Status can accompany the last Data-In PDU if the command did not end
                    // with an exception (i.e., the status is "good status" - GOOD,
                    // CONDITION MET, or INTERMEDIATE-CONDITION MET). The presence of
                    // status (and of a residual count) is signaled via the S flag bit.
                    // Although targets MAY choose to send even non-exception status in
                    // separate responses, initiators MUST support non-exception status in
                    // Data-In PDUs
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
                       // This is the data payload length of a SCSI Data-In or SCSI Data-Out
                       // PDU. The sending of 0-length data segments should be avoided, but
                       // initiators and targets MUST be able to properly receive 0-length data
                       // segments.
                       // The data segments of Data-In and Data-Out PDUs SHOULD be filled to
                       // the integer number of 4-byte words (real payload), unless the F bit
                       // is set to 1
    uint64_t lun; // Logical Unit Number (LUN) or Reserved
                  // If the Target Transfer Tag isprovided, then the LUN field MUST hold a
                  // valid value and be consistent with whatever was specified with the command;
                  // otherwise, the LUN field is reserved
    uint32_t init_task_tag; // Initiator task tag
    uint32_t target_xfer_tag; // On outgoing data, the Target Transfer Tag is provided to the target
                              // if the transfer is honoring an R2T. In this case, the Target
                              // Transfer Tag field is a replica of the Target Transfer Tag provided
                              // with the R2T.
                              // On incoming data, the Target Transfer Tag and LUN MUST be provided by
                              // the target if the A bit is set to 1; otherwise, they are reserved.
                              // The Target Transfer Tag and LUN are copied by the initiator into the
                              // SNACK of type DataACK that it issues as a result of receiving a SCSI
                              // Data-In PDU with the A bit set to 1.
                              // The Target Transfer Tag values are not specified by this protocol,
                              // except that the value 0xFFFFFFFF is reserved and means that the
                              // Target Transfer Tag is not supplied
    uint32_t stat_sn; // StatSN
    uint32_t exp_cmd_sn; // ExpCmdSN
    uint32_t max_cmd_sn; // MaxCmdSN
    uint32_t data_sn; // DataSN
                      // For input (read) or bidirectional Data-In PDUs, the DataSN is the
                      // input PDU number within the data transfer for the command identified
                      // by the Initiator Task Tag.
                      // R2T and Data-In PDUs, in the context of bidirectional commands, share
                      // the numbering sequence.
                      // For output (write) data PDUs, the DataSN is the Data-Out PDU number
                      // within the current output sequence. Either the current output
                      // sequence is identified by the Initiator Task Tag (for unsolicited
                      // data) or it is a data sequence generated for one R2T (for data
                      // solicited through R2T)
    uint32_t buf_offset; // Buffer Offset
                         // The Buffer Offset field contains the offset of this PDU payload data
                         // within the complete data transfer. The sum of the buffer offset and
                         // length should not exceed the expected transfer length for the
                         // command.
                         // The order of data PDUs within a sequence is determined by
                         // DataPDUInOrder. When set to Yes, it means that PDUs have to be in
                         // increasing buffer offset order and overlays are forbidden.
                         // The ordering between sequences is determined by DataSequenceInOrder.
                         // When set to Yes, it means that sequences have to be in increasing
                         // buffer offset order and overlays are forbidden
    uint32_t res_cnt; // Residual Count or Reserved
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_ds_cmd_data ds_cmd_data; // Data segment
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_scsi_data_in_response_packet;

/* When an initiator has submitted a SCSI command with data that passes
   from the initiator to the target (write), the target may specify
   which blocks of data it is ready to receive. The target may request
   that the data blocks be delivered in whichever order is convenient
   for the target at that particular instant. This information is
   passed from the target to the initiator in the Ready To Transfer
   (R2T) PDU.

   In order to allow write operations without an explicit initial R2T,
   the initiator and target MUST have negotiated the key InitialR2T to
   No during login.

   An R2T MAY be answered with one or more SCSI Data-Out PDUs with a
   matching Target Transfer Tag. If an R2T is answered with a single
   Data-Out PDU, the buffer offset in the data PDU MUST be the same as
   the one specified by the R2T, and the data length of the data PDU
   MUST be the same as the Desired Data Transfer Length specified in the
   R2T. If the R2T is answered with a sequence of data PDUs, the buffer
   offset and length MUST be within the range of those specified by the
   R2T, and the last PDU MUST have the F bit set to 1. If the last PDU
   (marked with the F bit) is received before the Desired Data Transfer
   Length is transferred, a target MAY choose to reject that PDU with
   the "Protocol Error" reason code. DataPDUInOrder governs the
   Data-Out PDU ordering. If DataPDUInOrder is set to Yes, the buffer
   offsets and lengths for consecutive PDUs MUST form a continuous
   non-overlapping range, and the PDUs MUST be sent in increasing offset
   order.

   The target may send several R2T PDUs. It therefore can have a number
   of pending data transfers. The number of outstanding R2T PDUs is
   limited by the value of the negotiated key MaxOutstandingR2T. Within
   a task, outstanding R2Ts MUST be fulfilled by the initiator in the
   order in which they were received.

   R2T PDUs MAY also be used to recover Data-Out PDUs. Such an R2T
   (Recovery-R2T) is generated by a target upon detecting the loss of
   one or more Data-Out PDUs due to:

      - Digest error

      - Sequence error

      - Sequence reception timeout

   A Recovery-R2T carries the next unused R2TSN but requests part of or
   the entire data burst that an earlier R2T (with a lower R2TSN) had
   already requested.

   DataSequenceInOrder governs the buffer offset ordering in consecutive
   R2Ts. If DataSequenceInOrder is Yes, then consecutive R2Ts MUST
   refer to continuous non-overlapping ranges, except for Recovery-R2Ts.
*/
typedef struct __attribute__((packed)) iscsi_r2t_packet {
    uint8_t opcode; // Always 0x31 according to specification (see above)
    uint8_t flags; // Reserved for future usage
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength, MUST be 0 for this PDU
    uint8_t ds_len[3]; // DataSegmentLength, MUST be 0 0 for this PDU
    uint64_t lun; // Logical Unit Number (LUN) or Reserved
    uint32_t init_task_tag; // Initiator task tag
    uint32_t target_xfer_tag; // Target transfer tag
    uint32_t stat_sn; // The StatSN field will contain the next StatSN. The StatSN for this
                      // connection is not advanced after this PDU is sent
    uint32_t exp_cmd_sn; // ExpCmdSN
    uint32_t max_cmd_sn; // MaxCmdSN
    uint32_t data_sn; // DataSN
    uint32_t r2t_sn; // R2TSN is the R2T PDU input PDU number within the command identified
                     // by the Initiator Task Tag.
                     // For bidirectional commands, R2T and Data-In PDUs share the input PDU
                     // numbering sequence
    uint32_t buf_offset; // Buffer Offset
                         // The target therefore also specifies a buffer offset that
                         // indicates the point at which the data transfer should begin, relative
                         // to the beginning of the total data transfer
    uint32_t des_data_xfer_len; // Desired Data Transfer Length
                                // The target specifies how many bytes it wants the initiator to send
                                // because of this R2T PDU. The target may request the data from the
                                // initiator in several chunks, not necessarily in the original order of
                                // the data. The Desired Data Transfer Length MUST NOT be 0 and MUST NOT
                                // exceed MaxBurstLength
    struct iscsi_header_digest hdr_digest; // Optional header digest
} iscsi_r2t_packet;

#define ISCSI_ASYNC_MSG_EVENT_SCSI_ASYNC_EVENT    0x00 // (SCSI Async Event) - a SCSI asynchronous event is reported in
                                                       // the sense data. Sense Data that accompanies the report, in
                                                       // the data segment, identifies the condition. The sending of a
                                                       // SCSI event ("asynchronous event reporting" in SCSI
                                                       // terminology) is dependent on the target support for SCSI
                                                       // asynchronous event reporting as indicated in the
                                                       // standard INQUIRY data. Its use may be enabled by
                                                       // parameters in the SCSI Control mode page
#define ISCSI_ASYNC_MSG_EVENT_LOGOUT_REQUEST      0x01 // (Logout Request) - the target requests Logout. This Async
                                                       // Message MUST be sent on the same connection as the one
                                                       // requesting to be logged out. The initiator MUST honor this
                                                       // request by issuing a Logout as early as possible but no later
                                                       // than Parameter3 seconds. The initiator MUST send a Logout
                                                       // with a reason code of "close the connection" OR "close the
                                                       // session" to close all the connections. Once this message is
                                                       // received, the initiator SHOULD NOT issue new iSCSI commands on
                                                       // the connection to be logged out. The target MAY reject any
                                                       // new I/O requests that it receives after this message with the
                                                       // reason code "Waiting for Logout". If the initiator does not
                                                       // log out in Parameter3 seconds, the target should send an Async
                                                       // PDU with iSCSI event code "Dropped the connection" if possible
                                                       // or simply terminate the transport connection. Parameter1 and
                                                       // Parameter2 are reserved
#define ISCSI_ASYNC_MSG_EVENT_CONNECT_DROP_NOTIFY 0x02 // (Connection Drop Notification) - the target indicates that it
                                                       // will drop the connection.
                                                       // The Parameter1 field indicates the CID of the connection that
                                                       // is going to be dropped.
                                                       // The Parameter2 field (Time2Wait) indicates, in seconds, the
                                                       // minimum time to wait before attempting to reconnect or
                                                       // reassign.
                                                       // The Parameter3 field (Time2Retain) indicates the maximum time
                                                       // allowed to reassign commands after the initial wait (in
                                                       // Parameter2).
                                                       // If the initiator does not attempt to reconnect and/or reassign
                                                       // the outstanding commands within the time specified by
                                                       // Parameter3, or if Parameter3 is 0, the target will terminate
                                                       // all outstanding commands on this connection. In this case, no
                                                       // other responses should be expected from the target for the
                                                       // outstanding commands on this connection.
                                                       // A value of 0 for Parameter2 indicates that reconnect can be
                                                       // attempted immediately
#define ISCSI_ASYNC_MSG_EVENT_SESSION_DROP_NOTIFY 0x03 // (Session Drop Notification) - the target indicates that it
                                                       // will drop all the connections of this session.
                                                       // The Parameter1 field is reserved.
                                                       // The Parameter2 field (Time2Wait) indicates, in seconds, the
                                                       // minimum time to wait before attempting to reconnect.
                                                       // The Parameter3 field (Time2Retain) indicates the maximum time
                                                       // allowed to reassign commands after the initial wait (in
                                                       // Parameter2).
                                                       // If the initiator does not attempt to reconnect and/or reassign
                                                       // the outstanding commands within the time specified by
                                                       // Parameter3, or if Parameter3 is 0, the session is terminated.
                                                       // In this case, the target will terminate all outstanding
                                                       // commands in this session; no other responses should be
                                                       // expected from the target for the outstanding commands in this
                                                       // session. A value of 0 for Parameter2 indicates that reconnect
                                                       // can be attempted immediately
#define ISCSI_ASYNC_MSG_EVENT_NEGOTIATION_REQUEST 0x04 // (Negotiation Request) - the target requests parameter
                                                       // negotiation on this connection. The initiator MUST honor this
                                                       // request by issuing a Text Request (that can be empty) on the
                                                       // same connection as early as possible, but no later than
                                                       // Parameter3 seconds, unless a Text Request is already pending
                                                       // on the connection, or by issuing a Logout Request. If the
                                                       // initiator does not issue a Text Request, the target may
                                                       // reissue the Asynchronous Message requesting parameter
                                                       // negotiation
#define ISCSI_ASYNC_MSG_EVENT_TASK_TERMINATION    0x05 // (Task Termination) - all active tasks for a LU with a matching
                                                       // LUN field in the Async Message PDU are being terminated. The
                                                       // receiving initiator iSCSI layer MUST respond to this message
                                                       // by taking the following steps, in order:
                                                       // - Stop Data-Out transfers on that connection for all active
                                                       //   TTTs for the affected LUN quoted in the Async Message PDU.
                                                       // - Acknowledge the StatSN of the Async Message PDU via a
                                                       //   NOP-Out PDU with ITT=0xFFFFFFFF (i.e., non-ping flavor),
                                                       //   while copying the LUN field from the Async Message to
                                                       //   NOP-Out.
                                                       // This value of AsyncEvent, however, MUST NOT be used on an
                                                       // iSCSI session unless the new TaskReporting text key was
                                                       // negotiated to FastAbort on the session
#define ISCSI_ASYNC_MSG_EVENT_VENDOR_FIRST        0xF8 // First vendor-specific iSCSI event. The AsyncVCode details the
                                                       // vendor code, and data MAY accompany the report
#define ISCSI_ASYNC_MSG_EVENT_VENDOR_LAST         0xFF // Last vendor-specific iSCSI event. The AsyncVCode details the
                                                       // vendor code, and data MAY accompany the report

/* An Asynchronous Message may be sent from the target to the initiator
   without corresponding to a particular command. The target specifies
   the reason for the event and sense data.
   Some Asynchronous Messages are strictly related to iSCSI, while
   others are related to SCSI
*/
typedef struct __attribute__((packed)) iscsi_async_msg_packet {
    uint8_t opcode; // Always 0x32 according to specification (see above
    uint8_t flags; // Reserved for future usage
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength, MUST be 0 for this PDU
    uint8_t ds_len[3]; // DataSegmentLength, MUST be 0 0 for this PDU
    uint64_t lun; // The LUN field MUST be valid if AsyncEvent is 0. Otherwise, this
                  // field is reserved
    uint32_t tag; // Tag (always 0xFFFFFFFF for now)
    uint32_t reserved2; // Reserved for future usage
    uint32_t stat_sn; // StatSN
                      // The StatSN counts this PDU as an acknowledgeable event (the StatSN is
                      // advanced), which allows for initiator and target state synchronization.
    uint32_t exp_cmd_sn; // ExpCmdSN
    uint32_t max_cmd_sn; // MaxCmdSN
    uint8_t async_event; // AsyncEvent
    uint8_t async_vcode; // AsyncVCode is a vendor-specific detail code that is only valid if the
                         // AsyncEvent field indicates a vendor-specific event. Otherwise, it is
                         // reserved
    uint16_t param_1; // Parameter1 or Reserved
    uint16_t param_2; // Parameter2 or Reserved
    uint16_t param_3; // Parameter3 or Reserved
    uint32_t reserved3; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_ds_cmd_data ds_cmd_data; // Data segment
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_async_msg_packet;

/* For a SCSI event, this data accompanies the report in the data
   segment and identifies the condition.

   For an iSCSI event, additional vendor-unique data MAY accompany the
   Async event. Initiators MAY ignore the data when not understood,
   while processing the rest of the PDU.

   If the DataSegmentLength is not 0, the format of the DataSegment is
   as follows:
*/
typedef struct __attribute__((packed)) iscsi_sense_event_data_packet {
    uint16_t sense_len; // SenseLength
                        // This is the length of Sense Data. When the Sense Data field is empty
                        // (e.g., the event is not a SCSI event), SenseLength is 0
    uint16_t sense_data[0]; // Sense Data
    uint16_t event_data[0]; // iSCSI Event Data
} iscsi_sense_event_data_packet;

#define ISCSI_TEXT_REQ_FLAGS_CONTINUE (1 << 6) // (C) When set to 1, this bit indicates that the text (set of key=value
                                               // pairs) in this Text Request is not complete (it will be continued on
                                               // subsequent Text Requests); otherwise, it indicates that this Text
                                               // Request ends a set of key=value pairs. A Text Request with the C bit
                                               // set to 1 MUST have the F bit set to 0.
#define ISCSI_TEXT_REQ_FLAGS_FINAL    (1 << 7) // (F) When set to 1, this bit indicates that this is the last or only Text
                                               // Request in a sequence of Text Requests; otherwise, it indicates that
                                               // more Text Requests will follow.

/* The Text Request is provided to allow for the exchange of information
   and for future extensions. It permits the initiator to inform a
   target of its capabilities or request some special operations.

   An initiator MUST NOT have more than one outstanding Text Request on
   a connection at any given time.

   On a connection failure, an initiator must either explicitly abort
   any active allegiant text negotiation task or cause such a task to be
   implicitly terminated by the target.
*/
typedef struct __attribute__((packed)) iscsi_text_req_packet {
    uint8_t opcode; // Always 0x04 according to specification (see above)
    int8_t flags; // Text request flags (see above)
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
    uint64_t lun; // Logical Unit Number (LUN) or Reserved
    uint32_t init_task_tag; // This is the initiator-assigned identifier for this Text Request. If
                            // the command is sent as part of a sequence of Text Requests and
                            // responses, the Initiator Task Tag MUST be the same for all the
                            // requests within the sequence (similar to linked SCSI commands). The
                            // I bit for all requests in a sequence also MUST be the same
    uint32_t target_xfer_tag; // When the Target Transfer Tag is set to the reserved value 0xFFFFFFFF,
                              // it tells the target that this is a new request, and the target resets
                              // any internal state associated with the Initiator Task Tag (resets the
                              // current negotiation state).
                              // The target sets the Target Transfer Tag in a Text Response to a value
                              // other than the reserved value 0xFFFFFFFF whenever it indicates that
                              // it has more data to send or more operations to perform that are
                              // associated with the specified Initiator Task Tag. It MUST do so
                              // whenever it sets the F bit to 0 in the response. By copying the
                              // Target Transfer Tag from the response to the next Text Request, the
                              // initiator tells the target to continue the operation for the specific
                              // Initiator Task Tag. The initiator MUST ignore the Target Transfer
                              // Tag in the Text Response when the F bit is set to 1.
                              // This mechanism allows the initiator and target to transfer a large
                              // amount of textual data over a sequence of text-command/text-response
                              // exchanges or to perform extended negotiation sequences.
                              // If the Target Transfer Tag is not 0xFFFFFFFF, the LUN field MUST be
                              // sent by the target in the Text Response.
                              // A target MAY reset its internal negotiation state if an exchange is
                              // stalled by the initiator for a long time or if it is running out of
                              // resources.
                              // Long Text Responses are handled as shown in the following example:
                              //    I->T Text SendTargets=All (F = 1, TTT = 0xFFFFFFFF)
                              //    T->I Text <part 1> (F = 0, TTT = 0x12345678)
                              //    I->T Text <empty> (F = 1, TTT = 0x12345678)
                              //    T->I Text <part 2> (F = 0, TTT = 0x12345678)
                              //    I->T Text <empty> (F = 1, TTT = 0x12345678)
                              //    ...
                              //    T->I Text <part n> (F = 1, TTT = 0xFFFFFFFF)
    uint32_t cmd_sn; // CmdSN
    uint32_t exp_stat_sn; // ExpStatSN
    uint64_t reserved2[2]; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_ds_cmd_data ds_cmd_data; // Data segment
                                          // The data lengths of a Text Request MUST NOT exceed the iSCSI target
                                          // MaxRecvDataSegmentLength (a parameter that is negotiated per
                                          // connection and per direction).
                                          // A key=value pair can span Text Request or Text Response boundaries.
                                          // A key=value pair can start in one PDU and continue on the next. In
                                          // other words, the end of a PDU does not necessarily signal the end of
                                          // a key=value pair.
                                          // The target responds by sending its response back to the initiator.
                                          // The response text format is similar to the request text format. The
                                          // Text Response MAY refer to key=value pairs presented in an earlier
                                          // Text Request, and the text in the request may refer to earlier
                                          // responses.
                                          // Text operations are usually meant for parameter setting/negotiations
                                          // but can also be used to perform some long-lasting operations
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_text_req_packet;

#define ISCSI_TEXT_RESPONSE_FLAGS_CONTINUE (1 << 6) // (C) When set to 1, this bit indicates that the text (set of key=value
                                                    // pairs) in this Text Response is not complete (it will be continued on
                                                    // subsequent Text Responses); otherwise, it indicates that this Text
                                                    // Response ends a set of key=value pairs. A Text Response with the
                                                    // C bit set to 1 MUST have the F bit set to 0
#define ISCSI_TEXT_RESPONSE_FLAGS_FINAL    (1 << 7) // (F) When set to 1, in response to a Text Request with the Final bit set
                                                    // to 1, the F bit indicates that the target has finished the whole
                                                    // operation. Otherwise, if set to 0 in response to a Text Request with
                                                    // the Final Bit set to 1, it indicates that the target has more work to
                                                    // do (invites a follow-on Text Request). A Text Response with the
                                                    // F bit set to 1 in response to a Text Request with the F bit set to 0
                                                    // is a protocol error.
                                                    // A Text Response with the F bit set to 1 MUST NOT contain key=value
                                                    // pairs that may require additional answers from the initiator.
                                                    // A Text Response with the F bit set to 1 MUST have a Target Transfer
                                                    // Tag field set to the reserved value 0xFFFFFFFF.
                                                    // A Text Response with the F bit set to 0 MUST have a Target Transfer
                                                    // Tag field set to a value other than the reserved value 0xFFFFFFFF

/* The Text Response PDU contains the target's responses to the
   initiator's Text Request. The format of the Text field matches that
   of the Text Request.
*/
typedef struct __attribute__((packed)) iscsi_text_response_packet {
    uint8_t opcode; // Always 0x24 according to specification (see above)
    int8_t flags; // Text response flags (see above)
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
    uint64_t lun; // Logical Unit Number (LUN) or Reserved
    uint32_t init_task_tag; // The Initiator Task Tag matches the tag used in the initial Text Request
    uint32_t target_xfer_tag; // When a target has more work to do (e.g., cannot transfer all the
                              // remaining text data in a single Text Response or has to continue the
                              // negotiation) and has enough resources to proceed, it MUST set the
                              // Target Transfer Tag to a value other than the reserved value
                              // 0xFFFFFFFF. Otherwise, the Target Transfer Tag MUST be set to
                              // 0xFFFFFFFF.
                              // When the Target Transfer Tag is not 0xFFFFFFFF, the LUN field may be
                              // significant.
                              // The initiator MUST copy the Target Transfer Tag and LUN in its next
                              // request to indicate that it wants the rest of the data.
                              // When the target receives a Text Request with the Target Transfer Tag
                              // set to the reserved value 0xFFFFFFFF, it resets its internal
                              // information (resets state) associated with the given Initiator Task
                              // Tag (restarts the negotiation).
                              // When a target cannot finish the operation in a single Text Response
                              // and does not have enough resources to continue, it rejects the Text
                              // Request with the appropriate Reject code.
                              // A target may reset its internal state associated with an Initiator
                              // Task Tag (the current negotiation state) as expressed through the
                              // Target Transfer Tag if the initiator fails to continue the exchange
                              // for some time. The target may reject subsequent Text Requests with
                              // the Target Transfer Tag set to the "stale" value
    uint32_t stat_sn; // StatSN. The target StatSN variable is advanced by each Text Response sent
    uint32_t exp_cmd_sn; // ExpCmdSN
    uint32_t max_cmd_sn; // MaxCmdSN
    uint64_t reserved2[2]; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_ds_cmd_data ds_cmd_data; // Data segment
                                          // The data lengths of a Text Response MUST NOT exceed the iSCSI
                                          // initiator MaxRecvDataSegmentLength (a parameter that is negotiated
                                          // per connection and per direction).
                                          // The text in the Text Response Data is governed by the same rules as
                                          // the text in the Text Request Data.
                                          // Although the initiator is the requesting party and controls the
                                          // request-response initiation and termination, the target can offer
                                          // key=value pairs of its own as part of a sequence and not only in
                                          // response to the initiator
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_text_response_packet;

#define ISCSI_ISID_TYPE_BITS (1 << 6) // Two bits - The T field identifies the format and usage of A, B, C, and D as
                                      // indicated below:
#define ISCSI_ISID_TYPE_FORMAT_OUI    0x0 // OUI-Format
                                          // A and B: 22-bit OUI
                                          // (the I/G and U/L bits are omitted)
                                          // C and D: 24-bit Qualifier
#define ISCSI_ISID_TYPE_FORMAT_EN     0x1 // EN: Format (IANA Enterprise Number)
                                          // A: Reserved
                                          // B and C: EN (IANA Enterprise Number)
                                          // D: Qualifier
#define ISCSI_ISID_TYPE_FORMAT_RANDOM 0x2 // Random
                                          // A: Reserved
                                          // B and C: Random
                                          // D: Qualifier

/* Only the following keys are used during the SecurityNegotiation stage
   of the Login Phase (other keys MUST NOT be used):
*/
#define ISCSI_LOGIN_AUTH_TEXT_KEY_SESSION_TYPE            "SessionType" // Use: LO, Declarative, Any-Stage
                                                                        // Senders: Initiator
                                                                        // Scope: SW
                                                                        // SessionType=<Discovery|Normal>
                                                                        // Default is Normal.
                                                                        // The initiator indicates the type of session it wants to create. The
                                                                        // target can either accept it or reject it.
                                                                        // A Discovery session indicates to the target that the only purpose of
                                                                        // this session is discovery. The only requests a target accepts in
                                                                        // this type of session are a Text Request with a SendTargets key and a
                                                                        // Logout Request with reason "close the session".
                                                                        // The Discovery session implies MaxConnections = 1 and overrides both
                                                                        // the default and an explicit setting. ErrorRecoveryLevel MUST be 0
                                                                        // (zero) for Discovery sessions.
                                                                        // Depending on the type of session, a target may decide on resources to
                                                                        // allocate, the security to enforce, etc., for the session. If the
                                                                        // SessionType key is thus going to be offered as "Discovery", it SHOULD
                                                                        // be offered in the initial Login Request by the initiator
#define ISCSI_LOGIN_AUTH_TEXT_KEY_INITIATOR_NAME          "InitiatorName" // Use: IO, Declarative, Any-Stage
                                                                          // Senders: Initiator
                                                                          // Scope: SW
                                                                          // InitiatorName=<iSCSI-name-value>
                                                                          // Examples:
                                                                          //    InitiatorName=iqn.1992-04.de.uni-freiburg.bwlehrpool:qcow2.5003
                                                                          //    InitiatorName=iqn.2001-02.de.uni-freiburg.matrix:basty.eduroam
                                                                          //    InitiatorName=naa.52004567BA64678D
                                                                          // The initiator of the TCP connection MUST provide this key to the
                                                                          // remote endpoint at the first login of the Login Phase for every
                                                                          // connection. The InitiatorName key enables the initiator to identify
                                                                          // itself to the remote endpoint.
                                                                          // The InitiatorName MUST NOT be redeclared within the Login Phase
#define ISCSI_LOGIN_AUTH_TEXT_KEY_TARGET_NAME             "TargetName" // Use: IO by initiator, FFPO by target - only as response to a
                                                                       // SendTargets, Declarative, Any-Stage
                                                                       // Senders: Initiator and target
                                                                       // Scope: SW
                                                                       // TargetName=<iSCSI-name-value>
                                                                       // Examples:
                                                                       //    TargetName=iqn.1993-11.de.uni-freiburg:diskarrays.sn.5003
                                                                       //    TargetName=eui.020000023B040506
                                                                       //    TargetName=naa.62004567BA64678D0123456789ABCDEF
                                                                       // The initiator of the TCP connection MUST provide this key to the
                                                                       // remote endpoint in the first Login Request if the initiator is not
                                                                       // establishing a Discovery session. The iSCSI Target Name specifies
                                                                       // the worldwide unique name of the target.
                                                                       // The TargetName key may also be returned by the SendTargets Text
                                                                       // Request (which is its only use when issued by a target).
                                                                       // The TargetName MUST NOT be redeclared within the Login Phase
#define ISCSI_LOGIN_AUTH_TEXT_KEY_TARGET_ADDRESS          "TargetAddress" // Use: ALL, Declarative, Any-Stage
                                                                          // Senders: Target
                                                                          // Scope: SW
                                                                          // TargetAddress=domainname[:port][,portal-group-tag]
                                                                          // The domainname can be specified as either a DNS host name, a dotted-
                                                                          // decimal IPv4 address, or a bracketed IPv6 address as specified in
                                                                          // RFC3986.
                                                                          // If the TCP port is not specified, it is assumed to be the IANA-
                                                                          // assigned default port for iSCSI.
                                                                          // If the TargetAddress is returned as the result of a redirect status
                                                                          // in a Login Response, the comma and portal-group-tag MUST be omitted.
                                                                          // If the TargetAddress is returned within a SendTargets response, the
                                                                          // portal-group-tag MUST be included.
                                                                          // Examples:
                                                                          //    TargetAddress=10.0.0.1:5003,1
                                                                          //    TargetAddress=[1080:0:0:0:8:800:200C:417A],65
                                                                          //    TargetAddress=[1080::8:800:200C:417A]:5003,1
                                                                          //    TargetAddress=gitlab.uni-freiburg.de,443
                                                                          // The formats for the port and portal-group-tag are the same as the one
                                                                          // specified in TargetPortalGroupTag
#define ISCSI_LOGIN_AUTH_TEXT_KEY_INITIATOR_ALIAS         "InitiatorAlias" // Use: ALL, Declarative, Any-Stage
                                                                           // Senders: Initiator
                                                                           // Scope: SW
                                                                           // InitiatorAlias=<iSCSI-local-name-value>
                                                                           // Examples:
                                                                           //    InitiatorAlias=Web Server 5
                                                                           //    InitiatorAlias=matrix.uni-freiburg.de
                                                                           //    InitiatorAlias=Matrix Server
                                                                           // If an initiator has been configured with a human-readable name or
                                                                           // description, it SHOULD be communicated to the target during a Login
                                                                           // Request PDU. If not, the host name can be used instead. This string
                                                                           // is not used as an identifier, nor is it meant to be used for
                                                                           // authentication or authorization decisions. It can be displayed by
                                                                           // the target's user interface in a list of initiators to which it is
                                                                           // connected
#define ISCSI_LOGIN_AUTH_TEXT_KEY_TARGET_ALIAS            "TargetAlias" // Use: ALL, Declarative, Any-Stage
                                                                        // Senders: Target
                                                                        // Scope: SW
                                                                        // TargetAlias=<iSCSI-local-name-value>
                                                                        // Examples:
                                                                        //    TargetAlias=Bob-s Disk
                                                                        //    TargetAlias=Database Server 1 Log Disk
                                                                        //    TargetAlias=Web Server 3 Disk 20
                                                                        // If a target has been configured with a human-readable name or
                                                                        // description, this name SHOULD be communicated to the initiator during
                                                                        // a Login Response PDU if SessionType=Normal. This string is not used
                                                                        // as an identifier, nor is it meant to be used for authentication or
                                                                        // authorization decisions. It can be displayed by the initiator's user
                                                                        // interface in a list of targets to which it is connected
#define ISCSI_LOGIN_AUTH_TEXT_KEY_TARGET_PORTAL_GROUP_TAG "TargetPortalGroupTag" // Use: IO by target, Declarative, Any-Stage
                                                                                 // Senders: Target
                                                                                 // Scope: SW
                                                                                 // TargetPortalGroupTag=<16-bit-binary-value>
                                                                                 // Example:
                                                                                 //    TargetPortalGroupTag=1
                                                                                 // The TargetPortalGroupTag key is a 16-bit binary-value that uniquely
                                                                                 // identifies a portal group within an iSCSI target node. This key
                                                                                 // carries the value of the tag of the portal group that is servicing
                                                                                 // the Login Request. The iSCSI target returns this key to the
                                                                                 // initiator in the Login Response PDU to the first Login Request PDU
                                                                                 // that has the C bit set to 0 when TargetName is given by the
                                                                                 // initiator.
                                                                                 // SAM2 notes in its informative text that the TPGT value should be
                                                                                 // non-zero; note that this is incorrect. A zero value is allowed as a
                                                                                 // legal value for the TPGT. This discrepancy currently stands
                                                                                 // corrected in SAM4
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD             "AuthMethod" // Use: During Login - Security Negotiation
                                                                       // Senders: Initiator and target
                                                                       // Scope: connection
                                                                       // AuthMethod = <list-of-values>
                                                                       // The main item of security negotiation is the authentication method
                                                                       // (AuthMethod).
                                                                       // The authentication methods that can be used (appear in the list-of-
                                                                       // values) are either vendor-unique methods or those listed in the
                                                                       // following table:
                                                                       // +--------------------------------------------------------------+
                                                                       // | Name         | Description                                   |
                                                                       // +--------------------------------------------------------------+
                                                                       // | KRB5         | Kerberos V5 - defined in RFC4120              |
                                                                       // +--------------------------------------------------------------+
                                                                       // | SRP          | Secure Remote Password -                      |
                                                                       // |              | defined in RFC2945                            |
                                                                       // +--------------------------------------------------------------+
                                                                       // | CHAP         | Challenge Handshake Authentication Protocol - |
                                                                       // |              | defined in RFC1994                            |
                                                                       // +--------------------------------------------------------------+
                                                                       // | None         | No authentication                             |
                                                                       // +--------------------------------------------------------------+
                                                                       // The AuthMethod selection is followed by an "authentication exchange"
                                                                       // specific to the authentication method selected.
                                                                       // The authentication method proposal may be made by either the
                                                                       // initiator or the target. However, the initiator MUST make the first
                                                                       // step specific to the selected authentication method as soon as it is
                                                                       // selected. It follows that if the target makes the authentication
                                                                       // method proposal, the initiator sends the first key(s) of the exchange
                                                                       // together with its authentication method selection.
                                                                       // The authentication exchange authenticates the initiator to the target
                                                                       // and, optionally, the target to the initiator. Authentication is
                                                                       // OPTIONAL to use but MUST be supported by the target and initiator.
                                                                       // The initiator and target MUST implement CHAP. All other
                                                                       // authentication methods are OPTIONAL.
                                                                       // Private or public extension algorithms MAY also be negotiated for
                                                                       // authentication methods. Whenever a private or public extension
                                                                       // algorithm is part of the default offer (the offer made in the absence
                                                                       // of explicit administrative action), the implementer MUST ensure that
                                                                       // CHAP is listed as an alternative in the default offer and "None" is
                                                                       // not part of the default offer.
                                                                       // Extension authentication methods MUST be named using one of the
                                                                       // following two formats:
                                                                       //    1) Z-reversed.vendor.dns_name.do_something=
                                                                       //    2) New public key with no name prefix constraints
                                                                       // Authentication methods named using the Z- format are used as private
                                                                       // extensions. New public keys must be registered with IANA using the
                                                                       // IETF Review process RFC5226. New public extensions for
                                                                       // authentication methods MUST NOT use the Z# name prefix.
                                                                       // For all of the public or private extension authentication methods,
                                                                       // the method-specific keys MUST conform to the format specified for
                                                                       // standard-label.
                                                                       // To identify the vendor for private extension authentication methods,
                                                                       // we suggest using the reversed DNS-name as a prefix to the proper
                                                                       // digest names.
                                                                       // The part of digest-name following Z- MUST conform to the format for
                                                                       // standard-label.
                                                                       // Support for public or private extension authentication methods is
                                                                       // OPTIONAL

/* Kerberos V5 (KRB5) related authentication keys: */
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_KRB_AP_REQ "KRB_AP_REQ" // For KRB5 (Kerberos V5) (see RFC4120 and RFC1964), the initiator MUST use:
                                                                      //    KRB_AP_REQ=<KRB_AP_REQ>
                                                                      // where KRB_AP_REQ is the client message as defined in RFC4120.
                                                                      // The default principal name assumed by an iSCSI initiator or target
                                                                      // (prior to any administrative configuration action) MUST be the iSCSI
                                                                      // Initiator Name or iSCSI Target Name, respectively, prefixed by the
                                                                      // string "iscsi/".
                                                                      // If the initiator authentication fails, the target MUST respond with a
                                                                      // Login reject with "Authentication Failure" status. Otherwise, if the
                                                                      // initiator has selected the mutual authentication option (by setting
                                                                      // MUTUAL-REQUIRED in the ap-options field of the KRB_AP_REQ), the
                                                                      // target MUST reply with:
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_KRB_AP_REP "KRB_AP_REP" //    KRB_AP_REP=<KRB_AP_REP>
                                                                      // where KRB_AP_REP is the server's response message as defined in
                                                                      // RFC4120.
                                                                      // If mutual authentication was selected and target authentication
                                                                      // fails, the initiator MUST close the connection.
                                                                      // KRB_AP_REQ and KRB_AP_REP are binary-values, and their binary length
                                                                      // (not the length of the character string that represents them in
                                                                      // encoded form) MUST NOT exceed 65536 bytes. Hex or Base64 encoding
                                                                      // may be used for KRB_AP_REQ and KRB_AP_REP

/* Secure Remote Password (SRP) related authentication keys: */
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_SRP_SRP_U     "SRP_U"     // For SRP RFC2945, the initiator MUST use:
                                                                        //    SRP_U=<U> TargetAuth=Yes or TargetAuth=No
                                                                        // The target MUST answer with a Login reject with the "Authorization
                                                                        // Failure" status or reply with:
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_SRP_SRP_GROUP "SRP_GROUP" //    SRP_GROUP=<G1,G2...> SRP_s=<s>
                                                                        // where G1,G2... are proposed groups, in order of preference.
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_SRP_SRP_A     "SRP_A"     // The initiator MUST either close the connection or continue with:
                                                                        //    SRP_A=<A>
                                                                        //    SRP_GROUP=<G>
                                                                        // where G is one of G1,G2... that were proposed by the target.
                                                                        // The target MUST answer with a Login reject with the "Authentication
                                                                        // Failure" status or reply with:
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_SRP_SRP_B     "SRP_B"     //     SRP_B=<B>
                                                                        // The initiator MUST close the connection or continue with:
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_SRP_SRP_M     "SRP_M"     //     SRP_M=<M>
                                                                        // If the initiator authentication fails, the target MUST answer with a
                                                                        // Login reject with "Authentication Failure" status. Otherwise, if the
                                                                        // initiator sent TargetAuth=Yes in the first message (requiring target
                                                                        // authentication), the target MUST reply with:
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_SRP_SRP_HM    "SRP_HM"    //     SRP_HM=<H(A | M | K)>
                                                                        // If the target authentication fails, the initiator MUST close the
                                                                        // connection:
                                                                        // where U, s, A, B, M, and H(A | M | K) are defined in RFC2945 (using
                                                                        // the SHA1 hash function, such as SRP-SHA1) and
                                                                        // G,Gn ("Gn" stands for G1,G2...) are identifiers of SRP groups
                                                                        // specified in RFC3723.
                                                                        // G, Gn, and U are text strings; s,A,B,M, and H(A | M | K) are
                                                                        // binary-values. The length of s,A,B,M and H(A | M | K) in binary form
                                                                        // (not the length of the character string that represents them in
                                                                        // encoded form) MUST NOT exceed 1024 bytes. Hex or Base64 encoding may
                                                                        // be used for s,A,B,M and H(A | M | K).
                                                                        // For the SRP_GROUP, all the groups specified in RFC3723 up to
                                                                        // 1536 bits (i.e. SRP-768, SRP-1024, SRP-1280, SRP-1536) must be
                                                                        // supported by initiators and targets. To guarantee interoperability,
                                                                        // targets MUST always offer "SRP-1536" as one of the proposed groups

/* Challenge Handshake Authentication Protocol (CHAP) related authentication keys: */
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_A "CHAP_A" // For CHAP RFC1994, the initiator MUST use:
                                                                   //    CHAP_A=<A1,A2...>
                                                                   // where A1,A2... are proposed algorithms, in order of preference.
                                                                   // The target MUST answer with a Login reject with the "Authentication
                                                                   // Failure" status or reply with:
                                                                   //    CHAP_A=<A>
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_I "CHAP_I" //    CHAP_I=<I>
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_C "CHAP_C" //    CHAP_C=<C>
                                                                   // where A is one of A1,A2... that were proposed by the initiator.
                                                                   // The initiator MUST continue with:
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_N "CHAP_N" //    CHAP_N=<N>
#define ISCSI_LOGIN_AUTH_TEXT_KEY_AUTH_METHOD_CHAP_CHAP_R "CHAP_R" //    CHAP_R=<R>
                                                                   // or, if it requires target authentication, with:
                                                                   //    CHAP_N=<N>
                                                                   //    CHAP_R=<R>
                                                                   //    CHAP_I=<I>
                                                                   //    CHAP_C=<C>
                                                                   // If the initiator authentication fails, the target MUST answer with a
                                                                   // Login reject with "Authentication Failure" status. Otherwise, if the
                                                                   // initiator required target authentication, the target MUST either
                                                                   // answer with a Login reject with "Authentication Failure" or reply
                                                                   // with:
                                                                   //    CHAP_N=<N>
                                                                   //    CHAP_R=<R>
                                                                   // If the target authentication fails, the initiator MUST close the
                                                                   // connection:
                                                                   // where N, (A,A1,A2), I, C, and R are (correspondingly) the Name,
                                                                   // Algorithm, Identifier, Challenge, and Response as defined in
                                                                   // RFC1994.
                                                                   // N is a text string; A,A1,A2, and I are numbers; C and R are
                                                                   // binary-values. Their binary length (not the length of the character
                                                                   // string that represents them in encoded form) MUST NOT exceed
                                                                   // 1024 bytes. Hex or Base64 encoding may be used for C and R.
                                                                   // For the Algorithm, as stated in [RFC1994], one value is required to
                                                                   // be implemented:
                                                                   // 5     (CHAP with MD5)
                                                                   // To guarantee interoperability, initiators MUST always offer it as one
                                                                   // of the proposed algorithms

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
#define ISCSI_LOGIN_AUTH_TEXT_KEY_HEADER_DIGEST "HeaderDigest" // Use: IO
#define ISCSI_LOGIN_AUTH_TEXT_KEY_DATA_DIGEST   "DataDigest"   // Senders: Initiator and target
                                                               // Scope: CO
                                                               // HeaderDigest = <list-of-values>
                                                               // DataDigest = <list-of-values>
                                                               // Default is None for both HeaderDigest and DataDigest.
                                                               // Digests enable the checking of end-to-end, non-cryptographic data
                                                               // integrity beyond the integrity checks provided by the link layers and
                                                               // the covering of the whole communication path, including all elements
                                                               // that may change the network-level PDUs, such as routers, switches,
                                                               // and proxies.
                                                               // The following table lists cyclic integrity checksums that can be
                                                               // negotiated for the digests and MUST be implemented by every iSCSI
                                                               // initiator and target. These digest options only have error detection
                                                               // significance.
                                                               // +---------------------------------------------+
                                                               // | Name          | Description     | Generator |
                                                               // +---------------------------------------------+
                                                               // | CRC32C        | 32-bit CRC      |0x11edc6f41|
                                                               // +---------------------------------------------+
                                                               // | None          | no digest                   |
                                                               // +---------------------------------------------+
                                                               // The generator polynomial G(x) for this digest is given in hexadecimal
                                                               // notation (e.g. "0x3b" stands for 0011 1011, and the polynomial is
                                                               // x**5 + x**4 + x**3 + x + 1).
                                                               // When the initiator and target agree on a digest, this digest MUST be
                                                               // used for every PDU in the Full Feature Phase.
                                                               // Padding bytes, when present in a segment covered by a CRC, SHOULD be
                                                               // set to 0 and are included in the CRC.
                                                               // The CRC MUST be calculated by a method that produces the same results
                                                               // as the following process:
                                                               // - The PDU bits are considered as the coefficients of a polynomial
                                                               //   M(x) of degree n - 1; bit 7 of the lowest numbered byte is
                                                               //   considered the most significant bit (x**n - 1), followed by bit 6
                                                               //   of the lowest numbered byte through bit 0 of the highest numbered
                                                               //   byte (x**0).
                                                               // - The most significant 32 bits are complemented.
                                                               // - The polynomial is multiplied by x**32, then divided by G(x). The
                                                               //   generator polynomial produces a remainder R(x) of degree <= 31.
                                                               // - The coefficients of R(x) are formed into a 32-bit sequence.
                                                               // - The bit sequence is complemented, and the result is the CRC.
                                                               // - The CRC bits are mapped into the digest word. The x**31
                                                               //   coefficient is mapped to bit 7 of the lowest numbered byte of the
                                                               //   digest, and the mapping continues with successive coefficients and
                                                               //   bits so that the x**24 coefficient is mapped to bit 0 of the lowest
                                                               //   numbered byte. The mapping continues further with the x**23
                                                               //   coefficient mapped to bit 7 of the next byte in the digest until
                                                               //   the x**0 coefficient is mapped to bit 0 of the highest numbered
                                                               //   byte of the digest.
                                                               // - Computing the CRC over any segment (data or header) extended to
                                                               //   include the CRC built using the generator 0x11edc6f41 will always
                                                               //   get the value 0x1c2d19ed as its final remainder (R(x)). This value
                                                               //   is given here in its polynomial form (i.e., not mapped as the
                                                               //   digest word).
                                                               // For a discussion about selection criteria for the CRC, see RFC3385.
                                                               // For a detailed analysis of the iSCSI polynomial, see Castagnoli93.
                                                               // Private or public extension algorithms MAY also be negotiated for
                                                               // digests. Whenever a private or public digest extension algorithm is
                                                               // part of the default offer (the offer made in the absence of explicit
                                                               // administrative action), the implementer MUST ensure that CRC32C is
                                                               // listed as an alternative in the default offer and "None" is not part
                                                               // of the default offer.
                                                               // Extension digest algorithms MUST be named using one of the following
                                                               // two formats:
                                                               //    1) Y-reversed.vendor.dns_name.do_something=
                                                               //    2) New public key with no name prefix constraints
                                                               // Digests named using the Y- format are used for private purposes
                                                               // (unregistered). New public keys must be registered with IANA using
                                                               // the IETF Review process (RFC5226). New public extensions for
                                                               // digests MUST NOT use the Y# name prefix.
                                                               // For private extension digests, to identify the vendor we suggest
                                                               // using the reversed DNS-name as a prefix to the proper digest names.
                                                               // The part of digest-name following Y- MUST conform to the format for
                                                               // standard-label specified.
                                                               // Support for public or private extension digests is OPTIONA
#define ISCSI_LOGIN_AUTH_TEXT_KEY_MAX_CONNECTIONS "MaxConnections" // Use: LO
                                                                   // Senders: Initiator and target
                                                                   // Scope: SW
                                                                   // Irrelevant when: SessionType=Discovery
                                                                   // MaxConnections=<numerical-value-from-1-to-65535>
                                                                   // Default is 1.
                                                                   // Result function is Minimum.
                                                                   // The initiator and target negotiate the maximum number of connections
                                                                   // requested/acceptable
#define ISCSI_LOGIN_AUTH_TEXT_KEY_SEND_TARGETS "SendTargets" // Use: FFPO
                                                             // Senders: Initiator
                                                             // Scope: SW
                                                             // The text in this appendix is a normative part of this document.
                                                             // To reduce the amount of configuration required on an initiator, iSCSI
                                                             // provides the SendTargets Text Request. The initiator uses the
                                                             // SendTargets request to get a list of targets to which it may have
                                                             // access, as well as the list of addresses (IP address and TCP port) on
                                                             // which these targets may be accessed.
                                                             // To make use of SendTargets, an initiator must first establish one of
                                                             // two types of sessions. If the initiator establishes the session
                                                             // using the key "SessionType=Discovery", the session is a Discovery
                                                             // session, and a target name does not need to be specified. Otherwise,
                                                             // the session is a Normal operational session. The SendTargets command
                                                             // MUST only be sent during the Full Feature Phase of a Normal or
                                                             // Discovery session.
                                                             // A system that contains targets MUST support Discovery sessions on
                                                             // each of its iSCSI IP address-port pairs and MUST support the
                                                             // SendTargets command on the Discovery session. In a Discovery
                                                             // session, a target MUST return all path information (IP address-port
                                                             // pairs and Target Portal Group Tags) for the targets on the target
                                                             // Network Entity that the requesting initiator is authorized to access.
                                                             // A target MUST support the SendTargets command on operational
                                                             // sessions; these will only return path information about the target to
                                                             // which the session is connected and do not need to return information
                                                             // about other target names that may be defined in the responding
                                                             // system.
                                                             // An initiator MAY make use of the SendTargets command as it sees fit.
                                                             // A SendTargets command consists of a single Text Request PDU. This
                                                             // PDU contains exactly one text key and value. The text key MUST be
                                                             // SendTargets. The expected response depends upon the value, as well
                                                             // as whether the session is a Discovery session or an operational
                                                             // session.
                                                             // The value must be one of:
                                                             //    All
                                                             //       The initiator is requesting that information on all relevant
                                                             //       targets known to the implementation be returned. This value
                                                             //       MUST be supported on a Discovery session and MUST NOT be
                                                             //       supported on an operational session.
                                                             //    <iSCSI-target-name>
                                                             //       If an iSCSI Target Name is specified, the session should
                                                             //       respond with addresses for only the named target, if possible.
                                                             //       This value MUST be supported on Discovery sessions. A
                                                             //       Discovery session MUST be capable of returning addresses for
                                                             //       those targets that would have been returned had value=All been
                                                             //       designated.
                                                             //    <nothing>
                                                             //       The session should only respond with addresses for the target
                                                             //       to which the session is logged in. This MUST be supported on
                                                             //       operational sessions and MUST NOT return targets other than the
                                                             //       one to which the session is logged in.
                                                             // The response to this command is a Text Response that contains a list
                                                             // of zero or more targets and, optionally, their addresses. Each
                                                             // target is returned as a target record. A target record begins with
                                                             // the TargetName text key, followed by a list of TargetAddress text
                                                             // keys, and bounded by the end of the Text Response or the next
                                                             // TargetName key, which begins a new record. No text keys other than
                                                             // TargetName and TargetAddress are permitted within a SendTargets
                                                             // response.
                                                             // A Discovery session MAY respond to a SendTargets request with its
                                                             // complete list of targets, or with a list of targets that is based on
                                                             // the name of the initiator logged in to the session.
                                                             // A SendTargets response MUST NOT contain target names if there are no
                                                             // targets for the requesting initiator to access.
                                                             // Each target record returned includes zero or more TargetAddress
                                                             // fields.
                                                             // Each target record starts with one text key of the form:
                                                             //    TargetName=<target-name-goes-here>
                                                             // followed by zero or more address keys of the form:
                                                             // TargetAddress=<hostname-or-ipaddress>[:<tcp-port>],
                                                             //    <portal-group-tag>
                                                             // The hostname-or-ipaddress contains a domain name, IPv4 address, or
                                                             // IPv6 address (RFC4291), as specified for the TargetAddress key.
                                                             // A hostname-or-ipaddress duplicated in TargetAddress responses for a
                                                             // given node (the port is absent or equal) would probably indicate that
                                                             // multiple address families are in use at once (IPv6 and IPv4).
                                                             // Each TargetAddress belongs to a portal group, identified by its
                                                             // numeric Target Portal Group Tag. The iSCSI Target
                                                             // Name, together with this tag, constitutes the SCSI port identifier;
                                                             // the tag only needs to be unique within a given target's name list of
                                                             // addresses.
                                                             // Multiple-connection sessions can span iSCSI addresses that belong to
                                                             // the same portal group.
                                                             // Multiple-connection sessions cannot span iSCSI addresses that belong
                                                             // to different portal groups.
                                                             // If a SendTargets response reports an iSCSI address for a target, it
                                                             // SHOULD also report all other addresses in its portal group in the
                                                             // same response.
                                                             // A SendTargets Text Response can be longer than a single Text Response
                                                             // PDU and makes use of the long Text Responses as specified.
                                                             // After obtaining a list of targets from the Discovery session, an
                                                             // iSCSI initiator may initiate new sessions to log in to the discovered
                                                             // targets for full operation. The initiator MAY keep the Discovery
                                                             // session open and MAY send subsequent SendTargets commands to discover
                                                             // new targets.
                                                             // Examples:
                                                             // This example is the SendTargets response from a single target that
                                                             // has no other interface ports.
                                                             // The initiator sends a Text Request that contains:
                                                             //    SendTargets=All
                                                             // The target sends a Text Response that contains:
                                                             //    TargetName=iqn.1993-11.de.uni-freiburg:diskarray.sn.8675309
                                                             // All the target had to return in this simple case was the target name.
                                                             // It is assumed by the initiator that the IP address and TCP port for
                                                             // this target are the same as those used on the current connection to
                                                             // the default iSCSI target.
                                                             // The next example has two internal iSCSI targets, each accessible via
                                                             // two different ports with different IP addresses. The following is
                                                             // the Text Response:
                                                             //    TargetName=iqn.1993-11.de.uni-freiburg:diskarray.sn.8675309
                                                             //    TargetAddress=10.1.0.45:5300,1
                                                             //    TargetAddress=10.1.1.45:5300,2
                                                             //    TargetName=iqn.1993-11.de.uni-freiburg:diskarray.sn.1234567
                                                             //    TargetAddress=10.1.0.45:5300,1
                                                             //    TargetAddress=10.1.1.45:5300,2
                                                             // Both targets share both addresses; the multiple addresses are likely
                                                             // used to provide multi-path support. The initiator may connect to
                                                             // either target name on either address. Each of the addresses has its
                                                             // own Target Portal Group Tag; they do not support spanning multiple-
                                                             // connection sessions with each other. Keep in mind that the Target
                                                             // Portal Group Tags for the two named targets are independent of one
                                                             // another; portal group "1" on the first target is not necessarily the
                                                             // same as portal group "1" on the second target.
                                                             // In the above example, a DNS host name or an IPv6 address could have
                                                             // been returned instead of an IPv4 address.
                                                             // The next Text Response shows a target that supports spanning sessions
                                                             // across multiple addresses and further illustrates the use of the
                                                             // Target Portal Group Tags:
                                                             //    TargetName=iqn.1993-11.de.uni-freiburg:diskarray.sn.8675309
                                                             //    TargetAddress=10.1.0.45:5300,1
                                                             //    TargetAddress=10.1.1.46:5300,1
                                                             //    TargetAddress=10.1.0.47:5300,2
                                                             //    TargetAddress=10.1.1.48:5300,2
                                                             //    TargetAddress=10.1.1.49:5300,3
                                                             // In this example, any of the target addresses can be used to reach the
                                                             // same target. A single-connection session can be established to any
                                                             // of these TCP addresses. A multiple-connection session could span
                                                             // addresses .45 and .46 or .47 and .48 but cannot span any other
                                                             // combination. A TargetAddress with its own tag (.49) cannot be
                                                             // combined with any other address within the same session.
                                                             // This SendTargets response does not indicate whether .49 supports
                                                             // multiple connections per session; it is communicated via the
                                                             // MaxConnections text key upon login to the target
#define ISCSI_LOGIN_AUTH_TEXT_KEY_INITIAL_R2T "InitialR2T" // Use: LO
                                                           // Senders: Initiator and target
                                                           // Scope: SW
                                                           // Irrelevant when: SessionType=Discovery
                                                           // InitialR2T=<boolean-value>
                                                           // Examples:
                                                           //    I->InitialR2T=No
                                                           //    T->InitialR2T=No
                                                           // Default is Yes.
                                                           // Result function is OR.
                                                           // The InitialR2T key is used to turn off the default use of R2T for
                                                           // unidirectional operations and the output part of bidirectional
                                                           // commands, thus allowing an initiator to start sending data to a
                                                           // target as if it has received an initial R2T with Buffer
                                                           // Offset=Immediate Data Length and Desired Data Transfer
                                                           // Length=(min(FirstBurstLength, Expected Data Transfer Length) -
                                                           // Received Immediate Data Length).
                                                           // The default action is that R2T is required, unless both the initiator
                                                           // and the target send this key-pair attribute specifying InitialR2T=No.
                                                           // Only the first outgoing data burst (immediate data and/or separate
                                                           // PDUs) can be sent unsolicited (i.e., not requiring an explicit R2T)
#define ISCSI_LOGIN_AUTH_TEXT_KEY_IMMEDIATE_DATA "ImmediateData" // Use: LO
                                                                 // Senders: Initiator and target
                                                                 // Scope: SW
                                                                 // Irrelevant when: SessionType=Discovery
                                                                 // ImmediateData=<boolean-value>
                                                                 // Default is Yes.
                                                                 // Result function is AND.
                                                                 // The initiator and target negotiate support for immediate dataTo
                                                                 // turn immediate data off, the initiator or target must state its
                                                                 // desire to do soImmediateData can be turned on if both the
                                                                 // initiator and target have ImmediateData=Yes.
                                                                 // If ImmediateData is set to Yes and InitialR2T is set to Yes
                                                                 // (default), then only immediate data are accepted in the first burst.
                                                                 // If ImmediateData is set to No and InitialR2T is set to Yes, then the
                                                                 // initiator MUST NOT send unsolicited data and the target MUST reject
                                                                 // unsolicited data with the corresponding response code.
                                                                 // If ImmediateData is set to No and InitialR2T is set to No, then the
                                                                 // initiator MUST NOT send unsolicited immediate data but MAY send one
                                                                 // unsolicited burst of Data-OUT PDUs.
                                                                 // If ImmediateData is set to Yes and InitialR2T is set to No, then the
                                                                 // initiator MAY send unsolicited immediate data and/or one unsolicited
                                                                 // burst of Data-OUT PDUs.
                                                                 // The following table is a summary of unsolicited data options:
                                                                 // +----------+-------------+------------------+-------------+
                                                                 // |InitialR2T|ImmediateData|    Unsolicited   |ImmediateData|
                                                                 // |          |             |   Data-Out PDUs  |             |
                                                                 // +----------+-------------+------------------+-------------+
                                                                 // | No       | No          | Yes              | No          |
                                                                 // +----------+-------------+------------------+-------------+
                                                                 // | No       | Yes         | Yes              | Yes         |
                                                                 // +----------+-------------+------------------+-------------+
                                                                 // | Yes      | No          | No               | No          |
                                                                 // +----------+-------------+------------------+-------------+
                                                                 // | Yes      | Yes         | No               | Yes         |
                                                                 // +----------+-------------+------------------+-------------+
#define ISCSI_LOGIN_AUTH_TEXT_KEY_MAX_RECV_DS_LEN "MaxRecvDataSegmentLength" // Use: ALL, Declarative
                                                                             // Senders: Initiator and target
                                                                             // Scope: CO
                                                                             // MaxRecvDataSegmentLength=<numerical-value-512-to-(2**24 - 1)>
                                                                             // Default is 8192 bytes.
                                                                             // The initiator or target declares the maximum data segment length in
                                                                             // bytes it can receive in an iSCSI PDU.
                                                                             // The transmitter (initiator or target) is required to send PDUs with a
                                                                             // data segment that does not exceed MaxRecvDataSegmentLength of the
                                                                             // receiver.
                                                                             // A target receiver is additionally limited by MaxBurstLength for
                                                                             // solicited data and FirstBurstLength for unsolicited dataAn
                                                                             // initiator MUST NOT send solicited PDUs exceeding MaxBurstLength nor
                                                                             // unsolicited PDUs exceeding FirstBurstLength (or FirstBurstLength-
                                                                             // Immediate Data Length if immediate data were sent)
#define ISCSI_LOGIN_AUTH_TEXT_KEY_MAX_BURST_LEN "MaxBurstLength" // Use: LO
                                                                 // Senders: Initiator and target
                                                                 // Scope: SW
                                                                 // Irrelevant when: SessionType=Discovery
                                                                 // MaxBurstLength=<numerical-value-512-to-(2**24 - 1)>
                                                                 // Default is 262144 (256 KB).
                                                                 // Result function is Minimum.
                                                                 // The initiator and target negotiate the maximum SCSI data payload in
                                                                 // bytes in a Data-In or a solicited Data-Out iSCSI sequence. A
                                                                 // sequence consists of one or more consecutive Data-In or Data-Out PDUs
                                                                 // that end with a Data-In or Data-Out PDU with the F bit set to 1
#define ISCSI_LOGIN_AUTH_TEXT_KEY_FIRST_BURST_LEN "FirstBurstLength" // Use: LO
                                                                     // Senders: Initiator and target
                                                                     // Scope: SW
                                                                     // Irrelevant when: SessionType=Discovery
                                                                     // Irrelevant when: ( InitialR2T=Yes and ImmediateData=No )
                                                                     // FirstBurstLength=<numerical-value-512-to-(2**24 - 1)>
                                                                     // Default is 65536 (64 KB).
                                                                     // Result function is Minimum.
                                                                     // The initiator and target negotiate the maximum amount in bytes of
                                                                     // unsolicited data an iSCSI initiator may send to the target during the
                                                                     // execution of a single SCSI command. This covers the immediate data
                                                                     // (if any) and the sequence of unsolicited Data-Out PDUs (if any) that
                                                                     // follow the command.
                                                                     // FirstBurstLength MUST NOT exceed MaxBurstLength
#define ISCSI_LOGIN_AUTH_TEXT_KEY_DEFAULT_TIME_WAIT "DefaultTime2Wait" // Use: LO
                                                                       // Senders: Initiator and target
                                                                       // Scope: SW
                                                                       // DefaultTime2Wait=<numerical-value-0-to-3600>
                                                                       // Default is 2.
                                                                       // Result function is Maximum.
                                                                       // The initiator and target negotiate the minimum time, in seconds, to
                                                                       // wait before attempting an explicit/implicit logout or an active task
                                                                       // reassignment after an unexpected connection termination or a
                                                                       // connection reset.
                                                                       // A value of 0 indicates that logout or active task reassignment can be
                                                                       // attempted immediately
#define ISCSI_LOGIN_AUTH_TEXT_KEY_DEFAULT_TIME_RETAIN "DefaultTime2Retain" // Use: LO
                                                                           // Senders: Initiator and target
                                                                           // Scope: SW
                                                                           // DefaultTime2Retain=<numerical-value-0-to-3600>
                                                                           // Default is 20.
                                                                           // Result function is Minimum.
                                                                           // The initiator and target negotiate the maximum time, in seconds,
                                                                           // after an initial wait (Time2Wait), before which an active task
                                                                           // reassignment is still possible after an unexpected connection
                                                                           // termination or a connection reset.
                                                                           // This value is also the session state timeout if the connection in
                                                                           // question is the last LOGGED_IN connection in the session.
                                                                           // A value of 0 indicates that connection/task state is immediately
                                                                           // discarded by the target
#define ISCSI_LOGIN_AUTH_TEXT_KEY_MAX_OUTSTANDING_R2T "MaxOutstandingR2T" // Use: LO
                                                                          // Senders: Initiator and target
                                                                          // Scope: SW
                                                                          // MaxOutstandingR2T=<numerical-value-from-1-to-65535>
                                                                          // Irrelevant when: SessionType=Discovery
                                                                          // Default is 1.
                                                                          // Result function is Minimum.
                                                                          // The initiator and target negotiate the maximum number of outstanding
                                                                          // R2Ts per task, excluding any implied initial R2T that might be part
                                                                          // of that task. An R2T is considered outstanding until the last data
                                                                          // PDU (with the F bit set to 1) is transferred or a sequence reception
                                                                          // timeout is encountered for that data sequence
#define ISCSI_LOGIN_AUTH_TEXT_KEY_DATA_PDU_IN_ORDER "DataPDUInOrder" // Use: LO
                                                                     // Senders: Initiator and target
                                                                     // Scope: SW
                                                                     // Irrelevant when: SessionType=Discovery
                                                                     // DataPDUInOrder=<boolean-value>
                                                                     // Default is Yes.
                                                                     // Result function is OR.
                                                                     // "No" is used by iSCSI to indicate that the data PDUs within sequences
                                                                     // can be in any order. "Yes" is used to indicate that data PDUs within
                                                                     // sequences have to be at continuously increasing addresses and
                                                                     // overlays are forbidden
#define ISCSI_LOGIN_AUTH_TEXT_KEY_DATA_SEQ_IN_ORDER "DataSequenceInOrder" // Use: LO
                                                                          // Senders: Initiator and target
                                                                          // Scope: SW
                                                                          // Irrelevant when: SessionType=Discovery
                                                                          // DataSequenceInOrder=<boolean-value>
                                                                          // Default is Yes.
                                                                          // Result function is OR.
                                                                          // A data sequence is a sequence of Data-In or Data-Out PDUs that end
                                                                          // with a Data-In or Data-Out PDU with the F bit set to 1. A Data-Out
                                                                          // sequence is sent either unsolicited or in response to an R2T.
                                                                          // Sequences cover an offset-range.
                                                                          // If DataSequenceInOrder is set to No, data PDU sequences may be
                                                                          // transferred in any order.
                                                                          // If DataSequenceInOrder is set to Yes, data sequences MUST be
                                                                          // transferred using continuously non-decreasing sequence offsets (R2T
                                                                          // buffer offset for writes, or the smallest SCSI Data-In buffer offset
                                                                          // within a read data sequence).
                                                                          // If DataSequenceInOrder is set to Yes, a target may retry at most the
                                                                          // last R2T, and an initiator may at most request retransmission for the
                                                                          // last read data sequence. For this reason, if ErrorRecoveryLevel is
                                                                          // not 0 and DataSequenceInOrder is set to Yes, then MaxOutstandingR2T
                                                                          // MUST be set to 1
#define ISCSI_LOGIN_AUTH_TEXT_KEY_ERR_RECOVERY_LEVEL "ErrorRecoveryLevel" // Use: LO
                                                                          // Senders: Initiator and target
                                                                          // Scope: SW
                                                                          // ErrorRecoveryLevel=<numerical-value-0-to-2>
                                                                          // Default is 0.
                                                                          // Result function is Minimum.
                                                                          // The initiator and target negotiate the recovery level supported.
                                                                          // Recovery levels represent a combination of recovery capabilities.
                                                                          // Each recovery level includes all the capabilities of the lower
                                                                          // recovery levels and adds some new ones to them.
                                                                          // In the description of recovery mechanisms, certain recovery classes
                                                                          // are specified
#define ISCSI_LOGIN_AUTH_TEXT_KEY_PRIV_EXT_KEY_FMT "X-reversed.vendor" // Use: ALL
                                                                       // Senders: Initiator and target
                                                                       // Scope: specific key dependent
                                                                       // X-reversed.vendor.dns_name.do_something=
                                                                       // Keys with this format are used for private extension purposes. These
                                                                       // keys always start with X- if unregistered with IANA (private). New
                                                                       // public keys (if registered with IANA via an IETF Review RFC5226) no
                                                                       // longer have an X# name prefix requirement; implementers may propose
                                                                       // any intuitive unique name.
                                                                       // For unregistered keys, to identify the vendor we suggest using the
                                                                       // reversed DNS-name as a prefix to the key-proper.
                                                                       // The part of key-name following X- MUST conform to the format for
                                                                       // key-name.
                                                                       // Vendor-specific keys MUST ONLY be used in Normal sessions.
                                                                       // Support for public or private extension keys is OPTIONAL
#define ISCSI_LOGIN_AUTH_TEXT_KEY_TASK_REPORTING "TaskReporting" // Use: LO
                                                                 // Senders: Initiator and target
                                                                 // Scope: SW
                                                                 // Irrelevant when: SessionType=Discovery
                                                                 // TaskReporting=<list-of-values>
                                                                 // Default is RFC3720.
                                                                 // This key is used to negotiate the task completion reporting semantics
                                                                 // from the SCSI target. The following table describes the semantics
                                                                 // that an iSCSI target MUST support for respective negotiated key
                                                                 // values. Whenever this key is negotiated, at least the RFC3720 and
                                                                 // ResponseFence values MUST be offered as options by the negotiation
                                                                 // originator.
                                                                 // +--------------+------------------------------------------+
                                                                 // | Name         |             Description                  |
                                                                 // +--------------+------------------------------------------+
                                                                 // | RFC3720      | RFC 3720-compliant semantics. Response   |
                                                                 // |              | fencing is not guaranteed, and fast      |
                                                                 // |              | completion of multi-task aborting is not |
                                                                 // |              | supported.                               |
                                                                 // +--------------+------------------------------------------+
                                                                 // | ResponseFence| Response Fence                           |
                                                                 // |              | semantics MUST be supported in reporting |
                                                                 // |              | task completions.                        |
                                                                 // +--------------+------------------------------------------+
                                                                 // | FastAbort    | Updated fast multi-task abort semantics  |
                                                                 // |              | defined in MUST be supported. Support    |
                                                                 // |              | for the Response. Fence is implied -     |
                                                                 // |              | i.e., semantics MUST be supported as     |
                                                                 // |              | well.                                    |
                                                                 // +--------------+------------------------------------------+
                                                                 // When TaskReporting is not negotiated to FastAbort, the
                                                                 // standard multi-task abort semantics MUST be used
#define ISCSI_LOGIN_AUTH_TEXT_KEY_X_NODE_ARCH "X#NodeArchitecture" // Use: LO, Declarative
                                                                   // Senders: Initiator and target
                                                                   // Scope: SW
                                                                   // X#NodeArchitecture=<list-of-values>
                                                                   // Default is None.
                                                                   // Examples:
                                                                   //    X#NodeArchitecture=ExampleOS/v1234,ExampleInc_SW_Initiator/1.05a
                                                                   //    X#NodeArchitecture=ExampleInc_HW_Initiator/4010,Firmware/2.0.0.5
                                                                   //    X#NodeArchitecture=ExampleInc_SW_Initiator/2.1,CPU_Arch/i686
                                                                   // This document does not define the structure or content of the list of
                                                                   // values.
                                                                   // The initiator or target declares the details of its iSCSI node
                                                                   // architecture to the remote endpoint. These details may include, but
                                                                   // are not limited to, iSCSI vendor software, firmware, or hardware
                                                                   // versions; the OS version; or hardware architecture. This key may be
                                                                   // declared on a Discovery session or a Normal session.
                                                                   // The length of the key value (total length of the list-of-values) MUST
                                                                   // NOT be greater than 255 bytes.
                                                                   // X#NodeArchitecture MUST NOT be redeclared during the Login Phase.
                                                                   // Functional behavior of the iSCSI node (this includes the iSCSI
                                                                   // protocol logic - the SCSI, iSCSI, and TCP/IP protocols) MUST NOT
                                                                   // depend on the presence, absence, or content of the X#NodeArchitecture
                                                                   // key. The key MUST NOT be used by iSCSI nodes for interoperability or
                                                                   // for exclusion of other nodes. To ensure proper use, key values
                                                                   // SHOULD be set by the node itself, and there SHOULD NOT be provisions
                                                                   // for the key values to contain user-defined text.
                                                                   // Nodes implementing this key MUST choose one of the following
                                                                   // implementation options:
                                                                   // - only transmit the key,
                                                                   // - only log the key values received from other nodes, or
                                                                   // - both transmit and log the key values.
                                                                   // Each node choosing to implement transmission of the key values MUST
                                                                   // be prepared to handle the response of iSCSI nodes that do not
                                                                   // understand the key.
                                                                   // Nodes that implement transmission and/or logging of the key values
                                                                   // may also implement administrative mechanisms that disable and/or
                                                                   // change the logging and key transmission details.
                                                                   // Thus, a valid behavior for this key may be that a node is completely
                                                                   // silent (the node does not transmit any key value and simply discards
                                                                   // any key values it receives without issuing a NotUnderstood response)
#define ISCSI_LOGIN_AUTH_TEXT_KEY_IF_MARKER   "IFMarker"  // Obsoleted Keys
#define ISCSI_LOGIN_AUTH_TEXT_KEY_OF_MARKER   "OFMarker"  // This document obsoletes the following keys defined in RFC3720:
#define ISCSI_LOGIN_AUTH_TEXT_KEY_OF_MARK_INT "OFMarkInt" // IFMarker, OFMarker, OFMarkInt, and IFMarkInt. However, iSCSI
#define ISCSI_LOGIN_AUTH_TEXT_KEY_IF_MARK_INT "IFMarkInt" // implementations compliant to this document may still receive these
                                                          // obsoleted keys - i.e., in a responder role - in a text negotiation.
                                                          // When an IFMarker or OFMarker key is received, a compliant iSCSI
                                                          // implementation SHOULD respond with the constant "Reject" value. The
                                                          // implementation MAY alternatively respond with a "No" value.
                                                          // However, the implementation MUST NOT respond with a "NotUnderstood"
                                                          // value for either of these keys.
                                                          // When an IFMarkInt or OFMarkInt key is received, a compliant iSCSI
                                                          // implementation MUST respond with the constant "Reject" value. The
                                                          // implementation MUST NOT respond with a "NotUnderstood" value for
                                                          // either of these keys

/* This is an initiator-defined component of the session identifier and
   is structured as follows:

   For the T field values 00b and 01b, a combination of A and B (for
   00b) or B and C (for 01b) identifies the vendor or organization whose
   component (software or hardware) generates this ISID. A vendor or
   organization with one or more OUIs, or one or more Enterprise
   Numbers, MUST use at least one of these numbers and select the
   appropriate value for the T field when its components generate ISIDs.
   An OUI or EN MUST be set in the corresponding fields in network byte
   order (byte big-endian).

   If the T field is 10b, B and C are set to a random 24-bit unsigned
   integer value in network byte order (byte big-endian).

   The Qualifier field is a 16-bit or 24-bit unsigned integer value that
   provides a range of possible values for the ISID within the selected
   namespace. It may be set to any value within the constraints
   specified in the iSCSI protocol.

   If the ISID is derived from something assigned to a hardware adapter
   or interface by a vendor as a preset default value, it MUST be
   configurable to a value assigned according to the SCSI port behavior
   desired by the system in which it is installed. The resultant ISID
   MUST also be persistent over power cycles, reboot, card swap, etc.
*/
typedef struct __attribute__((packed)) iscsi_isid {
    uint8_t a; // Meaning depends on T bit (see above)
    uint16_t b; // Meaning depends on T bit (see above)
    uint8_t c; // Meaning depends on T bit (see above)
    uint16_t d; // Meaning depends on T bit (see above)
} iscsi_isid;

#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION          0x0 // SecurityNegotiation
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1 // LoginOperationalNegotiation
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_FULL_FEATURE_PHASE            0x3 // FullFeaturePhase
#define ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE    (1 << 0) // (NSG) - Two bits - the Login negotiation requests and responses are
                                                     // associated with a specific stage in the session (SecurityNegotiation,
                                                     // LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
                                                     // next stage to which they want to move. The Next Stage value is only
                                                     // valid when the T bit is 1; otherwise, it is reserved
#define ISCSI_LOGIN_REQS_FLAGS_GET_NEXT_STAGE(x) ((x) & 3)

#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION          0x0 // SecurityNegotiation
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1 // LoginOperationalNegotiation
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_FULL_FEATURE_PHASE            0x3 // FullFeaturePhase
#define ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE (1 << 2) // (CSG) - Two bits - the Login negotiation requests and responses are
                                                     // associated with aspecific stage in the session (SecurityNegotiation,
                                                     // LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
                                                     // next stage to which they want to move
#define ISCSI_LOGIN_REQS_FLAGS_GET_CURRENT_STAGE(x) (((x) >> 2) & 3)

#define ISCSI_LOGIN_REQ_FLAGS_CONTINUE      (1 << 6) // (C) When set to 1, this bit indicates that the text (set of key=value
                                                     // pairs) in this Login Request is not complete (it will be continued on
                                                     // subsequent Login Requests); otherwise, it indicates that this Login
                                                     // Request ends a set of key=value pairs. A Login Request with the
                                                     // C bit set to 1 MUST have the T bit set to 0.
#define ISCSI_LOGIN_REQ_FLAGS_TRANSMIT      (1 << 7) // (T) When set to 1, this bit indicates that the initiator is ready to
                                                     // transit to the next stage.
                                                     // If the T bit is set to 1 and the NSG is set to FullFeaturePhase, then
                                                     // this also indicates that the initiator is ready for the Login
                                                     // Final-Response.

/* After establishing a TCP connection between an initiator and a
   target, the initiator MUST start a Login Phase to gain further access
   to the target's resources.

   The Login Phase consists of a sequence of Login Requests and Login
   Responses that carry the same Initiator Task Tag.

   Login Requests are always considered as immediate.
*/
typedef struct __attribute__((packed)) iscsi_login_req_packet {
    uint8_t opcode; // Always 0x03 according to specification (see above)
    int8_t flags; // Login request flags (see above)
    uint8_t version_max; // Version-max indicates the maximum version number supported.
                         // All Login Requests within the Login Phase MUST carry the same
                         // Version-max. Currently, this is always 0
                         // The target MUST use the value presented with the first Login Request.
    uint8_t version_min; // All Login Requests within the Login Phase MUST carry the same
                         // Version-min. The target MUST use the value presented with the first
                         // Login Request. Always 0 for now
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
    struct iscsi_isid isid; // ISID (see above for declaration)
    uint16_t tsih; // The TSIH must be set in the first Login Request. The reserved value
                   // 0 MUST be used on the first connection for a new session. Otherwise,
                   // the TSIH sent by the target at the conclusion of the successful login
                   // of the first connection for this session MUST be used. The TSIH
                   // identifies to the target the associated existing session for this new
                   // connection.
                   // All Login Requests within a Login Phase MUST carry the same TSIH.
                   // The target MUST check the value presented with the first Login
                   // Request
    uint32_t init_task_tag; // Initiator task tag
    uint16_t cid; // Connection ID. The CID provides a unique ID for this connection within the session.
                  // All Login Requests within the Login Phase MUST carry the same CID.
                  // The target MUST use the value presented with the first Login Request.
                  // A Login Request with a non-zero TSIH and a CID equal to that of an
                  // existing connection implies a logout of the connection followed by a
                  // login
    uint16_t reserved; // Reserved for future usage
    uint32_t cmd_sn; // The CmdSN is either the initial command sequence number of a session
                     // (for the first Login Request of a session - the "leading" login) or
                     // the command sequence number in the command stream if the login is for
                     // a new connection in an existing session.
                     // Examples:
                     // - Login on a leading connection: If the leading login carries the
                     //   CmdSN 123, all other Login Requests in the same Login Phase carry
                     //   the CmdSN 123, and the first non-immediate command in the Full
                     //   Feature Phase also carries the CmdSN 123.
                     // - Login on other than a leading connection: If the current CmdSN at
                     //   the time the first login on the connection is issued is 500, then
                     //   that PDU carries CmdSN=500. Subsequent Login Requests that are
                     //   needed to complete this Login Phase may carry a CmdSN higher than
                     //   500 if non-immediate requests that were issued on other connections
                     //   in the same session advance the CmdSN.
                     // If the Login Request is a leading Login Request, the target MUST use
                     // the value presented in the CmdSN as the target value for the
                     // ExpCmdSN
    uint32_t exp_stat_sn; // For the first Login Request on a connection, this is the ExpStatSN
                          // for the old connection, and this field is only valid if the Login
                          // Request restarts a connection
                          // For subsequent Login Requests, it is used to acknowledge the Login
                          // Responses with their increasing StatSN values
    uint64_t reserved2[2]; // Reserved for future usage
    struct iscsi_ds_cmd_data ds_cmd_data; // Data segment - Login Parameters in Text Request Format
                                          // The initiator MUST provide some basic parameters in order
                                          // to enable the target to determine if the initiator may use
                                          // the target's resources and the initial text parameters for the security exchange
} iscsi_login_req_packet;

#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION          0x0 // SecurityNegotiation
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1 // LoginOperationalNegotiation
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FULL_FEATURE_PHASE            0x3 // FullFeaturePhase
#define ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE    (1 << 0) // (NSG) - Two bits - the Login negotiation requests and responses are
                                                          // associated with a specific stage in the session (SecurityNegotiation,
                                                          // LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
                                                          // next stage to which they want to move The Next Stage value is only
                                                          // valid when the T bit is 1; otherwise, it is reserved
#define ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(x) ((x) & 3)

#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION          0x0 // SecurityNegotiation
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION 0x1 // LoginOperationalNegotiation
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FULL_FEATURE_PHASE            0x3 // FullFeaturePhase
#define ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE (1 << 2) // (CSG) - Two bits - the Login negotiation requests and responses are
                                                          // associated with aspecific stage in the session (SecurityNegotiation,
                                                          // LoginOperationalNegotiation, FullFeaturePhase) and may indicate the
                                                          // next stage to which they want to move
#define ISCSI_LOGIN_RESPONSE_FLAGS_GET_CURRENT_STAGE(x) (((x) >> 2) & 3)

#define ISCSI_LOGIN_RESPONSE_FLAGS_CONTINUE      (1 << 6) // (C) When set to 1, this bit indicates that the text (set of key=value
                                                          // pairs) in this Login Response is not complete (it will be continued
                                                          // on subsequent Login Responses); otherwise, it indicates that this
                                                          // Login Response ends a set of key=value pairs. A Login Response with
                                                          // the C bit set to 1 MUST have the T bit set to 0
#define ISCSI_LOGIN_RESPONSE_FLAGS_TRANSMIT      (1 << 7) // (T) The T bit is set to 1 as an indicator of the end of the stage. If
                                                          // the T bit is set to 1 and the NSG is set to FullFeaturePhase, then
                                                          // this is also the Login Final-Response. A T bit of 0 indicates a
                                                          // "partial" response, which means "more negotiation needed".
                                                          // A Login Response with the T bit set to 1 MUST NOT contain key=value
                                                          // pairs that may require additional answers from the initiator within
                                                          // the same stage.
                                                          // If the Status-Class is 0, the T bit MUST NOT be set to 1 if the T bit
                                                          // in the request was set to 0

#define ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS 0x00 // Success - indicates that the iSCSI target successfully
                                                       // received, understood, and accepted the request. The numbering
                                                       // fields (StatSN, ExpCmdSN, MaxCmdSN) are only valid if Status-
                                                       // Class is 0
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SUCCESS 0x00 // Login is proceeding OK. If the response T bit is set to 1 in both the
                                                         // request and the matching response, and the NSG is set to
                                                         // FullFeaturePhase in both the request and the matching response, the
                                                         // Login Phase is finished, and the initiator may proceed to issue SCSI
                                                         // commands.

#define ISCSI_LOGIN_RESPONSE_STATUS_CLASS_REDIRECT 0x01 // Redirection - indicates that the initiator must take further
                                                        // action to complete the request. This is usually due to the
                                                        // target moving to a different address. All of the redirection
                                                        // Status-Class responses MUST return one or more text key
                                                        // parameters of the type "TargetAddress", which indicates the
                                                        // target's new address. A redirection response MAY be issued by
                                                        // a target prior to or after completing a security negotiation if
                                                        // a security negotiation is required. A redirection SHOULD be
                                                        // accepted by an initiator, even without having the target
                                                        // complete a security negotiation if any security negotiation is
                                                        // required, and MUST be accepted by the initiator after the
                                                        // completion of the security negotiation if any security
                                                        // negotiation is required
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_REDIRECT_TEMP 0x01 // The requested iSCSI Target Name (ITN) has temporarily moved
                                                               // to the address provided
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_REDIRECT_PERM 0x02 // The requested ITN has permanently moved to the address provided

#define ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR 0x02 // Initiator Error (not a format error) - indicates that the
                                                          // initiator most likely caused the error. This MAY be due to a
                                                          // request for a resource for which the initiator does not have
                                                          // permission. The request should not be tried again
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC                   0x00 // Miscellaneous iSCSI initiator errors
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR               0x01 // The initiator could not be successfully
                                                                                   // authenticated or target authentication is
                                                                                   // not supported
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_FAIL              0x02 // The initiator is not allowed access to the
                                                                                   // given target
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_NOT_FOUND              0x03 // The requested ITN does not exist at this
                                                                                   // address
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_TARGET_REMOVED         0x04 // The requested ITN has been removed, and
                                                                                   // no forwarding address is provided
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_WRONG_VERSION          0x05 // The requested iSCSI version range is not
                                                                                   // supported by the target
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_TOO_MANY_CONNECTIONS   0x06 // Too many connections on this SSID
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER      0x07 // Missing parameters (e.g. iSCSI Initiator
                                                                                   // Name and/or Target Name)
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_NO_SESSION_SPANNING    0x08 // arget does not support session spanning
                                                                                   // to this connection (address)
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_SESSION_NO_SUPPORT     0x09 // Target does not support this type of
                                                                                   // session or not from this initiator
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_SESSION_NO_EXIST       0x0A // Attempt to add a connection to a non-
                                                                                   // existent session
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_INVALID_LOGIN_REQ_TYPE 0x0B // Invalid request type during login

#define ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR 0x03 // Target Error - indicates that the target sees no errors in the
                                                          // initiator's Login Request but is currently incapable of
                                                          // fulfilling the request. The initiator may retry the same Login
                                                          // Request later
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_TARGET_ERROR        0x00 // Target hardware or software error
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_SERVICE_UNAVAILABLE 0x01 // The iSCSI service or target is not
                                                                                // currently operational
#define ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES    0x02 // The target has insufficient session,
                                                                                // connection, or other resources

/* The Login Response indicates the progress and/or end of the Login
   Phase.
*/
typedef struct __attribute__((packed)) iscsi_login_response_packet {
    uint8_t opcode; // Always 0x23 according to specification (see above)
    int8_t flags; // Login response flags (see above)
    uint8_t version_max; // This is the highest version number supported by the target.
                         // All Login Responses within the Login Phase MUST carry the same
                         // Version-max
    uint8_t version_active; // Version-active indicates the highest version supported by the target
                            // and initiator. If the target does not support a version within the
                            // range specified by the initiator, the target rejects the login and
                            // this field indicates the lowest version supported by the target.
                            // All Login Responses within the Login Phase MUST carry the same
                            // Version-active.
                            // The initiator MUST use the value presented as a response to the first
                            // Login Request
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
    struct iscsi_isid isid; // ISID (see above for declaration)
    uint16_t tsih; // The TSIH is the target-assigned session-identifying handle. Its
                   // internal format and content are not defined by this protocol, except
                   // for the value 0, which is reserved. With the exception of the Login
                   // Final-Response in a new session, this field should be set to the TSIH
                   // provided by the initiator in the Login Request. For a new session,
                   // the target MUST generate a non-zero TSIH and ONLY return it in the
                   // Login Final-Response
    uint32_t init_task_tag; // Initiator task tag
    uint32_t reserved; // Reserved for future usage
    uint32_t stat_sn; // For the first Login Response (the response to the first Login
                      // Request), this is the starting status sequence number for the
                      // connection. The next response of any kind - including the next
                      // Login Response, if any, in the same Login Phase - will carry this
                      // number + 1. This field is only valid if the Status-Class is 0
    uint32_t exp_cmd_sn; // ExpCmdSN
    uint32_t max_cmd_sn; // MaxCmdSN
    uint8_t status_class; // Status-class (see above for details). If the Status-Class is
                          // not 0, the initiator and target MUST close the TCP connection
                          // If the target wishes to reject the Login Request for more than one
                          // reason, it should return the primary reason for the rejection
    uint8_t status_detail; // Status-detail (see above for details)
    uint16_t reserved2; // Reserved for future usage
    uint64_t reserved3; // Reserved for future usage
    struct iscsi_ds_cmd_data ds_cmd_data; // Data segment - Login Parameters in Text Request Format
                                          // The target MUST provide some basic parameters in order to enable the
                                          // initiator to determine if it is connected to the correct port and the
                                          // initial text parameters for the security exchange.
                                          // All the rules specified for Text Responses also hold for Login
                                          // Responses
} iscsi_login_response_packet;

#define ISCSI_LOGOUT_REQ_REASON_CODE_CLOSE_SESSION              0x00 // Close the session. All commands associated with the
                                                                     // session (if any) are terminated
#define ISCSI_LOGOUT_REQ_REASON_CODE_CLOSE_CONNECTION           0x01 // Close the connection. All commands associated with the
                                                                     // connection (if any) are terminated
#define ISCSI_LOGOUT_REQ_REASON_CODE_REMOVE_CONNECTION_RECOVERY 0x02 // Remove the connection for recovery. The connection is
                                                                     // closed, and all commands associated with it, if any, are
                                                                     // to be prepared for a new allegiance

/* The entire logout discussion in this section is also applicable for
   an implicit Logout realized by way of a connection reinstatement or
   session reinstatement. When a Login Request performs an implicit
   Logout, the implicit Logout is performed as if having the reason
   codes specified below:
*/
#define ISCSI_LOGOUT_REQ_REASON_CODE_IMPLICIT_SESSION_REINSTATEMENT      0x00 // Session reinstatement
#define ISCSI_LOGOUT_REQ_REASON_CODE_IMPLICIT_CONNECTION_REINSTATEMENT   0x01 // connection reinstatement when the operational
                                                                              // ErrorRecoveryLevel < 2
#define ISCSI_LOGOUT_REQ_REASON_CODE_IMPLICIT_CONNECTION_REINSTATEMENT_2 0x02 // connection reinstatement when the operational
                                                                              // ErrorRecoveryLevel = 2

/* The Logout Request is used to perform a controlled closing of a
   connection.

   An initiator MAY use a Logout Request to remove a connection from a
   session or to close an entire session.

   After sending the Logout Request PDU, an initiator MUST NOT send any
   new iSCSI requests on the closing connection. If the Logout Request
   is intended to close the session, new iSCSI requests MUST NOT be sent
   on any of the connections participating in the session.

   When receiving a Logout Request with the reason code "close the
   connection" or "close the session", the target MUST terminate all
   pending commands, whether acknowledged via the ExpCmdSN or not, on
   that connection or session, respectively.

   When receiving a Logout Request with the reason code "remove the
   connection for recovery", the target MUST discard all requests not
   yet acknowledged via the ExpCmdSN that were issued on the specified
   connection and suspend all data/status/R2T transfers on behalf of
   pending commands on the specified connection.

   The target then issues the Logout Response and half-closes the TCP
   connection (sends FIN). After receiving the Logout Response and
   attempting to receive the FIN (if still possible), the initiator MUST
   completely close the logging-out connection. For the terminated
   commands, no additional responses should be expected.

   A Logout for a CID may be performed on a different transport
   connection when the TCP connection for the CID has already been
   terminated. In such a case, only a logical "closing" of the iSCSI
   connection for the CID is implied with a Logout.

   All commands that were not terminated or not completed (with status)
   and acknowledged when the connection is closed completely can be
   reassigned to a new connection if the target supports connection
   recovery.

   If an initiator intends to start recovery for a failing connection,
   it MUST use the Logout Request to "clean up" the target end of a
   failing connection and enable recovery to start, or use the Login
   Request with a non-zero TSIH and the same CID on a new connection for
   the same effect. In sessions with a single connection, the
   connection can be closed and then a new connection reopened. A
   connection reinstatement login can be used for recovery.

   A successful completion of a Logout Request with the reason code
   "close the connection" or "remove the connection for recovery"
   results at the target in the discarding of unacknowledged commands
   received on the connection being logged out. These are commands that
   have arrived on the connection being logged out but that have not
   been delivered to SCSI because one or more commands with a smaller
   CmdSN have not been received by iSCSI. The resulting holes in the
   command sequence numbers will have to be handled by appropriate
   recovery, unless the session is also closed.
*/
typedef struct __attribute__((packed)) iscsi_logout_req_packet {
    uint8_t opcode; // Always 0x06 according to specification (see above)
    int8_t reason_code; // Reason Code
                        // A target implicitly terminates the active tasks due to the iSCSI
                        // protocol in the following cases:
                        // a) When a connection is implicitly or explicitly logged out with
                        //    the reason code "close the connection" and there are active
                        //    tasks allegiant to that connection.
                        // b) When a connection fails and eventually the connection state
                        //    times out and there are active tasks allegiant to that
                        //    connection
                        // c) When a successful recovery Logout is performed while there are
                        //    active tasks allegiant to that connection and those tasks
                        //    eventually time out after the Time2Wait and Time2Retain periods
                        //    without allegiance reassignment
                        // d) When a connection is implicitly or explicitly logged out with
                        //    the reason code "close the session" and there are active tasks
                        //    in that session
                        // If the tasks terminated in any of the above cases are SCSI tasks,
                        // they must be internally terminated as if with CHECK CONDITION status.
                        // This status is only meaningful for appropriately handling the
                        // internal SCSI state and SCSI side effects with respect to ordering,
                        // because this status is never communicated back as a terminating
                        // status to the initiator. However, additional actions may have to be
                        // taken at the SCSI level, depending on the SCSI context as defined by
                        // the SCSI standards (e.g., queued commands and ACA; UA for the next
                        // command on the I_T nexus in cases a), b), and c) above). After the
                        // tasks are terminated, the target MUST report a Unit Attention condition
                        // on the next command processed on any connection for each affected
                        // I_T_L nexus with the status of CHECK CONDITION, the ASC/ASCQ value
                        // of 0x47 / 0x7F ("SOME COMMANDS CLEARED BY ISCSI PROTOCOL EVENT"), etc.
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength (MUST be 0 for this PDU)
    uint8_t ds_len[3]; // DataSegmentLength (MUST be 0 for this PDU)
    uint64_t reserved2; // Reserved for future usage
    uint32_t init_task_tag; // Initiator task tag
    uint16_t cid; // This is the connection ID of the connection to be closed (including
                  // closing the TCP stream). This field is only valid if the reason code
                  // is not "close the session"
    uint16_t reserved3; // Reserved for future usage
    uint32_t cmd_sn; // CmdSN
    uint32_t exp_stat_sn; // This is the last ExpStatSN value for the connection to be closed
    uint64_t reserved4[2]; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
} iscsi_logout_req_packet;

#define ISCSI_LOGOUT_RESPONSE_CLOSED_SUCCESSFULLY               0x00 // Connection or session closed successfully
#define ISCSI_LOGOUT_RESPONSE_CID_NOT_FOUND                     0x01 // CID not found
#define ISCSI_LOGOUT_RESPONSE_CONNECTION_RECOVERY_NOT_SUPPORTED 0x02 // Connection recovery is not supported (i.e., the Logout reason
                                                                     // code was "remove the connection for recovery" and the target
                                                                     // does not support it as indicated by the operational
                                                                     // ErrorRecoveryLevel)
#define ISCSI_LOGOUT_RESPONSE_CLEANUP_FAILED                    0x03 // Cleanup failed for various reasons

/* The Logout Response is used by the target to indicate if the cleanup
   operation for the connection(s) has completed.

   After Logout, the TCP connection referred by the CID MUST be closed
   at both ends (or all connections must be closed if the logout reason
   was session close).
*/
typedef struct __attribute__((packed)) iscsi_logout_response_packet {
    uint8_t opcode; // Always 0x26 according to specification (see above)
    uint8_t flags; // Reserved for future usage
    uint8_t response; // Response
    uint8_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength (MUST be 0 for this PDU)
    uint8_t ds_len[3]; // DataSegmentLength (MUST be 0 for this PDU)
    uint64_t reserved2; // Reserved for future usage
    uint32_t init_task_tag; // Initiator task tag
    uint32_t reserved3; // Reserved for future usage
    uint32_t stat_sn; // StatSN
    uint32_t exp_cmd_sn; // ExpCmdSN
    uint32_t max_cmd_sn; // MaxCmdSN
    uint32_t reserved4; // Reserved for future usage
    uint16_t time_wait; // Time2Wait
                        // If the Logout response code is 0 and the operational
                        // ErrorRecoveryLevel is 2, this is the minimum amount of time, in
                        // seconds, to wait before attempting task reassignment. If the Logout
                        // response code is 0 and the operational ErrorRecoveryLevel is less
                        // than 2, this field is to be ignored.
                        // This field is invalid if the Logout response code is 1.
                        // If the Logout response code is 2 or 3, this field specifies the
                        // minimum time to wait before attempting a new implicit or explicit
                        // logout.
                        // If Time2Wait is 0, the reassignment or a new Logout may be attempted
                        // immediately
    uint16_t time_retain; // Time2Retain
                          // If the Logout response code is 0 and the operational
                          // ErrorRecoveryLevel is 2, this is the maximum amount of time, in
                          // seconds, after the initial wait (Time2Wait) that the target waits for
                          // the allegiance reassignment for any active task, after which the task
                          // state is discarded. If the Logout response code is 0 and the
                          // operational ErrorRecoveryLevel is less than 2, this field is to be
                          // ignored.
                          // This field is invalid if the Logout response code is 1.
                          // If the Logout response code is 2 or 3, this field specifies the
                          // maximum amount of time, in seconds, after the initial wait
                          // (Time2Wait) that the target waits for a new implicit or explicit
                          // logout.
                          // If it is the last connection of a session, the whole session state is
                          // discarded after Time2Retain.
                          // If Time2Retain is 0, the target has already discarded the connection
                          // (and possibly the session) state along with the task states. No
                          // reassignment or Logout is required in this case
    uint32_t reserved5; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
} iscsi_logout_response_packet;

#define ISCSI_SNACK_REQ_TYPE_DATA_R2T_SNACK 0x00 // Data/R2T SNACK: requesting retransmission of one or more
                                                 // Data-In or R2T PDUs
#define ISCSI_SNACK_REQ_TYPE_STATUS_SNACK   0x01 // Status SNACK: requesting retransmission of one or more
                                                 // numbered responses
#define ISCSI_SNACK_REQ_TYPE_DATA_ACK       0x02 // DataACK: positively acknowledges Data-In PDUs.
                                                 // If an initiator operates at ErrorRecoveryLevel 1 or higher, it MUST
                                                 // issue a SNACK of type DataACK after receiving a Data-In PDU with the
                                                 // A bit set to 1. However, if the initiator has detected holes in the
                                                 // input sequence, it MUST postpone issuing the SNACK of type DataACK
                                                 // until the holes are filled. An initiator MAY ignore the A bit if it
                                                 // deems that the bit is being set aggressively by the target (i.e.,
                                                 // before the MaxBurstLength limit is reached).
                                                 // The DataACK is used to free resources at the target and not to
                                                 // request or imply data retransmission.
                                                 // An initiator MUST NOT request retransmission for any data it had
                                                 // already acknowledged
#define ISCSI_SNACK_REQ_TYPE_R_DATA_SNACK   0x03 // R-Data SNACK: requesting retransmission of Data-In PDUs with
                                                 // possible resegmentation and status tagging.
                                                 // If the initiator MaxRecvDataSegmentLength changed between the
                                                 // original transmission and the time the initiator requests
                                                 // retransmission, the initiator MUST issue a R-Data SNACK.
                                                 // With R-Data SNACK, the initiator indicates that it discards all the
                                                 // unacknowledged data and expects the target to resend it. It also
                                                 // expects resegmentation. In this case, the retransmitted Data-In PDUs
                                                 // MAY be different from the ones originally sent in order to reflect
                                                 // changes in MaxRecvDataSegmentLength. Their DataSN starts with the
                                                 // BegRun of the last DataACK received by the target if any was received;
                                                 // otherwise, it starts with 0 and is increased by 1 for each resent
                                                 // Data-In PDU.
                                                 // A target that has received a R-Data SNACK MUST return a SCSI Response
                                                 // that contains a copy of the SNACK Tag field from the R-Data SNACK in
                                                 // the SCSI Response SNACK Tag field as its last or only Response. For
                                                 // example, if it has already sent a response containing another value
                                                 // in the SNACK Tag field or had the status included in the last Data-In
                                                 // PDU, it must send a new SCSI Response PDU. If a target sends more
                                                 // than one SCSI Response PDU due to this rule, all SCSI Response PDUs
                                                 // must carry the same StatSN. If an initiator attempts to recover a lost
                                                 // SCSI Response when more than one response has been sent, the
                                                 // target will send the SCSI Response with the latest content known to
                                                 // the target, including the last SNACK Tag for the command.
                                                 // For considerations in allegiance reassignment of a task to a
                                                 // connection with a different MaxRecvDataSegmentLength.

/* If the implementation supports ErrorRecoveryLevel greater than zero,
   it MUST support all SNACK types.

   The SNACK is used by the initiator to request the retransmission of
   numbered responses, data, or R2T PDUs from the target. The SNACK
   Request indicates the numbered responses or data "runs" whose
   retransmission is requested, where the run starts with the first
   StatSN, DataSN, or R2TSN whose retransmission is requested and
   indicates the number of Status, Data, or R2T PDUs requested,
   including the first. 0 has special meaning when used as a starting
   number and length:

      - When used in RunLength, it means all PDUs starting with the
        initial.

      - When used in both BegRun and RunLength, it means all
        unacknowledged PDUs.

   The numbered response(s) or R2T(s) requested by a SNACK MUST be
   delivered as exact replicas of the ones that the target transmitted
   originally, except for the fields ExpCmdSN, MaxCmdSN, and ExpDataSN,
   which MUST carry the current values. R2T(s)requested by SNACK MUST
   also carry the current value of the StatSN.

   The numbered Data-In PDUs requested by a Data SNACK MUST be delivered
   as exact replicas of the ones that the target transmitted originally,
   except for the fields ExpCmdSN and MaxCmdSN, which MUST carry the
   current values; and except for resegmentation.

   Any SNACK that requests a numbered response, data, or R2T that was
   not sent by the target or was already acknowledged by the initiator
   MUST be rejected with a reason code of "Protocol Error".
*/
typedef struct __attribute__((packed)) iscsi_snack_req_packet {
    uint8_t opcode; // Always 0x10 according to specification (see above)
    int8_t type; // Type
                 // Data/R2T SNACK, Status SNACK, or R-Data SNACK for a command MUST
                 // precede status acknowledgment for the given command
    uint16_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
    uint64_t lun; // LUN or Reserved
    uint32_t init_task_tag; // For a Status SNACK and DataACK, the Initiator Task Tag MUST be set to
                            // the reserved value 0xFFFFFFFF. In all other cases, the Initiator
                            // Task Tag field MUST be set to the Initiator Task Tag of the
                            // referenced command
    uint32_t target_xfer_snack_tag; // For a R-Data SNACK, this field MUST contain a value that is different
                                    // from 0 or 0xFFFFFFFF and is unique for the task (identified by the
                                    // Initiator Task Tag). This value MUST be copied by the iSCSI target
                                    // in the last or only SCSI Response PDU it issues for the command.
                                    // For DataACK, the Target Transfer Tag MUST contain a copy of the
                                    // Target Transfer Tag and LUN provided with the SCSI Data-In PDU with
                                    // the A bit set to 1.
                                    // In all other cases, the Target Transfer Tag field MUST be set to the
                                    // reserved value 0xFFFFFFFF
    uint32_t reserved2; // Reserved for future usage
    uint32_t exp_stat_sn; // ExpStatSN
    uint32_t reserved3; // Reserved for future usage
    uint32_t beg_run; // BegRun
                      // This field indicates the DataSN, R2TSN, or StatSN of the first PDU
                      // whose retransmission is requested (Data/R2T and Status SNACK), or the
                      // next expected DataSN (DataACK SNACK).
                      // A BegRun of 0, when used in conjunction with a RunLength of 0, means
                      // "resend all unacknowledged Data-In, R2T or Response PDUs".
                      // BegRun MUST be 0 for a R-Data SNACK
    uint32_t run_len; // RunLength
                      // This field indicates the number of PDUs whose retransmission is
                      // requested.
                      // A RunLength of 0 signals that all Data-In, R2T, or Response PDUs
                      // carrying the numbers equal to or greater than BegRun have to be
                      // resent.
                      // The RunLength MUST also be 0 for a DataACK SNACK in addition to a
                      // R-Data SNACK
    struct iscsi_header_digest hdr_digest; // Optional header digest
} iscsi_snack_req_packet;

#define ISCSI_REJECT_REASON_RESERVED                    0x01 // Reserved, original PDU can't be resent
#define ISCSI_REJECT_REASON_DATA_DIGEST_ERR             0x02 // Data (payload) digest error, original
                                                             // PDU can be resent.
                                                             // For iSCSI, Data-Out PDU retransmission is only done if the
                                                             // target requests retransmission with a recovery R2T. However,
                                                             // if this is the data digest error on immediate data, the
                                                             // initiator may choose to retransmit the whole PDU, including
                                                             // the immediate data
#define ISCSI_REJECT_REASON_SNACK_REJECT                0x03 // SNACK Reject (original PDU can be resent)
#define ISCSI_REJECT_REASON_PROTOCOL_ERR                0x04 // Protocol Error (e.g., SNACK Request for a status that was
                                                             // already acknowledged). Original PDU can't be resent'
#define ISCSI_REJECT_REASON_COMMAND_NOT_SUPPORTED       0x05 // Command not supported (original PDU can't be resent)
#define ISCSI_REJECT_REASON_TOO_MANY_IMMEDIATE_COMMANDS 0x06 // Immediate command reject - too many immediate
                                                             // commands (original PDU can be resent)
#define ISCSI_REJECT_REASON_TASK_IN_PROGRESS            0x07 // Task in progress (original PDU can't be resent)
#define ISCSI_REJECT_REASON_INVALID_DATA_ACK            0x08 // Invalid data ack (original PDU can't be resent)
#define ISCSI_REJECT_REASON_INVALID_PDU_FIELD           0x09 // Invalid PDU field, original PDU can't be resent.
                                                             // A target should use this reason code for all invalid values
                                                             // of PDU fields that are meant to describe a task, a response,
                                                             // or a data transfer. Some examples are invalid TTT/ITT,
                                                             // buffer offset, LUN qualifying a TTT, and an invalid sequence
                                                             // number in a SNACK
#define ISCSI_REJECT_REASON_OUT_OF_RESOURCES            0x0A // Long op reject - Can't generate Target Transfer Tag - out of
                                                             // resources. Original PDU can be resent later
#define ISCSI_REJECT_REASON_DEPRECATED                  0x0B // Deprecated; MUST NOT be used. Reason code 0x0B is deprecated
                                                             // and MUST NOT be used by implementations. An implementation
                                                             // receiving reason code 0x0B MUST treat it as a negotiation
                                                             // failure that terminates the Login Phase and the TCP connection
#define ISCSI_REJECT_REASON_WAITING_FOR_LOGOUT          0x0C // Waiting for Logout, original PDU can't be resent

typedef struct __attribute__((packed)) iscsi_reject_packet {
    uint8_t opcode; // Always 0x3F according to specification (see above)
    uint8_t flags; // Reserved for future usage
    uint8_t reason; // Reject reason (see above for definitions).
                    // In all the cases in which a pre-instantiated SCSI task is terminated
                    // because of the reject, the target MUST issue a proper SCSI command
                    // response with CHECK CONDITION. In these cases in which a status for
                    // the SCSI task was already sent before the reject, no additional
                    // status is required. If the error is detected while data from the
                    // initiator is still expected (i.e., the command PDU did not contain
                    // all the data and the target has not received a Data-Out PDU with the
                    // Final bit set to 1 for the unsolicited data, if any, and all
                    // outstanding R2Ts, if any), the target MUST wait until it receives
                    // the last expected Data-Out PDUs with the F bit set to 1 before
                    // sending the Response PDU
    uint8_t reserved; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
    uint64_t reserved2; // Reserved for future usage
    uint32_t tag; // Always 0xFFFFFFFF for now
    uint32_t reserved3; // Reserved for future usage
    uint32_t stat_sn; // StatSN. This field carries its usual value and is not related to the
                      // rejected command. The StatSN is advanced after a Reject
    uint32_t exp_cmd_sn; // ExpCmdSN. This field carries its usual value and is not related to the
                         // rejected command
    uint32_t max_cmd_sn; // MaxCmdSN. This field carries its usual value and is not related to the
                         // rejected command
    uint32_t data_r2tsn_sn; // DataSN/R2TSN or Reserved.
                            // This field is only valid if the rejected PDU is a Data/R2T SNACK and
                            // the Reject reason code is "Protocol Error". The DataSN/R2TSN is the
                            // next Data/R2T sequence number that the target would send for the
                            // task, if any
    uint32_t reserved4[2]; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_bhs_packet bad_pdu_hdr; // Complete Header of Bad PDU. The target returns the
                                         // header (not including the digest) of the PDU in error
                                         // as the data of the response
    uint8_t vendor_data[0]; // Vendor-specific data (if any)
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_reject_packet;

/* NOP-Out may be used by an initiator as a "ping request" to verify
   that a connection/session is still active and all its components are
   operational. The NOP-In response is the "ping echo".

   A NOP-Out is also sent by an initiator in response to a NOP-In.

   A NOP-Out may also be used to confirm a changed ExpStatSN if another
   PDU will not be available for a long time.

   Upon receipt of a NOP-In with the Target Transfer Tag set to a valid
   value (not the reserved value 0xffffffff), the initiator MUST respond
   with a NOP-Out. In this case, the NOP-Out Target Transfer Tag MUST
   contain a copy of the NOP-In Target Transfer Tag. The initiator

   SHOULD NOT send a NOP-Out in response to any other received NOP-In,
   in order to avoid lengthy sequences of NOP-In and NOP-Out PDUs sent
   in response to each other.
*/
typedef struct __attribute__((packed)) iscsi_nop_out_packet {
    uint8_t opcode; // Always 0x00 according to specification (see above)
    uint8_t reserved[3]; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
    uint64_t lun; // LUN or Reserved
    uint32_t init_task_tag; // The NOP-Out MUST have the Initiator Task Tag set to a valid value
                            // only if a response in the form of a NOP-In is requested (i.e., the
                            // NOP-Out is used as a ping request). Otherwise, the Initiator Task
                            // Tag MUST be set to 0xFFFFFFFF.
                            // When a target receives the NOP-Out with a valid Initiator Task Tag,
                            // it MUST respond with a NOP-In Response.
                            // If the Initiator Task Tag contains 0xFFFFFFFF, the I bit MUST be set
                            // to 1, and the CmdSN is not advanced after this PDU is sent
    uint32_t target_xfer_tag; // The Target Transfer Tag is a target-assigned identifier for the
                              // operation.
                              // The NOP-Out MUST only have the Target Transfer Tag set if it is
                              // issued in response to a NOP-In with a valid Target Transfer Tag. In
                              // this case, it copies the Target Transfer Tag from the NOP-In PDU.
                              // Otherwise, the Target Transfer Tag MUST be set to 0xFFFFFFFF.
                              // When the Target Transfer Tag is set to a value other than 0xFFFFFFFF,
                              // the LUN field MUST also be copied from the NOP-In
    uint32_t cmd_sn; // CmdSN
    uint32_t exp_stat_sn; // ExpStatSN
    uint64_t reserved2[2]; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_ds_cmd_data ds_ping_data; // DataSegment - Ping Data (optional)
                                           // Ping data is reflected in the NOP-In Response. The length of the
                                           // reflected data is limited to MaxRecvDataSegmentLength. The length of
                                           // ping data is indicated by the DataSegmentLength. 0 is a valid value
                                           // for the DataSegmentLength and indicates the absence of ping data
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_nop_out_packet;

/*  NOP-In is sent by a target as either a response to a NOP-Out, a
   "ping" to an initiator, or a means to carry a changed ExpCmdSN and/or
   MaxCmdSN if another PDU will not be available for a long time (as
   determined by the target).

   When a target receives the NOP-Out with a valid Initiator Task Tag
   (not the reserved value 0xFFFFFFFF), it MUST respond with a NOP-In
   with the same Initiator Task Tag that was provided in the NOP-Out
   request. It MUST also duplicate up to the first
   MaxRecvDataSegmentLength bytes of the initiator-provided Ping Data.
   For such a response, the Target Transfer Tag MUST be 0xFFFFFFFF. The

   target SHOULD NOT send a NOP-In in response to any other received
   NOP-Out in order to avoid lengthy sequences of NOP-In and NOP-Out
   PDUs sent in response to each other.

   Otherwise, when a target sends a NOP-In that is not a response to a
   NOP-Out received from the initiator, the Initiator Task Tag MUST be
   set to 0xFFFFFFFF, and the data segment MUST NOT contain any data
   (DataSegmentLength MUST be 0).
*/

typedef struct __attribute__((packed)) iscsi_nop_in_packet {
    uint8_t opcode; // Always 0x20 according to specification (see above)
    uint8_t reserved[3]; // Reserved for future usage
    uint8_t total_ahs_len; // TotalAHSLength
    uint8_t ds_len[3]; // DataSegmentLength
    uint64_t lun; // A LUN MUST be set to a correct value when the Target Transfer Tag is
                  // valid (not the reserved value 0xFFFFFFFF)
    uint32_t init_task_tag; // Initiator task tag or 0xFFFFFFFF
    uint32_t target_xfer_tag; // If the target is responding to a NOP-Out, this field is set to the
                              // reserved value 0xFFFFFFFF.
                              // If the target is sending a NOP-In as a ping (intending to receive a
                              // corresponding NOP-Out), this field is set to a valid value (not the
                              // reserved value 0xFFFFFFFF).
                              // If the target is initiating a NOP-In without wanting to receive a
                              // corresponding NOP-Out, this field MUST hold the reserved value
                              // 0xFFFFFFFF
    uint32_t stat_sn; // The StatSN field will always contain the next StatSN. However, when
                      // the Initiator Task Tag is set to 0xFFFFFFFF, the StatSN for the
                      // connection is not advanced after this PDU is sent
    uint32_t exp_cmd_sn; // ExpCmdSN
    uint32_t max_cmd_sn; // MaxCmdSN
    uint32_t reserved2[3]; // Reserved for future usage
    struct iscsi_header_digest hdr_digest; // Optional header digest
    struct iscsi_ds_cmd_data ds_ping_data; // DataSegment - Return Ping Data
    struct iscsi_data_digest data_digest; // Optional data digest
} iscsi_nop_in_packet;

#define ISCSI_VALIDATE_PACKET_RESULT_OK                         0L // Validation successful -> iSCSI packet recognized and compliance to protocol specification
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_NO_DATA             -1L // Validation failed -> No packet data specified
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_SIZE_TOO_SMALL      -2L // Validation failed -> Packet size smaller than smallest possible iSCSI packet
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_SIZE_MISMATCH       -3L // Validation failed -> Packet size doesn't match calculated lengths from BHS
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_UNSUPPORTED_VERSION -4L // Validation failed -> iSCSI protocol version not supported yet
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_PROTOCOL_SPECS      -5L // Validation failed -> Valid opcode but violates iSCSI protocol specification
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_INVALID_OPCODE      -6L // Validation failed -> Invalid opcode according to iSCSI protocol specification
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_CRC32C_HDR_DIGEST   -7L // Validation failed -> CRC32C check failed for header (BHS and/or AHS)
#define ISCSI_VALIDATE_PACKET_RESULT_ERROR_CRC32C_DATA_DIGEST  -8L // Validation failed -> CRC32C check failed for data segment

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
static int iscsi_validate_text_key_value_pair(const uint8_t *packet_data, const uint32_t len); // Validates a single text key / value pair according to iSCSI specs
static int iscsi_validate_key_value_pairs(const uint8_t *packet_data, uint len); // Validates all text key / value pairs according to iSCSI specs
int iscsi_validate_packet(const struct iscsi_bhs_packet *packet_data, const uint32_t len, const int header_digest_size, const int data_digest_size); // Check if valid iSCSI packet and validate if necessarily

#define ISCSI_TEXT_KEY_MAX_LEN 63UL // Maximum length of a key according to iSCSI specs

#define ISCSI_TEXT_VALUE_MAX_SIMPLE_LEN 255UL  // Maximum length of value for a simple key type
#define ISCSI_TEXT_VALUE_MAX_LEN        8192UL // Maximum length of value for a normal key

#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_INVALID         -1L // Invalid
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_UNSPECIFIED      0L // Unspecified type
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_LIST             1L // List
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MIN          2L // Numerical minimum
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_MAX          3L // Numerical maximum
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_NUM_DECLARATIVE  4L // Numerical declarative
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_DECLARATIVE      5L // Declarative
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_OR          6L // Boolean OR
#define ISCSI_TEXT_KEY_VALUE_PAIR_TYPE_BOOL_AND         7L // Boolean AND

typedef struct iscsi_key_value_pair {
	int type; // Type of pair (see above)
	int state_index;
	uint8_t *value; // Value of key
} iscsi_key_value_pair;

typedef struct iscsi_key_value_pair_packet {
    uint8_t *buf; // Current text buffer containing multiple zeroes
    uint len; // Current length of buffer including final zero terminator
} iscsi_key_value_pair_packet;

static int iscsi_parse_text_key_value_pair(iscsi_hashmap *pairs, const uint8_t *packet_data, const uint32_t len); // Extracts a single text key / value pairs out of an iSCSI packet into a hash map
int iscsi_parse_key_value_pairs(iscsi_hashmap **pairs, const uint8_t *packet_data, uint len, int cbit, uint8_t **partial_pair); // Extracts all text key / value pairs out of an iSCSI packet into a hash map
int iscsi_create_key_value_pair_packet_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // Creates a single partial iSCSI packet stream out of a single text key and value pair
iscsi_key_value_pair_packet *iscsi_create_key_value_pairs_packet(const iscsi_hashmap *pairs); // Creates a properly aligned iSCSI packet DataSegment out of a hash map containing text key and value pairs

typedef struct iscsi_connection {
    iscsi_hashmap *key_value_pairs; // Hash map containing text key / value pairs associated to this connection
    int header_digest; // iSCSI connection contains a header digest (CRC32), must be 0 or 4 for now
    int data_digest; // iSCSI connection contains a data digest (CRC32), must be 0 or 4 for now
    uint8_t opcode; // Always 0x03 according to specification (see above)
    int8_t flags; // Login request flags (see above)
    uint8_t version_max; // Version-max indicates the maximum version number supported.
                         // All Login Requests within the Login Phase MUST carry the same
                         // Version-max. Currently, this is always 0
                         // The target MUST use the value presented with the first Login Request.
    uint8_t version_min; // All Login Requests within the Login Phase MUST carry the same
                         // Version-min. The target MUST use the value presented with the first
                         // Login Request. Always 0 for now
    struct iscsi_isid isid; // ISID (see above for declaration)
    uint16_t tsih; // The TSIH must be set in the first Login Request. The reserved value
                   // 0 MUST be used on the first connection for a new session. Otherwise,
                   // the TSIH sent by the target at the conclusion of the successful login
                   // of the first connection for this session MUST be used. The TSIH
                   // identifies to the target the associated existing session for this new
                   // connection.
                   // All Login Requests within a Login Phase MUST carry the same TSIH.
                   // The target MUST check the value presented with the first Login
                   // Request
    uint32_t init_task_tag; // Initiator task tag
    uint16_t cid; // Connection ID. The CID provides a unique ID for this connection within the session.
                  // All Login Requests within the Login Phase MUST carry the same CID.
                  // The target MUST use the value presented with the first Login Request.
                  // A Login Request with a non-zero TSIH and a CID equal to that of an
                  // existing connection implies a logout of the connection followed by a
                  // login
    uint32_t cmd_sn; // The CmdSN is either the initial command sequence number of a session
                     // (for the first Login Request of a session - the "leading" login) or
                     // the command sequence number in the command stream if the login is for
                     // a new connection in an existing session.
                     // Examples:
                     // - Login on a leading connection: If the leading login carries the
                     //   CmdSN 123, all other Login Requests in the same Login Phase carry
                     //   the CmdSN 123, and the first non-immediate command in the Full
                     //   Feature Phase also carries the CmdSN 123.
                     // - Login on other than a leading connection: If the current CmdSN at
                     //   the time the first login on the connection is issued is 500, then
                     //   that PDU carries CmdSN=500. Subsequent Login Requests that are
                     //   needed to complete this Login Phase may carry a CmdSN higher than
                     //   500 if non-immediate requests that were issued on other connections
                     //   in the same session advance the CmdSN.
                     // If the Login Request is a leading Login Request, the target MUST use
                     // the value presented in the CmdSN as the target value for the
                     // ExpCmdSN
    uint32_t exp_stat_sn; // For the first Login Request on a connection, this is the ExpStatSN
                          // for the old connection, and this field is only valid if the Login
                          // Request restarts a connection
                          // For subsequent Login Requests, it is used to acknowledge the Login
                          // Responses with their increasing StatSN values
} iscsi_connection;

iscsi_connection *iscsi_connection_create(const iscsi_login_req_packet *login_req_pkt); // Creates data structure for an iSCSI connection request
void iscsi_connection_destroy(iscsi_connection *conn); // Deallocates all resources acquired by iscsi_connection_create
int iscsi_connection_destroy_callback(uint8_t *key, const size_t key_size, uint8_t *value, uint8_t *user_data); // iSCSI connection destructor callback for hash map

#endif /* DNBD3_ISCSI_H_ */
