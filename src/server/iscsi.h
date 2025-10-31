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

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <dnbd3/types.h>

#include "globals.h"

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
#define ISCSI_STRLEN(x) ((sizeof(x) / sizeof(uint8_t)) - 1)


/* iSCSI protocol stuff (all WORD/DWORD/QWORD values are big endian by default
   unless specified otherwise). */

/// iSCSI Basic Header Segment (BHS) size.
#define ISCSI_BHS_SIZE 48UL

/// iSCSI Advanced Header Segment (AHS) maximum allowed size.
#define ISCSI_MAX_AHS_SIZE (255UL << 2UL)

/// iSCSI DataSegment maximum allowed size.
#define ISCSI_MAX_DS_SIZE 16777215

/// iSCSI packet data alignment (BHS, AHS and DataSegment).
#define ISCSI_ALIGN_SIZE 4UL

/// iSCSI header and data digest size (CRC32C).
#define ISCSI_DIGEST_SIZE 4UL


/// iSCSI Default receive DataSegment (DS) size in bytes.
#define ISCSI_DEFAULT_RECV_DS_LEN 16384UL

/// iSCSI default maximum DataSegment receive length in bytes.
#define ISCSI_DEFAULT_MAX_RECV_DS_LEN 524288UL


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

#define ASSERT_IS_BHS(structname) _Static_assert( sizeof(structname) == ISCSI_BHS_SIZE, #structname " messed up" )

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
ASSERT_IS_BHS( iscsi_bhs_packet );



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
} iscsi_ahs_packet;

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
	uint8_t data[15];
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
	uint8_t opcode;

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
	uint8_t opcode;

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
	uint8_t opcode;

	/// Flags.
	uint8_t flags;

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
	uint8_t opcode;

	/// Flags.
	uint8_t flags;

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
	uint8_t opcode;

	/// Flags.
	uint8_t flags;

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
	uint8_t opcode;

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
	uint8_t opcode;

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
	uint8_t opcode;

	/// Flags.
	uint8_t flags;

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
	uint8_t opcode;

	/// Flags.
	uint8_t flags;

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
	uint8_t sense_data[];
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
	uint8_t flags;

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
	uint8_t flags;

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
	uint8_t params[];
} iscsi_scsi_vpd_page_inquiry_data_packet;


/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: iSCSI.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_ISCSI     0x05

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: First bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT 4

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data protocol identifier: Last bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_LAST_BIT  ((ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PROTOCOL_ID_FIRST_BIT) + 8 - 1)

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
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT    0

/// iSCSI SCSI Vital Product Data (VPD) Page Designation Descriptor Inquiry data code set: Last bit of the four bits.
#define ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_LAST_BIT     ((ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_FIRST_BIT) + 4 - 1)

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
	uint8_t flags;

	/// Reserved for future usage (always MUST be 0).
	uint8_t reserved;

	/// Length in bytes.
	uint8_t len;

	/// Designation descriptor.
	uint8_t desc[];
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
	uint8_t flags;

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
	uint8_t flags;

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
	uint32_t field_rep_unit_code;

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
	uint8_t flags;

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
	uint8_t flags;

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
	uint8_t flags;

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
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_mode_page_data_header {
	/// Page code and flags.
	uint8_t page_code_flags;

	/// Page length in bytes.
	uint8_t page_len;
} iscsi_scsi_mode_sense_mode_page_data_header;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) mode sub page packet data.
 *
 * This returns mode sub page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_mode_sub_page_data_header {
	/// Page code and flags.
	uint8_t page_code_flags;

	/// Sub page code.
	uint8_t sub_page_code;

	/// Page length in bytes.
	uint16_t page_len;
} iscsi_scsi_mode_sense_mode_sub_page_data_header;


/**
 * @brief iSCSI SCSI command MODE SENSE(6) and MODE SENSE(10) read/write error recovery mode page packet data.
 *
 * This returns mode page specific data.
 */
typedef struct __attribute__((packed)) iscsi_scsi_mode_sense_read_write_err_recovery_mode_page_data_packet {
	/// Mode page.
	iscsi_scsi_mode_sense_mode_page_data_header mode_page;

	/// Flags.
	uint8_t flags;

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
	iscsi_scsi_mode_sense_mode_page_data_header mode_page;

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
	iscsi_scsi_mode_sense_mode_page_data_header mode_page;

	/// Flags.
	uint8_t flags;

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
	iscsi_scsi_mode_sense_mode_page_data_header mode_page;

	/// Flags.
	uint8_t flags;

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
	iscsi_scsi_mode_sense_mode_page_data_header mode_page;

	/// Flags.
	uint8_t flags;

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
	iscsi_scsi_mode_sense_mode_sub_page_data_header mode_sub_page;

	/// Flags.
	uint8_t flags;

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
	iscsi_scsi_mode_sense_mode_page_data_header mode_page;

	/// Flags.
	uint8_t flags;

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
	iscsi_scsi_mode_sense_mode_page_data_header mode_page;

	/// Flags.
	uint8_t flags;

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
	iscsi_scsi_mode_sense_mode_page_data_header mode_page;

	/// Flags.
	uint8_t flags;

	/// Method Of Reporting Informational Exceptions (MRIE) flags.
	uint8_t mrie;

	/// Interval timer.
	uint32_t interval_timer;

	/// Report count.
	uint32_t report_cnt;
} iscsi_scsi_mode_sense_info_exceptions_control_mode_page_data_packet;



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
	uint8_t flags_task;

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
	uint8_t flags;

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
} iscsi_scsi_response_packet;

/// SCSI data out / in flags: Immediately process transfer.
#define ISCSI_SCSI_DATA_OUT_DATA_IN_FLAGS_IMMEDIATE (1 << 7)

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
	uint8_t flags;

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
} iscsi_scsi_data_in_response_packet;

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
	uint8_t flags;

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
	uint8_t flags;

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
	uint8_t flags;

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
} iscsi_login_req_packet;
ASSERT_IS_BHS( iscsi_login_req_packet );

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
	uint8_t flags;

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
	uint8_t flags;

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
} iscsi_logout_response_packet;


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
	uint8_t flags;

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

	/**
	 * @brief Complete Header of Bad PDU.
	 *
	 * The target returns the header (not including the digest) of the
	 * PDU in error as the data of the response.
	 */
	iscsi_bhs_packet bad_pdu_hdr;
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
	uint8_t flags;

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
	uint8_t flags;

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
	uint32_t reserved2;

	/// Reserved for future usage, always MUST be 0.
	uint64_t reserved3;
} iscsi_nop_in_packet;


/// Maximum length of a key according to iSCSI specifications.
#define ISCSI_TEXT_KEY_MAX_LEN          63U

/// Maximum length of value for a simple key type.
#define ISCSI_TEXT_VALUE_MAX_SIMPLE_LEN 255U

/// Maximum length of value for a normal key.
#define ISCSI_TEXT_VALUE_MAX_LEN        8192U


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


/// Read/write lock for iSCSI global vector. MUST be initialized with iscsi_create before any iSCSI functions are used.
//extern pthread_rwlock_t iscsi_globvec_rwlock;


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




/// iSCSI SCSI task run: Unknown.
#define ISCSI_SCSI_TASK_RUN_UNKNOWN  (-1)

/// iSCSI SCSI task run: Completed.
#define ISCSI_SCSI_TASK_RUN_COMPLETE  0


typedef struct iscsi_scsi_task iscsi_scsi_task;
typedef struct iscsi_scsi_lun iscsi_scsi_lun;


/**
 * @brief iSCSI SCSI Task.
 *
 * This structure is used for the iSCSI SCSI
 * layer task management.
 */
typedef struct iscsi_scsi_task {
	/// Connection associated with this task.
	iscsi_connection *connection;

	/// SCSI Command Descriptor Block (CDB).
	iscsi_scsi_cdb *cdb;

	/// SCSI sense data.
	iscsi_scsi_sense_data_packet *sense_data;

	/// Output buffer.
	uint8_t *buf;

	/// Whether output buffer os owned by this struct and must be freed on destroy
	bool must_free;

	/// Offset in bytes in image for DATA-in command.
	size_t file_offset;

	/// Length of buffer in bytes.
	uint32_t len;

	/// Expected data transfer length (from iSCSI PDU field)
	uint32_t exp_xfer_len;

	/// Unique identifier for this task.
	uint64_t id;

	/// Whether the R bit was set in the iSCSI request (BHS).
	bool is_read;

	/// Whether the W bit was set in the iSCSI request (BHS).
	bool is_write;

	/// Sense data length.
	uint8_t sense_data_len;

	/// iSCSI SCSI status code.
	uint8_t status;

	/// Uplink read mutex for sync
	pthread_mutex_t uplink_mutex;

	/// Conditional to signal uplink read complete
	pthread_cond_t uplink_cond;
} iscsi_scsi_task;


/// iSCSI SCSI emulation physical block size in bytes.
#define ISCSI_SCSI_EMU_PHYSICAL_BLOCK_SIZE      DNBD3_BLOCK_SIZE

/// iSCSI SCSI emulation logical block size in bytes.
#define ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE      (512)

/// Block shift difference between dnbd3 (4k) and iSCSI (512b)
#define ISCSI_SCSI_EMU_BLOCK_DIFF_SHIFT     (3)

_Static_assert( (ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE << ISCSI_SCSI_EMU_BLOCK_DIFF_SHIFT) == ISCSI_SCSI_EMU_PHYSICAL_BLOCK_SIZE,
	"Block size parameters are inconsistent" );

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


/// iSCSI SCSI emulation block flags: Write operation.
#define ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE  (1 << 0)

/// iSCSI SCSI emulation block flags: Verify operation.
#define ISCSI_SCSI_EMU_BLOCK_FLAGS_VERIFY (1 << 1)



/// iSCSI target node WWN identifier prefix string.
#define ISCSI_TARGET_NODE_WWN_NAME_PREFIX "wwn-0x"

/// iSCSI target node maximum length
#define ISCSI_TARGET_NODE_MAX_NAME_LEN 223U


/// iSCSI session type: Invalid.
#define ISCSI_SESSION_TYPE_INVALID   0

/// iSCSI session type: Normal.
#define ISCSI_SESSION_TYPE_NORMAL    1

/// iSCSI session type: Discovery.
#define ISCSI_SESSION_TYPE_DISCOVERY 2

/**
 * All mandatory fields in login process.
 * Set to -1 or NULL if not sent by client.
 */
typedef struct iscsi_login_kvp
{
	/// Largest PDU client can receive.
	int MaxRecvDataSegmentLength;

	/// Maximum burst length client can receive.
	int MaxBurstLength;

	// Maximum unsolicited burst length client can receive.
	int FirstBurstLength;

	/// Maximum number of connections.
	int MaxConnections;

	/// Error recovery level.
	int ErrorRecoveryLevel;

	/// The session type (Discovery, Normal).
	const char *SessionType;

	/// Desired auth method.
	const char *AuthMethod;

	/// SendTargets command.
	const char *SendTargets;

	/// HeaderDigest requested by client.
	const char *HeaderDigest;

	/// DataDigest requested by client.
	const char *DataDigest;

	const char *InitiatorName;

	const char *TargetName;
} iscsi_negotiation_kvp;

/**
 * Options/limits the client told us that
 * are relevant for proper communication
 */
typedef struct iscsi_session_options
{
	/// Largest PDU client can receive.
	int MaxRecvDataSegmentLength;

	/// Maximum burst length client can receive.
	int MaxBurstLength;

	// Maximum unsolicited burst length client can receive.
	int FirstBurstLength;
} iscsi_session_options;

/**
 * @brief iSCSI session.
 *
 * This structure manages an iSCSI session and
 * stores the key / value pairs from the
 * login phase.
 */
typedef struct iscsi_session {
	/// Initiator Session ID (ISID).
	uint64_t isid;

	/// Target Session Identifying Handle (TSIH).
	uint64_t tsih;

	/// Flags (extracted from key and value pairs).
	int flags;

	/// iSCSI session type.
	int type;

	/// ExpCmdSN.
	uint32_t exp_cmd_sn;

	/// MaxCmdSN.
	uint32_t max_cmd_sn;

	/// Session options client sent in login request.
	iscsi_session_options opts;
} iscsi_session;


typedef struct iscsi_pdu iscsi_pdu;


/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Packet parsed successfully.
#define ISCSI_CONNECT_PDU_READ_OK                                 0

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Packet processed successfully.
#define ISCSI_CONNECT_PDU_READ_PROCESSED                          1

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Fatail error during packet parsing.
#define ISCSI_CONNECT_PDU_READ_ERR_FATAL                         (-1)

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Login error response.
#define ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE                (-2)

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Login parameter error.
#define ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER               (-3)

/// iSCSI connection read packet data return code from iscsi_connection_pdu_read function: Login parameter not exchanged once error.
#define ISCSI_CONNECT_PDU_READ_ERR_LOGIN_PARAMETER_XCHG_NOT_ONCE (-4)


/// iSCSI connection flags: Full feature.
#define ISCSI_CONNECT_FLAGS_FULL_FEATURE    (1 << 3)

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


/// iSCSI connection state: Fresh connection, no login yet.
#define ISCSI_CONNECT_STATE_NEW 0

/// iSCSI connection state: Running as session type "normal".
#define ISCSI_CONNECT_STATE_NORMAL_SESSION 1

/// iSCSI connection state: Exiting, teardown of connection imminent.
#define ISCSI_CONNECT_STATE_EXITING 2


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
	/// iSCSI session associated with this connection.
	iscsi_session *session;

	/// Associated dnbd3 client
	dnbd3_client_t *client;

	/// Internal connection identifier
	int id;

	/// iSCSI connection flags.
	int flags;

	/// iSCSI connection state.
	int state;

	/// iSCSI connection login phase.
	int login_phase;

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

	/// StatSN.
	uint32_t stat_sn;
} iscsi_connection;


typedef struct iscsi_task iscsi_task;


/// iSCSI PDU will contain a small buffer for sending/receiving trivial PDUs with no/very small DS, and small AH
#define ISCSI_INTERNAL_BUFFER_SIZE (2 * ISCSI_BHS_SIZE)

/**
 * @brief This structure is used to partially read PDU data.
 *
 * Since TCP/IP packets can be fragmented, this
 * structure is needed which maintains reading
 * and filling the BHS, AHS and DS properly.
 */
typedef struct iscsi_pdu {
	/// iSCSI Basic Header Segment (BHS) packet data.
	iscsi_bhs_packet *bhs_pkt;

	/// iSCSI Advanced Header Segment (AHS) packet data for fast access and is straight after BHS packet in memory.
	iscsi_ahs_packet *ahs_pkt;

	/// iSCSI DataSegment (DS) packet data for fast access and is straight after BHS, AHS and header digest packet in memory.
	void *ds_cmd_data;

	/// Flags.
	int flags;

	/// Bytes of Basic Header Segment (BHS) already read.
	uint bhs_pos;

	/// AHSLength.
	uint ahs_len;

	/// DataSegmentLength.
	uint32_t ds_len;

	/// DS Buffer write pos when filling buffer for sending.
	uint32_t ds_write_pos;

	/// CmdSN.
	uint32_t cmd_sn;

	/// If we need a larger area than internal_buffer
	void *big_alloc;

	/// Used for smaller PDUs to avoid extra malloc/free
	char internal_buffer[ISCSI_INTERNAL_BUFFER_SIZE];
} iscsi_pdu;


/**
 * @brief This structure is used for iSCSI task management.
 *
 * This structure maintains the iSCSI task handling
 * including the underlying SCSI layer.
 */
typedef struct iscsi_task {
	/// Underlying SCSI task structure.
	iscsi_scsi_task scsi_task;

	/// Buffer length in bytes.
	uint32_t len;

	/// LUN identifier associated with this task (always MUST be between 0 and 7), used for hot removal tracking.
	int lun_id;

	/// Initiator Task Tag (ITT).
	uint32_t init_task_tag;

	/// Target Transfer Tag (TTT).
	uint32_t target_xfer_tag;
} iscsi_task;

void iscsi_connection_handle(dnbd3_client_t *client, const dnbd3_request_t *request, const int len); // Handles an iSCSI connection until connection is closed

#endif /* DNBD3_ISCSI_H_ */
