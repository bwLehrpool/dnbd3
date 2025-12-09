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
#include <unistd.h>
#include <assert.h>

#include "sendfile.h"
#include "globals.h"
#include "helper.h"
#include "image.h"
#include "iscsi.h"
#include "uplink.h"
#include "reference.h"

#define ISCSI_DEFAULT_LUN 0
#define ISCSI_DEFAULT_PROTOCOL_ID 1
#define ISCSI_DEFAULT_DEVICE_ID 1
#define ISCSI_DEFAULT_QUEUE_DEPTH 16

#include <dnbd3/afl.h>

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

//#define malloc(x) (rand() % 100 == 0 ? NULL : malloc(x))

/// Use for stack-allocated iscsi_pdu
#define CLEANUP_PDU __attribute__((cleanup(iscsi_connection_pdu_destroy)))

static bool iscsi_scsi_emu_block_process(iscsi_scsi_task *scsi_task);

static bool iscsi_scsi_emu_primary_process(iscsi_scsi_task *scsi_task);

static void iscsi_scsi_task_send_reply(iscsi_connection *conn, iscsi_scsi_task *scsi_task, const iscsi_pdu *request_pdu);

static uint64_t iscsi_scsi_lun_get_from_scsi(int lun_id); // Converts an internal representation of a LUN identifier to an iSCSI LUN required for packet data
static int iscsi_scsi_lun_get_from_iscsi(uint64_t lun); // Converts an iSCSI LUN from packet data to internal SCSI LUN identifier

static int iscsi_scsi_emu_io_blocks_read(iscsi_scsi_task *scsi_task,  dnbd3_image_t *image, uint64_t offset_blocks, uint64_t num_blocks); // Reads a number of blocks from a block offset of a DNBD3 image to a specified buffer

static void iscsi_strcpy_pad(char *dst, const char *src, size_t size, int pad); // Copies a string with additional padding character to fill in a specified size

static uint64_t iscsi_target_node_wwn_get(const uint8_t *name); // Calculates the WWN using 64-bit IEEE Extended NAA for a name

static bool iscsi_connection_pdu_init(iscsi_pdu *pdu, uint32_t ds_len, bool no_ds_alloc);
static void iscsi_connection_pdu_destroy(const iscsi_pdu *pdu);

static iscsi_bhs_packet *iscsi_connection_pdu_resize(iscsi_pdu *pdu, uint ahs_len, uint32_t ds_len); // Appends packet data to an iSCSI PDU structure used by connections

static bool iscsi_connection_pdu_write(iscsi_connection *conn, const iscsi_pdu *pdu);

static int iscsi_connection_handle_reject(iscsi_connection *conn, const iscsi_pdu *pdu, int reason_code);


/**
 * @brief Copies a string with additional padding character to fill in a specified size.
 *
 * If the src string is shorter than the destination buffer,
 * it will be padded with the given character. Otherwise,
 * the string will be copied and truncated if necessary.
 * In any case, the resulting string will NOT be null terminated.
 *
 * @param[in] dst Pointer to destination string to copy
 * with padding and must NOT be NULL, so be
 * careful.
 * @param[in] src Pointer to string for copying. NULL
 * is NOT allowed here, take caution.
 * @param[in] size Total size in bytes for padding.
 * @param[in] pad Padding character to use.
 */
static void iscsi_strcpy_pad(char *dst, const char *src, const size_t size, const int pad)
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
 * @brief Parses a string representation of an integer and assigns the result to
 * the provided destination variable, ensuring it is within valid range.
 *
 * This function checks for duplicate entries, empty strings, non-numeric
 * characters, and out-of-range values. Logs debug messages for invalid or
 * duplicate inputs and ensures values are clamped between 0 and INT_MAX.
 *
 * @param[in] name The name of the key associated with the integer value.
 * Used for logging purposes.
 * @param[in, out] dest Pointer to the destination integer variable where the
 * parsed value will be stored. Must not be NULL. If the pointed
 * value is -1, the parsed value will be assigned; otherwise,
 * the function considers it a duplicate and does not update it.
 * @param[in] src Pointer to the string containing the numeric representation
 * of the value to parse. Must not be NULL or empty.
 */
static void iscsi_copy_kvp_int(const char *name, int *dest, const char *src)
{
	long long res = 0;
	const char *end = NULL;

	if ( *dest != -1 ) {
		logadd( LOG_DEBUG1, "Received duplicate entry for key '%s', ignoring (new: %s, old: %d)", name, src, *dest );
		return;
	}

	if ( *src == '\0' ) {
		logadd( LOG_DEBUG1, "Empty value for numeric option '%s', ignoring", name );
		return;
	}
	res = strtoll( src, (char **)&end, 10 ); // WTF why is the second arg not const char **

	if ( end == NULL ) {
		logadd( LOG_DEBUG1, "base 10 not valid! O.o" );
		return;
	}
	if ( *end != '\0' ) {
		logadd( LOG_DEBUG1, "Invalid non-numeric character in value for '%s': '%c' (0x%02x), ignoring option",
				name, (int)*end, (int)*end );
		return;
	}
	if ( res < 0 ) {
		res = 0;
	} else if ( res > INT_MAX ) {
		res = INT_MAX;
	}
	*dest = (int)res;
}

/**
 * @brief Copies a key-value pair string to the destination if it hasn't been copied already.
 *
 * This function ensures that a key has a single corresponding value by
 * checking if the destination pointer has already been assigned. If assigned,
 * a debug log entry is created, and the new value is ignored.
 *
 * @param[in] name The name of the key being assigned. Used for logging.
 * @param[in,out] dest Pointer to the destination where the string is to be copied.
 * If the destination is already assigned, the function will log and return.
 * @param[in] src Pointer to the source string to be assigned to the destination.
 */
static void iscsi_copy_kvp_str(const char *name, const char **dest, const char *src)
{
	if ( *dest != NULL ) {
		logadd( LOG_DEBUG1, "Received duplicate entry for key '%s', ignoring (new: %s, old: %s)", name, src, *dest );
		return;
	}
	*dest = src;
}

/**
 * @brief Extracts a single text key / value pairs out of an iSCSI packet into a hash map.
 *
 * Parses and extracts a specific key and value pair out of an iSCSI packet
 * data stream amd puts the extracted data into a hash map to be used by
 * the iSCSI implementation.
 *
 * @param[in] key_value_pairs Pointer to hash map containing all related keys and pairs.
 * Must NOT be NULL, so take caution.
 * @param[in] packet_data Pointer to key / value pair to be parsed. NULL is
 * an illegal value, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @return Number of bytes used by the extracted key / vair pair or
 * a negative value in case of an error. This can be used for
 * incrementing the offset to the next key / value pair.
 */
static int iscsi_parse_text_key_value_pair(iscsi_negotiation_kvp *key_value_pairs, const char *packet_data, const uint32_t len)
{
	int key_val_len = (int) strnlen( packet_data, len );
	const char *key_end = memchr( packet_data, '=', key_val_len );

	if ( key_val_len == (int)len ) {
		logadd( LOG_DEBUG1, "iscsi_parse_text_key_value_pair: Final key/value pair not null-terminated, not spec compliant, aborting" );
		return -1;
	}
	// Account for the trailing nullchar (for return value), which we also consumed
	key_val_len++;

	if ( key_end == NULL ) {
		logadd( LOG_DEBUG1, "iscsi_parse_text_key_value_pair: Key/value separator '=' not found, ignoring" );
		return key_val_len;
	}

	const uint key_len = (uint) (key_end - packet_data);
	const uint val_len = (uint) (key_val_len - key_len - 1);

	if ( key_len == 0U ) {
		logadd( LOG_DEBUG1, "iscsi_parse_text_key_value_pair: Empty key, not allowed according to iSCSI specs, ignoring" );
		return key_val_len;
	}

	if ( key_len > ISCSI_TEXT_KEY_MAX_LEN ) {
		logadd( LOG_DEBUG1, "iscsi_parse_text_key_value_pair: Key is too long (max %d bytes), ignoring", ISCSI_TEXT_KEY_MAX_LEN );
		return key_val_len;
	}

	if ( val_len > ISCSI_TEXT_VALUE_MAX_LEN ) {
		logadd( LOG_DEBUG1, "iscsi_parse_text_key_value_pair: Value for '%.*s' is too long (max %d bytes), ignoring",
				(int)key_len, packet_data, ISCSI_TEXT_VALUE_MAX_LEN );
		return key_val_len;
	}

#define COPY_KVP(type, key) \
	else if ( strncmp( packet_data, #key, key_len ) == 0 ) iscsi_copy_kvp_ ## type ( #key, &key_value_pairs->key, key_end + 1 )

	if ( 0 ) {}
	COPY_KVP( int, MaxRecvDataSegmentLength );
	COPY_KVP( int, MaxBurstLength );
	COPY_KVP( int, FirstBurstLength );
	COPY_KVP( int, MaxConnections );
	COPY_KVP( int, ErrorRecoveryLevel );
	COPY_KVP( str, SessionType );
	COPY_KVP( str, AuthMethod );
	COPY_KVP( str, SendTargets );
	COPY_KVP( str, HeaderDigest );
	COPY_KVP( str, DataDigest );
	COPY_KVP( str, InitiatorName );
	COPY_KVP( str, TargetName );
	else {
		logadd( LOG_DEBUG1, "iscsi_parse_text_key_value_pair: Unknown option: '%.*s'", (int)key_len, packet_data );
	}

#undef COPY_KVP

	return (int)key_val_len;
}

/**
 * @brief Extracts all text key / value pairs out of an iSCSI packet into a hash map.
 *
 * Parses and extracts all key and value pairs out of iSCSI packet
 * data amd puts the extracted data into a hash map to be used by
 * the iSCSI implementation.
 *
 * @param[in] pairs struct to write all key-value-pair options from packet to
 * extracted keys and pairs. Must NOT be NULL, so take caution.
 * @param[in] packet_data Pointer to first key and value pair to
 * be parsed. NULL is an illegal value here, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @retval -1 An error occured during parsing key.
 * @retval 0 Key and value pair was parsed successfully and was added to
 * kvp struct.
 */
static int iscsi_parse_login_key_value_pairs(iscsi_negotiation_kvp *pairs, const uint8_t *packet_data, uint len)
{
	memset( pairs, -1 , sizeof(*pairs) );
	pairs->SessionType = NULL;
	pairs->AuthMethod = NULL;
	pairs->SendTargets = NULL;
	pairs->HeaderDigest = NULL;
	pairs->DataDigest = NULL;
	pairs->InitiatorName = NULL;
	pairs->TargetName = NULL;

	if ( len == 0U )
		return 0; // iSCSI specs don't allow zero length

	int offset = 0;

	while ( ((uint) offset < len) && (packet_data[offset] != '\0') ) {
		const int rc = iscsi_parse_text_key_value_pair( pairs, (const char *)(packet_data + offset), (len - offset) );

		if ( rc <= 0 )
			return -1;

		offset += rc;
	}

	return 0;
}

/**
 * @brief Sends a single iSCSI SCSI Data In packet to the client.
 *
 * This function reads the data from the
 * associated DNBD3 image as well and sends
 * it to the initiator.
 *
 * @param[in] conn Pointer to iSCSI connection for which the
 * packet should be sent for. Must NOT be
 * NULL, so be careful.
 * @param[in] task Pointer to iSCSI task which handles the
 * actual SCSI packet data. NULL is NOT
 * allowed here, so take caution.
 * @param[in] pos Offset of data to be sent in bytes.
 * @param[in] len Length of data to be sent in bytes
 * @param[in] res_cnt Residual Count.
 * @param[in] data_sn Data Sequence Number (DataSN).
 * @param[in] flags Flags for this data packet.
 * @param[in] immediate whether immediate bit was set in this request
 * @return true success, false error
 */
static bool iscsi_scsi_data_in_send(iscsi_connection *conn, const iscsi_task *task,
	const uint32_t pos, const uint32_t len, const uint32_t res_cnt, const uint32_t data_sn, const uint8_t flags, bool immediate)
{
	iscsi_pdu CLEANUP_PDU response_pdu;
	if ( !iscsi_connection_pdu_init( &response_pdu, len, true ) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_scsi_data_in_response_packet *scsi_data_in_pkt = (iscsi_scsi_data_in_response_packet *) response_pdu.bhs_pkt;

	scsi_data_in_pkt->opcode   = ISCSI_OPCODE_SERVER_SCSI_DATA_IN;
	scsi_data_in_pkt->flags    = flags;
	scsi_data_in_pkt->reserved = 0U;

	if ( (flags & ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS) != 0 ) {
		if ( (flags & ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL) != 0 && !immediate ) {
			conn->max_cmd_sn++;
		}
		scsi_data_in_pkt->status = task->scsi_task.status;
		iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->stat_sn, conn->stat_sn++ );
		iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->res_cnt, res_cnt );
	} else {
		// these don't carry any meaning if S bit is unset - saves us from doing the endian-conversion
		scsi_data_in_pkt->status  = 0U;
		scsi_data_in_pkt->stat_sn = 0UL;
		scsi_data_in_pkt->res_cnt = 0UL;
	}

	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->total_ahs_len, len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	scsi_data_in_pkt->lun = 0ULL; // Not used if we don't set the A bit (we never do)
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->init_task_tag, task->init_task_tag );
	scsi_data_in_pkt->target_xfer_tag = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->exp_cmd_sn, conn->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->max_cmd_sn, conn->max_cmd_sn );
	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->data_sn, data_sn );

	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->buf_offset, pos );

	if ( !iscsi_connection_pdu_write( conn, &response_pdu ) )
		return false;

	size_t padding;
	if ( task->scsi_task.buf != NULL ) {
		if ( !sock_sendAll( conn->client->sock, (task->scsi_task.buf + pos), len, ISCSI_CONNECT_SOCKET_WRITE_RETRIES ) )
			return false;
		padding = ISCSI_ALIGN( len, ISCSI_ALIGN_SIZE ) - len;
	} else {
		// sendfile - it must be a DATA-In, in which case len should be a multiple of 4, as it was given in number of
		// blocks, which is not just a multiple of 4 but usually a power of two.
		assert( len % 4 == 0 );
		const uint64_t off = task->scsi_task.file_offset + pos;
		size_t realBytes = len;
		if ( off >= conn->client->image->realFilesize ) {
			padding = len;
			realBytes = 0;
		} else if ( off + len > conn->client->image->realFilesize ) {
			padding = ( off + len ) - conn->client->image->realFilesize;
			realBytes -= padding;
		} else {
			padding = 0;
		}
		bool ret = sendfile_all( conn->client->image->readFd, conn->client->sock,
			(off_t)off, realBytes );
		if ( !ret )
			return false;
	}
	if ( padding != 0 ) {
		if ( !sock_sendPadding( conn->client->sock, padding ) )
			return false;
	}

	return true;
}

/**
 * @brief Handles iSCSI task read (incoming) data.
 *
 * This function handles iSCSI incoming data
 * read buffer for both processed and
 * unprocessed tasks.
 *
 * @param[in] conn Pointer to iSCSI connection of which the
 * incoming data should be handled, must NOT be
 * NULL, so be careful.
 * @param[in] task Pointer to iSCSI task for handling
 * the incoming data. NULL is NOT allowed here,
 * take caution.
 * @param immediate
 * @return true on success, false on error
 */
static bool iscsi_task_xfer_scsi_data_in(iscsi_connection *conn, const iscsi_task *task, bool immediate)
{
	const uint32_t expected_len = task->scsi_task.exp_xfer_len;
	uint32_t xfer_len           = task->scsi_task.len;
	uint32_t res_cnt            = 0UL;
	uint8_t flags                = 0;

	if ( expected_len < xfer_len ) {
		res_cnt  = (xfer_len - expected_len);
		xfer_len = expected_len;
		flags   |= ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_OVERFLOW;
	} else if ( expected_len > xfer_len ) {
		res_cnt  = (expected_len - xfer_len);
		flags   |= ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_UNDERFLOW;
	}
	if ( xfer_len == 0UL ) {
		// Can this even happen? Send empty data-in response...
		flags |= ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL | ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS;
		return iscsi_scsi_data_in_send( conn, task, 0, 0, res_cnt, 0, flags, immediate );
	}

	uint32_t data_sn                 = 0;
	// Max burst length = total cobined length of payload in all PDUs of one sequence
	const uint32_t max_burst_len     = conn->opts.MaxBurstLength;
	// Max recv segment length = total length of one individual PDU
	const uint32_t max_seg_len       = conn->opts.MaxRecvDataSegmentLength;

	for ( uint32_t current_burst_start = 0; current_burst_start < xfer_len; current_burst_start += max_burst_len ) {
		const uint32_t current_burst_end = MIN(xfer_len, current_burst_start + max_burst_len);

		for ( uint32_t offset = current_burst_start; offset < current_burst_end; offset += max_seg_len ) {
			const uint32_t current_seg_len = MIN(max_seg_len, current_burst_end - offset);

			flags &= ~(ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS | ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL);

			if ( (offset + current_seg_len) == current_burst_end ) {
				// This segment ends the current sequence - set F bit
				flags |= ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL;

				if ( (offset + current_seg_len) == xfer_len ) {
					// This segment ends the entire transfer - set S bit and include status
					flags  |= ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS;
				}
			}

			if ( !iscsi_scsi_data_in_send( conn, task, offset, current_seg_len, res_cnt, data_sn, flags, immediate ) )
				return false;

			data_sn++;
		}
	}

	conn->client->bytesSent += xfer_len;

	return true;
}

/**
 * @brief Send reply to a n iSCSI SCSI op.
 * Called when the request has been handled and the task is set up properly
 * with the according data to reply with. This is either payload data, for
 * a transfer, or sense data.
 *
 * @param[in] conn Current connection
 * @param[in] scsi_task Pointer to iSCSI SCSI task to send out a response for
 * @param request_pdu The request belonging to the response to send
 */
static void iscsi_scsi_task_send_reply(iscsi_connection *conn, iscsi_scsi_task *scsi_task, const iscsi_pdu *request_pdu)
{
	iscsi_task *task = container_of( scsi_task, iscsi_task, scsi_task );

	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) request_pdu->bhs_pkt;

	if ( task->scsi_task.status == ISCSI_SCSI_STATUS_GOOD && scsi_task->sense_data_len == 0 && scsi_task->is_read ) {
		iscsi_task_xfer_scsi_data_in( conn, task, (scsi_cmd_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) != 0 );

		return;
	}

	const uint32_t ds_len   = (scsi_task->sense_data_len != 0U)
		? (scsi_task->sense_data_len + offsetof(struct iscsi_scsi_ds_cmd_data, sense_data))
		: 0UL;

	iscsi_pdu CLEANUP_PDU response_pdu;
	if ( !iscsi_connection_pdu_init( &response_pdu, ds_len, false ) )
		return;

	iscsi_scsi_response_packet *scsi_response_pkt = (iscsi_scsi_response_packet *) response_pdu.bhs_pkt;

	if ( scsi_task->sense_data_len != 0U ) {
		iscsi_scsi_ds_cmd_data *ds_cmd_data_pkt = response_pdu.ds_cmd_data;

		iscsi_put_be16( (uint8_t *) &ds_cmd_data_pkt->len, scsi_task->sense_data_len );
		memcpy( ds_cmd_data_pkt->sense_data, scsi_task->sense_data, scsi_task->sense_data_len );

		iscsi_put_be32( (uint8_t *) &scsi_response_pkt->total_ahs_len, ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	} else {
		*(uint32_t *) &scsi_response_pkt->total_ahs_len = 0UL; // TotalAHSLength and DataSegmentLength are always 0, so write in one step.
	}

	scsi_response_pkt->opcode   = ISCSI_OPCODE_SERVER_SCSI_RESPONSE;
	scsi_response_pkt->flags    = 0x80;
	scsi_response_pkt->response = ISCSI_SCSI_RESPONSE_CODE_OK;
	const uint32_t exp_xfer_len = scsi_task->exp_xfer_len;

	if ( (exp_xfer_len != 0UL) && (scsi_task->status == ISCSI_SCSI_STATUS_GOOD) ) {
		const uint32_t resp_len             = ds_len;

		if ( resp_len < exp_xfer_len ) {
			const uint32_t res_cnt = (exp_xfer_len - resp_len);

			scsi_response_pkt->flags |= ISCSI_SCSI_RESPONSE_FLAGS_RES_UNDERFLOW;
			iscsi_put_be32( (uint8_t *) &scsi_response_pkt->res_cnt, res_cnt );
		} else if ( resp_len > exp_xfer_len ) {
			const uint32_t res_cnt = (resp_len - exp_xfer_len);

			scsi_response_pkt->flags |= ISCSI_SCSI_RESPONSE_FLAGS_RES_OVERFLOW;
			iscsi_put_be32( (uint8_t *) &scsi_response_pkt->res_cnt, res_cnt );
		} else {
			scsi_response_pkt->res_cnt = 0UL;
		}
	} else {
		scsi_response_pkt->res_cnt = 0UL;
	}

	scsi_response_pkt->status    = scsi_task->status;
	scsi_response_pkt->reserved  = 0ULL;
	iscsi_put_be32( (uint8_t *) &scsi_response_pkt->init_task_tag, task->init_task_tag );
	scsi_response_pkt->snack_tag = 0UL;
	iscsi_put_be32( (uint8_t *) &scsi_response_pkt->stat_sn, conn->stat_sn++ );

	if ( (scsi_cmd_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 ) {
		conn->max_cmd_sn++;
	}

	iscsi_put_be32( (uint8_t *) &scsi_response_pkt->exp_cmd_sn, conn->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &scsi_response_pkt->max_cmd_sn, conn->max_cmd_sn );
	scsi_response_pkt->exp_data_sn       = 0UL;
	scsi_response_pkt->bidi_read_res_cnt = 0UL;

	iscsi_connection_pdu_write( conn, &response_pdu );
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
 * code sense data for. Must NOT be NULL, so
 * be careful.
 * @param[in] sense_key Sense Key (SK).
 * @param[in] asc Additional Sense Code (ASC).
 * @param[in] ascq Additional Sense Code Qualifier (ASCQ).
 */
static void iscsi_scsi_task_sense_data_build(iscsi_scsi_task *scsi_task, const uint8_t sense_key, const uint8_t asc, const uint8_t ascq)
{
	iscsi_scsi_sense_data_check_cond_packet *sense_data = (iscsi_scsi_sense_data_check_cond_packet *) scsi_task->sense_data;

	if ( sense_data == NULL ) {
		sense_data = malloc( sizeof(iscsi_scsi_sense_data_check_cond_packet) );

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
	sense_data->sense_data.add_len         = (sizeof(iscsi_scsi_sense_data_check_cond_packet) - sizeof(iscsi_scsi_sense_data_packet));

	sense_data->cmd_spec_info        = 0UL; // Zero does not require endianess conversion
	sense_data->asc                  = asc;
	sense_data->ascq                 = ascq;
	sense_data->field_rep_unit_code  = 0UL;
	sense_data->sense_key_spec_flags = 0U;
	sense_data->sense_key_spec       = 0U; // Zero does not require endianess conversion

	scsi_task->sense_data_len = sizeof(iscsi_scsi_sense_data_check_cond_packet);
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
 * SCSI status and additional details for. Must
 * NOT be NULL, so be careful.
 * @param[in] status SCSI status code to be set.
 * @param[in] sense_key Sense Key (SK).
 * @param[in] asc Additional Sense Code (ASC).
 * @param[in] ascq Additional Sense Code Qualifier (ASCQ).
 */
static void iscsi_scsi_task_status_set(iscsi_scsi_task *scsi_task, const uint8_t status, const uint8_t sense_key, const uint8_t asc, const uint8_t ascq)
{
	if ( status == ISCSI_SCSI_STATUS_CHECK_COND ) {
		iscsi_scsi_task_sense_data_build( scsi_task, sense_key, asc, ascq );
	}

	scsi_task->status = status;
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
static uint64_t iscsi_scsi_lun_get_from_scsi(const int lun_id)
{
	uint64_t iscsi_scsi_lun;

	if ( lun_id < 0x100 ) {
		iscsi_scsi_lun = (uint64_t) (lun_id & 0xFF) << 48ULL;
	} else if ( lun_id < 0x4000 ) {
		iscsi_scsi_lun = (1ULL << 62ULL) | (uint64_t) (lun_id & 0x3FFF) << 48ULL;
	} else {
		iscsi_scsi_lun = 0ULL;
	}

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
static int iscsi_scsi_lun_get_from_iscsi(const uint64_t lun)
{
	int lun_id = (int) (lun >> 62ULL) & 0x03;

	if ( lun_id == 0x00 ) {
		lun_id = (int) (lun >> 48ULL) & 0xFF;
	} else if ( lun_id == 0x01 ) {
		lun_id = (int) (lun >> 48ULL) & 0x3FFF;
	} else {
		lun_id = 0xFFFF;
	}

	return lun_id;
}

/**
 * @brief Retrieves the number of total logical blocks for a DNBD3 image.
 *
 * This function depends on DNBD3 image
 * properties.
 *
 * @param[in] image Pointer to DNBD3 image to retrieve
 * the logical size from. Must NOT be NULL,
 * so be careful.
 * @return The number of total logical blocks.
 */
static inline uint64_t iscsi_scsi_emu_block_get_count(const dnbd3_image_t *image)
{
	return (image->virtualFilesize / ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE);
}


/**
 * @brief Converts offset and length specified by a block size to offset and length in bytes.
 *
 * This function uses bit shifting if
 * the block size is a power of two.
 *
 * @param[out] offset_bytes Pointer where to store the block
 * in bytes. Must NOT be NULL, so be
 * careful.
 * @param[in] offset_blocks Offset in blocks.
 * @param[in] num_blocks Number of blocks.
 * @return Number of blocks in bytes.
 */
static uint64_t iscsi_scsi_emu_blocks_to_bytes(uint64_t *offset_bytes, const uint64_t offset_blocks, const uint64_t num_blocks)
{
	*offset_bytes = (offset_blocks * ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE);

	return (num_blocks * ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE);
}

/**
 * @brief Called when data requested via an uplink server has arrived.
 *
 * This function is used to retrieve
 * block data which is NOT locally
 * available.
 *
 * @param[in] data Pointer to related scsi_task. Must NOT
 * be NULL, so be careful.
 * @param[in] handle Pointer to destination buffer, as passed to
 * iscsi_scsi_emu_io_block_read().
 * @param[in] start Start of range in bytes.
 * @param[in] length Length of range in bytes, as passed to
 * uplink_request().
 * @param[in] buffer Data for requested range.
 */
static void iscsi_uplink_callback(void *data, uint64_t handle UNUSED, uint64_t start UNUSED, uint32_t length, const char *buffer)
{
	iscsi_scsi_task *scsi_task = (iscsi_scsi_task *) data;

	memcpy( scsi_task->buf, buffer, length );

	pthread_mutex_lock( &scsi_task->uplink_mutex );
	pthread_cond_signal( &scsi_task->uplink_cond );
	pthread_mutex_unlock( &scsi_task->uplink_mutex );
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
 * executes the I/O read operation, must
 * NOT be NULL, so be careful.
 * @param[in] image Pointer to DNBD3 image to read
 * data from and must NOT be NULL, so
 * be careful.
 * @param[in] offset_blocks Offset in blocks to start reading from.
 * @param[in] num_blocks Number of blocks to read.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_io_blocks_read(iscsi_scsi_task *scsi_task,  dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks)
{
	int rc = 0;
	uint64_t offset_bytes;
	const uint64_t num_bytes = iscsi_scsi_emu_blocks_to_bytes( &offset_bytes, offset_blocks, num_blocks );

	if ( offset_bytes + num_bytes > image->virtualFilesize )
		return -ERANGE;

	scsi_task->file_offset = offset_bytes;
	scsi_task->len = (uint32_t)num_bytes;

	dnbd3_cache_map_t *cache = ref_get_cachemap( image );

	if ( cache != NULL ) {
		// This is a proxyed image, check if we need to relay the request...
		const uint64_t start = (offset_bytes & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1));
		const uint64_t end   = ((offset_bytes + num_bytes + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t) (DNBD3_BLOCK_SIZE - 1));
		bool readFromFile = image_isRangeCachedUnsafe( cache, start, end );

		ref_put( &cache->reference );

		if ( !readFromFile ) {
			// Not cached, request via uplink
			scsi_task->buf = malloc( num_bytes );
			if ( scsi_task->buf == NULL ) {
				return -ENOMEM;
			}
			pthread_mutex_init( &scsi_task->uplink_mutex, NULL );
			pthread_cond_init( &scsi_task->uplink_cond, NULL );
			pthread_mutex_lock( &scsi_task->uplink_mutex );

			if ( !uplink_request( image, scsi_task, iscsi_uplink_callback, 0, offset_bytes, (uint32_t)num_bytes ) ) {
				pthread_mutex_unlock( &scsi_task->uplink_mutex );

				logadd( LOG_DEBUG1, "Could not relay uncached request to upstream proxy for image %s:%d",
						image->name, image->rid );

				rc = -EIO;
			} else {
				// Wait sync (Maybe use pthread_cond_timedwait to detect unavailable uplink instead of hanging...)
				pthread_cond_wait( &scsi_task->uplink_cond, &scsi_task->uplink_mutex );
				pthread_mutex_unlock( &scsi_task->uplink_mutex );
				scsi_task->file_offset = (size_t)-1;
			}
			pthread_cond_destroy( &scsi_task->uplink_cond );
			pthread_mutex_destroy( &scsi_task->uplink_mutex );
		}
	}

	return rc;
}

/**
 * @brief Executes a read operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to read from
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this read or write
 * task. NULL is NOT allowed here, take
 * caution.
 * @param[in] lba Logical Block Address (LBA) to start
 * reading from or writing to.
 * @param[in] xfer_len Transfer length in logical blocks.
 */
static void iscsi_scsi_emu_block_read(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, const uint64_t lba, const uint32_t xfer_len)
{
	const uint32_t max_xfer_len = ISCSI_MAX_DS_SIZE / ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE;

	if ( xfer_len > max_xfer_len || !scsi_task->is_read || scsi_task->is_write ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ,
			ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return;
	}

	if ( xfer_len == 0UL ) {
		scsi_task->status = ISCSI_SCSI_STATUS_GOOD;

		return;
	}

	int rc = iscsi_scsi_emu_io_blocks_read( scsi_task, image, lba, xfer_len );

	if ( rc == 0 )
		return;

	if ( rc == -ENOMEM ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_HARDWARE_ERR,
			ISCSI_SCSI_ASC_INTERNAL_TARGET_FAIL, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE );

		return;
	}

	if ( rc == -ERANGE ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ,
			ISCSI_SCSI_ASC_LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return;
	}

	iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE,
		ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
}

/**
 * @brief Executes SCSI block emulation on a DNBD3 image.
 *
 * This function determines the block
 * based SCSI opcode and executes it.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * to process the SCSI block operation
 * for and must NOT be NULL, be careful.
 * @return true on successful operation, false otherwise.
 */
static bool iscsi_scsi_emu_block_process(iscsi_scsi_task *scsi_task)
{
	uint64_t lba;
	uint32_t xfer_len;
	dnbd3_image_t *image = scsi_task->connection->client->image;

	switch ( scsi_task->cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_READ6 : {
			const iscsi_scsi_cdb_read_write_6 *cdb_read_write_6 = (iscsi_scsi_cdb_read_write_6 *) scsi_task->cdb;

			lba      = iscsi_get_be24(cdb_read_write_6->lba);
			xfer_len = cdb_read_write_6->xfer_len;

			if ( xfer_len == 0UL ) {
				xfer_len = 256UL;
			}

			iscsi_scsi_emu_block_read( image, scsi_task, lba, xfer_len );

			break;
		}
		case ISCSI_SCSI_OPCODE_READ10 : {
			const iscsi_scsi_cdb_read_write_10 *cdb_read_write_10 = (iscsi_scsi_cdb_read_write_10 *) scsi_task->cdb;

			lba      = iscsi_get_be32(cdb_read_write_10->lba);
			xfer_len = iscsi_get_be16(cdb_read_write_10->xfer_len);

			iscsi_scsi_emu_block_read( image, scsi_task, lba, xfer_len );

			break;
		}
		case ISCSI_SCSI_OPCODE_READ12 : {
			const iscsi_scsi_cdb_read_write_12 *cdb_read_write_12 = (iscsi_scsi_cdb_read_write_12 *) scsi_task->cdb;

			lba      = iscsi_get_be32(cdb_read_write_12->lba);
			xfer_len = iscsi_get_be32(cdb_read_write_12->xfer_len);

			iscsi_scsi_emu_block_read( image, scsi_task, lba, xfer_len );

			break;
		}
		case ISCSI_SCSI_OPCODE_READ16 : {
			const iscsi_scsi_cdb_read_write_16 *cdb_read_write_16 = (iscsi_scsi_cdb_read_write_16 *) scsi_task->cdb;

			lba      = iscsi_get_be64(cdb_read_write_16->lba);
			xfer_len = iscsi_get_be32(cdb_read_write_16->xfer_len);

			iscsi_scsi_emu_block_read( image, scsi_task, lba, xfer_len );

			break;
		}
		case ISCSI_SCSI_OPCODE_READCAPACITY10 : {
			iscsi_scsi_read_capacity_10_parameter_data_packet *buf = malloc( sizeof(iscsi_scsi_read_capacity_10_parameter_data_packet) );

			if ( buf == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY,
					ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			lba = iscsi_scsi_emu_block_get_count( image ) - 1ULL;

			if ( lba > 0xFFFFFFFFULL ) {
				buf->lba = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
			} else {
				iscsi_put_be32( (uint8_t *) &buf->lba, (uint32_t) lba );
			}

			iscsi_put_be32( (uint8_t *) &buf->block_len, ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE );

			scsi_task->buf      = (uint8_t *) buf;
			scsi_task->len      = sizeof(*buf);
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_SERVICE_ACTION_IN_16 : {
			const iscsi_scsi_cdb_service_action_in_16 *cdb_servce_in_action_16 = (iscsi_scsi_cdb_service_action_in_16 *) scsi_task->cdb;

			if ( ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_GET_ACTION(cdb_servce_in_action_16->action)
						!= ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_READ_CAPACITY_16 ) {
				return false;
			}
			iscsi_scsi_service_action_in_16_parameter_data_packet *buf = malloc( sizeof(iscsi_scsi_service_action_in_16_parameter_data_packet) );

			if ( buf == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY,
					ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			lba = iscsi_scsi_emu_block_get_count( image ) - 1ULL;

			iscsi_put_be64( (uint8_t *) &buf->lba, lba );
			iscsi_put_be32( (uint8_t *) &buf->block_len, ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE );

			buf->flags = 0;

			const uint8_t exponent = ISCSI_SCSI_EMU_BLOCK_DIFF_SHIFT;

			buf->exponents = ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_PUT_LBPPB_EXPONENT((exponent <= ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_MASK) ? exponent : 0U);

			buf->lbp_lalba = 0U;
			buf->reserved[0] = 0ULL;
			buf->reserved[1] = 0ULL;

			const uint alloc_len = iscsi_get_be32( cdb_servce_in_action_16->alloc_len );

			scsi_task->buf      = (uint8_t *) buf;
			scsi_task->len      = MIN( alloc_len, sizeof(*buf) );
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_WRITE6 :
		case ISCSI_SCSI_OPCODE_WRITE10 :
		case ISCSI_SCSI_OPCODE_WRITE12 :
		case ISCSI_SCSI_OPCODE_WRITE16 :
		case ISCSI_SCSI_OPCODE_UNMAP :
		case ISCSI_SCSI_OPCODE_SYNCHRONIZECACHE10 :
		case ISCSI_SCSI_OPCODE_SYNCHRONIZECACHE16 : {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_WRITE_PROTECTED, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			break;
		}
		default : {
			return false;
		}
	}

	return true;
}

/**
 * @brief Calculates the 64-bit IEEE Extended NAA for a name.
 *
 * @param[out] buf Pointer to 64-bit output buffer for
 * storing the IEEE Extended NAA. Must
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
 * string to. Must NOT be NULL, so be
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
 * @brief Executes an inquiry operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to get
 * the inquiry data from. Must NOT be
 * NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this inqueiry
 * request. NULL is NOT allowed here,
 * take caution.
 * @param[in] cdb_inquiry Pointer to Command Descriptor
 * Block (CDB) and must NOT be NULL, be
 * careful.
 * @param[in] std_inquiry_data_pkt Pointer to standard inquiry
 * data packet to fill the inquiry
 * data with.
 * @param[in] len Length of inquiry result buffer
 * in bytes.
 * @return length of data on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_primary_inquiry(const dnbd3_image_t *image, iscsi_scsi_task *scsi_task, const iscsi_scsi_cdb_inquiry *cdb_inquiry, iscsi_scsi_std_inquiry_data_packet *std_inquiry_data_pkt, const uint len)
{
	if ( len < sizeof(iscsi_scsi_std_inquiry_data_packet) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE,
			ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return -1;
	}

	const int evpd = (cdb_inquiry->lun_flags & ISCSI_SCSI_CDB_INQUIRY_FLAGS_EVPD);
	const uint pc  = cdb_inquiry->page_code;

	if ( (evpd == 0) && (pc != 0U) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ,
			ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return -1;
	}

	if ( evpd != 0 ) {
		// VPD requested
		iscsi_scsi_vpd_page_inquiry_data_packet *vpd_page_inquiry_data_pkt = (iscsi_scsi_vpd_page_inquiry_data_packet *) std_inquiry_data_pkt;
		uint alloc_len;
		const uint8_t pti = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PUT_PERIPHERAL_TYPE(ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_TYPE_DIRECT) | ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PUT_PERIPHERAL_ID(ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PERIPHERAL_ID_POSSIBLE);

		vpd_page_inquiry_data_pkt->peripheral_type_id        = pti;
		vpd_page_inquiry_data_pkt->page_code                 = (uint8_t) pc;

		switch ( pc ) {
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SUPPORTED_VPD_PAGES : {
				vpd_page_inquiry_data_pkt->params[0] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_SUPPORTED_VPD_PAGES;
				vpd_page_inquiry_data_pkt->params[1] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_UNIT_SERIAL_NUMBER;
				vpd_page_inquiry_data_pkt->params[2] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_DEVICE_ID;
				vpd_page_inquiry_data_pkt->params[3] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_EXTENDED_INQUIRY_DATA;
				vpd_page_inquiry_data_pkt->params[4] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_LIMITS;
				vpd_page_inquiry_data_pkt->params[5] = ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_DEV_CHARS;

				alloc_len = 6U;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_UNIT_SERIAL_NUMBER : {
				const char *name = image->name;

				alloc_len = (uint) strlen( name );

				if ( alloc_len >= (len - sizeof(iscsi_scsi_vpd_page_inquiry_data_packet)) ) {
					alloc_len = (uint) ((len - sizeof(iscsi_scsi_vpd_page_inquiry_data_packet)) - 1U);
				}

				memcpy( vpd_page_inquiry_data_pkt->params, name, alloc_len );
				memset( (vpd_page_inquiry_data_pkt->params + alloc_len), '\0', (len - alloc_len - sizeof(iscsi_scsi_vpd_page_inquiry_data_packet)) );

				alloc_len++;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_DEVICE_ID : {
				const char *port_name = "Horst";
				const uint dev_name_len  = (uint) (strlen( image->name ) + 1U);
				const uint port_name_len = (uint) (strlen( port_name ) + 1U);

				// Calculate total length required for all design descriptors we are about to add:
				// 1. IEEE NAA Extended
				// 2. T10 Vendor ID
				// 3. SCSI Device Name
				// 4. SCSI Target Port Name
				// 5. Relative Target Port
				// 6. Target Port Group
				// 7. Logical Unit Group
				alloc_len  = (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet)); // 64-bit IEEE NAA Extended
				alloc_len += (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet)); // T10 Vendor ID
				alloc_len += (uint) (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + ISCSI_ALIGN(dev_name_len, ISCSI_ALIGN_SIZE)); // SCSI Device Name
				alloc_len += (uint) (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + ISCSI_ALIGN(port_name_len, ISCSI_ALIGN_SIZE)); // SCSI Target Port Name
				alloc_len += (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet)); // Relative Target Port
				alloc_len += (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet)); // Target Port Group
				alloc_len += (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet)); // Logical Unit Group

				if ( len < (alloc_len + sizeof(iscsi_scsi_vpd_page_inquiry_data_packet)) ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				// 1. Descriptor: IEEE NAA Extended
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_NAA) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet);

				iscsi_scsi_emu_naa_ieee_ext_set( (uint64_t *) vpd_page_design_desc_inquiry_data_pkt->desc, (uint8_t *) image->name );

				alloc_len = (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + alloc_len);
				// 2. Descriptor: T10 Vendor ID
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_ASCII) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_T10_VENDOR_ID) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet *vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->vendor_id, ISCSI_SCSI_STD_INQUIRY_DATA_DISK_VENDOR_ID, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->vendor_id), ' ' );
				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->product_id, image->name, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->product_id), ' ' );
				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->unit_serial_num, image->name, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->unit_serial_num), ' ' );

				alloc_len += (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet)));
				// 3. Descriptor: SCSI Device Name
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_DEVICE) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = (uint8_t) iscsi_scsi_emu_pad_scsi_name( vpd_page_design_desc_inquiry_data_pkt->desc, (const uint8_t*)image->name );

				alloc_len += (uint) (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len);

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len));
				// 4. Descriptor: SCSI Target Port Name
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = (uint8_t) iscsi_scsi_emu_pad_scsi_name( vpd_page_design_desc_inquiry_data_pkt->desc, (const uint8_t*)port_name );

				alloc_len += (uint) (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len);

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len));
				// 5. Descriptor: Relative Target Port
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_REL_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet *vpd_page_design_desc_rel_target_port_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_rel_target_port_inquiry_data_pkt->reserved = 0U;
				iscsi_put_be16( (uint8_t *) &vpd_page_design_desc_rel_target_port_inquiry_data_pkt->index, 1 );

				alloc_len += (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) +  (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet)));
				// 6. Descriptor: Target Port Group
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_TARGET_PORT_GROUP) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet *vpd_page_design_desc_target_port_group_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_target_port_group_inquiry_data_pkt->reserved = 0U;
				vpd_page_design_desc_target_port_group_inquiry_data_pkt->index    = 0U;

				alloc_len += (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) +  (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet)));
				// 7. Descriptor: Logical Unit Group
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LOGICAL_UNIT_GROUP) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet *vpd_page_design_desc_logical_unit_group_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet*)vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_logical_unit_group_inquiry_data_pkt->reserved = 0U;
				iscsi_put_be16( (uint8_t *) &vpd_page_design_desc_logical_unit_group_inquiry_data_pkt->id, (uint16_t) ISCSI_DEFAULT_DEVICE_ID );

				alloc_len += (sizeof(iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet));

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_EXTENDED_INQUIRY_DATA : {
				iscsi_scsi_vpd_page_ext_inquiry_data_packet *vpd_page_ext_inquiry_data_pkt = (iscsi_scsi_vpd_page_ext_inquiry_data_packet *) vpd_page_inquiry_data_pkt;

				alloc_len = (sizeof(iscsi_scsi_vpd_page_ext_inquiry_data_packet) - sizeof(iscsi_scsi_vpd_page_inquiry_data_packet));

				if ( len < (alloc_len + sizeof(iscsi_scsi_vpd_page_inquiry_data_packet)) ) {
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
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_LIMITS : {
				iscsi_scsi_vpd_page_block_limits_inquiry_data_packet *vpd_page_block_limits_inquiry_data_pkt = (iscsi_scsi_vpd_page_block_limits_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				if ( len < (sizeof(iscsi_scsi_vpd_page_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_block_limits_inquiry_data_packet)) ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				alloc_len = sizeof(iscsi_scsi_vpd_page_block_limits_inquiry_data_packet);

				vpd_page_block_limits_inquiry_data_pkt->flags = 0;

				// So, this has caused some headache, nice. With the kernel's iscsi implementation, we have to limit our
				// reported maximum supported transfer length to the client's maximum supported DS size. If you just do
				// ISCSI_MAX_DS_SIZE / ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE
				// the kernel will complain that the maximum transfer size is not a multiple of the physical block size,
				// so you might be tempted to use
				// ((ISCSI_MAX_DS_SIZE  / ISCSI_SCSI_EMU_PHYSICAL_BLOCK_SIZE)
				//	    * ISCSI_SCSI_EMU_PHYSICAL_BLOCK_SIZE) / ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE
				// to make sure it is. But then *surprise*, maximum transfer speeds drop from ~1.5GB/s to ~250MB/s.
				// OK, then you revert back to the simple formula and accept that annoying warning in dmesg, only to
				// realize that while "pv < /dev/sda > /dev/null" and dd with bs=256k are fast, a dd with bs=1M ends up
				// at about 25MB/s (!!!!)
				// So what finally, hopefully, seems to work properly is limiting the reported maximum transfer length to
				// the client's MaxRecvDataSegmentLength, which coincidentally is the same as its FirstBurstLength, so
				// let's hope picking MaxRecvDataSegmentLength is the right choice here. You'd think the client would
				// automatically pick a suitable transfer length that it can handle efficiently; the kernel however just
				// goes for the maximum supported by the server. Even just lowering the reported *optimal* length is not
				// sufficient. But maybe I'm just not good with computers.
				const uint32_t blocks = (scsi_task->connection->opts.MaxRecvDataSegmentLength
					/ ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE);

				vpd_page_block_limits_inquiry_data_pkt->max_cmp_write_len = 0;

				iscsi_put_be16( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->optimal_granularity_xfer_len,
					(uint16_t) ISCSI_SCSI_EMU_PHYSICAL_BLOCK_SIZE / ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE );
				iscsi_put_be32( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->max_xfer_len, blocks );
				iscsi_put_be32( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->optimal_xfer_len, blocks );
				vpd_page_block_limits_inquiry_data_pkt->max_prefetch_len = 0UL;

				vpd_page_block_limits_inquiry_data_pkt->max_unmap_lba_cnt = 0UL;
				vpd_page_block_limits_inquiry_data_pkt->max_unmap_block_desc_cnt = 0UL;

				vpd_page_block_limits_inquiry_data_pkt->optimal_unmap_granularity        = 0UL;
				vpd_page_block_limits_inquiry_data_pkt->unmap_granularity_align_ugavalid = 0UL;
				vpd_page_block_limits_inquiry_data_pkt->max_write_same_len               = 0;
				vpd_page_block_limits_inquiry_data_pkt->reserved[0]                      = 0ULL;
				vpd_page_block_limits_inquiry_data_pkt->reserved[1]                      = 0ULL;
				vpd_page_block_limits_inquiry_data_pkt->reserved2                        = 0UL;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_DEV_CHARS : {
				iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet *chars_resp = (iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				if ( len < (sizeof(iscsi_scsi_vpd_page_inquiry_data_packet) + sizeof(iscsi_scsi_vpd_page_block_dev_chars_inquiry_data_packet)) ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				alloc_len = sizeof(*chars_resp);

				iscsi_put_be16( (uint8_t *)&chars_resp->medium_rotation_rate, ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_MEDIUM_ROTATION_RATE_NONE );
				chars_resp->product_type         = ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_PRODUCT_TYPE_NOT_INDICATED;
				chars_resp->flags                = ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_PUT_NOMINAL_FORM_FACTOR(ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_FLAGS_NOMINAL_FORM_FACTOR_NOT_REPORTED);
				chars_resp->support_flags        = 0U;
				chars_resp->reserved[0]          = 0ULL;
				chars_resp->reserved[1]          = 0ULL;
				chars_resp->reserved[2]          = 0ULL;
				chars_resp->reserved[3]          = 0ULL;
				chars_resp->reserved[4]          = 0ULL;
				chars_resp->reserved[5]          = 0ULL;
				chars_resp->reserved2            = 0UL;
				chars_resp->reserved3            = 0U;
				chars_resp->reserved4            = 0U;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			default : {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return -1;

				break;
			}
		}

		return (int) (alloc_len + sizeof(iscsi_scsi_vpd_page_inquiry_data_packet));
	}

	// Normal INQUIRY, no VPD

	const uint8_t pti = ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_TYPE(ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_TYPE_DIRECT) | ISCSI_SCSI_BASIC_INQUIRY_DATA_PUT_PERIPHERAL_ID(ISCSI_SCSI_BASIC_INQUIRY_DATA_PERIPHERAL_ID_POSSIBLE);

	std_inquiry_data_pkt->basic_inquiry.peripheral_type_id        = pti;
	std_inquiry_data_pkt->basic_inquiry.peripheral_type_mod_flags = 0;
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

	uint add_len = (sizeof(iscsi_scsi_std_inquiry_data_packet) - sizeof(iscsi_scsi_basic_inquiry_data_packet));
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

		if ( alloc_len > (sizeof(iscsi_scsi_ext_inquiry_data_packet) - offsetof(iscsi_scsi_ext_inquiry_data_packet, version_desc[4])) ) {
			alloc_len = (sizeof(iscsi_scsi_ext_inquiry_data_packet) - offsetof(iscsi_scsi_ext_inquiry_data_packet, version_desc[4]));
		}

		memset( &ext_inquiry_data_pkt->version_desc[4], 0, alloc_len );
		add_len += alloc_len;
	}

	std_inquiry_data_pkt->basic_inquiry.add_len = (uint8_t) add_len;

	return (int) (add_len + sizeof(iscsi_scsi_basic_inquiry_data_packet));
}

/**
 * @brief Executes a report LUNs operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
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
static int iscsi_scsi_emu_primary_report_luns( iscsi_scsi_report_luns_parameter_data_lun_list_packet *report_luns_parameter_data_pkt, const uint len, const uint select_report)
{
	const uint64_t lun = iscsi_scsi_lun_get_from_scsi( ISCSI_DEFAULT_LUN );

	if ( len < sizeof(iscsi_scsi_report_luns_parameter_data_lun_list_packet) + sizeof(lun) )
		return -1;

	switch ( select_report ) {
		case ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_ADDR_METHOD :
		case ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_KNOWN :
		case ISCSI_SCSI_CDB_REPORT_LUNS_SELECT_REPORT_LU_ALL : {
			break;
		}
		default : {
			return -1;
		}
	}

	report_luns_parameter_data_pkt->reserved     = 0UL;
	iscsi_put_be32( (uint8_t *) &report_luns_parameter_data_pkt->lun_list_len, sizeof(lun) );
	iscsi_put_be64( (uint8_t *) (report_luns_parameter_data_pkt + 1), lun );

	return (int) (sizeof(lun) + sizeof(iscsi_scsi_report_luns_parameter_data_lun_list_packet));
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
 * @param[in] buffer Pointer to mode sense parameter
 * mode page or sub page data packet
 * to initialize. If this is NULL,
 * this function does nothing.
 * @param[in] len Length in bytes to initialize. Any padding will be zeroed.
 * @param[in] page Page code.
 * @param[in] sub_page Sub page code.
 */
static void iscsi_scsi_emu_primary_mode_sense_page_init(uint8_t *buffer, const uint len, const uint page, const uint sub_page)
{
	if ( buffer == NULL )
		return;

	if ( sub_page == 0U ) {
		iscsi_scsi_mode_sense_mode_page_data_header *mode_sense_mode_page_pkt = (iscsi_scsi_mode_sense_mode_page_data_header *) buffer;
		mode_sense_mode_page_pkt->page_code_flags = (uint8_t) ISCSI_SCSI_MODE_SENSE_MODE_PAGE_PUT_PAGE_CODE(page);
		mode_sense_mode_page_pkt->page_len        = (uint8_t) (len - sizeof(*mode_sense_mode_page_pkt));

		memset( mode_sense_mode_page_pkt + 1, 0, (len - sizeof(*mode_sense_mode_page_pkt)) );
	} else {
		iscsi_scsi_mode_sense_mode_sub_page_data_header *mode_sense_mode_sub_page_pkt = (iscsi_scsi_mode_sense_mode_sub_page_data_header *) buffer;

		mode_sense_mode_sub_page_pkt->page_code_flags = (uint8_t) (ISCSI_SCSI_MODE_SENSE_MODE_PAGE_PUT_PAGE_CODE(page) | ISCSI_SCSI_MODE_SENSE_MODE_PAGE_FLAGS_SPF);
		mode_sense_mode_sub_page_pkt->sub_page_code   = (uint8_t) sub_page;
		iscsi_put_be16( (uint8_t *) &mode_sense_mode_sub_page_pkt->page_len, (uint16_t) (len - sizeof(*mode_sense_mode_sub_page_pkt)) );

		memset( mode_sense_mode_sub_page_pkt + 1, 0, (len - sizeof(*mode_sense_mode_sub_page_pkt)) );
	}
}

/**
 * @brief Handles a specific mode sense page or sub page.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to get
 * the mode sense data from. Must NOT be
 * NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this mode sense
 * task. NULL is NOT allowed here,
 * take caution.
 * @param[in] buffer Pointer to mode sense parameter
 * mode page or sub page data packet
 * to process. If this is NULL, only
 * the length of page is calculated.
 * @param[in] pc Page control (PC).
 * @param[in] page Page code.
 * @param[in] sub_page Sub page code.
 * @return Number of bytes occupied or a
 * negative error code otherwise.
 */
static int iscsi_scsi_emu_primary_mode_sense_page(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, uint8_t *buffer, const uint pc, const uint page, const uint sub_page)
{
	uint page_len;
	uint len = 0;
	int tmplen;

	switch ( pc ) {
		case ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_CURRENT_VALUES :
		case ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_CHG_VALUES :
		case ISCSI_SCSI_CDB_MODE_SENSE_6_PAGE_CONTROL_DEFAULT_VALUES : {
			break;
		}
		default : {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ,
				ISCSI_SCSI_ASC_SAVING_PARAMETERS_NOT_SUPPORTED, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

			return -1;

			break;
		}
	}

	switch ( page ) {
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_READ_WRITE_ERR_RECOVERY : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(iscsi_scsi_mode_sense_read_write_err_recovery_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_DISCONNECT_RECONNECT : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(iscsi_scsi_mode_sense_disconnect_reconnect_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VERIFY_ERR_RECOVERY : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(iscsi_scsi_mode_sense_verify_err_recovery_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_CACHING : {
			if ( sub_page != 0U )
				break;

			iscsi_scsi_mode_sense_caching_mode_page_data_packet *cache_page = (iscsi_scsi_mode_sense_caching_mode_page_data_packet *) buffer;

			page_len = sizeof(*cache_page);

			iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

			if ( cache_page != NULL ) {
				cache_page->flags |= ISCSI_SCSI_MODE_SENSE_CACHING_MODE_PAGE_FLAGS_DISC;
				// 0xffff is endian-agnostic, don't need to convert
				cache_page->disable_prefetch_xfer_len = 0xffff;
				cache_page->min_prefetch = 0xffff;
				cache_page->max_prefetch = 0xffff;
				cache_page->max_prefetch_ceil = 0xffff;
			}

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_CONTROL : {
			switch ( sub_page ) {
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL : {
					page_len = sizeof(iscsi_scsi_mode_sense_control_mode_page_data_packet);

					iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

					len += page_len;

					break;
				}
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL_EXT : {
					/* Control Extension */

					page_len = sizeof(iscsi_scsi_mode_sense_control_ext_mode_page_data_packet);

					iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

					len += page_len;

					break;
				}
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL_ALL : {
					tmplen = iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((buffer != NULL) ? (buffer + len) : NULL), pc, page, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL );
					if ( tmplen == -1 )
						return -1;
					len += tmplen;
					tmplen = iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((buffer != NULL) ? (buffer + len) : NULL), pc, page, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_CONTROL_EXT );
					if ( tmplen == -1 )
						return -1;
					len += tmplen;

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

			page_len = sizeof(iscsi_scsi_mode_sense_xor_ext_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_POWER_COND : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(iscsi_scsi_mode_sense_power_cond_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_INFO_EXCEPTIOS_CONTROL : {
			if ( sub_page != 0U )
				break;

			page_len = sizeof(iscsi_scsi_mode_sense_info_exceptions_control_mode_page_data_packet);

			iscsi_scsi_emu_primary_mode_sense_page_init( buffer, page_len, page, sub_page );

			len += page_len;

			break;
		}
		case ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES : {
			switch ( sub_page ) {
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_PAGES : {
					for ( uint i = ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC; i < ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES; i++ ) {
						tmplen = iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((buffer != NULL) ? (buffer + len) : NULL), pc, i, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_PAGES );
						if ( tmplen == -1 )
							return -1;
						len += tmplen;
					}

					break;
				}
				case ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_SUB_PAGES : {
					for ( uint i = ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC; i < ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES; i++ ) {
						tmplen = iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((buffer != NULL) ? (buffer + len) : NULL), pc, i, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_PAGES );
						if ( tmplen == -1 )
							return -1;
						len += tmplen;
					}

					for ( uint i = ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_VENDOR_SPEC; i < ISCSI_SCSI_MODE_SENSE_MODE_PAGE_CODE_REPORT_ALL_MODE_PAGES; i++ ) {
						tmplen = iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, ((buffer != NULL) ? (buffer + len) : NULL), pc, i, ISCSI_SCSI_MODE_SENSE_MODE_SUB_PAGE_CODE_REPORT_ALL_MODE_SUB_PAGES );
						if ( tmplen == -1 )
							return -1;
						len += tmplen;
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

	return (int)len;
}

/**
 * @brief Executes a mode sense operation on a DNBD3 image.
 *
 * This function also sets the SCSI
 * status result code accordingly.
 *
 * @param[in] image Pointer to DNBD3 image to get
 * the mode sense data from. Must
 * NOT be NULL, so be careful.
 * @param[in] scsi_task Pointer to iSCSI SCSI task
 * responsible for this mode sense
 * task. NULL is NOT allowed here,
 * take caution.
 * @param[in] buffer Pointer to mode sense parameter
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
static int iscsi_scsi_emu_primary_mode_sense(dnbd3_image_t *image, iscsi_scsi_task *scsi_task, uint8_t *buffer,
		const uint hdr_len, const uint block_desc_len, const uint long_lba, const uint pc, const uint page_code, const uint sub_page_code)
{
	// Pointer to right after header and LBA block description; where the pages go
	uint8_t *mode_sense_payload = (buffer != NULL) ? (buffer + hdr_len + block_desc_len) : NULL;
	const int page_len = iscsi_scsi_emu_primary_mode_sense_page( image, scsi_task, mode_sense_payload, pc, page_code, sub_page_code );

	if ( page_len < 0 )
		return -1;

	const uint alloc_len = (hdr_len + block_desc_len + page_len);

	if ( buffer == NULL )
		return (int)alloc_len;

	if ( hdr_len == sizeof(iscsi_scsi_mode_sense_6_parameter_header_data_packet) ) {
		iscsi_scsi_mode_sense_6_parameter_header_data_packet *mode_sense_6_parameter_hdr_data_pkt = (iscsi_scsi_mode_sense_6_parameter_header_data_packet *) buffer;
		mode_sense_6_parameter_hdr_data_pkt->mode_data_len  = (uint8_t) (alloc_len - sizeof(uint8_t));
		mode_sense_6_parameter_hdr_data_pkt->medium_type    = 0U;
		mode_sense_6_parameter_hdr_data_pkt->flags          = ISCSI_SCSI_MODE_SENSE_6_PARAM_HDR_DATA_FLAGS_WP;
		mode_sense_6_parameter_hdr_data_pkt->block_desc_len = (uint8_t) block_desc_len;
	} else if ( hdr_len == sizeof(iscsi_scsi_mode_sense_10_parameter_header_data_packet) ) {
		iscsi_scsi_mode_sense_10_parameter_header_data_packet *mode_sense_10_parameter_hdr_data_pkt = (iscsi_scsi_mode_sense_10_parameter_header_data_packet *) buffer;

		iscsi_put_be16( (uint8_t *) &mode_sense_10_parameter_hdr_data_pkt->mode_data_len, (uint16_t) (alloc_len - sizeof(uint16_t)) );
		mode_sense_10_parameter_hdr_data_pkt->medium_type    = 0U;
		mode_sense_10_parameter_hdr_data_pkt->flags          = ISCSI_SCSI_MODE_SENSE_10_PARAM_HDR_DATA_FLAGS_WP;
		mode_sense_10_parameter_hdr_data_pkt->long_lba       = (uint8_t) long_lba;
		mode_sense_10_parameter_hdr_data_pkt->reserved       = 0U;
		iscsi_put_be16( (uint8_t *) &mode_sense_10_parameter_hdr_data_pkt->block_desc_len, (uint16_t) block_desc_len );
	} else {
		logadd( LOG_DEBUG1, "iscsi_scsi_emu_primary_mode_sense: invalid parameter header length %u", hdr_len );
		return -1;
	}

	const uint64_t num_blocks = iscsi_scsi_emu_block_get_count( image );
	const uint32_t block_size = ISCSI_SCSI_EMU_LOGICAL_BLOCK_SIZE;

	if ( block_desc_len == sizeof(iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet) ) {
		iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet *lba_parameter_block_desc = (iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet *) (buffer + hdr_len);

		if ( num_blocks > 0xFFFFFFFFULL ) {
			lba_parameter_block_desc->num_blocks = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
		} else {
			iscsi_put_be32( (uint8_t *) &lba_parameter_block_desc->num_blocks, (uint32_t) num_blocks );
		}

		lba_parameter_block_desc->reserved = 0U;
		iscsi_put_be24( (uint8_t *) &lba_parameter_block_desc->block_len, block_size );
	} else if ( block_desc_len == sizeof(iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet) ) {
		iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet *long_lba_parameter_block_desc = (iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet *) (buffer + hdr_len);

		iscsi_put_be64( (uint8_t *) &long_lba_parameter_block_desc->num_blocks, num_blocks );
		long_lba_parameter_block_desc->reserved = 0UL;
		iscsi_put_be32( (uint8_t *) &long_lba_parameter_block_desc->block_len, block_size );
	}

	return (int)alloc_len;
}

/**
 * @brief Determines the temporary allocation size for a SCSI reply.
 *
 * This function calculates the temporary allocation size to be used for SCSI
 * commands based on the requested allocation size. It ensures the allocation
 * size has a minimum size, to simplify buffer-filling. The response can then
 * later be truncated if it's larger than the alloc_size.
 * If the requested size exceeds the default maximum allowed size, a SCSI task
 * status with an error condition is set, and the allocation size is returned
 * as zero.
 *
 * @param[in] scsi_task Pointer to the SCSI task, used to set error status.
 * @param[in] alloc_size The client-requested allocation size in bytes.
 *
 * @return The determined temporary allocation size. Returns 0 if the size
 * exceeds the maximum allowed limit; otherwise, the size is either adjusted
 * to the default size or remains the requested size.
 */
static uint32_t iscsi_get_temporary_allocation_size(iscsi_scsi_task *scsi_task, uint32_t alloc_size)
{
	if ( alloc_size > ISCSI_DEFAULT_RECV_DS_LEN ) {
		// Don't allocate gigabytes of memory just because the client says so
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE,
					ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return 0;
	}
	if ( alloc_size < ISCSI_DEFAULT_RECV_DS_LEN )
		return ISCSI_DEFAULT_RECV_DS_LEN;

	return alloc_size;
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
 * operation for and must NOT be NULL,
 * be careful.
 * @return true on successful operation, false otherwise.
 */
static bool iscsi_scsi_emu_primary_process(iscsi_scsi_task *scsi_task)
{
	uint len;
	int rc;

	switch ( scsi_task->cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_INQUIRY : {
			const iscsi_scsi_cdb_inquiry *cdb_inquiry = (iscsi_scsi_cdb_inquiry *) scsi_task->cdb;
			const uint alloc_len = iscsi_get_be16(cdb_inquiry->alloc_len);

			len = iscsi_get_temporary_allocation_size( scsi_task, alloc_len );
			if ( len == 0 )
				break;

			iscsi_scsi_std_inquiry_data_packet *std_inquiry_data_pkt = malloc( len );

			if ( std_inquiry_data_pkt == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY,
					ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_emu_primary_inquiry( scsi_task->connection->client->image, scsi_task, cdb_inquiry, std_inquiry_data_pkt, len );

			if ( rc >= 0 ) {
				scsi_task->buf    = (uint8_t *) std_inquiry_data_pkt;
				scsi_task->len    = MIN( (uint)rc, alloc_len );
				scsi_task->status = ISCSI_SCSI_STATUS_GOOD;
			} else {
				free( std_inquiry_data_pkt );
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_REPORTLUNS : {
			const iscsi_scsi_cdb_report_luns *cdb_report_luns = (iscsi_scsi_cdb_report_luns *) scsi_task->cdb;
			const uint alloc_len = iscsi_get_be32(cdb_report_luns->alloc_len);

			len = iscsi_get_temporary_allocation_size( scsi_task, alloc_len );
			if ( len == 0 )
				break;

			iscsi_scsi_report_luns_parameter_data_lun_list_packet *report_luns_parameter_data_pkt = malloc( len );

			if ( report_luns_parameter_data_pkt == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY,
					ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_emu_primary_report_luns( report_luns_parameter_data_pkt, len, cdb_report_luns->select_report );

			if ( rc >= 0 ) {
				scsi_task->buf    = (uint8_t *) report_luns_parameter_data_pkt;
				scsi_task->len    = MIN( (uint)rc, alloc_len );
				scsi_task->status = ISCSI_SCSI_STATUS_GOOD;
			} else {
				free( report_luns_parameter_data_pkt );
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE,
					ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_MODESENSE6 : {
			const iscsi_scsi_cdb_mode_sense_6 *cdb_mode_sense_6 = (iscsi_scsi_cdb_mode_sense_6 *) scsi_task->cdb;
			const uint alloc_len = cdb_mode_sense_6->alloc_len;

			const uint block_desc_len = ((cdb_mode_sense_6->flags & ISCSI_SCSI_CDB_MODE_SENSE_6_FLAGS_DBD) == 0) ? sizeof(iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet) : 0U;
			const uint pc             = ISCSI_SCSI_CDB_MODE_SENSE_6_GET_PAGE_CONTROL(cdb_mode_sense_6->page_code_control);
			const uint page           = ISCSI_SCSI_CDB_MODE_SENSE_6_GET_PAGE_CODE(cdb_mode_sense_6->page_code_control);
			const uint sub_page       = cdb_mode_sense_6->sub_page_code;

			rc = iscsi_scsi_emu_primary_mode_sense( scsi_task->connection->client->image, scsi_task, NULL, sizeof(iscsi_scsi_mode_sense_6_parameter_header_data_packet), block_desc_len, 0U, pc, page, sub_page );

			if ( rc < 0 )
				break;

			len = rc;

			uint8_t *mode_sense_6_parameter_hdr_data_pkt = malloc( len );

			if ( mode_sense_6_parameter_hdr_data_pkt == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_emu_primary_mode_sense( scsi_task->connection->client->image, scsi_task, mode_sense_6_parameter_hdr_data_pkt, sizeof(iscsi_scsi_mode_sense_6_parameter_header_data_packet), block_desc_len, 0U, pc, page, sub_page );

			if ( rc >= 0 ) {
				scsi_task->buf    = mode_sense_6_parameter_hdr_data_pkt;
				scsi_task->len    = MIN( (uint)rc, alloc_len );
				scsi_task->status = ISCSI_SCSI_STATUS_GOOD;
			} else {
				free( mode_sense_6_parameter_hdr_data_pkt );
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE,
					ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_MODESENSE10 : {
			const iscsi_scsi_cdb_mode_sense_10 *cdb_mode_sense_10 = (iscsi_scsi_cdb_mode_sense_10 *) scsi_task->cdb;
			const uint alloc_len = iscsi_get_be16(cdb_mode_sense_10->alloc_len);

			const uint long_lba       = (((cdb_mode_sense_10->flags & ISCSI_SCSI_CDB_MODE_SENSE_10_FLAGS_LLBAA) != 0) ? ISCSI_SCSI_MODE_SENSE_10_PARAM_HDR_DATA_LONGLBA : 0U);
			const uint block_desc_len = (((cdb_mode_sense_10->flags & ISCSI_SCSI_CDB_MODE_SENSE_10_FLAGS_DBD) == 0) ? ((long_lba != 0) ? sizeof(iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet) : sizeof(iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet)) : 0U);
			const uint pc10           = ISCSI_SCSI_CDB_MODE_SENSE_10_GET_PAGE_CONTROL(cdb_mode_sense_10->page_code_control);
			const uint page10         = ISCSI_SCSI_CDB_MODE_SENSE_10_GET_PAGE_CODE(cdb_mode_sense_10->page_code_control);
			const uint sub_page10     = cdb_mode_sense_10->sub_page_code;

			rc = iscsi_scsi_emu_primary_mode_sense( scsi_task->connection->client->image, scsi_task, NULL, sizeof(iscsi_scsi_mode_sense_10_parameter_header_data_packet), block_desc_len, long_lba, pc10, page10, sub_page10 );

			if ( rc < 0 )
				break;

			len = rc;

			uint8_t *mode_sense_10_parameter_hdr_data_pkt = malloc( len );

			if ( mode_sense_10_parameter_hdr_data_pkt == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_emu_primary_mode_sense( scsi_task->connection->client->image, scsi_task, mode_sense_10_parameter_hdr_data_pkt, sizeof(iscsi_scsi_mode_sense_10_parameter_header_data_packet), block_desc_len, long_lba, pc10, page10, sub_page10 );

			if ( rc >= 0 ) {
				scsi_task->buf    = mode_sense_10_parameter_hdr_data_pkt;
				scsi_task->len    = MIN( (uint)rc, alloc_len );
				scsi_task->status = ISCSI_SCSI_STATUS_GOOD;
			} else {
				free( mode_sense_10_parameter_hdr_data_pkt );
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE,
					ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
			}

			break;
		}
		case ISCSI_SCSI_OPCODE_TESTUNITREADY :
		case ISCSI_SCSI_OPCODE_STARTSTOPUNIT : {
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		default : {
			return false;
		}
	}

	return true;
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
static uint64_t iscsi_target_node_wwn_get(const uint8_t *name)
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
 * @brief Appends a key and value pair to DataSegment packet data.
 *
 * This function adds any non-declarative key
 * and value pair to an output DataSegment
 * buffer and truncates if necessary.
 *
 * @param[in] number true = int, false = char*
 * @param[in] key Pointer to key to be written to output
 * buffer. NULL is NOT allowed, take caution.
 * @param[in] value Pointer to value of the key that should
 * be written to output buffer which must
 * NOT be NULL, so take caution.
 * @param[in] buf Pointer to output buffer to write the
 * key and value pair to. NULL is
 * prohibited, so be careful.
 * @param[in] pos Position of buffer in bytes to start
 * writing to.
 * @param[in] buflen Total length of buffer in bytes.
 * @return -1 if buffer is already full, otherwise the number
 * of bytes that are written or would have been written to
 * the buffer.
 */
static int iscsi_append_key_value_pair_packet(const bool number, const char *key, const char *value, char *buf, const uint32_t pos, const uint32_t buflen)
{
	if ( pos >= buflen )
		return -1;

	const ssize_t maxlen = buflen - pos;
	if ( number ) {
		return (int)snprintf( (buf + pos), maxlen, "%s=%d", key, (const int)(const size_t)value ) + 1;
	}
	return (int)snprintf( (buf + pos), maxlen, "%s=%s", key, value ) + 1;
}


#define CLAMP(val, min, max) ((val) < (min) ? (min) : ((val) > (max) ? (max) : (val)))

/**
 * @brief Updates selected iSCSI connection options from negotiated key-value pairs.
 *
 * Copies and clamps a subset of negotiated options (MaxBurstLength,
 * FirstBurstLength, MaxRecvDataSegmentLength) into the connection's
 * options.
 *
 * @param[in] conn Pointer to ISCSI connection which should be updated.
 * @param[in] pairs Set of readily parsed key-value pairs to apply.
 */
static void iscsi_connection_update_key_value_pairs(iscsi_connection *conn, const iscsi_negotiation_kvp *pairs)
{
	conn->opts.MaxBurstLength = CLAMP(pairs->MaxBurstLength, 512, ISCSI_MAX_DS_SIZE);
	conn->opts.FirstBurstLength = CLAMP(pairs->FirstBurstLength, 512, pairs->MaxBurstLength);
	conn->opts.MaxRecvDataSegmentLength = CLAMP(pairs->MaxRecvDataSegmentLength, 512, ISCSI_MAX_DS_SIZE);
}

/**
 * @brief Prepares an iSCSI login response PDU and sends it via TCP/IP.
 *
 * This function constructs the login response PDU
 * to be sent via TCP/IP.
 *
 * @param[in] conn Pointer to ISCSI connection to send the TCP/IP
 * packet with. Must NOT be NULL, so be
 * careful.
 * @param[in] resp_pdu Pointer to login response PDU to
 * be sent via TCP/IP. NULL is NOT
 * allowed here, take caution.
 * @return 0 if the login response has been sent
 * successfully, a negative error code otherwise.
 */
static int iscsi_send_login_response_pdu(iscsi_connection *conn, iscsi_pdu *resp_pdu)
{
	iscsi_login_response_packet *login_response_pkt =
		(iscsi_login_response_packet *) iscsi_connection_pdu_resize( resp_pdu, resp_pdu->ahs_len, resp_pdu->ds_write_pos );

	login_response_pkt->version_max    = ISCSI_VERSION_MAX;
	login_response_pkt->version_active = ISCSI_VERSION_MAX;

	iscsi_put_be32( (uint8_t *) &login_response_pkt->total_ahs_len, resp_pdu->ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	iscsi_put_be32( (uint8_t *) &login_response_pkt->stat_sn, conn->stat_sn++ );

	if ( conn->state != ISCSI_CONNECT_STATE_NEW ) {
		iscsi_put_be32( (uint8_t *) &login_response_pkt->exp_cmd_sn, conn->exp_cmd_sn );
		iscsi_put_be32( (uint8_t *) &login_response_pkt->max_cmd_sn, conn->max_cmd_sn );
	} else {
		iscsi_put_be32( (uint8_t *) &login_response_pkt->exp_cmd_sn, resp_pdu->cmd_sn );
		iscsi_put_be32( (uint8_t *) &login_response_pkt->max_cmd_sn, resp_pdu->cmd_sn );
	}

	if ( login_response_pkt->status_class != ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS ) {
		login_response_pkt->flags &= (int8_t) ~(ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT | ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_MASK | ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_MASK );
	}

	return iscsi_connection_pdu_write( conn, resp_pdu ) ? 0 : -1;
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
 * must NOT be NULL, so be careful.
 * @return 0 if initialization was successful, a negative error
 * code otherwise.
 */
static int iscsi_connection_pdu_login_response_init(iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu)
{
	iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) pdu->bhs_pkt;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	login_response_pkt->opcode = ISCSI_OPCODE_SERVER_LOGIN_RES;
	login_response_pkt->flags  = (int8_t) (login_req_pkt->flags & (ISCSI_LOGIN_REQ_FLAGS_TRANSIT | ISCSI_LOGIN_REQ_FLAGS_CONTINUE | ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_MASK));

	if ( (login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0 ) {
		login_response_pkt->flags |= (login_req_pkt->flags & ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_MASK);
	}

	login_response_pkt->isid          = login_req_pkt->isid;
	login_response_pkt->tsih          = 0;
	login_response_pkt->init_task_tag = login_req_pkt->init_task_tag; // Copying over doesn't change endianess.
	login_response_pkt->reserved      = 0UL;
	login_response_pdu->cmd_sn        = iscsi_get_be32(login_req_pkt->cmd_sn);
	login_response_pkt->stat_sn       = 0UL;
	login_response_pkt->reserved2     = 0U;
	login_response_pkt->reserved3     = 0ULL;

	if ( login_req_pkt->tsih != 0 ) {
		// Session resumption, not supported
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_SESSION_NO_EXIST;
	} else if ( ((login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0) && ((login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_CONTINUE) != 0) ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;
	} else if ( (ISCSI_VERSION_MAX < login_req_pkt->version_min) || (ISCSI_VERSION_MIN > login_req_pkt->version_max) ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_WRONG_VERSION;
	} else if ( (ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(login_response_pkt->flags) == ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_RESERVED) && ((login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0) ) {
		login_response_pkt->flags        &= (int8_t) ~(ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_MASK | ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT | ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_MASK);
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;
	} else {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SUCCESS;

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
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
 * @param[in] type_str Pointer to key and value pairs which
 * contain the session type parameter to be evaluated,
 * which must NOT be NULL, so take caution.
 * @param[in] type Write session type constant to this int.
 * Must not be null.
 * @return 0 on successful operation, a negative error code
 * otherwise. The output session 'type' is unchanged, if
 * an invalid session type value was retrieved.
 */
static int iscsi_login_parse_session_type(const iscsi_pdu *login_response_pdu, const char *type_str, int *type)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	if ( type_str != NULL && strcasecmp( type_str, "Normal" ) == 0 ) {
		*type = ISCSI_CONNECT_STATE_NORMAL_SESSION;
		return ISCSI_CONNECT_PDU_READ_OK;
	}

	*type = ISCSI_CONNECT_STATE_INVALID;
	logadd( LOG_DEBUG1, "Unsupported session type: %s", type_str );
	login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
	login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

	return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
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
 * @param[in] conn Pointer to iSCSI connection which must NOT be
 * NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU
 * to set the parameters for. NULL is NOT allowed
 * here, so take caution.
 * @param[in] target_name Pointer to target node name and must
 * NOT be NULL, be careful.
 * @return 0 if the check was successful or a negative
 * error code otherwise.
 */
static int iscsi_image_from_target(const iscsi_connection *conn, const iscsi_pdu *login_response_pdu, const char *target_name)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	char *image_rev        = NULL;
	char *tmpbuf           = strdup( target_name );
	char *image_name       = tmpbuf;
	char *tmp              = strchr( tmpbuf, ':' );

	if ( tmpbuf == NULL ) {
		logadd( LOG_ERROR, "iscsi_target_node_image_get: Out of memory while allocating DNBD3 image name for iSCSI target node" );
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	while ( tmp != NULL ) {
		*tmp++ = '\0';
		if ( image_rev != NULL ) {
			image_name = image_rev;
		}
		image_rev  = tmp;
		tmp        = strchr( tmp, ':' );
	}

	uint16_t rev   = 0;
	if ( image_rev != NULL ) {
		char *end = NULL;
		long rid = strtol( image_rev, &end, 10 );
		if ( end == NULL || *end != '\0' || rid < 0 || rid > 0xFFFF ) {
			logadd( LOG_DEBUG1, "iscsi_image_from_target: Invalid revision number (%s) in iSCSI target node name: '%s'", image_rev, target_name );
		} else {
			rev = (uint16_t)rid;
		}
	}
	dnbd3_image_t *image = image_getOrLoad( image_name, rev );

	if ( image == NULL && image_rev != NULL ) {
		image = image_getOrLoad( image_rev, rev );
	}

	if ( image == NULL && strncasecmp( image_name, ISCSI_TARGET_NODE_WWN_NAME_PREFIX, ISCSI_STRLEN(ISCSI_TARGET_NODE_WWN_NAME_PREFIX) ) == 0 ) {
		uint64_t wwn = strtoull( (image_name + ISCSI_STRLEN(ISCSI_TARGET_NODE_WWN_NAME_PREFIX)), NULL, 16 );

		image = image_getByWwn( wwn, rev, true );

		if ( image == NULL ) {
			wwn   = strtoull( (tmp + ISCSI_STRLEN(ISCSI_TARGET_NODE_WWN_NAME_PREFIX)), NULL, 16 );
			image = image_getByWwn( wwn, rev, true );
		}
	}

	free( tmpbuf );

	if ( image == NULL ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_NOT_FOUND;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}
	conn->client->image = image;

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Initializes an iSCSI Protocol Data Unit (PDU) object for use in iSCSI communication.
 *
 * Allocates and assigns the required memory for the Basic Header Segment (BHS) packet
 * and optionally for the aligned data segment (DS). Resets and initializes various fields
 * within the given PDU structure. Ensures proper memory alignment for data segment if
 * applicable, and zeroes out unused buffer regions.
 *
 * @param[in,out] pdu Pointer to the iSCSI PDU structure to initialize. Must not be NULL.
 * @param[in] ds_len Length of the Data Segment (DS) in bytes. Must not exceed ISCSI_MAX_DS_SIZE.
 * @param[in] no_ds_alloc If true, the Data Segment memory allocation is skipped.
 *
 * @retval true if initialization is successful.
 * @retval false if memory allocation for the BHS packet fails or ds_len exceeds the maximum allowed size.
 */
static bool iscsi_connection_pdu_init(iscsi_pdu *pdu, const uint32_t ds_len, bool no_ds_alloc)
{
	// Always set this pointer to NULL before any sanity checks,
	// so the attribute-cleanup magic won't screw up if init fails
	pdu->big_alloc = NULL;

	if ( ds_len > ISCSI_MAX_DS_SIZE ) {
		logadd( LOG_ERROR, "iscsi_pdu_init: Invalid DS length" );
		return false;
	}

	const uint32_t pkt_ds_len = no_ds_alloc ? 0 : ISCSI_ALIGN( ds_len, ISCSI_ALIGN_SIZE );
	const uint32_t alloc_len        = (uint32_t) ( sizeof(iscsi_bhs_packet) + pkt_ds_len );

	if ( alloc_len > ISCSI_INTERNAL_BUFFER_SIZE ) {
		pdu->bhs_pkt = pdu->big_alloc = malloc( alloc_len );
		if ( pdu->bhs_pkt == NULL ) {
			logadd( LOG_ERROR, "iscsi_pdu_init: Out of memory while allocating iSCSI BHS packet" );
			return false;
		}
	} else {
		pdu->bhs_pkt = (iscsi_bhs_packet *)pdu->internal_buffer;
	}

	pdu->ahs_pkt                 = NULL;
	pdu->ds_cmd_data             = (pkt_ds_len != 0UL)
		? (iscsi_scsi_ds_cmd_data *) (((uint8_t *) pdu->bhs_pkt) + sizeof(iscsi_bhs_packet))
		: NULL;
	pdu->flags                   = 0;
	pdu->bhs_pos                 = 0U;
	pdu->ahs_len                 = 0;
	pdu->ds_len                  = ds_len;
	pdu->ds_write_pos            = 0;
	pdu->cmd_sn                  = 0UL;

	if ( pkt_ds_len > ds_len ) {
		memset( (((uint8_t *) pdu->ds_cmd_data) + ds_len), 0, (pkt_ds_len - ds_len) );
	}

	return true;
}

/**
 * @brief Frees resources associated with an iSCSI PDU (Protocol Data Unit).
 *
 * This function releases memory allocated for certain members of the iSCSI
 * PDU structure. It ensures that the allocated resources are properly freed.
 * If the provided PDU pointer is NULL, the function returns immediately without
 * performing any operations.
 *
 * @param[in] pdu Pointer to the iSCSI PDU structure to be destroyed.
 * If NULL, the function has no effect.
 */
static void iscsi_connection_pdu_destroy(const iscsi_pdu *pdu)
{
	if ( pdu == NULL )
		return;
	free( pdu->big_alloc );
}

/**
 * @brief Appends packet data to an iSCSI PDU structure used by connections.
 *
 * This function adjusts the pointers if
 * the packet data size needs to be
 * extended.
 *
 * @param[in] pdu Pointer to iSCSI PDU where to append
 * the packet data to. Must NOT be NULL, so
 * be careful.
 * @param[in] ahs_len Length of AHS packet data to be appended.
 * @param[in] ds_len Length of DataSegment packet data to be appended.
 * May not exceed 16MiB - 1 (16777215 bytes).
 * @return Pointer to allocated and zero filled PDU or NULL
 * in case of an error (usually memory exhaustion).
 */
static iscsi_bhs_packet *iscsi_connection_pdu_resize(iscsi_pdu *pdu, const uint ahs_len,  const uint32_t ds_len)
{
	if ( (ahs_len != pdu->ahs_len) || (ds_len != pdu->ds_len) ) {
		if ( (ahs_len > ISCSI_MAX_AHS_SIZE) || (ds_len > ISCSI_MAX_DS_SIZE) || (ahs_len % ISCSI_ALIGN_SIZE != 0) ) {
			logadd( LOG_ERROR, "iscsi_connection_pdu_resize: Invalid AHS or DataSegment packet size" );
			return NULL;
		}
		if ( pdu->ds_len != 0 && pdu->ds_cmd_data == NULL ) {
			// If you really ever need this, handle it properly below (old_len, no copying, etc.)
			logadd( LOG_ERROR, "iscsi_connection_pdu_resize: Cannot resize PDU with virtual DS" );
			return NULL;
		}
		if ( pdu->ds_len != 0 && pdu->ahs_len != ahs_len && ds_len != 0 ) {
			// Cannot resize the AHS of a PDU that already has a DS and should keep the DS - we'd need to move the data
			// around. Implement this when needed (and make sure it works).
			logadd( LOG_ERROR, "iscsi_connection_pdu_resize: Cannot resize PDU's AHS that also has a DS" );
			return NULL;
		}

		iscsi_bhs_packet *bhs_pkt;
		const uint32_t pkt_ds_len = ISCSI_ALIGN(ds_len, ISCSI_ALIGN_SIZE);
		const size_t old_len      = (sizeof(iscsi_bhs_packet) + (uint32_t) pdu->ahs_len + ISCSI_ALIGN(pdu->ds_len, ISCSI_ALIGN_SIZE));
		const size_t new_len      = (sizeof(iscsi_bhs_packet) + (uint32_t) ahs_len + pkt_ds_len);
		const bool old_alloced    = pdu->big_alloc != NULL;
		const bool new_alloced    = new_len > ISCSI_INTERNAL_BUFFER_SIZE;

		if ( new_len == old_len ) {
			// Nothing changed
			bhs_pkt = pdu->bhs_pkt;
		} else {
			if ( new_alloced ) {
				// New block doesn't fit in internal buffer - (re)allocate big buffer
				bhs_pkt = realloc( pdu->big_alloc, new_len );
				if ( bhs_pkt == NULL ) {
					logadd( LOG_ERROR, "iscsi_connection_pdu_resize: Out of memory while reallocating iSCSI PDU packet data" );
					return NULL;
				}
				if ( !old_alloced ) {
					// Old was in internal buffer, copy contents to the new heap buffer
					memcpy( bhs_pkt, pdu->internal_buffer, MIN(new_len, old_len) );
				}
				// Update PDU's BHS pointer
				pdu->big_alloc = bhs_pkt;
				pdu->bhs_pkt = bhs_pkt;
			} else {
				// New block fits into internal buffer.
				// If we are already using big_alloc, we keep it to avoid realloc/free overhead,
				// as PDUs are short-lived.
				// Keep using old BHS pointer (which might be big_alloc or internal_buffer)
				bhs_pkt = pdu->bhs_pkt;
			}
		}

		pdu->ahs_pkt            = (ahs_len != 0U) ? (iscsi_ahs_packet *) (((uint8_t *) bhs_pkt) + sizeof(iscsi_bhs_packet)) : NULL;
		pdu->ds_cmd_data        = (pkt_ds_len != 0UL) ? (iscsi_scsi_ds_cmd_data *) (((uint8_t *) bhs_pkt) + sizeof(iscsi_bhs_packet) + ahs_len) : NULL;
		pdu->ahs_len            = ahs_len;
		pdu->ds_len             = ds_len;

		if ( pkt_ds_len != 0UL ) {
			memset( (((uint8_t *) pdu->ds_cmd_data) + ds_len), 0, (pkt_ds_len - ds_len) );
		}
	}

	return pdu->bhs_pkt;
}

/**
 * @brief Writes and sends a response PDU to the client.
 *
 * Sends the provided response PDU over the TCP connection. On send failure,
 * the connection state is set to ISCSI_CONNECT_STATE_EXITING.
 *
 * If a header or data segment is present, its size is rounded up to the iSCSI
 * alignment before transmission, so the underlying buffer MUST include padding
 * if neccesary.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. Must
 * NOT be NULL, so take caution.
 * @param[in] pdu Pointer to iSCSI server response PDU to send.
 * Must NOT be NULL, so be careful.
 * @retval true if the entire PDU was sent successfully.
 * @retval false on failure (connection state will be set to EXITING).
 */
static bool iscsi_connection_pdu_write(iscsi_connection *conn, const iscsi_pdu *pdu)
{
	if ( conn->state >= ISCSI_CONNECT_STATE_EXITING ) {
		return false;
	}

	// During allocation we already round up to ISCSI_ALIGN_SIZE, but store the requested size in the ds_len
	// member, so it's safe to round up here before sending, the accessed memory will be valid and zeroed
	const size_t len = (sizeof(iscsi_bhs_packet) + pdu->ahs_len
		+ (pdu->ds_cmd_data == NULL ? 0 : ISCSI_ALIGN(pdu->ds_len, ISCSI_ALIGN_SIZE)));
	const ssize_t rc = sock_sendAll( conn->client->sock, pdu->bhs_pkt, len, ISCSI_CONNECT_SOCKET_WRITE_RETRIES );

	if ( rc != (ssize_t)len ) {
		conn->state = ISCSI_CONNECT_STATE_EXITING;
		return false;
	}
	return true;
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
 * @retval -1 An error ocurred during reject packet generation,
 * currently only happens on memory exhaustion.
 * @retval 0 Reject packet and PDU constructed and sent successfully to the client.
 */
static int iscsi_connection_handle_reject(iscsi_connection *conn, const iscsi_pdu *pdu, const int reason_code)
{
	const uint32_t ds_len   = (uint32_t) sizeof(iscsi_bhs_packet) + (uint32_t) (pdu->bhs_pkt->total_ahs_len * ISCSI_ALIGN_SIZE);
	iscsi_pdu CLEANUP_PDU response_pdu;
	if ( !iscsi_connection_pdu_init( &response_pdu, ds_len, false ) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_reject_packet *reject_pkt = (iscsi_reject_packet *) response_pdu.bhs_pkt;

	reject_pkt->opcode    = ISCSI_OPCODE_SERVER_REJECT;
	reject_pkt->flags     = 0x80;
	reject_pkt->reason    = (uint8_t) reason_code;
	reject_pkt->reserved  = 0U;
	iscsi_put_be32( (uint8_t *) &reject_pkt->total_ahs_len, ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	reject_pkt->reserved2 = 0ULL;
	reject_pkt->tag       = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
	reject_pkt->reserved3 = 0UL;
	iscsi_put_be32( (uint8_t *) &reject_pkt->stat_sn, conn->stat_sn++ );

	if ( conn->state != ISCSI_CONNECT_STATE_NEW ) {
		iscsi_put_be32( (uint8_t *) &reject_pkt->exp_cmd_sn, conn->exp_cmd_sn );
		iscsi_put_be32( (uint8_t *) &reject_pkt->max_cmd_sn, conn->max_cmd_sn );
	} else {
		iscsi_put_be32( (uint8_t *) &reject_pkt->exp_cmd_sn, 1UL );
		iscsi_put_be32( (uint8_t *) &reject_pkt->max_cmd_sn, 1UL );
	}

	reject_pkt->reserved4 = 0ULL;

	memcpy( response_pdu.ds_cmd_data, pdu->bhs_pkt, ds_len );

	iscsi_connection_pdu_write( conn, &response_pdu );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Updates the expected command sequence number (ExpCmdSN) and validates sequence number bounds.
 *
 * This function extracts the CmdSN and checks whether it fits within the session's
 * expected command sequence range, considering session type and iSCSI operation types.
 * Also updates session-related sequence numbers as needed based on the received command.
 *
 * @param[in] conn Pointer to the iSCSI connection. Must not be NULL, and its session pointer should also be valid.
 * @param[in] request_pdu Pointer to the iSCSI PDU (Protocol Data Unit) containing command information. Must not be NULL.
 *
 * @return Returns `ISCSI_CONNECT_PDU_READ_OK` (0) on success or
 *         `ISCSI_CONNECT_PDU_READ_ERR_FATAL` (-1) if sequence numbers or other data are invalid.
 */
static int iscsi_connection_handle_cmd_sn(iscsi_connection *conn, iscsi_pdu *request_pdu)
{
	if ( conn->state == ISCSI_CONNECT_STATE_NEW )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) request_pdu->bhs_pkt;
	const int opcode = ISCSI_GET_OPCODE(scsi_cmd_pkt->opcode);

	request_pdu->cmd_sn = iscsi_get_be32(scsi_cmd_pkt->cmd_sn);

	if ( (scsi_cmd_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 ) {
		if ( (iscsi_seq_num_cmp_lt( request_pdu->cmd_sn, conn->exp_cmd_sn )
				|| iscsi_seq_num_cmp_gt( request_pdu->cmd_sn, conn->max_cmd_sn ))
				&& ((conn->state == ISCSI_CONNECT_STATE_NORMAL_SESSION) && (opcode != ISCSI_OPCODE_CLIENT_SCSI_DATA_OUT)) ) {
			logadd( LOG_WARNING, "Seqnum messup. Is: %u, want >= %u, < %u",
				request_pdu->cmd_sn, conn->exp_cmd_sn, conn->max_cmd_sn );
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		}
	} else if ( (request_pdu->cmd_sn != conn->exp_cmd_sn) && (opcode != ISCSI_OPCODE_CLIENT_NOP_OUT) ) {
		logadd( LOG_WARNING, "Seqnum messup. Is: %u, want: %u",
			request_pdu->cmd_sn, conn->exp_cmd_sn );
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	if ( ((scsi_cmd_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0) && (opcode != ISCSI_OPCODE_CLIENT_SCSI_DATA_OUT) ) {
		conn->exp_cmd_sn++;
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
 * @param[in] conn Pointer to iSCSI connection to handle. Must
 * NOT be NULL, so take caution.
 * @param[in] request_pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_handle_logout_req(iscsi_connection *conn, const iscsi_pdu *request_pdu)
{
	iscsi_logout_req_packet *logout_req_pkt = (iscsi_logout_req_packet *) request_pdu->bhs_pkt;

	if ( (conn->state == ISCSI_CONNECT_STATE_NEW)
			|| ((logout_req_pkt->reason_code & ISCSI_LOGOUT_REQ_REASON_CODE_MASK) != ISCSI_LOGOUT_REQ_REASON_CODE_CLOSE_SESSION) ) {
		logadd( LOG_DEBUG1, "Invalid logout request in state %d, reason_code %d", conn->state, logout_req_pkt->reason_code );
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_pdu CLEANUP_PDU response_pdu;
	if ( !iscsi_connection_pdu_init( &response_pdu, 0, false ) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_logout_response_packet *logout_response_pkt = (iscsi_logout_response_packet *) response_pdu.bhs_pkt;

	logout_response_pkt->opcode = ISCSI_OPCODE_SERVER_LOGOUT_RES;
	logout_response_pkt->flags  = 0x80;

	const uint16_t cid = iscsi_get_be16(logout_req_pkt->cid);

	if ( cid == conn->cid ) {
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

	if ( conn->state != ISCSI_CONNECT_STATE_NEW ) {
		conn->max_cmd_sn++;

		iscsi_put_be32( (uint8_t *) &logout_response_pkt->exp_cmd_sn, conn->exp_cmd_sn );
		iscsi_put_be32( (uint8_t *) &logout_response_pkt->max_cmd_sn, conn->max_cmd_sn );
	} else {
		iscsi_put_be32( (uint8_t *) &logout_response_pkt->exp_cmd_sn, request_pdu->cmd_sn );
		iscsi_put_be32( (uint8_t *) &logout_response_pkt->max_cmd_sn, request_pdu->cmd_sn );
	}

	logout_response_pkt->reserved4   = 0UL;
	logout_response_pkt->time_wait   = 0U;
	logout_response_pkt->time_retain = 0U;
	logout_response_pkt->reserved5   = 0UL;

	bool ret = iscsi_connection_pdu_write( conn, &response_pdu );

	if ( cid == conn->cid ) {
		conn->state = ISCSI_CONNECT_STATE_EXITING;
	}

	return ret ? ISCSI_CONNECT_PDU_READ_OK : ISCSI_CONNECT_PDU_READ_ERR_FATAL;
}

/**
 * @brief Handles an iSCSI task management function request and generates an appropriate response.
 *
 * This function processes an incoming iSCSI task management function request PDU,
 * constructs a corresponding response PDU, and sends it back to the initiator.
 *
 * @param[in] conn Pointer to the iSCSI connection structure. Must not be NULL.
 * This represents the connection for which the request is being handled.
 * @param[in] request_pdu Pointer to the incoming iSCSI task management function
 * request PDU. Must not be NULL.
 *
 * @return 0 on successful PDU write, or -1 on failure.
 */
static int iscsi_connection_handle_task_func_req(iscsi_connection *conn, const iscsi_pdu *request_pdu)
{
	iscsi_pdu CLEANUP_PDU response_pdu;
	if ( !iscsi_connection_pdu_init( &response_pdu, 0, false ) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	iscsi_task_mgmt_func_response_packet *mgmt_resp = (iscsi_task_mgmt_func_response_packet *) response_pdu.bhs_pkt;
	iscsi_task_mgmt_func_req_packet *mgmt_req = (iscsi_task_mgmt_func_req_packet *) request_pdu->bhs_pkt;

	mgmt_resp->opcode        = ISCSI_OPCODE_SERVER_TASK_FUNC_RES;
	mgmt_resp->response      = ISCSI_TASK_MGMT_FUNC_RESPONSE_FUNC_COMPLETE;
	mgmt_resp->flags         = 0x80;
	mgmt_resp->init_task_tag = mgmt_req->init_task_tag; // Copying over doesn't change endianess.
	iscsi_put_be32( (uint8_t *) &mgmt_resp->stat_sn, conn->stat_sn++ );
	iscsi_put_be32( (uint8_t *) &mgmt_resp->exp_cmd_sn, conn->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &mgmt_resp->max_cmd_sn, conn->max_cmd_sn );

	return iscsi_connection_pdu_write( conn, &response_pdu ) ? 0 : -1;
}

/**
 * @brief Handles receiving and sending of NOP in/out packets.
 *
 * This method can handle a received NOP-Out request and send
 * an according NOP-In response if applicable, i.e. the NOP-Out
 * wasn't sent as a reply to a NOP-In by us.\n
 * This method can also send an unsolicited NOP-In to the client
 * if we want to check whether the connection is still good.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. Must
 * NOT be NULL, so take caution.
 * @param[in] request_pdu Pointer to iSCSI client request PDU to handle,
 * or NULL for sending a connection alive check.
 * @return 0 on success. A negative value indicates
 * an error.
 */
static int iscsi_connection_handle_nop(iscsi_connection *conn, const iscsi_pdu *request_pdu)
{
	if ( conn->state != ISCSI_CONNECT_STATE_NORMAL_SESSION )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	if ( request_pdu != NULL && request_pdu->ds_len > ISCSI_DEFAULT_MAX_RECV_DS_LEN )
		return iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	iscsi_nop_out_packet *nop_out_pkt = request_pdu == NULL ? NULL : (iscsi_nop_out_packet *) request_pdu->bhs_pkt;
	const uint32_t target_xfer_tag    = nop_out_pkt == NULL ? 0xFFFFFFFFUL : iscsi_get_be32(nop_out_pkt->target_xfer_tag);
	const uint32_t init_task_tag      = nop_out_pkt == NULL ? 0 : iscsi_get_be32(nop_out_pkt->init_task_tag);
	uint32_t ds_len                   = request_pdu == NULL ? 0 : request_pdu->ds_len;
	const uint64_t lun                = nop_out_pkt == NULL ? 0 : iscsi_get_be64(nop_out_pkt->lun);

	if ( init_task_tag == 0xFFFFFFFFUL ) // Was response to a NOP by us, or no response desired - do not reply
		return ISCSI_CONNECT_PDU_READ_OK;

	if ( target_xfer_tag != 0xFFFFFFFFUL ) // If the initiator tag is not the special value, the target tag has to be.
		return iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_INVALID_PDU_FIELD );

	if ( ds_len > (uint32_t)conn->opts.MaxRecvDataSegmentLength ) {
		ds_len = conn->opts.MaxRecvDataSegmentLength;
	}

	iscsi_pdu CLEANUP_PDU response_pdu;
	if ( !iscsi_connection_pdu_init( &response_pdu, ds_len, false ) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_nop_in_packet *nop_in_pkt = (iscsi_nop_in_packet *) response_pdu.bhs_pkt;

	nop_in_pkt->opcode          = ISCSI_OPCODE_SERVER_NOP_IN;
	nop_in_pkt->flags           = 0x80;
	nop_in_pkt->reserved        = 0U;
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->total_ahs_len, ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	iscsi_put_be64( (uint8_t *) &nop_in_pkt->lun, lun );
	if ( nop_out_pkt == NULL ) {
		// Send a request which needs a reply, set target tag to anything but the special value
		nop_in_pkt->init_task_tag   = 0xFFFFFFFFUL;
		nop_in_pkt->target_xfer_tag = 0;
		iscsi_put_be32( (uint8_t *) &nop_in_pkt->stat_sn, conn->stat_sn ); // Don't inc
	} else {
		// This is a reply, set target tag to special value to indicate we don't want a NOP-Out in response
		iscsi_put_be32( (uint8_t *) &nop_in_pkt->init_task_tag, init_task_tag );
		nop_in_pkt->target_xfer_tag = 0xFFFFFFFFUL;
		iscsi_put_be32( (uint8_t *) &nop_in_pkt->stat_sn, conn->stat_sn++ ); // Inc
	}

	if ( nop_out_pkt == NULL || (nop_out_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 ) {
		conn->max_cmd_sn++;
	}

	iscsi_put_be32( (uint8_t *) &nop_in_pkt->exp_cmd_sn, conn->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->max_cmd_sn, conn->max_cmd_sn );
	nop_in_pkt->reserved2 = 0UL;
	nop_in_pkt->reserved3 = 0ULL;

	if ( ds_len != 0UL ) {
		memcpy( response_pdu.ds_cmd_data, request_pdu->ds_cmd_data, ds_len );
	}

	return iscsi_connection_pdu_write( conn, &response_pdu ) ? 0 : -1;
}

/**
 * @brief Handles an incoming iSCSI payload data SCSI command request PDU.
 *
 * This function handles SCSI command request payload
 * data sent by the client.\n
 * If a response needs to be sent, this will
 * be done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. Must
 * NOT be NULL, so take caution.
 * @param[in] request_pdu Pointer to iSCSI client request PDU to handle.
 * May be NULL in which case an error is returned.
 * @return 0 on success. A negative value indicates
 * an error. A positive value a warning.
 */
static int iscsi_connection_handle_scsi_cmd(iscsi_connection *conn, const iscsi_pdu *request_pdu)
{
	bool handled = false;
	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) request_pdu->bhs_pkt;
	uint32_t exp_xfer_len = iscsi_get_be32(scsi_cmd_pkt->exp_xfer_len);
	iscsi_task task = {
		.lun_id        = iscsi_scsi_lun_get_from_iscsi( iscsi_get_be64(scsi_cmd_pkt->lun) ),
		.init_task_tag = iscsi_get_be32(scsi_cmd_pkt->init_task_tag),

		.scsi_task.cdb          = &scsi_cmd_pkt->scsi_cdb,
		.scsi_task.exp_xfer_len = exp_xfer_len,
		.scsi_task.status       = ISCSI_SCSI_STATUS_GOOD,
		.scsi_task.connection   = conn,
	};

	// Per iSCSI, READ/WRITE bits in flags_task indicate data direction for this CDB
	if ( (scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_READ) != 0 ) {
		task.scsi_task.is_read = true;
	} else {
		if ( exp_xfer_len != 0UL ) {
			// Not a read request, but expecting data - not valid
			iscsi_scsi_task_status_set( &task.scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ,
					ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
			handled = true;
		}
	}

	if ( !handled ) {
		task.scsi_task.is_write = (scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_WRITE) != 0;

		// Single-LUN target for now, reject unknown LUNs with ILLEGAL REQUEST
		if ( task.lun_id != ISCSI_DEFAULT_LUN ) {
			logadd( LOG_WARNING, "Received SCSI command for unknown LUN %d", task.lun_id );
			iscsi_scsi_task_status_set( &task.scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ,
					ISCSI_SCSI_ASC_LU_NOT_SUPPORTED, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
			handled = true;
		} else {
			task.scsi_task.status = ISCSI_SCSI_STATUS_GOOD;

			// Try block commands first (READ/WRITE family), then primary (INQUIRY, MODE SENSE, etc.)
			handled = iscsi_scsi_emu_block_process( &task.scsi_task ) || iscsi_scsi_emu_primary_process( &task.scsi_task );

			if ( !handled ) {
				iscsi_scsi_task_status_set( &task.scsi_task, ISCSI_SCSI_STATUS_CHECK_COND,
						ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_COMMAND_OPERATION_CODE,
						ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
			}
		}
	}

	iscsi_scsi_task_send_reply( conn, &task.scsi_task, request_pdu );
	// Free any buffers that were allocated for this task
	free( task.scsi_task.buf );
	free( task.scsi_task.sense_data );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles iSCSI connection login phase none.
 *
 * This function negotiates the login phase
 * without a session.
 *
 * @param[in] conn Pointer to iSCSI connection,
 * must NOT be NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU.
 * NULL is not allowed here, so take caution.
 * @param[in] kvpairs Pointer to key and value pairs.
 * which must NOT be NULL, so take caution.
 * @return 0 on success, a negative error code otherwise.
 */
static int iscsi_connection_handle_login_phase_none(iscsi_connection *conn, const iscsi_pdu *login_response_pdu, const iscsi_negotiation_kvp *kvpairs)
{
	int type;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
	int rc = iscsi_login_parse_session_type( login_response_pdu, kvpairs->SessionType, &type );

	if ( rc < 0 )
		return rc;

	if ( type != ISCSI_CONNECT_STATE_NORMAL_SESSION ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_SESSION_NO_SUPPORT;
		rc = ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	} else if ( kvpairs->TargetName != NULL ) {
		rc = iscsi_image_from_target( conn, login_response_pdu, kvpairs->TargetName );
	} else {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;
		rc = ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	if ( rc < 0 )
		return rc;

	if ( conn->state == ISCSI_CONNECT_STATE_NEW ) {
		conn->stat_sn            = iscsi_get_be32(login_response_pkt->stat_sn);

		conn->exp_cmd_sn  = login_response_pdu->cmd_sn;
		conn->max_cmd_sn  = (uint32_t) (login_response_pdu->cmd_sn + ISCSI_DEFAULT_QUEUE_DEPTH - 1UL);
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Writes login options to a PDU (Protocol Data Unit).
 *
 * This function processes key-value pairs of login negotiation options and
 * appends them to the specified PDU. The function ensures the payload of the
 * response PDU does not exceed its designated length.
 *
 * @param[in] conn Pointer to the iSCSI connection structure containing session
 * options and other connection-specific information.
 * @param[in] pairs Pointer to the iSCSI negotiation key-value pairs structure
 * that holds applicable key-value options for the login phase.
 * @param[in,out] response_pdu Pointer to the PDU where the login options should
 * be added. The PDU's fields, such as data segment and payload length, are
 * updated within the function.
 *
 * @return The updated payload length of the response PDU if successful.
 * Returns -1 if an error occurs during key-value pair appending.
 */
static int iscsi_write_login_options_to_pdu(const iscsi_connection *conn, const iscsi_negotiation_kvp *pairs, iscsi_pdu *response_pdu)
{
	uint payload_len = response_pdu->ds_write_pos;

#	define ADD_KV_INTERNAL(num, key, value) do { \
int rc = iscsi_append_key_value_pair_packet( num, key, value, (char *)response_pdu->ds_cmd_data, payload_len, response_pdu->ds_len ); \
if ( rc < 0 ) return -1; \
payload_len += rc; \
} while (0)
#	define ADD_KV_OPTION_INT(key) do { \
if ( pairs->key != -1 ) ADD_KV_INTERNAL( true, #key, (const char *)(size_t)conn->opts.key ); \
} while (0)
#	define ADD_KV_OPTION_STR(key) do { \
if ( pairs->key != NULL ) ADD_KV_INTERNAL( false, #key, conn->opts.key ); \
} while (0)
#	define ADD_KV_PLAIN_INT(key, value) do { \
if ( pairs->key != -1 ) ADD_KV_INTERNAL( true, #key, (const char *)(size_t)(value) ); \
} while (0)
#	define ADD_KV_PLAIN_STR(key, value) do { \
if ( pairs->key != NULL ) ADD_KV_INTERNAL( false, #key, value ); \
} while (0)
	// Reply with these settings with actually negotiated values
	ADD_KV_OPTION_INT( MaxRecvDataSegmentLength );
	ADD_KV_OPTION_INT( MaxBurstLength );
	ADD_KV_OPTION_INT( FirstBurstLength );
	// These are always hard-coded to specific value, we don't support anything else
	ADD_KV_PLAIN_INT( MaxConnections, 1 );
	ADD_KV_PLAIN_INT( ErrorRecoveryLevel, 0 );
	ADD_KV_PLAIN_STR( HeaderDigest, "None" );
	ADD_KV_PLAIN_STR( DataDigest, "None" );
#	undef ADD_KV_PLAIN
#	undef ADD_KV_OPTION_INT
#	undef ADD_KV_OPTION_STR

	if ( payload_len <= response_pdu->ds_len ) {
		response_pdu->ds_write_pos = payload_len;
	} else {
		response_pdu->ds_write_pos = response_pdu->ds_len;
	}
	return (int)payload_len;
}

/**
 * @brief Handles iSCSI connection login response.
 *
 * This function negotiates the login parameters
 * and determines the authentication method.
 *
 * @param[in] conn Pointer to iSCSI connection,
 * must NOT be NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU.
 * NULL is not allowed here, so take caution.
 * @param[in] pairs Readily parsed key-value-pairs from according request
 * @return 0 on success, a negative error code otherwise.
 */
static int iscsi_connection_handle_login_response(iscsi_connection *conn, iscsi_pdu *login_response_pdu,  const iscsi_negotiation_kvp *pairs)
{
	if ( iscsi_connection_pdu_resize( login_response_pdu, 0, ISCSI_DEFAULT_RECV_DS_LEN ) == NULL ) {
		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	// Handle current stage (CSG bits)
	switch ( ISCSI_LOGIN_RESPONSE_FLAGS_GET_CURRENT_STAGE(login_response_pkt->flags) ) {
	case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION : {
		logadd( LOG_DEBUG1, "security nego" );
		if ( pairs->AuthMethod == NULL || strcasecmp( pairs->AuthMethod, "None" ) != 0 ) {
			// Only "None" supported
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}

		break;
	}
	case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION : {
		// Nothing to do, expect client to request transition to full feature phase
		break;
	}
	case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_FULL_FEATURE_PHASE :
	default : {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}
	}

	if ( (login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0 ) {
		// Client set the transition bit - requests to move on to next stage
		switch ( ISCSI_LOGIN_RESPONSE_FLAGS_GET_NEXT_STAGE(login_response_pkt->flags) ) {
		case ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_FULL_FEATURE_PHASE : {

			iscsi_put_be16( (uint8_t *) &login_response_pkt->tsih, 42 );

			conn->state = ISCSI_CONNECT_STATE_NORMAL_SESSION;

			iscsi_connection_update_key_value_pairs( conn, pairs );
			int payload_len = iscsi_write_login_options_to_pdu( conn, pairs, login_response_pdu );

			if ( payload_len < 0 || (uint32_t)payload_len > login_response_pdu->ds_len ) {
				logadd( LOG_DEBUG1, "iscsi_connecction_handle_login_response: Invalid payload length %d, ds_len: %u, write_pos: %u",
					payload_len, login_response_pdu->ds_len, login_response_pdu->ds_write_pos );
				login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
				login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

				return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
			}
			char tname[50];
			snprintf( tname, sizeof(tname), "i%s", conn->client->hostName );
			setThreadName( tname );

			break;
		}
		default : {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}
		}
	}

	return ISCSI_CONNECT_PDU_READ_OK;
}

/**
 * @brief Handles an incoming iSCSI login request PDU.
 *
 * Parses the login request, builds a corresponding login response PDU and
 * sends it. Performs basic validation (e.g., MaxRecvDataSegmentLength and
 * login phase/state). On certain errors, a reject or error response is sent.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. Must
 * NOT be NULL, so take caution.
 * @param[in] request_pdu Pointer to iSCSI client request PDU to handle.
 * Must NOT be NULL.
 * @return ISCSI_CONNECT_PDU_READ_OK on success; a negative
 * ISCSI_CONNECT_PDU_READ_ERR_* code on error.
 */
static int iscsi_connection_handle_login_req(iscsi_connection *conn, iscsi_pdu *request_pdu)
{
	// Reject malformed login PDUs:
	// - DataSegmentLength must fit our initial receive buffer (we don't support multi-PDU login here)
	// - Login is only valid in NEW state (before full feature phase)
	if ( request_pdu->ds_len > ISCSI_DEFAULT_RECV_DS_LEN || conn->state != ISCSI_CONNECT_STATE_NEW )
		return iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	const iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) request_pdu->bhs_pkt;

	request_pdu->cmd_sn = iscsi_get_be32(login_req_pkt->cmd_sn);

	// Prepare a response PDU; helper will size DS as needed later
	iscsi_pdu CLEANUP_PDU login_response_pdu;
	if ( !iscsi_connection_pdu_init( &login_response_pdu, 0, false ) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	int rc = iscsi_connection_pdu_login_response_init( &login_response_pdu, request_pdu );

	if ( rc < 0 ) {
		// response_init already encoded an error in the response PDU - send and bail
		return iscsi_send_login_response_pdu( conn, &login_response_pdu );
	}

	iscsi_negotiation_kvp pairs;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu.bhs_pkt;
	// Parse key=value pairs from the login text payload
	rc = iscsi_parse_login_key_value_pairs( &pairs, (uint8_t *) request_pdu->ds_cmd_data, request_pdu->ds_len );

	if ( rc < 0 ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

		return iscsi_send_login_response_pdu( conn, &login_response_pdu );
	}

	// Handle security/operational negotiation for this stage
	rc = iscsi_connection_handle_login_phase_none( conn, &login_response_pdu, &pairs );

	if ( rc != ISCSI_CONNECT_PDU_READ_OK ) {
		return iscsi_send_login_response_pdu( conn, &login_response_pdu );
	}

	// Possibly transition to next stage depending on flags
	iscsi_connection_handle_login_response( conn, &login_response_pdu, &pairs );
	if ( conn->state == ISCSI_CONNECT_STATE_NORMAL_SESSION ) {
		// Record ConnectionID from request once we enter full feature phase
		conn->cid = iscsi_get_be16(login_req_pkt->cid);
	}
	return iscsi_send_login_response_pdu( conn, &login_response_pdu );
}

/**
 * @brief Handles an incoming iSCSI text request PDU.
 *
 * Parses the key-value pairs in the text request and responds with a text
 * response PDU containing the negotiated values. Multi-PDU continuation of
 * text requests is not supported.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. Must NOT be NULL.
 * @param[in] request_pdu Pointer to iSCSI client request PDU to handle.
 * Must NOT be NULL.
 * @return ISCSI_CONNECT_PDU_READ_OK on success; a negative
 * ISCSI_CONNECT_PDU_READ_ERR_* code on error or when a reject is sent.
 */
static int iscsi_connection_handle_text_req(iscsi_connection *conn, const iscsi_pdu *request_pdu)
{
	iscsi_text_req_packet *text_req_pkt = (iscsi_text_req_packet *) request_pdu->bhs_pkt;

	if ( request_pdu->ds_len > ISCSI_MAX_DS_SIZE )
		return iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	if ( (text_req_pkt->flags & (ISCSI_TEXT_REQ_FLAGS_CONTINUE | ISCSI_TEXT_REQ_FLAGS_FINAL))
			== (ISCSI_TEXT_REQ_FLAGS_CONTINUE | ISCSI_TEXT_REQ_FLAGS_FINAL) ) {
		// Continue and Final at the same time is invalid
		return iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );
	}
	if ( (text_req_pkt->flags & ISCSI_TEXT_REQ_FLAGS_FINAL) == 0 ) {
		// Text request spread across multiple PDUs not supported
		return iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_COMMAND_NOT_SUPPORTED );
	}
	if ( text_req_pkt->target_xfer_tag != 0xFFFFFFFFUL ) {
		// Initial request must have this set to all 1
		return iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );
	}

	const uint32_t exp_stat_sn   = iscsi_get_be32(text_req_pkt->exp_stat_sn);
	if ( exp_stat_sn != conn->stat_sn ) {
		conn->stat_sn = exp_stat_sn;
	}

	iscsi_negotiation_kvp pairs;
	int rc = iscsi_parse_login_key_value_pairs( &pairs, (uint8_t *) request_pdu->ds_cmd_data, request_pdu->ds_len );

	if ( rc < 0 ) {
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_pdu CLEANUP_PDU response_pdu;
	if ( !iscsi_connection_pdu_init( &response_pdu, MIN( 8192, conn->opts.MaxRecvDataSegmentLength ), false ) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_connection_update_key_value_pairs( conn, &pairs );

	// TODO: Handle SendTargets
	int payload_len = iscsi_write_login_options_to_pdu( conn, &pairs, &response_pdu );

	if ( payload_len < 0 || (uint32_t)payload_len > response_pdu.ds_len ) {
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_text_response_packet *text_response_pkt =
		(iscsi_text_response_packet *) iscsi_connection_pdu_resize( &response_pdu, 0, response_pdu.ds_write_pos );

	text_response_pkt->opcode = ISCSI_OPCODE_SERVER_TEXT_RES;
	text_response_pkt->flags  = (int8_t) ISCSI_TEXT_RESPONSE_FLAGS_FINAL;

	text_response_pkt->reserved = 0;

	// TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	iscsi_put_be32( (uint8_t *) &text_response_pkt->total_ahs_len, response_pdu.ds_write_pos );
	text_response_pkt->lun             = text_req_pkt->lun; // Copying over doesn't change endianess.
	text_response_pkt->init_task_tag   = text_req_pkt->init_task_tag; // Copying over doesn't change endianess.
	text_response_pkt->target_xfer_tag = 0xFFFFFFFFUL; // Minus one does not require endianess conversion

	iscsi_put_be32( (uint8_t *) &text_response_pkt->stat_sn, conn->stat_sn++ );

	conn->max_cmd_sn++;

	iscsi_put_be32( (uint8_t *) &text_response_pkt->exp_cmd_sn, conn->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &text_response_pkt->max_cmd_sn, conn->max_cmd_sn );
	text_response_pkt->reserved2[0] = 0ULL;
	text_response_pkt->reserved2[1] = 0ULL;

	return iscsi_connection_pdu_write( conn, &response_pdu ) ? ISCSI_CONNECT_PDU_READ_OK : ISCSI_CONNECT_PDU_READ_ERR_FATAL;
}

/**
 * @brief Dispatches and handles a single incoming iSCSI request PDU.
 *
 * Parses the opcode from the request PDU and invokes the corresponding
 * handler. On protocol errors, a REJECT may be sent. Fatal errors set the
 * connection to exiting state via lower-level helpers.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. Must NOT be NULL.
 * @param[in] request_pdu Pointer to iSCSI client request PDU to handle.
 * Must NOT be NULL.
 * @return ISCSI_CONNECT_PDU_READ_OK on success; a negative
 * ISCSI_CONNECT_PDU_READ_ERR_* code on error.
 */
static int iscsi_connection_pdu_handle(iscsi_connection *conn, iscsi_pdu *request_pdu)
{
	int rc = 0;

	const uint8_t opcode = ISCSI_GET_OPCODE(request_pdu->bhs_pkt->opcode);

	if ( conn->state == ISCSI_CONNECT_STATE_NEW ) {
		// Fresh connection, not logged in yet - per RFC7143 only LOGIN PDUs are valid here.
		if ( opcode == ISCSI_OPCODE_CLIENT_LOGIN_REQ ) {
			rc = iscsi_connection_handle_login_req( conn, request_pdu );
		} else {
			rc = iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );
		}
	} else if ( conn->state == ISCSI_CONNECT_STATE_EXITING ) {
		// Already transitioning to close: ignore further work but report OK so caller can unwind.
		rc = ISCSI_CONNECT_PDU_READ_OK;
	} else if ( conn->state == ISCSI_CONNECT_STATE_NORMAL_SESSION ) {
		// Normal full-feature phase operation.
		// First validate/advance CmdSN window semantics (ExpCmdSN/MaxCmdSN handling).
		rc = iscsi_connection_handle_cmd_sn( conn, request_pdu );
		if ( rc != 0 )
			return rc;

		switch ( opcode ) {
			case ISCSI_OPCODE_CLIENT_NOP_OUT : {
				// Keep-alive ping from initiator or response to our NOP-In
				rc = iscsi_connection_handle_nop( conn, request_pdu );

				break;
			}
			case ISCSI_OPCODE_CLIENT_SCSI_CMD : {
				// SCSI CDB request - may entail data-in or data-out depending on flags
				rc = iscsi_connection_handle_scsi_cmd( conn, request_pdu );

				break;
			}
			case ISCSI_OPCODE_CLIENT_TEXT_REQ : {
				// Text negotiation/SendTargets style key=value exchange
				rc = iscsi_connection_handle_text_req( conn, request_pdu );

				break;
			}
			case ISCSI_OPCODE_CLIENT_LOGOUT_REQ : {
				// Session/connection logout (transition to exiting handled in callee)
				rc = iscsi_connection_handle_logout_req( conn, request_pdu );

				break;
			}
			case ISCSI_OPCODE_CLIENT_TASK_FUNC_REQ : {
				// Task management functions (ABORT TASK, CLEAR TASK SET, etc.)
				rc = iscsi_connection_handle_task_func_req( conn, request_pdu );

				break;
			}
			default : {
				// Unknown/unsupported opcode - protocol error
				rc = iscsi_connection_handle_reject( conn, request_pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

				break;
			}
		}
	}

	if ( rc < 0 ) {
		logadd( LOG_ERROR, "Fatal error during payload handler (opcode 0x%02x) detected for client %s", (int) opcode, conn->client->hostName );
	}

	return rc;
}

/**
 * @brief Reads and processes incoming iSCSI connection PDUs in a loop.
 *
 * This function continuously reads Protocol Data Units (PDUs) on an iSCSI
 * connection and performs operations based on the type and content of the
 * received data. The function processes Basic Header Segment (BHS), Additional
 * Header Segment (AHS), and Data Segment (DS) as part of the PDU handling. If
 * any errors occur during the process, the function gracefully exits the loop.
 *
 * @param[in] conn Pointer to the iSCSI connection object. Must not be NULL and
 * contains the state and data required for processing the iSCSI connection.
 * @param[in] request Pointer to the initial received data for the PDU. This
 * serves as the partially received data of the BHS. Must not be NULL.
 * @param[in] len Length of the already received portion of the BHS in bytes.
 */
static void iscsi_connection_pdu_read_loop(iscsi_connection *conn, const dnbd3_request_t *request, const int len)
{
	ssize_t ret;
	iscsi_pdu CLEANUP_PDU request_pdu;

	if ( !iscsi_connection_pdu_init( &request_pdu, 0, false ) )
		return;

	// 1) Receive BHS (partially already received, in "request", merge and finish)
	memcpy( request_pdu.bhs_pkt, request, len );
	if ( (size_t)sock_recv( conn->client->sock, ((uint8_t *)request_pdu.bhs_pkt) + len, sizeof(iscsi_bhs_packet) - len )
			!= sizeof(iscsi_bhs_packet) - len ) {
		logadd( LOG_INFO, "Cannot receive first BHS from client %s", conn->client->hostName );
		return;
	}

	do {
		// 2) Evaluate BHS regarding length of AHS and DS
		// total_ahs_len is encoded in 4-byte units per RFC; ds_len is 24-bit big-endian.
		iscsi_bhs_packet *bhs_pkt = request_pdu.bhs_pkt;
		const uint ahs_len        = ((uint) bhs_pkt->total_ahs_len * ISCSI_ALIGN_SIZE);
		const uint32_t ds_len     = iscsi_get_be24(bhs_pkt->ds_len);

		bhs_pkt = iscsi_connection_pdu_resize( &request_pdu, ahs_len, ds_len );

		if ( bhs_pkt == NULL ) {
			// Allocation/size sanity failed; cannot proceed with this PDU
			logadd( LOG_WARNING, "Cannot resize PDU for client %s", conn->client->hostName );
			break;
		}

		// 3) Receive the optional AHS
		if ( ahs_len != 0 && sock_recv( conn->client->sock, request_pdu.ahs_pkt, ahs_len ) != ahs_len ) {
			logadd( LOG_DEBUG1, "Could not receive AHS from client %s", conn->client->hostName );
			break;
		}

		// 4) Receive the optional DS
		if ( request_pdu.ds_len != 0U ) {
			const uint32_t padded_ds_len = ISCSI_ALIGN( request_pdu.ds_len, ISCSI_ALIGN_SIZE );

			if ( sock_recv( conn->client->sock, request_pdu.ds_cmd_data, padded_ds_len ) != padded_ds_len ) {
				logadd( LOG_DEBUG1, "Could not receive DS from client %s", conn->client->hostName );
				break;
			}
		}

		// 5) Handle PDU
		if ( iscsi_connection_pdu_handle( conn, &request_pdu ) != ISCSI_CONNECT_PDU_READ_OK
				|| conn->state == ISCSI_CONNECT_STATE_EXITING ) {
			// Either handler reported a fatal/terminal condition or connection is shutting down
			break;
		}

		// In case we needed an extra buffer, reset
		if ( request_pdu.big_alloc != NULL ) {
			iscsi_connection_pdu_destroy( &request_pdu );
			if ( !iscsi_connection_pdu_init( &request_pdu, 0, false ) ) {
				logadd( LOG_WARNING, "Cannot re-initialize PDU for client %s", conn->client->hostName );
				break;
			}
		}

		// Move first part of next iteration last in this loop, as we completed the first, partial
		// header before the loop - this saves us from accounting for this within the mainloop

		// 1) Receive entire BHS
		ret = sock_recv( conn->client->sock, request_pdu.bhs_pkt, sizeof(iscsi_bhs_packet) );
		if ( ret == -1 && errno == EAGAIN ) {
			// Receive timeout - send a NOP-In and try recv one more time; a healthy initiator should reply NOP-Out
			if ( iscsi_connection_handle_nop( conn, NULL ) != ISCSI_CONNECT_PDU_READ_OK ) {
				logadd( LOG_DEBUG1, "Cannot send NOP-In to idle client %s - connection dead", conn->client->hostName );
				break;
			}
			ret = sock_recv( conn->client->sock, request_pdu.bhs_pkt, sizeof(iscsi_bhs_packet) );
		}
		if ( ret != sizeof(iscsi_bhs_packet) ) {
			logadd( LOG_DEBUG1, "Cannot receive BHS from client %s (%d/%d)", conn->client->hostName, (int)ret, (int)errno );
			break;
		}
	} while ( !_shutdown );
}

/**
 * @brief Handles an iSCSI connection until it is closed.
 *
 * Initializes a per-connection state object, processes incoming PDUs by
 * delegating to the PDU read loop (which continues until an error, shutdown,
 * or explicit exit state), and finally shuts down the write side of the socket
 * while draining any remaining incoming data.
 *
 * @param[in] client Pointer to DNBD3 client structure.
 * Must NOT be NULL.
 * @param[in] request Pointer to the already-received initial bytes (partial
 * Basic Header Segment) of the first iSCSI PDU. Must NOT be NULL.
 * @param[in] len Length in bytes of the initial data in 'request'.
 */
void iscsi_connection_handle(dnbd3_client_t *client, const dnbd3_request_t *request, const int len)
{
	_Static_assert( sizeof(dnbd3_request_t) <= sizeof(iscsi_bhs_packet),
		"DNBD3 request size larger than iSCSI BHS packet data size - Manual intervention required!" );

	iscsi_connection conn = {
		.state =  ISCSI_CONNECT_STATE_NEW,
		.client = client,
	};

	static atomic_int CONN_ID = 0;
	conn.id = ++CONN_ID;

	iscsi_connection_pdu_read_loop( &conn, request, len );

	// Wait for the client to receive any pending outgoing PDUs
	shutdown( client->sock, SHUT_WR );
	sock_setTimeout( client->sock, 100 );
	while ( recv( client->sock, (void *)request, len, 0 ) > 0 ) {}
}
