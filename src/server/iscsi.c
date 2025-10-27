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

#include "sendfile.h"
#include "globals.h"
#include "helper.h"
#include "image.h"
#include "iscsi.h"
#include "uplink.h"
#include "reference.h"

#include <assert.h>

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


static int iscsi_scsi_emu_block_process(iscsi_scsi_task *scsi_task);

static int iscsi_scsi_emu_primary_process(iscsi_scsi_task *scsi_task);


static void iscsi_scsi_task_create(iscsi_scsi_task *scsi_task); // Allocates and initializes a SCSI task

static void iscsi_scsi_task_xfer_complete(iscsi_scsi_task *scsi_task, iscsi_pdu *pdu); // Callback function when an iSCSI SCSI task completed the data transfer

static void iscsi_scsi_task_lun_process_none(iscsi_scsi_task *scsi_task); // Processes a iSCSI SCSI task with no LUN identifier


static uint64_t iscsi_scsi_lun_get_from_scsi(const int lun_id); // Converts an internal representation of a LUN identifier to an iSCSI LUN required for packet data
static int iscsi_scsi_lun_get_from_iscsi(const uint64_t lun); // Converts an iSCSI LUN from packet data to internal SCSI LUN identifier

static void iscsi_scsi_lun_task_run( iscsi_scsi_task *scsi_task, iscsi_pdu *pdu); // Runs an iSCSI SCSI task for a specified iSCSI SCSI LUN

static int iscsi_scsi_emu_io_blocks_read(iscsi_scsi_task *scsi_task,  dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks); // Reads a number of blocks from a block offset of a DNBD3 image to a specified buffer


static void iscsi_strcpy_pad(char *dst, const char *src, const size_t size, const int pad); // Copies a string with additional padding character to fill in a specified size


static iscsi_task *iscsi_task_create(iscsi_connection *conn); // Allocates and initializes an iSCSI task structure
static void iscsi_task_destroy(iscsi_task *task); // Deallocates resources acquired by iscsi_task_create

static void iscsi_task_response(iscsi_connection *conn, iscsi_task *task, iscsi_pdu *pdu); // Creates, initializes and sends an iSCSI task reponse PDU.

static uint64_t iscsi_target_node_wwn_get(const uint8_t *name); // Calculates the WWN using 64-bit IEEE Extended NAA for a name

static iscsi_session *iscsi_session_create(iscsi_connection *conn,  const int type); // Creates and initializes an iSCSI session
static void iscsi_session_destroy(iscsi_session *session); // Deallocates all resources acquired by iscsi_session_create


static iscsi_connection *iscsi_connection_create(dnbd3_client_t *client); // Creates data structure for an iSCSI connection from iSCSI portal and TCP/IP socket
static void iscsi_connection_destroy(iscsi_connection *conn); // Deallocates all resources acquired by iscsi_connection_create

static int32_t iscsi_connection_read(const iscsi_connection *conn, uint8_t *buf, const uint32_t len); // Reads data for the specified iSCSI connection from its TCP socket

static void iscsi_connection_login_response_reject(iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu); // Initializes a rejecting login response packet
static iscsi_pdu *iscsi_connection_pdu_create(iscsi_connection *conn, const uint32_t ds_len, bool no_ds_alloc);
static void iscsi_connection_pdu_destroy(iscsi_pdu *pdu); // Destroys an iSCSI PDU structure used by connections

static iscsi_bhs_packet *iscsi_connection_pdu_resize(iscsi_pdu *pdu, const uint ahs_len,  const uint32_t ds_len); // Appends packet data to an iSCSI PDU structure used by connections

static bool iscsi_connection_pdu_write(iscsi_connection *conn, iscsi_pdu *pdu);


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
 * May NOT be NULL, so take caution.
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
 * extracted keys and pairs. May NOT be NULL, so take caution.
 * @param[in] packet_data Pointer to first key and value pair to
 * be parsed. NULL is an illegal value here, so be careful.
 * @param[in] len Length of the remaining packet data.
 * @retval -1 An error occured during parsing key.
 * @retval 0 Key and value pair was parsed successfully and was added to
 * hash map.
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
 * @return Pointer to iSCSI task structure or NULL
 * in case of an error (memory exhaustion).
 */
static iscsi_task *iscsi_task_create(iscsi_connection *conn)
{
	iscsi_task *task = malloc( sizeof(struct iscsi_task) );

	if ( task == NULL ) {
		logadd( LOG_ERROR, "iscsi_task_create: Out of memory while allocating iSCSI task" );

		return NULL;
	}

	task->conn              = conn;
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

	iscsi_scsi_task_create( &task->scsi_task );
	task->scsi_task.connection = conn;

	return task;
}

/**
 * @brief Deallocates resources acquired by iscsi_task_create.
 *
 * This function also frees the embedded SCSI task.
 *
 * @param[in] task Pointer to iSCSI task to deallocate. If
 * set to NULL, this function does nothing.
 */
static void iscsi_task_destroy(iscsi_task *task)
{
	if ( task == NULL )
		return;

	if ( task->scsi_task.must_free ) {
		free( task->scsi_task.buf );
	}
	free( task->scsi_task.sense_data );
	free( task );
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
static uint32_t iscsi_scsi_data_in_send(iscsi_connection *conn, iscsi_task *task, const uint32_t pos, const uint32_t len, const uint32_t res_cnt, const uint32_t data_sn, const int8_t flags, bool immediate)
{
	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, len, true );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_scsi_data_in_send: Out of memory while allocating iSCSI SCSI Data In response PDU" );

		return data_sn;
	}

	response_pdu->task = task;

	iscsi_scsi_data_in_response_packet *scsi_data_in_pkt = (iscsi_scsi_data_in_response_packet *) response_pdu->bhs_pkt;

	scsi_data_in_pkt->opcode   = ISCSI_OPCODE_SERVER_SCSI_DATA_IN;
	scsi_data_in_pkt->flags    = (flags & ~(ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_UNDERFLOW | ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_OVERFLOW));
	scsi_data_in_pkt->reserved = 0U;

	if ( (flags & ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS) != 0 ) {
		if ( (flags & ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_FINAL) != 0 ) {
			scsi_data_in_pkt->flags |= (flags & (ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_UNDERFLOW | ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_RES_OVERFLOW));

			if ( !immediate ) {
				conn->session->max_cmd_sn++;
			}

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

	iscsi_put_be32( (uint8_t *) &scsi_data_in_pkt->buf_offset, pos );

	iscsi_connection_pdu_write( conn, response_pdu );

	if ( task->scsi_task.buf != NULL ) {
		if ( !sock_sendAll( conn->client->sock, (task->scsi_task.buf + pos), len, ISCSI_CONNECT_SOCKET_WRITE_RETRIES ) ) {
			// Set error
			return data_sn;
		}
		if ( len % ISCSI_ALIGN_SIZE != 0 ) {
			const size_t padding = ISCSI_ALIGN_SIZE - (len % ISCSI_ALIGN_SIZE);
			if ( !sock_sendPadding( conn->client->sock, padding ) ) {
				// Set error
				return data_sn;
			}
		}
	} else {
		const off_t off = task->scsi_task.file_offset + pos;
		size_t padding = 0;
		size_t realBytes = len;
		if ( off >= conn->client->image->realFilesize ) {
			padding = len;
			realBytes = 0;
		} else if ( off + len > conn->client->image->realFilesize ) {
			padding = ( off + len ) - conn->client->image->realFilesize;
			realBytes -= padding;
		}
		bool ret = sendfile_all( conn->client->image->readFd, conn->client->sock,
			off, realBytes );
		if ( !ret ) {
			// Set error
			return data_sn;
		}
		if ( padding > 0 ) {
			if ( !sock_sendPadding( conn->client->sock, padding ) ) {
				// Set error
				return data_sn;
			}
		}
	}

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
 * @param immediate
 * @return 0 on successful incoming transfer handling,
 * a negative error code otherwise.
 */
static int iscsi_task_xfer_scsi_data_in(iscsi_connection *conn, iscsi_task *task, bool immediate)
{
	if ( task->scsi_task.status != ISCSI_SCSI_STATUS_GOOD )
		return 0;

	const uint32_t pos      = task->scsi_task.xfer_pos;
	uint32_t xfer_len       = task->scsi_task.len;
	const uint32_t seg_len  = conn->session->opts.MaxRecvDataSegmentLength;
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
	if ( xfer_len == 0UL )
		return 0;

	uint32_t data_sn                 = task->data_sn;
	uint32_t max_burst_offset        = 0UL;
	const uint32_t max_burst_len     = conn->session->opts.MaxBurstLength;
	const uint32_t data_in_seq_count = ((xfer_len - 1UL) / max_burst_len) + 1UL;
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

				if ( (task->scsi_task.sense_data_len == 0U) && ((offset + len) == xfer_len) && (task->des_data_xfer_pos == task->scsi_task.xfer_len) ) {
					flags  |= (int8_t) ISCSI_SCSI_DATA_IN_RESPONSE_FLAGS_STATUS;
					status |= flags;
				}
			}

			data_sn = iscsi_scsi_data_in_send( conn, task, offset, len, res_cnt, data_sn, flags, immediate );
		}

		max_burst_offset += max_burst_len;
	}

	task->data_sn = data_sn;

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
static void iscsi_task_response(iscsi_connection *conn, iscsi_task *task, iscsi_pdu *pdu)
{
	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) pdu->bhs_pkt;
	const uint32_t xfer_len             = task->scsi_task.xfer_len;

	if ( (scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_READ) != 0 ) {
		const int rc = iscsi_task_xfer_scsi_data_in( conn, task, (pdu->bhs_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) != 0 );

		if ( (rc > 0) || (task->des_data_xfer_pos != task->scsi_task.xfer_len) )
			return;
	}

	const uint32_t ds_len   = (task->scsi_task.sense_data_len != 0U)
		? (task->scsi_task.sense_data_len + offsetof(struct iscsi_scsi_ds_cmd_data, sense_data))
		: 0UL;
	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, ds_len, false );

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

	scsi_response_pkt->opcode   = ISCSI_OPCODE_SERVER_SCSI_RESPONSE;
	scsi_response_pkt->flags    = -0x80;
	scsi_response_pkt->response = ISCSI_SCSI_RESPONSE_CODE_OK;

	const uint32_t pos = task->scsi_task.xfer_pos;

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

	iscsi_connection_pdu_write( conn, response_pdu );
}

/**
 * @brief Initializes a SCSI task.
 *
 * @param[in] scsi_task Pointer to SCSI task. This
 * may NOT be NULL, so be careful.
 */
static void iscsi_scsi_task_create(iscsi_scsi_task *scsi_task)
{
	scsi_task->cdb                    = NULL;
	scsi_task->sense_data             = NULL;
	scsi_task->buf                    = NULL;
	scsi_task->must_free              = true;
	scsi_task->len                    = 0UL;
	scsi_task->id                     = 0ULL;
	scsi_task->flags                  = 0;
	scsi_task->xfer_pos               = 0UL;
	scsi_task->xfer_len               = 0UL;
	scsi_task->sense_data_len         = 0U;
	scsi_task->status                 = ISCSI_SCSI_STATUS_GOOD;
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
 * @param pdu
 */
static void iscsi_scsi_task_xfer_complete(iscsi_scsi_task *scsi_task, iscsi_pdu *pdu)
{
	iscsi_task *task = container_of( scsi_task, iscsi_task, scsi_task );
	iscsi_connection *conn   = task->conn;

	task->des_data_xfer_pos += task->scsi_task.len;

	iscsi_task_response( conn, task, pdu );
	iscsi_task_destroy( task );
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
static void iscsi_scsi_task_sense_data_build(iscsi_scsi_task *scsi_task, const uint8_t sense_key, const uint8_t asc, const uint8_t ascq)
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
	sense_data->field_rep_unit_code  = 0UL;
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
static void iscsi_scsi_task_lun_process_none(iscsi_scsi_task *scsi_task)
{
	iscsi_scsi_std_inquiry_data_packet std_inquiry_data_pkt;
	iscsi_scsi_cdb_inquiry *cdb = (iscsi_scsi_cdb_inquiry *) scsi_task->cdb;

	scsi_task->len = scsi_task->xfer_len;

	iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_LU_NOT_SUPPORTED, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

	scsi_task->xfer_pos = 0UL;
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
static int iscsi_scsi_lun_get_from_iscsi(const uint64_t lun)
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
 * @brief Runs an iSCSI SCSI task for a specified iSCSI SCSI LUN.
 *
 * This function moves the task back to the
 * iSCSI SCSI LUN tasks hash map prior
 * execution.\n
 * Errors are nandled according to the SCSI
 * standard.
 *
 * @param[in] scsi_task Pointer to iSCSI SCSI task to be run.
 * NULL is NOT valid here, take caution.
 * @param pdu
 */
static void iscsi_scsi_lun_task_run( iscsi_scsi_task *scsi_task, iscsi_pdu *pdu)
{
	int rc;

	scsi_task->status = ISCSI_SCSI_STATUS_GOOD;

	rc = iscsi_scsi_emu_block_process( scsi_task );

	if ( rc == ISCSI_SCSI_TASK_RUN_UNKNOWN ) {
		rc = iscsi_scsi_emu_primary_process( scsi_task );

		if ( rc == ISCSI_SCSI_TASK_RUN_UNKNOWN ) {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_COMMAND_OPERATION_CODE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );
			// TODO: Free task
			rc = ISCSI_SCSI_TASK_RUN_COMPLETE;
		}
	}

	if ( rc == ISCSI_SCSI_TASK_RUN_COMPLETE ) {
		iscsi_scsi_task_xfer_complete( scsi_task, pdu );
	}
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
	return ISCSI_SCSI_EMU_PHYSICAL_BLOCK_SIZE;
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
	return (image->virtualFilesize / ISCSI_SCSI_EMU_BLOCK_SIZE);
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
static uint64_t iscsi_scsi_emu_bytes_to_blocks(uint64_t *offset_blocks, uint64_t *num_blocks, const uint64_t offset_bytes, const uint64_t num_bytes)
{
	*offset_blocks = (offset_bytes / ISCSI_SCSI_EMU_BLOCK_SIZE);
	*num_blocks    = (num_bytes / ISCSI_SCSI_EMU_BLOCK_SIZE);

	return ((offset_bytes % ISCSI_SCSI_EMU_BLOCK_SIZE) | (num_bytes % ISCSI_SCSI_EMU_BLOCK_SIZE));
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
 * @return Number of blocks in bytes.
 */
static uint64_t iscsi_scsi_emu_blocks_to_bytes(uint64_t *offset_bytes, const uint64_t offset_blocks, const uint64_t num_blocks)
{
	*offset_bytes = (offset_blocks * ISCSI_SCSI_EMU_BLOCK_SIZE);

	return (num_blocks * ISCSI_SCSI_EMU_BLOCK_SIZE);
}

/**
 * @brief Called when data requested via an uplink server has arrived.
 *
 * This function is used to retrieve
 * block data which is NOT locally
 * available.
 *
 * @param[in] data Pointer to related scsi_task. May NOT
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
 * executes the I/O read operation, may
 * NOT be NULL, so be careful.
 * @param[in] image Pointer to DNBD3 image to read
 * data from and may NOT be NULL, so
 * be careful.
 * @param[in] offset_blocks Offset in blocks to start reading from.
 * @param[in] num_blocks Number of blocks to read.
 * @param[in] block_size Block size in bytes.
 * @return 0 on successful operation, a negative
 * error code otherwise.
 */
static int iscsi_scsi_emu_io_blocks_read(iscsi_scsi_task *scsi_task,  dnbd3_image_t *image, const uint64_t offset_blocks, const uint64_t num_blocks)
{
	int rc = 0;
	uint64_t offset_bytes;
	const uint64_t num_bytes = iscsi_scsi_emu_blocks_to_bytes( &offset_bytes, offset_blocks, num_blocks );
	scsi_task->file_offset = offset_bytes;

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

			if ( !uplink_request( image, scsi_task, iscsi_uplink_callback, 0, offset_bytes, num_bytes ) ) {
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

	if ( (flags & ISCSI_SCSI_EMU_BLOCK_FLAGS_WRITE) != 0 ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	if ( (scsi_task->flags & (ISCSI_SCSI_TASK_FLAGS_XFER_READ | ISCSI_SCSI_TASK_FLAGS_XFER_WRITE)) == (ISCSI_SCSI_TASK_FLAGS_XFER_READ | ISCSI_SCSI_TASK_FLAGS_XFER_WRITE) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	const uint64_t imgBlockCount = iscsi_scsi_emu_block_get_count( image );

	if ( (imgBlockCount <= lba) || ((imgBlockCount - lba) < xfer_len) ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	if ( xfer_len == 0UL ) {
		scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	const uint32_t max_xfer_len = ISCSI_MAX_DS_SIZE / ISCSI_SCSI_EMU_BLOCK_SIZE;

	if ( xfer_len > max_xfer_len || xfer_len * ISCSI_SCSI_EMU_BLOCK_SIZE != scsi_task->len ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	uint64_t offset_blocks;
	uint64_t num_blocks;

	if ( iscsi_scsi_emu_bytes_to_blocks( &offset_blocks, &num_blocks, 0, scsi_task->len ) != 0ULL ) {
		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	offset_blocks += lba;

	int rc = iscsi_scsi_emu_io_blocks_read( scsi_task, image, offset_blocks, num_blocks );

	if ( rc < 0 ) {
		if ( rc == -ENOMEM ) {
			iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_HARDWARE_ERR,
				ISCSI_SCSI_ASC_INTERNAL_TARGET_FAIL, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE );

			return ISCSI_SCSI_TASK_RUN_COMPLETE;
		}

		iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

		return ISCSI_SCSI_TASK_RUN_COMPLETE;
	}

	scsi_task->xfer_pos = scsi_task->len;

	return ISCSI_SCSI_TASK_RUN_COMPLETE;
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
	uint64_t lba;
	uint32_t xfer_len;
	dnbd3_image_t *image = scsi_task->connection->client->image;

	switch ( scsi_task->cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_READ6 : {
			const iscsi_scsi_cdb_read_write_6 *cdb_read_write_6 = (iscsi_scsi_cdb_read_write_6 *) scsi_task->cdb;

			lba      = iscsi_get_be24(cdb_read_write_6->lba);
			xfer_len = cdb_read_write_6->xfer_len;

			if ( xfer_len == 0UL )
				xfer_len = 256UL;

			return iscsi_scsi_emu_block_read_write( image, scsi_task, lba, xfer_len, 0 );
		}
		case ISCSI_SCSI_OPCODE_READ10 : {
			const iscsi_scsi_cdb_read_write_10 *cdb_read_write_10 = (iscsi_scsi_cdb_read_write_10 *) scsi_task->cdb;

			lba      = iscsi_get_be32(cdb_read_write_10->lba);
			xfer_len = iscsi_get_be16(cdb_read_write_10->xfer_len);

			return iscsi_scsi_emu_block_read_write( image, scsi_task, lba, xfer_len, 0 );
		}
		case ISCSI_SCSI_OPCODE_READ12 : {
			const iscsi_scsi_cdb_read_write_12 *cdb_read_write_12 = (iscsi_scsi_cdb_read_write_12 *) scsi_task->cdb;

			lba      = iscsi_get_be32(cdb_read_write_12->lba);
			xfer_len = iscsi_get_be32(cdb_read_write_12->xfer_len);

			return iscsi_scsi_emu_block_read_write( image, scsi_task, lba, xfer_len, 0 );
		}
		case ISCSI_SCSI_OPCODE_READ16 : {
			const iscsi_scsi_cdb_read_write_16 *cdb_read_write_16 = (iscsi_scsi_cdb_read_write_16 *) scsi_task->cdb;

			lba      = iscsi_get_be64(cdb_read_write_16->lba);
			xfer_len = iscsi_get_be32(cdb_read_write_16->xfer_len);

			return iscsi_scsi_emu_block_read_write( image, scsi_task, lba, xfer_len, 0 );
		}
		case ISCSI_SCSI_OPCODE_READCAPACITY10 : {
			iscsi_scsi_read_capacity_10_parameter_data_packet *buf = (iscsi_scsi_read_capacity_10_parameter_data_packet *) malloc( sizeof(struct iscsi_scsi_read_capacity_10_parameter_data_packet) );

			if ( buf == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				return ISCSI_SCSI_TASK_RUN_COMPLETE;
			}

			lba = iscsi_scsi_emu_block_get_count( image ) - 1ULL;

			if ( lba > 0xFFFFFFFFULL )
				buf->lba = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
			else
				iscsi_put_be32( (uint8_t *) &buf->lba, (uint32_t) lba );

			iscsi_put_be32( (uint8_t *) &buf->block_len, ISCSI_SCSI_EMU_BLOCK_SIZE );

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

			if ( ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_GET_ACTION(cdb_servce_in_action_16->action)
						!= ISCSI_SCSI_CDB_SERVICE_ACTION_IN_16_ACTION_READ_CAPACITY_16 ) {
				return ISCSI_SCSI_TASK_RUN_UNKNOWN;
			}
			iscsi_scsi_service_action_in_16_parameter_data_packet *buf = malloc( sizeof(struct iscsi_scsi_service_action_in_16_parameter_data_packet) );

			if ( buf == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				return ISCSI_SCSI_TASK_RUN_COMPLETE;
			}

			lba      = iscsi_scsi_emu_block_get_count( image ) - 1ULL;

			iscsi_put_be64( (uint8_t *) &buf->lba, lba );
			iscsi_put_be32( (uint8_t *) &buf->block_len, ISCSI_SCSI_EMU_BLOCK_SIZE );

			buf->flags = 0;

			const uint8_t exponent = ISCSI_SCSI_EMU_BLOCK_DIFF_SHIFT;

			buf->exponents = ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_PUT_LBPPB_EXPONENT((exponent <= ISCSI_SCSI_SERVICE_ACTION_IN_16_PARAM_DATA_LBPPB_EXPONENT_MASK) ? exponent : 0U);

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

	return ISCSI_SCSI_TASK_RUN_COMPLETE;
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

	if ( evpd != 0 ) {
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

				if ( alloc_len >= (len - sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet)) )
					alloc_len = (uint) ((len - sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet)) - 1U);

				memcpy( vpd_page_inquiry_data_pkt->params, name, alloc_len );
				memset( (vpd_page_inquiry_data_pkt->params + alloc_len), '\0', (len - alloc_len - sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet)) );

				alloc_len++;

				iscsi_put_be16( (uint8_t *) &vpd_page_inquiry_data_pkt->alloc_len, (uint16_t) alloc_len );

				break;
			}
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_DEVICE_ID : {
				const char *port_name = "Horst";
				const uint dev_name_len  = (uint) (strlen( image->name ) + 1U);
				const uint port_name_len = (uint) (strlen( port_name ) + 1U);

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

				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_NAA) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet);

				iscsi_scsi_emu_naa_ieee_ext_set( (uint64_t *) vpd_page_design_desc_inquiry_data_pkt->desc, (uint8_t *) image->name );

				alloc_len = (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_ieee_naa_ext_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + alloc_len);
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_ASCII) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_T10_VENDOR_ID) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet *vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->vendor_id, ISCSI_SCSI_STD_INQUIRY_DATA_DISK_VENDOR_ID, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->vendor_id), ' ' );
				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->product_id, image->name, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->product_id), ' ' );
				iscsi_strcpy_pad( (char *) vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->unit_serial_num, image->name, sizeof(vpd_page_design_desc_t10_vendor_id_inquiry_data_pkt->unit_serial_num), ' ' );

				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_t10_vendor_id_inquiry_data_packet)));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_DEVICE) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = (uint8_t) iscsi_scsi_emu_pad_scsi_name( vpd_page_design_desc_inquiry_data_pkt->desc, (const uint8_t*)image->name );

				alloc_len += (uint) (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len);

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_UTF8) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_SCSI_NAME) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = (uint8_t) iscsi_scsi_emu_pad_scsi_name( vpd_page_design_desc_inquiry_data_pkt->desc, (const uint8_t*)port_name );

				alloc_len += (uint) (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len);

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) + (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + vpd_page_design_desc_inquiry_data_pkt->len));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_REL_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet *vpd_page_design_desc_rel_target_port_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_rel_target_port_inquiry_data_pkt->reserved = 0U;
				iscsi_put_be16( (uint8_t *) &vpd_page_design_desc_rel_target_port_inquiry_data_pkt->index, 1 );

				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) +  (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_rel_target_port_inquiry_data_packet)));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_TARGET_PORT_GROUP) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_TARGET_PORT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet *vpd_page_design_desc_target_port_group_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet *) vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_target_port_group_inquiry_data_pkt->reserved = 0U;
				vpd_page_design_desc_target_port_group_inquiry_data_pkt->index    = 0U;

				alloc_len += (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet));

				vpd_page_design_desc_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_inquiry_data_packet *) (((uint8_t *) vpd_page_design_desc_inquiry_data_pkt) +  (sizeof(struct iscsi_scsi_vpd_page_design_desc_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_design_desc_target_port_group_inquiry_data_packet)));
				vpd_page_design_desc_inquiry_data_pkt->protocol_id_code_set = ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_CODE_SET(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_CODE_SET_BINARY) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_PUT_PROTOCOL_ID(ISCSI_DEFAULT_PROTOCOL_ID);
				vpd_page_design_desc_inquiry_data_pkt->flags                = (int8_t) (ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_TYPE(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_TYPE_LOGICAL_UNIT_GROUP) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PUT_ASSOC(ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_ASSOC_LOGICAL_UNIT) | ISCSI_SCSI_VPD_PAGE_DESIGN_DESC_INQUIRY_DATA_FLAGS_PIV);
				vpd_page_design_desc_inquiry_data_pkt->reserved             = 0U;
				vpd_page_design_desc_inquiry_data_pkt->len                  = sizeof(struct iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet);

				iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet *vpd_page_design_desc_logical_unit_group_inquiry_data_pkt = (iscsi_scsi_vpd_page_design_desc_logical_unit_group_inquiry_data_packet*)vpd_page_design_desc_inquiry_data_pkt->desc;

				vpd_page_design_desc_logical_unit_group_inquiry_data_pkt->reserved = 0U;
				iscsi_put_be16( (uint8_t *) &vpd_page_design_desc_logical_unit_group_inquiry_data_pkt->id, (uint16_t) ISCSI_DEFAULT_DEVICE_ID );

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
			case ISCSI_SCSI_VPD_PAGE_INQUIRY_DATA_PAGE_CODE_BLOCK_LIMITS : {
				iscsi_scsi_vpd_page_block_limits_inquiry_data_packet *vpd_page_block_limits_inquiry_data_pkt = (iscsi_scsi_vpd_page_block_limits_inquiry_data_packet *) vpd_page_inquiry_data_pkt->params;

				if ( len < (sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet) + sizeof(struct iscsi_scsi_vpd_page_block_limits_inquiry_data_packet)) ) {
					iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_ILLEGAL_REQ, ISCSI_SCSI_ASC_INVALID_FIELD_IN_CDB, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

					return -1;
				}

				alloc_len = sizeof(struct iscsi_scsi_vpd_page_block_limits_inquiry_data_packet);

				vpd_page_block_limits_inquiry_data_pkt->flags = 0;

				uint32_t blocks = (ISCSI_MAX_DS_SIZE  / ISCSI_SCSI_EMU_BLOCK_SIZE);

				vpd_page_block_limits_inquiry_data_pkt->max_cmp_write_len = (uint8_t) blocks;

				iscsi_put_be16( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->optimal_granularity_xfer_len, (uint16_t) blocks );
				iscsi_put_be32( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->max_xfer_len, blocks );
				iscsi_put_be32( (uint8_t *) &vpd_page_block_limits_inquiry_data_pkt->optimal_xfer_len, blocks );
				vpd_page_block_limits_inquiry_data_pkt->max_prefetch_len = 0UL;

				vpd_page_block_limits_inquiry_data_pkt->max_unmap_lba_cnt = 0UL;
				vpd_page_block_limits_inquiry_data_pkt->max_unmap_block_desc_cnt = 0UL;

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

				vpd_page_block_dev_chars_inquiry_data_pkt->medium_rotation_rate = ISCSI_SCSI_VPD_PAGE_BLOCK_DEV_CHARS_INQUIRY_DATA_MEDIUM_ROTATION_RATE_NONE;
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
			default : {
				scsi_task->xfer_pos = 0UL;

				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NO_SENSE, ISCSI_SCSI_ASC_NO_ADDITIONAL_SENSE, ISCSI_SCSI_ASCQ_CAUSE_NOT_REPORTABLE );

				return -1;

				break;
			}
		}

		return (int) (alloc_len + sizeof(struct iscsi_scsi_vpd_page_inquiry_data_packet));
	}

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

	if ( len < sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_list_packet) + sizeof(lun) )
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

	return (int) (sizeof(lun) + sizeof(struct iscsi_scsi_report_luns_parameter_data_lun_list_packet));
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
		mode_sense_6_parameter_hdr_data_pkt->flags          = ISCSI_SCSI_MODE_SENSE_6_PARAM_HDR_DATA_FLAGS_WP;
		mode_sense_6_parameter_hdr_data_pkt->block_desc_len = (uint8_t) block_desc_len;
	} else if ( hdr_len == sizeof(struct iscsi_scsi_mode_sense_10_parameter_header_data_packet) ) {
		iscsi_scsi_mode_sense_10_parameter_header_data_packet *mode_sense_10_parameter_hdr_data_pkt = (iscsi_scsi_mode_sense_10_parameter_header_data_packet *) mode_sense_6_parameter_hdr_data_pkt;

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
	const uint32_t block_size = ISCSI_SCSI_EMU_BLOCK_SIZE;

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
	uint alloc_len;
	uint len;
	int rc;

	switch ( scsi_task->cdb->opcode ) {
		case ISCSI_SCSI_OPCODE_INQUIRY : {
			const iscsi_scsi_cdb_inquiry *cdb_inquiry = (iscsi_scsi_cdb_inquiry *) scsi_task->cdb;

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

			rc = iscsi_scsi_emu_primary_inquiry( scsi_task->connection->client->image, scsi_task, cdb_inquiry, std_inquiry_data_pkt, len );

			if ( (rc >= 0) && (len > 0U) ) {
				if ( len > alloc_len ) {
					len = alloc_len;
				}

				scsi_task->buf = (uint8_t *) std_inquiry_data_pkt;

				if ( rc < (int) len )
					memset( (((uint8_t *) std_inquiry_data_pkt) + rc), 0, (len - rc) );

				rc = len;
			} else {
				free( std_inquiry_data_pkt );
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

			rc = iscsi_scsi_emu_primary_report_luns( report_luns_parameter_data_pkt, len, cdb_report_luns->select_report );

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
		case ISCSI_SCSI_OPCODE_MODESENSE6 : {
			const iscsi_scsi_cdb_mode_sense_6 *cdb_mode_sense_6 = (iscsi_scsi_cdb_mode_sense_6 *) scsi_task->cdb;

			alloc_len = cdb_mode_sense_6->alloc_len;

			const uint block_desc_len = ((cdb_mode_sense_6->flags & ISCSI_SCSI_CDB_MODE_SENSE_6_FLAGS_DBD) == 0) ? sizeof(struct iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet) : 0U;
			const uint pc             = ISCSI_SCSI_CDB_MODE_SENSE_6_GET_PAGE_CONTROL(cdb_mode_sense_6->page_code_control);
			const uint page           = ISCSI_SCSI_CDB_MODE_SENSE_6_GET_PAGE_CODE(cdb_mode_sense_6->page_code_control);
			const uint sub_page       = cdb_mode_sense_6->sub_page_code;

			rc = iscsi_scsi_emu_primary_mode_sense( scsi_task->connection->client->image, scsi_task, NULL, sizeof(struct iscsi_scsi_mode_sense_6_parameter_header_data_packet), block_desc_len, 0U, pc, page, sub_page );

			if ( rc < 0 )
				break;

			len = rc;

			iscsi_scsi_mode_sense_6_parameter_header_data_packet *mode_sense_6_parameter_hdr_data_pkt = (iscsi_scsi_mode_sense_6_parameter_header_data_packet *) malloc( len );

			if ( mode_sense_6_parameter_hdr_data_pkt == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_emu_primary_mode_sense( scsi_task->connection->client->image, scsi_task, mode_sense_6_parameter_hdr_data_pkt, sizeof(struct iscsi_scsi_mode_sense_6_parameter_header_data_packet), block_desc_len, 0U, pc, page, sub_page );

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

			alloc_len = iscsi_get_be16(cdb_mode_sense_10->alloc_len);

			const uint long_lba       = (((cdb_mode_sense_10->flags & ISCSI_SCSI_CDB_MODE_SENSE_10_FLAGS_LLBAA) != 0) ? ISCSI_SCSI_MODE_SENSE_10_PARAM_HDR_DATA_LONGLBA : 0U);
			const uint block_desc_len = (((cdb_mode_sense_10->flags & ISCSI_SCSI_CDB_MODE_SENSE_10_FLAGS_DBD) == 0) ? ((long_lba != 0) ? sizeof(struct iscsi_scsi_mode_sense_long_lba_parameter_block_desc_data_packet) : sizeof(struct iscsi_scsi_mode_sense_lba_parameter_block_desc_data_packet)) : 0U);
			const uint pc10           = ISCSI_SCSI_CDB_MODE_SENSE_10_GET_PAGE_CONTROL(cdb_mode_sense_10->page_code_control);
			const uint page10         = ISCSI_SCSI_CDB_MODE_SENSE_10_GET_PAGE_CODE(cdb_mode_sense_10->page_code_control);
			const uint sub_page10     = cdb_mode_sense_10->sub_page_code;

			rc = iscsi_scsi_emu_primary_mode_sense( scsi_task->connection->client->image, scsi_task, NULL, sizeof(struct iscsi_scsi_mode_sense_10_parameter_header_data_packet), block_desc_len, long_lba, pc10, page10, sub_page10 );

			if ( rc < 0 )
				break;

			len = rc;

			iscsi_scsi_mode_sense_10_parameter_header_data_packet *mode_sense_10_parameter_hdr_data_pkt = (iscsi_scsi_mode_sense_10_parameter_header_data_packet *) malloc( len );

			if ( mode_sense_10_parameter_hdr_data_pkt == NULL ) {
				iscsi_scsi_task_status_set( scsi_task, ISCSI_SCSI_STATUS_CHECK_COND, ISCSI_SCSI_SENSE_KEY_NOT_READY, ISCSI_SCSI_ASC_LOGICAL_UNIT_NOT_READY, ISCSI_SCSI_ASCQ_BECOMING_READY );

				break;
			}

			rc = iscsi_scsi_emu_primary_mode_sense( scsi_task->connection->client->image, scsi_task, (iscsi_scsi_mode_sense_6_parameter_header_data_packet *) mode_sense_10_parameter_hdr_data_pkt, sizeof(struct iscsi_scsi_mode_sense_10_parameter_header_data_packet), block_desc_len, long_lba, pc10, page10, sub_page10 );

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
		case ISCSI_SCSI_OPCODE_TESTUNITREADY : {
			scsi_task->xfer_pos = 0UL;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

			break;
		}
		case ISCSI_SCSI_OPCODE_STARTSTOPUNIT : {
			scsi_task->xfer_pos = 0UL;
			scsi_task->status   = ISCSI_SCSI_STATUS_GOOD;

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
 * @brief Creates and initializes an iSCSI session.
 *
 * This function creates and initializes all relevant
 * data structures of an ISCSI session.\n
 * Default key and value pairs are created and
 * assigned before they are negotiated at the
 * login phase.
 *
 * @param[in] conn Pointer to iSCSI connection to associate with the session.
 * @param[in] type Session type to initialize the session with.
 * @return Pointer to initialized iSCSI session or NULL in case an error
 * occured (usually due to memory exhaustion).
 */
static iscsi_session *iscsi_session_create(iscsi_connection *conn,  const int type)
{
	iscsi_session *session = malloc( sizeof(struct iscsi_session) );

	if ( session == NULL ) {
		logadd( LOG_ERROR, "iscsi_session_create: Out of memory allocating iSCSI session" );

		return NULL;
	}

	session->tsih                       = 0ULL;
	session->type                       = type;
	session->exp_cmd_sn                 = 0UL;
	session->max_cmd_sn                 = 0UL;
	session->current_text_init_task_tag = 0xFFFFFFFFUL;

	return session;
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
static void iscsi_session_destroy(iscsi_session *session)
{
	free( session );
}

/**
 * @brief Creates data structure for an iSCSI connection from iSCSI portal and TCP/IP socket.
 *
 * Creates a data structure for incoming iSCSI connection
 * requests from iSCSI packet data.
 *
 * @param[in] client dnbd3 client to associate the connection with.
 * @return Pointer to initialized iSCSI connection structure or NULL in
 * case of an error (invalid iSCSI packet data or memory exhaustion).
 */
static iscsi_connection *iscsi_connection_create(dnbd3_client_t *client)
{
	iscsi_connection *conn = malloc( sizeof(struct iscsi_connection) );

	if ( conn == NULL ) {
		logadd( LOG_ERROR, "iscsi_create_connection: Out of memory while allocating iSCSI connection" );

		return NULL;
	}

	conn->session                  = NULL;
	conn->pdu_processing           = NULL;
	conn->login_response_pdu       = NULL;
	conn->id                       = 0;
	conn->client                   = client;
	conn->pdu_recv_state           = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_READY;
	conn->flags                    = 0;
	conn->state                    = ISCSI_CONNECT_STATE_INVALID;
	conn->login_phase              = ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_SECURITY_NEGOTIATION;
	conn->tsih                     = 0U;
	conn->cid                      = 0U;
	conn->state_negotiated         = 0U;
	conn->session_state_negotiated = 0UL;
	conn->init_task_tag            = 0UL;
	conn->target_xfer_tag          = 0UL;
	conn->stat_sn                  = 0UL;

	return conn;
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
static void iscsi_connection_destroy(iscsi_connection *conn)
{
	if ( conn != NULL ) {
		iscsi_connection_pdu_destroy( conn->login_response_pdu );
		iscsi_session_destroy( conn->session );
		iscsi_connection_pdu_destroy( conn->pdu_processing );
		free( conn );
	}
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
static int32_t iscsi_connection_read(const iscsi_connection *conn, uint8_t *buf, const uint32_t len)
{
	if ( len == 0UL )
		return 0L;

	int32_t rc;
	do {
		rc = (int32_t) recv( conn->client->sock, buf, (size_t) len, MSG_WAITALL );
	} while ( rc == -1 && errno == EINTR );

	if ( rc == 0 )
		return -1; // EOF
	return rc;
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
 * be written to output buffer which may
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
 * @brief Updates iSCSI connection and session values after being retrieved from the client.
 *
 * This function copies the key and value pairs into the
 * internal connection and session structure and checks
 * them for consistency.\n
 * The TCP receive buffer will be adjusted to the new
 * updated value but is never lower than 4KiB and never
 * higher than 8KiB plus header overhead and a factor of
 * 16 for receiving 16 packets at once.
 *
 * @param[in] conn Pointer to ISCSI connection which should
 * be updated.
 * @retval -1 An error occured, e.g. socket is already closed.
 * @retval 0 All values have been updated successfully and
 * the socket is still alive.
 */
static void iscsi_connection_update_key_value_pairs(iscsi_connection *conn, iscsi_negotiation_kvp *pairs)
{
	conn->session->opts.MaxBurstLength = CLAMP(pairs->MaxBurstLength, 512, ISCSI_MAX_DS_SIZE);
	conn->session->opts.FirstBurstLength = CLAMP(pairs->FirstBurstLength, 512, pairs->MaxBurstLength);
	conn->session->opts.MaxRecvDataSegmentLength = CLAMP(pairs->MaxRecvDataSegmentLength, 512, ISCSI_MAX_DS_SIZE);
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
 * @param[in] resp_pdu Pointer to login response PDU to
 * be sent via TCP/IP. NULL is NOT
 * allowed here, take caution.
 * @return 0 if the login response has been sent
 * successfully, a negative error code otherwise.
 */
static int iscsi_connection_pdu_login_response(iscsi_connection *conn, iscsi_pdu *resp_pdu)
{
	iscsi_login_response_packet *login_response_pkt =
		(iscsi_login_response_packet *) iscsi_connection_pdu_resize( resp_pdu, resp_pdu->ahs_len, resp_pdu->ds_write_pos );

	login_response_pkt->version_max    = ISCSI_VERSION_MAX;
	login_response_pkt->version_active = ISCSI_VERSION_MAX;

	iscsi_put_be32( (uint8_t *) &login_response_pkt->total_ahs_len, resp_pdu->ds_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	iscsi_put_be32( (uint8_t *) &login_response_pkt->stat_sn, conn->stat_sn++ );

	if ( conn->session != NULL ) { // TODO: Needed? MC/S?
		iscsi_put_be32( (uint8_t *) &login_response_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
		iscsi_put_be32( (uint8_t *) &login_response_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	} else {
		iscsi_put_be32( (uint8_t *) &login_response_pkt->exp_cmd_sn, resp_pdu->cmd_sn );
		iscsi_put_be32( (uint8_t *) &login_response_pkt->max_cmd_sn, resp_pdu->cmd_sn );
	}

	if ( login_response_pkt->status_class != ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SUCCESS )
		login_response_pkt->flags &= (int8_t) ~(ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT | ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_MASK | ISCSI_LOGIN_RESPONSE_FLAGS_NEXT_STAGE_MASK );

	iscsi_connection_pdu_write( conn, resp_pdu );
	if ( conn->login_response_pdu == resp_pdu ) {
		conn->login_response_pdu = NULL;
	}

	return ISCSI_CONNECT_PDU_READ_OK;
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

	login_response_pkt->opcode = ISCSI_OPCODE_SERVER_LOGIN_RES;
	login_response_pkt->flags  = (int8_t) (login_req_pkt->flags & (ISCSI_LOGIN_REQ_FLAGS_TRANSIT | ISCSI_LOGIN_REQ_FLAGS_CONTINUE | ISCSI_LOGIN_REQ_FLAGS_CURRENT_STAGE_MASK));

	if ( (login_response_pkt->flags & ISCSI_LOGIN_RESPONSE_FLAGS_TRANSIT) != 0 )
		login_response_pkt->flags |= (login_req_pkt->flags & ISCSI_LOGIN_REQ_FLAGS_NEXT_STAGE_MASK);

	login_response_pkt->isid          = login_req_pkt->isid;
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
 * which may NOT be NULL, so take caution.
 * @return 0 on successful operation, a negative error code
 * otherwise. The output session 'type' is unchanged, if
 * an invalid session type value was retrieved.
 */
static int iscsi_login_parse_session_type(iscsi_pdu *login_response_pdu, const char *type_str, int *type)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	if ( type_str != NULL && strcasecmp( type_str, "Normal" ) == 0 ) {
		*type = ISCSI_SESSION_TYPE_NORMAL;
		return ISCSI_CONNECT_PDU_READ_OK;
	}

	*type = ISCSI_SESSION_TYPE_INVALID;
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
 * @param[in] conn Pointer to iSCSI connection which may NOT be
 * NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU
 * to set the parameters for. NULL is NOT allowed
 * here, so take caution.
 * @param[in] target_name Pointer to target node name and may
 * NOT be NULL, be careful.
 * @return 0 if the check was successful or a negative
 * error code otherwise.
 */
static int iscsi_image_from_target(iscsi_connection *conn, iscsi_pdu *login_response_pdu, const char *target_name)
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
static void iscsi_connection_login_response_reject(iscsi_pdu *login_response_pdu, const iscsi_pdu *pdu)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	login_response_pkt->opcode                       = ISCSI_OPCODE_SERVER_LOGIN_RES;
	login_response_pkt->flags                        = 0;
	login_response_pkt->version_max                  = ISCSI_VERSION_MAX;
	login_response_pkt->version_active               = ISCSI_VERSION_MAX;
	*(uint32_t *) &login_response_pkt->total_ahs_len = 0UL; // TotalAHSLength and DataSegmentLength are always 0, so write in one step.
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
 * @param[in] ds_len Length of DataSegment packet data to be appended.
 * May not exceed 16MiB - 1 (16777215 bytes).
 * @param no_ds_alloc Do not allocate buffer space for DS, only set
 * value for header - for sending DS manually later
 * @return Pointer to allocated and zero filled PDU or NULL
 * in case of an error (usually memory exhaustion).
 */
static iscsi_pdu *iscsi_connection_pdu_create(iscsi_connection *conn, const uint32_t ds_len, bool no_ds_alloc)
{
	if ( ds_len > ISCSI_MAX_DS_SIZE ) {
		logadd( LOG_ERROR, "iscsi_pdu_create: Invalid  DS length" );
		return NULL;
	}

	const uint32_t pkt_ds_len = no_ds_alloc ? 0 : ISCSI_ALIGN( ds_len, ISCSI_ALIGN_SIZE );
	const uint32_t len        = (uint32_t) ( sizeof(struct iscsi_bhs_packet) + pkt_ds_len );

	iscsi_pdu *pdu = malloc( sizeof(struct iscsi_pdu) );
	if ( pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_pdu_create: Out of memory while allocating iSCSI PDU" );

		return NULL;
	}

	iscsi_bhs_packet *bhs_pkt = malloc( len );
	if ( bhs_pkt == NULL ) {
		free( pdu );
		logadd( LOG_ERROR, "iscsi_pdu_create: Out of memory while allocating iSCSI BHS packet" );

		return NULL;
	}

	pdu->bhs_pkt                 = bhs_pkt;
	pdu->ahs_pkt                 = NULL;
	pdu->ds_cmd_data             = (pkt_ds_len != 0UL) ? (iscsi_scsi_ds_cmd_data *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet)) : NULL;
	pdu->task                    = NULL;
	pdu->flags                   = 0;
	pdu->bhs_pos                 = 0U;
	pdu->ahs_len                 = 0;
	pdu->ds_len                  = ds_len;
	pdu->ds_write_pos            = 0;
	pdu->cmd_sn                  = 0UL;
	pdu->recv_pos                = 0;

	if ( pkt_ds_len > ds_len ) {
		memset( (((uint8_t *) pdu->ds_cmd_data) + ds_len), 0, (pkt_ds_len - ds_len) );
	}

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
static void iscsi_connection_pdu_destroy(iscsi_pdu *pdu)
{
	if ( pdu == NULL )
		return;
	free( pdu->bhs_pkt );
	free( pdu );
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
 * @param[in] ds_len Length of DataSegment packet data to be appended.
 * May not exceed 16MiB - 1 (16777215 bytes).
 * @return Pointer to allocated and zero filled PDU or NULL
 * in case of an error (usually memory exhaustion).
 */
static iscsi_bhs_packet *iscsi_connection_pdu_resize(iscsi_pdu *pdu, const uint ahs_len,  const uint32_t ds_len)
{
	if ( (ahs_len > ISCSI_MAX_AHS_SIZE) || (ds_len > ISCSI_MAX_DS_SIZE) || (ahs_len % 4 != 0) ) {
		logadd( LOG_ERROR, "iscsi_connection_pdu_resize: Invalid AHS or DataSegment packet size" );
		return NULL;
	}
	if ( pdu->ds_len != 0 && pdu->ds_cmd_data == NULL ) {
		// If you really ever need this, handle it properly below (old_len, no copying, etc.)
		logadd( LOG_ERROR, "iscsi_connection_pdu_resize: Cannot resize PDU with virtual DS" );
		return NULL;
	}

	if ( (ahs_len != pdu->ahs_len) || (ds_len != pdu->ds_len) ) {
		iscsi_bhs_packet *bhs_pkt;
		const uint32_t pkt_ds_len = ISCSI_ALIGN(ds_len, ISCSI_ALIGN_SIZE);
		const size_t old_len    = (sizeof(struct iscsi_bhs_packet) + (uint32_t) pdu->ahs_len + ISCSI_ALIGN(pdu->ds_len, ISCSI_ALIGN_SIZE));
		const size_t new_len    = (sizeof(struct iscsi_bhs_packet) + (uint32_t) ahs_len + pkt_ds_len);

		if ( new_len > old_len ) {
			bhs_pkt = realloc( pdu->bhs_pkt, new_len );

			if ( bhs_pkt == NULL ) {
				logadd( LOG_ERROR, "iscsi_connection_pdu_resize: Out of memory while reallocating iSCSI PDU packet data" );

				return NULL;
			}

			pdu->bhs_pkt = bhs_pkt;
		} else {
			bhs_pkt = pdu->bhs_pkt;
		}

		pdu->ahs_pkt            = (ahs_len != 0U) ? (iscsi_ahs_packet *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet)) : NULL;
		pdu->ds_cmd_data        = (pkt_ds_len != 0UL) ? (iscsi_scsi_ds_cmd_data *) (((uint8_t *) bhs_pkt) + sizeof(struct iscsi_bhs_packet) + ahs_len) : NULL;
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
 * This function sends a response PDU to the
 * client after being processed by the server.\n
 * If a header or data digest (CRC32C) needs to
 * be calculated, this is done as well.
 *
 * @param[in] conn Pointer to iSCSI connection to handle. May
 * NOT be NULL, so take caution. Will be freed after sending,
 * so don't access afterwards.
 * @param[in] pdu Pointer to iSCSI server response PDU to send.
 * May NOT be NULL, so be careful.
 */
static bool iscsi_connection_pdu_write(iscsi_connection *conn, iscsi_pdu *pdu)
{
	if ( conn->state >= ISCSI_CONNECT_STATE_EXITING ) {
		iscsi_connection_pdu_destroy( pdu );
		return false;
	}

	// During allocation we already round up to ISCSI_ALIGN_SIZE, but store the requested size in the ds_len
	// member, so it's safe to round up here before sending, the accessed memory will be valid and zeroed
	const size_t len = (sizeof(struct iscsi_bhs_packet) + pdu->ahs_len
		+ (pdu->ds_cmd_data == NULL ? 0 : ISCSI_ALIGN(pdu->ds_len, ISCSI_ALIGN_SIZE)));
	const ssize_t rc = sock_sendAll( conn->client->sock, pdu->bhs_pkt, len, ISCSI_CONNECT_SOCKET_WRITE_RETRIES );

	iscsi_connection_pdu_destroy( pdu );

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
static int iscsi_connection_handle_reject(iscsi_connection *conn, iscsi_pdu *pdu, const int reason_code)
{
	pdu->flags |= ISCSI_PDU_FLAGS_REJECTED;

	const uint32_t ds_len   = (uint32_t) sizeof(struct iscsi_bhs_packet) + ((uint32_t) pdu->bhs_pkt->total_ahs_len << 2UL);
	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, ds_len, false );

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

	iscsi_connection_pdu_write( conn, response_pdu );

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

	if ( (scsi_cmd_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 ) {
		if ( (iscsi_seq_num_cmp_lt( pdu->cmd_sn, session->exp_cmd_sn )
				|| iscsi_seq_num_cmp_gt( pdu->cmd_sn, session->max_cmd_sn ))
				&& ((session->type == ISCSI_SESSION_TYPE_NORMAL) && (opcode != ISCSI_OPCODE_CLIENT_SCSI_DATA_OUT)) ) {
			logadd( LOG_WARNING, "Seqnum messup. Is: %u, want >= %u, < %u",
				pdu->cmd_sn, session->exp_cmd_sn, session->max_cmd_sn );
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		}
	} else if ( (pdu->cmd_sn != session->exp_cmd_sn) && (opcode != ISCSI_OPCODE_CLIENT_NOP_OUT) ) {
		logadd( LOG_WARNING, "Seqnum messup. Is: %u, want: %u",
			pdu->cmd_sn, session->exp_cmd_sn );
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	uint32_t exp_stat_sn = iscsi_get_be32(scsi_cmd_pkt->exp_stat_sn);

	if ( iscsi_seq_num_cmp_gt( exp_stat_sn, conn->stat_sn ) )
		exp_stat_sn = conn->stat_sn;

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
	if ( ((conn->flags & ISCSI_CONNECT_FLAGS_FULL_FEATURE) != 0) && (conn->session != NULL)
			&& (conn->session->type == ISCSI_SESSION_TYPE_DISCOVERY) )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	const iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) pdu->bhs_pkt;

	pdu->cmd_sn = iscsi_get_be32(login_req_pkt->cmd_sn);

	if ( pdu->ds_len > ISCSI_DEFAULT_RECV_DS_LEN )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	iscsi_pdu *login_response_pdu = conn->login_response_pdu != NULL
		? conn->login_response_pdu
		: iscsi_connection_pdu_create( conn, 8192, false );

	if ( login_response_pdu == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	const int rc = iscsi_connection_pdu_login_response_init( login_response_pdu, pdu );

	if ( rc < 0 ) {
		iscsi_connection_pdu_login_response( conn, login_response_pdu );

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
	if ( conn->session->type != ISCSI_SESSION_TYPE_NORMAL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	iscsi_scsi_cmd_packet *scsi_cmd_pkt = (iscsi_scsi_cmd_packet *) pdu->bhs_pkt;

	if ( (scsi_cmd_pkt->flags_task & (ISCSI_SCSI_CMD_FLAGS_TASK_READ | ISCSI_SCSI_CMD_FLAGS_TASK_WRITE))
			== (ISCSI_SCSI_CMD_FLAGS_TASK_READ | ISCSI_SCSI_CMD_FLAGS_TASK_WRITE) ) { // Bidirectional transfer is not supported
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_task *task = iscsi_task_create( conn );

	if ( task == NULL )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

	uint32_t exp_xfer_len = iscsi_get_be32(scsi_cmd_pkt->exp_xfer_len);

	task->scsi_task.len         = (uint) (((uint8_t *) pdu->ds_cmd_data) - ((uint8_t *) pdu->bhs_pkt));
	task->scsi_task.cdb         = &scsi_cmd_pkt->scsi_cdb;
	task->scsi_task.xfer_len    = exp_xfer_len;
	task->init_task_tag         = iscsi_get_be32(scsi_cmd_pkt->init_task_tag);

	const uint64_t lun = iscsi_get_be64(scsi_cmd_pkt->lun);
	task->lun_id       = iscsi_scsi_lun_get_from_iscsi( lun );

	if ( ((scsi_cmd_pkt->flags_task & (ISCSI_SCSI_CMD_FLAGS_TASK_READ | ISCSI_SCSI_CMD_FLAGS_TASK_WRITE)) == 0) && (exp_xfer_len > 0UL) ) {
		iscsi_task_destroy( task );

		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_INVALID_PDU_FIELD );
	}

	if ( (scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_READ) != 0 )
		task->scsi_task.flags |= ISCSI_SCSI_TASK_FLAGS_XFER_READ;

	if ( (scsi_cmd_pkt->flags_task & ISCSI_SCSI_CMD_FLAGS_TASK_WRITE) != 0 ) {
		iscsi_task_destroy( task );
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_COMMAND_NOT_SUPPORTED );
	}

	pdu->task = task;

	return ISCSI_CONNECT_PDU_READ_OK;
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
	if ( pdu->ds_len > (uint) (sizeof(struct iscsi_bhs_packet) + ISCSI_DEFAULT_RECV_DS_LEN) )
		return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );

	iscsi_text_req_packet *text_req_pkt = (iscsi_text_req_packet *) pdu->bhs_pkt;

	const uint32_t init_task_tag = iscsi_get_be32(text_req_pkt->init_task_tag);
	const uint32_t exp_stat_sn   = iscsi_get_be32(text_req_pkt->exp_stat_sn);

	if ( exp_stat_sn != conn->stat_sn )
		conn->stat_sn = exp_stat_sn;

	if ( (text_req_pkt->flags & (ISCSI_TEXT_REQ_FLAGS_CONTINUE | ISCSI_TEXT_REQ_FLAGS_FINAL))
			== (ISCSI_TEXT_REQ_FLAGS_CONTINUE | ISCSI_TEXT_REQ_FLAGS_FINAL) ) {
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	if ( conn->session->current_text_init_task_tag == 0xFFFFFFFFUL ) {
		conn->session->current_text_init_task_tag = init_task_tag;
		return ISCSI_CONNECT_PDU_READ_OK;
	}
	return iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_PROTOCOL_ERR );
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

	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 0UL, false );

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

	iscsi_connection_pdu_write( conn, response_pdu );

	return ISCSI_CONNECT_PDU_READ_OK;
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
		iscsi_pdu *login_response_pdu = iscsi_connection_pdu_create( conn, 0UL, false );

		if ( login_response_pdu == NULL )
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

		iscsi_connection_login_response_reject( login_response_pdu, pdu );
		iscsi_connection_pdu_write( conn, login_response_pdu );

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}
	if ( conn->state == ISCSI_CONNECT_STATE_INVALID ) {
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
		case ISCSI_OPCODE_CLIENT_TEXT_REQ : {
			rc = iscsi_connection_pdu_header_handle_text_req( conn, pdu );

			break;
		}
		case ISCSI_OPCODE_CLIENT_LOGOUT_REQ : {
			rc = iscsi_connection_pdu_header_handle_logout_req( conn, pdu );

			break;
		}
		default : {
			rc = iscsi_connection_handle_reject( conn, pdu, ISCSI_REJECT_REASON_COMMAND_NOT_SUPPORTED );

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

	if ( ds_len > conn->session->opts.MaxRecvDataSegmentLength )
		ds_len = conn->session->opts.MaxRecvDataSegmentLength;

	const uint64_t lun           = iscsi_get_be64(nop_out_pkt->lun);
	const uint32_t init_task_tag = iscsi_get_be32(nop_out_pkt->init_task_tag);

	conn->flags &= ~ISCSI_CONNECT_FLAGS_NOP_OUTSTANDING;

	if ( init_task_tag == 0xFFFFFFFFUL )
		return ISCSI_CONNECT_PDU_READ_OK;

	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, ds_len, false );

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
	nop_in_pkt->target_xfer_tag = 0xFFFFFFFFUL; // Minus one does not require endianess conversion
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->init_task_tag, init_task_tag );
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->stat_sn, conn->stat_sn++ );

	if ( (nop_out_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 )
		conn->session->max_cmd_sn++;

	iscsi_put_be32( (uint8_t *) &nop_in_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &nop_in_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	nop_in_pkt->reserved2 = 0UL;
	nop_in_pkt->reserved3 = 0ULL;

	if ( ds_len != 0UL )
		memcpy( response_pdu->ds_cmd_data, pdu->ds_cmd_data, ds_len );

	iscsi_connection_pdu_write( conn, response_pdu );

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

	if ( task->lun_id != ISCSI_DEFAULT_LUN ) {
		logadd( LOG_WARNING, "Received SCSI command for unknown LUN %d", task->lun_id );
		iscsi_scsi_task_lun_process_none( &task->scsi_task );
		iscsi_scsi_task_xfer_complete( &task->scsi_task, pdu );

		return ISCSI_CONNECT_PDU_READ_OK;
	}

	if ( (task->scsi_task.flags & ISCSI_SCSI_TASK_FLAGS_XFER_READ) != 0 ) {
		task->scsi_task.buf = NULL;
		task->scsi_task.len = task->scsi_task.xfer_len;
	}
	iscsi_scsi_lun_task_run( &task->scsi_task, pdu );

	return ISCSI_CONNECT_PDU_READ_OK;
}

/*
 * This function is used to set the info in the connection data structure
 * return
 * 0: success
 * otherwise: error
 */
static int iscsi_connection_login_set_info(iscsi_connection *conn, iscsi_pdu *login_response_pdu,  const int type, const uint cid)
{
	conn->flags          &= ~ISCSI_CONNECT_FLAGS_AUTH;
	conn->cid             = (uint16_t) cid;

	if ( conn->session == NULL ) {
		iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
		conn->session = iscsi_session_create( conn, type );

		if ( conn->session == NULL ) {
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}

		conn->stat_sn            = iscsi_get_be32(login_response_pkt->stat_sn);

		conn->session->exp_cmd_sn  = login_response_pdu->cmd_sn;
		conn->session->max_cmd_sn  = (uint32_t) (login_response_pdu->cmd_sn + ISCSI_DEFAULT_QUEUE_DEPTH - 1UL);
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
 * @param[in] kvpairs Pointer to key and value pairs.
 * which may NOT be NULL, so take caution.
 * @param[in] cid Connection ID (CID).
 * @return 0 on success, a negative error code otherwise.
 */
static int iscsi_connection_handle_login_phase_none(iscsi_connection *conn, iscsi_pdu *login_response_pdu, iscsi_negotiation_kvp *kvpairs, uint cid)
{
	int type, rc;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

	rc = iscsi_login_parse_session_type( login_response_pdu, kvpairs->SessionType, &type );

	if ( rc < 0 )
		return rc;

	if ( kvpairs->TargetName != NULL && type == ISCSI_SESSION_TYPE_NORMAL ) {
		rc = iscsi_image_from_target( conn, login_response_pdu, kvpairs->TargetName );
	} else {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISSING_PARAMETER;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	if ( rc < 0 )
		return rc;

	return iscsi_connection_login_set_info( conn, login_response_pdu, type, cid );
}

static int iscsi_write_login_options_to_pdu( iscsi_connection *conn, iscsi_negotiation_kvp *pairs, iscsi_pdu *response_pdu )
{
	uint payload_len = response_pdu->ds_write_pos;

#	define ADD_KV_INTERNAL(num, key, value) do { \
int rc = iscsi_append_key_value_pair_packet( num, key, value, (char *)response_pdu->ds_cmd_data, payload_len, response_pdu->ds_len ); \
if ( rc < 0 ) return -1; \
payload_len += rc; \
} while (0)
#	define ADD_KV_OPTION_INT(key) do { \
if ( pairs->key != -1 ) ADD_KV_INTERNAL( true, #key, (const char *)(size_t)conn->session->opts.key ); \
} while (0)
#	define ADD_KV_OPTION_STR(key) do { \
if ( pairs->key != NULL ) ADD_KV_INTERNAL( false, #key, conn->session->opts.key ); \
} while (0)
#	define ADD_KV_PLAIN_INT(key, value) do { \
if ( pairs->key != -1 ) ADD_KV_INTERNAL( true, #key, (const char *)(size_t)(value) ); \
} while (0)
#	define ADD_KV_PLAIN_STR(key, value) do { \
if ( pairs->key != NULL ) ADD_KV_INTERNAL( false, #key, value ); \
} while (0)
	ADD_KV_OPTION_INT( MaxRecvDataSegmentLength );
	ADD_KV_OPTION_INT( MaxBurstLength );
	ADD_KV_OPTION_INT( FirstBurstLength );
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
 * may NOT be NULL, so be careful.
 * @param[in] login_response_pdu Pointer to login response PDU.
 * NULL is not allowed here, so take caution.
 * @return 0 on success, a negative error code otherwise.
 */
static int iscsi_connecction_handle_login_response(iscsi_connection *conn, iscsi_pdu *login_response_pdu,  iscsi_negotiation_kvp *pairs)
{
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
	iscsi_connection_update_key_value_pairs( conn, pairs );
	int payload_len = iscsi_write_login_options_to_pdu( conn, pairs, login_response_pdu );

	if ( payload_len < 0 || payload_len > login_response_pdu->ds_len ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_SERVER_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_SERVER_ERR_OUT_OF_RESOURCES;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	// Handle current stage (CSG bits)
	switch ( ISCSI_LOGIN_RESPONSE_FLAGS_GET_CURRENT_STAGE(login_response_pkt->flags) ) {
	case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_SECURITY_NEGOTIATION : {
		if ( pairs->AuthMethod != NULL && strcasecmp( pairs->AuthMethod, "None" ) == 0 ) {
			conn->flags |= ISCSI_CONNECT_FLAGS_AUTH;
		} else {
			// Only "None" supported
			login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
			login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

			return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
		}

		break;
	}
	case ISCSI_LOGIN_RESPONSE_FLAGS_CURRENT_STAGE_LOGIN_OPERATIONAL_NEGOTIATION : {
		if ( conn->state == ISCSI_CONNECT_STATE_INVALID ) {
			conn->flags |= ISCSI_CONNECT_FLAGS_AUTH;
		}

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

			if ( (conn->session->type != ISCSI_SESSION_TYPE_NORMAL) && (conn->session->type != ISCSI_SESSION_TYPE_DISCOVERY) ) {
				logadd( LOG_DEBUG1, "Unsupported session type %d, rejecting", conn->session->type );
				iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;

				login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
				login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_MISC;

				return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
			}

			conn->flags |= ISCSI_CONNECT_FLAGS_FULL_FEATURE;

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
	int rc;
	iscsi_pdu *login_response_pdu = (iscsi_pdu *) conn->login_response_pdu;

	if ( login_response_pdu == NULL )
		return ISCSI_CONNECT_PDU_READ_OK;

	iscsi_login_req_packet *login_req_pkt = (iscsi_login_req_packet *) pdu->bhs_pkt;
	uint cid = iscsi_get_be16(login_req_pkt->cid);

	iscsi_negotiation_kvp pairs;
	iscsi_login_response_packet *login_response_pkt = (iscsi_login_response_packet *) login_response_pdu->bhs_pkt;
	rc = iscsi_parse_login_key_value_pairs( &pairs, (uint8_t *) pdu->ds_cmd_data, pdu->ds_len );

	if ( rc < 0 || rc > login_response_pdu->ds_len ) {
		login_response_pkt->status_class  = ISCSI_LOGIN_RESPONSE_STATUS_CLASS_CLIENT_ERR;
		login_response_pkt->status_detail = ISCSI_LOGIN_RESPONSE_STATUS_DETAILS_CLIENT_ERR_AUTH_ERR;

		return ISCSI_CONNECT_PDU_READ_ERR_LOGIN_RESPONSE;
	}

	if ( conn->state == ISCSI_CONNECT_STATE_INVALID ) {
		rc = iscsi_connection_handle_login_phase_none( conn, login_response_pdu, &pairs, cid );
		logadd( LOG_DEBUG1, "rc2: %d", rc );

		if ( rc != ISCSI_CONNECT_PDU_READ_OK ) {
			iscsi_connection_pdu_login_response( conn, login_response_pdu );

			return ISCSI_CONNECT_PDU_READ_OK;
		}
	}

	rc = iscsi_connecction_handle_login_response( conn, login_response_pdu, &pairs );

	if ( rc == ISCSI_CONNECT_PDU_READ_OK ) {
		conn->state = ISCSI_CONNECT_STATE_RUNNING;
	}

	iscsi_connection_pdu_login_response( conn, login_response_pdu );

	return ISCSI_CONNECT_PDU_READ_OK;
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
	iscsi_text_req_packet *text_req_pkt = (iscsi_text_req_packet *) pdu->bhs_pkt;
	iscsi_negotiation_kvp pairs;
	int rc = iscsi_parse_login_key_value_pairs( &pairs, (uint8_t *) pdu->ds_cmd_data, pdu->ds_len );

	if ( rc < 0 ) {
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_pdu *response_pdu = iscsi_connection_pdu_create( conn, 8192, false );

	if ( response_pdu == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_pdu_data_handle_text_req: Out of memory while allocating iSCSI text response PDU" );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_connection_update_key_value_pairs( conn, &pairs );

	int payload_len = iscsi_write_login_options_to_pdu( conn, &pairs, response_pdu );

	if ( payload_len < 0 || payload_len > response_pdu->ds_len ) {
		iscsi_connection_pdu_destroy( response_pdu );

		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
	}

	iscsi_text_response_packet *text_response_pkt = (iscsi_text_response_packet *) iscsi_connection_pdu_resize( response_pdu, 0, response_pdu->ds_write_pos );

	text_response_pkt->opcode = ISCSI_OPCODE_SERVER_TEXT_RES;
	text_response_pkt->flags  = (int8_t) ISCSI_TEXT_RESPONSE_FLAGS_FINAL;

	text_response_pkt->reserved = 0;

	iscsi_put_be32( (uint8_t *) &text_response_pkt->total_ahs_len, payload_len ); // TotalAHSLength is always 0 and DataSegmentLength is 24-bit, so write in one step.
	text_response_pkt->lun           = text_req_pkt->lun; // Copying over doesn't change endianess.
	text_response_pkt->init_task_tag = text_req_pkt->init_task_tag; // Copying over doesn't change endianess.

	if ( (text_req_pkt->flags & ISCSI_TEXT_REQ_FLAGS_FINAL) != 0 ) {
		text_response_pkt->target_xfer_tag = 0xFFFFFFFFUL; // Minus one does not require endianess conversion

		conn->session->current_text_init_task_tag = 0xFFFFFFFFUL;
	} else {
		iscsi_put_be32( (uint8_t *) &text_response_pkt->target_xfer_tag, (uint32_t) conn->id + 1UL );
	}

	iscsi_put_be32( (uint8_t *) &text_response_pkt->stat_sn, conn->stat_sn++ );

	if ( (text_response_pkt->opcode & ISCSI_OPCODE_FLAGS_IMMEDIATE) == 0 )
		conn->session->max_cmd_sn++;

	iscsi_put_be32( (uint8_t *) &text_response_pkt->exp_cmd_sn, conn->session->exp_cmd_sn );
	iscsi_put_be32( (uint8_t *) &text_response_pkt->max_cmd_sn, conn->session->max_cmd_sn );
	text_response_pkt->reserved2[0] = 0ULL;
	text_response_pkt->reserved2[1] = 0ULL;

	iscsi_connection_pdu_write( conn, response_pdu );

	return ISCSI_CONNECT_PDU_READ_OK;
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

	if ( rc < 0 ) {
		logadd( LOG_ERROR, "Fatal error during payload handler (opcode 0x%02x) detected for client %s", (int) opcode, conn->client->hostName );
	}
	return rc;
}

/**
 * @brief Retrieves and merges splitted iSCSI PDU data read from TCP/IP socket.
 *
 * This function handles partial reads of data
 * packets.\n
 * The function is guaranteed to read as many bytes as indicated by the
 * PDU struct, unless the read timeout is reached, or the connection
 * is closed/reset.\n
 * Care is also taken for padding bytes that have to be read. It is
 * assumed the according buffer will have enough space for the padding
 * bytes, which is always guaranteed when using the create and resize
 * helpers for allocating PDUs.
 *
 * @param[in] conn Pointer to iSCSI connection to read TCP/IP data from.
 * @param[in] pdu Pointer to iSCSI PDU to read TCP/IP data into.
 * @retval -1 Fatal error occured during processing the PDU.
 * @retval 0 Read operation was successful and next read is ready.
 * @retval 1 Read operation was successful and PDU was fully processed.
 */
static int iscsi_connection_pdu_data_read(iscsi_connection *conn, iscsi_pdu *pdu)
{
	const uint32_t ds_len = ISCSI_ALIGN( pdu->ds_len, ISCSI_ALIGN_SIZE );

	if ( pdu->recv_pos < ds_len ) {
		const int32_t len = iscsi_connection_read( conn, (((uint8_t *) pdu->ds_cmd_data) + pdu->recv_pos), (ds_len - pdu->recv_pos) );

		if ( len < 0L )
			return len;

		pdu->recv_pos += len;
	}

	if ( pdu->recv_pos < ds_len )
		return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

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
				assert( conn->pdu_processing == NULL );
				conn->pdu_processing = iscsi_connection_pdu_create( conn, 0UL, false );

				if ( conn->pdu_processing == NULL )
					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR;

				break;
			}
			case ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR : {
				while ( pdu->bhs_pos < sizeof(struct iscsi_bhs_packet) ) {
					const int32_t len = iscsi_connection_read( conn, (((uint8_t *) pdu->bhs_pkt) + pdu->bhs_pos), (sizeof(struct iscsi_bhs_packet) - pdu->bhs_pos) );

					if ( len < 0L ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
					}

					pdu->bhs_pos += len;
				}

				if ( (conn->flags & ISCSI_CONNECT_FLAGS_LOGGED_OUT) != 0 ) {
					conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
				}

				iscsi_bhs_packet *bhs_pkt = pdu->bhs_pkt;
				const uint ahs_len        = ((uint) bhs_pkt->total_ahs_len * 4);
				const uint32_t ds_len     = iscsi_get_be24(bhs_pkt->ds_len);

				bhs_pkt = iscsi_connection_pdu_resize( pdu, ahs_len, ds_len );

				if ( bhs_pkt == NULL )
					return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				int pos = 0;
				while ( pos < ahs_len ) {
					const int32_t len = iscsi_connection_read( conn, (((uint8_t *) pdu->ahs_pkt) + pos), (ahs_len - pos) );

					if ( len < 0L ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
					}

					pos += len;
				}

				if ( iscsi_connection_pdu_header_handle( conn, pdu ) < 0 ) {
					conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;
 				} else {
 					conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_DATA;
 				}

				break;
			}
			case ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_DATA : {
				if ( pdu->ds_len != 0U ) {
					const int len = iscsi_connection_pdu_data_read( conn, pdu );

					if ( len < 0 ) {
						conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

						return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
					} else if ( len > 0 ) {
						return ISCSI_CONNECT_PDU_READ_OK;
					}
				}

				int rc;

				conn->pdu_processing = NULL;
				if ( (conn->flags & ISCSI_CONNECT_FLAGS_REJECTED) != 0 ) {
					rc = 0;
				} else {
					rc = iscsi_connection_pdu_data_handle( conn, pdu );
				}

				iscsi_connection_pdu_destroy( pdu );

				if ( rc == 0 ) {
					conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_READY;

					return ISCSI_CONNECT_PDU_READ_PROCESSED;
				}
				conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_ERR;

				break;
			}
			case ISCSI_CONNECT_PDU_RECV_STATE_ERR : {
				return ISCSI_CONNECT_PDU_READ_ERR_FATAL;

				break;
			}
			default : {
				logadd( LOG_ERROR, "iscsi_connection_pdu_read: Fatal error reading, unknown packet status."
							  " Should NEVER happen! Please report this bug to the developer" );

				break;
			}
		}
		if ( conn->state == ISCSI_CONNECT_STATE_EXITING || _shutdown ) {
			return ISCSI_CONNECT_PDU_READ_ERR_FATAL;
		}
	} while ( prev_recv_state != conn->pdu_recv_state );

	return 0;
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
	_Static_assert( sizeof(dnbd3_request_t) <= sizeof(struct iscsi_bhs_packet),
		"DNBD3 request size larger than iSCSI BHS packet data size - Manual intervention required!" );
	sock_setTimeout( client->sock, 1000L * 3600L ); // TODO: Remove after finishing iSCSI implementation

	iscsi_connection *conn = iscsi_connection_create( client );

	if ( conn == NULL ) {
		logadd( LOG_ERROR, "iscsi_connection_handle: Out of memory while allocating iSCSI connection" );

		return;
	}

	conn->pdu_processing = iscsi_connection_pdu_create( conn, 0UL, false );

	if ( conn->pdu_processing == NULL ) {
		iscsi_connection_destroy( conn );

		return;
	}

	memcpy( conn->pdu_processing->bhs_pkt, request, len );

	conn->pdu_processing->bhs_pos = len;
	conn->pdu_recv_state = ISCSI_CONNECT_PDU_RECV_STATE_WAIT_PDU_HDR;

	static atomic_int CONN_ID = 0;
	conn->id = ++CONN_ID;

	while ( iscsi_connection_pdu_read( conn ) >= ISCSI_CONNECT_PDU_READ_OK ) {
	}

	iscsi_connection_destroy( conn );
}
