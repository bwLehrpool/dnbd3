#include "cowfile.h"
#include "main.h"
#include "connection.h"

#include <dnbd3/config.h>
#include <dnbd3/types.h>
#include <dnbd3/shared/log.h>
#include <sys/mman.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <curl/curl.h>
#include <signal.h>
#include <inttypes.h>
#include <assert.h>

#define UUID_STRLEN 36
// Maximum assumed page size, in case the cow data gets transferred between different architectures
// 16k should be the largest minimum in existence (Itanium)
#define MAX_PAGE_SIZE 16384

extern void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );

static const int CURRENT_COW_VERSION = 3;

static bool statStdout;
static bool statFile;
static pthread_t tidCowUploader;
static pthread_t tidStatUpdater;
static const char *cowServerAddress;
static CURL *curl;
static cowfile_metadata_header_t *metadata = NULL;
static atomic_uint_fast64_t bytesUploaded;
static uint64_t totalBlocksUploaded = 0;
static int activeUploads = 0;
static int uploadLoopThrottle = 0;
static atomic_bool uploadLoop = true; // Keep upload loop running?
static atomic_bool uploadLoopDone = false; // Upload loop has finished all work?
static atomic_bool uploadCancelled = false; // Skip uploading remaining blocks
static struct curl_slist *uploadHeaders = NULL;

static struct cow
{
	char *metadata_mmap;
	l1 *l1;
	l2 *l2;
	int fdMeta;
	int fdData;
	int fdStats;
	pthread_mutex_t l2CreateLock;
} cow;

static size_t curlHeaderCallbackUploadBlock( char *buffer, size_t size, size_t nitems, void *userdata );

static int countOneBits( atomic_uchar *bf, int numBytes )
{
	int bitCount = 0;
	for ( int i = 0; i < numBytes; ++i ) {
		unsigned char value = bf[i];
		while ( value > 0 ) {
			if ( ( value & 1 ) == 1 ) {
				bitCount++;
			}
			value >>= 1;
		}
	}
	return bitCount;
}

#define IS_4K_ALIGNED(v) ( ( (uint64_t)(v) & DNBD3_BLOCK_MASK ) == 0 )

static bool writeAll( int fd, const char *buf, size_t count, off_t offset )
{
	while ( count > 0 ) {
		ssize_t ret = pwrite( fd, buf, count, offset );
		if ( ret == (ssize_t)count )
			return true;
		if ( ret == -1 ) {
			if ( errno == EINTR )
				continue;
			return false;
		}
		if ( ret == 0 )
			return false;
		count -= ret;
		buf += ret;
	}
	return true;
}

/**
 * @brief Computes the l1 index for an absolute file offset
 * 
 * @param offset absolute file offset
 * @return int l1 index
 */
static int offsetToL1Index( size_t offset )
{
	return (int)( offset / COW_FULL_L2_TABLE_DATA_SIZE );
}

/**
 * @brief Computes the l2 index for an absolute file offset
 * 
 * @param offset absolute file offset
 * @return int l2 index
 */
static int offsetToL2Index( size_t offset )
{
	return (int)( ( offset % COW_FULL_L2_TABLE_DATA_SIZE ) / COW_DATA_CLUSTER_SIZE );
}

/**
 * @brief Computes the bit in the bitfield from the absolute file offset
 * 
 * @param offset absolute file offset
 * @return int bit(0-319) in the bitfield
 */
static int getBitfieldOffsetBit( size_t offset )
{
	return (int)( offset / DNBD3_BLOCK_SIZE ) % ( COW_BITFIELD_SIZE * 8 );
}

/**
 * @brief Sets the specified bits in the specified range threadsafe to 1.
 * 
 * @param byte of a bitfield
 * @param from start bit
 * @param to end bit
 * @param value set bits to 1 or 0
 */
static void setBits( atomic_uchar *byte, int64_t from, int64_t to, bool value )
{
	char mask = (char)( ( 255 >> ( 7 - ( to - from ) ) ) << from );
	if ( value ) {
		atomic_fetch_or( byte, mask );
	} else {
		atomic_fetch_and( byte, ~mask );
	}
}

/**
 * @brief Sets the specified bits in the specified range threadsafe to 1.
 * 
 * @param bitfield of a cow_l2_entry
 * @param from start bit
 * @param to end bit
 * @param value set bits to 1 or 0
 */
static void setBitsInBitfield( atomic_uchar *bitfield, int64_t from, int64_t to, bool value )
{
	assert( from >= 0 && to < COW_BITFIELD_SIZE * 8 );
	int64_t start = from / 8;
	int64_t end = to / 8;

	for ( int64_t i = start; i <= end; i++ ) {
		setBits( ( bitfield + i ), from - i * 8, MIN( 7, to - i * 8 ), value );
		from = ( i + 1 ) * 8;
	}
}

/**
 * @brief Checks if the n bit of a bit field is 0 or 1.
 * 
 * @param bitfield of a cow_l2_entry
 * @param n the bit which should be checked
 */
static bool checkBit( atomic_uchar *bitfield, int64_t n )
{
	return ( bitfield[n / 8] >> ( n % 8 ) ) & 1;
}


/**
 * Generic callback for writing received data to a 500 byte buffer.
 * MAKE SURE THE BUFFER IS EMPTY AT THE START! (i.e. buffer[0] = '\0')
 */
static size_t curlWriteCb500( char *buffer, size_t itemSize, size_t nitems, void *userpointer )
{
	char *dest = (char*)userpointer;
	size_t done = strlen( dest );
	size_t bytes = itemSize * nitems;

	assert( done < 500 );
	if ( done < 499 ) {
		size_t n = MIN( bytes, 499 - done );
		memcpy( dest + done, buffer, n );
		dest[done + n] = '\0';
	}
	return bytes;
}

/**
 * @brief Create a Session with the cow server and gets the session uuid.
 */
static bool createSession( const char *imageName, uint16_t rid )
{
	CURLcode res;
	char url[COW_URL_STRING_SIZE];
	char body[1000], reply[500];
	const char *nameEsc;

	curl_easy_reset( curl );
	snprintf( url, COW_URL_STRING_SIZE, COW_API_CREATE, cowServerAddress );
	logadd( LOG_INFO, "COW_API_CREATE URL: %s", url );
	curl_easy_setopt( curl, CURLOPT_POST, 1L );
	curl_easy_setopt( curl, CURLOPT_URL, url );

	nameEsc = curl_easy_escape( curl, imageName, 0 );
	if ( nameEsc == NULL ) {
		logadd( LOG_ERROR, "Error escaping imageName" );
		nameEsc = imageName; // Hope for the best
	}
	snprintf( body, sizeof body, "revision=%d&bitfieldSize=%d&imageName=%s",
			(int)rid, (int)metadata->bitfieldSize, nameEsc );
	if ( nameEsc != imageName ) {
		curl_free( (char*)nameEsc );
	}
	curl_easy_setopt( curl, CURLOPT_POSTFIELDS, body );

	reply[0] = '\0';
	curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, curlWriteCb500 );
	curl_easy_setopt( curl, CURLOPT_WRITEDATA, reply );

	res = curl_easy_perform( curl );

	/* Check for errors */
	if ( res != CURLE_OK ) {
		logadd( LOG_ERROR, "COW_API_CREATE  failed: curl says %s", curl_easy_strerror( res ) );
		return false;
	}

	long http_code = 0;
	curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, &http_code );
	if ( http_code < 200 || http_code >= 300 ) {
		logadd( LOG_ERROR, "COW_API_CREATE  failed: http code %ld, %s", http_code, reply );
		return false;
	}
	if ( strlen( reply ) > UUID_STRLEN ) {
		logadd( LOG_ERROR, "Returned session id is too long: '%s'", reply );
		return false;
	}
	strncpy( metadata->uuid, reply, sizeof(metadata->uuid) );
	logadd( LOG_DEBUG1, "Cow session started, uuid: %s", metadata->uuid );
	return true;
}

/**
 * @brief Implementation of CURLOPT_READFUNCTION, this function will first send the bit field and
 * then the block data in one bitstream. this function is usually called multiple times per block,
 * because the buffer is usually not large for one block and its bitfield.
 * for more details see: https://curl.se/libcurl/c/CURLOPT_READFUNCTION.html
 * 
 * @param ptr to the buffer
 * @param size of one element in buffer
 * @param nmemb number of elements in buffer
 * @param userdata from CURLOPT_READFUNCTION
 * @return size_t size written in buffer
 */
static size_t curlReadCallbackUploadBlock( char *ptr, size_t size, size_t nmemb, void *userdata )
{
	cow_curl_read_upload_t *uploadBlock = (cow_curl_read_upload_t *)userdata;
	size_t len = 0;

	if ( size * nmemb < DNBD3_BLOCK_SIZE ) {
		logadd( LOG_INFO, "Wow, curl read callback with %d bytes left", (int)( size * nmemb ) );
	}
	// Check if we're still in the bitfield
	if ( uploadBlock->position < COW_BITFIELD_SIZE ) {
		size_t lenCpy = MIN( COW_BITFIELD_SIZE - uploadBlock->position, size * nmemb );
		memcpy( ptr + uploadBlock->position, uploadBlock->bitfield + uploadBlock->position,
				lenCpy );
		uploadBlock->position += lenCpy;
		len += lenCpy;
	}
	// No elseif here, might just have crossed over...
	if ( uploadBlock->position >= COW_BITFIELD_SIZE ) {
		// Subtract the bitfield size from everything first
		off_t inClusterOffset = uploadBlock->position - COW_BITFIELD_SIZE;
		ssize_t spaceLeft = ( size * nmemb ) - len;
		// Only read blocks that have been written to the cluster. Saves bandwidth. Not optimal since
		// we do a lot of 4k/32k reads, but it's not that performance critical I guess...
		while ( spaceLeft > 0 && inClusterOffset < (off_t)COW_DATA_CLUSTER_SIZE ) {
			int bitNumber = (int)( inClusterOffset / DNBD3_BLOCK_SIZE );
			uint32_t blockOffset = (uint32_t)( inClusterOffset % DNBD3_BLOCK_SIZE );
			size_t readSize;
			// Small performance hack: All bits one in a byte, do a 32k instead of 4k read
			// TODO: preadv with a large iov, reading unchanged blocks into a trash-buffer
			if ( spaceLeft >= (ssize_t)DNBD3_BLOCK_SIZE * 8
					&& bitNumber % 8 == 0
					&& uploadBlock->bitfield[bitNumber / 8] == 0xff ) {
				readSize = DNBD3_BLOCK_SIZE * 8;
			} else {
				readSize = DNBD3_BLOCK_SIZE;
			}
			readSize -= blockOffset;
			if ( (ssize_t)readSize > spaceLeft ) {
				readSize = spaceLeft;
			}
			// If handling single block, check bits in our copy, as global bitfield could change
			// If uploading 8 blocks at once, check already happened above
			if ( readSize > DNBD3_BLOCK_SIZE || checkBit( uploadBlock->bitfield, bitNumber ) ) {
				ssize_t lengthRead = pread( cow.fdData, ( ptr + len ), readSize,
						uploadBlock->cluster->offset + inClusterOffset );
				if ( lengthRead == -1 ) {
					if ( errno == EAGAIN )
						continue;
					logadd( LOG_ERROR, "Upload: Reading from COW file failed with errno %d", errno );
					return CURL_READFUNC_ABORT;
				}
				if ( lengthRead != (ssize_t)readSize ) {
					logadd( LOG_ERROR, "Upload: Reading from COW file failed with short read (%d/%d)",
							(int)lengthRead, (int)readSize );
					return CURL_READFUNC_ABORT;
				}
				len += lengthRead;
				spaceLeft -= lengthRead;
			}
			inClusterOffset += readSize;
			uploadBlock->position += readSize;
		}
	}
	return len;
}


/**
 * @brief Requests the merging of the image on the cow server.
 */
static bool postMergeRequest()
{
	CURLcode res;
	char url[COW_URL_STRING_SIZE];
	char body[500], reply[500];
	char *uuid;

	curl_easy_reset( curl );
	snprintf( url, COW_URL_STRING_SIZE, COW_API_START_MERGE, cowServerAddress );
	curl_easy_setopt( curl, CURLOPT_URL, url );
	curl_easy_setopt( curl, CURLOPT_POST, 1L );
	curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, curlWriteCb500 );
	curl_easy_setopt( curl, CURLOPT_WRITEDATA, reply );

	uuid = curl_easy_escape( curl, metadata->uuid, 0 );
	if ( uuid == NULL ) {
		logadd( LOG_ERROR, "Error escaping uuid" );
		uuid = metadata->uuid; // Hope for the best
	}
	snprintf( body, sizeof body, "originalFileSize=%"PRIu64"&newFileSize=%"PRIu64"&uuid=%s",
			metadata->validRemoteSize, metadata->imageSize, uuid );
	if ( uuid != metadata->uuid ) {
		curl_free( uuid );
	}
	curl_easy_setopt( curl, CURLOPT_POSTFIELDS, body );

	reply[0] = '\0';
	res = curl_easy_perform( curl );
	if ( res != CURLE_OK ) {
		logadd( LOG_WARNING, "COW_API_START_MERGE  failed. curl reported: %s", curl_easy_strerror( res ) );
		return false;
	}
	long http_code = 0;
	curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, &http_code );
	if ( http_code < 200 || http_code >= 300 ) {
		logadd( LOG_WARNING, "COW_API_START_MERGE  failed with http: %ld: %s", http_code, reply );
		return false;
	}
	return true;
}

/**
 * @brief Wrapper for postMergeRequest so if its fails it will be tried again.
 * 
 */
static void requestRemoteMerge()
{
	int fails = 0;
	bool success = false;
	success = postMergeRequest();
	while ( fails <= 5 && !success ) {
		fails++;
		logadd( LOG_WARNING, "Trying again. %i/5", fails );
		sleep( 10 );
		postMergeRequest();
	}
}

/**
 * @brief Implementation of the CURLOPT_XFERINFOFUNCTION.
 * For more infos see: https://curl.se/libcurl/c/CURLOPT_XFERINFOFUNCTION.html
 * 
 * Each active transfer callbacks this function.
 * This function computes the uploaded bytes between each call and adds it to
 * bytesUploaded, which is used to compute the kb/s uploaded over all transfers.
 * 
 * @param ulNow number of bytes uploaded by this transfer so far.
 * @return int always returns 0 to continue the callbacks.
 */
static int progress_callback( void *clientp, UNUSED curl_off_t dlTotal,
		UNUSED curl_off_t dlNow, UNUSED curl_off_t ulTotal, curl_off_t ulNow )
{
	cow_curl_read_upload_t *uploadingCluster = (cow_curl_read_upload_t *)clientp;
	bytesUploaded += ( ulNow - uploadingCluster->ulLast );
	uploadingCluster->ulLast = ulNow;
	return 0;
}

#ifdef COW_DUMP_BLOCK_UPLOADS
static int cmpfunc( const void *a, const void *b )
{
	return (int)( ( (cow_cluster_statistics_t *)b )->uploads - ( (cow_cluster_statistics_t *)a )->uploads );
}
/**
 * @brief Writes all block numbers sorted by the number of uploads into the statsfile.
 * 
 */
static void dumpBlockUploads()
{
	long unsigned int l1MaxOffset = 1 + ( ( metadata->imageSize - 1 ) / COW_FULL_L2_TABLE_DATA_SIZE );

	cow_cluster_statistics_t blockUploads[l1MaxOffset * COW_L2_TABLE_SIZE];
	uint64_t currentBlock = 0;
	for ( long unsigned int l1Index = 0; l1Index < l1MaxOffset; l1Index++ ) {
		if ( cow.l1[l1Index] == -1 ) {
			continue;
		}
		for ( int l2Index = 0; l2Index < COW_L2_TABLE_SIZE; l2Index++ ) {
			cow_l2_entry_t *block = ( cow.l2[cow.l1[l1Index]] + l2Index );

			blockUploads[currentBlock].uploads = block->uploads;
			blockUploads[currentBlock].clusterNumber = ( l1Index * COW_L2_TABLE_SIZE + l2Index );
			currentBlock++;
		}
	}
	qsort( blockUploads, currentBlock, sizeof( cow_cluster_statistics_t ), cmpfunc );

	dprintf( cow.fdStats, "\n\n[BlockStats]\n" );
	for ( uint64_t i = 0; i < currentBlock; i++ ) {
		dprintf( cow.fdStats, "%" PRIu64 "=%" PRIu64 " \n",
				blockUploads[i].clusterNumber, blockUploads[i].uploads );
	}
}
#endif

/**
 * @brief Updates the status to the stdout/statfile depending on the startup parameters.
 * 
 * @param inQueue Blocks that have changes old enough to be uploaded.
 * @param modified Blocks that have been changed but whose changes are not old enough to be uploaded.
 * @param idle Blocks that do not contain changes that have not yet been uploaded.
 * @param speedBuffer ptr to char array that contains the current upload speed.
 */
static void updateCowStatsFile( uint64_t inQueue, uint64_t modified, uint64_t idle, char *speedBuffer )
{
	char buffer[300];
	const char *state;

	if ( uploadLoop ) {
		state = "backgroundUpload";
	} else if ( !uploadLoopDone ) {
		state = "uploading";
	} else {
		state = "done";
	}

	int len = snprintf( buffer, sizeof buffer,
			"[General]\n"
			"uuid=%s\n"
			"state=%s\n"
			"inQueue=%" PRIu64 "\n"
			"modifiedClusters=%" PRIu64 "\n"
			"idleClusters=%" PRIu64 "\n"
			"totalClustersUploaded=%" PRIu64 "\n"
			"activeUploads=%i\n"
			"%s%s\n",
			metadata->uuid,
			state, inQueue, modified, idle, totalBlocksUploaded, activeUploads,
			COW_SHOW_UL_SPEED ? "avgSpeedKb=" : "",
			speedBuffer );

	if ( len == -1 ) {
		logadd( LOG_ERROR, "snprintf error" );
		return;
	}

	if ( statStdout ) {
		logadd( LOG_INFO, "%s", buffer );
	}

	if ( statFile ) {
		// Pad with a bunch of newlines so we don't change the file size all the time
		ssize_t extra = MIN( 20, (ssize_t)sizeof(buffer) - len - 1 );
		memset( buffer + len, '\n', extra );
		if ( pwrite( cow.fdStats, buffer, len + extra, 0 ) != len + extra ) {
			logadd( LOG_WARNING, "Could not update cow status file" );
		}
#ifdef COW_DUMP_BLOCK_UPLOADS
		if ( !uploadLoop && uploadLoopDone ) {
			lseek( cow.fdStats, len + extra, SEEK_SET );
			dumpBlockUploads();
		}
#endif
	}
}

/**
 * @brief Starts the upload of a given block.
 * 
 * @param cm Curl_multi
 * @param uploadingCluster containing the data for the block to upload.
 */
static bool addUpload( CURLM *cm, cow_curl_read_upload_t *uploadingCluster )
{
	CURL *eh = curl_easy_init();

	char url[COW_URL_STRING_SIZE];

	snprintf( url, COW_URL_STRING_SIZE,
			COW_API_UPDATE, cowServerAddress, metadata->uuid, uploadingCluster->clusterNumber );

	curl_easy_setopt( eh, CURLOPT_URL, url );
	curl_easy_setopt( eh, CURLOPT_POST, 1L );
	curl_easy_setopt( eh, CURLOPT_HEADERFUNCTION, curlHeaderCallbackUploadBlock );
	curl_easy_setopt( eh, CURLOPT_HEADERDATA, (void *)uploadingCluster );
	curl_easy_setopt( eh, CURLOPT_READFUNCTION, curlReadCallbackUploadBlock );
	curl_easy_setopt( eh, CURLOPT_READDATA, (void *)uploadingCluster );
	curl_easy_setopt( eh, CURLOPT_WRITEFUNCTION, curlWriteCb500 );
	curl_easy_setopt( eh, CURLOPT_WRITEDATA, (void *)uploadingCluster->replyBuffer );
	curl_easy_setopt( eh, CURLOPT_PRIVATE, (void *)uploadingCluster );
	// min upload speed of 1kb/s over 10 sec otherwise the upload is canceled.
	curl_easy_setopt( eh, CURLOPT_LOW_SPEED_TIME, 10L );
	curl_easy_setopt( eh, CURLOPT_LOW_SPEED_LIMIT, 1000L );

	curl_easy_setopt( eh, CURLOPT_POSTFIELDSIZE_LARGE,
			(long)( COW_BITFIELD_SIZE
				+ DNBD3_BLOCK_SIZE * countOneBits( uploadingCluster->bitfield, COW_BITFIELD_SIZE ) )
			);

	if ( COW_SHOW_UL_SPEED ) {
		uploadingCluster->ulLast = 0;
		curl_easy_setopt( eh, CURLOPT_NOPROGRESS, 0L );
		curl_easy_setopt( eh, CURLOPT_XFERINFOFUNCTION, progress_callback );
		curl_easy_setopt( eh, CURLOPT_XFERINFODATA, uploadingCluster );
	}
	curl_easy_setopt( eh, CURLOPT_HTTPHEADER, uploadHeaders );
	curl_multi_add_handle( cm, eh );

	return true;
}

static size_t curlHeaderCallbackUploadBlock( char *buffer, size_t size, size_t nitems, void *userdata )
{
	size_t len, offset;
	int delay;
	cow_curl_read_upload_t *uploadingCluster = (cow_curl_read_upload_t*)userdata;

	// If the "Retry-After" header is set, we interpret this as the server being overloaded
	// or not ready yet to take another update. We slow down our upload loop then.
	// We'll only accept a delay in seconds here, not an HTTP Date string.
	// Otherwise, increase the fails counter.
	len = size * nitems;
	if ( len < 13 )
		return len;
	for ( int i = 0; i < 11; ++i ) {
		buffer[i] |= 0x20;
	}
	if ( strncmp( buffer, "retry-after:", 12 ) != 0 )
		return len;
	offset = 12;
	while ( offset + 1 < len && buffer[offset] == ' ' ) {
		offset++;
	}
	delay = atoi( buffer + offset );
	if ( delay > 0 ) {
		if ( delay > 120 ) {
			// Cap to two minutes
			delay = 120;
		}
		uploadLoopThrottle = MAX( uploadLoopThrottle, delay );
		uploadingCluster->retryTime = delay;
	}
	return len;
}

/**
 * @brief After an upload completes, either successful or unsuccessful this
 * function cleans everything up. If unsuccessful and there are some tries left
 * retries to upload the block.
 * 
 * @param cm Curl_multi
 * @param msg CURLMsg
 * @return true returned if the upload was successful or retries are still possible.
 * @return false returned if the upload was unsuccessful.
 */
static bool clusterUploadDoneHandler( CURLM *cm, CURLMsg *msg )
{
	bool success = false;
	cow_curl_read_upload_t *uploadingCluster;
	CURLcode res;
	CURLcode res2;
	res = curl_easy_getinfo( msg->easy_handle, CURLINFO_PRIVATE, &uploadingCluster );

	long http_code = 0;
	res2 = curl_easy_getinfo( msg->easy_handle, CURLINFO_RESPONSE_CODE, &http_code );

	if ( msg->msg != CURLMSG_DONE ) {
		logadd( LOG_ERROR, "multi_message->msg unexpectedly not DONE (%d)", (int)msg->msg );
	} else if ( msg->data.result != CURLE_OK ) {
		logadd( LOG_ERROR, "curl_easy returned non-OK after multi-finish: %s",
				curl_easy_strerror( msg->data.result ) );
		logadd( LOG_ERROR, "(%ld, %s)", http_code, uploadingCluster->replyBuffer );
	} else if ( res != CURLE_OK || res2 != CURLE_OK ) {
		logadd( LOG_ERROR, "curl_easy_getinfo failed after multifinish (%d, %d)", (int)res, (int)res2 );
	} else if ( http_code == 503 ) {
		if ( uploadingCluster->retryTime > 0 ) {
			logadd( LOG_INFO, "COW server is asking to backoff for %d seconds", uploadingCluster->retryTime );
		} else {
			logadd( LOG_ERROR, "COW server returned 503 without Retry-After value: %s",
					uploadingCluster->replyBuffer );
		}
	} else if ( http_code < 200 || http_code >= 300 ) {
		logadd( LOG_ERROR, "COW server returned HTTP %ld: %s", http_code, uploadingCluster->replyBuffer );
	} else {
		// everything went ok, reset timeChanged of underlying cluster, but only if it
		// didn't get updated again in the meantime.
		atomic_compare_exchange_strong( &uploadingCluster->cluster->timeChanged, &uploadingCluster->time, 0 );
		uploadingCluster->cluster->uploads++;
		uploadingCluster->cluster->fails = 0;
		totalBlocksUploaded++;
		success = true;
	}
	if ( !success ) {
		uploadingCluster->cluster->fails++;
		if ( uploadingCluster->retryTime > 0 ) {
			// Don't reset timeChanged timestamp, so the next iteration of uploadModifiedClusters
			// will queue this upload again after the throttle time expired.
		} else {
			logadd( LOG_ERROR, "Uploading cluster failed %i/5 times", uploadingCluster->cluster->fails );
			// Pretend the block changed again just now, to prevent immediate retry
			atomic_compare_exchange_strong( &uploadingCluster->cluster->timeChanged, &uploadingCluster->time,
					time( NULL ) );
		}
	}
	curl_multi_remove_handle( cm, msg->easy_handle );
	curl_easy_cleanup( msg->easy_handle );
	free( uploadingCluster );

	return success;
}

/**
 * @param cm Curl_multi
 * @param activeUploads ptr to integer which holds the number of current uploads
 * @param minNumberUploads break out of loop as soon as there are less than these many transfers running
 * else COW_MAX_PARALLEL_BACKGROUND_UPLOADS.
 * @return true returned if all uploads were successful
 * @return false returned if  one ore more upload failed.
 */
static bool curlMultiLoop( CURLM *cm, int minNumberUploads )
{
	CURLMsg *msg;
	int msgsLeft = -1;
	bool status = true;

	if ( minNumberUploads <= 0 ) {
		minNumberUploads = 1;
	}
	for ( ;; ) {
		CURLMcode mc = curl_multi_perform( cm, &activeUploads );
		if ( mc != CURLM_OK ) {
			logadd( LOG_ERROR, "curl_multi_perform error %d, bailing out", (int)mc );
			status = false;
			break;
		}

		while ( ( msg = curl_multi_info_read( cm, &msgsLeft ) ) != NULL ) {
			if ( !clusterUploadDoneHandler( cm, msg ) ) {
				status = false;
			}
		}
		if ( activeUploads < minNumberUploads ) {
			break;
		}
		// ony wait if there are active uploads
		if ( activeUploads > 0 ) {
			mc = curl_multi_wait( cm, NULL, 0, 1000, NULL );
			if ( mc != CURLM_OK ) {
				logadd( LOG_ERROR, "curl_multi_wait error %d, bailing out", (int)mc );
				status = false;
				break;
			}
		}

	}
	return status;
}

/**
 * @brief loops through all blocks and uploads them.
 * 
 * @param ignoreMinUploadDelay If true uploads all blocks that have changes while
 * ignoring COW_MIN_UPLOAD_DELAY
 * @param cm Curl_multi
 * @return true if all blocks uploaded successful
 * @return false if one ore more blocks failed to upload
 */
bool uploadModifiedClusters( bool ignoreMinUploadDelay, CURLM *cm )
{
	bool success = true;
	const time_t now = time( NULL );

	long unsigned int l1MaxOffset = 1 + ( ( metadata->imageSize - 1 ) / COW_FULL_L2_TABLE_DATA_SIZE );
	// Iterate over all blocks, L1 first
	for ( long unsigned int l1Index = 0; l1Index < l1MaxOffset; l1Index++ ) {
		if ( cow.l1[l1Index] == -1 ) {
			continue; // Not allocated
		}
		// Now all L2 clusters
		for ( int l2Index = 0; l2Index < COW_L2_TABLE_SIZE; l2Index++ ) {
			cow_l2_entry_t *cluster = ( cow.l2[cow.l1[l1Index]] + l2Index );
			if ( cluster->offset == -1 ) {
				continue; // Not allocated
			}
			if ( cluster->timeChanged == 0 ) {
				continue; // Not changed
			}
			if ( !ignoreMinUploadDelay && ( now - cluster->timeChanged < COW_MIN_UPLOAD_DELAY ) ) {
				continue; // Last change not old enough
			}
			// Run curl mainloop at least one, but keep doing so while max concurrent uploads is reached
			int minUploads = ignoreMinUploadDelay
					? COW_MAX_PARALLEL_UPLOADS
					: COW_MAX_PARALLEL_BACKGROUND_UPLOADS;
			if ( !curlMultiLoop( cm, minUploads ) ) {
				success = false;
			}
			// Maybe one of the uploads was rejected by the server asking us to slow down a bit.
			// Check for that case and don't trigger a new upload.
			if ( uploadLoopThrottle > 0 ) {
				goto DONE;
			}
			cow_curl_read_upload_t *b = malloc( sizeof( cow_curl_read_upload_t ) );
			b->cluster = cluster;
			b->clusterNumber = ( l1Index * COW_L2_TABLE_SIZE + l2Index );
			b->position = 0;
			b->retryTime = 0;
			b->time = cluster->timeChanged;
			b->replyBuffer[0] = '\0';
			// Copy, so it doesn't change during upload
			// when we assemble the data in curlReadCallbackUploadBlock()
			for ( int i = 0; i < COW_BITFIELD_SIZE; ++i ) {
				b->bitfield[i] = cluster->bitfield[i];
			}
			addUpload( cm, b );
			if ( !ignoreMinUploadDelay && !uploadLoop ) {
				goto DONE;
			}
		}
	}
DONE:
	// Finish all the transfers still active
	while ( activeUploads > 0 ) {
		if ( !curlMultiLoop( cm, 1 ) ) {
			success = false;
			break;
		}
	}
	return success;
}


/**
 * @brief Computes the data for the status to the stdout/statfile every COW_STATS_UPDATE_TIME seconds.
 * 
 */

void *cowfile_statUpdater( UNUSED void *something )
{
	uint64_t lastUpdateTime = time( NULL );
	time_t now;
	char speedBuffer[20] = "0";

	while ( !uploadLoopDone ) {
		int modified = 0;
		int inQueue = 0;
		int idle = 0;
		long unsigned int l1MaxOffset = 1 + ( ( metadata->imageSize - 1 ) / COW_FULL_L2_TABLE_DATA_SIZE );
		now = time( NULL );
		for ( long unsigned int l1Index = 0; l1Index < l1MaxOffset; l1Index++ ) {
			if ( cow.l1[l1Index] == -1 ) {
				continue;
			}
			for ( int l2Index = 0; l2Index < COW_L2_TABLE_SIZE; l2Index++ ) {
				cow_l2_entry_t *block = ( cow.l2[cow.l1[l1Index]] + l2Index );
				if ( block->offset == -1 ) {
					continue;
				}
				if ( block->timeChanged != 0 ) {
					if ( !uploadLoop || now > block->timeChanged + COW_MIN_UPLOAD_DELAY ) {
						inQueue++;
					} else {
						modified++;
					}
				} else {
					idle++;
				}
			}
		}

		if ( COW_SHOW_UL_SPEED ) {
			double delta;
			double bytes = (double)atomic_exchange( &bytesUploaded, 0 );
			now = time( NULL );
			delta = (double)( now - lastUpdateTime );
			lastUpdateTime = now;
			if ( delta > 0 ) {
				snprintf( speedBuffer, sizeof speedBuffer, "%.2f", bytes / 1000.0 / delta );
			}
		}

		updateCowStatsFile( inQueue, modified, idle, speedBuffer );
		sleep( COW_STATS_UPDATE_TIME );
	}
	return NULL;
}

void quitSigHandler( int sig UNUSED )
{
	uploadCancelled = true;
	uploadLoop = false;
}

/**
 * @brief main loop for blockupload in the background
 */
static void *uploaderThreadMain( UNUSED void *something )
{
	CURLM *cm;

	cm = curl_multi_init();
	curl_multi_setopt( cm, CURLMOPT_MAXCONNECTS,
			(long)MAX( COW_MAX_PARALLEL_UPLOADS, COW_MAX_PARALLEL_BACKGROUND_UPLOADS ) );

	do {
		// Unblock so this very thread gets the signal for abandoning the upload
		struct sigaction newHandler = { .sa_handler = &quitSigHandler };
		sigemptyset( &newHandler.sa_mask );
		sigaction( SIGQUIT, &newHandler, NULL );
		sigset_t sigmask;
		sigemptyset( &sigmask );
		sigaddset( &sigmask, SIGQUIT );
		pthread_sigmask( SIG_UNBLOCK, &sigmask, NULL );
	} while ( 0 );

	while ( uploadLoop ) {
		while ( uploadLoopThrottle > 0 && uploadLoop ) {
			sleep( 1 );
			uploadLoopThrottle--;
		}
		sleep( 2 );
		if ( !uploadLoop )
			break;
		uploadModifiedClusters( false, cm );
	}

	if ( uploadCancelled ) {
		uploadLoopDone = true;
		logadd( LOG_INFO, "Not uploading remaining clusters, SIGQUIT received" );
	} else {
		// force the upload of all remaining blocks because the user dismounted the image
		logadd( LOG_INFO, "Start uploading the remaining clusters." );
		if ( !uploadModifiedClusters( true, cm ) ) {
			uploadLoopDone = true;
			logadd( LOG_ERROR, "One or more clusters failed to upload" );
		} else {
			uploadLoopDone = true;
			logadd( LOG_DEBUG1, "All clusters uploaded" );
			if ( cow_merge_after_upload ) {
				requestRemoteMerge();
				logadd( LOG_DEBUG1, "Requesting merge" );
			}
		}
	}
	curl_multi_cleanup( cm );
	return NULL;
}

/**
 * @brief Create a Cow Stats File  an inserts the session uuid
 * 
 * @param path where the file is created
 * @return true 
 * @return false if failed to create or to write into the file
 */
static bool createCowStatsFile( char *path )
{
	char pathStatus[strlen( path ) + 12];

	snprintf( pathStatus, strlen( path ) + 12, "%s%s", path, "/status" );

	char buffer[100];
	int len = snprintf( buffer, 100, "[General]\nuuid=%s\nstate=active\n", metadata->uuid );
	if ( statStdout ) {
		logadd( LOG_INFO, "%s", buffer );
	}
	if ( statFile ) {
		if ( ( cow.fdStats = open( pathStatus, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ) == -1 ) {
			logadd( LOG_ERROR, "Could not create cow status file. Bye.\n" );
			return false;
		}

		if ( pwrite( cow.fdStats, buffer, len, 0 ) != len ) {
			logadd( LOG_ERROR, "Could not write to cow status file. Bye.\n" );
			return false;
		}
	}
	return true;
}

static bool commonInit( const char* serverAddress, const char *cowUuid )
{
	CURLcode m;

	if ( cowUuid != NULL && strlen( cowUuid ) > UUID_STRLEN ) {
		logadd( LOG_ERROR, "COW UUID too long: '%s'", cowUuid );
		return false;
	}
	uploadHeaders = curl_slist_append( uploadHeaders, "Content-Type: application/octet-stream" );
	pthread_mutex_init( &cow.l2CreateLock, NULL );
	cowServerAddress = serverAddress;
	if ( ( m = curl_global_init( CURL_GLOBAL_ALL ) ) != CURLE_OK ) {
		logadd( LOG_ERROR, "curl_global_init failed: %s",
				curl_easy_strerror( m ) );
		return false;
	}
	curl = curl_easy_init();
	if ( curl == NULL ) {
		logadd( LOG_ERROR, "Error on curl_easy_init" );
		return false;
	}
	return true;
}

/**
 * @brief initializes the cow functionality, creates the data & meta file.
 * 
 * @param path where the files should be stored
 * @param image_Name name of the original file/image
 * @param imageSizePtr
 * @param cowUuid optional, use given UUID for talking to COW server instead of creating session
 */
bool cowfile_init( char *path, const char *image_Name, uint16_t imageVersion,
		atomic_uint_fast64_t **imageSizePtr,
		char *serverAddress, bool sStdout, bool sfile, const char *cowUuid )
{
	char pathMeta[strlen( path ) + 6];
	char pathData[strlen( path ) + 6];

	if ( !commonInit( serverAddress, cowUuid ) )
		return false;

	statStdout = sStdout;
	statFile = sfile;

	snprintf( pathMeta, strlen( path ) + 6, "%s%s", path, "/meta" );
	snprintf( pathData, strlen( path ) + 6, "%s%s", path, "/data" );

	if ( ( cow.fdMeta = open( pathMeta, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not create cow meta file. Bye.\n %s \n", pathMeta );
		return false;
	}

	if ( ( cow.fdData = open( pathData, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not create cow data file. Bye.\n" );
		return false;
	}
	struct stat fs;
	if ( fstat( cow.fdData, &fs ) == -1 || fs.st_size != 0 ) {
		logadd( LOG_ERROR, "/data file already exists and is not empty" );
		return false;
	}

	size_t metaDataSizeHeader = sizeof( cowfile_metadata_header_t );

	// Calculate how many full l2 tables we need to address COW_MAX_IMAGE_SIZE
	size_t l1NumEntries = ( ( COW_MAX_IMAGE_SIZE + COW_FULL_L2_TABLE_DATA_SIZE - 1 )
			/ COW_FULL_L2_TABLE_DATA_SIZE );
	// Make sure l1 and l2 are aligned to struct size
	size_t sizeL1 = sizeof(cow.l1[0]);
	size_t sizeL2 = sizeof(cow.l2[0]);
	size_t startL1 = ( ( metaDataSizeHeader + sizeL1 - 1 ) / sizeL1 ) * sizeL1;
	size_t startL2 = ( ( startL1 + l1NumEntries * sizeL1 + sizeL2 - 1 ) / sizeL2 ) * sizeL2;

	// size of l1 array + number of l2's * size of l2
	size_t ps = getpagesize();
	if ( ps == 0 || ps > INT_MAX ) {
		logadd( LOG_ERROR, "Cannot get native page size, aborting..." );
		return false;
	}
	size_t metaSize = ( ( startL2 + l1NumEntries * sizeof( l2 ) + ps - 1 ) / ps ) * ps;

	if ( ftruncate( cow.fdMeta, metaSize ) != 0 ) {
		logadd( LOG_ERROR, "Could not set file size of meta data file (errno=%d). Bye.\n", errno );
		return false;
	}

	cow.metadata_mmap = mmap( NULL, metaSize, PROT_READ | PROT_WRITE, MAP_SHARED, cow.fdMeta, 0 );

	if ( cow.metadata_mmap == MAP_FAILED ) {
		logadd( LOG_ERROR, "Error while mmap()ing meta data, errno=%d", errno );
		return false;
	}

	metadata = (cowfile_metadata_header_t *)( cow.metadata_mmap );
	metadata->magicValue = COW_FILE_META_MAGIC_VALUE;
	metadata->imageSize = **imageSizePtr;
	metadata->version = CURRENT_COW_VERSION;
	metadata->validRemoteSize = **imageSizePtr;
	metadata->startL1 = (uint32_t)startL1;
	metadata->startL2 = (uint32_t)startL2;
	metadata->bitfieldSize = COW_BITFIELD_SIZE;
	metadata->nextL2 = 0;
	metadata->metaSize = ATOMIC_VAR_INIT( metaSize );
	metadata->nextClusterOffset = ATOMIC_VAR_INIT( COW_DATA_CLUSTER_SIZE );
	metadata->maxImageSize = COW_MAX_IMAGE_SIZE;
	metadata->creationTime = time( NULL );
	snprintf( metadata->imageName, 200, "%s", image_Name );

	cow.l1 = (l1 *)( cow.metadata_mmap + startL1 );
	cow.l2 = (l2 *)( cow.metadata_mmap + startL2 );
	for ( size_t i = 0; i < l1NumEntries; i++ ) {
		cow.l1[i] = -1;
	}

	// write header to data file
	uint64_t header = COW_FILE_DATA_MAGIC_VALUE;
	if ( pwrite( cow.fdData, &header, sizeof( uint64_t ), 0 ) != sizeof( uint64_t ) ) {
		logadd( LOG_ERROR, "Could not write header to cow data file. Bye.\n" );
		return false;
	}

	if ( cowUuid != NULL ) {
		snprintf( metadata->uuid, sizeof(metadata->uuid), "%s", cowUuid );
		logadd( LOG_INFO, "Using provided upload session id" );
	} else if ( !createSession( image_Name, imageVersion ) ) {
		return false;
	}
	createCowStatsFile( path );
	*imageSizePtr = &metadata->imageSize;
	return true;
}

/**
 * @brief loads an existing cow state from the meta & data files
 * 
 * @param path where the meta & data file is located 
 * @param imageSizePtr 
 */
bool cowfile_load( char *path, atomic_uint_fast64_t **imageSizePtr, char *serverAddress, bool sStdout, bool sFile, const char *cowUuid )
{
	char pathMeta[strlen( path ) + 6];
	char pathData[strlen( path ) + 6];

	if ( !commonInit( serverAddress, cowUuid ) )
		return false;

	statStdout = sStdout;
	statFile = sFile;

	snprintf( pathMeta, strlen( path ) + 6, "%s%s", path, "/meta" );
	snprintf( pathData, strlen( path ) + 6, "%s%s", path, "/data" );

	if ( ( cow.fdMeta = open( pathMeta, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not open cow meta file. Bye.\n" );
		return false;
	}
	if ( ( cow.fdData = open( pathData, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not open cow data file. Bye.\n" );
		return false;
	}

	cowfile_metadata_header_t header;
	{
		size_t sizeToRead = sizeof( cowfile_metadata_header_t );
		size_t readBytes = 0;
		while ( readBytes < sizeToRead ) {
			ssize_t bytes = pread( cow.fdMeta, ( ( &header ) + readBytes ), sizeToRead - readBytes, 0 );
			if ( bytes <= 0 ) {
				logadd( LOG_ERROR, "Error while reading meta file header. Bye.\n" );
				return false;
			}
			readBytes += bytes;
		}


		if ( header.magicValue != COW_FILE_META_MAGIC_VALUE ) {
			if ( __builtin_bswap64( header.magicValue ) == COW_FILE_META_MAGIC_VALUE ) {
				logadd( LOG_ERROR, "cow meta file of wrong endianess. Bye.\n" );
				return false;
			}
			logadd( LOG_ERROR, "cow meta file of unkown format. Bye.\n" );
			return false;
		}

		if ( header.bitfieldSize != COW_BITFIELD_SIZE ) {
			logadd( LOG_ERROR, "cow meta file has unexpected bitfield size %d", (int)header.bitfieldSize );
			return false;
		}
		if ( header.startL1 >= header.startL2 || header.startL2 >= header.metaSize ) {
			logadd( LOG_ERROR, "l1/l2 offset messed up in metadata." );
			return false;
		}

		struct stat st;
		fstat( cow.fdMeta, &st );
		if ( st.st_size < (off_t)header.metaSize ) {
			logadd( LOG_ERROR, "cow meta file too small. Bye." );
			return false;
		}
	}
	{
		uint64_t magicValueDataFile;
		if ( pread( cow.fdData, &magicValueDataFile, sizeof( uint64_t ), 0 ) != sizeof( uint64_t ) ) {
			logadd( LOG_ERROR, "Error while reading cow data file, wrong file?. Bye." );
			return false;
		}

		if ( magicValueDataFile != COW_FILE_DATA_MAGIC_VALUE ) {
			if ( __builtin_bswap64( magicValueDataFile ) == COW_FILE_DATA_MAGIC_VALUE ) {
				logadd( LOG_ERROR, "cow data file of wrong endianess. Bye." );
				return false;
			}
			logadd( LOG_ERROR, "cow data file of unkown format. Bye." );
			return false;
		}
		struct stat st;
		fstat( cow.fdData, &st ); // add cluster size, since we don't preallocate
		if ( header.nextClusterOffset > st.st_size + (int)COW_DATA_CLUSTER_SIZE ) {
			logadd( LOG_ERROR, "cow data file too small. Expected=%jd, Is=%jd.",
					(intmax_t)header.nextClusterOffset, (intmax_t)st.st_size );
			return false;
		}
	}

	cow.metadata_mmap = mmap( NULL, header.metaSize, PROT_READ | PROT_WRITE, MAP_SHARED, cow.fdMeta, 0 );

	if ( cow.metadata_mmap == MAP_FAILED ) {
		logadd( LOG_ERROR, "Error while mapping mmap, errno=%d.", errno );
		return false;
	}
	if ( header.version != CURRENT_COW_VERSION ) {
		logadd( LOG_ERROR, "Error wrong file version got: %i expected: %i. Bye.",
				metadata->version, CURRENT_COW_VERSION );
		return false;
	}


	metadata = (cowfile_metadata_header_t *)( cow.metadata_mmap );

	if ( cowUuid != NULL ) {
		logadd( LOG_INFO, "Overriding stored upload session id with provided one" );
		snprintf( metadata->uuid, sizeof(metadata->uuid), "%s", cowUuid );
	}

	*imageSizePtr = &metadata->imageSize;
	cow.l1 = (l1 *)( cow.metadata_mmap + metadata->startL1 );
	cow.l2 = (l2 *)( cow.metadata_mmap + metadata->startL2 );
	createCowStatsFile( path );
	return true;
}
/**
 * @brief Starts the cow BackgroundThreads which are needed for stats and data upload
 * 
 */
bool cowfile_startBackgroundThreads()
{
	if( pthread_create( &tidCowUploader, NULL, &uploaderThreadMain, NULL ) != 0  ) {
		logadd( LOG_ERROR, "Could not create cow uploader thread");
		return false;
	}
	if ( statFile || statStdout ) {
		if(pthread_create( &tidStatUpdater, NULL, &cowfile_statUpdater, NULL ) != 0 ) {
			logadd( LOG_ERROR, "Could not create stat updater thread");
			return false;
		}
	}
	return true;
}

/**
 * Check if block at given offset is local, i.e. has been modified.
 * @param meta The cow_l2_entry for the according cluster MUST be provided
 * @param offset offset of data, can be absolute image offset as it will be transformed into cluster offset
 */
static bool isBlockLocal( cow_l2_entry_t *meta, off_t offset )
{
	if ( meta == NULL )
		return false;
	return checkBit( meta->bitfield, ( offset % COW_DATA_CLUSTER_SIZE ) / DNBD3_BLOCK_SIZE );
}

/**
 * @brief Get the cow_l2_entry_t from l1Index and l2Index.
 * l1 offset must be valid
 * 
 * @param l1Index 
 * @param l2Index 
 * @return cow_l2_entry_t* 
 */
static cow_l2_entry_t *getL2Entry( int l1Index, int l2Index, bool create )
{
	if ( cow.l1[l1Index] == -1 )
		return NULL;
	cow_l2_entry_t *block = cow.l2[cow.l1[l1Index]] + l2Index;
	if ( block->offset == -1 ) {
		if ( !create )
			return NULL;
		block->offset = atomic_fetch_add( &metadata->nextClusterOffset, COW_DATA_CLUSTER_SIZE );
	}
	return block;
}

/**
 * @brief creates an new L2 table and initializes the containing cow_l2_entry_t
 * 
 * @param l1Index 
 */
static bool createL2Table( int l1Index )
{
	pthread_mutex_lock( &cow.l2CreateLock );
	if ( cow.l1[l1Index] == -1 ) {
		int idx = metadata->nextL2++;
		for ( int i = 0; i < COW_L2_TABLE_SIZE; i++ ) {
			cow.l2[idx][i].offset = -1;
			cow.l2[idx][i].timeChanged = ATOMIC_VAR_INIT( 0 );
			cow.l2[idx][i].uploads = ATOMIC_VAR_INIT( 0 );
			for ( int j = 0; j < COW_BITFIELD_SIZE; j++ ) {
				cow.l2[idx][i].bitfield[j] = ATOMIC_VAR_INIT( 0 );
			}
		}
		cow.l1[l1Index] = idx;
	}
	pthread_mutex_unlock( &cow.l2CreateLock );
	return true;
}

/**
 * @brief Is called once a fuse write request ist finished.
 * Calls the corrsponding fuse reply depending on the type and
 * success of the request.
 * 
 * @param req fuse_req_t
 * @param cowRequest
 */

static void finishWriteRequest( fuse_req_t req, cow_request_t *cowRequest )
{
	if ( atomic_fetch_sub( &cowRequest->workCounter, 1 ) != 1 )
		return; // More sub-requests are pending, bail out
	if ( cowRequest->errorCode != 0 ) {
		fuse_reply_err( req, cowRequest->errorCode );
	} else {
		uint64_t newSize = cowRequest->bytesWorkedOn + cowRequest->fuseRequestOffset;
		if ( newSize > metadata->imageSize ) {
			uint64_t oldSize;
			do {
				oldSize = metadata->imageSize;
				newSize = MAX( oldSize, newSize );
			} while ( !atomic_compare_exchange_weak( &metadata->imageSize, &oldSize, newSize ) );
		}
		fuse_reply_write( req, cowRequest->bytesWorkedOn );
	}
	free( cowRequest );
}

/**
 * @brief Called after the padding data was received from the dnbd3 server.
 * The data from the write request will be combined with the data from the server
 * so that we get a full DNBD3_BLOCK and is then written on the disk.
 * @param sRequest 
 */
static void writePaddedBlock( cow_sub_request_t *sRequest )
{
	assert( ( sRequest->inClusterOffset % DNBD3_BLOCK_SIZE ) + sRequest->size <= DNBD3_BLOCK_SIZE );
	// Here, we again check if the block is written locally - there might have been a second write
	// that wrote the full block, hence didn't have to wait for remote data and finished faster.
	// In that case, don't pad from remote as we'd overwrite newer data.
	if ( isBlockLocal( sRequest->cluster, sRequest->inClusterOffset ) ) {
		logadd( LOG_INFO, "It happened!" );
	} else {
		// copy write Data
		// writeBuffer is the received data, patch data from fuse write into it
		memcpy( sRequest->writeBuffer + ( sRequest->inClusterOffset % DNBD3_BLOCK_SIZE ), sRequest->writeSrc,
				sRequest->size );
		if ( !writeAll( cow.fdData, sRequest->writeBuffer, DNBD3_BLOCK_SIZE,
					sRequest->cluster->offset + ( sRequest->inClusterOffset & ~DNBD3_BLOCK_MASK ) ) ) {
			sRequest->cowRequest->errorCode = errno;
		} else {
			sRequest->cowRequest->bytesWorkedOn += sRequest->size;
			int64_t bit = sRequest->inClusterOffset / DNBD3_BLOCK_SIZE;
			setBitsInBitfield( sRequest->cluster->bitfield, bit, bit, true );
			sRequest->cluster->timeChanged = time( NULL );
		}
	}

	finishWriteRequest( sRequest->dRequest.fuse_req, sRequest->cowRequest );
	free( sRequest );
}

/**
 * @brief If a block does not start or finish on an multiple of DNBD3_BLOCK_SIZE, the blocks need to be
 * padded. If this block is inside the original image size, the padding data will be read from the server.
 * Otherwise it will be padded with 0 since the it must be a block after the end of the image.
 * @param req fuse_req_t
 * @param cowRequest cow_request_t
 * @param startOffset Absolute offset where the real data starts
 * @param endOffset Absolute offset where the real data ends
 * @param srcBuffer pointer to the data that needs to be padded, ie. data from user space.
 */
static bool padBlockForWrite( fuse_req_t req, cow_request_t *cowRequest,
		off_t startOffset, off_t endOffset, const char *srcBuffer )
{
	// Make sure we pad exactly one block
	endOffset = MIN( (uint64_t)endOffset, ( startOffset + DNBD3_BLOCK_SIZE ) & ~DNBD3_BLOCK_MASK );
	assert( startOffset < endOffset );
	size_t size = (size_t)( endOffset - startOffset );
	int l1Index = offsetToL1Index( startOffset );
	int l2Index = offsetToL2Index( startOffset );
	off_t inClusterOffset = startOffset % COW_DATA_CLUSTER_SIZE;
	cow_l2_entry_t *cluster = getL2Entry( l1Index, l2Index, true );
	if ( isBlockLocal( cluster, startOffset ) ) {
		// No padding at all, keep existing data
		bool ret = writeAll( cow.fdData, srcBuffer, size, cluster->offset + inClusterOffset );
		if ( ret ) {
			cowRequest->bytesWorkedOn += size;
			cluster->timeChanged = time( NULL );
		}
		return ret;
	}
	// Not local, need some form of padding
	createL2Table( l1Index );
	if ( cluster == NULL ) {
		cluster = getL2Entry( l1Index, l2Index, true );
	}
	uint64_t validImageSize = metadata->validRemoteSize; // As we don't lock
	if ( startOffset >= (off_t)validImageSize ) {
		// After end of remote valid data, pad with zeros entirely
		char buf[DNBD3_BLOCK_SIZE] = {0};
		off_t start = startOffset % DNBD3_BLOCK_SIZE;
		assert( start + size <= DNBD3_BLOCK_SIZE );
		memcpy( buf + start, srcBuffer, size );
		bool ret = writeAll( cow.fdData, buf, DNBD3_BLOCK_SIZE,
				cluster->offset + ( inClusterOffset & ~DNBD3_BLOCK_MASK ) );
		if ( ret ) {
			int64_t bit = inClusterOffset / DNBD3_BLOCK_SIZE;
			setBitsInBitfield( cluster->bitfield, bit, bit, true );
			cowRequest->bytesWorkedOn += size;
			cluster->timeChanged = time( NULL );
		}
		return ret;
	}
	// Need to fetch padding from upstream, allocate struct plus one block
	cow_sub_request_t *sub = calloc( sizeof( *sub ) + DNBD3_BLOCK_SIZE, 1 );
	sub->callback = writePaddedBlock;
	sub->inClusterOffset = inClusterOffset;
	sub->cluster = cluster;
	sub->size = size;
	sub->writeSrc = srcBuffer;
	sub->cowRequest = cowRequest;
	sub->buffer = sub->writeBuffer;

	sub->dRequest.length = (uint32_t)MIN( DNBD3_BLOCK_SIZE, validImageSize - startOffset );
	sub->dRequest.offset = startOffset & ~DNBD3_BLOCK_MASK;
	sub->dRequest.fuse_req = req;

	atomic_fetch_add( &cowRequest->workCounter, 1 );

	if ( !connection_read( &sub->dRequest ) ) {
		free( sub );
		errno = ENOTSOCK;
		// Don't need to go via finishWriteRequest here since the caller will take care of error handling
		atomic_fetch_sub( &cowRequest->workCounter, 1 );
		return false;
	}
	return true;
}

/**
 * @brief Will be called after a dnbd3_async_t is finished.
 * Calls the corrsponding callback function, either writePaddedBlock or readRemoteCallback
 * depending if the original fuse request was a write or read.
 * 
 */
void cowfile_handleCallback( dnbd3_async_t *request )
{
	cow_sub_request_t *sRequest = container_of( request, cow_sub_request_t, dRequest );
	sRequest->callback( sRequest );
}


/**
 * @brief called once dnbd3_async_t is finished. Increases bytesWorkedOn by the number of bytes
 * this request had. Also checks if it was the last dnbd3_async_t to finish the fuse request, if
 * so replys to fuse and cleans up the request.
 * 
 */
static void readRemoteCallback( cow_sub_request_t *sRequest )
{
	atomic_fetch_add( &sRequest->cowRequest->bytesWorkedOn, sRequest->dRequest.length );

	if ( atomic_fetch_sub( &sRequest->cowRequest->workCounter, 1 ) == 1 ) {
		if ( sRequest->cowRequest->bytesWorkedOn != sRequest->cowRequest->fuseRequestSize ) {
			// Because connection_read() will always return exactly as many bytes as requested,
			// or simply never finish.
			logadd( LOG_ERROR, "BUG? Pad read has invalid size. worked on: %"PRIu64", request size: %"
					PRIu64", offset: %"PRIu64,
					(uint64_t)sRequest->cowRequest->bytesWorkedOn,
					(uint64_t)sRequest->cowRequest->fuseRequestSize,
					(uint64_t)sRequest->cowRequest->fuseRequestOffset );
			fuse_reply_err( sRequest->dRequest.fuse_req, EIO );
		} else {
			fuse_reply_buf( sRequest->dRequest.fuse_req, sRequest->cowRequest->readBuffer,
					sRequest->cowRequest->bytesWorkedOn );
		}
		free( sRequest->cowRequest->readBuffer );
		free( sRequest->cowRequest );
	}
	free( sRequest );
}

/**
 * @brief changes the imageSize
 * 
 * @param req fuse request
 * @param size new size the image should have
 * @param ino fuse_ino_t
 * @param fi fuse_file_info
 */

void cowfile_setSize( fuse_req_t req, size_t size, fuse_ino_t ino, struct fuse_file_info *fi )
{
	if ( size < metadata->imageSize ) {
		// truncate file
		if ( size < metadata->validRemoteSize ) {
			metadata->validRemoteSize = size;
		}
	} else if ( size > metadata->imageSize ) {
		// grow file, pad with zeroes
		off_t offset = metadata->imageSize;
		int l1Index = offsetToL1Index( offset );
		int l2Index = offsetToL2Index( offset );
		int l1EndIndex = offsetToL1Index( size );
		int l2EndIndex = offsetToL2Index( size );
		// Special case, first cluster through which the size change passes
		cow_l2_entry_t *cluster = getL2Entry( l1Index, l2Index, false );
		if ( cluster != NULL ) {
			off_t inClusterOffset = offset % COW_DATA_CLUSTER_SIZE;
			// if the new size is inside a DNBD3_BLOCK it might still contain old data before a truncate
			if ( !IS_4K_ALIGNED( metadata->imageSize ) ) {
				size_t sizeToWrite = DNBD3_BLOCK_SIZE - ( metadata->imageSize % DNBD3_BLOCK_SIZE );

				if ( checkBit( cluster->bitfield, inClusterOffset / DNBD3_BLOCK_SIZE ) ) {
					char buf[DNBD3_BLOCK_SIZE] = {0};
					ssize_t bytesWritten = pwrite( cow.fdData, buf, sizeToWrite, cluster->offset + inClusterOffset );

					if ( bytesWritten < (ssize_t)sizeToWrite ) {
						fuse_reply_err( req, bytesWritten == -1 ? errno : EIO );
						return;
					}
					cluster->timeChanged = time( NULL );
					offset += sizeToWrite;
				}
			}
			// all remaining bits in cluster will get set to 0
			inClusterOffset = offset % COW_DATA_CLUSTER_SIZE;
			setBitsInBitfield( cluster->bitfield, inClusterOffset / DNBD3_BLOCK_SIZE,
					( COW_BITFIELD_SIZE * 8 ) - 1, false );
			cluster->timeChanged = time( NULL );
			l2Index++;
			if ( l2Index >= COW_L2_TABLE_SIZE ) {
				l2Index = 0;
				l1Index++;
			}
		}
		// normal case, if clusters exist, null bitfields
		while ( l1Index < l1EndIndex || ( l1Index == l1EndIndex && l2Index <= l2EndIndex ) ) {
			if ( cow.l1[l1Index] == -1 ) {
				l1Index++;
				l2Index = 0;
				continue;
			}
			cluster = getL2Entry( l1Index, l2Index, false );
			if ( cluster != NULL ) {
				memset( cluster->bitfield, 0, COW_BITFIELD_SIZE );
				cluster->timeChanged = time( NULL );
			}
			l2Index++;
			if ( l2Index >= COW_L2_TABLE_SIZE ) {
				l2Index = 0;
				l1Index++;
			}
		}
	}
	metadata->imageSize = size;
	if ( req != NULL ) {
		image_ll_getattr( req, ino, fi );
	}
}

/**
 * @brief Implementation of a write request.
 * 
 * @param req fuse_req_t
 * @param cowRequest 
 * @param offset Offset where the write starts,
 * @param size Size of the write.
 */
void cowfile_write( fuse_req_t req, cow_request_t *cowRequest, off_t offset, size_t size )
{
	// if beyond end of file, pad with 0
	if ( offset > (off_t)metadata->imageSize ) {
		cowfile_setSize( NULL, offset, 0, NULL );
	}


	off_t currentOffset = offset;
	off_t endOffset = offset + size;

	if ( !IS_4K_ALIGNED( currentOffset ) ) {
		// Handle case where start is not 4k aligned
		if ( !padBlockForWrite( req, cowRequest, currentOffset, endOffset, cowRequest->writeBuffer ) ) {
			goto fail;
		}
		// Move forward to next block border
		currentOffset = ( currentOffset + DNBD3_BLOCK_SIZE ) & ~DNBD3_BLOCK_MASK;
	}
	if ( currentOffset < endOffset && !IS_4K_ALIGNED( endOffset ) ) {
		// Handle case where end is not 4k aligned
		off_t lastBlockStart = endOffset & ~DNBD3_BLOCK_MASK;
		if ( !padBlockForWrite( req, cowRequest, lastBlockStart, endOffset,
				cowRequest->writeBuffer + ( lastBlockStart - offset ) ) ) {
			goto fail;
		}
		endOffset = lastBlockStart;
	}

	// From here on start and end are block-aligned
	int l1Index = offsetToL1Index( currentOffset );
	int l2Index = offsetToL2Index( currentOffset );
	while ( currentOffset < endOffset ) {
		if ( cow.l1[l1Index] == -1 ) {
			createL2Table( l1Index );
		}
		//loop over L2 array (metadata)
		while ( currentOffset < endOffset && l2Index < COW_L2_TABLE_SIZE ) {
			cow_l2_entry_t *cluster = getL2Entry( l1Index, l2Index, true );
			size_t inClusterOffset = currentOffset % COW_DATA_CLUSTER_SIZE;
			// How many bytes we can write to this cluster before crossing a boundary,
			// or before the write request is complete
			size_t bytesToWriteToCluster =
					MIN( (size_t)( endOffset - currentOffset ), COW_DATA_CLUSTER_SIZE - inClusterOffset );

			if ( !writeAll( cow.fdData, cowRequest->writeBuffer + ( currentOffset - offset ),
						bytesToWriteToCluster, cluster->offset + inClusterOffset ) ) {
				goto fail;
			}
			int64_t f = inClusterOffset / DNBD3_BLOCK_SIZE;
			int64_t t = ( inClusterOffset + bytesToWriteToCluster - 1 ) / DNBD3_BLOCK_SIZE;
			setBitsInBitfield( cluster->bitfield, f, t, true );
			cowRequest->bytesWorkedOn += bytesToWriteToCluster;
			currentOffset += bytesToWriteToCluster;
			cluster->timeChanged = time( NULL );
			l2Index++;
		}
		l1Index++;
		l2Index = 0;
	}
	goto success;

fail:
	if ( cowRequest->errorCode == 0 ) {
		cowRequest->errorCode = errno != 0 ? errno : EIO;
	}
	// Fallthrough
success:
	finishWriteRequest( req, cowRequest );
}


/**
 * @brief Request data, that is not available locally, via the network.
 * 
 * @param req fuse_req_t
 * @param offset from the start of the file
 * @param size of data to request
 * @param buffer into which the data is to be written
 * @param cowRequest cow_request_t
 */
static void readRemote( fuse_req_t req, off_t offset, ssize_t size, char *buffer, cow_request_t *cowRequest )
{
	assert( offset < (off_t)metadata->validRemoteSize );
	assert( offset + size <= (off_t)metadata->validRemoteSize );
	if ( size == 0 )
		return;
	assert( size > 0 );
	cow_sub_request_t *sRequest = malloc( sizeof( cow_sub_request_t ) );
	sRequest->callback = readRemoteCallback;
	sRequest->dRequest.length = (uint32_t)size;
	sRequest->dRequest.offset = offset;
	sRequest->dRequest.fuse_req = req;
	sRequest->cowRequest = cowRequest;
	sRequest->buffer = buffer;

	atomic_fetch_add( &cowRequest->workCounter, 1 );
	if ( !connection_read( &sRequest->dRequest ) ) {
		cowRequest->errorCode = EIO;
		free( sRequest );
		if ( atomic_fetch_sub( &cowRequest->workCounter, 1 ) == 1 ) {
			fuse_reply_err( req, EIO );
			free( cowRequest->readBuffer );
			free( cowRequest );
		}
	}
}

/**
 * @brief Get the Block Data Source object
 * 
 * @param block
 * @param bitfieldOffset
 * @param offset
 * @return enum dataSource
 */
enum dataSource getBlockDataSource( cow_l2_entry_t *block, off_t bitfieldOffset, off_t offset )
{
	if ( block != NULL && checkBit( block->bitfield, bitfieldOffset ) ) {
		return ds_local;
	}
	if ( offset >= (off_t)metadata->validRemoteSize ) {
		return ds_zero;
	}
	return ds_remote;
}

/**
 * @brief Reads data at given offset. If the data are available locally,
 * they are read locally, otherwise they are requested remotely.
 * 
 * @param req fuse_req_t
 * @param size of date to read
 * @param offset offset where the read starts.
 * @return uint64_t Number of bytes read.
 */
void cowfile_read( fuse_req_t req, size_t size, off_t startOffset )
{
	cow_request_t *cowRequest = malloc( sizeof( cow_request_t ) );
	cowRequest->fuseRequestSize = size;
	cowRequest->bytesWorkedOn = ATOMIC_VAR_INIT( 0 );
	cowRequest->workCounter = ATOMIC_VAR_INIT( 1 );
	cowRequest->errorCode = ATOMIC_VAR_INIT( 0 );
	cowRequest->readBuffer = calloc( size, 1 );
	cowRequest->fuseRequestOffset = startOffset;
	off_t lastReadOffset = -1;
	off_t endOffset = startOffset + size;
	off_t searchOffset = startOffset;
	int l1Index = offsetToL1Index( startOffset );
	int l2Index = offsetToL2Index( startOffset );
	int bitfieldOffset = getBitfieldOffsetBit( startOffset );
	cow_l2_entry_t *cluster = getL2Entry( l1Index, l2Index, false );
	enum dataSource dataState = ds_invalid;
	bool flushCurrentSpan = false; // Set if we need to read the current span and start the next one
	bool newSourceType = true; // Set if we're starting a new span, and the source type needs to be determined

	while ( searchOffset < endOffset ) {
		if ( newSourceType ) {
			newSourceType = false;
			lastReadOffset = searchOffset;
			dataState = getBlockDataSource( cluster, bitfieldOffset, searchOffset );
		} else if ( getBlockDataSource( cluster, bitfieldOffset, searchOffset ) != dataState ) {
			// Source type changed, obviously need to flush current span
			flushCurrentSpan = true;
		} else {
			bitfieldOffset++;
			// If reading from local cow file, crossing a cluster border means we need to flush
			// since the next cluster might be somewhere else in the data file
			if ( dataState == ds_local && bitfieldOffset == COW_BITFIELD_SIZE * 8 ) {
				flushCurrentSpan = true;
			}
		}

		// compute the absolute image offset from bitfieldOffset, l2Index and l1Index
		// bitfieldOffset might be out of bounds here, but that doesn't matter for the calculation
		searchOffset = DNBD3_BLOCK_SIZE * bitfieldOffset + l2Index * COW_DATA_CLUSTER_SIZE
				+ l1Index * COW_FULL_L2_TABLE_DATA_SIZE;
		if ( flushCurrentSpan || searchOffset >= endOffset ) {
			ssize_t spanEndOffset = MIN( searchOffset, endOffset );
			if ( dataState == ds_remote ) {
				if ( spanEndOffset > (ssize_t)metadata->validRemoteSize ) {
					// Account for bytes we leave zero, because they're beyond the (truncated) original image size
					atomic_fetch_add( &cowRequest->bytesWorkedOn, spanEndOffset - metadata->validRemoteSize );
					spanEndOffset = metadata->validRemoteSize;
				}
				readRemote( req, lastReadOffset, spanEndOffset - lastReadOffset,
						cowRequest->readBuffer + ( lastReadOffset - startOffset ), cowRequest );
			} else if ( dataState == ds_zero ) {
				// Past end of image, account for leaving them zero
				ssize_t numBytes = spanEndOffset - lastReadOffset;
				atomic_fetch_add( &cowRequest->bytesWorkedOn, numBytes );
			} else if ( dataState == ds_local ) {
				ssize_t numBytes = spanEndOffset - lastReadOffset;
				// Compute the startOffset in the data file where the read starts
				off_t localRead = cluster->offset + ( lastReadOffset % COW_DATA_CLUSTER_SIZE );
				ssize_t totalBytesRead = 0;
				while ( totalBytesRead < numBytes ) {
					ssize_t bytesRead = pread( cow.fdData, cowRequest->readBuffer + ( lastReadOffset - startOffset ),
							numBytes - totalBytesRead, localRead + totalBytesRead );
					if ( bytesRead == -1 ) {
						cowRequest->errorCode = errno;
						goto fail;
					} else if ( bytesRead == 0 ) {
						logadd( LOG_ERROR, "EOF for read at localRead=%"PRIu64", totalBR=%"PRIu64,
								(uint64_t)localRead, (uint64_t)totalBytesRead );
						logadd( LOG_ERROR, "searchOffset=%"PRIu64", endOffset=%"PRIu64", imageSize=%"PRIu64,
								searchOffset, endOffset, metadata->imageSize );
						cowRequest->errorCode = EIO;
						goto fail;
					}
					totalBytesRead += bytesRead;
				}

				atomic_fetch_add( &cowRequest->bytesWorkedOn, numBytes );
			} else {
				assert( 4 == 6 );
			}
			lastReadOffset = searchOffset;
			flushCurrentSpan = false;
			// Since the source type changed, reset
			newSourceType = true;
		}
		if ( bitfieldOffset == COW_BITFIELD_SIZE * 8 ) {
			// Advance to next cluster in current l2 table
			bitfieldOffset = 0;
			l2Index++;
			if ( l2Index >= COW_L2_TABLE_SIZE ) {
				// Advance to next l1 entry, reset l2 index
				l2Index = 0;
				l1Index++;
			}
			cluster = getL2Entry( l1Index, l2Index, false );
		}
	}
fail:;
	if ( atomic_fetch_sub( &cowRequest->workCounter, 1 ) == 1 ) {
		if ( cowRequest->errorCode != 0 || cowRequest->bytesWorkedOn != size ) {
			logadd( LOG_ERROR, "incomplete read or I/O error (errno=%d, workedOn: %"PRIu64", size: %"PRIu64")",
					cowRequest->errorCode, (uint64_t)cowRequest->bytesWorkedOn, (uint64_t)size );
			fuse_reply_err( req, cowRequest->errorCode != 0 ? cowRequest->errorCode : EIO );
		} else {
			fuse_reply_buf( req, cowRequest->readBuffer, cowRequest->bytesWorkedOn );
		}
		free( cowRequest->readBuffer );
		free( cowRequest );
	}
}


/**
 * @brief stops the StatUpdater and CowUploader threads
 * and waits for them to finish, then cleans up curl.
 * 
 */
void cowfile_close()
{
	uploadLoop = false;
	pthread_join( tidCowUploader, NULL );
	if ( statFile || statStdout ) {
		// Send a signal in case it's hanging in the sleep call
		pthread_kill( tidStatUpdater, SIGHUP );
		pthread_join( tidStatUpdater, NULL );
	}

	curl_slist_free_all( uploadHeaders );
	if ( curl ) {
		curl_easy_cleanup( curl );
		curl_global_cleanup();
	}
}
