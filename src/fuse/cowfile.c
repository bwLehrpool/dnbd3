#include "cowfile.h"
#include "main.h"
#include "connection.h"

#include <dnbd3/shared/log.h>
#include <sys/mman.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <curl/curl.h>

#define UUID_STRLEN 36
// Maximum assumed page size, in case the cow data gets transferred between different architectures
// 16k should be the largest minimum in existence (Itanium)
#define MAX_PAGE_SIZE 16384

extern void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );

static const int CURRENT_COW_VERSION = 2;

static bool statStdout;
static bool statFile;
static pthread_t tidCowUploader;
static pthread_t tidStatUpdater;
static char *cowServerAddress;
static CURL *curl;
static cowfile_metadata_header_t *metadata = NULL;
static atomic_uint_fast64_t bytesUploaded;
static uint64_t totalBlocksUploaded = 0;
static int activeUploads = 0;
atomic_bool uploadLoop = true; // Keep upload loop running?
atomic_bool uploadLoopDone = false; // Upload loop has finished all work?

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
 * @brief Implementation of CURLOPT_WRITEFUNCTION , this function will be called when
 * the server sends back data.
 * for more details see: https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION .html
 *  
 * @param buffer that contains the response data from the server
 * @param itemSize size of one item
 * @param nitems number of items
 * @param response userdata which will later contain the uuid
 * @return size_t size that have been read
 */
size_t curlCallbackCreateSession( char *buffer, size_t itemSize, size_t nitems, void *response )
{
	uint64_t done = strlen( response );
	uint64_t bytes = itemSize * nitems;
	if ( done + bytes > UUID_STRLEN ) {
		logadd( LOG_INFO, "strlen(response): %"PRIu64" bytes: %"PRIu64"\n", done, bytes );
		return bytes;
	}

	strncat( response, buffer, UUID_STRLEN - done + 1 );
	return bytes;
}

/**
 * @brief Create a Session with the cow server and gets the session guid.
 * 
 * @param imageName 
 * @param version of the original Image
 */
bool createSession( const char *imageName, uint16_t version )
{
	CURLcode res;
	char url[COW_URL_STRING_SIZE];
	snprintf( url, COW_URL_STRING_SIZE, COW_API_CREATE, cowServerAddress );
	logadd( LOG_INFO, "COW_API_CREATE URL: %s", url );
	curl_easy_setopt( curl, CURLOPT_POST, 1L );
	curl_easy_setopt( curl, CURLOPT_URL, url );

	curl_mime *mime;
	curl_mimepart *part;
	mime = curl_mime_init( curl );
	part = curl_mime_addpart( mime );
	curl_mime_name( part, "imageName" );
	curl_mime_data( part, imageName, CURL_ZERO_TERMINATED );
	part = curl_mime_addpart( mime );
	curl_mime_name( part, "version" );
	char buf[sizeof( int ) * 3 + 2];
	snprintf( buf, sizeof buf, "%d", version );
	curl_mime_data( part, buf, CURL_ZERO_TERMINATED );

	part = curl_mime_addpart( mime );
	curl_mime_name( part, "bitfieldSize" );
	snprintf( buf, sizeof buf, "%d", metadata->bitfieldSize );
	curl_mime_data( part, buf, CURL_ZERO_TERMINATED );

	curl_easy_setopt( curl, CURLOPT_MIMEPOST, mime );

	metadata->uuid[0] = '\0';
	curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, curlCallbackCreateSession );
	curl_easy_setopt( curl, CURLOPT_WRITEDATA, &metadata->uuid );

	res = curl_easy_perform( curl );
	curl_mime_free( mime );

	/* Check for errors */
	if ( res != CURLE_OK ) {
		logadd( LOG_ERROR, "COW_API_CREATE  failed: %s\n", curl_easy_strerror( res ) );
		return false;
	}

	long http_code = 0;
	curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, &http_code );
	if ( http_code < 200 || http_code >= 300 ) {
		logadd( LOG_ERROR, "COW_API_CREATE  failed http: %ld\n", http_code );
		return false;
	}
	curl_easy_reset( curl );
	metadata->uuid[UUID_STRLEN] = '\0';
	logadd( LOG_DEBUG1, "Cow session started, guid: %s\n", metadata->uuid );
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
size_t curlReadCallbackUploadBlock( char *ptr, size_t size, size_t nmemb, void *userdata )
{
	cow_curl_read_upload_t *uploadBlock = (cow_curl_read_upload_t *)userdata;
	size_t len = 0;
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
		while ( spaceLeft >= (ssize_t)DNBD3_BLOCK_SIZE && inClusterOffset < (off_t)COW_DATA_CLUSTER_SIZE ) {
			int bitNumber = (int)( inClusterOffset / DNBD3_BLOCK_SIZE );
			size_t readSize;
			// Small performance hack: All bits one in a byte, do a 32k instead of 4k read
			if ( spaceLeft >= (ssize_t)DNBD3_BLOCK_SIZE * 8
					&& bitNumber % 8 == 0
					&& uploadBlock->bitfield[bitNumber / 8] == 0xff ) {
				readSize = DNBD3_BLOCK_SIZE * 8;
			} else {
				readSize = DNBD3_BLOCK_SIZE;
			}
			// Check bits in our copy, as global bitfield could change
			if ( checkBit( uploadBlock->bitfield, bitNumber ) ) {
				ssize_t lengthRead = pread( cow.fdData, ( ptr + len ), readSize,
						uploadBlock->block->offset + inClusterOffset );
				if ( lengthRead == -1 ) {
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
bool mergeRequest()
{
	CURLcode res;
	curl_easy_setopt( curl, CURLOPT_POST, 1L );

	char url[COW_URL_STRING_SIZE];
	snprintf( url, COW_URL_STRING_SIZE, COW_API_START_MERGE, cowServerAddress );
	curl_easy_setopt( curl, CURLOPT_URL, url );


	curl_mime *mime;
	curl_mimepart *part;
	mime = curl_mime_init( curl );

	part = curl_mime_addpart( mime );
	curl_mime_name( part, "guid" );
	curl_mime_data( part, metadata->uuid, CURL_ZERO_TERMINATED );

	part = curl_mime_addpart( mime );
	curl_mime_name( part, "originalFileSize" );
	char buf[21];
	snprintf( buf, sizeof buf, "%" PRIu64, metadata->validRemoteSize );
	curl_mime_data( part, buf, CURL_ZERO_TERMINATED );

	part = curl_mime_addpart( mime );
	curl_mime_name( part, "newFileSize" );
	snprintf( buf, sizeof buf, "%" PRIu64, metadata->imageSize );
	curl_mime_data( part, buf, CURL_ZERO_TERMINATED );

	curl_easy_setopt( curl, CURLOPT_MIMEPOST, mime );


	res = curl_easy_perform( curl );
	if ( res != CURLE_OK ) {
		logadd( LOG_WARNING, "COW_API_START_MERGE  failed: %s\n", curl_easy_strerror( res ) );
		curl_easy_reset( curl );
		return false;
	}
	long http_code = 0;
	curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, &http_code );
	if ( http_code != 200 ) {
		logadd( LOG_WARNING, "COW_API_START_MERGE  failed http: %ld\n", http_code );
		curl_easy_reset( curl );
		return false;
	}
	curl_easy_reset( curl );
	curl_mime_free( mime );
	return true;
}

/**
 * @brief Wrapper for mergeRequest so if its fails it will be tried again.
 * 
 */
void startMerge()
{
	int fails = 0;
	bool success = false;
	success = mergeRequest();
	while ( fails <= 5 && !success ) {
		fails++;
		logadd( LOG_WARNING, "Trying again. %i/5", fails );
		mergeRequest();
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
 * @param clientp 
 * @param ulNow number of bytes uploaded by this transfer so far.
 * @return int always returns 0 to continue the callbacks.
 */
int progress_callback( void *clientp, __attribute__((unused)) curl_off_t dlTotal,
		__attribute__((unused)) curl_off_t dlNow, __attribute__((unused)) curl_off_t ulTotal, curl_off_t ulNow )
{
	CURL *eh = (CURL *)clientp;
	cow_curl_read_upload_t *uploadingCluster;
	CURLcode res;
	res = curl_easy_getinfo( eh, CURLINFO_PRIVATE, &uploadingCluster );
	if ( res != CURLE_OK ) {
		logadd( LOG_ERROR, "ERROR" );
		return 0;
	}
	bytesUploaded += ( ulNow - uploadingCluster->ulLast );
	uploadingCluster->ulLast = ulNow;
	return 0;
}

/**
 * @brief Updates the status to the stdout/statfile depending on the startup parameters.
 * 
 * @param inQueue Blocks that have changes old enough to be uploaded.
 * @param modified Blocks that have been changed but whose changes are not old enough to be uploaded.
 * @param idle Blocks that do not contain changes that have not yet been uploaded.
 * @param speedBuffer ptr to char array that contains the current upload speed.
 */

void updateCowStatsFile( uint64_t inQueue, uint64_t modified, uint64_t idle, char *speedBuffer )
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

	int len = snprintf( buffer, 300,
			"state=%s\n"
			"inQueue=%" PRIu64 "\n"
			"modifiedClusters=%" PRIu64 "\n"
			"idleClusters=%" PRIu64 "\n"
			"totalClustersUploaded=%" PRIu64 "\n"
			"activeUploads=%i\n"
			"%s%s",
			state, inQueue, modified, idle, totalBlocksUploaded, activeUploads,
			COW_SHOW_UL_SPEED ? "ulspeed=" : "",
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
		lseek( cow.fdStats, 43, SEEK_SET );
		if ( write( cow.fdStats, buffer, len + extra ) != len ) {
			logadd( LOG_WARNING, "Could not update cow status file" );
		}
#ifdef COW_DUMP_BLOCK_UPLOADS
		if ( !uploadLoop && uploadLoopDone ) {
			dumpBlockUploads();
		}
#endif
	}
}
int cmpfunc( const void *a, const void *b )
{
	return (int)( ( (cow_cluster_statistics_t *)b )->uploads - ( (cow_cluster_statistics_t *)a )->uploads );
}
/**
 * @brief Writes all block numbers sorted by the number of uploads into the statsfile.
 * 
 */
void dumpBlockUploads()
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

	dprintf( cow.fdStats, "\n\nclusterNumber: uploads\n==Block Upload Dump===\n" );
	for ( uint64_t i = 0; i < currentBlock; i++ ) {
		dprintf( cow.fdStats, "%" PRIu64 ": %" PRIu64 " \n", blockUploads[i].clusterNumber, blockUploads[i].uploads );
	}
}

/**
 * @brief Starts the upload of a given block.
 * 
 * @param cm Curl_multi
 * @param uploadingCluster containing the data for the block to upload.
 */
bool addUpload( CURLM *cm, cow_curl_read_upload_t *uploadingCluster, struct curl_slist *headers )
{
	CURL *eh = curl_easy_init();

	char url[COW_URL_STRING_SIZE];

	snprintf( url, COW_URL_STRING_SIZE, COW_API_UPDATE, cowServerAddress, metadata->uuid, uploadingCluster->clusterNumber );

	curl_easy_setopt( eh, CURLOPT_URL, url );
	curl_easy_setopt( eh, CURLOPT_POST, 1L );
	curl_easy_setopt( eh, CURLOPT_READFUNCTION, curlReadCallbackUploadBlock );
	curl_easy_setopt( eh, CURLOPT_READDATA, (void *)uploadingCluster );
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
		curl_easy_setopt( eh, CURLOPT_XFERINFODATA, eh );
	}
	curl_easy_setopt( eh, CURLOPT_HTTPHEADER, headers );
	curl_multi_add_handle( cm, eh );

	return true;
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
bool finishUpload( CURLM *cm, CURLMsg *msg, struct curl_slist *headers )
{
	bool status = true;
	cow_curl_read_upload_t *uploadingCluster;
	CURLcode res;
	CURLcode res2;
	res = curl_easy_getinfo( msg->easy_handle, CURLINFO_PRIVATE, &uploadingCluster );

	long http_code = 0;
	res2 = curl_easy_getinfo( msg->easy_handle, CURLINFO_RESPONSE_CODE, &http_code );

	if ( res != CURLE_OK || res2 != CURLE_OK || http_code < 200 || http_code >= 300
			|| msg->msg != CURLMSG_DONE ) {
		uploadingCluster->fails++;
		logadd( LOG_ERROR, "COW_API_UPDATE  failed %i/5: %s\n", uploadingCluster->fails,
				curl_easy_strerror( msg->data.result ) );
		if ( uploadingCluster->fails < 5 ) {
			addUpload( cm, uploadingCluster, headers );
			goto CLEANUP;
		}
		free( uploadingCluster );
		status = false;
		goto CLEANUP;
	}

	// everything went ok, update timeChanged
	atomic_compare_exchange_strong( &uploadingCluster->block->timeChanged, &uploadingCluster->time, 0 );

	uploadingCluster->block->uploads++;

	totalBlocksUploaded++;
	free( uploadingCluster );
CLEANUP:
	curl_multi_remove_handle( cm, msg->easy_handle );
	curl_easy_cleanup( msg->easy_handle );
	return status;
}

/**
 * @brief 
 * 
 * @param cm Curl_multi
 * @param activeUploads ptr to integer which holds the number of current uploads
 * @param breakIfNotMax will return as soon as there are not all upload slots used, so they can be filled up.
 * @param foregroundUpload used to determine the number of max uploads. If true COW_MAX_PARALLEL_UPLOADS will be the limit,
 * else COW_MAX_PARALLEL_BACKGROUND_UPLOADS.
 * @return true returned if all upload's were successful 
 * @return false returned if  one ore more upload's failed.
 */
bool MessageHandler(
		CURLM *cm,  bool breakIfNotMax, bool foregroundUpload, struct curl_slist *headers )
{
	CURLMsg *msg;
	int msgsLeft = -1;
	bool status = true;
	do {
		curl_multi_perform( cm, &activeUploads );

		while ( ( msg = curl_multi_info_read( cm, &msgsLeft ) ) != NULL ) {
			if ( !finishUpload( cm, msg, headers ) ) {
				status = false;
			}
		}
		if ( breakIfNotMax
				&& activeUploads
						< ( foregroundUpload ? COW_MAX_PARALLEL_UPLOADS : COW_MAX_PARALLEL_BACKGROUND_UPLOADS ) ) {
			break;
		}
		// ony wait if there are active uploads
		if ( activeUploads ) {
			curl_multi_wait( cm, NULL, 0, 1000, NULL );
		}

	} while ( activeUploads );
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
bool uploaderLoop( bool ignoreMinUploadDelay, CURLM *cm )
{
	bool success = true;
	struct curl_slist *headers = NULL;
	const time_t now = time( NULL );
	headers = curl_slist_append( headers, "Content-Type: application/octet-stream" );

	long unsigned int l1MaxOffset = 1 + ( ( metadata->imageSize - 1 ) / COW_FULL_L2_TABLE_DATA_SIZE );
	// Iterate over all blocks, L1 first
	for ( long unsigned int l1Index = 0; l1Index < l1MaxOffset; l1Index++ ) {
		if ( cow.l1[l1Index] == -1 ) {
			continue; // Not allocated
		}
		// Now all L2 blocks
		for ( int l2Index = 0; l2Index < COW_L2_TABLE_SIZE; l2Index++ ) {
			cow_l2_entry_t *block = ( cow.l2[cow.l1[l1Index]] + l2Index );
			if ( block->offset == -1 ) {
				continue; // Not allocated
			}
			if ( block->timeChanged == 0 ) {
				continue; // Not changed
			}
			if ( !ignoreMinUploadDelay && ( now - block->timeChanged < COW_MIN_UPLOAD_DELAY ) ) {
				continue; // Last change not old enough
			}
			// Run curl mainloop at least one, but keep doing so while max concurrent uploads is reached
			do {
				if ( !MessageHandler( cm, true, ignoreMinUploadDelay, headers ) ) {
					success = false;
				}
			} while ( ( activeUploads >= ( ignoreMinUploadDelay ? COW_MAX_PARALLEL_UPLOADS
																				 : COW_MAX_PARALLEL_BACKGROUND_UPLOADS ) )
					&& activeUploads > 0 );
			cow_curl_read_upload_t *b = malloc( sizeof( cow_curl_read_upload_t ) );
			b->block = block;
			b->clusterNumber = ( l1Index * COW_L2_TABLE_SIZE + l2Index );
			b->fails = 0;
			b->position = 0;
			b->time = block->timeChanged;
			// Copy, so it doesn't change during upload
			// when we assemble the data in curlReadCallbackUploadBlock()
			for ( int i = 0; i < COW_BITFIELD_SIZE; ++i ) {
				b->bitfield[i] = block->bitfield[i];
			}
			addUpload( cm, b, headers );
			if ( !ignoreMinUploadDelay && !uploadLoop ) {
				goto DONE;
			}
		}
	}
DONE:
	while ( activeUploads > 0 ) {
		MessageHandler( cm, false, ignoreMinUploadDelay, headers );
	}
	curl_slist_free_all( headers );
	return success;
}


/**
 * @brief Computes the data for the status to the stdout/statfile every COW_STATS_UPDATE_TIME seconds.
 * 
 */

void *cowfile_statUpdater( __attribute__((unused)) void *something )
{
	uint64_t lastUpdateTime = time( NULL );

	while ( !uploadLoopDone ) {
		sleep( COW_STATS_UPDATE_TIME );
		int modified = 0;
		int inQueue = 0;
		int idle = 0;
		long unsigned int l1MaxOffset = 1 + ( ( metadata->imageSize - 1 ) / COW_FULL_L2_TABLE_DATA_SIZE );
		uint64_t now = time( NULL );
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
		char speedBuffer[20];

		if ( COW_SHOW_UL_SPEED ) {
			now = time( NULL );
			uint64_t bytes = atomic_exchange( &bytesUploaded, 0 );
			snprintf( speedBuffer, 20, "%.2f", (double)( ( bytes ) / ( 1 + now - lastUpdateTime ) / 1000 ) );

			lastUpdateTime = now;
		}


		updateCowStatsFile( inQueue, modified, idle, speedBuffer );
	}
	return NULL;
}

/**
 * @brief main loop for blockupload in the background
 */
static void *uploaderThreadMain( __attribute__((unused)) void *something )
{
	CURLM *cm;

	cm = curl_multi_init();
	curl_multi_setopt(
			cm, CURLMOPT_MAXCONNECTS, (long)MAX( COW_MAX_PARALLEL_UPLOADS, COW_MAX_PARALLEL_BACKGROUND_UPLOADS ) );


	while ( uploadLoop ) {
		uploaderLoop( false, cm );
		sleep( 2 );
	}
	logadd( LOG_DEBUG1, "start uploading the remaining blocks." );

	// force the upload of all remaining blocks because the user dismounted the image
	if ( !uploaderLoop( true, cm ) ) {
		logadd( LOG_ERROR, "one or more blocks failed to upload" );
		curl_multi_cleanup( cm );
		uploadLoopDone = true;
		return NULL;
	}
	uploadLoopDone = true;
	curl_multi_cleanup( cm );
	logadd( LOG_DEBUG1, "all blocks uploaded" );
	if ( cow_merge_after_upload ) {
		startMerge();
		logadd( LOG_DEBUG1, "Requesting merge." );
	}
	return NULL;
}

/**
 * @brief Create a Cow Stats File  an inserts the session guid
 * 
 * @param path where the file is created
 * @return true 
 * @return false if failed to create or to write into the file
 */
static bool createCowStatsFile( char *path )
{
	char pathStatus[strlen( path ) + 12];

	snprintf( pathStatus, strlen( path ) + 12, "%s%s", path, "/status.txt" );

	char buffer[100];
	int len = snprintf( buffer, 100, "uuid=%s\nstate: active\n", metadata->uuid );
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

/**
 * @brief initializes the cow functionality, creates the data & meta file.
 * 
 * @param path where the files should be stored
 * @param image_Name name of the original file/image
 * @param imageSizePtr
 */
bool cowfile_init( char *path, const char *image_Name, uint16_t imageVersion,
		atomic_uint_fast64_t **imageSizePtr,
		char *serverAddress, bool sStdout, bool sfile )
{
	statStdout = sStdout;
	statFile = sfile;
	char pathMeta[strlen( path ) + 6];
	char pathData[strlen( path ) + 6];

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

	pthread_mutex_init( &cow.l2CreateLock, NULL );

	cowServerAddress = serverAddress;
	curl_global_init( CURL_GLOBAL_ALL );
	curl = curl_easy_init();
	if ( !curl ) {
		logadd( LOG_ERROR, "Error on curl init. Bye.\n" );
		return false;
	}
	if ( !createSession( image_Name, imageVersion ) ) {
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
bool cowfile_load( char *path, atomic_uint_fast64_t **imageSizePtr, char *serverAddress, bool sStdout, bool sFile )
{
	statStdout = sStdout;
	statFile = sFile;
	cowServerAddress = serverAddress;
	curl_global_init( CURL_GLOBAL_ALL );
	curl = curl_easy_init();
	char pathMeta[strlen( path ) + 6];
	char pathData[strlen( path ) + 6];

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

	*imageSizePtr = &metadata->imageSize;
	cow.l1 = (l1 *)( cow.metadata_mmap + metadata->startL1 );
	cow.l2 = (l2 *)( cow.metadata_mmap + metadata->startL2 );
	pthread_mutex_init( &cow.l2CreateLock, NULL );
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
	if ( isBlockLocal( sRequest->block, sRequest->inClusterOffset ) ) {
		logadd( LOG_INFO, "It happened!" );
	} else {
		// copy write Data
		// writeBuffer is the received data, patch data from fuse write into it
		memcpy( sRequest->writeBuffer + ( sRequest->inClusterOffset % DNBD3_BLOCK_SIZE ), sRequest->writeSrc,
				sRequest->size );
		if ( !writeAll( cow.fdData, sRequest->writeBuffer, DNBD3_BLOCK_SIZE,
					sRequest->block->offset + ( sRequest->inClusterOffset & ~DNBD3_BLOCK_MASK ) ) ) {
			sRequest->cowRequest->errorCode = errno;
		} else {
			sRequest->cowRequest->bytesWorkedOn += sRequest->size;
			int64_t bit = sRequest->inClusterOffset / DNBD3_BLOCK_SIZE;
			setBitsInBitfield( sRequest->block->bitfield, bit, bit, true );
			sRequest->block->timeChanged = time( NULL );
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
	sub->block = cluster;
	sub->size = size;
	sub->writeSrc = srcBuffer;
	sub->cowRequest = cowRequest;

	sub->dRequest.length = (uint32_t)MIN( DNBD3_BLOCK_SIZE, validImageSize - startOffset );
	sub->dRequest.offset = startOffset & ~DNBD3_BLOCK_MASK;
	sub->dRequest.fuse_req = req;

	if ( !connection_read( &sub->dRequest ) ) {
		free( sub );
		errno = ENOTSOCK;
		return false;
	}
	atomic_fetch_add( &cowRequest->workCounter, 1 );
	return true;
}

/**
 * @brief Will be called after a dnbd3_async_t is finished.
 * Calls the corrsponding callback function, either writePaddedBlock or readRemoteData
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
void readRemoteData( cow_sub_request_t *sRequest )
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
	sRequest->callback = readRemoteData;
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
	if ( statFile || statStdout ) {
		pthread_join( tidStatUpdater, NULL );
	}
	pthread_join( tidCowUploader, NULL );

	if ( curl ) {
		curl_global_cleanup();
		curl_easy_cleanup( curl );
	}
}
