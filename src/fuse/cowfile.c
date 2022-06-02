#include "cowfile.h"
#include "math.h"
extern void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );

static int cowFileVersion = 1;
static pthread_t tidCowUploader;
static char *cowServerAddress;
static CURL *curl;
static cowfile_metadata_header_t *metadata = NULL;
atomic_bool uploadLoop = true;

//both variables are only relevant for the upload after the image is dismounted
static uint32_t blocksForCompleteUpload = 0; 
static uint32_t blocksUploaded = 0;

static struct cow
{
	pthread_mutex_t l2CreateLock;
	int fhm;
	int fhd;
	int fhs;
	char *metadata_mmap;
	l1 *l1;
	l2 *firstL2;
	size_t maxImageSize;
	size_t l1Size; //size of l1 array

} cow;

/**
 * @brief computes the l1 offset from the absolute file offset
 * 
 * @param offset absolute file offset
 * @return int l2 offset
 */
static int getL1Offset( size_t offset )
{
	return (int)( offset / COW_L2_STORAGE_CAPACITY );
}

/**
 * @brief computes the l2 offset from the absolute file offset
 * 
 * @param offset absolute file offset
 * @return int l2 offset
 */
static int getL2Offset( size_t offset )
{
	return (int)( ( offset % COW_L2_STORAGE_CAPACITY ) / COW_METADATA_STORAGE_CAPACITY );
}

/**
 * @brief computes the bit in the bitfield from the absolute file offset
 * 
 * @param offset absolute file offset
 * @return int bit(0-319) in the bitfield
 */
static int getBitfieldOffset( size_t offset )
{
	return (int)( offset / DNBD3_BLOCK_SIZE ) % (COW_BITFIELD_SIZE * 8);
}

/**
 * @brief sets the specified bits in the specified range threadsafe to 1.
 * 
 * @param byte of a bitfield
 * @param from start bit
 * @param to end bit
 */
static void setBits( atomic_char *byte, int from, int to )
{
	char mask = (char)( 255 >> ( 7 - ( to - from ) ) ) << from;
	atomic_fetch_or( byte, ( *byte | mask ) );
}

/**
 * @brief sets the specified bits in the specified range threadsafe to 1.
 * 
 * @param bitfield of a cow_block_metadata
 * @param from start bit
 * @param to end bit
 */
static void setBitsInBitfield( atomic_char *bitfield, int from, int to )
{
	assert( from >= 0 || to < COW_BITFIELD_SIZE * 8 );
	int start = from / 8;
	int end = to / 8;

	for ( int i = start; i <= end; i++ ) {
		setBits( ( bitfield + i ), from - i * 8, MIN( 7, to - i * 8 ) );
		from = ( i + 1 ) * 8;
	}
}

/**
 * @brief Checks if the n bit of an bitfield is 0 or 1.
 * 
 * @param bitfield of a cow_block_metadata
 * @param n the bit which should be checked
 */
static bool checkBit( atomic_char *bitfield, int n )
{
	return ( atomic_load( ( bitfield + ( n / 8 ) ) ) >> ( n % 8 ) ) & 1;
}


size_t curlCallbackCreateSession( char *buffer, size_t itemSize, size_t nitems, void *response )
{
	size_t bytes = itemSize * nitems;
	if ( strlen( response ) + bytes != 36 ) {
		logadd( LOG_INFO, "strlen(response): %lu bytes: %lu \n", strlen( response ), bytes );
		return bytes;
	}

	strncat( response, buffer, 36 );
	return bytes;
}

/**
 * @brief Create a Session with the cow server and gets the session guid
 * 
 * @param imageName 
 * @param version of the original Image
 */
bool createSession( const char *imageName, uint16_t version )
{
	CURLcode res;
	char url[COW_URL_STRING_SIZE];
	snprintf ( url, COW_URL_STRING_SIZE, COW_API_CREATE, cowServerAddress );
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
	if ( http_code != 200 ) {
		logadd( LOG_ERROR, "COW_API_CREATE  failed http: %ld\n", http_code );
		return false;
	}
	curl_easy_reset( curl );
	metadata->uuid[36] = '\0';
	logadd( LOG_DEBUG1, "Cow session started, guid: %s\n", metadata->uuid );
	return true;
}


void print_bin( char a )
{
	for ( int i = 0; i < 8; i++ ) {
		printf( "%d", !!( ( a << i ) & 0x80 ) );
	}
}

void print_bin_arr( char *ptr, int size )
{
	for ( int i = 0; i < size; i++ ) {
		print_bin( ptr[i] );
		printf( " " );
	}
	printf( "\n" );
}

/**
 * @brief Implementation of CURLOPT_READFUNCTION, this function will first send the bitfield and
 * then the block data in one bitstream. this function is usually called multible times per block,
 * because the buffer is usually not large for one block and its bitfield.
 * for more details see: https://curl.se/libcurl/c/CURLOPT_READFUNCTION.html
 * 
 * @param ptr to the buffer
 * @param size size of one element in buffer
 * @param nmemb number of elements in buffer
 * @param userdata from CURLOPT_READFUNCTION
 * @return size_t size written in buffer
 */
size_t curlReadCallbackUploadBlock( char *ptr, size_t size, size_t nmemb, void *userdata )
{
	cow_curl_read_upload_t *uploadBlock = (cow_curl_read_upload_t *)userdata;
	size_t len = 0;
	if ( uploadBlock->position < (size_t)metadata->bitfieldSize ) {
		size_t lenCpy = MIN( metadata->bitfieldSize - uploadBlock->position, size * nmemb );
		memcpy( ptr, uploadBlock->block->bitfield + uploadBlock->position, lenCpy );
		uploadBlock->position += lenCpy;
		len += lenCpy;
	}
	if ( uploadBlock->position >= (size_t)metadata->bitfieldSize ) {
		size_t lenRead = MIN( COW_METADATA_STORAGE_CAPACITY - ( uploadBlock->position - ( metadata->bitfieldSize  ) ),
				( size * nmemb ) - len );
		off_t inBlockOffset = uploadBlock->position - metadata->bitfieldSize;
		size_t lengthRead = pread( cow.fhd, ( ptr + len ), lenRead, uploadBlock->block->offset + inBlockOffset );

		if(lenRead != lengthRead){
			// temp fix, fill up non full blocks
			lengthRead = lenRead;
		}
		uploadBlock->position += lengthRead;
		len += lengthRead;
	}
	return len;
}

/**
 * @brief uploads the given block to the cow server.
 * 
 * @param block pointer to the cow_block_metadata_t
 * @param blocknumber is the absolute block number from the beginning.
 * @param time relative Time since the creation of the cow file. will be used to
 * set the block->timeUploaded.
 */
bool uploadBlock( cow_block_metadata_t *block, uint32_t blocknumber, uint32_t time )
{
	CURLcode res;
	cow_curl_read_upload_t curlUploadBlock;
	char url[COW_URL_STRING_SIZE];

	snprintf( url, COW_URL_STRING_SIZE, COW_API_UPDATE, cowServerAddress, metadata->uuid, blocknumber );
	curlUploadBlock.block = block;
	curlUploadBlock.position = 0;

	curl_easy_setopt( curl, CURLOPT_URL, url );
	curl_easy_setopt( curl, CURLOPT_POST, 1L );
	curl_easy_setopt( curl, CURLOPT_READFUNCTION, curlReadCallbackUploadBlock );
	curl_easy_setopt( curl, CURLOPT_READDATA, (void *)&curlUploadBlock );
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(
			curl, CURLOPT_POSTFIELDSIZE_LARGE, (long)( metadata->bitfieldSize + COW_METADATA_STORAGE_CAPACITY ) );

	struct curl_slist *headers = NULL;
	headers = curl_slist_append( headers, "Content-Type: application/octet-stream" );
	curl_easy_setopt( curl, CURLOPT_HTTPHEADER, headers );


	res = curl_easy_perform( curl );

	/* Check for errors */
	if ( res != CURLE_OK ) {
		logadd( LOG_ERROR, "COW_API_UPDATE  failed: %s\n", curl_easy_strerror( res ) );
		curl_easy_reset( curl );
		return false;
	}
	///////////////// TODO DEBUG REMOVE LATER
	double total;
	res = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total);
    if(CURLE_OK == res) {
		curl_off_t ul;
    	res = curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD_T, &ul);
		if(CURLE_OK == res) {
			logadd( LOG_INFO, "Speed: %f  kb/s", (double) (((double)ul/total)/1000));
		}
    }
	logadd( LOG_INFO, "CURLINFO_TOTAL_TIME: %f", total);
	////////////////////


	long http_code = 0;
	curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, &http_code );
	if ( http_code != 200 ) {
		logadd( LOG_ERROR, "COW_API_UPDATE  failed http: %ld\n", http_code );
		curl_easy_reset( curl );
		return false;
	}

	// everything went ok, update timeUploaded
	block->timeUploaded = (atomic_uint_fast32_t)time;
	curl_easy_reset( curl );
	return true;
}


/**
 * @brief requests the merging of the image on the cow server

 */
bool mergeRequest()
{
	CURLcode res;
	curl_easy_setopt( curl, CURLOPT_POST, 1L );

	char url[COW_URL_STRING_SIZE];
	snprintf( url, COW_URL_STRING_SIZE, COW_API_START_MERGE, cowServerAddress);
	curl_easy_setopt( curl, CURLOPT_URL, url );


	curl_mime *mime;
	curl_mimepart *part;
	mime = curl_mime_init( curl );
	part = curl_mime_addpart( mime );
	
	curl_mime_name( part, "guid" );
	curl_mime_data( part, metadata->uuid, CURL_ZERO_TERMINATED );
	part = curl_mime_addpart( mime );

	curl_mime_name( part, "fileSize" );
	char buf[21];
	snprintf( buf, sizeof buf, "%" PRIu64, metadata->imageSize  );
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
	return true;
}

/**
 * @brief wrapper for mergeRequest so if its fails it will be tried again.
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

void updateCowStatsFile( uint blocks, uint totalBlocks, bool done ) {
	char buffer[300];

	int len = snprintf( buffer, 100, "state: %s\nuploaded: %lu\ntotalBlocks: %lu\n", done?"done":"uploading" ,blocks, totalBlocks );
	pwrite( cow.fhs, buffer, len, 43 );
	ftruncate( cow.fhs, 43 + len );
}

/**
 * @brief loops through all blocks and uploads them.
 * 
 * @param lastLoop if set to true, all blocks which are not uploaded will be uploaded, ignoring their timeChanged
 */
bool uploaderLoop( bool lastLoop )
{
	bool success = true;
	uint64_t lastUpdateTime =  time( NULL );
	int l1MaxOffset =  1 + ((metadata->imageSize  - 1) / COW_L2_STORAGE_CAPACITY); 
	int fails = 0;
	for ( int l1Offset = 0; l1Offset < l1MaxOffset; l1Offset++ ) {
		if ( cow.l1[l1Offset] == -1 ) {
			continue;
		}
		for ( int l2Offset = 0; l2Offset < COW_L2_SIZE; l2Offset++ ) {
			cow_block_metadata_t *block = ( cow.firstL2[cow.l1[l1Offset]] + l2Offset );
			if ( block->offset == -1 ) {
				continue;
			}
			if ( block->timeUploaded < block->timeChanged ) {
				uint32_t relativeTime = (uint32_t)( time( NULL ) - metadata->creationTime );
				if ( ( ( relativeTime - block->timeChanged ) > COW_MIN_UPLOAD_DELAY ) || lastLoop ) {
					
					fails = 0;
					while(!uploadBlock( block, l1Offset * COW_L2_SIZE + l2Offset, relativeTime ) && fails > 5 ) {
						logadd( LOG_WARNING, "Trying again. %i/5", fails );
						fails++;
					}
					if ( fails >= 5 ) {
						logadd( LOG_ERROR, "Block upload failed" );
						success = false;
					}
					else{
						if( lastLoop ) {
							blocksUploaded++;
							if(  time(NULL) - lastUpdateTime  > COW_STATS_UPDATE_TIME ) {
								updateCowStatsFile( blocksUploaded, blocksForCompleteUpload, false );
								lastUpdateTime =  time( NULL );
							}
						}
					}
				}
			}
		}
	}
	return success;
}
/**
Counts blocks that have changes that have not yet been uploaded
*/
int countBlocksForUpload() {
	int res = 0;
	int l1MaxOffset =  1 + ((metadata->imageSize  - 1) / COW_L2_STORAGE_CAPACITY); 
	for ( int l1Offset = 0; l1Offset < l1MaxOffset; l1Offset++ ) {
		if ( cow.l1[l1Offset] == -1 ) {
			continue;
		}
		for ( int l2Offset = 0; l2Offset < COW_L2_SIZE; l2Offset++ ) {
			cow_block_metadata_t *block = ( cow.firstL2[cow.l1[l1Offset]] + l2Offset );
			if ( block->offset == -1 ) {
				continue;
			}
			if ( block->timeUploaded < block->timeChanged ) {
				res++;
			}
		}
	}
	return res;
}

/**
 * @brief main loop for blockupload in the background
 */
void cowfile_uploader( void *something )
{
	while ( uploadLoop ) {
		uploaderLoop( false );
		sleep( 2 );
	}
	logadd( LOG_DEBUG1, "start uploading the remaining blocks." );

	blocksForCompleteUpload = countBlocksForUpload();
	updateCowStatsFile( blocksUploaded,blocksForCompleteUpload , false );
	// force the upload of all remaining blocks because the user dismounted the image
	if ( !uploaderLoop( true ) ) {
		logadd( LOG_ERROR, "one or more blocks failed to upload" );
		return;
	}
	updateCowStatsFile( blocksUploaded,blocksForCompleteUpload , true );
	logadd( LOG_DEBUG1, "all blocks uploaded" );
	if( cow_merge_after_upload ) {
		startMerge();
		logadd( LOG_DEBUG1, "Requesting merge." );
	}
}

/**
 * @brief initializes the cow functionality, creates the data & meta file.
 * 
 * @param path where the files should be stored
 * @param image_Name name of the original file/image
 * @param imageSizePtr 
 */
bool cowfile_init(
		char *path, const char *image_Name, uint16_t imageVersion, size_t **imageSizePtr, char *serverAddress )
{
	char pathMeta[strlen( path ) + 6];
	char pathData[strlen( path ) + 6];

	snprintf( pathMeta, strlen( path ) + 6, "%s%s", path, "/meta" ) ;
	snprintf( pathData, strlen( path ) + 6, "%s%s", path, "/data" ) ;

	if ( ( cow.fhm = open( pathMeta, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not create cow meta file. Bye.\n %s \n", pathMeta );
		return false;
	}

	if ( ( cow.fhd = open( pathData, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not create cow data file. Bye.\n" );
		return false;
	}

	int maxPageSize = 8192;

	// TODO IMAGE NAME IS FIXED
	size_t metaDataSizeHeader = sizeof( cowfile_metadata_header_t ) + strlen( image_Name );


	cow.maxImageSize = 1000LL * 1000LL * 1000LL * 1000LL; // tb*gb*mb*kb todo make this changeable
	cow.l1Size = ( ( cow.maxImageSize + COW_L2_STORAGE_CAPACITY - 1LL ) / COW_L2_STORAGE_CAPACITY );

	// size of l1 array + number of l2's * size of l2
	size_t metadata_size = cow.l1Size * sizeof( l1 ) + cow.l1Size * sizeof( l2 );

	// compute next fitting multiple of getpagesize()
	size_t meta_data_start = ( ( metaDataSizeHeader + maxPageSize - 1 ) / maxPageSize ) * maxPageSize;

	size_t metadataFileSize = meta_data_start + metadata_size;
	if ( pwrite( cow.fhm, "", 1, metadataFileSize ) != 1 ) {
		logadd( LOG_ERROR, "Could not write cow meta_data_table to file. Bye.\n" );
		return false;
	}

	cow.metadata_mmap = mmap( NULL, metadataFileSize, PROT_READ | PROT_WRITE, MAP_SHARED, cow.fhm, 0 );


	if ( cow.metadata_mmap == MAP_FAILED ) {
		logadd( LOG_ERROR, "Error while mapping mmap:\n%s \n Bye.\n", strerror( errno ) );
		return false;
	}

	metadata = (cowfile_metadata_header_t *)( cow.metadata_mmap );
	metadata->magicValue = COW_FILE_META_MAGIC_VALUE;
	metadata->version = cowFileVersion;
	metadata->dataFileSize = ATOMIC_VAR_INIT( 0 );
	metadata->metadataFileSize = ATOMIC_VAR_INIT( 0 );
	metadata->metadataFileSize = metadataFileSize;
	metadata->blocksize = DNBD3_BLOCK_SIZE;
	metadata->originalImageSize = **imageSizePtr;
	metadata->imageSize = metadata->originalImageSize;
	metadata->creationTime = time( NULL );
	*imageSizePtr = &metadata->imageSize;
	metadata->metaDataStart = meta_data_start;
	metadata->bitfieldSize = COW_BITFIELD_SIZE;
	metadata->maxImageSize = cow.maxImageSize;
	snprintf( metadata->imageName, 200, "%s", image_Name );
	cow.l1 = (l1 *)( cow.metadata_mmap + meta_data_start );
	metadata->nextL2 = 0;

	for ( size_t i = 0; i < cow.l1Size; i++ ) {
		cow.l1[i] = -1;
	}
	cow.firstL2 = (l2 *)( ( (char *)cow.l1 ) + cow.l1Size );

	// write header to data file
	uint64_t header = COW_FILE_DATA_MAGIC_VALUE;
	if ( pwrite( cow.fhd, &header, sizeof( uint64_t ), 0 ) != sizeof( uint64_t ) ) {
		logadd( LOG_ERROR, "Could not write header to cow data file. Bye.\n" );
		return false;
	}
	// move the dataFileSize to make room for the header
	atomic_store( &metadata->dataFileSize, COW_METADATA_STORAGE_CAPACITY );

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
	pthread_create( &tidCowUploader, NULL, &cowfile_uploader, NULL );
	return true;
}
/**
 * @brief loads an existing cow state from the meta & data files
 * 
 * @param path where the meta & data file is located 
 * @param imageSizePtr 
 */

bool cowfile_load( char *path, size_t **imageSizePtr, char *serverAddress )
{
	cowServerAddress = serverAddress;
	char pathMeta[strlen( path ) + 6];
	char pathData[strlen( path ) + 6];

	snprintf( pathMeta, strlen( path ) + 6, "%s%s", path, "/meta" ) ;
	snprintf( pathData, strlen( path ) + 6, "%s%s", path, "/data" ) ;


	if ( ( cow.fhm = open( pathMeta, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not open cow meta file. Bye.\n" );
		return false;
	}
	if ( ( cow.fhd = open( pathData, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not open cow data file. Bye.\n" );
		return false;
	}

	cowfile_metadata_header_t header;
	{
		size_t sizeToRead = sizeof( cowfile_metadata_header_t );
		size_t readBytes = 0;
		while ( readBytes < sizeToRead ) {
			ssize_t bytes = pread( cow.fhm, ( ( &header ) + readBytes ), sizeToRead, 0 );
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
		struct stat st;
		stat( pathMeta, &st );
		if ( (long)st.st_size < (long)header.metaDataStart + (long)header.nextL2 * (long)sizeof( l2 ) ) {
			logadd( LOG_ERROR, "cow meta file to small. Bye.\n" );
			return false;
		}
	}
	{
		uint64_t magicValueDataFile;
		pread( cow.fhd, &magicValueDataFile, sizeof( uint64_t ), 0 );

		if ( magicValueDataFile != COW_FILE_DATA_MAGIC_VALUE ) {
			if ( __builtin_bswap64( magicValueDataFile ) == COW_FILE_DATA_MAGIC_VALUE ) {
				logadd( LOG_ERROR, "cow data file of wrong endianess. Bye.\n" );
				return false;
			}
			logadd( LOG_ERROR, "cow data file of unkown format. Bye.\n" );
			return false;
		}
		struct stat st;
		stat( pathData, &st );
		if ( (long)header.dataFileSize < st.st_size ) {
			logadd( LOG_ERROR, "cow data file to small. Bye.\n" );
			return false;
		}
	}

	cow.metadata_mmap = mmap( NULL, header.metadataFileSize, PROT_READ | PROT_WRITE, MAP_SHARED, cow.fhm, 0 );

	if ( cow.metadata_mmap == MAP_FAILED ) {
		logadd( LOG_ERROR, "Error while mapping mmap:\n%s \n Bye.\n", strerror( errno ) );
		return false;
	}
	if ( header.version != cowFileVersion ) {
		logadd( LOG_ERROR, "Error wrong file version got: %i expected: 1. Bye.\n", metadata->version );
		return false;
	}


	metadata = (cowfile_metadata_header_t *)( cow.metadata_mmap );

	*imageSizePtr = &metadata->imageSize;
	cow.l1 = (l1 *)( cow.metadata_mmap + metadata->metaDataStart );
	cow.maxImageSize = metadata->maxImageSize;
	cow.l1Size = ( ( cow.maxImageSize + COW_L2_STORAGE_CAPACITY - 1LL ) / COW_L2_STORAGE_CAPACITY );

	cow.firstL2 = (l2 *)( ( (char *)cow.l1 ) + cow.l1Size );

	createCowStatsFile( path );

	pthread_mutex_init( &cow.l2CreateLock, NULL );

	return true;
}

/**
 * @brief writes the given data in the data file 
 * 
 * @param buffer containing the data
 * @param size of the buffer
 * @param netSize which actually contributes to the fuse write request (can be different from size if partial full blocks are written)
 * @param cowRequest 
 * @param block 
 * @param inBlockOffset 
 */
static void writeData( const char *buffer, ssize_t size, size_t netSize, cow_request_t *cowRequest,
		cow_block_metadata_t *block, off_t inBlockOffset )
{
	ssize_t totalBytesWritten = 0;
	while ( totalBytesWritten < size ) {
		ssize_t bytesWritten = pwrite( cow.fhd, ( buffer + totalBytesWritten ), size - totalBytesWritten,
				block->offset + inBlockOffset + totalBytesWritten );
		if ( bytesWritten == -1 ) {
			cowRequest->errorCode = errno;
			break;
		} else if ( bytesWritten == 0 ) {
			cowRequest->errorCode = EIO;
			break;
		}
		totalBytesWritten += bytesWritten;
	}
	atomic_fetch_add( &cowRequest->bytesWorkedOn, netSize );
	setBitsInBitfield( block->bitfield, (int)( inBlockOffset / DNBD3_BLOCK_SIZE ),
			(int)( ( inBlockOffset + totalBytesWritten - 1 ) / DNBD3_BLOCK_SIZE ) );

	block->timeChanged = (atomic_uint_fast32_t)( time( NULL ) - metadata->creationTime );
}

/**
 * @brief 
 * 
 * @param block 
 * @return true 
 * @return false 
 */
static bool allocateMetaBlockData( cow_block_metadata_t *block )
{
	block->offset = (atomic_long)atomic_fetch_add( &metadata->dataFileSize, COW_METADATA_STORAGE_CAPACITY );
	return true;
}

/**
 * @brief Get the cow_block_metadata_t from l1Offset and l2Offset
 * 
 * @param l1Offset 
 * @param l2Offset 
 * @return cow_block_metadata_t* 
 */
static cow_block_metadata_t *getBlock( int l1Offset, int l2Offset )
{
	cow_block_metadata_t *block = ( cow.firstL2[cow.l1[l1Offset]] + l2Offset );
	if ( block->offset == -1 ) {
		allocateMetaBlockData( block );
	}
	return block;
}

/**
 * @brief creates an new L2 Block and initializes the containing cow_block_metadata_t blocks
 * 
 * @param l1Offset 
 */
static bool createL2Block( int l1Offset )
{
	pthread_mutex_lock( &cow.l2CreateLock );
	if ( cow.l1[l1Offset] == -1 ) {
		for ( int i = 0; i < COW_L2_SIZE; i++ ) {
			cow.firstL2[metadata->nextL2][i].offset = -1;
			cow.firstL2[metadata->nextL2][i].timeChanged = 0;
			cow.firstL2[metadata->nextL2][i].timeUploaded = 0;
			for ( int j = 0; j < COW_BITFIELD_SIZE; j++ ) {
				cow.firstL2[metadata->nextL2][i].bitfield[j] = ATOMIC_VAR_INIT( 0 );
			}
		}
		cow.l1[l1Offset] = metadata->nextL2;
		metadata->nextL2 += 1;
	}
	pthread_mutex_unlock( &cow.l2CreateLock );
	return true;
}

static void finishWriteRequest( fuse_req_t req, cow_request_t *cowRequest )
{
	if ( cowRequest->errorCode != 0 ) {
		fuse_reply_err( req, cowRequest->errorCode );

	} else {
		metadata->imageSize = MAX( metadata->imageSize, cowRequest->bytesWorkedOn + cowRequest->fuseRequestOffset );
		if ( cowRequest->replyAttr ) {
			//TODO HANDLE ERROR
			image_ll_getattr( req, cowRequest->ino, cowRequest->fi );

		} else {
			fuse_reply_write( req, cowRequest->bytesWorkedOn );
		}
	}
	if ( cowRequest->replyAttr ) {
		free( (char *)cowRequest->writeBuffer );
	}
	free( cowRequest );
}

static void writePaddedBlock( cow_sub_request_t *sRequest )
{
	//copy write Data
	memcpy( ( sRequest->dRequest.buffer + ( sRequest->inBlockOffset % DNBD3_BLOCK_SIZE ) ), sRequest->buffer,
			sRequest->size );
	writeData( sRequest->dRequest.buffer, DNBD3_BLOCK_SIZE, (ssize_t)sRequest->size, sRequest->cowRequest,
			sRequest->block, ( sRequest->inBlockOffset - ( sRequest->inBlockOffset % DNBD3_BLOCK_SIZE ) ) );


	if ( atomic_fetch_sub( &sRequest->cowRequest->workCounter, 1 ) == 1 ) {
		finishWriteRequest( sRequest->dRequest.fuse_req, sRequest->cowRequest );
	}
	free( sRequest );
}

// TODO if > remote pad 0
/**
 * @brief 
 * 
 */
static void padBlockFromRemote( fuse_req_t req, off_t offset, cow_request_t *cowRequest, char *buffer, size_t size,
		cow_block_metadata_t *block, off_t inBlockOffset )
{
	if ( offset > (off_t)metadata->originalImageSize ) {
		//pad 0 and done
		//TODO 
		char buf[DNBD3_BLOCK_SIZE] = { 0 };
		memcpy( buf, buffer, size );

		writeData( buf, DNBD3_BLOCK_SIZE, (ssize_t)size, cowRequest, block, inBlockOffset );
		return;
	}
	cow_sub_request_t *sRequest = malloc( sizeof( cow_sub_request_t ) + DNBD3_BLOCK_SIZE );
	sRequest->callback = writePaddedBlock;
	sRequest->inBlockOffset = inBlockOffset;
	sRequest->block = block;
	sRequest->size = size;
	sRequest->buffer = buffer;
	sRequest->cowRequest = cowRequest;
	off_t start = offset - ( offset % DNBD3_BLOCK_SIZE );

	sRequest->dRequest.length = DNBD3_BLOCK_SIZE;
	sRequest->dRequest.offset = start;
	sRequest->dRequest.fuse_req = req;
	sRequest->cowRequest = cowRequest;

	if ( ( (size_t)( offset + DNBD3_BLOCK_SIZE ) ) > metadata->originalImageSize ) {
		sRequest->dRequest.length =
				(uint32_t)MIN( DNBD3_BLOCK_SIZE, offset + DNBD3_BLOCK_SIZE - metadata->originalImageSize );
	}

	atomic_fetch_add( &cowRequest->workCounter, 1 );
	if ( !connection_read( &sRequest->dRequest ) ) {
		atomic_fetch_sub( &cowRequest->workCounter, 1 );
		// todo check if not  now
		cowRequest->errorCode = EIO;
		free( sRequest );
		return;
	}
}

void cowFile_handleCallback( dnbd3_async_t *request )
{
	cow_sub_request_t *sRequest = container_of( request, cow_sub_request_t, dRequest );
	sRequest->callback( sRequest );
}

static void readRemoteData( cow_sub_request_t *sRequest )
{
	memcpy( sRequest->cowRequest->readBuffer + ( sRequest->dRequest.offset - sRequest->cowRequest->fuseRequestOffset ),
			sRequest->dRequest.buffer, sRequest->dRequest.length );


	atomic_fetch_add( &sRequest->cowRequest->bytesWorkedOn, sRequest->dRequest.length );

	if ( atomic_fetch_sub( &sRequest->cowRequest->workCounter, 1 ) == 1 ) {
		fuse_reply_buf(
				sRequest->dRequest.fuse_req, sRequest->cowRequest->readBuffer, sRequest->cowRequest->bytesWorkedOn );
		free( sRequest->cowRequest->readBuffer );
		free( sRequest->cowRequest );
	}
	free( sRequest );
}


/// TODO move block padding in write
void cowfile_write( fuse_req_t req, cow_request_t *cowRequest, off_t offset, size_t size )
{
	if ( cowRequest->replyAttr ) {
		cowRequest->writeBuffer = calloc( sizeof( char ), MIN( size, COW_METADATA_STORAGE_CAPACITY ) );
	}
	// if beyond end of file, pad with 0
	if ( offset > (off_t)metadata->imageSize ) {
		size_t pSize = offset - metadata->imageSize;
		// half end block will be padded with original write
		pSize = pSize - ( ( pSize + offset ) % DNBD3_BLOCK_SIZE );
		atomic_fetch_add( &cowRequest->workCounter, 1 );
		//TODO FIX that its actually 0
		cowfile_write( req, cowRequest, metadata->imageSize, pSize );
	}


	off_t currentOffset = offset;
	off_t endOffset = offset + size;

	// write data

	int l1Offset = getL1Offset( currentOffset );
	int l2Offset = getL2Offset( currentOffset );
	while ( currentOffset < endOffset ) {
		if ( cow.l1[l1Offset] == -1 ) {
			createL2Block( l1Offset );
		}
		//loop over L2 array (metadata)
		while ( currentOffset < (off_t)endOffset && l2Offset < COW_L2_SIZE ) {
			cow_block_metadata_t *metaBlock = getBlock( l1Offset, l2Offset );


			size_t metaBlockStartOffset = l1Offset * COW_L2_STORAGE_CAPACITY + l2Offset * COW_METADATA_STORAGE_CAPACITY;

			size_t inBlockOffset = currentOffset - metaBlockStartOffset;
			size_t sizeToWriteToBlock =
					MIN( (size_t)( endOffset - currentOffset ), COW_METADATA_STORAGE_CAPACITY - inBlockOffset );


			/////////////////////////
			// lock for the half block probably needed
			if ( currentOffset % DNBD3_BLOCK_SIZE != 0
					&& !checkBit( metaBlock->bitfield, (int)( inBlockOffset / DNBD3_BLOCK_SIZE ) ) ) {
				// write remote
				size_t padSize = MIN( sizeToWriteToBlock, DNBD3_BLOCK_SIZE - ( (size_t)currentOffset % DNBD3_BLOCK_SIZE ) );
				char *sbuf = cowRequest->writeBuffer + ( ( currentOffset - offset ) * !cowRequest->replyAttr );
				padBlockFromRemote( req, offset, cowRequest, sbuf, padSize, metaBlock, (off_t)inBlockOffset );
				currentOffset += padSize;
				continue;
			}

			size_t endPaddedSize = 0;
			if ( ( currentOffset + sizeToWriteToBlock ) % DNBD3_BLOCK_SIZE != 0 ) {
				off_t currentEndOffset = currentOffset + sizeToWriteToBlock;
				off_t padStartOffset = currentEndOffset - ( currentEndOffset % 4096 );
				off_t inBlockPadStartOffset = padStartOffset - metaBlockStartOffset;
				if ( !checkBit( metaBlock->bitfield, (int)( inBlockPadStartOffset / DNBD3_BLOCK_SIZE ) ) ) {
					char *sbuf = cowRequest->writeBuffer + ( ( padStartOffset - offset ) * !cowRequest->replyAttr );
					padBlockFromRemote( req, padStartOffset, cowRequest, sbuf, (currentEndOffset)-padStartOffset, metaBlock,
							inBlockPadStartOffset );


					sizeToWriteToBlock -= (currentEndOffset)-padStartOffset;
					endPaddedSize = (currentEndOffset)-padStartOffset;
				}
			}


			writeData( cowRequest->writeBuffer + ( ( currentOffset - offset ) * !cowRequest->replyAttr ),
					(ssize_t)sizeToWriteToBlock, sizeToWriteToBlock, cowRequest, metaBlock, inBlockOffset );

			currentOffset += sizeToWriteToBlock;
			currentOffset += endPaddedSize;


			l2Offset++;
		}
		l1Offset++;
		l2Offset = 0;
	}
	// return to fuse either here or in remote reads/writes
	// increase file size if its now larger
	if ( atomic_fetch_sub( &cowRequest->workCounter, 1 ) == 1 ) {
		finishWriteRequest( req, cowRequest );
	}
}


/**
 * @brief Request data, that is not available locally, via the network.
 * 
 * @param req fuse_req_t 
 * @param offset from the start of the file
 * @param size of data to request
 * @param buffer into which the data is to be written
 * @param workCounter workCounter is increased by one and later reduced by one again when the request is completed.
 */
static void readRemote( fuse_req_t req, off_t offset, ssize_t size, cow_request_t *cowRequest )
{
	cow_sub_request_t *sRequest = malloc( sizeof( cow_sub_request_t ) + size );
	sRequest->callback = readRemoteData;
	sRequest->dRequest.length = (uint32_t)size;
	sRequest->dRequest.offset = offset;
	sRequest->dRequest.fuse_req = req;
	sRequest->cowRequest = cowRequest;


	atomic_fetch_add( &cowRequest->workCounter, 1 );
	if ( !connection_read( &sRequest->dRequest ) ) {
		atomic_fetch_sub( &cowRequest->workCounter, 1 );
		//TODO ChECK IF NOT  0  Now
		cowRequest->errorCode = EIO;
		free( sRequest );
		return;
	}
}

void byte_to_binary( atomic_char *a )
{
	for ( int i = 0; i < 8; i++ ) {
		char tmp = *a;
		printf( "%d", !!( ( tmp << i ) & 0x80 ) );
	}
	printf( "\n" );
}

/*
Maybe optimize that remote reads are done first
*/
/**
 * @brief 
 * 
 * @param req Fuse request
 * @param size of date to read
 * @param offset 
 * @return uint64_t 
 */
void cowfile_read( fuse_req_t req, size_t size, off_t offset )
{
	cow_request_t *cowRequest = malloc( sizeof( cow_request_t ) );
	cowRequest->fuseRequestSize = size;
	cowRequest->bytesWorkedOn = ATOMIC_VAR_INIT( 0 );
	cowRequest->workCounter = ATOMIC_VAR_INIT( 1 );
	cowRequest->errorCode = ATOMIC_VAR_INIT( 0 );
	cowRequest->readBuffer = malloc( size );
	cowRequest->fuseRequestOffset = offset;
	off_t lastReadOffset = offset;
	off_t endOffset = offset + size;
	off_t searchOffset = offset;
	off_t inBlockOffset;
	int l1Offset = getL1Offset( offset );
	int l2Offset = getL2Offset( offset );
	int bitfieldOffset = getBitfieldOffset( offset );
	bool isLocal;
	cow_block_metadata_t *block = NULL;

	if ( cow.l1[l1Offset] != -1 ) {
		block = getBlock( l1Offset, l2Offset );
	}

	bool doRead = false;
	bool firstLoop = true;
	bool updateBlock = false;
	while ( searchOffset < endOffset ) {
		if ( firstLoop ) {
			firstLoop = false;
			lastReadOffset = searchOffset;
			isLocal = block != NULL && checkBit( block->bitfield, bitfieldOffset );
		} else if ( ( block != NULL && checkBit( block->bitfield, bitfieldOffset ) != isLocal ) ) {
			doRead = true;
		} else {
			bitfieldOffset++;
		}

		if ( bitfieldOffset >= COW_BITFIELD_SIZE * 8 ) {
			bitfieldOffset = 0;
			l2Offset++;
			if ( l2Offset >= COW_L2_SIZE ) {
				l2Offset = 0;
				l1Offset++;
			}
			updateBlock = true;
			if ( isLocal ) {
				doRead = true;
			}
		}
		// compute the original file offset from bitfieldOffset, l2Offset and l1Offset
		searchOffset = DNBD3_BLOCK_SIZE * ( bitfieldOffset ) + l2Offset * COW_METADATA_STORAGE_CAPACITY
				+ l1Offset * COW_L2_STORAGE_CAPACITY;
		if ( doRead || searchOffset >= endOffset ) {
			ssize_t sizeToRead = MIN( searchOffset, endOffset ) - lastReadOffset;
			if ( !isLocal ) {
				readRemote( req, lastReadOffset, sizeToRead, cowRequest );
			} else {
				// Compute the offset in the data file where the read starts
				off_t localRead =
						block->offset + ( ( lastReadOffset % COW_L2_STORAGE_CAPACITY ) % COW_METADATA_STORAGE_CAPACITY );
				ssize_t totalBytesRead = 0;
				while ( totalBytesRead < sizeToRead ) {
					ssize_t bytesRead =
							pread( cow.fhd, cowRequest->readBuffer + ( lastReadOffset - offset ), sizeToRead, localRead );
					if ( bytesRead == -1 ) {
						cowRequest->errorCode = errno;
						goto fail;
					} else if ( bytesRead <= 0 ) {
						cowRequest->errorCode = EIO;
						goto fail;
					}
					totalBytesRead += bytesRead;
				}

				atomic_fetch_add( &cowRequest->bytesWorkedOn, totalBytesRead );
			}
			lastReadOffset = searchOffset;
			doRead = false;
			firstLoop = true;
		}

		if ( updateBlock ) {
			if ( cow.l1[l1Offset] != -1 ) {
				block = getBlock( l1Offset, l2Offset );
			} else {
				block = NULL;
			}
			updateBlock = false;
		}
	}
fail:;
	if ( atomic_fetch_sub( &cowRequest->workCounter, 1 ) == 1 ) {
		if ( cowRequest->errorCode != 0 ) {
			fuse_reply_err( req, cowRequest->errorCode );

		} else {
			fuse_reply_buf( req, cowRequest->readBuffer, cowRequest->bytesWorkedOn );
		}
		free( cowRequest->readBuffer );
		free( cowRequest );
	}
}


void createCowStatsFile( char* path ) {
	char pathStatus[strlen( path ) + 12];

	snprintf( pathStatus, strlen( path ) + 12, "%s%s", path, "/status.txt") ;

	if ( ( cow.fhs = open( pathStatus, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not create cow status file. Bye.\n" );
		return false;
	}
	char buffer[100];
	int len = snprintf( buffer, 100, "uuid: %s\nstate: active\n",metadata->uuid );
	pwrite(cow.fhs, buffer, len, 0);
}




int cow_printStats( char *buffer, const size_t len ) {

	int ret = 0;
	if(uploadLoop){
		ret = snprintf( buffer, len, "uuid: %s\nstate: %s\ntotalBlocks: \n",
							metadata->uuid, "active");
	}

	if(!uploadLoop){
		ret =  snprintf( buffer, len, "uuidS %s\nstate: %s\ntotalBlocks: \nuploading: %lu/%lu\n",
							metadata->uuid, "uploading", blocksUploaded, blocksForCompleteUpload );
	}
	if ( ret < 0 ) {
		ret = 0;
	}

	return ret;
}

void cowfile_close()
{
	uploadLoop = false;
	pthread_join( tidCowUploader, NULL );
	if ( curl ) {
		curl_global_cleanup();
		curl_easy_cleanup( curl );
	}
}
