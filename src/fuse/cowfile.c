#include "cowfile.h"

extern void image_ll_getattr( fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi );

int cowFileVersion = 1;
cowfile_metadata_header_t *metadata = NULL;

static struct cow
{
	pthread_mutex_t l2CreateLock;
	int fhm;
	int fhd;
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
	return (int)( ( offset % COW_L2_STORAGE_CAPACITY ) / COW_METADAT_STORAGE_CAPACITY );
}

/**
 * @brief computes the bit in the bitfield from the absolute file offset
 * 
 * @param offset absolute file offset
 * @return int bit(0-39) in the bitfield
 */
static int getBitfieldOffset( size_t offset )
{
	return (int)( offset / DNBD3_BLOCK_SIZE ) % COW_BITFIELD_SIZE;
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
	assert( from >= 0 || to < COW_BITFIELD_SIZE );
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

/**
 * @brief initializes the cow functionality, creates the .data & .meta file.
 * 
 * @param path where the files should be stored
 * @param image_Name name of the original file/image
 * @param imageSizePtr 
 */
bool cowfile_init( char *path, const char *image_Name, size_t **imageSizePtr )
{
	char pathMeta[strlen( path ) + 6];
	char pathData[strlen( path ) + 6];
	strcpy( pathMeta, path );
	strcpy( pathData, path );
	strcat( pathMeta, ".meta" );
	if ( ( cow.fhm = open( pathMeta, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not create cow meta file. Bye.\n" );
		return false;
	}

	strcat( pathData, ".data" );
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
	strcpy( metadata->imageName, image_Name );
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
	atomic_store( &metadata->dataFileSize, COW_METADAT_STORAGE_CAPACITY );

	pthread_mutex_init( &cow.l2CreateLock, NULL );
	return 1;
}
/**
 * @brief loads an existing cow state from the .meta & .data files
 * 
 * @param path where the .meta & .data file is located 
 * @param imageSizePtr 
 */

bool cowfile_load( char *path, size_t **imageSizePtr )
{
	char pathMeta[strlen( path ) + 6];
	char pathData[strlen( path ) + 6];
	strcpy( pathMeta, path );
	strcpy( pathData, path );
	strcat( pathMeta, ".meta" );
	strcat( pathData, ".data" );
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
	pthread_mutex_init( &cow.l2CreateLock, NULL );

	return true;
}

/**
 * @brief writes the given data in the .data file 
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
	block->offset = (atomic_long)atomic_fetch_add( &metadata->dataFileSize, COW_METADAT_STORAGE_CAPACITY );
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


// TODO if > remote pad 0
/**
 * @brief 
 * 
 */
static void padBlockFromRemote(
		fuse_req_t req, off_t offset, cow_request_t *cowRequest, cow_write_request_t *cowWriteRequest )
{
	if ( offset > (off_t)metadata->originalImageSize ) {
		//pad 0 and done
		char buffer[DNBD3_BLOCK_SIZE] = { 0 };
		memcpy( buffer, cowWriteRequest->buffer, cowWriteRequest->size );

		writeData( buffer, DNBD3_BLOCK_SIZE, (ssize_t)cowWriteRequest->size, cowRequest, cowWriteRequest->block,
				cowWriteRequest->inBlockOffset );
		free( cowWriteRequest );
		return;
	}

	off_t start = offset - ( offset % DNBD3_BLOCK_SIZE );

	dnbd3_async_t *request = malloc( sizeof( dnbd3_async_t ) );
	request->buffer = calloc( DNBD3_BLOCK_SIZE, sizeof( char ) );
	request->length = DNBD3_BLOCK_SIZE;
	request->offset = start;
	request->fuse_req = req;
	request->cow = cowRequest;
	request->cow_write = cowWriteRequest;
	if ( ( (size_t)( offset + DNBD3_BLOCK_SIZE ) ) > metadata->originalImageSize ) {
		request->length = (uint32_t)MIN( DNBD3_BLOCK_SIZE, offset + DNBD3_BLOCK_SIZE - metadata->originalImageSize );
	}

	atomic_fetch_add( &cowRequest->workCounter, 1 );
	if ( !connection_read( request ) ) {
		atomic_fetch_sub( &cowRequest->workCounter, 1 );
		// todo check if not  now
		cowRequest->errorCode = EIO;
		free( request );
		return;
	}
}

void cowfile_writePaddedBlock( dnbd3_async_t *request )
{
	//copy write Data
	memcpy( ( request->buffer + ( request->cow_write->inBlockOffset % DNBD3_BLOCK_SIZE ) ), request->cow_write->buffer,
			request->cow_write->size );
	writeData( request->buffer, DNBD3_BLOCK_SIZE, (ssize_t)request->cow_write->size, request->cow,
			request->cow_write->block,
			( request->cow_write->inBlockOffset - ( request->cow_write->inBlockOffset % DNBD3_BLOCK_SIZE ) ) );

	free( request->cow_write );
	if ( atomic_fetch_sub( &request->cow->workCounter, 1 ) == 1 ) {
		finishWriteRequest( request->fuse_req, request->cow );
	}
	free( request->buffer );
	free( request );
}

void cowFile_readRemoteData( dnbd3_async_t *request )
{
	atomic_fetch_add( &request->cow->bytesWorkedOn, request->length );
	if ( atomic_fetch_sub( &request->cow->workCounter, 1 ) == 1 ) {
		fuse_reply_buf( request->fuse_req, request->cow->readBuffer, request->cow->bytesWorkedOn );
		free( request->cow->readBuffer );
		free( request->cow );
	}
	free( request );
}


/// TODO move block padding in write
void cowfile_write( fuse_req_t req, cow_request_t *cowRequest, off_t offset, size_t size )
{
	if ( cowRequest->replyAttr ) {
		cowRequest->writeBuffer = calloc( sizeof( char ), MIN( size, COW_METADAT_STORAGE_CAPACITY ) );
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


			size_t metaBlockStartOffset = l1Offset * COW_L2_STORAGE_CAPACITY + l2Offset * COW_METADAT_STORAGE_CAPACITY;

			size_t inBlockOffset = currentOffset - metaBlockStartOffset;
			size_t sizeToWriteToBlock =
					MIN( (size_t)( endOffset - currentOffset ), COW_METADAT_STORAGE_CAPACITY - inBlockOffset );


			/////////////////////////
			// lock for the half block probably needed
			if ( currentOffset % DNBD3_BLOCK_SIZE != 0
					&& !checkBit( metaBlock->bitfield, (int)( inBlockOffset / DNBD3_BLOCK_SIZE ) ) ) {
				// write remote
				size_t padSize = MIN( sizeToWriteToBlock, DNBD3_BLOCK_SIZE - ( (size_t)currentOffset % DNBD3_BLOCK_SIZE ) );
				cow_write_request_t *cowWriteRequest = malloc( sizeof( cow_write_request_t ) );
				cowWriteRequest->inBlockOffset = (off_t)inBlockOffset;
				cowWriteRequest->block = metaBlock;
				cowWriteRequest->size = padSize;
				cowWriteRequest->buffer = cowRequest->writeBuffer + ( ( currentOffset - offset ) * !cowRequest->replyAttr );
				padBlockFromRemote( req, offset, cowRequest, cowWriteRequest );
				currentOffset += padSize;
				continue;
			}

			size_t endPaddedSize = 0;
			if ( ( currentOffset + sizeToWriteToBlock ) % DNBD3_BLOCK_SIZE != 0 ) {
				off_t currentEndOffset = currentOffset + sizeToWriteToBlock;
				off_t padStartOffset = currentEndOffset - ( currentEndOffset % 4096 );
				off_t inBlockPadStartOffset = padStartOffset - metaBlockStartOffset;
				if ( !checkBit( metaBlock->bitfield, (int)( inBlockPadStartOffset / DNBD3_BLOCK_SIZE ) ) ) {
					cow_write_request_t *cowWriteRequest = malloc( sizeof( cow_write_request_t ) );
					cowWriteRequest->inBlockOffset = inBlockPadStartOffset;
					cowWriteRequest->block = metaBlock;
					cowWriteRequest->size = (currentEndOffset)-padStartOffset;
					cowWriteRequest->buffer =
							cowRequest->writeBuffer + ( ( padStartOffset - offset ) * !cowRequest->replyAttr );
					padBlockFromRemote( req, padStartOffset, cowRequest, cowWriteRequest );


					sizeToWriteToBlock -= (currentEndOffset)-padStartOffset;
					endPaddedSize = (currentEndOffset)-padStartOffset;
				}
			}


			writeData( cowRequest->writeBuffer + ( ( currentOffset - offset ) * !cowRequest->replyAttr ),
					(ssize_t)sizeToWriteToBlock, sizeToWriteToBlock, cowRequest, metaBlock, inBlockOffset );

			cow_block_metadata_t *b = getBlock( l1Offset, l2Offset );
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
static void readRemote( fuse_req_t req, off_t offset, ssize_t size, char *buffer, cow_request_t *cowRequest )
{
	dnbd3_async_t *request = malloc( sizeof( dnbd3_async_t ) );
	request->buffer = buffer;
	request->length = (uint32_t)size;
	request->offset = offset;
	request->fuse_req = req;
	request->cow = cowRequest;
	request->cow_write = NULL;
	atomic_fetch_add( &cowRequest->workCounter, 1 );
	if ( !connection_read( request ) ) {
		atomic_fetch_sub( &cowRequest->workCounter, 1 );
		//TODO ChECK IF NOT  0  Now
		cowRequest->errorCode = EIO;
		free( request );
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

		if ( bitfieldOffset >= COW_BITFIELD_SIZE ) {
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
		searchOffset = DNBD3_BLOCK_SIZE * ( bitfieldOffset ) + l2Offset * COW_METADAT_STORAGE_CAPACITY
				+ l1Offset * COW_L2_STORAGE_CAPACITY;
		if ( doRead || searchOffset >= endOffset ) {
			ssize_t sizeToRead = MIN( searchOffset, endOffset ) - lastReadOffset;
			if ( !isLocal ) {
				readRemote(
						req, lastReadOffset, sizeToRead, cowRequest->readBuffer + ( lastReadOffset - offset ), cowRequest );
			} else {
				// Compute the offset in the .data file where the read starts
				off_t localRead =
						block->offset + ( ( lastReadOffset % COW_L2_STORAGE_CAPACITY ) % COW_METADAT_STORAGE_CAPACITY );
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
