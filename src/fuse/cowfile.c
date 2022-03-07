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
	cow_block_metadata_t **l1;
	l2 nextL2;
	atomic_size_t metadataFileSize;
	atomic_size_t dataFileSize;
	size_t maxImageSize;

	size_t l1Size; //size of l1 array
	int l2Size;    //size of an l2 array

	size_t metadataStorageCapacity;
	size_t l2StorageCapacity; // memory a l2 array can address
} cow;

static int getL1Offset( size_t offset )
{
	return (int)( offset / cow.l2StorageCapacity );
}

static int getL2Offset( size_t offset )
{
	return (int)( ( offset % cow.l2StorageCapacity ) / cow.metadataStorageCapacity );
}
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
	char mask =(char) (((255-from) >> (7-(to-from))));
	atomic_fetch_or(byte, (mask));
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
	cow.dataFileSize = 0;
	// create Meta Data Mapping
	int pageSize = getpagesize();
	int maxPageSize = 8192;

	// TODO IMAGE NAME IS FIXED
	size_t metaDataSizeHeader = sizeof( cowfile_metadata_header_t ) + strlen( image_Name );


	cow.maxImageSize = 1000LL * 1000LL * 1000LL * 1000LL; // tb*gb*mb*kb
	cow.l2Size = 1024;

	cow.metadataStorageCapacity = COW_BITFIELD_SIZE* DNBD3_BLOCK_SIZE;
	cow.l2StorageCapacity = ( cow.l2Size * cow.metadataStorageCapacity );

	cow.l1Size = ( ( cow.maxImageSize + cow.l2StorageCapacity - 1LL ) / cow.l2StorageCapacity );

	size_t metadata_size = cow.l1Size * sizeof( l1 ) + cow.l1Size * cow.l2Size * sizeof( l2 )
			+ cow.l1Size * cow.l2Size * ( sizeof( cow_block_metadata_t ) );


	//compute next fitting multiple of getpagesize()
	size_t meta_data_start = ( ( metaDataSizeHeader + maxPageSize - 1 ) / maxPageSize ) * maxPageSize;

	cow.metadataFileSize = meta_data_start + metadata_size;
	if ( pwrite( cow.fhm, "", 1, cow.metadataFileSize ) != 1 ) {
		logadd( LOG_ERROR, "Could not write cow meta_data_table to file. Bye.\n" );
		return false;
	}

	cow.metadata_mmap = mmap( NULL, cow.metadataFileSize, PROT_READ | PROT_WRITE, MAP_SHARED, cow.fhm, 0 );


	if ( cow.metadata_mmap == MAP_FAILED ) {
		logadd( LOG_ERROR, "Error while mapping mmap. Bye.\n" );
		return false;
	}


	size_t *metaDataHeaderSizePtr = (size_t *)cow.metadata_mmap;
	*metaDataHeaderSizePtr = metaDataSizeHeader;
	metadata = (cowfile_metadata_header_t *)( cow.metadata_mmap + sizeof( size_t ) );
	metadata->version = cowFileVersion;
	metadata->blocksize = pageSize;
	metadata->originalImageSize = **imageSizePtr;
	metadata->imageSize = metadata->originalImageSize;
	*imageSizePtr = &metadata->imageSize;

	metadata->metaDataStart = meta_data_start;


	metadata->bitfieldSize = COW_BITFIELD_SIZE;
	metadata->maxImageSize = cow.maxImageSize;
	strcpy( metadata->imageName, image_Name );
	cow.l1 = (cow_block_metadata_t **)( cow.metadata_mmap + meta_data_start );


	for ( size_t i = 0; i < cow.l1Size; i++ ) {
		cow.l1[i] = NULL;
	}
	cow.nextL2 = (l2)( cow.l1 + cow.l1Size );
	pthread_mutex_init( &cow.l2CreateLock, NULL );
	return 1;
}

bool cowfile_load( char *path )
{
	if ( ( cow.fhm = open( strcat( path, ".meta" ), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not open cow meta file. Bye.\n" );
		return false;
	}
	if ( ( cow.fhd = open( strcat( path, ".data" ), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR ) ) == -1 ) {
		logadd( LOG_ERROR, "Could not open cow data file. Bye.\n" );
		return false;
	}
	size_t metaDataSizeHeader;
	ssize_t bytesRead = read( cow.fhm, &metaDataSizeHeader, sizeof( size_t ) );
	if ( bytesRead < (ssize_t)sizeof( size_t ) ) {
		if ( bytesRead < 0 ) {
			logadd( LOG_ERROR, "Error while reading metaDataSizeHeader: " );
		} else {
			logadd( LOG_ERROR, "metaDataSizeHeader smaller than expected. Bye.\n" );
		}
		return false;
	}
	cowfile_metadata_header_t *metadata = malloc( metaDataSizeHeader );
	bytesRead = read( cow.fhm, metadata, metaDataSizeHeader );
	if ( bytesRead < (ssize_t)sizeof( size_t ) ) {
		if ( bytesRead < 0 ) {
			logadd( LOG_ERROR, "Error while reading metadata. Bye.\n" );
		} else {
			logadd( LOG_ERROR, "metadata smaller than expected. Bye.\n" );
		}
		return false;
	}
	logadd( LOG_DEBUG1, "===Image Name===: %s\n", metadata->imageName );

	return true;
}

static void writeData( const char *buffer, size_t size, size_t netSize, cow_request_t *cowRequest, cow_block_metadata_t *block,
		off_t inBlockOffset )
{
	ssize_t bytesWritten = pwrite( cow.fhd, buffer, size, block->offset + inBlockOffset );

	if ( bytesWritten == -1 ) {
		cowRequest->errorCode = errno;
	} else if ( (size_t)bytesWritten < size ) {
		cowRequest->errorCode = EIO;
	}
	atomic_fetch_add( &cowRequest->bytesWorkedOn, netSize );
	setBitsInBitfield(
			block->bitfield, (int)( inBlockOffset / DNBD3_BLOCK_SIZE ), (int)( ( inBlockOffset + size ) / DNBD3_BLOCK_SIZE ) );
	block->timeChanged = (atomic_uint_fast32_t)time( NULL );
}


static bool createL2Block( int l1Offset )
{
	pthread_mutex_lock( &cow.l2CreateLock );
	if ( cow.l1[l1Offset] == NULL ) {
		for ( int i = 0; i < cow.l2Size; i++ ) {
			cow.nextL2[i].offset = -1;
			cow.nextL2[i].timeChanged = 0;
			cow.nextL2[i].timeUploaded = 0;
			for (int j = 0; j < COW_BITFIELD_SIZE; j++){
				cow.nextL2[i].bitfield[j] = ATOMIC_VAR_INIT( 0 );
			}
		}
		cow.l1[l1Offset] = cow.nextL2;
		cow.nextL2 += cow.l2Size;
	}
	pthread_mutex_unlock( &cow.l2CreateLock );
	return true;
}

static bool allocateMetaBlockData( cow_block_metadata_t *block )
{
	block->offset = (atomic_long)atomic_fetch_add( &cow.dataFileSize, cow.metadataStorageCapacity );
	return true;
}


// TODO if > remote pad 0
/**
 * @brief 
 * 
 */
static void padBlockFromRemote( fuse_req_t req, off_t offset, cow_request_t *cowRequest, cow_write_request_t *cowWriteRequest )
{
	if ( offset > (off_t)metadata->originalImageSize ) {
		//pad 0 and done
		char buffer[DNBD3_BLOCK_SIZE] = { 0 };
		memcpy( buffer, cowWriteRequest->buffer, cowWriteRequest->size );

		writeData(
				buffer, DNBD3_BLOCK_SIZE, cowWriteRequest->size, cowRequest, cowWriteRequest->block, cowWriteRequest->inBlockOffset );
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


void cowfile_writePaddedBlock( dnbd3_async_t *request )
{
	//copy write Data
	memcpy( request->buffer + ( request->cow_write->inBlockOffset % DNBD3_BLOCK_SIZE ), request->cow_write->buffer,
			request->cow_write->size );
	writeData( request->buffer, DNBD3_BLOCK_SIZE, request->cow_write->size, request->cow, request->cow_write->block,
			request->cow_write->inBlockOffset );

	free( request->cow_write );
	if ( atomic_fetch_sub( &request->cow->workCounter, 1 ) == 1 ) {
		finishWriteRequest( request->fuse_req, request->cow );
	}
	free( request->buffer );
	free( request );
}

/// TODO move block padding in write
void cowfile_write( fuse_req_t req, cow_request_t *cowRequest, off_t offset, size_t size )
{
	if ( cowRequest->replyAttr ) {
		cowRequest->writeBuffer = calloc( sizeof( char ), MIN( size, cow.metadataStorageCapacity ) );
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

	// TODO PREVENT RACE CONDITION on not full block writes

	off_t currentOffset = offset;
	off_t endOffset = offset + size;
	// get start & end block if needed( not on border and not already there)
	if ( offset % DNBD3_BLOCK_SIZE != 0 ) {
		int l1Offset = getL1Offset( offset );
		int l2Offset = getL2Offset( offset );
		if ( cow.l1[l1Offset] == NULL ) {
			createL2Block( l1Offset );
		}
		cow_block_metadata_t *metaBlock = &( cow.l1[l1Offset] )[l2Offset];
		size_t metaBlockStartOffset = l1Offset * cow.l2StorageCapacity + l2Offset * cow.metadataStorageCapacity;
		size_t inBlockOffset = offset - metaBlockStartOffset;


		if ( !checkBit( metaBlock->bitfield, (int)( inBlockOffset / DNBD3_BLOCK_SIZE ) ) ) {
			size_t padSize = MIN( size, DNBD3_BLOCK_SIZE - ( (size_t)offset % DNBD3_BLOCK_SIZE ) );
			cow_write_request_t *cowWriteRequest = malloc( sizeof( cow_write_request_t ) );
			cowWriteRequest->inBlockOffset = (off_t)inBlockOffset;
			cowWriteRequest->block = metaBlock;
			cowWriteRequest->size = padSize;
			cowWriteRequest->buffer = cowRequest->writeBuffer;
			padBlockFromRemote( req, offset, cowRequest, cowWriteRequest );
			currentOffset += padSize;
		}
	}
	// also make sure endblock != start block
	if ( offset + size % DNBD3_BLOCK_SIZE != 0 && ( ( offset + (off_t)size ) / DNBD3_BLOCK_SIZE ) != ( offset / DNBD3_BLOCK_SIZE ) ) {
		int l1Offset = getL1Offset( offset + size );
		int l2Offset = getL2Offset( offset + size );
		if ( cow.l1[l1Offset] == NULL ) {
			createL2Block( l1Offset );
		}
		cow_block_metadata_t *metaBlock = &( cow.l1[l1Offset] )[l2Offset];
		if ( metaBlock->offset == -1 ) {
			allocateMetaBlockData( metaBlock );
		}
		size_t metaBlockStartOffset = l1Offset * cow.l2StorageCapacity + l2Offset * cow.metadataStorageCapacity;
		size_t padOffset = endOffset - ( endOffset % DNBD3_BLOCK_SIZE );
		size_t inBlockOffset = padOffset - metaBlockStartOffset;


		if ( !checkBit( metaBlock->bitfield, (int)( inBlockOffset / DNBD3_BLOCK_SIZE ) ) ) {
			cow_write_request_t *cowWriteRequest = malloc( sizeof( cow_write_request_t ) );
			cowWriteRequest->inBlockOffset = (off_t)inBlockOffset;
			cowWriteRequest->block = metaBlock;
			cowWriteRequest->size = endOffset - padOffset;
			cowWriteRequest->buffer = cowRequest->writeBuffer + ( padOffset - offset );
			padBlockFromRemote( req, padOffset, cowRequest, cowWriteRequest );

			endOffset = padOffset; //TODO written size
		}
	}

	// lock for have block probably needed

	// write data

	int l1Offset = getL1Offset( currentOffset );
	int l2Offset = getL2Offset( currentOffset );
	while ( currentOffset < endOffset ) {
		if ( cow.l1[l1Offset] == NULL ) {
			createL2Block( l1Offset );
		}
		//loop over L2 array (metadata)
		while ( currentOffset < (off_t)endOffset && l2Offset < cow.l2Size ) {
			cow_block_metadata_t *metaBlock = &( cow.l1[l1Offset] )[l2Offset];
			if ( metaBlock->offset == -1 ) {
				allocateMetaBlockData( metaBlock );
			}
			size_t metaBlockStartOffset = l1Offset * cow.l2StorageCapacity + l2Offset * cow.metadataStorageCapacity;

			size_t inBlockOffset = currentOffset - metaBlockStartOffset;
			size_t sizeToWriteToBlock =
					MIN( (size_t)( endOffset - currentOffset ), cow.metadataStorageCapacity - inBlockOffset );

			writeData( cowRequest->writeBuffer + ( ( currentOffset - offset ) * !cowRequest->replyAttr ),
					sizeToWriteToBlock, sizeToWriteToBlock, cowRequest, metaBlock, inBlockOffset );


			currentOffset += sizeToWriteToBlock;
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
static void readRemote( fuse_req_t req, off_t offset, size_t size, char *buffer, cow_request_t *cowRequest )
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
	int l1Offset = getL1Offset( offset );
	int l2Offset = getL2Offset( offset );
	int bitfieldOffset = getBitfieldOffset( offset );
	bool isLocal;
	cow_block_metadata_t *block = NULL;
	;
	if ( cow.l1[l1Offset] != NULL ) {
		block = &( cow.l1[l1Offset] )[l2Offset];
	}

	bool doRead = false;
	bool firstLoop = true;
	bool updateBlock = false;
	while ( searchOffset < endOffset ) {
		if ( firstLoop ) {
			firstLoop = false;
			lastReadOffset = searchOffset;
			isLocal = block != NULL && checkBit( block->bitfield, bitfieldOffset );
		} else if ( ( block != NULL && checkBit( block->bitfield, bitfieldOffset ) ) != isLocal ) {
			doRead = true;
		}

		bitfieldOffset++;
		if ( bitfieldOffset >= COW_BITFIELD_SIZE ) {
			bitfieldOffset = 0;
			l2Offset++;
			if ( l2Offset >= cow.l2Size ) {
				l2Offset = 0;
				l1Offset++;
			}
			updateBlock = true;
			doRead = true;
		}

		searchOffset =
				DNBD3_BLOCK_SIZE * ( bitfieldOffset ) + l2Offset * cow.metadataStorageCapacity + l1Offset * cow.l2StorageCapacity;
		if ( doRead || searchOffset >= endOffset ) {
			size_t sizeToRead = MIN( searchOffset, endOffset ) - lastReadOffset;
			if ( !isLocal ) {
				readRemote(
						req, lastReadOffset, sizeToRead, cowRequest->readBuffer + ( lastReadOffset - offset ), cowRequest );
			} else {
				off_t localRead = block->offset + DNBD3_BLOCK_SIZE * bitfieldOffset + lastReadOffset % DNBD3_BLOCK_SIZE;
				ssize_t bytesRead =
						pread( cow.fhd, cowRequest->readBuffer + ( lastReadOffset - offset ), sizeToRead, localRead );
				if ( bytesRead == -1 ) {
					cowRequest->errorCode = errno;
				} else if ( bytesRead < (ssize_t)sizeToRead ) {
					cowRequest->errorCode = EIO;
				}
				atomic_fetch_add( &cowRequest->bytesWorkedOn, bytesRead );
			}
			lastReadOffset = searchOffset;
			doRead = false;
			firstLoop = true;
		}

		if ( updateBlock ) {
			if ( cow.l1[l1Offset] != NULL ) {
				block = &( cow.l1[l1Offset] )[l2Offset];
			} else {
				block = NULL;
			}
			updateBlock = false;
		}
	}

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
