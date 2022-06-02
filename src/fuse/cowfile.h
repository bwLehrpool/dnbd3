#ifndef _COWFILE_H_
#define _COWFILE_H_

#include "connection.h"
#include "main.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <dnbd3/shared/log.h>
#include <sys/mman.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <curl/curl.h>


#define COW_METADATA_STORAGE_CAPACITY ( COW_BITFIELD_SIZE * 8 * DNBD3_BLOCK_SIZE )
#define COW_L2_SIZE 1024
#define COW_L2_STORAGE_CAPACITY ( COW_L2_SIZE * COW_METADATA_STORAGE_CAPACITY )
#define container_of( ptr, type, member ) ( (type *)( (char *)( ptr ) - (char *)&( ( (type *)NULL )->member ) ) )


#define COW_METADATA_HEADER_SIZE 296
typedef struct __attribute__( ( packed ) ) cowfile_metadata_header
{
	uint64_t magicValue;            // 8byte
	atomic_uint_fast64_t imageSize; // 8byte
	int32_t version;                // 4byte
	int32_t blocksize;              // 4byte
	uint64_t originalImageSize;     // 8byte
	uint64_t metaDataStart;         // 8byte
	int32_t bitfieldSize;           // 4byte
	int32_t nextL2;                 // 4byte
	atomic_size_t metadataFileSize; // 8byte
	atomic_size_t dataFileSize;     // 8byte
	uint64_t maxImageSize;          // 8byte
	uint64_t creationTime;          // 8byte
	uuid_t uuid;                    // 16byte
	char imageName[200];            // 200byte
} cowfile_metadata_header_t;
_Static_assert(
		sizeof( cowfile_metadata_header_t ) == COW_METADATA_HEADER_SIZE, "cowfile_metadata_header is messed up" );

typedef struct cow_block_metadata
{
	atomic_long offset;
	atomic_uint_fast32_t timeChanged;
	atomic_uint_fast32_t timeUploaded;
	atomic_char bitfield[40];
} cow_block_metadata_t;

typedef struct cow_request
{
	size_t fuseRequestSize;
	off_t fuseRequestOffset;
	char *readBuffer;
	const char *writeBuffer;
	atomic_size_t bytesWorkedOn;
	atomic_int workCounter;
	atomic_int errorCode;
	bool replyAttr;
	fuse_ino_t ino;
	struct fuse_file_info *fi;
} cow_request_t;

typedef struct cow_sub_request cow_sub_request_t;
typedef void ( *cow_callback )( cow_sub_request_t *sRequest );

typedef struct cow_sub_request
{
	size_t size;
	off_t inBlockOffset;
	const char *buffer;
	cow_block_metadata_t *block;
	cow_callback callback;
	cow_request_t *cowRequest;
	dnbd3_async_t dRequest;

} cow_sub_request_t;

typedef struct cow_curl_read_upload
{
	cow_block_metadata_t *block;
	size_t position;
} cow_curl_read_upload_t;

typedef int32_t l1;
typedef cow_block_metadata_t l2[COW_L2_SIZE];

bool cowfile_init(
		char *path, const char *image_Name, uint16_t imageVersion, size_t **imageSizePtr, char *serverAdress );

bool cowfile_load( char *path, size_t **imageSizePtr, char *serverAdress );

void cowfile_read( fuse_req_t req, size_t size, off_t offset );

void cowfile_write( fuse_req_t req, cow_request_t *cowRequest, off_t offset, size_t size );

void cowfile_handleCallback( dnbd3_async_t *request );

int cow_printStats( char *buffer, const size_t len );

void cowfile_close();

#endif /* COWFILE_H_ */