#ifndef _COWFILE_H_
#define _COWFILE_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <dnbd3/shared/log.h>
#include <sys/mman.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <curl/curl.h>
#include "main.h"
#include "connection.h"


#define COW_METADATA_STORAGE_CAPACITY ( COW_BITFIELD_SIZE * 8 * DNBD3_BLOCK_SIZE )
#define COW_L2_SIZE 1024
#define COW_L2_STORAGE_CAPACITY ( COW_L2_SIZE * COW_METADATA_STORAGE_CAPACITY )
#define container_of( ptr, type, member ) ( (type *)( (char *)( ptr ) - (char *)&( ( (type *)NULL )->member ) ) )

_Static_assert( ATOMIC_INT_LOCK_FREE == 2, "ATOMIC INT not lock free" );
_Static_assert( ATOMIC_LONG_LOCK_FREE == 2, "ATOMIC LONG not lock free" );
_Static_assert( ATOMIC_LLONG_LOCK_FREE == 2, "ATOMIC LLONG not lock free" );
_Static_assert( sizeof( atomic_uint_least64_t ) == 8, "atomic_uint_least64_t not 8 byte" );
_Static_assert( sizeof( atomic_int_least64_t ) == 8, "atomic_int_least64_t not 8 byte" );

#define COW_METADATA_HEADER_SIZE 320
typedef struct cowfile_metadata_header
{
	uint64_t magicValue;                    // 8byte
	atomic_uint_least64_t imageSize;        // 8byte
	int32_t version;                        // 4byte
	int32_t blocksize;                      // 4byte
	uint64_t originalImageSize;             // 8byte
	uint64_t metaDataStart;                 // 8byte
	int32_t bitfieldSize;                   // 4byte
	int32_t nextL2;                         // 4byte
	atomic_uint_least64_t metadataFileSize; // 8byte
	atomic_uint_least64_t dataFileSize;     // 8byte
	uint64_t maxImageSize;                  // 8byte
	uint64_t creationTime;                  // 8byte
	char uuid[40];                          // 40byte
	char imageName[200];                    // 200byte
} cowfile_metadata_header_t;
_Static_assert(
		sizeof( cowfile_metadata_header_t ) == COW_METADATA_HEADER_SIZE, "cowfile_metadata_header is messed up" );

#define COW_METADATA_METADATA_SIZE 64
typedef struct cow_block_metadata
{
	atomic_int_least64_t offset;
	atomic_uint_least64_t timeChanged;
	atomic_uint_least64_t uploads;
	atomic_char bitfield[40];
} cow_block_metadata_t;
_Static_assert( sizeof( cow_block_metadata_t ) == COW_METADATA_METADATA_SIZE, "cow_block_metadata_t is messed up" );


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
	const char *writeSrc;
	char *buffer;
	cow_block_metadata_t *block;
	cow_callback callback;
	cow_request_t *cowRequest;
	dnbd3_async_t dRequest;
	char writeBuffer[];
} cow_sub_request_t;

typedef struct cow_curl_read_upload
{
	atomic_uint_least64_t time;
	cow_block_metadata_t *block;
	size_t position;
	long unsigned int blocknumber;
	int fails;
	curl_off_t ulLast;
} cow_curl_read_upload_t;


typedef struct cow_block_upload_statistics
{
	uint64_t blocknumber;
	uint64_t uploads;
} cow_block_upload_statistics_t;


typedef int32_t l1;
typedef cow_block_metadata_t l2[COW_L2_SIZE];

bool cowfile_init( char *path, const char *image_Name, uint16_t imageVersion, atomic_uint_fast64_t **imageSizePtr,
		char *serverAddress, bool sStdout, bool sFile );

bool cowfile_load( char *path, atomic_uint_fast64_t **imageSizePtr, char *serverAddress, bool sStdout, bool sFile );

void cowfile_read( fuse_req_t req, size_t size, off_t offset );

void cowfile_write( fuse_req_t req, cow_request_t *cowRequest, off_t offset, size_t size );

void cowfile_handleCallback( dnbd3_async_t *request );

void readRemoteData( cow_sub_request_t *sRequest );

int cow_printStats( char *buffer, const size_t len );

void cowfile_close();

#endif /* COWFILE_H_ */