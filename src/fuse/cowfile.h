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
#include "main.h"


#define COW_METADATA_HEADER_SIZE 244
typedef struct __attribute__((packed)) cowfile_metadata_header
{
	uint64_t imageSize;			// 8byte
	int32_t version;			// 4byte
	int32_t blocksize;			// 4byte
	uint64_t originalImageSize; // 8byte
	uint64_t metaDataStart;		// 8byte
	int32_t bitfieldSize;		// 4byte
	uint64_t maxImageSize;		// 8byte
	char imageName[200];		// 200byte
} cowfile_metadata_header_t;	// 244byte
_Static_assert( sizeof(cowfile_metadata_header_t) == COW_METADATA_HEADER_SIZE, "cowfile_metadata_header is messed up" );

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
	char* readBuffer;
	const char* writeBuffer;
	atomic_size_t bytesWorkedOn;
	atomic_int workCounter;
	atomic_int errorCode;
	bool replyAttr;
	fuse_ino_t ino;
	struct fuse_file_info *fi;
} cow_request_t;

typedef struct cow_write_request
{
	const char* buffer;
	size_t size;
	off_t inBlockOffset;
	cow_block_metadata_t * block;

} cow_write_request_t;


typedef cow_block_metadata_t** l1;
typedef cow_block_metadata_t* l2;

bool cowfile_init( char *path, const char *image_Name, size_t ** imageSizePtr );
bool cowfile_load( char *path );
void cowfile_read(fuse_req_t req,  size_t size, off_t offset);
void cowfile_write( fuse_req_t req, cow_request_t* cowRequest, off_t offset, size_t size);

size_t cowfile_append( char *buffer, uint64_t offset, uint64_t size );

#endif /* COWFILE_H_ */