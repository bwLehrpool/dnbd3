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

#define min( X, Y ) ( ( ( X ) < ( Y ) ) ? ( X ) : ( Y ) )
#define max( X, Y ) ( ( ( X ) > ( Y ) ) ? ( X ) : ( Y ) )

typedef struct cowfile_metadata_Header
{
	int version;
	int blocksize;
	size_t originalImageSize;
	size_t ImageSize;
	size_t meta_data_start;
	int bitfieldSize;
	size_t maxImageSize;
	char imageName[200];
} cowfile_metadata_Header;

typedef struct cow_block_metadata
{
	atomic_long offset;
	atomic_uint_fast32_t time_changed;
	atomic_uint_fast32_t time_uploaded;
	atomic_char bitfield[40];
} cow_block_metadata;


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
} cow_request;

typedef struct cow_write_request
{
	const char* buffer;
	size_t size;
	off_t inBlockOffset;
	cow_block_metadata * block;

} cow_write_request;


typedef cow_block_metadata** l1;
typedef cow_block_metadata* l2;

bool cowfile_init( char *path, const char *image_Name, size_t ** imageSizePtr );
bool cowfile_load( char *path );
void cowfile_read(fuse_req_t req,  size_t size, off_t offset);
void cowfile_write( fuse_req_t req, cow_request* cowRequest, off_t offset, size_t size);

size_t cowfile_append( char *buffer, uint64_t offset, uint64_t size );

#endif /* COWFILE_H_ */