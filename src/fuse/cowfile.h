#ifndef _COWFILE_H_
#define _COWFILE_H_

#include "connection.h"

#include <dnbd3/config/cow.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>

// Net storage capacity of a single cluster in the data file
#define COW_DATA_CLUSTER_SIZE ( COW_BITFIELD_SIZE * 8 * DNBD3_BLOCK_SIZE )
// Number of entries per L2 table
#define COW_L2_TABLE_SIZE 1024
// Net storage capacity in data file represented by a full L2 table
#define COW_FULL_L2_TABLE_DATA_SIZE ( COW_L2_TABLE_SIZE * COW_DATA_CLUSTER_SIZE )

_Static_assert( ATOMIC_INT_LOCK_FREE == 2, "ATOMIC INT not lock free" );
_Static_assert( ATOMIC_LONG_LOCK_FREE == 2, "ATOMIC LONG not lock free" );
_Static_assert( ATOMIC_LLONG_LOCK_FREE == 2, "ATOMIC LLONG not lock free" );
_Static_assert( sizeof( atomic_uint_least64_t ) == 8, "atomic_uint_least64_t not 8 byte" );
_Static_assert( sizeof( _Atomic(uint32_t) ) == 4, "_Atomic(uint32_t) not 4 byte" );
_Static_assert( sizeof( atomic_int_least64_t ) == 8, "atomic_int_least64_t not 8 byte" );

enum dataSource
{
	ds_invalid,
	ds_local,
	ds_remote,
	ds_zero
};

#define COW_METADATA_HEADER_SIZE 320
typedef struct cowfile_metadata_header
{
	uint64_t magicValue;                    // 8byte
	atomic_uint_least64_t imageSize;        // 8byte
	int32_t version;                        // 4byte
	int32_t blocksize;                      // 4byte
	uint64_t validRemoteSize;               // 8byte
	uint32_t startL1;                       // 4byte
	uint32_t startL2;                       // 4byte
	int32_t bitfieldSize;                   // 4byte
	int32_t nextL2;                         // 4byte
	atomic_int_least64_t metaSize;          // 8byte
	atomic_int_least64_t nextClusterOffset; // 8byte
	uint64_t maxImageSize;                  // 8byte
	uint64_t creationTime;                  // 8byte
	char uuid[40];                          // 40byte
	char imageName[200];                    // 200byte
} cowfile_metadata_header_t;
_Static_assert( sizeof( cowfile_metadata_header_t ) == COW_METADATA_HEADER_SIZE,
		"cowfile_metadata_header is messed up" );

#define COW_L2_ENTRY_SIZE 64
typedef struct cow_l2_entry
{
	atomic_int_least64_t offset;
	atomic_int_least64_t timeChanged;
	_Atomic(uint32_t) uploads;
	_Atomic(uint32_t) fails;
	atomic_uchar bitfield[COW_BITFIELD_SIZE];
} cow_l2_entry_t;
_Static_assert( sizeof( cow_l2_entry_t ) == COW_L2_ENTRY_SIZE, "cow_l2_entry_t is messed up" );

/**
 * Open request for reading/writing the virtual image we expose.
 */
typedef struct cow_request
{
	size_t fuseRequestSize; // Number of bytes to be read/written
	off_t fuseRequestOffset; // Absolute offset into the image, as seen by user space
	char *readBuffer; // Used only in read case
	const char *writeBuffer; // Used only in write case
	atomic_size_t bytesWorkedOn; // Used for tracking how many bytes we have touched (exluding padding etc)
	atomic_int workCounter; // How many pending sub requests (see below)
	atomic_int errorCode; // For reporting back to fuse
	fuse_ino_t ino; // Inode of file, used for ??? (For reporting back to fuse, dont know if needed?)
	struct fuse_file_info *fi; // Used for ??? (For reporting back to fuse, dont know if needed?)
	//fuse_req_t req; // Fuse request
} cow_request_t;

typedef struct cow_sub_request cow_sub_request_t;
typedef void ( *cow_callback )( cow_sub_request_t *sRequest );

/**
 * A sub-request for above, which needs to be completed successfully
 * before the parent cow_request can be completed.
 * TODO Please verify field comments
 */
typedef struct cow_sub_request
{
	size_t size; // size of this sub-request
	off_t inClusterOffset; // offset relative to the beginning of the cluster
	const char *writeSrc; // pointer to the data of a write request which needs padding
	char *buffer; // The pointer points to the original read buffer to the place where the sub read request should be copied to.
	cow_l2_entry_t *cluster; // the cluster inClusterOffset refers to
	cow_callback callback; // Callback when we're done handling this
	cow_request_t *cowRequest; // parent request
	dnbd3_async_t dRequest; // Probably request to dnbd3-server for non-aligned writes (wrt 4k dnbd3 block)
	char writeBuffer[]; // buffer for a padding write request, gets filled from a remote read, then the writeSrc data gets copied into it.
} cow_sub_request_t;

typedef struct cow_curl_read_upload
{
	atomic_uint_least64_t time;
	cow_l2_entry_t *cluster;
	size_t position;
	long unsigned int clusterNumber;
	int64_t ulLast;
	atomic_uchar bitfield[COW_BITFIELD_SIZE];
} cow_curl_read_upload_t;


typedef struct cow_cluster_statistics
{
	uint64_t clusterNumber;
	uint64_t uploads;
} cow_cluster_statistics_t;

typedef int32_t l1;
typedef cow_l2_entry_t l2[COW_L2_TABLE_SIZE];

bool cowfile_init( char *path, const char *image_Name, uint16_t imageVersion, atomic_uint_fast64_t **imageSizePtr,
		char *serverAddress, bool sStdout, bool sFile, const char *cowUuid );

bool cowfile_load( char *path, atomic_uint_fast64_t **imageSizePtr, char *serverAddress, bool sStdout, bool sFile, const char *cowUuid );
bool cowfile_startBackgroundThreads();
void cowfile_read( fuse_req_t req, size_t size, off_t offset );

void cowfile_write( fuse_req_t req, cow_request_t *cowRequest, off_t offset, size_t size );

void cowfile_handleCallback( dnbd3_async_t *request );

void cowfile_setSize( fuse_req_t req, size_t size, fuse_ino_t ino, struct fuse_file_info *fi );

void readRemoteData( cow_sub_request_t *sRequest );

int cow_printStats( char *buffer, const size_t len );

void cowfile_close();

#endif /* COWFILE_H_ */
