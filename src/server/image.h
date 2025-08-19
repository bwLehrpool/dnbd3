#ifndef _IMAGE_H_
#define _IMAGE_H_

#include "globals.h"

struct json_t;

void image_serverStartup();

bool image_isComplete(dnbd3_image_t *image);

bool image_isHashBlockComplete(dnbd3_cache_map_t * const cache, const uint64_t block, const uint64_t fileSize);

void image_updateCachemap(dnbd3_image_t *image, uint64_t start, uint64_t end, const bool set);

void image_markComplete(dnbd3_image_t *image);

bool image_ensureOpen(dnbd3_image_t *image);

dnbd3_image_t* image_byId(int imgId);

dnbd3_image_t* image_getByWwn(uint64_t wwn, uint16_t revision, bool ensureFdOpen);

dnbd3_image_t* image_get(const char *name, uint16_t revision, bool checkIfWorking);

bool image_reopenCacheFd(dnbd3_image_t *image, const bool force);

dnbd3_image_t* image_getOrLoad(char *name, uint16_t revision);

dnbd3_image_t* image_lock(dnbd3_image_t *image);

dnbd3_image_t* image_release(dnbd3_image_t *image);

bool image_checkBlocksCrc32(int fd, uint32_t *crc32list, const int *blocks, const uint64_t fileSize);

void image_killUplinks();

bool image_loadAll(char *path);

bool image_tryFreeAll();

bool image_create(char *image, int revision, uint64_t size);

bool image_generateCrcFile(char *image);

struct json_t* image_getListAsJson();

int image_getCompletenessEstimate(dnbd3_image_t * const image);

void image_closeUnusedFd();

bool image_ensureDiskSpaceLocked(uint64_t size, bool force);

bool image_saveCacheMap(dnbd3_image_t *image);

void image_checkForNextFullCheck(void);

void image_hashAllImages(void);

/**
 * Check if given range is cached. Be careful when using this function because:
 * 1) you need to hold a reference to the cache map
 * 2) start and end are assumed to be 4k aligned
 * 3) start and end are not checked to be in bounds (we don't know the image in this context)
 */
static inline bool image_isRangeCachedUnsafe(dnbd3_cache_map_t *cache, uint64_t start, uint64_t end)
{
	const uint64_t firstByteInMap = start >> 15;
	const uint64_t lastByteInMap = (end - 1) >> 15;
	const uint8_t fb = (uint8_t)(0xff << ((start >> 12) & 7));
	const uint8_t lb = (uint8_t)(~(0xff << ((((end - 1) >> 12) & 7) + 1)));
	uint64_t pos;
	uint8_t b;
	bool isCached;
	if ( firstByteInMap == lastByteInMap ) { // Single byte to check, much simpler
		b = cache->map[firstByteInMap];
		isCached = ( b & ( fb & lb ) ) == ( fb & lb );
	} else {
		isCached = true;
		atomic_thread_fence( memory_order_acquire );
		// First byte
		if ( isCached ) {
			b = atomic_load_explicit( &cache->map[firstByteInMap], memory_order_relaxed );
			isCached = ( ( b & fb ) == fb );
		}
		// Last byte
		if ( isCached ) {
			b = atomic_load_explicit( &cache->map[lastByteInMap], memory_order_relaxed );
			isCached = ( ( b & lb ) == lb );
		}
		// Middle, must be all bits set (0xff)
		if ( isCached ) {
			for ( pos = firstByteInMap + 1; pos < lastByteInMap; ++pos ) {
				if ( atomic_load_explicit( &cache->map[pos], memory_order_relaxed ) != 0xff ) {
					isCached = false;
					break;
				}
			}
		}
	}
	return isCached;
}

// one byte in the map covers 8 4kib blocks, so 32kib per byte
// "+ (1 << 15) - 1" is required to account for the last bit of
// the image that is smaller than 32kib
// this would be the case whenever the image file size is not a
// multiple of 32kib (= the number of blocks is not divisible by 8)
// ie: if the image is 49152 bytes and you do 49152 >> 15 you get 1,
// but you actually need 2 bytes to have a complete cache map
#define IMGSIZE_TO_MAPBYTES(bytes) ((int)(((bytes) + (1 << 15) - 1) >> 15))

// calculate number of hash blocks in file. One hash block is 16MiB
#define HASH_BLOCK_SIZE ((int64_t)(1 << 24))
#define IMGSIZE_TO_HASHBLOCKS(bytes) ((int)(((bytes) + HASH_BLOCK_SIZE - 1) / HASH_BLOCK_SIZE))

#endif
