#ifndef _COW_CONFIG_H_
#define _COW_CONFIG_H_

// +++++ COW +++++
#define COW_BITFIELD_SIZE 40 // NEVER CHANGE THIS OR THE WORLD WILL ALSO END!
#define COW_FILE_META_MAGIC_VALUE ((uint64_t)0xEBE44D6E72F7825E) // Magic Value to recognize a Cow meta file
#define COW_FILE_DATA_MAGIC_VALUE ((uint64_t)0xEBE44D6E72F7825F) // Magic Value to recognize a Cow data file
#define COW_MIN_UPLOAD_DELAY 60 // in seconds
#define COW_STATS_UPDATE_TIME 5 // time in seconds the cow status files gets updated (while uploading blocks)
#define COW_MAX_PARALLEL_UPLOADS 10 // maximum number of parallel uploads
#define COW_MAX_PARALLEL_BACKGROUND_UPLOADS 2 // maximum number of parallel uploads while the image is still mounted
#define COW_URL_STRING_SIZE 500 // Max string size for an url
#define COW_SHOW_UL_SPEED 1 // enable display of ul speed in cow status file
#define COW_MAX_IMAGE_SIZE (1000LL * 1000LL * 1000LL * 1000LL) // Maximum size an image can have(tb*gb*mb*kb)
// +++++ COW API Endpoints +++++
#define COW_API_CREATE "%s/api/file/create"
#define COW_API_UPDATE "%s/api/file/update?guid=%s&clusterindex=%lu"
#define COW_API_START_MERGE "%s/api/file/merge"

#endif
