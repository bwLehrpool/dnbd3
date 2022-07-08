
# Fuse Copy on Write (CoW)

### Table of Contents
1. [Introduction](#introduction)
2. [Usage](#usage)
3. [Implementation Details](#implementation-details)
4. [REST Api](#rest-api)


# Introduction

This extension to the fuse dnbd3 client allows images to be mounted writable. The changes are saved in a separate file (also called Copy on Write, cow for short) on the client computer. These changes are uploaded to the cow server in the background. Once the user unmounts the image, any remaining changes are uploaded. As soon as all changes have been uploaded, the changes can be merged into a copy of the original image on the cow server (this can be set in the start parameters).

A typical use case is updating or adding software to an existing image.

# Usage

### New Parameters
- `-c <path>` Enables the cow functionality, the argument sets the path for the temporary `meta` and `data` file in which the writes are stored.
- `-C <address>` sets the address of the cow server. The cow server is responsible for merging the original image with the changes from the client.
- `-L <path>` Similar to `-c <path>` but instead of creating a new session, it loads an existing from the given path.
- `-m` if set, the client will request a merge after the image is unmounted and all change are uploaded.

- `cowStatFile` creates a status file at the same location as the data and meta file. The file contains information about the current session, for more information see [here](#status).
- `--cowStatStdout` similar to `--cowStatFile` but the information will be printed in the stdout.

Example parameters for creating a new cow session:
```
./dnbd3-fuse "/home/user/VMs/mount" -f -h localhost -i imagename -c "/home/user/temp" -C "192.168.178.20:5000" --cowStatStdout -m

```

# Implementation Details





## Data structure

The data structure is split in two main parts. The actual data from the write on the image and its corresponding metadata. Its also important to distinguish between a dnbd3 block which is 4096byte and and cow block which groups 320 dnbd3 blocks together. An cow block has an `cow_block_metadata_t` struct which holds the corresponding meta data.  The metadata is used to determine if and block has been written on, where this block is stored in the data file, when it was last modified and when it was uploaded. But more later. 


### Blockmetadata

![Datastructure](img/datastructure.jpg)

The data structure for storing metadata cow blocks contains a Layer 1(L1) and a Layer 2 (L2). L1 contains pointers to the L2's.
The whole L1 array is initialized at the beginning and cannot be resized, so the size of the L1 array limits the total size of the image.
The L2's are dynamically created once needed. So at the beginning, all L1 pointers will be null. The L2's are arrays which contain 1024 
`cow_block_metadata_t` structs.

```C
typedef struct cow_block_metadata
{
	atomic_int_least64_t offset;
	atomic_uint_least64_t timeChanged;
	atomic_uint_least64_t uploads;
	atomic_char bitfield[40];
} cow_block_metadata_t;
```
Each `cow_block_metadata_t` contains a 40 byte so 320 bit bit field. The bit field indicates whether the corresponding dnbd3 block contains data or not. For e.g. if the bit field starts with 01.., the first 4096 contains not data and the next 4096 contain data.
So each `cow_block_metadata_t` stores the metadata  of up to 320*4096 byte if all bits are set to 1. The offset is the offset where in the data file is the corresponding data stored. The timeChanged property contains the unix when the block was last modified. It's 0 if it was never modified or if the last changes are already uploaded.


The L2 arrays and `cow_block_metadata_t` are sorted to original Offsets. So the first L1 pointer, thus the first L2 array, addresses the first 1024 * 320 * 4096 Bytes (L2Size * bitfieldsize * DNBD3Blocksize) of Data and so on.


So for example, to get the `cow_block_metadata_t` for offset 4033085440 you would take L1[3] since 
```
4033085440 / ( COW_L2_STORAGE_CAPACITY ) ≈ 3.005
```

 Then you would take the fifth `cow_block_metadata_t` in the L2 array because of 
```
(4033085440 mod COW_L2_STORAGE_CAPACITY) / COW_METADATA_STORAGE_CAPACITY = 5
```
Where:
```
COW_L2_STORAGE_CAPACITY = 1024 * 320 * 4096 
COW_METADATA_STORAGE_CAPACITY = 320 * 4096 
```


 
### Read Request



For an read request, for every 4096byte block it will be checked if the block is already locally on the computer (therefore was already written before). If so it will be read from disk, otherwise it will be requested from the dnbd3 server. To increase performance, multiple following blocks that are also local/non local like the block before will be combined to to one larger reads from disc respectively one larger request from the server.

![readrequest](img/readrequest.svg)

The graph shown above is somewhat simplified for better visibility. The reads from the server happen async. So it will not be waiting for the server to respond, rather the it will move on with the next blocks. As soon as the respond from the server is finished, the data will be written in 
the fuse buffer. Each request to the dnbd3 server will increase the `workCounter` variable by one and every time a request is done it will be decreased by one. Once `workCounter` is 0 again, fuse_request will be returned. 

Also on the local side, it has to break the loop once the end of an `cow_block_metadata_t` is reached, since the next data offset of the next `cow_block_metadata_t` is very likely not directly after it in the data file.

### Write Request
For the write request, if the start or the end or the end does not align with a multiple of 4096, then the start and/or end block must be padded.
Because every 4096byte block needs complete data, since if the bit in the bit field for that block is set, all the data will be read locally.
To pad the block, if it's still in the range of the original image size, the missing bytes will be requested from the dnbd3 server. If it's outside of the original image (because the image grown in size) then the missing bytes will be padded with 0.
The write request will write compute the corresponding `cow_block_metadata_t` from the offset. If the corresponding `cow_block_metadata_t` does not exist yet it will be created. The data will be written in the data file, at the offset which is stored in the `cow_block_metadata_t`.
Then the corresponding bit in the bit fields will be set and the `timeChanged` will be updated. If there is more data to write, the next `cow_block_metadata_t` will be computed and the steps above will be repeated.
The `workCounter` variable is used here again to make sure that if padding was needed it is done before the fuse request returns.


### Block Upload
For block upload there is a background thread which loops periodically over all cow blocks and checks if `timeChanged` is not 0 and the time difference between now an `timeChanged` is larger than `COW_MIN_UPLOAD_DELAY`. If so, the block will be uploaded. The `timeChanged` before the upload will be temporary stored. After the upload `timeChanged` will be set to 0 if it still has the same time than temporary stored (if not there was an modification while the upload and it needs to be uploaded again). Once the image is unmounted `COW_MIN_UPLOAD_DELAY` is ignored an all blocks if a time of not 0 will be uploaded. The upload is done via an  [rest request](#/api/file/update). There are two different  limits for the number of parallel uploads in the [config.h](#config-variables).

## Files
If a new CoW session is started, a new `meta`, `data` and if set so in the Command line arguments a `status.txt` file is created.

### status
The `status.txt` can be activated with the `--cowStatFile` command line parameter.

The file will contain:

```
uuid=<uuid>
state=backgroundUpload
inQueue=0
modifiedBlocks=0
idleBlocks=0
totalBlocksUploaded=0
activeUploads:0
ulspeed=0.00
```
- The `uuid` is the session uuid, which the cow server uses to identify the session.

- The `state` is `backgroundUpload` if the image is still mounted and cow blocks are uploaded in the background.
It is `uploading` if the image got dismounted and all not yet uploaded blocks are  uploaded.
it is `done` if the image got dismounted and all blocks are uploaded. 
- `inQueue` are the cow blocks which are currently uploaded or waiting for a free slot.
- `modifiedBlocks` are cow block which have changes which are not uploaded to the server yet, because the changes are to recent.
- `totalBlocksUploaded` the total amount of cow blocks uploaded since the image was mounted.
- `activeUploads` is the number blocks that are currently uploaded.
- `ulspeed` the current upload speed in kb/s.

Once all blocks are uploaded, the state will be set to `done`.
If you define `COW_DUMP_BLOCK_UPLOADS`, then after the block upload is complete, a list of all blocks and sorted by the number of uploads will be dumped into status.txt.

With the command line parameter `--cowStatStdout` the same output of the stats file will be printed in stdout.

### meta
The `meta` file contains the following header:
```C
// cowfile.h
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
```
After this header at byte 8192 starts the l1 and then the l2 data structure mentioned above.
### data
The `data` files contain the magicValue and at the 40 * 8 * 4096 Offset(capacity of one cowfile_metadata_header_t) starts the first block data.



### magic values in the file headers
The magic values in both files are used to ensure that a suitable file is read and that the machine has the correct endianness.
```C
//config.h
#define COW_FILE_META_MAGIC_VALUE ((uint64_t)0xEBE44D6E72F7825E) // Magic Value to recognize a Cow meta file
#define COW_FILE_DATA_MAGIC_VALUE ((uint64_t)0xEBE44D6E72F7825F) // Magic Value to recognize a Cow data file
```


### Threads
This extension uses two new threads: 
```
tidCowUploader
tidStatUpdater
```
```tidCowUploader``` is the thread that uploads blocks to the cow server.

```tidStatUpdater``` updates the stats in stdout or the stats files
(depending on parameters).

### Locks

This extension uses a new lock  ```cow.l2CreateLock```. It is used when a new L2 array is allocated.



### Config Variables
The following configuration variables have been added to ```config.h```.
```c
//config.h
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
#define COW_MAX_IMAGE_SIZE 1000LL * 1000LL * 1000LL * 1000LL; // Maximum size an image can have(tb*gb*mb*kb)
// +++++ COW API Endpoints +++++
#define COW_API_CREATE "%s/api/File/Create"
#define COW_API_UPDATE "%s/api/File/Update?guid=%s&BlockNumber=%lu"
#define COW_API_START_MERGE "%s/api/File/StartMerge"
```

- ```COW_MIN_UPLOAD_DELAY``` defines the minimum time in seconds that must have elapsed since the last modification of a cow block before it is uploaded. This value can be fine tuned. A larger value usually reduces duplicate block uploads. While a lower value usually reduces the time for the final upload after the image got unmounted. If you define `COW_DUMP_BLOCK_UPLOADS` and have set the command line parameter `--cowStatFile`, then after the block upload is complete, a list of all blocks and sorted by the number of uploads will be dumped into status.txt. This can help adjusting `COW_MIN_UPLOAD_DELAY`.

- ```COW_STATS_UPDATE_TIME``` defines the update frequency in seconds of the stdout print/ stats file update. Setting this too low could impact the performance since it hast to loop over all blocks.
- ```COW_MAX_PARALLEL_UPLOADS``` defines to maximal number of parallel block uploads. These number is used once the image hast was dismounted and the final blocks are uploaded.
- ```COW_MAX_PARALLEL_BACKGROUND_UPLOADS``` defines to maximal number of parallel block uploads. These number is used will the image is still mounted and the user is still using it.



# REST Api
To transfer the data to the cow server, the following rest API is used:


### /api/File/Create

#### POST
##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Success |

This request is used  once a new cow session is created. The returned guid is used in all later requests to identify the session.


### /api/File/Update

#### POST
##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| guid | query |  | Yes | string (uuid) |
| blockNumber | query |  | Yes | integer |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Success |

Used for uploading a block of data. The blocknumber is the absolute block number. The body contains an "application/octet-stream" where the first bytes are the bit field directly followed by the  actual blockdata. 

### /api/File/StartMerge

#### POST
##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Success |
Used to start the merging on the server.

### /api/File/GetTopModifiedBlocks

#### GET
##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| guid | query |  | Yes | string (uuid) |
| amount | query |  | Yes | integer |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Success |

This request returns a list that contains Block Ids and the amount of times this block got uploaded, sorted by the amount of uploads. This is useful to adjust the `COW_MIN_UPLOAD_DELAY`.

### /api/File/Status

#### GET
##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| guid | query |  | Yes | string (uuid) |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Success |

Returns the SessionStatus Model, which gives information about the session.

### Models

#### BlockStatistics

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| blockNumber | integer |  | Yes |
| modifications | integer |  | Yes |

#### SessionState

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| SessionState | string |  |  |

#### SessionStatus

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| state | string | _Enum:_ `"Copying"`, `"Active"`, `"Merging"`, `"Done"`, `"Failed"` | Yes |
| imageName | string |  | Yes |
| originalImageVersion | integer |  | Yes |
| newImageVersion | integer |  | Yes |
| mergedBlocks | integer |  | Yes |
| totalBlocks | integer |  | Yes |
