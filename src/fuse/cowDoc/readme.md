
# Fuse Copy on Write (CoW)

### Table of Contents
1. [Introduction](#introduction)
2. [Usage](#usage)
3. [Implementation Details](#implementation-details)
4. [REST Api](#rest-api)


# Introduction

This extension to the fuse dnbd3 client allows it to mount images writable. The changes to an writeable mounted image will be stored in a separate files (also called Copy on Write (Cow)) on the client computer. These changes are uploaded in the background to the cow server. Once the user unmounts the images all remaining changes will be uploaded. Then the image will be merged on the server (depending on the startup parameters).


# Usage

### New Parameters
- `-c <path>` Enables the cow functionality, the argument sets the path for the temporary `.meta` and `.data` file in which the writes are stored
- `-C <address>` sets the address of the cow server. The cow server is responsible for merging the original image with the changes from the client.
- `-L <path>` Similar to `-c <path>` but instead of creating a new session it loads an existing from the given path.
- `-m` if set, the client will request a merge after the image is unmounted and all change are uploaded.

Example parameters for creating a new cow session:
```
./dnbd3-fuse "/home/user/VMs/mount" -f -h localhost -i test -c "/home/user/temp" -C "192.168.178.20:5000"

```

# Implementation Details


## Files
If a new CoW session is started, a new `.meta` and `.data` file is created.

### .meta
The `.meta` file contains the following header:
```C
// cowfile.h
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

```

### .data
The `.data` files contains



### magic values in the file headers
The magic values in both files are used to ensure that a suitable file is read and that the machine has the correct endianness.
```C
//config.h
#define COW_FILE_META_MAGIC_VALUE ((uint64_t)0xEBE44D6E72F7825E) // Magic Value to recognize a Cow .meta file
#define COW_FILE_DATA_MAGIC_VALUE ((uint64_t)0xEBE44D6E72F7825F) // Magic Value to recognize a Cow .data file
```
## Data strucure
![Datastructure](img/Bild1.jpg "")


# REST Api
To transfer the data to the cow server, the following rest api is used:

### /api/File/Create

#### POST
##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Success |

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

### /api/File/StartMerge

#### GET
##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| guid | query |  | Yes | string (uuid) |
| fileSize | query |  | Yes | long |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Success |

### /api/File/Satus

#### GET
##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| guid | query |  | Yes | string (uuid) |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Success |

## Models

#### SessionState

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| SessionState | string |  | Yes |

#### SessionStatus

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| state | string | _Enum:_ `"Copying"`, `"Active"`, `"Merging"`, `"Done"` | Yes |
| imageName | string |  | Yes |
| originalImageVersion | integer |  | Yes |
| newImageVersion | integer |  | Yes |
| mergedBlocks | integer |  | Yes |
| totalBlocks | integer |  | Yes |
