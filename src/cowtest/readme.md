# Cowtest

### Table of Contents
1. [Introduction](#introduction)
2. [Usage](#usage)
3. [Tests](#tests)



# Introduction

This test collection is used to check whether the cow implementation of the fuse client is working correctly. It can check whether read and write operations on the cow fuse client work correctly and whether the cow server merges the image correctly.


# Usage

### Parameters
- `-c <path>` generates a test image in the specified path. This image is needed for the tests.
- `-t <file>` performs the standard tests on the image at the specified location.
- `-v <file>` checks if previous tests of the image were successful (also reads the image completely).
- `-r <mountedImageFile> <normalImageFile>` writes randomly and changes the size of two images. After pressing ctrl +c, both images are compared for equality. 
- `-x <mergedImageFile> <normalImageFile>` Checks if both images are equal.



### Example usage for standard test

1. Generate the test image with `-c <path>` and copy it into the image directory of the dnbd3 server. Also make sure that the `OriginalImageDirectory` of the Cow server points to the same directory or has also been copied to this directory. This step is only required once for the setup.
2. Start the dnbd3 and cow server.
3. Mount the image in cow mode (`-c <path>` and `-C <address>` on the fuse client).
4. Run the test with `-t <path>`, with the path pointing to the mounted image.
5. Optional verify again with `-v <path>`.
6. Optionally unmount the image and then load it again (with `-L <path>` instead of `-C <path>` on the Fuse client). Then verify the loaded image with `-v <path>`.
7. Unmount and merge the image (`-m` on the fuse client).
8. Verify the merged image from the cow server with `-v <path>`.

### Example usage for random writes
1. Generate the test image with `-c <path>` and copy it into the image directory of the dnbd3 server. Also make sure that the `OriginalImageDirectory` of the Cow server points to the same directory or has also been copied to this directory. This step is only required once for the setup.
2. Make a copy of the created image in another location. 
3. Start the dnbd3 and cow server.
4. Mount the image in cow mode (`-c <path>` and `-C <address>` on the fuse client).
5. Run the test with `-t <mountedImagePath> <normalImagePath>`, where `<mountedImagePath>` refers to the mounted image and `<normalImagePath>` refers to the copied image on the hard disk.
6. After some time, press ctrl+c to end the test. Afterwards, both images are automatically compared for equality.
7. Unmount the image and merge it(`-m` on the fuse client).
8. Run `-x <mergedImagePath> <normalImagePath>` where `<mergedImagePath>` points to the merged image and `<normalImagePath>` points to the copied image on the hard disk. This verifies that the merged image matches the image on the hard disk.

Another help for running or setting up the tests can be the git ci test script [test-cow-fuse.yml](../../.github/workflows/test-cow-fuse.yml). There, a complete test setup is created and the standard test as well as the random test is executed.

# Tests

### TestSingleBit
Reads the first block and checks whether all bits are 0. Then sets the first bit to 1 and writes it.
This test checks the basic functions and whether the image is still "clean".
Then sets a single bit in the second block to 1 to verify that padding works correctly.

| offset | size | 
| -------| -----| 
| 0 | 2 * DNBD3_BLOCK_SIZE|


### WriteOverTwoBlocks
Tests that continuous writes over two DNBD3_BLOCK's are possible.

| offset | size | 
| -------| -----| 
| DNBD3_BLOCK_SIZE * 3| size: DNBD3_BLOCK_SIZE * 2|


### WriteNotOnBlockBorder
Verifies that writes are not aligned to block boundaries (multiples of 4096).

| offset | size | 
| -------| -----| 
| DNBD3_BLOCK_SIZE * 11 - DNBD3_BLOCK_SIZE / 2| DNBD3_BLOCK_SIZE * 2 |


### InterleavedTest

| offset | size | 
| -------| -----| 
|DNBD3_BLOCK_SIZE * 35 | DNBD3_BLOCK_SIZE * 10|

### WriteOverL2
Tests whether continuous writes across L2 boundaries are possible.

| offset | size | 
| -------| -----| 
|l2Capacity * 2 - DNBD3_BLOCK_SIZE | DNBD3_BLOCK_SIZE * 2 |


### MultipleWrites
Writes different data several times on the same block. The individual writes can be delayed with the parameter `-d`. This is useful to test whether uploading the same blocks multiple times works as intended.


| offset | size | 
| -------| -----| 
| 100 * DNBD3_BLOCK_SIZE * bitfieldByteSize | DNBD3_BLOCK_SIZE * 10 * bitfieldByteSize |


### fileSizeChanges
Tests changes to the file size. First it increases the file size by 2 * l2Capacity with a truncate. Then it checks if all bits in the newly allocated memory space are set to 0. Then it writes data to the file to check if writes are possible. After that, it is truncated back to the original size. Then it is reduced again to
the original size + 2 * l2Capacity and checks whether all bits in the newly allocated memory space are 0 again (so that the previously written data is set to 0 again).

### LongNonAlignedPattern
This test writes a long pattern over 3 l2 blocks. The pattern repeats chars from 0 to 254, so it is not a multiple of 4096, which results in all blocks being filled with different data. Furthermore, this test is not block-aligned.


| offset | size | 
| -------| -----| 
|l2Capacity * 3 - 1|l2Capacity + 2|
