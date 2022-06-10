# Cowtest

### Table of Contents
1. [Introduction](#introduction)
2. [Usage](#usage)
3. [Tests](#tests)



# Introduction

This test suit is for verifying that the fuse cow implementation works correctly. It can verify that read and writes on the cow fuse client work correctly and that the cow server merges the image correctly.


# Usage

### Parameters
- `-c <path>` generates a test image at given path. This image should be loaded for the tests to work.
- `-t <path>` runs the tests on the image at the given past.
- `-v <path>` verifies that previous tests on the image were successfully (also reads the image completely).

### Example Usage

1. generate the test image with `-c <path>` and copy it to the image location of the dnbd3 server. Also make sure that the cow servers `OriginalImageDirectory` points to the same Directory or copied in that Directory too. This step is only needed once for set up.
2. Start the dnbd3 and cow server.
3. Mount the image in cow mode.
4. Run the test with `-t <path>`, where path points to the mounted image.
5. Optional verify again with `-v <path>`.
6. Optional unmount the image and then load it again (with `-L <path>` in the fuse client). Then verify the loaded image with `-v <path>`.
7. Unmount and merge the image.
8. Verify the merged image from the cow server with `-v <path>`.


# Tests

### TestFirstBit
Reads the first block and verifies that all bits are 0. Then it sets the first bit to 1 and writes it.
This test, tests basic functionality and verifies that the image is still 'clean'.

| offset | size | 
| -------| -----| 
| 0 | DNBD3_BLOCK_SIZE|


### WriteOverTwoBlocks
tests that continuous writes over two DNBD3_BLOCK's are possible.

| offset | size | 
| -------| -----| 
| DNBD3_BLOCK_SIZE * 3| size: DNBD3_BLOCK_SIZE * 2|


### WriteNotOnBlockBorder
Verifies that writes not aligned to block borders (multiples of 4096).

| offset | size | 
| -------| -----| 
| DNBD3_BLOCK_SIZE * 11 - DNBD3_BLOCK_SIZE / 2| DNBD3_BLOCK_SIZE * 2 |


### InterleavedTest

| offset | size | 
| -------| -----| 
|DNBD3_BLOCK_SIZE * 35 | DNBD3_BLOCK_SIZE * 10|

### WriteOverL2
Tests that continuous writes over L2 borders are possible.

| offset | size | 
| -------| -----| 
|l2Capacity * 2 - DNBD3_BLOCK_SIZE | DNBD3_BLOCK_SIZE * 2 |

### fileSizeChanges
Tests file size changes. First in increases the file size with a truncate by 2 * l2Capacity. It then checks that all the bits in the new allocated space are set to 0. Then it writes data to it to verify writes are possible. After that it truncates it back to the original size. Then it truncates it back to
the original size + 2 * l2Capacity and verifies that the again all bits in the new allocated space are 0 (so that the before written data is set to 0 again).

### LongNonAlignedPattern
This test writes writes an long pattern over 3 l2 borders. The pattern are repeating chars from 0 to 254, so it's not a multiple of 4096, which therefore results that all Blocks are filled with different data. Also this test is not block aligned.
| offset | size | 
| -------| -----| 
|l2Capacity * 3 - 1|l2Capacity + 2|
