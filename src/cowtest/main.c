#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <dnbd3/types.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <getopt.h>

typedef bool ( *func_ptr )();
typedef struct verify_test
{
	off_t offset;
	size_t size;
	func_ptr test;
} verify_test_t;

typedef struct special_test
{
	off_t offset;
	size_t size;

} special_test_t;

typedef struct random_write_args
{
	char *mountedImage;
	char *normalImage;
	float minSizePercent;
	float maxSizePercent;
} random_write_args_t;

const size_t l2Size = 1024;
const size_t bitfieldByteSize = 40;
const size_t l2Capacity = l2Size * DNBD3_BLOCK_SIZE * bitfieldByteSize * 8;
const size_t testFileSize = l2Capacity * 2.9L;

#define RND_MAX_WRITE_SIZE 4096 * 320
#define RND_TRUNCATE_PROBABILITY 5
#define RND_UNALIGNED_WRITE_PROBABILITY 5
#define RND_DEFAULT_MIN_SIZE_PERCENT 0.9f
#define RND_DEFAULT_MAX_SIZE_PERCENT 1.1f
#define BASE_DATA (char)42
#define CLAMP( x, min, max ) MAX( MIN( x, min ), max )

int delay = 0;
static char filePath[400];
static int fh = 0;

bool printOnError = true;
/**
 * @brief generates a Test file
 * 
 * @param path Location where the file is created
 * @param size Size of the file in byte
 */

bool generateTestFile( char *path, size_t size )
{
	int fh;
	if ( ( fh = open( path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not create test file: " );
		return false;
	}
	/*
	if ( ftruncate( fh, size ) == -1 ) {
		perror( "Error while expanding test file: " );
		return;
	}
	*/

	ssize_t writtenSize = 0;
	char buf[DNBD3_BLOCK_SIZE * 50];
	memset( buf, BASE_DATA, DNBD3_BLOCK_SIZE * 50 );
	while ( writtenSize < (ssize_t)size ) {
		size_t sizeToWrite = MIN( DNBD3_BLOCK_SIZE * 50, size - writtenSize );
		ssize_t tmp = pwrite( fh, buf, sizeToWrite, writtenSize );
		if ( tmp == 0 ) {
			printf( "Error while populating the test file:  " );
			return false;
		}
		if ( tmp == -1 ) {
			perror( "Error while populating the test file:  " );
			return false;
		}
		writtenSize += tmp;
	}

	close( fh );
	printf( "Generated Test File of size: %zu bytes. \n", size );
	return true;
}


void printCharInHexadecimal( const char *str, int len )
{
	for ( int i = 0; i < len; ++i ) {
		printf( "0x%02x ", (int)str[i] );
	}
	printf( "\n" );
}

bool compare( char buff[], char expected[], size_t size, char errorMessage[] )
{
	if ( memcmp( buff, expected, size ) != 0 ) {
		printf( "%s", errorMessage );
		if ( printOnError ) {
			printf( "Expected: \n" );
			printCharInHexadecimal( expected, (int)size );
			printf( "Got: \n " );
			printCharInHexadecimal( buff, (int)size );
		}
		return false;
	}
	return true;
}


bool readSizeTested( int fh, char *buf, ssize_t size, off_t off, char *error )
{
	ssize_t readSize = pread( fh, buf, size, off );
	if ( readSize == -1 ) {
		perror( "Read failed: " );
	} else if ( readSize < size ) {
		printf( "%s \n size read: %zu\n Expected %zu\n", error, readSize, size );
		return false;
	}
	return true;
}

bool writeSizeTested( int fh, char *buf, ssize_t size, off_t off, char *error )
{
	ssize_t writeSize = pwrite( fh, buf, size, off );
	if ( writeSize == 1 )
		perror( "write failed: " );
	if ( writeSize < size ) {
		printf( "%s", error );
		return false;
	}
	return true;
}

bool writeTwoFilesTested( int fhm, int fhn, char *buf, ssize_t size, off_t off )
{
	printf( "write offset: %zu size: %zu\n", off, size );

	if ( !writeSizeTested( fhm, buf, size, off, "failed to write on mounted image" ) ) {
		return false;
	}
	if ( !writeSizeTested( fhn, buf, size, off, "failed to write on normal image" ) ) {
		return false;
	}
	return true;
}
bool changeFileSizeAndVerify( char *filePath, size_t size )
{
	if ( truncate( filePath, size ) != 0 ) {
		perror( "truncate failed: " );
		return false;
	}
	// verify
	struct stat st;
	stat( filePath, &st );
	size_t newSize = st.st_size;

	if ( size != newSize ) {
		printf( "truncate failed, wrong file size\n expectedSize: %zu\n got: %zu\n", size, newSize );
		return false;
	}
	return true;
}

bool changeTwoFileSizeAndVerify( char *filePath, char *filePath2, size_t size )
{
	printf( "change filesize to: %zu\n", size );
	return changeFileSizeAndVerify( filePath, size ) && changeFileSizeAndVerify( filePath2, size );
}

bool verifySingleBit()
{
	char buff[DNBD3_BLOCK_SIZE];
	char expected[DNBD3_BLOCK_SIZE];
	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE );
	expected[0] = 1;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, 0, "SingleBit test Failed: first read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "SingleBit test Failed: first write not as expected" ) )
		return false;

	expected[0] = BASE_DATA;
	expected[DNBD3_BLOCK_SIZE / 2] = 1;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE, "SingleBit test Failed: second read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "SingleBit test Failed: second write not as expected" ) )
		return false;
	printf( "testSingleBit successful!\n" );
	return true;
}

bool testSingleBit()
{
	char buff[DNBD3_BLOCK_SIZE];
	char expected[DNBD3_BLOCK_SIZE];
	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE );
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, 0, "SingleBit test Failed: first read to small" ) )
		return false;

	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "SingleBit test Failed: initial read" ) )
		return false;
	expected[0] = 1;
	if ( !writeSizeTested( fh, expected, DNBD3_BLOCK_SIZE, 0, "SingleBit test Failed: first write failed" ) )
		return false;

	expected[0] = BASE_DATA;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE, "SingleBit test Failed: second read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "SingleBit test Failed: second read" ) )
		return false;
	expected[0] = 1;
	if ( !writeSizeTested(
				  fh, expected, 1, DNBD3_BLOCK_SIZE + DNBD3_BLOCK_SIZE / 2, "SingleBit test Failed: second write failed" ) )
		return false;
	return verifySingleBit();
}

bool verifyWriteOverTwoBlocks()
{
	char buff[DNBD3_BLOCK_SIZE * 2];
	char expected[DNBD3_BLOCK_SIZE * 2];
	memset( expected, 1, DNBD3_BLOCK_SIZE * 2 );
	if ( !readSizeTested(
				  fh, buff, DNBD3_BLOCK_SIZE * 2, DNBD3_BLOCK_SIZE * 3, "writeOverTwoBlocks test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2, "OverTwoBlocks test Failed: write not as expected" ) )
		return false;
	printf( "writeOverTwoBlocks successful!\n" );
	return true;
}

bool writeOverTwoBlocks()
{
	char buff[DNBD3_BLOCK_SIZE * 2];
	char expected[DNBD3_BLOCK_SIZE * 2];
	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE * 2 );
	if ( !readSizeTested(
				  fh, buff, DNBD3_BLOCK_SIZE * 2, DNBD3_BLOCK_SIZE * 3, "writeOverTwoBlocks test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2, "OverTwoBlocks test Failed: initial read" ) )
		return false;
	memset( expected, 1, DNBD3_BLOCK_SIZE * 2 );
	if ( !writeSizeTested( fh, expected, DNBD3_BLOCK_SIZE * 2, DNBD3_BLOCK_SIZE * 3,
				  "writeOverTwoBlocks test Failed: write failed" ) )
		return false;
	return verifyWriteOverTwoBlocks();
}


bool verifyWriteOverL2()
{
	char buff[DNBD3_BLOCK_SIZE * 2];
	char expected[DNBD3_BLOCK_SIZE * 2];

	memset( expected, 1, DNBD3_BLOCK_SIZE * 2 );
	size_t offset = l2Capacity * 2 - DNBD3_BLOCK_SIZE;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 2, offset, "writeOverL2 test Failed: read to small" ) ) {
		return false;
	}
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2, "writeOverL2 test Failed: write not as expected" ) ) {
		return false;
	}
	printf( "writeOverL2 successful!\n" );
	return true;
}

bool writeOverL2()
{
	char buff[DNBD3_BLOCK_SIZE * 2];
	char expected[DNBD3_BLOCK_SIZE * 2];
	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE * 2 );
	size_t offset = l2Capacity * 2 - DNBD3_BLOCK_SIZE;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 2, offset, "writeOverL2 test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2, "writeOverL2 test Failed: initial read" ) )
		return false;
	memset( expected, 1, DNBD3_BLOCK_SIZE * 2 );
	if ( !writeSizeTested( fh, expected, DNBD3_BLOCK_SIZE * 2, offset, "writeOverL2 test Failed: write failed" ) )
		return false;

	return verifyWriteOverL2();
}


bool verifyWriteNotOnBlockBorder()
{
	char buff[DNBD3_BLOCK_SIZE * 2];
	char expected[DNBD3_BLOCK_SIZE * 2];
	memset( expected, 1, DNBD3_BLOCK_SIZE * 2 );
	size_t offset = DNBD3_BLOCK_SIZE * 11 - DNBD3_BLOCK_SIZE / 2;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 2, offset, "writeNotOnBlockBorder test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2, "writeNotOnBlockBorder test Failed: write not as expected" ) )
		return false;
	printf( "writeNotOnBlockBorder successful!\n" );
	return true;
}

// perhaps do some initial markers on the file
bool writeNotOnBlockBorder()
{
	char buff[DNBD3_BLOCK_SIZE * 2];
	char expected[DNBD3_BLOCK_SIZE * 2];
	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE * 2 );
	size_t offset = DNBD3_BLOCK_SIZE * 11 - DNBD3_BLOCK_SIZE / 2;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 2, offset, "writeNotOnBlockBorder test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2, "writeNotOnBlockBorder test Failed: initial read" ) )
		return false;
	memset( expected, 1, DNBD3_BLOCK_SIZE * 2 );
	if ( !writeSizeTested(
				  fh, expected, DNBD3_BLOCK_SIZE * 2, offset, "writeNotOnBlockBorder test Failed: write failed" ) )
		return false;
	return verifyWriteNotOnBlockBorder();
}

bool verifyLongNonAlignedPattern()
{
	int size = DNBD3_BLOCK_SIZE * 10;
	char buffer[size];
	char expected[size];
	for ( int i = 0; i < size; i++ ) {
		expected[i] = (char)( i % 255 );
	}

	off_t offset = l2Capacity * 3 - 1;
	size_t totalSize = l2Capacity + 2;
	off_t endOffset = offset + totalSize;

	while ( offset < endOffset ) {
		size_t sizeToRead = MIN( size, endOffset - offset );
		if ( !readSizeTested( fh, buffer, sizeToRead, offset, "writeLongNonAlignedPattern test Failed: read failed" ) ) {
			return false;
		}
		if ( !compare( buffer, expected, sizeToRead, "writeLongNonAlignedPattern test Failed:  read failed" ) )
			return false;
		offset += sizeToRead;
	}
	printf( "LongNonAlignedPattern successful!\n" );
	return true;
}

bool writeLongNonAlignedPattern()
{
	int size = DNBD3_BLOCK_SIZE * 10;
	char buffer[size];

	for ( int i = 0; i < size; i++ ) {
		buffer[i] = (char)( i % 255 );
	}

	off_t offset = l2Capacity * 3 - 1;
	size_t totalSize = l2Capacity + 2;
	off_t endOffset = offset + totalSize;

	while ( offset < endOffset ) {
		size_t sizeToWrite = MIN( size, endOffset - offset );
		if ( !writeSizeTested(
					  fh, buffer, sizeToWrite, offset, "writeLongNonAlignedPattern test Failed: write failed" ) ) {
			return false;
		}
		offset += sizeToWrite;
	}
	return verifyLongNonAlignedPattern();
}

//l2Capacity * 2.9L * 0.9
bool verifyFileSizeChanges()
{
	printf( "verify size changes...\n" );
	char buff[DNBD3_BLOCK_SIZE * 2];
	char expected[DNBD3_BLOCK_SIZE * 2];

	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE );
	memset( expected + DNBD3_BLOCK_SIZE, 0, DNBD3_BLOCK_SIZE );
	off_t offset = (size_t)( ( (double)testFileSize ) * 0.9 ) - DNBD3_BLOCK_SIZE;

	if ( !readSizeTested(
				  fh, buff, DNBD3_BLOCK_SIZE * 2, offset, "verifyFileSizeChanges test Failed: read to small\n" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2,
				  "verifyFileSizeChanges test Failed: increased data not as expected.\n" ) )
		return false;
	offset += DNBD3_BLOCK_SIZE * 2;

	offset = offset - ( offset % DNBD3_BLOCK_SIZE );

	memset( expected, 0, DNBD3_BLOCK_SIZE );

	while ( offset < (off_t) (l2Capacity * 3 - 1 )) {
		size_t sizeToRead = MIN( DNBD3_BLOCK_SIZE * 2, ( l2Capacity * 3 - 1 ) - offset );
		if ( !readSizeTested( fh, buff, sizeToRead, offset, "verifyFileSizeChanges test Failed: read to small" ) )
			return false;

		if ( !compare( buff, expected, sizeToRead, "verifyFileSizeChanges test Failed: data not 0.\n" ) )
			return false;
		offset += sizeToRead;
	}
	printf( "verified fileSizeChanges.\n" );
	return true;
}
bool fileSizeChanges()
{
	// check if increased is 0
	char buff[DNBD3_BLOCK_SIZE * 10];
	char expected[DNBD3_BLOCK_SIZE * 10];
	memset( expected, 0, DNBD3_BLOCK_SIZE * 10 );

	// decrease FileSize
	printf( "Decrease Filesize to:  %zu\n", (size_t)( ( (double)testFileSize ) * 0.9 ) );
	if ( !changeFileSizeAndVerify( filePath, (size_t)( ( (double)testFileSize ) * 0.9 ) ) ) {
		return false;
	}

	printf( "increase Filesize to:  %zu\n", testFileSize );
	if ( !changeFileSizeAndVerify( filePath, testFileSize ) ) {
		return false;
	}

	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE );
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 10, (size_t)( ( (double)testFileSize ) * 0.9 ) - DNBD3_BLOCK_SIZE,
				  "fileSizeChanges test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 10, "fileSizeChanges test Failed: increased not as expected.\n" ) )
		return false;

	memset( expected, 0, DNBD3_BLOCK_SIZE );
	// increase filesize

	if ( !changeFileSizeAndVerify( filePath, testFileSize + 2 * l2Capacity ) ) {
		return false;
	}


	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 10, testFileSize + l2Capacity,
				  "fileSizeChanges test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 10, "fileSizeChanges test Failed: increased data not 0" ) )
		return false;
	printf( "increased data is 0 as expected\n" );
	// write on increased blocks
	memset( expected, 1, DNBD3_BLOCK_SIZE * 10 );
	if ( !writeSizeTested(
				  fh, expected, DNBD3_BLOCK_SIZE * 10, testFileSize, "fileSizeChanges test Failed: write failed" ) )
		return false;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 10, testFileSize, "fileSizeChanges test Failed: read to small" ) )
		return false;
	if ( !compare(
				  buff, expected, DNBD3_BLOCK_SIZE * 10, "fileSizeChanges test Failed: write on increased size failed" ) )
		return false;
	printf( "writes to new Block Ok\n" );
	// decrease filesize
	printf( "Truncate file to: %zu \n", testFileSize );
	if ( !changeFileSizeAndVerify( filePath, testFileSize ) ) {
		return false;
	}
	printf( "size verified\n" );
	// increase again, check its 0 again
	printf( "Truncate file to: %zu\n", testFileSize + 2 * l2Capacity );
	if ( !changeFileSizeAndVerify( filePath, testFileSize + 2 * l2Capacity ) ) {
		return false;
	}

	printf( "size verified\n" );
	memset( expected, 0, DNBD3_BLOCK_SIZE * 10 );


	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 10, testFileSize, "fileSizeChanges test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2,
				  "fileSizeChanges test Failed: increased data (second time) not 0" ) )
		return false;


	return verifyFileSizeChanges();
}


bool verifyInterleavedTest()
{
	char buff[DNBD3_BLOCK_SIZE * 10];
	char expected[DNBD3_BLOCK_SIZE * 10];
	off_t offset = 35 * DNBD3_BLOCK_SIZE;
	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE * 10 );
	memset( expected, 10, DNBD3_BLOCK_SIZE );
	memset( ( expected + ( DNBD3_BLOCK_SIZE * 2 ) ), 12, DNBD3_BLOCK_SIZE );
	memset( ( expected + ( DNBD3_BLOCK_SIZE * 4 ) ), 14, DNBD3_BLOCK_SIZE );
	memset( ( expected + ( DNBD3_BLOCK_SIZE * 5 ) ), 15, DNBD3_BLOCK_SIZE );
	memset( ( expected + ( DNBD3_BLOCK_SIZE * 8 ) ), 18, DNBD3_BLOCK_SIZE );
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 10, offset, "interleavedTest test Failed: read 2 to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 10, "interleavedTest test Failed: read not as expected" ) )
		return false;
	printf( "interleavedTest successful!\n" );
	return true;
}

bool interleavedTest()
{
	printf( "starting interleavedTest \n" );
	char buff[DNBD3_BLOCK_SIZE * 10];
	char expected[DNBD3_BLOCK_SIZE * 10];
	off_t offset = 35 * DNBD3_BLOCK_SIZE;
	memset( expected, BASE_DATA, DNBD3_BLOCK_SIZE * 10 );
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 10, offset, "interleavedTest test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 10, "interleavedTest test Failed: read data not 0" ) )
		return false;

	memset( expected, 10, DNBD3_BLOCK_SIZE );
	if ( !writeSizeTested( fh, expected, DNBD3_BLOCK_SIZE, offset, "interleavedTest test Failed: write 1 failed" ) )
		return false;

	memset( ( expected + ( DNBD3_BLOCK_SIZE * 2 ) ), 12, DNBD3_BLOCK_SIZE );
	if ( !writeSizeTested( fh, ( expected + ( DNBD3_BLOCK_SIZE * 2 ) ), DNBD3_BLOCK_SIZE, offset + DNBD3_BLOCK_SIZE * 2,
				  "interleavedTest test Failed: write 2 failed" ) )
		return false;

	memset( ( expected + ( DNBD3_BLOCK_SIZE * 4 ) ), 14, DNBD3_BLOCK_SIZE );
	memset( ( expected + ( DNBD3_BLOCK_SIZE * 5 ) ), 15, DNBD3_BLOCK_SIZE );

	if ( !writeSizeTested( fh, ( expected + ( DNBD3_BLOCK_SIZE * 4 ) ), DNBD3_BLOCK_SIZE * 2,
				  offset + DNBD3_BLOCK_SIZE * 4, "interleavedTest test Failed: write 3 failed" ) )
		return false;

	memset( ( expected + ( DNBD3_BLOCK_SIZE * 8 ) ), 18, DNBD3_BLOCK_SIZE );
	if ( !writeSizeTested( fh, ( expected + ( DNBD3_BLOCK_SIZE * 8 ) ), DNBD3_BLOCK_SIZE, offset + DNBD3_BLOCK_SIZE * 8,
				  "interleavedTest test Failed: write 4 failed" ) )
		return false;
	return verifyInterleavedTest();
}

bool verifyMultipleWrites()
{
	size_t size = DNBD3_BLOCK_SIZE * 10 * bitfieldByteSize;
	char buff[size];
	char expected[size];
	off_t offset = 100 * DNBD3_BLOCK_SIZE * bitfieldByteSize;
	memset( expected, 3, size );
	if ( !readSizeTested( fh, buff, size, offset, "multipleWrites test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, size, "multipleWrites: read incorrect data" ) )
		return false;
	printf( "MultipleWrites successful!\n" );
	return true;
}

bool multipleWrites()
{
	printf( "starting multipleWrites\n" );
	size_t size = DNBD3_BLOCK_SIZE * 10 * bitfieldByteSize;
	char buff[size];
	char expected[size];
	off_t offset = 100 * DNBD3_BLOCK_SIZE * bitfieldByteSize;

	for ( int i = 1; i <= 3; i++ ) {
		printf( "multipleWrites: %i/3 \n", i );

		memset( expected, i, size );
		if ( !writeSizeTested( fh, expected, size, offset, "multipleWrites: write Failed" ) )
			return false;
		if ( !readSizeTested( fh, buff, size, offset, "multipleWrites test Failed: read to small" ) )
			return false;
		if ( !compare( buff, expected, size, "multipleWrites: read incorrect data" ) )
			return false;
		if ( delay > 0 && i < 3 ) {
			printf( "waiting %is\n", delay );
			sleep( delay );
		}
	}
	return verifyMultipleWrites();
}


bool runTest( char *path )
{
	if ( ( fh = open( path, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open test file" );
		printf( "Given path: %s \n", path );
		return;
	}
	strcpy( filePath, path );
	printf( "file opened: %s\n", path );

	if ( !testSingleBit() )
		return false;
	if ( !writeOverTwoBlocks() )
		return false;

	if ( !writeNotOnBlockBorder() )
		return false;

	if ( !writeOverL2() )
		return false;
	if ( !fileSizeChanges() )
		return false;
	if ( !interleavedTest() )
		return false;
	if ( !multipleWrites() ) {
		return false;
	}
	if ( !writeLongNonAlignedPattern() ) {
		return false;
	}


	printf( "All test's successful.\n" );
	return true;
}


void verifyTests( verify_test_t *tests )
{
	// offset, size, function

	off_t fileSizeOffset = (size_t)( ( (double)testFileSize * 0.9 ) - DNBD3_BLOCK_SIZE );
	size_t fileSizeSize = ( l2Capacity * 3 - 1 ) - fileSizeOffset;
	tests[0] = ( verify_test_t ){ 0, 2 * DNBD3_BLOCK_SIZE, verifySingleBit };
	tests[1] = ( verify_test_t ){ DNBD3_BLOCK_SIZE * 3, DNBD3_BLOCK_SIZE * 3, verifyWriteOverTwoBlocks };
	tests[2] = ( verify_test_t ){ DNBD3_BLOCK_SIZE * 11 - DNBD3_BLOCK_SIZE / 2, DNBD3_BLOCK_SIZE * 2,
		verifyWriteNotOnBlockBorder };
	tests[3] = ( verify_test_t ){ 35 * DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE * 10, verifyInterleavedTest };
	tests[4] = ( verify_test_t ){ 100 * DNBD3_BLOCK_SIZE * bitfieldByteSize, DNBD3_BLOCK_SIZE * 10 * bitfieldByteSize,
		verifyMultipleWrites };
	tests[5] = ( verify_test_t ){ l2Capacity * 2 - DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE * 2, verifyWriteOverL2 };
	tests[6] = ( verify_test_t ){ fileSizeOffset, fileSizeSize, verifyFileSizeChanges };
	tests[7] = ( verify_test_t ){ l2Capacity * 3 - 1, l2Capacity + 2, verifyLongNonAlignedPattern };
}

bool verifyFinalFile( char *path )
{
	if ( ( fh = open( path, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open test file" );
		printf( "Given path: %s \n", path );
		return false;
	}
	// verify file size

	size_t fileSize = testFileSize + 2 * l2Capacity;
	struct stat st;
	stat( path, &st );
	size_t size = st.st_size;
	if ( size != fileSize ) {
		printf( "verify Failed, wrong file size\n expectedSize: %zu\n got: %zu\n", fileSize, size );
		return false;
	}

	// read to whole file

	int maxReadSize = DNBD3_BLOCK_SIZE * COW_BITFIELD_SIZE * 8;
	char buffer[maxReadSize];
	char emptyData[maxReadSize];
	memset( emptyData, BASE_DATA, maxReadSize );
	size_t offset = 0;


	int numberOfTests = 8;
	verify_test_t tests[numberOfTests];
	verifyTests( tests );

	int currentTest = 0;
	bool swapToIncreased = false;


	while ( offset < fileSize ) {
		size_t sizeToRead = MIN( (size_t)maxReadSize, fileSize - offset );
		if ( currentTest < numberOfTests ) {
			sizeToRead = MIN( sizeToRead, tests[currentTest].offset - offset );
		}
		if ( currentTest < numberOfTests && tests[currentTest].offset == (off_t)offset ) {
			if ( !tests[currentTest].test() ) {
				return false;
			}
			offset += tests[currentTest].size;
			currentTest++;
		} else {
			// if offset > testFileSize filler data is 0
			if ( !swapToIncreased && offset > testFileSize ) {
				memset( emptyData, 0, maxReadSize );
			}
			ssize_t sizeRead = pread( fh, buffer, sizeToRead, offset );
			if ( sizeRead <= 0 ) {
				perror( "Error while reading data: " );
				printf( "verify failed. \n" );
				return false;
			}
			if ( !compare( buffer, emptyData, sizeRead, "verify failed. Expected 0 data" ) ) {
				printf( "Offset: %zu \n", offset );
				return false;
			}
			offset += (size_t)sizeRead;
		}
	}

	printf( "file verified successful.\n" );
	return true;
	}


void generateRandomData( int fhr, char *dest, size_t size )
{
	read( fhr, dest, size );
}


atomic_bool randomTestLoop = true;

void printProgress( float progress )
{
	progress = MIN( 1, progress );
	progress = MAX( 0, progress );
	int barWidth = 50;
	char buf[barWidth + 1];
	buf[barWidth] = 0;
	int pos = (int)( (float)barWidth * progress );
	memset( buf, '=', pos );
	memset( ( buf + pos ), ' ', ( barWidth - pos ) );
	printf( "\033[F[%s] %i%%\n", buf, (int)( progress * 100 ) );
}

off_t findDiffOffset( char *buf1, char *buf2, size_t size )
{
	for ( size_t i = 0; i < size; i++ ) {
		if ( buf1[i] != buf2[i] ) {
			return i;
		}
	}
	return -1;
}

bool compareTwoFiles( char *mountedImagePath, char *normalImagePath, int fhm, int fhn )
{
	char buf[RND_MAX_WRITE_SIZE];
	char exBuf[RND_MAX_WRITE_SIZE];
	off_t offset = 0;
	struct stat st;
	stat( mountedImagePath, &st );
	size_t sizeMounted = st.st_size;
	stat( normalImagePath, &st );
	size_t sizeNormal = st.st_size;

	if ( sizeMounted != sizeNormal ) {
		printf( "Error size difference, mounted: %zu normal: %zu \n", sizeMounted, sizeNormal );
		return false;
	}
	printf( "\n" );
	while ( offset < (off_t)sizeMounted ) {
		size_t sizeToRead = MIN( RND_MAX_WRITE_SIZE, sizeMounted - offset );
		read( fhm, buf, sizeToRead );

		read( fhn, exBuf, sizeToRead );

		if ( memcmp( buf, exBuf, sizeToRead ) != 0 ) {
			off_t dif = findDiffOffset( buf, exBuf, sizeToRead );
			printf( "Error: Different data, offset: %zu \n expected: %i got %i \n", offset + dif, (int)exBuf[dif],
					(int)buf[dif] );
			return false;
		}

		offset += sizeToRead;
		printProgress( ( (float)offset ) / ( (float)sizeMounted ) );
	}
	printf( "\nTest successful !!!\n" );
	return true;
}

bool startCompareTwoFiles( char *mountedImagePath, char *normalImagePath )
{
	int fhm, fhn;
	bool ok = true;
	if ( ( fhm = open( mountedImagePath, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open mounted Image" );
		printf( "Given path: %s \n", mountedImagePath );
		ok = false;
	}
	if ( ( fhn = open( normalImagePath, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open normal Image" );
		printf( "Given path: %s \n", normalImagePath );
		ok = false;
	}
	if(!ok){
		return false;
	}
	return compareTwoFiles( mountedImagePath, normalImagePath, fhm, fhn );
}


bool specialTwoFilesTest( char *mountedImagePath, char *normalImagePath )
{
	int fhm;
	int fhn;
	int fhr;
	char buf[RND_MAX_WRITE_SIZE];
	bool ok = true;
	if ( ( fhm = open( mountedImagePath, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open mounted Image" );
		printf( "Given path: %s \n", mountedImagePath );
		ok = false;
	}
	if ( ( fhn = open( normalImagePath, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open normal Image" );
		printf( "Given path: %s \n", normalImagePath );
		ok = false;
	}
	if ( ( fhr = open( "/dev/urandom", O_RDONLY ) ) == -1 ) {
		perror( "Could not open /dev/urandom" );
		ok = false;
	}
	if(!ok){
		return false;
	}
	special_test_t tests[] = {
		{976314368, 569344},
		{970432512, 1253376},
		{959447040, 692224},
		{782128012, 0},
		{945591351, 0},
		{956534784, 344064},
		{ 966615040, 397312 }, { 906517288, 0 }, 
		{2062985199, 0},			
		{ 966663420, 1097920 },
		{969617408, 327680},
		{957513728, 1105920},
		{964941207, 1183680},
		{958701568, 741376},
		{958701568, 102400},
		{970027008, 20480},
	};

	for ( int i = 0; i < (int) (sizeof( tests ) / sizeof( special_test_t )); i++ ) {
		if ( tests[i].size == 0 ) {
			changeTwoFileSizeAndVerify( mountedImagePath, normalImagePath, tests[i].offset );
		} else {
			generateRandomData( fhr, buf, tests[i].size );
			writeTwoFilesTested( fhm, fhn, buf, tests[i].size, tests[i].offset );
		}
	}

	printf( "\n" );
	return compareTwoFiles( mountedImagePath, normalImagePath, fhm, fhn );
}

void *randomWriteTest( void *args )
{
	char *mountedImagePath = ( (random_write_args_t *)args )->mountedImage;
	char *normalImagePath = ( (random_write_args_t *)args )->normalImage;
	float minSizePercent = ( (random_write_args_t *)args )->minSizePercent;
	float maxSizePercent = ( (random_write_args_t *)args )->maxSizePercent;
	
	int fhm;
	int fhn;
	int fhr;
	srand( (unsigned)time( NULL ) );

	struct stat st;
	stat( normalImagePath, &st );
	size_t startFileSize = st.st_size;
	size_t maxOffset = (size_t)( startFileSize * 1.1L );
	double minFileSize = (double)startFileSize * minSizePercent;
	double fileSizeVariation = (double)startFileSize * ( maxSizePercent - minFileSize );


	char buf[RND_MAX_WRITE_SIZE];

	printf( "===starting random write test ===\n" );
	printf( "mounted image path %s\n", mountedImagePath );
	printf( "normal image path %s\n", normalImagePath );

	bool ok = true;
	if ( ( fhm = open( mountedImagePath, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open mounted Image" );
		printf( "Given path: %s \n", mountedImagePath );
		ok = false;
	}
	if ( ( fhn = open( normalImagePath, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open normal Image" );
		printf( "Given path: %s \n", normalImagePath );
		ok = false;
	}
	if ( ( fhr = open( "/dev/urandom", O_RDONLY ) ) == -1 ) {
		perror( "Could not open /dev/urandom" );
		ok = false;
	}
	if(!ok){
		return (void*) false;
	}
	// RANDOM WRITE LOOP
	printf( "Press any key to cancel\n" );
	while ( randomTestLoop ) {
		//select test
		int r = rand() % 100;

		if ( r < RND_TRUNCATE_PROBABILITY ) {
			// truncate both images
			size_t size = (size_t)( ( rand() % (int)( fileSizeVariation ) ) + minFileSize );

			printf( "change filesize to: %zu\n", size );
			if ( !changeFileSizeAndVerify( mountedImagePath, size ) ) {
				return (void*) false;
			}
			if ( !changeFileSizeAndVerify( normalImagePath, size ) ) {
				return (void*) false;
			}

		} else {
			off_t offset = rand() % maxOffset;
			size_t size = rand() % RND_MAX_WRITE_SIZE;
			size = MAX( size, 1 );
			if ( r > RND_TRUNCATE_PROBABILITY + RND_UNALIGNED_WRITE_PROBABILITY ) {
				offset = offset - ( offset % 4096 );
				size = MAX( size - ( size % 4096 ), 4096 );
			}

			generateRandomData( fhr, buf, size );
			printf( "write offset: %zu size: %zu\n", offset, size );
			if ( !writeSizeTested( fhm, buf, size, offset, "failed to write on mounted image" ) )
				return (void*) false;
			if ( !writeSizeTested( fhn, buf, size, offset, "failed to write on normal image" ) )
				return (void*) false;
		}
	}

	// COMPARE BOTH IMAGES
	printf( "comparing both files: \n\n" );
	compareTwoFiles( mountedImagePath, normalImagePath, fhm, fhn );

	return (void*) true;
}


bool startRandomWriteTest( char *mountedImagePath, char *normalImagePath, float minSizePercent, float maxSizePercent )
{
	// start Thread


	if ( minSizePercent < 0 || maxSizePercent < minSizePercent || maxSizePercent < 0.1 ) {
		printf( "minSizePercent or maxSizePercent of wrong value, reverting to default.\n" );
		minSizePercent = RND_DEFAULT_MIN_SIZE_PERCENT;
		maxSizePercent = RND_DEFAULT_MAX_SIZE_PERCENT;
	}
	printf( "minSizePercent: %.1f%% maxSizePercent: %.1f%%\n", minSizePercent * 100, maxSizePercent * 100 );
	pthread_t tid;
	random_write_args_t *args = malloc( sizeof( random_write_args_t ) );

	args->mountedImage = mountedImagePath;
	args->normalImage = normalImagePath;
	args->minSizePercent = minSizePercent;
	args->maxSizePercent = maxSizePercent;

	bool *result;
	pthread_create( &tid, NULL, &randomWriteTest, args );
	// wait for key
	getchar();
	randomTestLoop = false;

	pthread_join( tid, (void*) &result );
	free( args );
	return result;
}

static const char *optString = "d:c:t:v:r:x:y:z:w:h:";
static const struct option longOpts[] = { { "delay", required_argument, NULL, 'd' },
	{ "testFile", optional_argument, NULL, 'c' }, { "test", required_argument, NULL, 't' },
	{ "verify", required_argument, NULL, 'v' }, { "specialTwoFiles", required_argument, NULL, 'w' },
	{ "randomTest", required_argument, NULL, 'r' }, { "compare", required_argument, NULL, 'x' },
	{ "minSizePercent", required_argument, NULL, 'y' }, { "maxSizePercent", required_argument, NULL, 'z' },
	{ "help", required_argument, NULL, 'h' }, { 0, 0, 0, 0 } };


void printUsageStandardTest()
{
	printf( "Todo information about standard test...\n" );
	printf( "\n" );
	printf( "Instructions on how to use the standard test: \n" );
	printf(
			"1. Generate the test image with -c <path> and copy it to the image location of the dnbd3 server. Also make sure that the cow servers OriginalImageDirectory points to the same Directory or copied in that Directory too. This step is only needed once for setting up.\n" );
	printf( "2. Start the dnbd3 and cow server.\n" );
	printf( "3. Mount the image in cow mode.\n" );
	printf( "4. Run the test with -t <path>, where the path points to the mounted image.\n" );
	printf( "5. Optional verify again with -v <path>.\n" );
	printf(
			"6. Optional unmount the image and then load it again (with -L <path> in the fuse client). Then verify the loaded image with -v <path>.\n" );
	printf( "7. Unmount and merge the image (to merge the image use -m on the fuse client).\n" );
	printf( "8. Verify the merged image from the cow server with -v <path>.\n" );
}

void printUsageRandomTest()
{
	printf( "Todo information about random test...\n" );
	printf( "\n" );
	printf( "Instructions on how to use the random test: \n" );
	printf(
			"1. Generate the test image with -c <path> and copy it to the image location of the dnbd3 server. Also make sure that the cow servers OriginalImageDirectory points to the same Directory or copied in that Directory too. This step is only needed once for setting up.\n" );
	printf( "2. Copy the generated image to another location.\n" );
	printf( "3. Start the dnbd3 and cow server.\n" );
	printf( "4. Mount the image in cow mode.\n" );
	printf(
			"5. Run the test with -t <mountedFile> <normalFile>, where the <mountedFile> points to the mounted image and <normalFile> points to the copied image on the disk.\n" );
	printf( "6. After some time press enter and both images will be compared for equalness." );
	printf( "7. Unmount the image and merge.\n" );
	printf(
			"8. Run -x <mergedFile> <normalFile> where the <mergedFile> points to the merged image and <normalFile> points to the copied image on the disk. This will verify that the merged image is equal to the image on the disk.\n" );
}

void printUsage()
{
	printf( "There are two test variants, the standard test in which different edcases are tested and "
			  "a random test in which data or size changes are randomly made in a mounted file and a file "
			  "located on the normal file system and then compared. "
			  "To get information about the two tests and how to run them use -h test and -h randomTest.\n" );
	printf( "Usage: \n" );
	printf( "   -c  --testFile       <file>                     Creates test file at the path. \n" );
	printf(
			"   -d  --delay          <seconds>                  Delay in Seconds for multiple block write in the standard test.\n" );
	printf( "   -t  --test           <file>                     Runs the standard test procedure. \n" );
	printf( "   -v  --verify         <file>                     verifies a file. \n" );
	printf(
			"   -r  --randomTest     <mountedFile> <normalFile> randomly writes in both file's and after cancel(ENTER) compares them if they are equal.\n" );
	printf(
			"   -y  --minSizePercent <percent>                  sets the minimum size in percent(integer) the file will be reduced to in the random test.\n" );
	printf(
			"   -z  --maxSizePercent <percent>                  sets the maximum size in percent(integer) the file will be enlarged to in the random test.\n" );
	printf( "   -x  --compare        <mountedFile> <normalFile> compares two files for equalness.\n" );
}

int main( int argc, char *argv[] )
{
	if ( argc <= 1 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "--usage" ) == 0 ) {
		printUsage();
		return 0;
	}
	int opt, lidx;

	bool runTestFile = false;
	bool runStandardTest = false;
	bool runVerifyTest = false;
	bool runRandomTest = false;
	bool runCompare = false;
	bool runSpecialTwoFiles = false;
	char fileCreationPath[400];
	char *standardTestPath;
	char *verifyPath;
	char *rndMountedPath;
	char *rndNormalPath;
	size_t generateFileSize = testFileSize;
	float minSizePercent = RND_DEFAULT_MIN_SIZE_PERCENT;
	float maxSizePercent = RND_DEFAULT_MAX_SIZE_PERCENT;

	while ( ( opt = getopt_long( argc, argv, optString, longOpts, &lidx ) ) != -1 ) {
		char *pEnd;
		switch ( opt ) {
		case 'd':

			delay = (int)strtol( optarg, &pEnd, 10 );
			printf( "Delay set to %i\n", delay );
			break;
		case 'c':
			strncpy( fileCreationPath, optarg, 400 );
			if ( optind >= argc && argv[optind] != NULL && argv[optind][0] != '-' ) {
				generateFileSize = (size_t)strtol( argv[optind], &pEnd, 10 );
				++optind;
			}

			runTestFile = true;
			break;
		case 't':
			standardTestPath = optarg;
			runStandardTest = true;
			break;
		case 'v':
			verifyPath = optarg;
			runVerifyTest = true;
			break;
		case 'r':
			printf( "\nasd\n", opt );
			if ( optind >= argc && argv[optind] != NULL && argv[optind][0] != '-' ) {
				printUsage();
				return 0;
			}
			rndMountedPath = optarg;
			rndNormalPath = argv[optind];
			optind++;
			runRandomTest = true;

			break;
		case 'x':
			if ( optind >= argc && argv[optind] != NULL && argv[optind][0] != '-' ) {
				printUsage();
				return 0;
			}
			rndMountedPath = optarg;
			rndNormalPath = argv[optind];
			optind++;
			runCompare = true;
			break;
		case 'w':
			if ( optind >= argc && argv[optind] != NULL && argv[optind][0] != '-' ) {
				printUsage();
				return 0;
			}
			rndMountedPath = optarg;
			rndNormalPath = argv[optind];
			optind++;
			runSpecialTwoFiles = true;
			break;
		case 'y': minSizePercent = ( (float)strtol( optarg, &pEnd, 10 ) ) / 100; break;
		case 'z': maxSizePercent = ( (float)strtol( optarg, &pEnd, 10 ) ) / 100; break;

		case 'h':
			if ( strcmp( optarg, "test" ) == 0 ) {
				printUsageStandardTest();
				return 0;
			} else if ( strcmp( optarg, "randomTest" ) == 0 ) {
				printUsageRandomTest();
				return 0;
			} else {
				printUsage();
				return 0;
			}
			break;
		default:
			printUsage();
			return 0;
			break;
		}
	}
	bool result = true;
	if ( runTestFile ) {
		result = generateTestFile( fileCreationPath, generateFileSize );
	} else if ( runStandardTest ) {
		printf( "starting standard test\n" );
		result = runTest( standardTestPath );
	} else if ( runVerifyTest ) {
		printf( "verifying file \n" );
		result = verifyFinalFile( verifyPath );
	} else if ( runRandomTest ) {
		result = startRandomWriteTest( rndMountedPath, rndNormalPath, minSizePercent, maxSizePercent );
	} else if ( runCompare ) {
		result = startCompareTwoFiles( rndMountedPath, rndNormalPath );
	} else if ( runSpecialTwoFiles ) {
		result = specialTwoFilesTest( rndMountedPath, rndNormalPath );
	} else {
		printUsage();
	}
	if(!result ){
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
