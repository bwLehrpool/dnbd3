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


typedef bool ( *func_ptr )();
typedef struct verify_test
{
	off_t offset;
	size_t size;
	func_ptr test;
} verify_test_t;


const size_t l2Size = 1024;
const size_t bitfieldByteSize = 40;
const size_t l2Capacity = l2Size * DNBD3_BLOCK_SIZE * bitfieldByteSize * 8;

const size_t testFileSize = l2Capacity * 2.9L;

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

void generateTestFile( char *path, size_t size )
{
	int fh;
	strcpy( filePath, path );
	if ( ( fh = open( path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not create test file: " );
		return;
	}
	if ( ftruncate( fh, size ) == -1 ) {
		perror( "Error while expanding test file: " );
		return;
	}


	close( fh );
	printf( "Generated Test File of size: %zu bytes. \n", size );
	//todo write markers:
}


void printUsage()
{
	printf( "Press the following for: \n" );
	printf( "   d <delay>     Delay in Seconds for multiple block write (must be first).\n" );
	printf( "   c <path>      Creates test file at the path. \n" );
	printf( "   t <path>      Runs the standard test procedure. \n" );
	printf( "   v <path>      verifies a file. \n" );
}

void printCharInHexadecimal( const char *str, int len )
{
	for ( int i = 0; i < len; ++i ) {
		uint8_t val = str[i];
		char tbl[] = "0123456789ABCDEF";
		printf( "0x" );
		printf( "%c", tbl[val / 16] );
		printf( "%c", tbl[val % 16] );
		printf( " " );
	}
	printf( "\n" );
}

bool compare( char buff[], char expected[], size_t size, char errorMessage[] )
{
	if ( memcmp( buff, expected, size ) != 0 ) {
		perror( errorMessage );
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
	if ( readSize < size ) {
		printf( "%s \n size read: %zu\n Expected %zu\n", error, readSize, size );
		return false;
	}
	return true;
}

bool writeSizeTested( int fh, char *buf, ssize_t size, off_t off, char *error )
{
	if ( pwrite( fh, buf, size, off ) < size ) {
		perror( error );
		return false;
	}
	return true;
}

bool verifySingleBit()
{
	char buff[DNBD3_BLOCK_SIZE];
	char expected[DNBD3_BLOCK_SIZE];
	memset( expected, 0, DNBD3_BLOCK_SIZE );
	expected[0] = 1;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, 0, "SingleBit test Failed: first read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "SingleBit test Failed: first write not as expected" ) )
		return false;

	expected[0] = 0;
	expected[DNBD3_BLOCK_SIZE/2] = 1;
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
	memset( expected, 0, DNBD3_BLOCK_SIZE );
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, 0, "SingleBit test Failed: first read to small" ) )
		return false;

	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "SingleBit test Failed: initial read" ) )
		return false;
	expected[0] = 1;
	if ( !writeSizeTested( fh, expected, DNBD3_BLOCK_SIZE, 0, "SingleBit test Failed: first write failed" ) )
		return false;

	expected[0] = 0;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE, "SingleBit test Failed: second read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "SingleBit test Failed: second read" ) )
		return false;
	expected[0] = 1;
	if ( !writeSizeTested( fh, expected, 1, DNBD3_BLOCK_SIZE + DNBD3_BLOCK_SIZE / 2 , "SingleBit test Failed: second write failed" ) )
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
	memset( expected, 0, DNBD3_BLOCK_SIZE * 2 );
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
	memset( expected, 0, DNBD3_BLOCK_SIZE * 2 );
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
	memset( expected, 0, DNBD3_BLOCK_SIZE * 2 );
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


bool fileSizeChanges()
{
	// increase filesize

	printf( "Truncate file to: %zu\n", testFileSize + 2 * l2Capacity );
	if ( truncate( filePath, testFileSize + 2 * l2Capacity ) != 0 ) {
		perror( "fileSizeChanges test Failed: first truncate failed." );
		return false;
	}
	// verify
	struct stat st;
	stat( filePath, &st );
	size_t size = st.st_size;

	if ( size != testFileSize + 2 * l2Capacity ) {
		printf( "fileSizeChanges test Failed\n expectedSize: %zu\n got: %zu\n", testFileSize + 2 * l2Capacity, size );
		return false;
	}
	// check if increased is 0
	char buff[DNBD3_BLOCK_SIZE * 10];
	char expected[DNBD3_BLOCK_SIZE * 10];
	memset( expected, 0, DNBD3_BLOCK_SIZE * 10 );
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
	if ( truncate( filePath, testFileSize ) != 0 ) {
		perror( "fileSizeChanges test Failed: second truncate failed." );
		return false;
	}
	// verify
	printf( "truncate done, verifying...\n" );
	stat( filePath, &st );
	size = st.st_size;
	if ( size != testFileSize ) {
		printf(
				"fileSizeChanges test Failed, decrease not worked.\n expectedSize: %zu\n got: %zu\n", testFileSize, size );
		return false;
	}
	printf( "size verified\n" );
	// increase again, check its 0 again
	printf( "Truncate file to: %zu\n", testFileSize + 2 * l2Capacity );
	if ( truncate( filePath, testFileSize + 2 * l2Capacity ) != 0 ) {
		perror( "fileSizeChanges test Failed: second increase failed." );
		return false;
	}
	printf( "truncate done, verifying...\n" );
	stat( filePath, &st );
	size = st.st_size;
	if ( size != ( testFileSize + 2 * l2Capacity ) ) {
		printf( "fileSizeChanges test Failed, increase not worked.\n expectedSize: %zu\n got: %zu\n", testFileSize, size );
		return false;
	}
	printf( "size verified\n" );
	memset( expected, 0, DNBD3_BLOCK_SIZE * 10 );


	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE * 10, testFileSize, "fileSizeChanges test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE * 2,
				  "fileSizeChanges test Failed: increased data (second time) not 0" ) )
		return false;
	printf( "fileSizeChanges successful!\n" );
	return true;
}


bool verifyInterleavedTest()
{
	char buff[DNBD3_BLOCK_SIZE * 10];
	char expected[DNBD3_BLOCK_SIZE * 10];
	off_t offset = 35 * DNBD3_BLOCK_SIZE;
	memset( expected, 0, DNBD3_BLOCK_SIZE * 10 );
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
	memset( expected, 0, DNBD3_BLOCK_SIZE * 10 );
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

bool verifyMultipleWrites(){
	size_t size = DNBD3_BLOCK_SIZE * 10 * bitfieldByteSize;
	char buff[size];
	char expected[size];
	off_t offset = 100 * DNBD3_BLOCK_SIZE * bitfieldByteSize;
	memset( expected, 3, size );
	if ( !readSizeTested( fh, buff, size , offset, "multipleWrites test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, size, "multipleWrites: read incorrect data" ) )
		return false;
	printf( "MultipleWrites successful!\n" );
	return true;
}

bool multipleWrites(){
	printf( "starting multipleWrites\n" );
	size_t size = DNBD3_BLOCK_SIZE * 10 * bitfieldByteSize;
	char buff[size];
	char expected[size];
	off_t offset = 100 * DNBD3_BLOCK_SIZE * bitfieldByteSize;
	
	for (int i = 1; i <= 3; i++ ){
		printf( "multipleWrites: %i/3 \n", i );

		memset( expected, i, size );
		if ( !writeSizeTested( fh, expected, size, offset, "multipleWrites: write Failed" ) )
			return false;
		if ( !readSizeTested( fh, buff, size, offset, "multipleWrites test Failed: read to small" ) )
			return false;
		if ( !compare( buff, expected, size, "multipleWrites: read incorrect data" ) )
			return false;
		if( delay > 0 && i < 3 ){
			printf( "waiting %is\n", delay );
			sleep(delay);
		}
	}
	return verifyMultipleWrites();
}



void runTest( char *path )
{
	if ( ( fh = open( path, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open test file" );
		printf( "Given path: %s \n", path );
		return;
	}
	strcpy( filePath, path );
	printf( "file opened: %s\n", path );

	if ( !testSingleBit() )
		return;
	if ( !writeOverTwoBlocks() )
		return;

	if ( !writeNotOnBlockBorder() )
		return;

	if ( !writeOverL2() )
		return;
	if ( !fileSizeChanges() )
		return;
	if ( !interleavedTest() )
		return;
	if ( !multipleWrites() ){
		return;
	}
	if ( !writeLongNonAlignedPattern() ) {
		return;
	}


	printf( "All test's successful.\n" );
}


void verifyTests( verify_test_t *tests )
{
	// offset, size, function

	tests[0] = ( verify_test_t ){ 0, 2 * DNBD3_BLOCK_SIZE, verifySingleBit};
	tests[1] = ( verify_test_t ){ DNBD3_BLOCK_SIZE * 3, DNBD3_BLOCK_SIZE * 3, verifyWriteOverTwoBlocks };
	tests[2] = ( verify_test_t ){ DNBD3_BLOCK_SIZE * 11 - DNBD3_BLOCK_SIZE / 2, DNBD3_BLOCK_SIZE * 2,
		verifyWriteNotOnBlockBorder };
	tests[3] = ( verify_test_t ){ 35 * DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE * 10, verifyInterleavedTest };
	tests[4] = ( verify_test_t ){ 100 * DNBD3_BLOCK_SIZE * bitfieldByteSize, DNBD3_BLOCK_SIZE * 10 * bitfieldByteSize, verifyMultipleWrites };
	tests[5] = ( verify_test_t ){ l2Capacity * 2 - DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE * 2, verifyWriteOverL2 };
	tests[6] = ( verify_test_t ){ l2Capacity * 3 - 1, l2Capacity + 2, verifyLongNonAlignedPattern };
}

void verifyFinalFile( char *path )
{
	if ( ( fh = open( path, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open test file" );
		printf( "Given path: %s \n", path );
		return;
	}
	// verify file size

	size_t fileSize = testFileSize + 2 * l2Capacity;
	struct stat st;
	stat( path, &st );
	size_t size = st.st_size;
	if ( size != fileSize ) {
		printf( "verify Failed, wrong file size\n expectedSize: %zu\n got: %zu\n", fileSize, size );
		return;
	}

	// read to whole file

	int maxReadSize = DNBD3_BLOCK_SIZE * COW_BITFIELD_SIZE * 8;
	char buffer[maxReadSize];
	char emptyData[maxReadSize];
	memset( emptyData, 0, maxReadSize );
	size_t offset = 0;


	int numberOfTests = 7;
	verify_test_t tests[numberOfTests];
	verifyTests( tests );

	int currentTest = 0;


	while ( offset < fileSize ) {
		size_t sizeToRead = MIN( (size_t)maxReadSize, fileSize - offset );
		if ( currentTest < numberOfTests ) {
			sizeToRead = MIN( sizeToRead, tests[currentTest].offset - offset );
		}
		if ( currentTest < numberOfTests && tests[currentTest].offset == (off_t)offset ) {
			if ( !tests[currentTest].test() ) {
				return;
			}
			offset += tests[currentTest].size;
			currentTest++;
		} else {
			ssize_t sizeRead = pread( fh, buffer, sizeToRead, offset );
			if ( sizeRead <= 0 ) {
				perror( "Error while reading data: " );
				printf( "verify failed. \n" );
				return;
			}
			if ( !compare( buffer, emptyData, sizeRead, "verify failed. Expected 0 data" ) ) {
				printf( "Offset: %zu \n", offset );
				return;
			}
			offset += (size_t)sizeRead;
		}
	}

	printf( "file verified successful.\n" );
}



int main( int argc, char *argv[] )
{
	if ( argc < 1 ){
		printUsage();
		return 0;
	}
	while ( 1 )
    {
        int result = getopt( argc, argv, "d:c:t:v:" );
        if ( result == -1 ) break; /* end of list */
		char * pEnd;
        switch (result)
        {
            case 'd':
				
				delay =(int) strtol (optarg, &pEnd, 10);
				printf("Delay set to %i\n", delay);
                break;
            case 'c':
				generateTestFile( optarg, testFileSize );
				break;
			case 't':
				printf( "starting standard test\n" );
				runTest( optarg );
				break;
			case 'v':
				printf( "verifying file \n" );
				verifyFinalFile( optarg );
		break;
            default: 
				printUsage();
				return 0;
                break;
        }
    }
	return 0;
}


