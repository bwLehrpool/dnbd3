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
const size_t l2Capacity = l2Size * DNBD3_BLOCK_SIZE * bitfieldByteSize;

const size_t testFileSize = l2Size * bitfieldByteSize * DNBD3_BLOCK_SIZE * 8L * 2.9L;


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
	printf( "Press the follwing for: \n" );
	printf( "   c <path>      Creates test file at the path. \n" );
	printf( "   t <path>      Runs the standart test procedure. \n" );
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

bool verifyTestFirstBit()
{
	char buff[DNBD3_BLOCK_SIZE];
	char expected[DNBD3_BLOCK_SIZE];
	memset( expected, 0, DNBD3_BLOCK_SIZE );
	expected[0] = 1;
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, 0, "FirstBit test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "FirstBit test Failed: write not as expected" ) )
		return false;
	printf( "testFirstBit successful!\n" );
	return true;
}

bool testFirstBit()
{
	char buff[DNBD3_BLOCK_SIZE];
	char expected[DNBD3_BLOCK_SIZE];
	memset( expected, 0, DNBD3_BLOCK_SIZE );
	if ( !readSizeTested( fh, buff, DNBD3_BLOCK_SIZE, 0, "FirstBit test Failed: read to small" ) )
		return false;

	if ( !compare( buff, expected, DNBD3_BLOCK_SIZE, "FirstBit test Failed: initial read" ) )
		return false;
	expected[0] = 1;
	if ( !writeSizeTested( fh, expected, DNBD3_BLOCK_SIZE, 0, "FirstBit test Failed: write failed" ) )
		return false;
	return verifyTestFirstBit();
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
	printf( "truncate done, verifing...\n" );
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
	printf( "truncate done, verifing...\n" );
	stat( filePath, &st );
	size = st.st_size;
	if ( size != ( testFileSize + 2 * l2Capacity ) ) {
		printf( "fileSizeChanges test Failed, increse not worked.\n expectedSize: %zu\n got: %zu\n", testFileSize, size );
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

void runTest( char *path )
{
	if ( ( fh = open( path, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open test file" );
		printf( "Given path: %s \n", path );
		return;
	}
	strcpy( filePath, path );
	printf( "file opened: %s\n", path );

	if ( !testFirstBit() )
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

	printf( "All test's successful.\n" );
}


void verifyTests( verify_test_t *tests )
{
	// offset, size, function

	tests[0] = ( verify_test_t ){ 0, DNBD3_BLOCK_SIZE, verifyTestFirstBit };
	tests[1] = ( verify_test_t ){ DNBD3_BLOCK_SIZE * 3, DNBD3_BLOCK_SIZE * 3, verifyWriteOverTwoBlocks };
	tests[2] = ( verify_test_t ){ DNBD3_BLOCK_SIZE * 11 - DNBD3_BLOCK_SIZE / 2, DNBD3_BLOCK_SIZE * 2,
		verifyWriteNotOnBlockBorder };
	tests[3] = ( verify_test_t ){ 35 * DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE * 10, verifyInterleavedTest };
	tests[4] = ( verify_test_t ){ l2Capacity * 2 - DNBD3_BLOCK_SIZE, DNBD3_BLOCK_SIZE * 2, verifyWriteOverL2 };
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

	int maxReadSize = DNBD3_BLOCK_SIZE * COW_BITFIELD_SIZE;
	char buffer[maxReadSize];
	char emptyData[maxReadSize];
	memset( emptyData, 0, maxReadSize );
	size_t offset = 0;


	int numberOfTests = 5;
	verify_test_t tests[numberOfTests];
	verifyTests( tests );

	int currentTest = 0;



	while ( offset < fileSize ) {
		size_t sizeToRead = MIN( maxReadSize, fileSize - offset );
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

void execCommand( char command, char *parameters )
{
	switch ( command ) {
	case 'c':
		if ( parameters[0] == '\0' ) {
			printUsage();
			break;
		}
		generateTestFile( parameters, testFileSize );
		break;
	case 't':
		if ( parameters[0] == '\0' ) {
			printUsage();
			break;
		}
		printf( "starting standart test\n" );
		runTest( parameters );
		break;
	case 'v':
		if ( parameters[0] == '\0' ) {
			printUsage();
			break;
		}
		printf( "verifing file \n" );
		verifyFinalFile( parameters );
		break;
	default:
		printf( "Command not Found \n" );
		printUsage();
		break;
	}
}


int main( int argc, char *argv[] )
{
	if ( argc == 3 ) {
		execCommand( argv[1][0], argv[2] );
	} else {
		printUsage();
	}
	return 0;
}


/*
  methode to generate test file.
*/
/* Tests to impelment:

1. Read & Writes over block borders (l1, l2, metadata).
2. Parallel writes on different unchanged blocks.(test for race condition on cow file increse).
3. Test truncate file (smaller and lager).
4. Random read writes.
5. Read & Writes over data which is partially in cow file
6. Read & Write single byte
*/