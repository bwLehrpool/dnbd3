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


static bool run = true;

const size_t l2Size = 1024;
const size_t bitfieldByteSize = 40;
const size_t blocksize = 4096;
const size_t l2Capacity = l2Size * blocksize * bitfieldByteSize;

const size_t testFileSize = l2Size * bitfieldByteSize * blocksize * 5;

const char standartValue = 'a';
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
			printCharInHexadecimal( expected, size );
			printf( "Got: \n " );
			printCharInHexadecimal( buff, size );
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

bool testFirstBit()
{
	char buff[blocksize];
	char expected[blocksize];
	memset( expected, 0, blocksize );
	if ( !readSizeTested( fh, buff, 4096, 0, "FirstBit test Failed: read to small" ) )
		return false;

	if ( !compare( buff, expected, 4096, "FirstBit test Failed: initial read" ) )
		return false;
	expected[0] = 1;
	if ( !writeSizeTested( fh, expected, 4096, 0, "FirstBit test Failed: write failed" ) )
		return false;
	if ( !readSizeTested( fh, buff, 4096, 0, "FirstBit test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, 4096, "FirstBit test Failed: write not as expected" ) )
		return false;
	printf( "testFirstBit successful!\n" );
	return true;
}

bool writeOverTwoBlocks()
{
	char buff[blocksize * 2];
	char expected[blocksize * 2];
	memset( expected, 0, blocksize * 2 );
	if ( !readSizeTested( fh, buff, blocksize * 2, blocksize * 3, "writeOverTwoBlocks test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 2, "OverTwoBlocks test Failed: initial read" ) )
		return false;
	memset( expected, 1, blocksize * 2 );
	if ( !writeSizeTested( fh, expected, blocksize * 2, blocksize * 3, "writeOverTwoBlocks test Failed: write failed" ) )
		return false;
	if ( !readSizeTested( fh, buff, blocksize * 2, blocksize * 3, "writeOverTwoBlocks test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 2, "OverTwoBlocks test Failed: write not as expected" ) )
		return false;
	printf( "writeOverTwoBlocks successful!\n" );
	return true;
}

bool writeOverL2()
{
	char buff[blocksize * 2];
	char expected[blocksize * 2];
	memset( expected, 0, blocksize * 2 );
	size_t offset = l2Capacity * 2 - blocksize;
	if ( !readSizeTested( fh, buff, blocksize * 2, offset, "writeOverL2 test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 2, "writeOverL2 test Failed: initial read" ) )
		return false;
	memset( expected, 1, blocksize * 2 );
	if ( !writeSizeTested( fh, expected, blocksize * 2, offset, "writeOverL2 test Failed: write failed" ) )
		return false;
	if ( !readSizeTested( fh, buff, blocksize * 2, offset, "writeOverL2 test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 2, "writeOverL2 test Failed: write not as expected" ) )
		return false;
	printf( "writeOverL2 successful!\n" );
	return true;
}


// perhaps do some initial markers on the file
bool writeNotOnBlockBorder()
{
	char buff[blocksize * 2];
	char expected[blocksize * 2];
	memset( expected, 0, blocksize * 2 );
	size_t offset = blocksize * 11 - blocksize / 2;
	if ( !readSizeTested( fh, buff, blocksize * 2, offset, "writeNotOnBlockBorder test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 2, "writeNotOnBlockBorder test Failed: initial read" ) )
		return false;
	memset( expected, 1, blocksize * 2 );
	if ( !writeSizeTested( fh, expected, blocksize * 2, offset, "writeNotOnBlockBorder test Failed: write failed" ) )
		return false;
	if ( !readSizeTested( fh, buff, blocksize * 2, offset, "writeNotOnBlockBorder test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 2, "writeNotOnBlockBorder test Failed: write not as expected" ) )
		return false;
	printf( "writeNotOnBlockBorder successful!\n" );
	return true;
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
	char buff[blocksize * 10];
	char expected[blocksize * 10];
	memset( expected, 0, blocksize * 10 );
	if ( !readSizeTested(
				  fh, buff, blocksize * 10, testFileSize + l2Capacity, "fileSizeChanges test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 10, "fileSizeChanges test Failed: increased data not 0" ) )
		return false;
	printf( "increased data is 0 as expected\n" );
	// write on increased blocks
	memset( expected, 1, blocksize * 10 );
	if ( !writeSizeTested( fh, expected, blocksize * 10, testFileSize, "fileSizeChanges test Failed: write failed" ) )
		return false;
	if ( !readSizeTested( fh, buff, blocksize * 10, testFileSize, "fileSizeChanges test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 10, "fileSizeChanges test Failed: write on increased size failed" ) )
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
	memset( expected, 0, blocksize * 10 );


	if ( !readSizeTested( fh, buff, blocksize * 10, testFileSize, "fileSizeChanges test Failed: read to small" ) )
		return false;
	if ( !compare( buff, expected, blocksize * 2, "fileSizeChanges test Failed: increased data (second time) not 0" ) )
		return false;
	printf( "fileSizeChanges successful!\n" );
	return true;
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
	if ( !writeOverL2() )
		return;
	if ( !fileSizeChanges() )
		return;
	printf( "All test's successful.\n" );
}


void verifyFinalFile( char *path )
{
	if ( ( fh = open( path, O_RDWR, S_IRUSR | S_IWUSR ) ) == -1 ) {
		perror( "Could not open test file" );
		printf( "Given path: %s \n", path );
		return;
	}
}

void execCommand( char command, char *parameters )
{
	switch ( command ) {
	case 'c':
		if ( parameters[0] == '\0' ) {
			printUsage();
			break;
		}
		generateTestFile( parameters, 3 * l2Capacity );
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
		runTest( parameters );
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