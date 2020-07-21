#include "helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>


void printLog( log_info *info )
{
	FILE *logFile;

	// Create logfile

	logFile = fopen( "log.txt", "w" );
	if ( logFile == NULL ) {
		printf( "Error creating/opening log.txt\n" );
		return;
	}

	//rewind(file);
	fprintf( logFile, "ImageSize: %"PRIu64" MiB\n", (uint64_t)( info->imageSize/ ( 1024ll*1024ll ) ) );
	fprintf( logFile, "ReceivedMiB: %"PRIu64" MiB\n", (uint64_t)( info->receivedBytes/ ( 1024ll*1024ll ) ) );
	fprintf( logFile, "imageBlockCount: %"PRIu64"\n", info->imageBlockCount );
	fprintf( logFile, "Blocksize: 4KiB\n\n" );
	fprintf( logFile, "Block access count:\n" );

	uint64_t i = 0;
	for ( ; i < info->imageBlockCount; i++ ) {
		if ( i % 50 == 0 ) {
			fprintf( logFile, "\n" );
		}
		fprintf( logFile, "%i ", (int) info->blockRequestCount[i] );
	}
	fprintf( logFile, "\n" );
	fclose( logFile );
}
