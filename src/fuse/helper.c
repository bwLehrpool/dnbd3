/*
 * Helper functions for imageFuse
 * by Stephan Schwaer, January 2014
 */

#include "helper.h"
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
	fprintf( logFile, "ImageSize: %"PRIu64" MiB\n", ( uint64_t )( info->imageSize/ ( 1024ll*1024ll ) ) );
	fprintf( logFile, "ReceivedMiB: %"PRIu64" MiB\n", ( uint64_t )( info->receivedBytes/ ( 1024ll*1024ll ) ) );
	fprintf( logFile, "imageBlockCount: %"PRIu64"\n", info->imageBlockCount );
	fprintf( logFile, "Blocksize: 4KiB\n\n" );
	fprintf( logFile, "Block access count:\n" );

	uint64_t i = 0;
	for ( ; i < info->imageBlockCount; i++ ) {
		if ( i % 50 == 0 ) {
			fprintf( logFile, "\n" );
		}
		fprintf( logFile, "%i ", ( int ) info->blockRequestCount[i] );
	}
	fprintf( logFile, "\n" );
	fclose( logFile );
}

bool sock_printable( struct sockaddr *addr, socklen_t addrLen, char *output, int len )
{
	char host[100], port[10];
	int ret = getnameinfo( addr, addrLen, host, 100, port, 10, NI_NUMERICHOST | NI_NUMERICSERV );
	if ( ret == 0 ) {
		snprintf( output, len, "[%s]:%s", host, port );
	}
	return ret == 0;
}

// TODO: Pretty much same as in server/*
int connect_to_server( char *server_address, int port )
{
	const int on = 1;
	int sock = -1;
	struct addrinfo hints, *res, *ptr;
	char portStr[6];

	// Set hints for local addresses.
	memset( &hints, 0, sizeof( hints ) );
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf( portStr, sizeof portStr, "%d", port );
	if ( getaddrinfo( server_address, portStr, &hints, &res ) != 0 || res == NULL ) {
		return false;
	}
	// Attempt to bind to all of the addresses as long as there's room in the poll list
	for ( ptr = res; ptr != NULL; ptr = ptr->ai_next ) {
		char bla[100];
		if ( !sock_printable( ( struct sockaddr * ) ptr->ai_addr, ptr->ai_addrlen, bla, 100 ) ) {
			snprintf( bla, 100, "[invalid]" );
		}
		printf( "Trying to connect to %s ", bla );
		sock = socket( ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol );
		if ( sock < 0 ) {
			printf( "...cannot create socket, errno=%d\n", errno );
			sock = -1;
			continue;
		}
		setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof( on ) );
		if ( ptr->ai_family == PF_INET6 ) {
			setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof( on ) );
		}
		if ( connect( sock, ptr->ai_addr, ptr->ai_addrlen ) < 0 ) {
			// if ( bind( sock, ptr->ai_addr, ptr->ai_addrlen ) == -1 ) {
			printf( "...socket Error, errno=%d\n", errno );
			close( sock );
			sock = -1;
			continue;
		} else {
			printf( "... connecting successful!\n" );
			break;
		}
	}

	freeaddrinfo( res );
	return sock;
}

