/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
 *
 * This file may be licensed under the terms of of the
 * GNU General Public License Version 2 (the ``GPL'').
 *
 * Software distributed under the License is distributed
 * on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied. See the GPL for the specific language
 * governing rights and limitations.
 *
 * You should have received a copy of the GPL along with this
 * program. If not, go to http://www.gnu.org/licenses/gpl.html
 * or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "../types.h"
#include "../version.h"

#define SOCK_PATH "/var/run/dnbd3.socket"
#define SOCK_BUFFER 1000
#define DEV_LEN 15
#define MAX_DEVS 50

static int openDevices[MAX_DEVS];
static const char *optString = "f:h:i:r:d:a:c:s:HV?";
static const struct option longOpts[] = {
        { "file", required_argument, NULL, 'f' },
        { "host", required_argument, NULL, 'h' },
        { "image", required_argument, NULL, 'i' },
        { "rid", required_argument, NULL, 'r' },
        { "device", required_argument, NULL, 'd' },
        { "ahead", required_argument, NULL, 'a' },
        { "close", required_argument, NULL, 'c' },
        { "switch", required_argument, NULL, 's' },
        { "help", no_argument, NULL, 'H' },
        { "version", no_argument, NULL, 'V' },
        { "daemon", no_argument, NULL, 'D' },
        { "nofork", no_argument, NULL, 'N' },
        { "kill", no_argument, NULL, 'k' },
        { "user", required_argument, NULL, 'U' }, // Only used in daemon mode
        { 0, 0, 0, 0 }
};

static int dnbd3_ioctl(const char *dev, const int command, dnbd3_ioctl_t * const msg);
static void dnbd3_client_daemon();
static void dnbd3_daemon_action(int client, int argc, char **argv);
static int dnbd3_daemon_close(int uid, char *device);
static char* dnbd3_daemon_open(int uid, char *host, char *image, int rid, int readAhead);
static int dnbd3_daemon_send(int argc, char **argv);
static void dnbd3_print_help(char *argv_0);
static void dnbd3_print_version();

/**
 * Parse IPv4 or IPv6 address in string representation to a suitable format usable by the BSD socket library
 * @string eg. "1.2.3.4" or "2a01::10:5", optially with port appended, eg "1.2.3.4:6666" or "[2a01::10:5]:6666"
 * @af will contain either AF_INET or AF_INET6
 * @addr will contain the address in network representation
 * @port will contain the port in network representation, defaulting to #define PORT if none was given
 * returns 1 on success, 0 in failure. contents of af, addr and port are undefined in the latter case
 * !! Contents of @string might be modified by this function !!
 */
static char parse_address(char *string, dnbd3_host_t *host)
{
	struct in_addr v4;
	struct in6_addr v6;

	// Try IPv4 without port
	if ( 1 == inet_pton( AF_INET, string, &v4 ) ) {
		host->type = AF_INET;
		memcpy( host->addr, &v4, 4 );
		host->port = htons( PORT );
		return 1;
	}
	// Try IPv6 without port
	if ( 1 == inet_pton( AF_INET6, string, &v6 ) ) {
		host->type = AF_INET6;
		memcpy( host->addr, &v6, 16 );
		host->port = htons( PORT );
		return 1;
	}

	// Scan for port
	char *portpos = NULL, *ptr = string;
	while ( *ptr ) {
		if ( *ptr == ':' )
		portpos = ptr;
		++ptr;
	}
	if ( portpos == NULL ) return 0; // No port in string
	// Consider IP being surrounded by [ ]
	if ( *string == '[' && *(portpos - 1) == ']' ) {
		++string;
		*(portpos - 1) = '\0';
	}
	*portpos++ = '\0';
	int p = atoi( portpos );
	if ( p < 1 || p > 65535 )
	return 0; // Invalid port
	host->port = htons( (uint16_t)p );

	// Try IPv4 with port
	if ( 1 == inet_pton( AF_INET, string, &v4 ) ) {
		host->type = AF_INET;
		memcpy( host->addr, &v4, 4 );
		return 1;
	}
	// Try IPv6 with port
	if ( 1 == inet_pton( AF_INET6, string, &v6 ) ) {
		host->type = AF_INET6;
		memcpy( host->addr, &v6, 16 );
		return 1;
	}

	// FAIL
	return 0;
}

static int dnbd3_get_ip(char *hostname, dnbd3_host_t *host)
{
	if ( parse_address( hostname, host ) ) return TRUE;
	// TODO: Parse port too for host names
	struct hostent *hent;
	if ( (hent = gethostbyname( hostname )) == NULL ) {
		printf( "Unknown host '%s'\n", hostname );
		return FALSE;
	}

	host->type = (uint8_t)hent->h_addrtype;
	if ( hent->h_addrtype == AF_INET ) {
		memcpy( host->addr, hent->h_addr, 4);
	} else if (hent->h_addrtype == AF_INET6) {
		memcpy(host->addr, hent->h_addr, 16);
	} else {
		printf("FATAL: Unknown address type: %d\n", hent->h_addrtype);
		return FALSE;
	}
	host->port = htons( PORT );
	return TRUE;
}

int main(int argc, char *argv[])
{
	char *dev = NULL;

	int close_dev = 0;
	int switch_host = 0;

	dnbd3_ioctl_t msg;
	memset( &msg, 0, sizeof(dnbd3_ioctl_t) );
	msg.len = (uint16_t)sizeof(dnbd3_ioctl_t);
	msg.read_ahead_kb = DEFAULT_READ_AHEAD_KB;
	msg.host.port = htons( PORT );
	msg.host.type = 0;
	msg.imgname = NULL;
	msg.is_server = FALSE;

	int opt = 0;
	int longIndex = 0;

	opt = getopt_long( argc, argv, optString, longOpts, &longIndex );

	while ( opt != -1 ) {
		switch ( opt ) {
		case 'f':
			break;
		case 'h':
			if ( !dnbd3_get_ip( optarg, &msg.host ) ) exit( EXIT_FAILURE );
			break;
		case 'i':
			msg.imgname = strdup( optarg );
			break;
		case 'r':
			msg.rid = atoi( optarg );
			break;
		case 'd':
			dev = strdup( optarg );
			printf( "Device is %s\n", dev );
			break;
		case 'a':
			msg.read_ahead_kb = atoi( optarg );
			break;
		case 'c':
			dev = strdup( optarg );
			close_dev = 1;
			break;
		case 's':
			dnbd3_get_ip( optarg, &msg.host );
			switch_host = 1;
			break;
		case 'H':
			dnbd3_print_help( argv[0] );
			break;
		case 'V':
			dnbd3_print_version();
			break;
		case '?':
			dnbd3_print_help( argv[0] );
			break;
		case 'D':
			dnbd3_client_daemon();
			break;
		}
		opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
	}

	// See if socket exists, if so, try to send to daemon
	struct stat st;
	if ( stat( SOCK_PATH, &st ) == 0 ) {
		if ( dnbd3_daemon_send( argc, argv ) ) exit( 0 );
		printf( "Failed.\n" );
		exit( 1 );
	}

	// Direct requests

	// In case the client was invoked as a suid binary, change uid back to original user
	// when being used for direct ioctl, so that the device's permissions are taken into account
	if ( geteuid() == 0 ) {
		setgid( getgid() );
		setuid( getuid() );
	}

	// close device
	if ( close_dev && msg.host.type == 0 && dev && (msg.imgname == NULL )) {
		printf( "INFO: Closing device %s\n", dev );
		if ( dnbd3_ioctl( dev, IOCTL_CLOSE, &msg ) ) exit( EXIT_SUCCESS );
		printf( "Couldn't close device.\n" );
		exit( EXIT_FAILURE );
	}

	// switch host
	if ( switch_host && msg.host.type != 0 && dev && (msg.imgname == NULL )) {
		printf( "INFO: Switching device %s to %s\n", dev, "<fixme>" );
		if ( dnbd3_ioctl( dev, IOCTL_SWITCH, &msg ) ) exit( EXIT_SUCCESS );
		printf( "Switching server failed. Maybe the device is not connected?\n" );
		exit( EXIT_FAILURE );
	}

	// connect
	if ( msg.host.type != 0 && dev && (msg.imgname != NULL )) {
		printf( "INFO: Connecting device %s to %s for image %s\n", dev, "<fixme>", msg.imgname );
		if ( dnbd3_ioctl( dev, IOCTL_OPEN, &msg ) ) exit( EXIT_SUCCESS );
		printf( "ERROR: connecting device failed. Maybe it's already connected?\n" );
		exit( EXIT_FAILURE );
	}

	dnbd3_print_help( argv[0] );
	exit( EXIT_FAILURE );
}

static int dnbd3_ioctl(const char *dev, const int command, dnbd3_ioctl_t * const msg)
{
	const int fd = open( dev, O_WRONLY );
	if ( fd < 0 ) {
		printf( "open() for %s failed.\n", dev );
		return FALSE;
	}
	if ( msg != NULL && msg->imgname != NULL ) msg->imgnamelen = (uint16_t)strlen( msg->imgname );
	const int ret = ioctl( fd, command, msg );
	if ( ret < 0 ) {
		printf( "ioctl() failed.\n" );
	}
	close( fd );
	return ret >= 0;
}

static void dnbd3_client_daemon()
{
	int listener, client;
	struct sockaddr_un addrLocal, addrRemote;
	char buffer[SOCK_BUFFER];
	struct timeval tv;
	int done, ret, len;
	socklen_t socklen;

	if ( geteuid() != 0 ) {
		printf( "Only root can run the dnbd3-client in daemon mode!\n" );
		exit( 1 );
	}

	if ( (listener = socket( AF_UNIX, SOCK_STREAM, 0 )) == -1 ) {
		perror( "socket" );
		exit( 1 );
	}

	addrLocal.sun_family = AF_UNIX;
	snprintf( addrLocal.sun_path, sizeof(addrLocal.sun_path), "%s", SOCK_PATH );
	unlink( addrLocal.sun_path );
	if ( bind( listener, (struct sockaddr *)&addrLocal, sizeof(addrLocal) ) < 0 ) {
		perror( "bind" );
		exit( 1 );
	}
	chmod( addrLocal.sun_path, 0600 );
	if ( listen( listener, 5 ) == -1 ) {
		perror( "listen" );
		exit( 1 );
	}

	memset( openDevices, -1, sizeof(openDevices) );

	for (;;) {
		socklen = sizeof(addrRemote);
		if ( (client = accept( listener, (struct sockaddr *)&addrRemote, &socklen )) == -1 ) {
			printf( "accept error %d\n", (int)errno);
			sleep( 1 );
			continue;
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt( client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) );
		setsockopt( client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv) );

		ret = recv( client, &len, sizeof(len), MSG_WAITALL );
		if ( ret != sizeof(len) || len <= 0 || len + 4 > SOCK_BUFFER ) { // Leave a little room (at least one byte for the appended nullchar)
			printf( "Error reading length field\n" );
			close( client );
			continue;
		}
		done = recv( client, buffer, len, MSG_WAITALL );

		if ( done != len ) {
			printf( "receiving payload from client failed (%d/%d)\n", done, len );
		} else {
			buffer[len] = '\0';
			char *pos = buffer, *end = buffer + len;
			int argc = 1;
			char *argv[20] = { 0 };
			while ( pos < end ) {
				argv[argc++] = pos;
				while ( *++pos != '\0' ) { // This will always be in bounds because of -4 above
					if ( pos >= end ) break;
				}
				++pos;
			}
			dnbd3_daemon_action( client, argc, argv );
		}

		close( client );
	}
}

static void dnbd3_daemon_action(int client, int argc, char **argv)
{
	int opt = 0;
	int longIndex = 0;
	char *host = NULL, *image = NULL, *device = NULL;
	int rid = 0, uid = 0, killMe = FALSE, ahead = 512;
	int len;

	optind = 1;
	opt = getopt_long( argc, argv, optString, longOpts, &longIndex );

	while ( opt != -1 ) {
		switch ( opt ) {
		case 'h':
			host = optarg;
			break;
		case 'i':
			image = optarg;
			break;
		case 'r':
			rid = atoi( optarg );
			break;
		case 'U':
			uid = atoi( optarg );
			break;
		case 'c':
			device = optarg;
			break;
		case 'a':
			ahead = atoi( optarg );
			break;
		case 'k':
			killMe = TRUE;
			break;
		}
		opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
	}

	if ( killMe ) {
		if ( uid != 0 ) {
			printf( "Ignoring kill request by user %d\n", uid );
			close( client );
			return;
		}
		printf( "Received kill request; exiting.\n" );
		close( client );
		unlink( SOCK_PATH );
		exit( 0 );
	}

	if ( device != NULL ) {
		if ( dnbd3_daemon_close( uid, device ) ) {
			len = 0;
		} else {
			len = -1;
		}
		send( client, &len, sizeof(len), 0 );
		return;
	}
	if ( host != NULL && image != NULL && rid >= 0 ) {
		device = dnbd3_daemon_open( uid, host, image, rid, ahead );
		if ( device != NULL ) {
			len = strlen( device );
			send( client, &len, sizeof(len), 0 );
			send( client, device, len, 0 );
		} else {
			len = -1;
			send( client, &len, sizeof(len), 0 );
		}
		return;
	}
	printf( "Received a client request I cannot understand.\n" );
}

static int dnbd3_daemon_close(int uid, char *device)
{
	int index = -1;
	char dev[DEV_LEN];
	if ( strncmp( device, "/dev/dnbd", 9 ) == 0 ) {
		index = atoi( device + 9 );
	} else {
		index = atoi( device );
	}
	if ( index < 0 || index >= MAX_DEVS ) {
		printf( "Close request with invalid device id %d\n", index );
		return FALSE;
	}
	snprintf( dev, DEV_LEN, "/dev/dnbd%d", index );
	if ( openDevices[index] == -1 ) {
		printf( "Close request by %d for closed device %s\n", uid, dev );
		return TRUE;
	}
	if ( openDevices[index] != uid ) {
		printf( "User %d is not allowed to close %s owned by %d\n", uid, dev, openDevices[index] );
		return FALSE;
	}
	if ( dnbd3_ioctl( dev, IOCTL_CLOSE, NULL ) ) {
		printf( "Closed device %s of user %d\n", dev, uid );
		openDevices[index] = -1;
		return TRUE;
	}
	printf( "Error closing device %s, requested by %d\n", dev, uid );
	return FALSE;
}

static char* dnbd3_daemon_open(int uid, char *host, char *image, int rid, int readAhead)
{
	int i, sameUser = 0;
	struct stat st;
	static char dev[DEV_LEN];
	printf( "Opening a device for %s on %s\n", image, host );
	// Check number of open devices
	for (i = 0; i < MAX_DEVS; ++i) {
		if ( openDevices[i] == uid ) sameUser++;
	}
	if ( sameUser > 1 ) {
		printf( "Ignoring request by %d as there are already %d open devices for that user.\n", uid, sameUser );
		return NULL ;
	}
	// Find free device
	for (i = 0; i < MAX_DEVS; ++i) {
		if ( openDevices[i] != -1 ) continue;
		snprintf( dev, DEV_LEN, "/dev/dnbd%d", i );
		if ( stat( dev, &st ) == -1 ) {
			break;
		}
		// Open
		dnbd3_ioctl_t msg;
		msg.len = (uint16_t)sizeof(msg);
		if ( !dnbd3_get_ip( host, &msg.host ) ) {
			printf( "Cannot parse host address %s\n", host );
			return NULL ;
		}
		msg.imgname = image;
		msg.imgnamelen = strlen( image );
		msg.rid = rid;
		msg.is_server = FALSE;
		msg.read_ahead_kb = readAhead;
		if ( dnbd3_ioctl( dev, IOCTL_OPEN, &msg ) ) {
			openDevices[i] = uid;
			printf( "Device %s now occupied by %d\n", dev, uid );
			return dev;
		}
		printf( "ioctl to open device %s failed, trying next...\n", dev );
	}
	// All devices in use
	printf( "No more free devices. All %d are in use :-(\n", i );
	return NULL ;
}

static int dnbd3_daemon_send(int argc, char **argv)
{
	const int uid = getuid();
	int s, i, len;
	struct sockaddr_un remote;
	char buffer[SOCK_BUFFER];

	if ( (s = socket( AF_UNIX, SOCK_STREAM, 0 )) == -1 ) {
		perror( "socket" );
		return FALSE;
	}

	remote.sun_family = AF_UNIX;
	snprintf( remote.sun_path, sizeof(remote.sun_path), "%s", SOCK_PATH );
	if ( connect( s, (struct sockaddr *)&remote, sizeof(remote) ) == -1 ) {
		perror( "connect" );
		close( s );
		return FALSE;
	}
	// (Re)build argument string into a single one, arguments separated by null chars
	char *pos = buffer, *end = buffer + SOCK_BUFFER;
	pos += snprintf( pos, end - pos, "--user%c%d", '\0', uid ) + 1;
	for (i = 1; i < argc && pos < end; ++i) {
		pos += snprintf( pos, end - pos, "%s", argv[i] ) + 1;
	}
	// Send
	len = (int)(pos - buffer);
	if ( send( s, &len, sizeof(len), 0 ) != sizeof(len) || send( s, buffer, len, 0 ) != len ) {
		perror( "Sending request to daemon failed" );
		close( s );
		return FALSE;
	}
	// Read reply
	if ( recv( s, &len, sizeof(len), MSG_WAITALL ) != sizeof(len) ) {
		perror( "Reading length-field from daemon failed" );
		close( s );
		return FALSE;
	}
	if ( len <= 0 ) {
		printf( "Daemon returned exit code %d\n", -len );
		close( s );
		exit( -len );
	}
	if ( len + 4 > SOCK_BUFFER ) {
		printf( "Reply too long (is %d bytes)\n", len );
		close( s );
		return FALSE;
	}
	if ( recv( s, buffer, len, MSG_WAITALL ) != len ) {
		perror( "Reading reply payload from daemon failed" );
		close( s );
		return FALSE;
	}
	buffer[len] = '\0';
	printf( "%s", buffer );
	return TRUE;
}

static void dnbd3_print_help(char *argv_0)
{
	printf( "\nUsage: %s\n"
			"\t-h <host> -i <image name> [-r <rid>] -d <device> [-a <KB>] || -c <device>\n\n", argv_0 );
	printf( "Start the DNBD3 client.\n" );
	//printf("-f or --file \t\t Configuration file (default /etc/dnbd3-client.conf)\n");
	printf( "-h or --host \t\t Host running dnbd3-server.\n" );
	printf( "-i or --image \t\t Image name of exported image.\n" );
	printf( "-r or --rid \t\t Release-ID of exported image (default 0, latest).\n" );
	printf( "-d or --device \t\t DNBD3 device name.\n" );
	printf( "-a or --ahead \t\t Read ahead in KByte (default %i).\n", DEFAULT_READ_AHEAD_KB );
	printf( "-c or --close \t\t Disconnect and close device.\n" );
	printf( "-s or --switch \t\t Switch dnbd3-server on device (DEBUG).\n" );
	printf( "-H or --help \t\t Show this help text and quit.\n" );
	printf( "-V or --version \t Show version and quit.\n\n" );
	printf( "\t--daemon \t Run as helper daemon\n" );
	printf( "\t--kill \t Kill running helper daemon\n" );
	printf( "The helper daemon makes it possible for normal users to connect dnbd3 devices.\n" );
	printf( "The client binary needs to be a setuid program for this to work!\n\n" );
	exit( EXIT_SUCCESS );
}

void dnbd3_print_version()
{
	printf( "Version: %s\n", VERSION_STRING );
	exit( EXIT_SUCCESS );
}
