/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
 *
 * This file may be licensed under the terms of the
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

#include <dnbd3/config/client.h>
#include <dnbd3/types.h>
#include <dnbd3/version.h>
#include <dnbd3/build.h>

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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCK_PATH "/run/dnbd3.socket"
#define SOCK_BUFFER 1000
#define DEV_LEN 15
#define MAX_DEVS 50
#define TMP_STR_LEN 100

static int openDevices[MAX_DEVS];
static const char *optString = "h:i:r:d:a:cs:SA:R:HV?k";
static const struct option longOpts[] = {
        { "host", required_argument, NULL, 'h' },
        { "image", required_argument, NULL, 'i' },
        { "rid", required_argument, NULL, 'r' },
        { "device", required_argument, NULL, 'd' },
        { "ahead", required_argument, NULL, 'a' },
        { "close", no_argument, NULL, 'c' },
        { "switch", required_argument, NULL, 's' },
		{ "sticky", no_argument, NULL, 'S' },
        { "add", required_argument, NULL, 'A' },
        { "remove", required_argument, NULL, 'R' },
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
static void dnbd3_daemon_action(int client, int uid, int argc, char **argv);
static int dnbd3_daemon_ioctl(int uid, char *device, int action, const char *actionName, char *host);
static char* dnbd3_daemon_open(int uid, char *host, char *image, int rid, int readAhead, const bool doLearnNewServers);
static int dnbd3_daemon_send(int argc, char **argv);
static void dnbd3_print_help(char *argv_0);
static void dnbd3_print_version();

/**
 * Convert a host and port (network byte order) to printable representation.
 * Worst case required buffer len is 48, eg. [1234:1234:1234:1234:1234:1234:1234:1234]:12345 (+ \0)
 * Returns true on success, false on error
 */
static char host_to_string(const dnbd3_host_t *host, char *target, size_t targetlen)
{
	// Worst case: Port 5 chars, ':' to separate ip and port 1 char, terminating null 1 char = 7, [] for IPv6
	if ( targetlen < 10 ) return false;
	if ( host->type == HOST_IP6 ) {
		*target++ = '[';
		inet_ntop( AF_INET6, host->addr, target, (socklen_t)targetlen - 10 );
		target += strlen( target );
		*target++ = ']';
	} else if ( host->type == HOST_IP4 ) {
		inet_ntop( AF_INET, host->addr, target, (socklen_t)targetlen - 8 );
		target += strlen( target );
	} else {
		snprintf( target, targetlen, "<?addrtype=%d>", (int)host->type );
		return false;
	}
	*target = '\0';
	if ( host->port != 0 ) {
		// There are still at least 7 bytes left in the buffer, port is at most 5 bytes + ':' + '\0' = 7
		snprintf( target, 7, ":%d", (int)ntohs( host->port ) );
	}
	return true;
}


/**
 * Parse IPv4 or IPv6 address in string representation to a suitable format usable by the BSD socket library
 * @string eg. "1.2.3.4" or "2a01::10:5", optially with port appended, eg "1.2.3.4:6666" or "[2a01::10:5]:6666"
 * @af will contain either HOST_IP4 or HOST_IP6
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
		host->type = HOST_IP4;
		memcpy( host->addr, &v4, 4 );
		host->port = htons( PORT );
		return 1;
	}
	// Try IPv6 without port
	if ( 1 == inet_pton( AF_INET6, string, &v6 ) ) {
		host->type = HOST_IP6;
		memcpy( host->addr, &v6, 16 );
		host->port = htons( PORT );
		return 1;
	}

	// Scan for port
	char *portpos = NULL, *ptr = string;
	while ( *ptr ) {
		if ( *ptr == ':' ) {
			portpos = ptr;
		}
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
		host->type = HOST_IP4;
		memcpy( host->addr, &v4, 4 );
		return 1;
	}
	// Try IPv6 with port
	if ( 1 == inet_pton( AF_INET6, string, &v6 ) ) {
		host->type = HOST_IP6;
		memcpy( host->addr, &v6, 16 );
		return 1;
	}

	// FAIL
	return 0;
}

static int dnbd3_get_ip(char *hostname, dnbd3_host_t *host)
{
	if ( parse_address( hostname, host ) ) return true;
	// TODO: Parse port too for host names
	struct hostent *hent;
	if ( (hent = gethostbyname( hostname )) == NULL ) {
		printf( "Unknown host '%s'\n", hostname );
		return false;
	}

	if ( hent->h_addrtype == AF_INET ) {
		host->type = HOST_IP4;
		memcpy( host->addr, hent->h_addr, 4);
	} else if (hent->h_addrtype == AF_INET6) {
		host->type = HOST_IP6;
		memcpy(host->addr, hent->h_addr, 16);
	} else {
		printf("FATAL: Unknown address type: %d\n", hent->h_addrtype);
		return false;
	}
	host->port = htons( PORT );
	return true;
}

/* parses hosts from space separated cmdln string, resolves them and saves them into hosts */
static int dnbd3_get_resolved_hosts(char *hosts_str, dnbd3_host_t *hosts, const size_t hosts_len)
{
	char *hosts_current_token = hosts_str;
	char *hosts_last_host;
	int hosts_index = 0;
	char host_str[TMP_STR_LEN];
	size_t host_str_len = 0;

	do {
		/* get next host from string */
		while ( *hosts_current_token == ' ' ) {
			hosts_current_token++;
		}

		/* buffer substring of host to get ip from it */
		hosts_last_host = strchr( hosts_current_token, ' ' );
		host_str_len = (hosts_last_host == NULL ? TMP_STR_LEN : (size_t)(hosts_last_host - hosts_current_token) + 1);
		if ( host_str_len > TMP_STR_LEN ) {
			host_str_len = TMP_STR_LEN;
		}

		snprintf( host_str, host_str_len, "%s", hosts_current_token );

		if ( !dnbd3_get_ip( host_str, &hosts[hosts_index] ) )
			return false;

		hosts_index++;

		/* continue processing of hosts */
		hosts_current_token = hosts_last_host + 1;

	} while ( hosts_last_host != NULL && hosts_index < hosts_len );

	return hosts_index;
}

int main(int argc, char *argv[])
{
	char *dev = NULL;
	char host[50];

	int action = -1;
	bool learnNewServers = true;
	int active_device_num = 0;

	dnbd3_ioctl_t msg = { .len = (uint16_t)sizeof(msg) };
	msg.hosts_num = 0;
	msg.read_ahead_kb = DEFAULT_READ_AHEAD_KB;
	msg.imgname = NULL;

	int opt = 0;
	int longIndex = 0;

	// In case the client was invoked as a suid binary, change uid back to original user
	// and warn the user as this was legacy mode
	if ( geteuid() == 0 && getuid() != 0 ) {
		fprintf( stderr, "Warning! %s is a setuid binary. This is deprecated and not needed anymore.\n", argv[0] );
		fprintf( stderr, "Switching back o user %d\n", (int)getuid() );
		setgid( getgid() );
		setuid( getuid() );
	}

	opt = getopt_long( argc, argv, optString, longOpts, &longIndex );

	while ( opt != -1 ) {
		switch ( opt ) {
		case 'h':
			msg.hosts_num = (uint8_t)dnbd3_get_resolved_hosts( optarg, msg.hosts, MAX_HOSTS_PER_IOCTL );
			if ( !msg.hosts_num )
				exit( EXIT_FAILURE );
			break;
		case 'i':
			action = IOCTL_OPEN;
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
			action = IOCTL_CLOSE;
			break;
		case 's':
			dnbd3_get_ip( optarg, &msg.hosts[0] );
			msg.hosts_num = 1;
			action = IOCTL_SWITCH;
			break;
		case 'S':
			learnNewServers = false;
			break;
		case 'A':
			dnbd3_get_ip( optarg, &msg.hosts[0] );
			msg.hosts_num = 1;
			action = IOCTL_ADD_SRV;
			break;
		case 'R':
			dnbd3_get_ip( optarg, &msg.hosts[0] );
			msg.hosts_num = 1;
			action = IOCTL_REM_SRV;
			break;
		case 'H':
			dnbd3_print_help( argv[0] );
			exit( EXIT_SUCCESS );
			break;
		case 'V':
			dnbd3_print_version( argv[0] );
			exit( EXIT_SUCCESS );
			break;
		case '?':
			dnbd3_print_help( argv[0] );
			exit( EXIT_SUCCESS );
			break;
		case 'D':
			dnbd3_client_daemon();
			break;
		}
		opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
	}

	/* abort if sticky mode is set and image will not be opened */
	if ( !learnNewServers && action != IOCTL_OPEN ) {
		printf( "ERROR: sticky mode can only be set if image will be opened.\n" );
		exit( EXIT_FAILURE );
	}

	msg.use_server_provided_alts = learnNewServers;

	// See if socket exists, if so, try to send to daemon
	struct stat st;
	if ( stat( SOCK_PATH, &st ) == 0 ) {
		if ( dnbd3_daemon_send( argc, argv ) ) exit( 0 );
		printf( "\nFailed.\n" );
		exit( 1 );
	}

	// Direct requests

	// close device
	if ( action == IOCTL_CLOSE && msg.hosts_num == 0 && dev && (msg.imgname == NULL )) {
		printf( "INFO: Closing device %s\n", dev );
		if ( dnbd3_ioctl( dev, IOCTL_CLOSE, &msg ) == 0 ) exit( EXIT_SUCCESS );
		printf( "Couldn't close device.\n" );
		exit( EXIT_FAILURE );
	}

	// switch host
	if ( (action == IOCTL_SWITCH || action == IOCTL_ADD_SRV || action == IOCTL_REM_SRV) && msg.hosts_num == 1 && dev && (msg.imgname == NULL )) {
		host_to_string( &msg.hosts[0], host, 50 );
		if ( action == IOCTL_SWITCH ) printf( "INFO: Switching device %s to %s\n", dev, host );
		if ( action == IOCTL_ADD_SRV ) printf( "INFO: %s: adding %s\n", dev, host );
		if ( action == IOCTL_REM_SRV ) printf( "INFO: %s: removing %s\n", dev, host );
		if ( dnbd3_ioctl( dev, action, &msg ) == 0 ) exit( EXIT_SUCCESS );
		printf( "Failed! Maybe the device is not connected?\n" );
		exit( EXIT_FAILURE );
	}

	// connect
	if ( action == IOCTL_OPEN && msg.hosts_num > 0 && dev && (msg.imgname != NULL )) {
		printf( "INFO: Connecting device %s for image %s\n", dev, msg.imgname );
		active_device_num = dnbd3_ioctl( dev, IOCTL_OPEN, &msg );
		if ( active_device_num >= 0 ) {
			host_to_string( &msg.hosts[active_device_num], host, 50 );
			printf( "INFO: Device %s for image %s is connected to server %s\n", dev, msg.imgname, host);
			exit( EXIT_SUCCESS );
		} else {
			printf( "ERROR: connecting device failed. Maybe it's already connected?\n" );
			exit( EXIT_FAILURE );
		}
	}

	dnbd3_print_help( argv[0] );
	exit( EXIT_FAILURE );
}

static int dnbd3_ioctl(const char *dev, const int command, dnbd3_ioctl_t * const msg)
{
	const int fd = open( dev, O_WRONLY );
	if ( fd == -1 ) {
		perror( "open() failed" );
		return -ENODEV;
	}
	if ( msg != NULL && msg->imgname != NULL ) {
		msg->imgnamelen = (uint16_t)strlen( msg->imgname );
	}
	const int ret = ioctl( fd, command, msg );
	if ( ret < 0 ) {
		perror( "ioctl() failed" );
	}
	close( fd );
	return ret;
}

static void dnbd3_client_daemon()
{
	int listener, client;
	struct sockaddr_un addrLocal, addrRemote;
	char buffer[SOCK_BUFFER];
	struct timeval tv;
	int done, ret, len;
	socklen_t socklen;
	struct ucred ucred;
	int fdTest;

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
	fchmod( listener, 0666 );
	chmod( SOCK_PATH, 0666 );
	if ( listen( listener, 5 ) == -1 ) {
		perror( "listen" );
		unlink( addrLocal.sun_path );
		exit( 1 );
	}

	fdTest = open( "/dev/dnbd0", O_RDWR );
	if ( fdTest == -1 ) {
		perror( "Opening /dev/dnbd0 failed. Daemon will probably not work" );
	} else {
		close( fdTest );
	}

	memset( openDevices, -1, sizeof(openDevices) );

	for (;;) {
		socklen = sizeof(addrRemote);
		if ( (client = accept( listener, (struct sockaddr *)&addrRemote, &socklen )) == -1 ) {
			printf( "accept error %d\n", (int)errno);
			sleep( 1 );
			continue;
		}

		socklen = sizeof(ucred);
		if ( getsockopt( client, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen ) == -1 ) {
			perror( "Could not get credentials of connection" );
			close( client );
			continue;
		}
		printf("Call from user %d\n", (int)ucred.uid );

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt( client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) );
		setsockopt( client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv) );

		ret = recv( client, &len, sizeof(len), MSG_WAITALL );
		if ( ret != sizeof(len) || len <= 0 || len + 4 > SOCK_BUFFER ) { // Leave a little room (at least one byte for the appended nullchar)
			printf( "Error reading length field (ret: %d, len: %d)\n", ret, len );
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
			char *argv[20] = { "dnbd3-client" };
			while ( pos < end && argc < 20 ) {
				while ( *pos == '\0' ) {
					if ( ++pos >= end ) break;
				}
				if ( pos >= end ) break;
				argv[argc++] = pos;
				//printf("Arg %d: '%s'\n", argc, pos);
				while ( *pos != '\0' ) { // This will always be in bounds because of -4 above
					if ( ++pos >= end ) break;
				}
			}
			dnbd3_daemon_action( client, (int)ucred.uid, argc, argv );
		}

		close( client );
	}
}

static void dnbd3_daemon_action(int client, int uid, int argc, char **argv)
{
	int opt = 0;
	int longIndex = 0;
	char *host = NULL, *image = NULL, *device = NULL;
	int rid = 0, killMe = false, ahead = 512;
	int len;
	int action = -1;
	const char *actionName = NULL;
	bool learnNewServers = true;

	optind = 1;
	opt = getopt_long( argc, argv, optString, longOpts, &longIndex );

	while ( opt != -1 ) {
		switch ( opt ) {
		case 'd':
			device = optarg;
			break;
		case 'h':
			host = optarg;
			break;
		case 'i':
			image = optarg;
			action = IOCTL_OPEN;
			actionName = "Open";
			break;
		case 'r':
			rid = atoi( optarg );
			break;
		case 'c':
			action = IOCTL_CLOSE;
			actionName = "Close";
			break;
		case 'S':
			learnNewServers = false;
			break;
		case 'A':
			action = IOCTL_ADD_SRV;
			actionName = "Add Server";
			break;
		case 'R':
			action = IOCTL_REM_SRV;
			actionName = "Remove Server";
			break;
		case 'a':
			ahead = atoi( optarg );
			break;
		case 'k':
			killMe = true;
			break;
		}
		opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
	}

	if ( killMe ) {
		if ( uid != geteuid() ) {
			printf( "Ignoring kill request by user %d\n", uid );
			close( client );
			return;
		}
		printf( "Received kill request; exiting.\n" );
		unlink( SOCK_PATH );
		close( client );
		exit( 0 );
	}

	if ( (action == IOCTL_CLOSE || ((action == IOCTL_ADD_SRV || action == IOCTL_REM_SRV) && host != NULL)) && device != NULL ) {
		if ( dnbd3_daemon_ioctl( uid, device, action, actionName, host ) ) {
			len = 0;
		} else {
			len = -1;
		}
		send( client, &len, sizeof(len), 0 );
		return;
	}
	if ( action == IOCTL_OPEN && host != NULL && image != NULL && rid >= 0 ) {
		device = dnbd3_daemon_open( uid, host, image, rid, ahead, learnNewServers);
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

static int dnbd3_daemon_ioctl(int uid, char *device, int action, const char *actionName, char *host)
{
	int index = -1;
	char dev[DEV_LEN];
	if ( strncmp( device, "/dev/dnbd", 9 ) == 0 ) {
		index = atoi( device + 9 );
	} else {
		index = atoi( device );
	}
	dnbd3_ioctl_t msg = { .len = (uint16_t)sizeof(msg) };
	if ( host != NULL ) {
		dnbd3_get_ip( host, &msg.hosts[0] );
	}
	if ( index < 0 || index >= MAX_DEVS ) {
		printf( "%s request with invalid device id %d\n", actionName, index );
		return false;
	}
	snprintf( dev, DEV_LEN, "/dev/dnbd%d", index );
	if ( openDevices[index] == -1 ) {
		printf( "%s request by %d for closed device %s\n", actionName, uid, dev );
		return true;
	}
	if ( openDevices[index] != uid ) {
		printf( "%s: User %d cannot access %s owned by %d\n", actionName, uid, dev, openDevices[index] );
		return false;
	}
	if ( dnbd3_ioctl( dev, action, &msg ) == 0 ) {
		printf( "%s request for device %s of user %d successful\n", actionName, dev, uid );
		openDevices[index] = -1;
		return true;
	}
	printf( "%s: Error on device %s, requested by %d\n", actionName, dev, uid );
	return false;
}

static char* dnbd3_daemon_open(int uid, char *host, char *image, int rid, int readAhead, const bool doLearnNewServers)
{
	int i, sameUser = 0;
	struct stat st;
	static char dev[DEV_LEN];
	printf( "Opening a device for %s on %s\n", image, host );
	// Check number of open devices
	if ( uid != 0 ) {
		for ( i = 0; i < MAX_DEVS; ++i ) {
			if ( openDevices[i] == uid ) sameUser++;
		}
		if ( sameUser > 1 ) {
			printf( "Ignoring request by %d as there are already %d open devices for that user.\n", uid, sameUser );
			return NULL;
		}
	}
	// Find free device
	for ( i = 0; i < MAX_DEVS; ++i ) {
		if ( openDevices[i] != -1 )
			continue;
		snprintf( dev, DEV_LEN, "/dev/dnbd%d", i );
		if ( stat( dev, &st ) == -1 ) {
			break;
		}
		// Open
		dnbd3_ioctl_t msg;
		msg.len = (uint16_t)sizeof(msg);
		if ( !dnbd3_get_ip( host, &msg.hosts[0] ) ) {
			printf( "Cannot parse host address %s\n", host );
			return NULL ;
		}
		msg.imgname = image;
		msg.imgnamelen = strlen( image );
		msg.rid = rid;
		msg.use_server_provided_alts = doLearnNewServers;
		msg.read_ahead_kb = readAhead;
		if ( dnbd3_ioctl( dev, IOCTL_OPEN, &msg ) >= 0 ) {
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
	int s, i, len;
	struct sockaddr_un remote;
	char buffer[SOCK_BUFFER];

	if ( (s = socket( AF_UNIX, SOCK_STREAM, 0 )) == -1 ) {
		perror( "socket" );
		return false;
	}

	remote.sun_family = AF_UNIX;
	snprintf( remote.sun_path, sizeof(remote.sun_path), "%s", SOCK_PATH );
	if ( connect( s, (struct sockaddr *)&remote, sizeof(remote) ) == -1 ) {
		perror( "connect" );
		close( s );
		return false;
	}
	// (Re)build argument string into a single one, arguments separated by null chars
	char *pos = buffer;
	char *end = buffer + SOCK_BUFFER;
	for (i = 1; i < argc && pos < end; ++i) {
		pos += snprintf( pos, end - pos, "%s", argv[i] ) + 1;
	}
	// Send
	len = (int)(pos - buffer);
	if ( send( s, &len, sizeof(len), 0 ) != sizeof(len) || send( s, buffer, len, 0 ) != len ) {
		perror( "Sending request to daemon failed" );
		close( s );
		return false;
	}
	// Read reply
	if ( recv( s, &len, sizeof(len), MSG_WAITALL ) != sizeof(len) ) {
		perror( "Reading length-field from daemon failed" );
		close( s );
		return false;
	}
	if ( len <= 0 ) {
		printf( "Daemon returned exit code %d\n", -len );
		close( s );
		exit( -len );
	}
	if ( len + 4 > SOCK_BUFFER ) {
		printf( "Reply too long (is %d bytes)\n", len );
		close( s );
		return false;
	}
	if ( recv( s, buffer, len, MSG_WAITALL ) != len ) {
		perror( "Reading reply payload from daemon failed" );
		close( s );
		return false;
	}
	buffer[len] = '\0';
	printf( "%s", buffer );
	return true;
}

static void dnbd3_print_help(char *argv_0)
{
	printf( "Usage: %s\n", argv_0 );
	printf( "       -h <host> -i <image name> [-r <rid>] -d <device> [-a <KB>] || -c -d <device>\n\n" );
	printf( "Start the DNBD3 client.\n\n" );
	printf( "-h or --host \t\t List of space separated hosts to use.\n" );
	printf( "-i or --image \t\t Image name of exported image.\n" );
	printf( "-r or --rid \t\t Release-ID of exported image (default 0, latest).\n" );
	printf( "-d or --device \t\t DNBD3 device name.\n" );
	printf( "-a or --ahead \t\t Read ahead in KByte (default %i).\n", DEFAULT_READ_AHEAD_KB );
	printf( "-c or --close \t\t Disconnect and close device.\n" );
	printf( "-s or --switch \t\t Switch dnbd3-server on device (DEBUG).\n" );
	printf( "-S or --sticky \t\t Use only servers from command line (no learning from servers)\n" );
	printf( "-A or --add \t\t Add given dnbd3-server on device.\n");
	printf( "-R or --remove \t\t Remove given dnbd3-server on device.\n");
	printf( "-H or --help \t\t Show this help text and quit.\n" );
	printf( "-V or --version \t Show version and quit.\n\n" );
	printf( "      --daemon \t\t Run as helper daemon\n" );
	printf( "      --kill \t\t Kill running helper daemon\n\n" );
	printf( "The helper daemon makes it possible for normal users to connect dnbd3 devices.\n" );
}

void dnbd3_print_version()
{
	printf( "dnbd3-client version: %s\n", DNBD3_VERSION_LONG );
	printf( "Built: %s\n", DNBD3_BUILD_DATE );
}
