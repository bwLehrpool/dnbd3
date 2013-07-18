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

#include "../types.h"
#include "../version.h"

void dnbd3_print_help(char *argv_0)
{
	printf("\nUsage: %s\n"
	       "\t-h <host> -i <image name> [-r <rid>] -d <device> [-a <KB>] || -f <file> || -c <device>\n\n", argv_0);
	printf("Start the DNBD3 client.\n");
	//printf("-f or --file \t\t Configuration file (default /etc/dnbd3-client.conf)\n");
	printf("-h or --host \t\t Host running dnbd3-server.\n");
	printf("-i or --image \t\t Image name of exported image.\n");
	printf("-r or --rid \t\t Release-ID of exported image (default 0, latest).\n");
	printf("-d or --device \t\t DNBD3 device name.\n");
	printf("-a or --ahead \t\t Read ahead in KByte (default %i).\n", DEFAULT_READ_AHEAD_KB);
	printf("-c or --close \t\t Disconnect and close device.\n");
	printf("-s or --switch \t\t Switch dnbd3-server on device (DEBUG).\n");
	printf("-H or --help \t\t Show this help text and quit.\n");
	printf("-V or --version \t Show version and quit.\n\n");
	exit(EXIT_SUCCESS);
}

void dnbd3_print_version()
{
	printf("Version: %s\n", VERSION_STRING);
	exit(EXIT_SUCCESS);
}

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
	if (1 == inet_pton(AF_INET, string, &v4))
	{
		host->type = AF_INET;
		memcpy(host->addr, &v4, 4);
		host->port = htons(PORT);
		return 1;
	}
	// Try IPv6 without port
	if (1 == inet_pton(AF_INET6, string, &v6))
	{
		host->type = AF_INET6;
		memcpy(host->addr, &v6, 16);
		host->port = htons(PORT);
		return 1;
	}

	// Scan for port
	char *portpos = NULL, *ptr = string;
	while (*ptr)
	{
		if (*ptr == ':')
			portpos = ptr;
		++ptr;
	}
	if (portpos == NULL)
		return 0; // No port in string
	// Consider IP being surrounded by [ ]
	if (*string == '[' && *(portpos - 1) == ']')
	{
		++string;
		*(portpos - 1) = '\0';
	}
	*portpos++ = '\0';
	int p = atoi(portpos);
	if (p < 1 || p > 65535)
		return 0; // Invalid port
	host->port = htons((uint16_t)p);

	// Try IPv4 with port
	if (1 == inet_pton(AF_INET, string, &v4))
	{
		host->type = AF_INET;
		memcpy(host->addr, &v4, 4);
		return 1;
	}
	// Try IPv6 with port
	if (1 == inet_pton(AF_INET6, string, &v6))
	{
		host->type = AF_INET6;
		memcpy(host->addr, &v6, 16);
		return 1;
	}

	// FAIL
	return 0;
}

static void dnbd3_get_ip(char *hostname, dnbd3_host_t *host)
{
	if (parse_address(hostname, host))
		return;
	// TODO: Parse port too for host names
	struct hostent *hent;
	if ((hent = gethostbyname(hostname)) == NULL)
	{
		printf("FATAL: Unknown host '%s'\n", hostname);
		exit(EXIT_FAILURE);
	}

	host->type = (uint8_t)hent->h_addrtype;
	if (hent->h_addrtype == AF_INET)
		memcpy(host->addr, hent->h_addr, 4);
	else if (hent->h_addrtype == AF_INET6)
		memcpy(host->addr, hent->h_addr, 16);
	else
	{
		printf("FATAL: Unknown address type: %d\n", hent->h_addrtype);
		exit(EXIT_FAILURE);
	}
	host->port = htons(PORT);
}

int main(int argc, char *argv[])
{
	int fd;
	char *dev = NULL;

	int close_dev = 0;
	int switch_host = 0;

	dnbd3_ioctl_t msg;
	memset(&msg, 0, sizeof(dnbd3_ioctl_t));
	msg.len = (uint16_t)sizeof(dnbd3_ioctl_t);
	msg.read_ahead_kb = DEFAULT_READ_AHEAD_KB;
	msg.host.port = htons(PORT);
	msg.host.type = 0;
	msg.imgname = NULL;
	msg.is_server = FALSE;

	int opt = 0;
	int longIndex = 0;
	static const char *optString = "f:h:i:r:d:a:c:s:HV?";
	static const struct option longOpts[] =
	{
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
	};

	opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

	while (opt != -1)
	{
		switch (opt)
		{
		case 'f':
			break;
		case 'h':
			dnbd3_get_ip(optarg, &msg.host);
			break;
		case 'i':
			msg.imgname = strdup(optarg);
			printf("Image: %s\n", msg.imgname);
			break;
		case 'r':
			msg.rid = atoi(optarg);
			break;
		case 'd':
			dev = strdup(optarg);
			printf("Device is %s\n", dev);
			break;
		case 'a':
			msg.read_ahead_kb = atoi(optarg);
			break;
		case 'c':
			dev = strdup(optarg);
			close_dev = 1;
			break;
		case 's':
			dnbd3_get_ip(optarg, &msg.host);
			switch_host = 1;
			break;
		case 'H':
			dnbd3_print_help(argv[0]);
			break;
		case 'V':
			dnbd3_print_version();
			break;
		case '?':
			dnbd3_print_help(argv[0]);
			break;
		}
		opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
	}

	// close device
	if (close_dev && msg.host.type == 0 && dev && (msg.imgname == NULL))
	{
		fd = open(dev, O_WRONLY);
		printf("INFO: Closing device %s\n", dev);

		const int ret = ioctl(fd, IOCTL_CLOSE, &msg);
		if (ret < 0)
		{
			printf("ERROR: ioctl not successful (close, %s (%d))\n", strerror(-ret), ret);
			exit(EXIT_FAILURE);
		}

		close(fd);
		exit(EXIT_SUCCESS);
	}

	// switch host
	if (switch_host && msg.host.type != 0 && dev && (msg.imgname == NULL))
	{
		fd = open(dev, O_WRONLY);
		printf("INFO: Switching device %s to %s\n", dev, "<fixme>");

		const int ret = ioctl(fd, IOCTL_SWITCH, &msg);
		if (ret < 0)
		{
			printf("ERROR: ioctl not successful (switch, %s (%d))\n", strerror(-ret), ret);
			exit(EXIT_FAILURE);
		}

		close(fd);
		exit(EXIT_SUCCESS);
	}

	// connect
	if (msg.host.type != 0 && dev && (msg.imgname != NULL))
	{
		msg.imgnamelen = (uint16_t)strlen(msg.imgname);
		fd = open(dev, O_WRONLY);
		printf("INFO: Connecting %s to %s (%s rid:%i)\n", dev, "<fixme>", msg.imgname, msg.rid);

		const int ret = ioctl(fd, IOCTL_OPEN, &msg);
		if (ret < 0)
		{
			printf("ERROR: ioctl not successful (connect, %s (%d))\n", strerror(-ret), ret);
			exit(EXIT_FAILURE);
		}

		close(fd);
		exit(EXIT_SUCCESS);
	}

	dnbd3_print_help(argv[0]);
	exit(EXIT_FAILURE);
}
