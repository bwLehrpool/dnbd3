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
#include <glib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

#include "../types.h"
#include "../version.h"

char *_config_file_name = DEFAULT_CLIENT_CONFIG_FILE;

void dnbd3_print_help(char* argv_0)
{
    printf("\nUsage: %s\n"
            "\t-h <host> -i <image name> [-r <rid>] -d <device> [-a <KB>] || -f <file> || -c <device>\n\n", argv_0);
    printf("Start the DNBD3 client.\n");
    printf("-f or --file \t\t Configuration file (default /etc/dnbd3-client.conf)\n");
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

static void dnbd3_get_ip(char* hostname, uint8_t *target, uint8_t *addrtype)
{
    struct hostent *host;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        printf("FATAL: Unknown host '%s'\n", hostname);
        exit(EXIT_FAILURE);
    }

    *addrtype = (uint8_t)host->h_addrtype;
    if (host->h_addrtype == AF_INET)
    	memcpy(target, host->h_addr, 4);
    else if (host->h_addrtype == AF_INET6)
    	memcpy(target, host->h_addr, 16);
    else
    {
    	printf("FATAL: Unknown address type: %d\n", host->h_addrtype);
    	exit(EXIT_FAILURE);
    }
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
    msg.port = htons(PORT);
    msg.addrtype = 0;

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
    { "version", no_argument, NULL, 'V' }, };

    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

    while (opt != -1)
    {
        switch (opt)
        {
        case 'f':
            _config_file_name = strdup(optarg);
            break;
        case 'h':
            dnbd3_get_ip(optarg, msg.addr, &msg.addrtype);
            printf("Host set to %s (type %d)\n", inet_ntoa(*(struct in_addr*)msg.addr), (int)msg.addrtype);
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
            dnbd3_get_ip(optarg, msg.addr, &msg.addrtype);
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
    if (close_dev && msg.addrtype == 0 && dev && (msg.imgname == NULL))
    {
        fd = open(dev, O_WRONLY);
        printf("INFO: Closing device %s\n", dev);

        const int ret = ioctl(fd, IOCTL_OPEN, &msg);
        if (ret < 0)
        {
            printf("ERROR: ioctl not successful (close, errcode: %d)\n", ret);
            exit(EXIT_FAILURE);
        }

        close(fd);
        exit(EXIT_SUCCESS);
    }

    // switch host
    if (switch_host && msg.addrtype != 0 && dev && (msg.imgname == NULL))
    {
        fd = open(dev, O_WRONLY);
        printf("INFO: Switching device %s to %s\n", dev, "<fixme>");

        if (ioctl(fd, IOCTL_SWITCH, &msg) < 0)
        {
            printf("ERROR: ioctl not successful (switch)\n");
            exit(EXIT_FAILURE);
        }

        close(fd);
        exit(EXIT_SUCCESS);
    }

    // connect
    if (msg.addrtype != 0 && dev && (msg.imgname != NULL))
    {
    	msg.imgnamelen = (uint16_t)strlen(msg.imgname);
        fd = open(dev, O_WRONLY);
        printf("INFO: Connecting %s to %s (%s rid:%i)\n", dev, "<fixme>", msg.imgname, msg.rid);

        const int ret = ioctl(fd, IOCTL_OPEN, &msg);
        if (ret < 0)
        {
            printf("ERROR: ioctl not successful (connect, errcode: %d)\n", ret);
            exit(EXIT_FAILURE);
        }

        close(fd);
        exit(EXIT_SUCCESS);
    }

    // use configuration file if exist
    GKeyFile* gkf;
    int i = 0;
    size_t j = 0;

    gkf = g_key_file_new();

    if (g_key_file_load_from_file(gkf, _config_file_name, G_KEY_FILE_NONE, NULL))
    {
        gchar **groups = NULL;
        groups = g_key_file_get_groups(gkf, &j);

        for (i = 0; i < j; i++)
        {
            dnbd3_get_ip(g_key_file_get_string(gkf, groups[i], "server", NULL), msg.addr, &msg.addrtype);
            msg.imgname = g_key_file_get_string(gkf, groups[i], "name", NULL);
            msg.rid = g_key_file_get_integer(gkf, groups[i], "rid", NULL);
            dev = g_key_file_get_string(gkf, groups[i], "device", NULL);

            msg.read_ahead_kb = g_key_file_get_integer(gkf, groups[i], "ahead", NULL);
            if (!msg.read_ahead_kb)
                msg.read_ahead_kb = DEFAULT_READ_AHEAD_KB;

            fd = open(dev, O_WRONLY);
            printf("INFO: Connecting %s to %s (%s rid:%i)\n", dev, "<fixme>", msg.imgname, msg.rid);

            const int ret = ioctl(fd, IOCTL_OPEN, &msg);
            if (ret < 0)
            {
                printf("ERROR: ioctl not successful (config file, errcode: %d)\n", ret);
                exit(EXIT_FAILURE);
            }

            close(fd);
        }

        g_strfreev(groups);
        g_key_file_free(gkf);
        exit(EXIT_SUCCESS);
    }
    else
    {
        printf("ERROR: Config file not found: %s\n", _config_file_name);
    }

    g_key_file_free(gkf);

    dnbd3_print_help(argv[0]);
    exit(EXIT_FAILURE);
}
