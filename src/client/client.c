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

#include "../types.h"
#include "../version.h"

char *_config_file_name = DEFAULT_CLIENT_CONFIG_FILE;

void dnbd3_print_help(char* argv_0)
{
    printf("Usage: %s -h <host> -p <port> -v <vid> -r <rid> -d <device> || -f file\n", argv_0);
    printf("Start the DNBD3 client.\n");
    printf("-f or --file \t\t Configuration file (default /etc/dnbd3-client.conf)\n");
    printf("-h or --host \t\t Host running dnbd3-server.\n");
    printf("-p or --port \t\t Port used by server.\n");
    printf("-v or --vid \t\t Volume-ID of exported image.\n");
    printf("-r or --rid \t\t Release-ID of exported image.\n");
    printf("-d or --device \t\t DNBD3 device name.\n");
    printf("-c or --changehost \t Change dnbd3-server on device (DEBUG).\n");
    printf("-H or --help \t\t Show this help text and quit.\n");
    printf("-V or --version \t Show version and quit.\n");
    exit(EXIT_SUCCESS);
}

void dnbd3_print_version()
{
    printf("Version: %s\n", VERSION_STRING);
    exit(EXIT_SUCCESS);
}

void dnbd3_connect(char *host, char *port, int vid, int rid, char *dev)
{
    int fd = open(dev, O_WRONLY);

    printf("Connecting %s to %s:%s vid:%i rid:%i\n", dev, host, port, vid, rid);

    if (ioctl(fd, IOCTL_SET_HOST, host) < 0)
        printf("ERROR: ioctl not successful\n");

    if (ioctl(fd, IOCTL_SET_PORT, port) < 0)
        printf("ERROR: ioctl not successful\n");

    if (ioctl(fd, IOCTL_SET_VID, vid) < 0)
        printf("ERROR: ioctl not successful\n");

    if (ioctl(fd, IOCTL_SET_RID, rid) < 0)
        printf("ERROR: ioctl not successful\n");

    if (ioctl(fd, IOCTL_CONNECT) < 0)
        printf("ERROR: ioctl not successful\n");

    close(fd);
}

int main(int argc, char *argv[])
{
    int fd;
    char *host = NULL;
    char *port = NULL;
    int vid = 0;
    int rid = 0;
    char *dev = NULL;
    int change_host = 0;

    int opt = 0;
    int longIndex = 0;
    static const char *optString = "f:h:p:v:r:d:c:HV?";
    static const struct option longOpts[] =
    {
    { "file", required_argument, NULL, 'f' },
    { "host", required_argument, NULL, 'h' },
    { "port", required_argument, NULL, 'p' },
    { "vid", required_argument, NULL, 'v' },
    { "rid", required_argument, NULL, 'r' },
    { "device", required_argument, NULL, 'd' },
    { "changehost", required_argument, NULL, 'c' },
    { "help", no_argument, NULL, 'H' },
    { "version", no_argument, NULL, 'V' }, };

    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

    while (opt != -1)
    {
        switch (opt)
        {
        case 'f':
            _config_file_name = optarg;
            break;
        case 'h':
            host = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'v':
            vid = atoi(optarg);
            break;
        case 'r':
            rid = atoi(optarg);
            break;
        case 'd':
            dev = optarg;
            break;
        case 'c':
            host = optarg;
            change_host = 1;
            break;
        case 'H':
            dnbd3_print_help(argv[0]);
            break;
        case 'V':
            dnbd3_print_version();
            break;
        case '?':
            dnbd3_print_help(argv[0]);
        }
        opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
    }

    // change host
    if (change_host && host && dev && !port && (vid == 0) && (rid == 0))
    {
        fd = open(dev, O_WRONLY);

        if (ioctl(fd, IOCTL_DISCONNECT) < 0)
            printf("ERROR: ioctl not successful\n");

        if (ioctl(fd, IOCTL_SET_HOST, host) < 0)
            printf("ERROR: ioctl not successful\n");

        if (ioctl(fd, IOCTL_CONNECT) < 0)
            printf("ERROR: ioctl not successful\n");

        close(fd);
        exit(EXIT_SUCCESS);
    }

    // connect
    if (host && port && dev && (vid != 0) && (rid != 0))
    {
        dnbd3_connect(host, port, vid, rid, dev);
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
            host = g_key_file_get_string(gkf, groups[i], "server", NULL);
            port = g_key_file_get_string(gkf, groups[i], "port", NULL);
            vid = g_key_file_get_integer(gkf, groups[i], "vid", NULL);
            rid = g_key_file_get_integer(gkf, groups[i], "rid", NULL);
            dev = g_key_file_get_string(gkf, groups[i], "device", NULL);
            dnbd3_connect(host, port, vid, rid, dev);
        }

        g_strfreev(groups);
        g_key_file_free(gkf);
        exit(EXIT_SUCCESS);
    }
    else
    {
        printf("WARN: Config file not found: %s\n", _config_file_name);
    }

    g_key_file_free(gkf);

    dnbd3_print_help(argv[0]);
    exit(EXIT_FAILURE);
}
