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

#include "../types.h"
#include "../version.h"

void dnbd3_print_help(char* argv_0)
{
    printf("Usage: %s -H <host> -p <port> -i <image-id> -d <device>\n", argv_0);
    printf("Start the DNBD3 client.\n");
    printf("-H or --host \t\t Host running dnbd3-server.\n");
    printf("-p or --port \t\t Port used by server.\n");
    printf("-i or --image \t\t Exported image ID.\n");
    printf("-d or --device \t\t DNBD3 device name.\n");
    printf("-c or --changehost \t Change dnbd3-server on device (DEBUG).\n");
    printf("-h or --help \t\t Show this help text and quit.\n");
    printf("-v or --version \t Show version and quit.\n");
    exit(EXIT_SUCCESS);
}

void dnbd3_print_version()
{
    printf("Version: %s\n", VERSION_STRING);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    int fd;
    char *host = NULL;
    char *port = NULL;
    char *image_id = NULL;
    char *dev = NULL;
    int change_host = 0;

    int opt = 0;
    int longIndex = 0;
    static const char *optString = "H:p:i:d:c:hv?";
    static const struct option longOpts[] =
    {
    { "host", required_argument, NULL, 'H' },
    { "port", required_argument, NULL, 'p' },
    { "image", required_argument, NULL, 'i' },
    { "device", required_argument, NULL, 'd' },
    { "changehost", required_argument, NULL, 'c' },
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'v' }, };

    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

    while (opt != -1)
    {
        switch (opt)
        {
        case 'H':
            host = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'i':
            image_id = optarg;
            break;
        case 'd':
            dev = optarg;
            break;
        case 'c':
            host = optarg;
            change_host = 1;
            break;
        case 'h':
            dnbd3_print_help(argv[0]);
            break;
        case 'v':
            dnbd3_print_version();
            break;
        case '?':
            dnbd3_print_help(argv[0]);
        }
        opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
    }

    // change host
    if (change_host && host && dev && !port && !image_id)
    {
        fd = open(dev, O_RDONLY);

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
    if (host && port && dev && image_id)
    {
        fd = open(dev, O_RDONLY);

        if (ioctl(fd, IOCTL_SET_HOST, host) < 0)
            printf("ERROR: ioctl not successful\n");

        if (ioctl(fd, IOCTL_SET_PORT, port) < 0)
            printf("ERROR: ioctl not successful\n");

        if (ioctl(fd, IOCTL_SET_IMAGE, image_id) < 0)
            printf("ERROR: ioctl not successful\n");

        if (ioctl(fd, IOCTL_CONNECT) < 0)
            printf("ERROR: ioctl not successful\n");

        close(fd);
        exit(EXIT_SUCCESS);
    }

    dnbd3_print_help(argv[0]);
    exit(EXIT_FAILURE);
}
