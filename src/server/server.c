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
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

#include <pthread.h>

#include "../types.h"
#include "../version.h"

#include "hashtable.h"

void print_help(char* argv_0)
{

	printf("Usage: %s [OPTIONS]...\n", argv_0);
	printf("Start the DNBD3 server\n");
	printf("-f or --file \t\t Configuration file\n \t\t\t (default /etc/dnbd3-server.conf)\n");
	printf("-h or --help \t\t Show this help text and quit\n");
	printf("-v or --version \t Show version and quit\n");
	exit(0);
}

void print_version()
{
	printf("Version: %s\n", VERSION_STRING);
	exit(0);
}

void handle_sigpipe(int signum)
{
	printf("ERROR: Received signal SIGPIPE, Broken pipe (errno: %i)\n", errno);
	return;
}

void *handle_query(void *client_socket)
{
	int image_file = -1;
	off_t filesize = 0;
	int sock = (int) client_socket;
	struct dnbd3_request request;
	struct dnbd3_reply reply;
	uint16_t cmd;

	while (recv(sock, &request, sizeof(struct dnbd3_request), MSG_WAITALL) > 0)
	{
		cmd = request.cmd;
		switch (cmd)
		{
		case CMD_GET_SIZE:
			image_file = open(ht_search(request.image_id), O_RDONLY);
			if (image_file < 0)
			{
				printf("ERROR: Client requested an unknown image id.\n");
				filesize = 0;
			}
			else
			{
				struct stat st;
				fstat(image_file, &st);
				filesize = st.st_size;
			}

			reply.cmd = request.cmd;
			reply.filesize = filesize;
			send(sock, (char *) &reply, sizeof(struct dnbd3_reply), 0);
			break;

		case CMD_GET_BLOCK:
			if (image_file < 0)
				break;

			reply.cmd = request.cmd;
			memcpy(reply.handle, request.handle, sizeof(request.handle));
			send(sock, (char *) &reply, sizeof(struct dnbd3_reply), 0);

			if (sendfile(sock, image_file, (off_t *) &request.offset, request.size) <0)
				printf("ERROR: sendfile returned -1\n");

			break;

		default:
			printf("ERROR: Unknown command\n");
			break;
		}

	}
	close(sock);
	printf("Client exit.\n");
	pthread_exit((void *)0);
}

int main(int argc, char* argv[])
{
	char *config_file_name = DEFAULT_CONFIG_FILE;

	int opt = 0;
	int longIndex = 0;
	static const char *optString = "f:hv?";
	static const struct option longOpts[] =
	{
	{ "file", required_argument, NULL, 'f' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' } };

	opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

	while (opt != -1)
	{
		switch (opt)
		{
		case 'f':
			config_file_name = optarg;
			break;
		case 'h':
			print_help(argv[0]);
			break;
		case 'v':
			print_version();
			break;
		case '?':
			exit(1);
		}
		opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
	}

	// parse config file
	ht_create();
	FILE *config_file = fopen(config_file_name , "r");
	if (config_file == NULL)
	{
		printf("ERROR: Config file not found: %s\n", config_file_name);
		exit(EXIT_FAILURE);
	}
	char line[MAX_FILE_NAME + 1 + MAX_FILE_ID];
	char* image_name = NULL;
	char* image_id = NULL;
	while (fgets (line , sizeof(line) , config_file) != NULL )
	{
		sscanf (line, "%as %as", &image_name, &image_id);
		if (ht_insert(image_id, image_name) < 0)
		{
			printf("ERROR: Image name or ID is too big\n");
			exit(EXIT_FAILURE);
		}
	}

	// setup network
	signal(SIGPIPE, handle_sigpipe);

	struct sockaddr_in server;
	struct sockaddr_in client;
	int sock, fd;
	unsigned int len;

	// Create socket
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		printf("ERROR: Socket failure\n");
		exit(EXIT_FAILURE);
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET; // IPv4
	server.sin_addr.s_addr = htonl(INADDR_ANY); // Take all IPs
	server.sin_port = htons(PORT); // set port number

	// Bind to socket
	if (bind(sock, (struct sockaddr*) &server, sizeof(server)) < 0)
	{
		printf("ERROR: Bind failure\n");
		exit(EXIT_FAILURE);
	}

	// Listen on socket
	if (listen(sock, 50) == -1)
	{
		printf("ERROR: Listen failure\n");
		exit(EXIT_FAILURE);
	}

	printf("INFO: Server is ready...\n");

	while (1)
	{
		len = sizeof(client);
		fd = accept(sock, (struct sockaddr*) &client, &len);
		if (fd < 0)
		{
			printf("ERROR: Accept failure\n");
			exit(EXIT_FAILURE);
		}
		printf("INFO: Client: %s connected\n", inet_ntoa(client.sin_addr));

		// FIXME: catch SIGKILL/SIGTERM and close all socket before exit
		pthread_t thread;
		pthread_create(&(thread), NULL, handle_query, (void *) fd);
		pthread_detach(thread);
	}
	return EXIT_SUCCESS;
}
