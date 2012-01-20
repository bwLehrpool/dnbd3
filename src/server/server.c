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

int file;
off_t filesize;

void print_help(char* argv_0)
{

	printf("Usage: %s [OPTIONS]...\n", argv_0);
	printf("Start the DNBD3 server.\n");
	printf("-f or --file \t\t File to export.\n");
	printf("-h or --help \t\t Show this help text and quit.\n");
	printf("-v or --version \t Show version and quit.\n");
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
			reply.cmd = request.cmd;
			reply.filesize = filesize;
			send(sock, (char *) &reply, sizeof(struct dnbd3_reply), 0);
			break;

		case CMD_GET_BLOCK:
			reply.cmd = request.cmd;
			memcpy(reply.handle, request.handle, sizeof(request.handle));
			send(sock, (char *) &reply, sizeof(struct dnbd3_reply), 0);

			if (sendfile(sock, file, (off_t *) &request.offset, request.size) <0)
				printf("ERROR: sendfile returned -1\n");

			break;

		default:
			printf("ERROR: Unknown command\n");
		}

	}
	close(sock);
	printf("Client exit.\n");
	pthread_exit((void *)0);
}

int main(int argc, char* argv[])
{
	int opt = 0;
	int longIndex = 0;
	static const char *optString = "f:hv?";
	static const struct option longOpts[] =
	{
	{ "file", required_argument, NULL, 'f' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' } };

	opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
	if (opt == -1)
		print_help(argv[0]);

	while (opt != -1)
	{
		switch (opt)
		{
		case 'f':
			file = open(optarg, O_RDONLY);
			struct stat st;
			fstat(file, &st);
			filesize = st.st_size;
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

	printf("INFO: Filesize: %llu bytes\n", filesize);
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
