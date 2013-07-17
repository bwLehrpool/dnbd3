#include "helper.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "../types.h"
#include "../config.h"

/**
 * Parse IPv4 or IPv6 address in string representation to a suitable format usable by the BSD socket library
 * @string eg. "1.2.3.4" or "2a01::10:5", optially with port appended, eg "1.2.3.4:6666" or "[2a01::10:5]:6666"
 * @af will contain either AF_INET or AF_INET6
 * @addr will contain the address in network representation
 * @port will contain the port in network representation, defaulting to #define PORT if none was given
 * returns 1 on success, 0 in failure. contents of af, addr and port are undefined in the latter case
 * !! Contents of @string might be modified by this function !!
 */
char parse_address(char *string, dnbd3_host_t *host)
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

/**
 * Convert a host and port (network byte order) to printable representation.
 * Worst case required buffer len is 48, eg. [1234:1234:1234:1234:1234:1234:1234:1234]:12345 (+ \0)
 * Returns TRUE on success, FALSE on error
 */
char host_to_string(const dnbd3_host_t *host, char *target, size_t targetlen)
{
	// Worst case: Port 5 chars, ':' to separate ip and port 1 char, terminating null 1 char = 7, [] for IPv6
	if (targetlen < 10)
		return FALSE;
	if (host->type == AF_INET6)
	{
		*target++ = '[';
		inet_ntop(AF_INET6, host->addr, target, targetlen - 9);
		target += strlen(target);
		*target++ = ']';
	}
	else if (host->type == AF_INET)
	{
		inet_ntop(AF_INET, host->addr, target, targetlen - 7);
		target += strlen(target);
	}
	else
	{
		snprintf(target, targetlen, "<?addrtype=%d>", (int)host->type);
		return FALSE;
	}
	*target = '\0';
	if (host->port != 0)
	{
		// There are still at least 7 bytes left in the buffer, port is at most 5 bytes + ':' + '\0' = 7
		snprintf(target, 7, ":%d", (int)ntohs(host->port));
	}
	return TRUE;
}

char is_valid_namespace(char *namespace)
{
	if (namespace == NULL || *namespace == '\0' || *namespace == '/')
		return 0; // Invalid: Length = 0 or starting with a slash
	while (*namespace)
	{
		if (*namespace != '/' && *namespace != '-' && (*namespace < 'a' || *namespace > 'z')
		        && (*namespace < 'A' || *namespace > 'Z')
		        && (*namespace < '0' || *namespace > '9'))
			return 0;
		++namespace;
	}
	if (strstr(namespace, "//") != NULL)
		return 0; // Invalid: Double slash
	if (*(namespace - 1) == '/')
		return 0; // Invalid: Ends in a slash
	return 1;
}

char is_valid_imagename(char *namespace)
{
	if (*namespace == '\0' || *namespace == ' ')
		return 0; // Invalid: Length = 0 or starting with a space
	while (*namespace)
	{
		// Check for invalid chars
		if (*namespace != '.' && *namespace != '-' && *namespace != ' '
		        && *namespace != '(' && *namespace != ')'
		        && (*namespace < 'a' || *namespace > 'z') && (*namespace < 'A' || *namespace > 'Z')
		        && (*namespace < '0' || *namespace > '9'))
			return 0;
		++namespace;
	}
	if (*(namespace - 1) == ' ')
		return 0; // Invalid: Ends in a space
	return 1;
}

void strtolower(char *string)
{
	while (*string)
	{
		if (*string >= 'A' && *string <= 'Z')
			*string += 32;
		++string;
	}
}

void remove_trailing_slash(char *string)
{
	char *ptr = string + strlen(string) - 1;
	while (ptr >= string && *ptr == '/')
		*ptr-- = '\0';
}

int file_exists(char *file)
{
	int fd = open(file, O_RDONLY);
	if (fd < 0)
		return FALSE;
	close(fd);
	return TRUE;
}

int file_writable(char *file)
{
	int fd = open(file, O_WRONLY);
	if (fd >= 0)
	{
		close(fd);
		return TRUE;
	}
	fd = open(file, O_WRONLY | O_CREAT, 0600);
	if (fd < 0)
		return FALSE;
	close(fd);
	unlink(file);
	return TRUE;
}
