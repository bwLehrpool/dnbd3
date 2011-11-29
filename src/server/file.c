#include <fcntl.h>
#include <errno.h>
#include "file.h"

int file_open(char *filename)
{
	int fd = open(filename, O_RDONLY);
	if (fd == -1)
		return -1;

	struct stat st;
	if (fstat(fd, &st) == -1)
		return -1;

	return fd;
}

int file_getsize(int fd, off_t *size)
{
	*size = lseek64(fd, 0, SEEK_END);

	if (*size == -1)
		return -1;

	return 0;
}

int file_read(int fd, void *buf, size_t size, off_t pos)
{
	off_t newpos = lseek(fd, pos, SEEK_SET);

	if (newpos == -1)
		return -1;

	size_t nleft = size;
	ssize_t nread;
	char *ptr = buf;

	while (nleft > 0)
	{
		if ((nread = read(fd, ptr, nleft)) < 0)
		{
			if (errno == EINTR)
				continue;

			return -1;
		}
		if (nread == 0)
		{
			break;
		}

		nleft -= nread;
		ptr += nread;
	}

	return 0;
}
