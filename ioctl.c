#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

#include "my_pipe.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Specify new buffer size\n");
		return -1;
	}

	int bytes = atol(argv[1]);

	int f = open("/dev/my_pipe", O_RDWR);
	if(f == -1) {
		printf("couldn't open\n");
		return -1;
	}
	printf("opened\n");

	printf("Calling ioctl with %d bytes\n", bytes);
	ioctl(f, WR_CAPCITY, bytes);

	close(f);
	printf("closed\n");
	return 0;
}