#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "my_pipe.h"

int main()
{
	int f = open("/dev/my_pipe", O_RDWR);
	if(f == -1) {
		printf("couldn't open\n");
		return -1;
	}
	printf("opened\n");

	ioctl(f, WR_CAPCITY, 1000);

	close(f);
	printf("closed\n");
	return 0;
}