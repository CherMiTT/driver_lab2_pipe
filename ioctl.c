#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main()
{
	int f = open("/dev/my_pipe", O_RDWR);
	if(f == -1) {
		printf("couldn't open\n");
		return -1;
	}
	printf("opened\n");

	ioctl(f, 0, 0);

	close(f);
	printf("closed\n");
	return 0;
}