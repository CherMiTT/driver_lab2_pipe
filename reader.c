#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

int main()
{
	int f = open("/dev/my_pipe", O_RDONLY);
	if(f == -1) 
	{
		printf("couldn't open\n");
		return -1;
	}
	printf("opened\n");

	char buf[10];
	int r = read(f, buf, 10);
	printf("read %d bytes\n", r);

	close(f);
	printf("closed\n");
	return 0;
}