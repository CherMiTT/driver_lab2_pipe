#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

int main()
{
	int f = open("/dev/my_pipe", O_WRONLY);
	if(f == -1) {
		printf("couldn't open\n");
		return -1;
	}
	printf("opened\n");

	char *str = "Hello world";
	int w = write(f, str, 12);
	printf("written %d bytes\n", w);

	close(f);
	printf("closed\n");
	return 0;
}