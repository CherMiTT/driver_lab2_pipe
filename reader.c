#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

int main()
{
	//FILE *file = fopen("dev/my_pipe", "r");
	int f = open("/dev/my_pipe", O_RDONLY);
	//if (file == NULL)
	if(f == -1) {
		printf("couldn't open\n");
		return -1;
	}
	printf("opened\n");

	char buf[12];
	int r = read(f, buf, 12);
	//int r = fread();
	printf("read %d bytes\n", r);
	printf("read string %s\n", buf);

	//fclose(file);
	close(f);
	printf("closed\n");
	return 0;
}