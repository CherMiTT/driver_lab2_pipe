#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Specify amount of bytes to read\n");
		return -1;
	}

	ssize_t bytes = atol(argv[1]);
	char *data;
	data = malloc(bytes);
	if (data == NULL) {
		printf("Could not allocate memory to read bytes\n");
		return -1;
	}

	int my_pipe = open("/dev/my_pipe", O_RDONLY);
	if(my_pipe == -1) {
		printf("Could not open my_pipe\n");
		return -1;
	}
	printf("Opened my_pipe\n");

	int r = read(my_pipe, data, bytes);
	printf("Read %d bytes\n", r);
	printf("Read string %s\n", data);

	close(my_pipe);
	printf("closed\n");
	return 0;
}