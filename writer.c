#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Specify file name");
	}

	struct stat file_stat;
	int err = stat(argv[1], &file_stat);
	if (err == -1) {
		printf("Some error has occured! %s not found!\n", argv[1]);
		return -1;
	}

	char *data = malloc(file_stat.st_size);
	if (data == NULL) {
		printf("Could not allocate memory to read file\n");
		return -1;
	}

	int inp = open(argv[1], O_RDONLY);
	if (inp == -1) {
		printf("Could not open file\n");
		return -1;
	}
	int bytes_read = read(inp, data, file_stat.st_size);
	printf("Read %d bytes of data\n", bytes_read);

	int my_pipe = open("/dev/my_pipe", O_WRONLY);
	if (my_pipe == -1) {
		printf("Could not open my_pipe\n");
		return -1;
	}
	printf("Opened my_pipe\n");

	int bytes_written = write(my_pipe, data, bytes_read);
	printf("Written %d bytes\n", bytes_written);

	close(my_pipe);
	printf("Closed my_pipe\n");
	return 0;
}