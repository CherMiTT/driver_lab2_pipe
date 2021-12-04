#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void *wr(void *args)
{
	int number = *(int*)args;

	int my_pipe = open("/dev/my_pipe", O_WRONLY);
	if (my_pipe == -1) {
		printf("Could not open my_pipe\n");
		return NULL;
	}
	printf("Opened my_pipe\n");

	char *data = malloc(50);
	for(int i = 0; i < 50; i++)
	{
		data[i] = 'a' + number;
	}

	for(int i = 0; i < 5; i++)
	{
		int bytes_written = write(my_pipe, data, 10);
		printf("Thread %d, iter %d, written bytes %d\n", number, i, bytes_written);
	}

	free(data);

	close(my_pipe);
	printf("Closed my_pipe\n");
	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t a_thread[10];
	int numbers[10];

	for(int i = 0; i < 10; i++)
	{
		numbers[i] = i;
		int res = pthread_create(&(a_thread[i]), NULL, wr, (void*) &numbers[i]);
		if(res != 0) {
			perror("Thread creation failed!");
			exit(EXIT_FAILURE);
		}

	}

	for(int i = 0; i < 10; i++)
	{
		int res = pthread_join(a_thread[i], NULL);
	}

	return 0;
}

