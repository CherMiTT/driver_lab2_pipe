#include <stdio.h>

int main()
{
	FILE *f = fopen("/dev/my_pipe", "w");
	if(f == NULL) 
	{
		printf("couldn't open\n");
		return -1;
	}
	printf("opened\n");
	fclose(f);
	printf("closed\n");
	return 0;
}