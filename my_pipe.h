//common file for driver and user-space application
//commands for ioctl system call are defines here

#define MAGIC_NUMBER 'k'
#define WR_CAPCITY _IOW(MAGIC_NUMBER, 1, int)