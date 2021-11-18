obj-m := my_pipe.o

KDIR := /home/chermi/projects/kernel/linux-stable
all:
	$(MAKE) -C $(KDIR) M=$$PWD

check:
	cppcheck --enable=all --inconclusive --library=posix my_pipe.c
	/home/chermi/projects/kernel/linux-stable/scripts/checkpatch.pl -f my_pipe.c

writer:
	rm writer
	gcc -o writer writer.c

reader:
	rm reader
	gcc -o reader reader.c

ioctl:
	rm ioctl
	gcc -o ioctl ioctl.c

load:
	sudo mknod /dev/my_pipe c 508 0
	sudo chmod 777 /dev/my_pipe
	sudo insmod my_pipe.ko

reload:
	sudo rmmod my_pipe
	sudo dmesg -C
	sudo insmod my_pipe.ko