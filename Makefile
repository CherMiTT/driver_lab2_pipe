obj-m := my_pipe.o

KDIR := /home/chermi/projects/kernel/linux-stable
all:
	$(MAKE) -C $(KDIR) M=$$PWD

reload:
	sudo rmmod my_pipe
	sudo dmesg -C
	sudo insmod my_pipe.ko

check:
	cppcheck --enable=all --inconclusive --library=posix my_pipe.c
	/home/chermi/projects/kernel/linux-stable/scripts/checkpatch.pl -f my_pipe.c

writer:
	gcc -o writer writer.c

reader:
	gcc -o reader reader.c