obj-m := my_pipe.o

KDIR := /home/chermi/projects/kernel/linux-stable
all:
	$(MAKE) -C $(KDIR) M=$$PWD

check:
	cppcheck --enable=all --inconclusive --library=posix my_pipe.c
	/home/chermi/projects/kernel/linux-stable/scripts/checkpatch.pl -f my_pipe.c