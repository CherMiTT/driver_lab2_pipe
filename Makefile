obj-m := my_pipe.o

KDIR := /home/chermi/projects/kernel/linux-stable
all:
	$(MAKE) -C $(KDIR) M=$$PWD