// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>

static int major; //major number

struct circular_buffer_t {
	char *buffer;
	size_t size;
	size_t read_ptr;
	size_t write_ptr;
	size_t bytes_avail;
};

static struct circular_buffer_t *circular_buffer;

struct circular_buffer_t *allocate_circular_buffer(size_t size)
{
	struct circular_buffer_t *buf;
	buf = kmalloc(sizeof(struct circular_buffer_t), GFP_KERNEL);
	if (buf == NULL) {
		pr_err("Could not allocate memory for circular_buffer_t");
		return NULL;
	}

	buf->size = size;
	buf->buffer = kmalloc(size, GFP_KERNEL);
	if (buf->buffer == NULL) {
		pr_err("Could not allocate memory for data of circular_buffer_t");
		kfree(buf);
		return NULL;
	}

	buf->read_ptr = 0;
	buf->write_ptr = 0;
	buf->bytes_avail = size;
	return buf;
}

void free_circular_buffer(struct circular_buffer_t *circular_buffer)
{
	kfree(circular_buffer->buffer);
	kfree(circular_buffer);
}

int read_from_circular_buffer(struct circular_buffer_t *circular_buffer, size_t n)
{

	return 0;
}

int write_to_circular_buffer(struct circular_buffer_t *circular_buffer, size_t n)
{

	return 0;
}


static ssize_t pipe_read(struct file *f, char __user *buf,
	size_t count, loff_t *offset)
{
	pr_alert("my_pipe read %lu bytes\n", count);

	//TODO: calculate bytes to copy here

	//unsigned long copied = copy_to_user(buf, circular_buffer, count);
	return 0;
}

static ssize_t pipe_write(struct file *f, const char __user *buf,
	size_t count, loff_t *offset)
{
	pr_alert("my_pipe write %lu bytes\n", count);
	char *tmp_buf;
	tmp_buf = kmalloc(count, GFP_KERNEL);
	//TODO: check memory allocation
	//TODO: check count against buffer_size, maybe sleep
	unsigned long copied = copy_from_user(tmp_buf, buf, count);
	if (copied != 0) {
		pr_err("Couldn't copy buffer from user in write\n");
	}

	pr_info("write from user: %s\n", tmp_buf);

	//TODO: check write_ptr agains buffer_size and add sleep
	int i;
	for (i = 0; i < count; ++i) {
		if (circular_buffer->write_ptr < circular_buffer->size) {
			circular_buffer->buffer[circular_buffer->write_ptr++] = tmp_buf[i];
		} else {
			//sleep
		}
	}

	kfree(tmp_buf);

	pr_alert("state of circular_buffer after write is %s\n", circular_buffer->buffer);
	return i;
}

static int pipe_open(struct inode *i, struct file *f)
{
	pr_alert("my_pipe open\n");
	return 0;
}

static int pipe_release(struct inode *i, struct file *f)
{
	pr_alert("my_pipe release\n");
	return 0;
}

static const struct file_operations fops = {
	.read = pipe_read,
	.write = pipe_write,
	.open = pipe_open,
	.release = pipe_release,
	//.unlocked_ioctl = ,
};

static int __init pipe_init(void)
{
	pr_alert("Init");
	major = register_chrdev(0, "my_pipe", &fops);
	if (major < 0) {
		pr_crit("failed to register\n");
		return major;
	}
	pr_alert("my_pipe assigned major %d\n", major);

	//TODO: check result
	circular_buffer = allocate_circular_buffer(1024);

	return 0;
}

static void __exit pipe_exit(void)
{
	free_circular_buffer(circular_buffer);
	unregister_chrdev(major, "my_pipe");
}

module_init(pipe_init);
module_exit(pipe_exit);

MODULE_AUTHOR("Chernomorets M.");
MODULE_DESCRIPTION("A simple implementation of pipe");
MODULE_LICENSE("GPL");