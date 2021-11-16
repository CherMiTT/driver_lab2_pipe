// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

static int major; //major number


const size_t BUFFER_SIZE = 1024;
static char *circular_buffer;
int read_ptr, write_ptr;


static ssize_t pipe_read(struct file *f, char __user *buf,
	size_t count, loff_t *offset)
{
	pr_alert("my_pipe read %lu bytes\n", count);

	return 0;
}

static ssize_t pipe_write(struct file *f, const char __user *buf,
	size_t count, loff_t *offset)
{
	pr_alert("my_pipe write %lu bytes\n", count);
	char *tmp_buf;
	tmp_buf = kmalloc(count, GFP_KERNEL);
	//TODO: check memory allocation
	//TODO: check count against buffer_size
	copy_from_user(tmp_buf, buf, count);
	pr_info("write from user: %s\n", tmp_buf);
	kfree(tmp_buf);

	return 0;
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

	circular_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	//TODO: check memory allocation
	read_ptr = write_ptr = 0;

	return 0;
}

static void __exit pipe_exit(void)
{
	kfree(circular_buffer);
	unregister_chrdev(major, "my_pipe");
}

module_init(pipe_init);
module_exit(pipe_exit);

MODULE_AUTHOR("Chernomorets M.");
MODULE_DESCRIPTION("A simple implementation of pipe");
MODULE_LICENSE("GPL");