// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/wait.h>

DECLARE_WAIT_QUEUE_HEAD(module_queue);

static int major; //major number

struct circular_buffer_t {
	char *buffer;
	size_t size;
	size_t read_ptr; //номер следующего байта, который читать
	size_t write_ptr; //номер следующего байта, куда писать
	//TODO: change all operations to memcpy based on bytes_avail
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

size_t read_from_circular_buffer(struct circular_buffer_t *circular_buffer, size_t n, char *dst)
{
	size_t i;
	for (i = 0; i < n; ++i) {
		if (circular_buffer->bytes_avail == circular_buffer->size) {
			return i;
		}
		dst[i] = circular_buffer->buffer[circular_buffer->read_ptr++];

		if (circular_buffer->read_ptr == circular_buffer->size) {
			circular_buffer->read_ptr = 0;
		}
		//circular_buffer->bytes_avail = circular_buffer->size -
		//	(circular_buffer->write_ptr - circular_buffer->read_ptr);
		circular_buffer->bytes_avail++;
	}
	return i;
}

size_t write_to_circular_buffer(struct circular_buffer_t *circular_buffer, size_t n, char *src)
{
	size_t i;
	for (i = 0; i < n; ++i) {
		if (circular_buffer->bytes_avail == 0) {
			return i;
		}
		circular_buffer->buffer[circular_buffer->write_ptr++] = src[i];

		if (circular_buffer->write_ptr == circular_buffer->size) {
			circular_buffer->write_ptr = 0;
		}

		circular_buffer->bytes_avail--;
	}
	return i;
}


static ssize_t pipe_read(struct file *f, char __user *buf,
	size_t count, loff_t *offset)
{
	pr_alert("my_pipe read %lu bytes\n", count);

	char *tmp_buf;
	tmp_buf = kmalloc(count, GFP_KERNEL);
	//TODO: check memory allocation
	size_t read_bytes = read_from_circular_buffer(circular_buffer, count, tmp_buf);
	if (read_bytes < count) {
		pr_alert("Read %lu bytes, wanted to read %lu bytes. Going to sleep\n", read_bytes, count);
		//TODO: sleep
		wake_up(&module_queue);		
		wait_event_interruptible_exclusive(module_queue, circular_buffer->bytes_avail != circular_buffer->size);
	} else {
		pr_alert("read_bytes %lu bytes - all we wanted!\n", read_bytes);
	}
	pr_info("circular_buffer->bytes_avail = %lu\n", circular_buffer->bytes_avail);

	unsigned long copied = copy_to_user(buf, tmp_buf, count);
	if (copied != 0) {
		pr_err("Couldn't copy buffer to user in read\n");
	}

	return read_bytes;
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

	size_t written_bytes = write_to_circular_buffer(circular_buffer, count, tmp_buf);
	if (written_bytes < count) {
		pr_alert("Written %lu bytes, wanted to write %lu bytes. Going to sleep\n", written_bytes, count);
		//TODO: sleep
		wake_up(&module_queue);
		wait_event_interruptible_exclusive(module_queue, circular_buffer->bytes_avail > 0);
	} else {
		pr_alert("Written %lu bytes - all we wanted!\n", written_bytes);
	}

	kfree(tmp_buf);

	pr_alert("state of circular_buffer after write is %s\n", circular_buffer->buffer +
		circular_buffer->read_ptr);
	return written_bytes;
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
	circular_buffer = allocate_circular_buffer(10);

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