// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/wait.h>

#include <uapi/asm-generic/ioctl.h>

#include "my_pipe.h"

DECLARE_WAIT_QUEUE_HEAD(module_queue);

static int major; //major number

struct circular_buffer_t {
	char *buffer;
	size_t size;
	ssize_t read_ptr; //номер следующего байта, который читать
	ssize_t write_ptr; //номер следующего байта, куда писать
	//TODO: change all operations to memcpy based on bytes_avail
	ssize_t bytes_avail;
};

static struct circular_buffer_t *circular_buffer;

struct circular_buffer_t *allocate_circular_buffer(size_t size)
{
	struct circular_buffer_t *buf;
	buf = kmalloc(sizeof(struct circular_buffer_t), GFP_KERNEL);
	if (buf == NULL) {
		pr_err("Could not allocate memory for circular_buffer_t\n");
		return NULL;
	}

	buf->size = size;
	buf->buffer = kmalloc(size, GFP_KERNEL);
	if (buf->buffer == NULL) {
		pr_err("Could not allocate memory for data of circular_buffer_t\n");
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
	ssize_t i;
	for (i = 0; i < n; ++i) {
		if (circular_buffer->bytes_avail == circular_buffer->size) {
			return i;
		}
		dst[i] = circular_buffer->buffer[circular_buffer->read_ptr++];

		if (circular_buffer->read_ptr == circular_buffer->size) {
			circular_buffer->read_ptr = 0;
		}

		circular_buffer->bytes_avail++;
	}
	return i;
}

size_t write_to_circular_buffer(struct circular_buffer_t *circular_buffer, size_t n, char *src)
{
	ssize_t i;
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
	ssize_t read_bytes_total = 0;
	while (read_bytes_total < count) {
		ssize_t read_bytes_iter = read_from_circular_buffer(circular_buffer,
			count - read_bytes_total, tmp_buf + read_bytes_total);
		//TODO: read_bytes_iter used only for debug, either use or remove
		read_bytes_total += read_bytes_iter;
		if (read_bytes_total < count) {
			pr_alert("Read %lu bytes this iteration, %lu bytes total. "
				"Wanted to read %lu bytes. Going to sleep\n",
				read_bytes_iter, read_bytes_total, count);

			wake_up(&module_queue);
			wait_event_interruptible_exclusive(module_queue,
				circular_buffer->bytes_avail != circular_buffer->size);
		} else {
			pr_alert("Read %lu bytes this iteration, %lu bytes total. "
				"Read all the bytes we wanted!\n",
				read_bytes_iter, read_bytes_total);
			wake_up(&module_queue);
		}
		pr_info("circular_buffer->bytes_avail = %lu\n", circular_buffer->bytes_avail);
		pr_info("Raw state of circular_buffer after read is %s\n", circular_buffer->buffer);
	}

	unsigned long copied = copy_to_user(buf, tmp_buf, count);
	if (copied != 0) {
		pr_err("Couldn't copy buffer to user in read\n");
	}

	return read_bytes_total;
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
		pr_err("Returning 0 to user.\n");
		return 0;
	}

	pr_info("write from user: %s\n", tmp_buf);

	ssize_t written_bytes_total = 0;
	while (written_bytes_total < count) {
		ssize_t written_bytes_iter = write_to_circular_buffer(circular_buffer,
			count - written_bytes_total, tmp_buf + written_bytes_total);
		//TODO: written_bytes_iter is used only for debug, either use or remove
		written_bytes_total += written_bytes_iter;
		if (written_bytes_total < count) {
			pr_alert("Written %lu bytes this iteration, %lu bytes total. "
				"Wanted to write %lu bytes. Going to sleep\n",
				written_bytes_iter, written_bytes_total, count);

			wake_up(&module_queue);
			wait_event_interruptible_exclusive(module_queue, circular_buffer->bytes_avail > 0);
		} else {
			pr_alert("Written %lu bytes this iteration, %lu bytes total. "
				"Written all the bytes we wanted!\n",
				written_bytes_iter, written_bytes_total);
			wake_up(&module_queue);
		}
	}

	kfree(tmp_buf);

	pr_info("circular_buffer->bytes_avail = %lu\n", circular_buffer->bytes_avail);
	pr_info("Raw state of circular_buffer after write is %s\n", circular_buffer->buffer);
	return written_bytes_total;
}

static int pipe_open(struct inode *i, struct file *f)
{
	pr_alert("my_pipe open\n");

	//TODO:
	//struct pid *this_pid = f->f_owner.pid;
	return 0;
}

static int pipe_release(struct inode *i, struct file *f)
{
	pr_alert("my_pipe release\n");
	return 0;
}

static long pipe_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	pr_alert("my_pipe ioctl; cmd is %d, arg is %lu\n", cmd, arg);

	switch (cmd) {
	case WR_CAPCITY:
		pr_alert("cmd is WR_CAPCITY\n");

		struct circular_buffer_t *tmp = allocate_circular_buffer(arg);
		if (circular_buffer == NULL) {
			pr_err("Could not allocate requested circular buffer in ioctl\n");
			return -EINVAL;
		}

		free_circular_buffer(circular_buffer);
		circular_buffer = tmp;
		pr_alert("Buffer capacity changed to %lu\n", arg);
		return 0;

	default:
		pr_alert("cmd is unknown\n");
		return -ENOTTY;
	}
}

static const struct file_operations fops = {
	.read = pipe_read,
	.write = pipe_write,
	.open = pipe_open,
	.release = pipe_release,
	.unlocked_ioctl = pipe_ioctl,
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
	circular_buffer = allocate_circular_buffer(20);

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