// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/cred.h>

#include <uapi/asm-generic/ioctl.h>

#include "my_pipe.h"

//Stolen from https://elixir.bootlin.com/linux/v5.10/source/kernel/groups.c#L81
static int gid_cmp(const void *_a, const void *_b)
{
	kgid_t a = *(kgid_t *)_a;
	kgid_t b = *(kgid_t *)_b;

	return gid_gt(a, b) - gid_lt(a, b);
}

DEFINE_MUTEX(assoc_arr_mutex);

const size_t BUF_SIZE = 1000;

static int major; //major number

struct circular_buffer_t {
	char *buffer;
	size_t size;
	ssize_t read_ptr; //номер следующего байта, который читать
	ssize_t write_ptr; //номер следующего байта, куда писать
	//TODO: change all operations to memcpy based on bytes_avail
	ssize_t bytes_avail;
	struct mutex lock;
	wait_queue_head_t queue;
};

struct assoc_arr_gid_buf_t {
	size_t n;
	struct circular_buffer_t **buf_arr;
	kgid_t *gid_arr;
};

static struct assoc_arr_gid_buf_t *buffers;


static struct circular_buffer_t *allocate_circular_buffer(ssize_t size)
{
	struct circular_buffer_t *buf;

	buf = kmalloc(sizeof(struct circular_buffer_t), GFP_KERNEL);
	if (buf == NULL) {
		//pr_err("Could not allocate memory for circular_buffer_t\n");
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
	mutex_init(&buf->lock);
	init_waitqueue_head(&buf->queue);
	return buf;
}

static void free_circular_buffer(struct circular_buffer_t *circular_buffer)
{
	kfree(circular_buffer->buffer);
	kfree(circular_buffer);
}

static size_t read_from_circular_buffer(struct circular_buffer_t *circular_buffer, ssize_t n, char *dst)
{
	ssize_t i;

	for (i = 0; i < n; ++i) {
		if (circular_buffer->bytes_avail == circular_buffer->size)
			return i;
		dst[i] = circular_buffer->buffer[circular_buffer->read_ptr++];

		if (circular_buffer->read_ptr == circular_buffer->size)
			circular_buffer->read_ptr = 0;

		circular_buffer->bytes_avail++;
	}
	return i;
}

static size_t write_to_circular_buffer(struct circular_buffer_t *circular_buffer, ssize_t n, char *src)
{
	ssize_t i;

	for (i = 0; i < n; ++i) {
		if (circular_buffer->bytes_avail == 0)
			return i;

		circular_buffer->buffer[circular_buffer->write_ptr++] = src[i];

		if (circular_buffer->write_ptr == circular_buffer->size)
			circular_buffer->write_ptr = 0;

		circular_buffer->bytes_avail--;
	}
	return i;
}

static struct assoc_arr_gid_buf_t *allocate_assoc_arr_buf_gid(void)
{
	struct assoc_arr_gid_buf_t *arr;
	int res = mutex_lock_interruptible(&assoc_arr_mutex);

	if (res != 0) {
		pr_err("Mutex interrupted with return value %d\n", res);
		mutex_unlock(&assoc_arr_mutex);
		return NULL;
	}

	arr = kmalloc(sizeof(struct assoc_arr_gid_buf_t), GFP_KERNEL);
	if (arr == NULL) {
		//pr_err("Could not allocate memory for assoc_arr_gid_buf_t\n");
		mutex_unlock(&assoc_arr_mutex);
		return NULL;
	}
	arr->n = 0;
	arr->buf_arr = NULL;
	arr->gid_arr = NULL;
	mutex_unlock(&assoc_arr_mutex);
	return arr;
}

static void free_assoc_arr_buf_gid(void)
{
	int i;
	int res = mutex_lock_interruptible(&assoc_arr_mutex);

	if (res != 0) {
		pr_err("Mutex interrupted with return value %d\n", res);
		mutex_unlock(&assoc_arr_mutex);
		return;
	}

	for (i = 0; i < buffers->n; i++)
		free_circular_buffer(buffers->buf_arr[i]);

	kfree(buffers->buf_arr);
	kfree(buffers->gid_arr);
	kfree(buffers);
	mutex_unlock(&assoc_arr_mutex);
}

/* Function reallocates memory in assoc_arr_gid_buf_t for one new buffer.
 * Returns pointer to new buffer on success, NULL on failure.
 */
static struct circular_buffer_t *add_new_buffer(kgid_t gid)
{
	int res = mutex_lock_interruptible(&assoc_arr_mutex);
	struct circular_buffer_t **tmp_buf_arr;
	kgid_t *tmp_gid_arr;
	size_t new_size = ((buffers->n) + 1);

	if (res != 0) {
		pr_err("Mutex interrupted with return value %d\n", res);
		mutex_unlock(&assoc_arr_mutex);
		return NULL;
	}

	tmp_buf_arr = krealloc(buffers->buf_arr, new_size * sizeof(struct circular_buffer_t *), GFP_KERNEL);
	if (tmp_buf_arr == NULL) {
		pr_err("Could not reallocate memory for assoc_arr_gid_buf_t->buf_arr\n");
		mutex_unlock(&assoc_arr_mutex);
		return NULL;
	}

	tmp_gid_arr = krealloc(buffers->gid_arr, new_size * sizeof(kgid_t), GFP_KERNEL);
	if (tmp_gid_arr == NULL) {
		pr_err("Could not reallocate memory for assoc_arr_gid_buf_t->tmp_gid_arr\n");
		mutex_unlock(&assoc_arr_mutex);
		return NULL;
	}

	tmp_gid_arr[new_size - 1] = gid;
	tmp_buf_arr[new_size - 1] = allocate_circular_buffer(BUF_SIZE);

	buffers->buf_arr = tmp_buf_arr;
	buffers->gid_arr = tmp_gid_arr;
	buffers->n++;
	mutex_unlock(&assoc_arr_mutex);
	return buffers->buf_arr[new_size-1];
}

/* Finds struct circular_buffer_t in assoc_arr_gid_buf_t by kgid_t.
 * Returns pointer to struct circular_buffer_t if found, NULL if not.
 */
static struct circular_buffer_t *find_buffer(kgid_t gid)
{
	int i;
	int res = mutex_lock_interruptible(&assoc_arr_mutex);

	if (res != 0) {
		pr_err("Mutex interrupted with return value %d\n", res);
		mutex_unlock(&assoc_arr_mutex);
		return NULL;
	}

	for (i = 0; i < buffers->n; i++) {
		if (gid_cmp((void *)&gid, (void *)&buffers->gid_arr[i]) == 0) {
			pr_alert("Found matching kgid! At index %d\n", i);
			mutex_unlock(&assoc_arr_mutex);
			return buffers->buf_arr[i];
		}
	}
	mutex_unlock(&assoc_arr_mutex);
	return NULL;
}

static ssize_t pipe_read(struct file *f, char __user *buf,
	size_t count, loff_t *offset)
{
	//struct circular_buffer_t *circ_buf = find_buffer(f->f_cred->egid);
	struct circular_buffer_t *circ_buf = (struct circular_buffer_t *) f->private_data;
	char *tmp_buf = kmalloc(count, GFP_KERNEL);
	ssize_t read_bytes_total = 0;
	unsigned long copied; //number of bytes copied to user
	int res;

	if (tmp_buf == NULL) {
		pr_err("Could not allocate tmp_buf in read\n");
		return -1;
	}

	pr_alert("my_pipe read %lu bytes\n", count);
	pr_alert("Locking mutex");
	res = mutex_lock_interruptible(&circ_buf->lock);
	if (res != 0) {
		pr_err("Mutex interrupted with return value %d\n", res);
		return read_bytes_total;
	}

	while (read_bytes_total < count) {
		ssize_t read_bytes_iter = read_from_circular_buffer(circ_buf,
			count - read_bytes_total, tmp_buf + read_bytes_total);
		//TODO: read_bytes_iter used only for debug, either use or remove
		read_bytes_total += read_bytes_iter;
		if (read_bytes_total < count) {
			pr_alert("Read %lu bytes this iteration, %lu bytes total.\n\t"
				"Wanted to read %lu bytes. Unlocking mutex, going to sleep\n",
				read_bytes_iter, read_bytes_total, count);

			wake_up(&circ_buf->queue);
			mutex_unlock(&circ_buf->lock);
			res = wait_event_interruptible(circ_buf->queue,
				circ_buf->bytes_avail != circ_buf->size);
			if (res == -ERESTARTSYS) {
				pr_err("Sleep interrupted with return value %d\n", res);
				return read_bytes_total;
			}

			pr_alert("Woke up in read, locking mutex\n");
			res = mutex_lock_interruptible(&circ_buf->lock);
			if (res != 0) {
				pr_err("Mutex interrupted with return value %d\n", res);
				return read_bytes_total;
			}
		} else {
			pr_alert("Read %lu bytes this iteration, %lu bytes total.\n\t"
				"Read all the bytes we wanted! Unlocking mutex\n",
				read_bytes_iter, read_bytes_total);
			wake_up(&circ_buf->queue);
			mutex_unlock(&circ_buf->lock);
		}
		pr_info("circular_buffer->bytes_avail = %lu\n", circ_buf->bytes_avail);
		pr_info("Raw state of circular_buffer after read is %s\n", circ_buf->buffer);
	}

	copied = copy_to_user(buf, tmp_buf, count);
	if (copied != 0)
		pr_err("Couldn't copy buffer to user in read\n");

	return read_bytes_total;
}

static ssize_t pipe_write(struct file *f, const char __user *buf,
	size_t count, loff_t *offset)
{
	//struct circular_buffer_t *circ_buf = find_buffer(f->f_cred->egid);
	struct circular_buffer_t *circ_buf = (struct circular_buffer_t *) f->private_data;
	char *tmp_buf = kmalloc(count, GFP_KERNEL);
	unsigned long copied = copy_from_user(tmp_buf, buf, count);
	ssize_t written_bytes_total = 0;
	int res;

	if (tmp_buf == NULL) {
		pr_err("Could not allocate tmp_buf in read\n");
		return -1;
	}

	pr_alert("my_pipe write %lu bytes\n", count);
	//pr_alert("Egid: %d\n", f->f_cred->egid);
	if (copied != 0) {
		pr_err("Couldn't copy buffer from user in write\n");
		pr_err("Returning 0 to user.\n");
		return 0;
	}

	pr_info("write from user: %s\n", tmp_buf);

	pr_alert("Locking mutex");
	res = mutex_lock_interruptible(&circ_buf->lock);
	if (res != 0) {
		pr_err("Mutex interrupted with return value %d\n", res);
		return written_bytes_total;
	}

	while (written_bytes_total < count) {
		ssize_t written_bytes_iter = write_to_circular_buffer(circ_buf,
			count - written_bytes_total, tmp_buf + written_bytes_total);
		//TODO: written_bytes_iter is used only for debug, either use or remove
		written_bytes_total += written_bytes_iter;
		if (written_bytes_total < count) {
			pr_alert("Written %lu bytes this iteration, %lu bytes total.\n\t"
				"Wanted to write %lu bytes. Unlocking mutex, going to sleep\n",
				written_bytes_iter, written_bytes_total, count);

			wake_up(&circ_buf->queue);
			mutex_unlock(&circ_buf->lock);
			res = wait_event_interruptible(circ_buf->queue, circ_buf->bytes_avail > 0);
			if (res == -ERESTARTSYS) {
				pr_err("Sleep interrupted with return value %d\n", res);
				return written_bytes_total;
			}

			pr_alert("Woke up in write, locking mutex\n");
			res = mutex_lock_interruptible(&circ_buf->lock);
			if (res != 0) {
				pr_err("Mutex interrupted with return value %d\n", res);
				return written_bytes_total;
			}
		} else {
			pr_alert("Written %lu bytes this iteration, %lu bytes total.\n\t"
				"Written all the bytes we wanted! Unlocking mutex\n",
				written_bytes_iter, written_bytes_total);
			wake_up(&circ_buf->queue);
			mutex_unlock(&circ_buf->lock);
		}
	}

	kfree(tmp_buf);

	pr_info("circular_buffer->bytes_avail = %lu\n", circ_buf->bytes_avail);
	pr_info("Raw state of circular_buffer after write is %s\n", circ_buf->buffer);
	return written_bytes_total;
}

static int pipe_open(struct inode *i, struct file *f)
{
	kgid_t gid = f->f_cred->egid;
	struct circular_buffer_t *tmp = find_buffer(gid);

	pr_alert("my_pipe open\n");
	//pr_alert("Egid: %lu\n", gid);
	if (tmp == NULL) {
		pr_alert("Buffer not found. Adding buffer.\n");
		tmp = add_new_buffer(gid);
		if (tmp == NULL)
			return -1;
	}
	f->private_data = (void *) tmp;

	return 0;
}

static int pipe_release(struct inode *i, struct file *f)
{
	pr_alert("my_pipe release\n");
	pr_alert("buffer address: %p\n", f->private_data);
	return 0;
}

static long pipe_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct circular_buffer_t *tmp;
	//struct circular_buffer_t *circ_buf = find_buffer(f->f_cred->egid);
	struct circular_buffer_t *circ_buf = (struct circular_buffer_t *) f->private_data;

	int res, i;

	pr_alert("my_pipe ioctl; cmd is %d, arg is %lu\n", cmd, arg);

	switch (cmd) {
	case WR_CAPCITY:
		pr_alert("cmd is WR_CAPCITY\n");

		if (circ_buf == NULL) {
			pr_err("Could not allocate requested circular buffer in ioctl\n");
			return -EINVAL;
		}

		res = mutex_lock_interruptible(&circ_buf->lock);
		if (res != 0) {
			pr_err("Mutex interrupted with return value %d\n", res);
			mutex_unlock(&circ_buf->lock);
			return -EINVAL;
		}

		if (circ_buf->bytes_avail < circ_buf->size) {
			pr_alert("Circular buffer is not empty, could not change capacity");
			mutex_unlock(&circ_buf->lock);
			return -EINVAL;
		}

		tmp = allocate_circular_buffer(arg);
		if (tmp == NULL) {
			pr_err("Could not allocate circular_buffer_t\n");
			return -EINVAL;
		}

		for (i = 0; i < buffers->n; i++) {
			if (buffers->buf_arr[i] == circ_buf) {
				buffers->buf_arr[i] = tmp;
				f->private_data = (void *) tmp;
				free_circular_buffer(circ_buf);
			}
		}

		pr_alert("Buffer capacity changed to %lu\n", arg);
		mutex_unlock(&circ_buf->lock);
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

	buffers = allocate_assoc_arr_buf_gid();
	if (buffers == NULL) {
		pr_err("Could not allocate_assoc_arr_buf_gid, exiting");
		return -1;
	}
	return 0;
}

static void __exit pipe_exit(void)
{
	free_assoc_arr_buf_gid();
	unregister_chrdev(major, "my_pipe");
}

module_init(pipe_init);
module_exit(pipe_exit);

MODULE_AUTHOR("Chernomorets M.");
MODULE_DESCRIPTION("A simple implementation of pipe");
MODULE_LICENSE("GPL");