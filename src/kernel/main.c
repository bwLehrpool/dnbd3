#include <linux/fs.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <net/sock.h>

// Own
#include "config.h"
#include "include/types.h"

static int major;
static struct gendisk *disk;
static struct request_queue *dnbd3_queue;

DEFINE_SPINLOCK( dnbd3_lock);

static struct socket *_sock;
static struct dnbd3_request _dnbd3_request;
static struct dnbd3_reply _dnbd3_reply;

static char* host;
static char* port;

unsigned int inet_addr(char *str)
{
	int a, b, c, d;
	char arr[4];
	sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
	arr[0] = a;
	arr[1] = b;
	arr[2] = c;
	arr[3] = d;
	return *(unsigned int*) arr;
}

void connect(void)
{
	if (!host || !port)
	{
		printk("ERROR: Host or port not set.");
		return;
	}

	// initialize socket
	struct sockaddr_in sin;
	if (sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &_sock) < 0)
	{
		printk("ERROR: dnbd3 couldn't create socket.\n");
		return;
	}
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(host);
	sin.sin_port = htons(simple_strtol(port, NULL, 10));
	if (kernel_connect(_sock, (struct sockaddr *) &sin, sizeof(sin), 0) < 0)
	{
		printk("ERROR: dnbd3 couldn't connect to given host.\n");
		return;
	}

	// prepare message
	struct msghdr msg;
	struct kvec iov;
	_sock->sk->sk_allocation = GFP_NOIO; // GFP_NOIO: blocking is possible, but no I/O will be performed.
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL; // No SIGPIPE

	// send request
	_dnbd3_request.cmd = CMD_GET_SIZE;
	iov.iov_base = &_dnbd3_request;
	iov.iov_len = sizeof(_dnbd3_request);
	kernel_sendmsg(_sock, &msg, &iov, 1, sizeof(_dnbd3_request));

	// receive replay
	iov.iov_base = &_dnbd3_reply;
	iov.iov_len = sizeof(_dnbd3_reply);
	kernel_recvmsg(_sock, &msg, &iov, 1, sizeof(_dnbd3_reply), msg.msg_flags);

	// set filesize
	printk("INFO: dnbd3 filesize: %llu\n", _dnbd3_reply.filesize);
	set_capacity(disk, _dnbd3_reply.filesize >> 9); /* 512 Byte blocks */
}

void dnbd3_request(struct request_queue *q)
{
	if (!_sock)
		return;

	struct request *req;
	struct msghdr msg;
	struct kvec iov;

	_sock->sk->sk_allocation = GFP_NOIO; // GFP_NOIO: blocking is possible, but no I/O will be performed.
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL; // No SIGPIPE

	while ((req = blk_fetch_request(q)) != NULL)
	{
		if (req->cmd_type != REQ_TYPE_FS)
		{
			if (!__blk_end_request_cur(req, 0))
				req = blk_fetch_request(q);
			continue;
		}

		spin_unlock_irq(q->queue_lock);
		if (rq_data_dir(req) == READ)
		{
			_dnbd3_request.cmd = CMD_GET_BLOCK;
			_dnbd3_request.offset = blk_rq_pos(req) << 9; // *512
			_dnbd3_request.size = blk_rq_bytes(req); // blk_rq_bytes() Returns bytes left to complete in the entire request

			// send request
			iov.iov_base = &_dnbd3_request;
			iov.iov_len = sizeof(_dnbd3_request);
			kernel_sendmsg(_sock, &msg, &iov, 1, sizeof(_dnbd3_request));

			// receive replay
			struct req_iterator iter;
			struct bio_vec *bvec;
			rq_for_each_segment(bvec, req, iter)
			{
				iov.iov_base = kmap(bvec->bv_page) + bvec->bv_offset;
				iov.iov_len = bvec->bv_len;
				kernel_recvmsg(_sock, &msg, &iov, 1, bvec->bv_len, msg.msg_flags);
				kunmap(bvec->bv_page);
			}
		}

		spin_lock_irq(q->queue_lock);
		__blk_end_request_all(req, 0);
	}
}

int dnbd3_ioctl(struct block_device *bdev, fmode_t mode,
		unsigned int cmd, unsigned long arg)
{
	switch (cmd)
	{
	case IOCTL_SET_HOST:
		host = (char *) arg;
		break;

	case IOCTL_SET_PORT:
		port = (char *) arg;
		break;

	case IOCTL_CONNECT:
		connect();
		break;
	case BLKFLSBUF:
		// TODO: if missing, hdparm tells "BLKFLSBUF failed: Operation not permitted". Figure out what this should do.
		break;

	default:
		return -1;

	}
	return 0;
}

struct block_device_operations dnbd3_ops =
{ .owner = THIS_MODULE, .ioctl = dnbd3_ioctl, };

static int __init dnbd3_init(void)
{
	// Init blkdev
	if ((major = register_blkdev(0, "dnbd")) == 0)
	{
		printk("ERROR: dnbd3 register_blkdev failed.\n");
		return -EIO;
	}
	if (!(disk = alloc_disk(1)))
	{
		printk("ERROR: dnbd3 alloc_disk failed.\n");
		return -EIO;
	}
	disk->major = major;
	disk->first_minor = 0;
	sprintf(disk->disk_name, "dnbd0");
	set_capacity(disk, 0);
	//set_disk_ro(disk, 1);
	disk->fops = &dnbd3_ops;

	if ((dnbd3_queue = blk_init_queue(&dnbd3_request, &dnbd3_lock)) == NULL)
	{
		printk("ERROR: dnbd3 blk_init_queue failed.\n");
		return -EIO;
	}

	blk_queue_logical_block_size(dnbd3_queue, DNBD3_BLOCK_SIZE); // set logical block size for the queue
	disk->queue = dnbd3_queue;

	add_disk(disk);
	printk("INFO: dnbd3 init successful.\n");
	return 0;
}

static void __exit dnbd3_exit(void)
{
	if (_sock)
		sock_release(_sock);
	unregister_blkdev(major, "dnbd");
	del_gendisk(disk);
	put_disk(disk);
	blk_cleanup_queue(dnbd3_queue);
	printk("INFO: dnbd3 exit.\n");
}

module_init( dnbd3_init);
module_exit( dnbd3_exit);
MODULE_LICENSE("GPL");
