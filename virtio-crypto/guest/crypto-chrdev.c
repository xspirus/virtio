/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
    struct scatterlist syscall_type_sg,
                       host_fd_sg,
                       *sgs[2];

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	/* ?? */
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
    debug("Syscall init one good");
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
    debug("Init sg fd good");

    debug("syscall_type_sg %p", (void *)&syscall_type_sg);
    debug("host_fd_sg %p", (void *)&host_fd_sg);

    sgs[0] = &syscall_type_sg;
    sgs[1] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
    err = virtqueue_add_sgs(crof->crdev->vq, sgs, 1, 1, sgs[0], GFP_ATOMIC);
    virtqueue_kick(crof->crdev->vq);

	/* If host failed to open() return -ENODEV. */
	/* ?? */
    while (virtqueue_get_buf(crof->crdev->vq, &len) == NULL)
        /* do nothing */ ;

    crof->host_fd = *host_fd;

    debug("got file descriptor %d", crof->host_fd);

    if (crof->host_fd == -1)
        return -ENODEV;

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
    int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
    unsigned int len;
    struct scatterlist syscall_type_sg,
                       host_fd_sg,
                       *sgs[2];

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;

	/**
	 * Send data to the host.
	 **/
	/* ?? */
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));

    sgs[0] = &syscall_type_sg;
    sgs[1] = &host_fd_sg;

    err = virtqueue_add_sgs(crdev->vq, sgs, 2, 0, sgs[0], GFP_ATOMIC);
    virtqueue_kick(crdev->vq);

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
    while (virtqueue_get_buf(crdev->vq, &len) == NULL)
        /* do nothing */ ;

	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err, host_ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
    struct scatterlist syscall_type_sg,
                       host_fd_sg,
                       ioctl_cmd_sg,
                       session_key_sg,
                       session_op_sg,
                       session_id_sg,
                       crypt_op_sg,
                       src_sg,
                       iv_sg,
                       dst_sg,
                       return_sg,
                       *sgs[8];
	unsigned int num_out, num_in, len;
    unsigned int sess_id;
	unsigned char *key,
                  *src,
                  *iv,
                  *dst;
	unsigned int *syscall_type;
    struct session_op sess;
    struct crypt_op cryp;

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;

	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	/* ?? */
    sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
    sgs[num_out++] = &host_fd_sg;
    sg_init_one(&ioctl_cmd_sg, &cmd, sizeof(cmd));
    sgs[num_out++] = &ioctl_cmd_sg;

    debug("syscall_type_sg %p", (void *)&syscall_type_sg);
    debug("host_fd_sg %p", (void *)&host_fd_sg);
    debug("ioctl_cmd_sg %p", (void *)&ioctl_cmd_sg);

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		/* memcpy(output_msg, "Hello HOST from ioctl CIOCGSESSION.", 36); */
		/* input_msg[0] = '\0'; */
		/* sg_init_one(&output_msg_sg, output_msg, MSG_LEN); */
		/* sgs[num_out++] = &output_msg_sg; */
		/* sg_init_one(&input_msg_sg, input_msg, MSG_LEN); */
		/* sgs[num_out + num_in++] = &input_msg_sg; */
        /* sess = (struct session_op *) arg; */
        if (copy_from_user(&sess, (struct session_op *) arg, sizeof(struct session_op))) {
            debug("copy from user fail");
            return -EFAULT;
        }
        key  = (unsigned char *) sess.key;
        if (key == NULL)
            debug("key is null");
        debug("key pointer is %p", (void *) key);
        debug("size of key is %d", sess.keylen);
        sg_init_one(&session_key_sg, key, sess.keylen);
        sgs[num_out++] = &session_key_sg;
        sg_init_one(&session_op_sg, &sess, sizeof(sess));
        sgs[num_out + num_in++] = &session_op_sg;
        sg_init_one(&return_sg, &host_ret, sizeof(host_ret));
        sgs[num_out + num_in++] = &return_sg;
        debug("num out %d num in %d", num_out, num_in);
        while (num_out + num_in != 8) {
            sgs[num_out + num_in++] = NULL;
        }
        debug("num out %d num in %d", num_out, num_in);
		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		/* memcpy(output_msg, "Hello HOST from ioctl CIOCFSESSION.", 36); */
		/* input_msg[0] = '\0'; */
		/* sg_init_one(&output_msg_sg, output_msg, MSG_LEN); */
		/* sgs[num_out++] = &output_msg_sg; */
		/* sg_init_one(&input_msg_sg, input_msg, MSG_LEN); */
		/* sgs[num_out + num_in++] = &input_msg_sg; */
        /* sess_id = (unsigned int *) arg; */
        if (copy_from_user(&sess_id, (unsigned int *) arg, sizeof(unsigned int))) {
            debug("copy from user fail");
            return -EFAULT;
        }
        debug("sess id %d", sess_id);
        sg_init_one(&session_id_sg, &sess_id, sizeof(sess_id));
        sgs[num_out++] = &session_id_sg;
        sg_init_one(&return_sg, &host_ret, sizeof(host_ret));
        sgs[num_out + num_in++] = &return_sg;
        while (num_out + num_in != 8) {
            sgs[num_out + num_in++] = NULL;
        }
		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		/* memcpy(output_msg, "Hello HOST from ioctl CIOCCRYPT.", 33); */
		/* input_msg[0] = '\0'; */
		/* sg_init_one(&output_msg_sg, output_msg, MSG_LEN); */
		/* sgs[num_out++] = &output_msg_sg; */
		/* sg_init_one(&input_msg_sg, input_msg, MSG_LEN); */
		/* sgs[num_out + num_in++] = &input_msg_sg; */
        /* cryp = (struct crypt_op *) arg; */
        if (copy_from_user(&cryp, (struct crypt_op *) arg, sizeof(struct crypt_op))) {
            debug("copy from user fail");
            return -EFAULT;
        }
        src  = (unsigned char *) cryp.src;
        dst  = (unsigned char *) cryp.dst;
        iv   = (unsigned char *) cryp.iv;
        sg_init_one(&crypt_op_sg, &cryp, sizeof(cryp));
        sgs[num_out++] = &crypt_op_sg;
        sg_init_one(&src_sg, src, cryp.len);
        sgs[num_out++] = &src_sg;
        sg_init_one(&iv_sg, iv, AES_BLOCK_LEN);
        sgs[num_out++] = &iv_sg;
        sg_init_one(&dst_sg, dst, cryp.len);
        sgs[num_out + num_in++] = &dst_sg;
        sg_init_one(&return_sg, &host_ret, sizeof(host_ret));
        sgs[num_out + num_in++] = &return_sg;
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
    debug("num out %d num in %d", num_out, num_in);
    for (err = 0; err < 8; err++) {
        if (sgs[err] == NULL)
            debug("sgs[%d] is null", err);
        debug("sgs[%d] has address %p", err, (void *)sgs[err]);
    }
	/* err = virtqueue_add_sgs(vq, sgs, num_out, num_in, */
							/* &syscall_type_sg, GFP_ATOMIC); */
	/* virtqueue_kick(vq); */
	/* while (virtqueue_get_buf(vq, &len) == NULL) */
		/* [> do nothing <]; */

	/* debug("We said: '%s'", src); */
	/* debug("Host answered: '%s'", dst); */

	kfree(syscall_type);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
