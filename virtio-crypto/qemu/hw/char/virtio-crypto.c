/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 *
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	unsigned int *syscall_type;
    int *cfd, *ret, i;
    unsigned int *sess_id, *cmd;
    unsigned char *key,
                  *src,
                  *dst,
                  *iv;
    struct session_op *sess;
    struct crypt_op *cryp;

	DEBUG_IN();

    DEBUG("virtqueue_pop");

	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	} 

	DEBUG("I have got an item from VQ :)");

	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) {
	case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
		/* ?? */
        cfd = elem.in_sg[0].iov_base;
        if ((*cfd = open(CRYPTODEV_FILENAME, O_RDWR)) < 0) {
            *cfd = -1;
        }
        DEBUG("opened file descriptor");
        printf("file descriptor opened is %d\n", *cfd);
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
		/* ?? */
        cfd = elem.out_sg[1].iov_base;
        close(*cfd);
		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
		/* ?? */
        cfd = (int *) elem.out_sg[1].iov_base;
        cmd = (unsigned int *) elem.out_sg[2].iov_base;
        if (*cmd == CIOCGSESSION) {
            key          = (unsigned char *) elem.out_sg[3].iov_base;
            sess         = (struct session_op *) elem.in_sg[0].iov_base;
            ret          = (int *) elem.in_sg[1].iov_base;
            sess->key    = key;
            sess->keylen = elem.out_sg[3].iov_len;
            *ret         = ioctl(*cfd, CIOCGSESSION, sess);
            printf("gonna return session id %d\n", sess->ses);
        } else if (*cmd == CIOCFSESSION) {
            sess_id = (unsigned int *) elem.out_sg[3].iov_base;
            ret     = (int *) elem.in_sg[0].iov_base;
            *ret    = ioctl(*cfd, CIOCFSESSION, sess_id);
            printf("session id is %d\n", *sess_id);
        } else if (*cmd == CIOCCRYPT) {
            cryp      = (struct crypt_op *) elem.out_sg[3].iov_base;
            src       = (unsigned char *) elem.out_sg[4].iov_base;
            iv        = (unsigned char *) elem.out_sg[5].iov_base;
            dst       = (unsigned char *) elem.in_sg[0].iov_base;
            cryp->src = src;
            cryp->iv  = iv;
            cryp->dst = dst;
            ret       = (int *) elem.in_sg[1].iov_base;
            *ret      = ioctl(*cfd, CIOCCRYPT, cryp);
            printf("\nSource Data:\n");
            for (i = 0; i < cryp->len; i++) {
                printf("%x", cryp->src[i]);
            }
            printf("\n");
            printf("\nDestination Data:\n");
            for (i = 0; i < cryp->len; i++) {
                printf("%x", cryp->dst[i]);
            }
            printf("\n");
        }
		break;

	default:
		DEBUG("Unknown syscall_type");
	}

    DEBUG("pushing");
	virtqueue_push(vq, &elem, 0);
    DEBUG("pushed");
    DEBUG("notifying");
	virtio_notify(vdev, vq);
    DEBUG("notified");
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
