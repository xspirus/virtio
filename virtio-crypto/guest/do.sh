#!/bin/bash

git pull origin master
make clean
make
rmmod -f virtio_crypto
insmod virtio_crypto.ko
./crypto_dev_nodes.sh
