#!/bin/bash

set -e

if [ ! -f "/tmp/syzimages-$(whoami)/bullseye.tar.gz" ]
then
	mkdir -p /tmp/syzimages-$(whoami)
	wget https://github.com/olmeke/syzimages/releases/download/images/bullseye.tar.gz -O /tmp/syzimages-$(whoami)/bullseye.tar.gz
fi

if [ ! -f "/tmp/syzimages-$(whoami)/bullseye.img" ]
then
	pushd /tmp/syzimages-$(whoami)
	tar xfz /tmp/syzimages-$(whoami)/bullseye.tar.gz
	popd
fi

if [ ! -f "/tmp/syzimages-$(whoami)/bullseye.img" ]
then
	mkdir -p /tmp/syzimages-$(whoami)
	wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O /tmp/syzimages-$(whoami)/create-image.sh
	patch /tmp/syzimages-$(whoami)/create-image.sh ./common/create-image.patch
	chmod +x /tmp/syzimages-$(whoami)/create-image.sh
	pushd /tmp/syzimages-$(whoami)/
	./create-image.sh
	popd
	sudo rm -rf /tmp/syzimages-$(whoami)/chroot
fi

mkdir -p ./image
cp /tmp/syzimages-$(whoami)/bullseye* ./image/
