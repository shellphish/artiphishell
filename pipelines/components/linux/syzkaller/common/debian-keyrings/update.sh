#!/bin/bash

wget https://ftp-master.debian.org/keys/release-9.asc -qO- | gpg --import --no-default-keyring --keyring ./debian-release-9.gpg
wget https://ftp-master.debian.org/keys/release-10.asc -qO- | gpg --import --no-default-keyring --keyring ./debian-release-10.gpg
wget https://ftp-master.debian.org/keys/release-11.asc -qO- | gpg --import --no-default-keyring --keyring ./debian-release-11.gpg
wget https://ftp-master.debian.org/keys/release-12.asc -qO- | gpg --import --no-default-keyring --keyring ./debian-release-12.gpg