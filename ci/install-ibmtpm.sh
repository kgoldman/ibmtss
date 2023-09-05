#!/bin/sh
set -ex

if [ -w /usr/local/bin ]; then
	SUDO=
else
	SUDO=sudo
fi

# get latest TPM from github
git clone http://github.com/kgoldman/ibmswtpm2.git

# build and install SW TPM
cd ibmswtpm2
cd src
openssl version
make -j$(nproc)
$SUDO cp tpm_server /usr/local/bin/
cd ../..
