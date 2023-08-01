#!/bin/sh
set -ex

if [ -w /usr/local/bin ]; then
	SUDO=
else
	SUDO=sudo
fi

version=1682

wget --no-check-certificate https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm${version}.tar.gz/download
mkdir -p ibmtpm$version
cd ibmtpm$version
tar -xvzf ../download
cd src
openssl version
make -j$(nproc)
$SUDO cp tpm_server /usr/local/bin/
cd ../..
