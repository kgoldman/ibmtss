#!/bin/sh
set -ex

version=1637

wget --no-check-certificate https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm${version}.tar.gz/download
mkdir -p ibmtpm$version
cd ibmtpm$version
tar -xvzf ../download
cd src
make -j$(nproc)
sudo cp tpm_server /usr/local/bin/
cd ../..
