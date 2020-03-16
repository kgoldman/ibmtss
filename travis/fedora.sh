#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -e

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

# ibmswtpm2 requires gcc
[ "$CC" = "gcc" ] || CC="gcc $CC"

yum -y install \
	$CC autoconf \
	automake \
	diffutils \
	libattr-devel \
	make \
	openssl \
	openssl-devel \
	binutils \
	pkg-config \
	libtool \
	sudo \
	wget \
	which
