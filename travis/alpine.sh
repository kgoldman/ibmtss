#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

# ibmswtpm2 requires gcc
[ "$CC" = "gcc" ] || CC="gcc $CC"

apk update

apk add \
	$CC \
	attr \
	attr-dev \
	autoconf \
	automake \
	diffutils \
	libtool \
	libxslt \
	make \
	musl-dev \
	openssl \
	openssl-dev \
	pkgconfig \
	sudo \
	wget \
	which
