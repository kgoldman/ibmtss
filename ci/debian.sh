#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

[ "$CC" = "gcc" ] || CC="gcc $CC"

# debian.*.sh must be run first
if [ "$ARCH" ]; then
	ARCH=":$ARCH"
	unset CC
else
	apt update
fi

apt="apt install -y --no-install-recommends"

$apt \
	$CC autoconf \
	automake \
	ca-certificates \
	diffutils \
	debianutils \
	git \
	libattr1-dev$ARCH \
	libkeyutils-dev$ARCH \
	libssl-dev$ARCH \
	libtool \
	make \
	openssl \
	pkg-config \
	ssh \
	sudo \
	wget
