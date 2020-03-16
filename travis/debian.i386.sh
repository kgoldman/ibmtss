#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

dpkg --add-architecture i386
apt update

apt install -y --no-install-recommends \
	linux-libc-dev:i386 \
	gcc-multilib \
	pkg-config:i386
