#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>

set -e

trap cleanup INT TERM EXIT

# Only stop this test's software TPM
cleanup() {
	if [ -n "${TPMSERVER_PID}" ]; then
		tsstpmcmd -stop
	fi
}

CC="${CC:-gcc}"
CFLAGS="${CFLAGS:--Wformat -Werror=format-security -Werror=implicit-function-declaration -Werror=return-type -fno-common}"
PREFIX="${PREFIX:-$HOME/tpm2}"

export LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:/usr/local/lib64:/usr/local/lib"
export PATH="$PREFIX/bin:/usr/local/bin:$PATH"

title()
{
	echo "===== $1 ====="
}

log_exit()
{
	local ret="${3:-$?}"
	local log="$1"
	local msg="$2"
	local prefix

	echo "=== $log ==="
	[ $ret -eq 0 ] || prefix="FAIL: "
	cat $log
	echo
	echo "$prefix$msg, see output of $log above"
	exit $ret
}

cd `dirname $0`

case "$VARIANT" in
	i386)
		echo "32-bit compilation"
		export CFLAGS="-m32 $CFLAGS" LDFLAGS="-m32 $LDFLAGS"
		export PKG_CONFIG_LIBDIR=/usr/lib/i386-linux-gnu/pkgconfig
		;;
	cross-compile)
		host="${CC%-gcc}"
		export CROSS_COMPILE="${host}-"
		host="--host=$host"
		echo "cross compilation: $host"
		echo "CROSS_COMPILE: '$CROSS_COMPILE'"
		;;
	*)
		if [ "$VARIANT" ]; then
			echo "Wrong VARIANT: '$VARIANT'" >&2
			exit 1
		fi
		echo "native build"
		;;
esac

title "compiler version"
$CC --version
echo "CFLAGS: '$CFLAGS'"
echo "LDFLAGS: '$LDFLAGS'"
echo "PREFIX: '$PREFIX'"

title "configure"
./autogen.sh
./configure --prefix=$PREFIX --disable-hwtpm --disable-tpm-1.2 $host || log_exit config.log "configure failed"

title "make"
make -j$(nproc)
make install

title "test"
if [ "$VARIANT" ]; then
	echo "INFO: skip make check on cross compilation"
	exit 0
fi

ret=0
export TPM_INTERFACE_TYPE="socsim"
export TPM_COMMAND_PORT=2321
export TPM_PLATFORM_PORT=2322
export TPM_SERVER_NAME="localhost"
export TPM_SERVER_TYPE="mssim"

echo "INFO: starting tpm_server"
tpm_server > /dev/null 2>&1 &
TPMSERVER_PID=$!

# The tpm_server might take a while to initialize, wait before trying
sleep 1
tssstartup
if [ $? -ne 0 ]; then
	echo "INFO: Retry sending software TPM startup"
	sleep 1
	tssstartup
	if [ $? -ne 0 ]; then
		echo "INFO: Software TPM startup failed"
		exit 0
	fi
fi
echo "INFO: software TSS startup completed"

# To use the root certificates here, update the certificate file path
sed -i -e "s/^.*utils\///g" utils/certificates/rootcerts.txt
VERBOSE=1 make check > ./reg.sh.log || grep "Success -" ./reg.sh.log
ret=$?
if [ $ret -eq 0 ]; then
	grep "Success -" ./reg.sh.log
else
	grep -A 1 -B 4 "ERROR:" ./reg.sh.log
fi
rm ./reg.sh.log
exit $ret
