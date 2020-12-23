#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Set package release version"
# After committing set git tag version.
AC_INIT(ibmtss, 1.6.0, kgold@linux.ibm.com)
AC_PREREQ([2.63])

# Convert major.minor.micro to libtool versioning (current-revision-age)
TSSLIB_VER_MAJOR=1
TSSLIB_VER_MINOR=6
TSSLIB_VER_MICRO=0
TSSLIB_VERSION_INFO=`expr $TSSLIB_VER_MAJOR + $TSSLIB_VER_MINOR`:$TSSLIB_VER_MICRO:$TSSLIB_VER_MINOR
AC_SUBST([TSSLIB_VERSION_INFO], [$TSSLIB_VERSION_INFO])

# Put autotools auxiliary files in a subdir, so they don't clutter top dir:
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST

# save userspace CFLAGS options
USER_CFLAGS=$CFLAGS

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
LT_INIT([disable-static])

PKG_CHECK_MODULES(LIBCRYPTO, [libcrypto >= 1.0.1 ])
AC_CHECK_HEADERS(openssl/conf.h)

# check for optional efiboot library for boot log pretty printing
PKG_CHECK_MODULES(EFIBOOT, [efiboot efivar],,[true])
CPPFLAGS="$CPPFLAGS $EFIBOOT_CFLAGS"
AC_CHECK_HEADERS([efiboot.h])

# Checks for header files.
AC_HEADER_STDC

AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/param.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gethostbyname memmove memset socket strerror strtoul])

# Replace autotools default optimization
AC_ARG_ENABLE(debug,
   AS_HELP_STRING([--enable-debug], [Build a TSS library used for debugging]))
   AS_IF([test "$enable_debug" = "yes"], [CFLAGS="$USER_CFLAGS -g -ggdb -O0"])

# Linux requires -DTPM_POSIX
case $host_os in
       linux-*)        CFLAGS="-DTPM_POSIX $CFLAGS" ;;
esac

AC_ARG_ENABLE(tpm-2.0,
   AS_HELP_STRING([--disable-tpm-2.0], [Include only TPM 1.2 support]),
     [case "${enableval}" in
     yes | no ) tpm20="${enableval}" ;;
     *) AC_MSG_ERROR([bad value ${enableval} for --disable-tpm-2.0]) ;;
   esac], [tpm20="yes"])
   AM_CONDITIONAL([CONFIG_TPM20], [test x$tpm20 = xyes])

AC_ARG_ENABLE(tpm-1.2,
   AS_HELP_STRING([--disable-tpm-1.2], [Include only TPM 2.0 support]),
     [case "${enableval}" in
     yes | no ) tpm12="${enableval}" ;;
     *) AC_MSG_ERROR([bad value ${enableval} for --disable-tpm-1.2]) ;;
   esac], [tpm12="yes"])
   AM_CONDITIONAL([CONFIG_TPM12], [test x$tpm12 = xyes])

AC_ARG_ENABLE(noprint,
   AS_HELP_STRING([--enable-noprint], [Build a TSS library without tracing or prints]))
   AM_CONDITIONAL([CONFIG_TSS_NOPRINT], [test "x$enable_noprint" = "xyes"])
   AS_IF([test "$enable_noprint" != "yes"], [enable_noprint="no"])

AC_ARG_ENABLE(nofile,
	      AS_HELP_STRING([--enable-nofile], [Build a TSS library that does not
		   use files to preserve state]))
   AM_CONDITIONAL([CONFIG_TSS_NOFILE], [test "x$enable_nofile" = "xyes"])
   AS_IF([test "$enable_nofile" != "yes"], [enable_nofile="no"])

AC_ARG_ENABLE(nocrypto,
	      AS_HELP_STRING([--enable-nocrypto], [Build a TSS library that does not
		   require a crypto library]))
   AM_CONDITIONAL([CONFIG_TSS_NOCRYPTO], [test "x$enable_nocrypto" = "xyes"])
   AS_IF([test "$enable_nocrypto" != "yes"], [enable_nocrypto="no"])

AC_ARG_ENABLE(noecc,
	      AS_HELP_STRING([--enable-noecc], [Build a TSS library that does not
		   require OpenSSL elliptic curve support]))
   AM_CONDITIONAL([CONFIG_TSS_NOECC], [test "x$enable_noecc" = "xyes"])
   AS_IF([test "$enable_noecc" != "yes"], [enable_noecc="no"])

AC_ARG_ENABLE(hwtpm,
   AS_HELP_STRING([--disable-hwtpm], [Use a software TPM instead of the hardware one]),, [enable_hwtpm="yes"])
   AM_CONDITIONAL([CONFIG_HWTPM], [test "x$enable_hwtpm" = "xyes"])
   AS_IF([test "$enable_hwtpm" != "yes"], [enable_hwtpm="no"])

AC_ARG_ENABLE(rmtpm,
   AS_HELP_STRING([--disable-rmtpm], [Do not use the resource manager]),, [enable_rmtpm="yes"])
   AM_CONDITIONAL([CONFIG_RMTPM], [test "x$enable_rmtpm" = "xyes"])
   AS_IF([test "$enable_rmtpm" != "yes"], [enable_rmtpm="no"])

AC_CONFIG_FILES([Makefile
		utils/Makefile
		utils12/Makefile
		])
AC_OUTPUT

# Give some feedback
echo   "Configuration:"
echo   "	CFLAGS:		$CFLAGS"
echo   "	tpm12:		$tpm12"
echo   "	tpm20:		$tpm20"
echo   "	hwtpm:		$enable_hwtpm"
echo   "	rmtpm:		$enable_rmtpm"
echo   "	nofile:		$enable_nofile"
echo   "	noprint:	$enable_noprint"
echo   "	nocrypto:	$enable_nocrypto"
echo   "	noecc:		$enable_noecc"
