#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(ibmtss, 1.0, kgold@linux.ibm.com)
AC_PREREQ([2.63])

# Put autotools auxiliary files in a subdir, so they don't clutter top dir:
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
LT_INIT()

PKG_CHECK_MODULES(OPENSSL, [ openssl >= 1.0.1 ])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)
AC_CHECK_HEADERS(openssl/conf.h)
AC_CHECK_LIB([crypto], [AES_set_encrypt_key])

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

AC_CONFIG_FILES([Makefile
		utils/Makefile
		utils12/Makefile
		])
AC_OUTPUT

# Give some feedback
echo   "Configuration:"
echo   "	CFLAGS:	$CFLAGS"
echo   "	tpm12:	$tpm12"
echo   "	tpm20:	$tpm20"
echo   "	noprint:	$enable_noprint"
