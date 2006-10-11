#
# Copyright (c) 2006 Zeljko Vrba <zvrba@globalnet.hr>
# Copyright (c) 2006 Alon Bar-Lev <alon.barlev@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modifi-
# cation, are permitted provided that the following conditions are met:
#
#   o  Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#
#   o  Redistributions in binary form must reproduce the above copyright no-
#      tice, this list of conditions and the following disclaimer in the do-
#      cumentation and/or other materials provided with the distribution.
#
#   o  The names of the contributors may not be used to endorse or promote
#      products derived from this software without specific prior written
#      permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
# ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
# TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
# ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
# LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

AC_PREREQ(2.59)
AC_INIT(gnupg-pkcs11-scd, 0.01)
AM_INIT_AUTOMAKE(gnupg-pkcs11-scd, [$PACKAGE_VERSION])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([common.h])

AC_ARG_ENABLE(pedantic,
	[  --enable-pedantic       Enable pedantic compiler warnings, will not generate a working executable (debugging option)],
	[PEDANTIC="$enableval"],
	[PEDANTIC="no"]
)

AC_ARG_WITH(openssl,
	[  --with-openssl          Use OpenSSL],
	[USE_OPENSSL="yes"]
)

AC_ARG_WITH(gnutls,
	[  --with-gnutls           Use GNUTLS],
	[USE_GNUTLS="yes"]
)

GNUPG_HOME="~/.gnupg"
AC_ARG_WITH(gnutls,
	[  --with-gnupg-home=DIR   Define gnupg home],
	[GNUPG_HOME="${withval}"]
)

AC_ARG_WITH(mem-check,
	[  --with-mem-check=TYPE  Build with debug memory checking, TYPE = valgrind],
	[MEMCHECK="$withval"]
)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_GCC_TRADITIONAL
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	gettimeofday memmove memset socket strchr strdup strerror strrchr \
	snprintf \
])

# Checks for libraries.
AC_CHECK_LIB([gcrypt], [gcry_pk_get_keygrip],, AC_MSG_ERROR([Cannot locate gcrypt]))
AC_CHECK_LIB([assuan], [assuan_init_pipe_server],, AC_MSG_ERROR([Cannot locate assuan]))
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([pthread], [pthread_create])

PKG_CHECK_MODULES([GNUTLS], [gnutls >= 1.4], [HAVE_GNUTLS=yes], [HAVE_GNUTLS=no])
PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 0.9.7], [HAVE_OPENSSL=yes], [HAVE_OPENSSL=no])
if test "${HAVE_OPENSSL}" = "no"; then
	PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.7], [HAVE_OPENSSL=yes], [HAVE_OPENSSL=no])
fi

if test "${USE_OPENSSL}" != "yes" -a "${USE_GNUTLS}" != "yes"; then
	if test "${HAVE_OPENSSL}" = "yes"; then
		USE_OPENSSL="yes"
	elif test "${HAVE_GNUTLS}" = "yes"; then
		USE_GNUTLS="yes"
	else
		AC_MSG_ERROR([Cannot locate OpenSSL or GNUTLS])
	fi
fi

if test "${USE_GNUTLS}" = "yes" -a "${HAVE_GNUTLS}" != "yes"; then
	AC_MSG_ERROR([Cannot locate use GNUTLS since it was not located])
fi

if test "${USE_OPENSSL}" = "yes" -a "${HAVE_OPENSSL}" != "yes"; then
	AC_MSG_ERROR([Cannot locate use OpenSSL since it was not located])
fi

if test "${USE_OPENSSL}" == "yes"; then
	AC_MSG_RESULT([Using OpenSSL])
	AC_DEFINE(USE_OPENSSL, 1, [Use OpenSSL library])
	CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
	LIBS="${LIBS} ${OPENSSL_LIBS}"
else
	AC_MSG_RESULT([Using GNUTLS])
	AC_DEFINE(USE_GNUTLS, 1, [Use GNUTLS library])
	CFLAGS="${CFLAGS} ${GNUTLS_CFLAGS}"
	LIBS="${LIBS} ${GNUTLS_LIBS}"
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([ \
	stdio.h \
	stdlib.h \
	stdargs.h \
	malloc.h \
	ctype.h \
	string.h \
	errno.h \
	signal.h \
	dlfcn.h \
	unistd.h \
])
AC_CHECK_HEADERS([gpg-error.h],, AC_MSG_ERROR([Missing gpg-error.h]))
AC_CHECK_HEADERS([assuan.h],, AC_MSG_ERROR([Missing assuan.h]))


if test "$MEMCHECK" = "valgrind"; then
	AC_CHECKING([for valgrind tool and Header files])
	PKG_CHECK_MODULES([VALGRIND], [valgrind >= 3.0.0], [HAVE_VALGRIND=yes], [HAVE_VALGRIND=no])
	if test "${HAVE_VALGRIND}" != "yes"; then
		AC_MSG_ERROR([valgrind was not found])
	fi
	AC_DEFINE(USE_VALGRIND, 1, [Use valgrind memory debugging library])
	CFLAGS="${CFLAGS} ${VALGRIND_CFLAGS} -g -fno-inline"
#	LIBS="${VALGRIND_LIBS} ${LIBS}"
fi

CFLAGS="$CFLAGS -Wall -Wpointer-arith -Wsign-compare -Wno-unused-parameter -Wno-unused-function"

if test "$PEDANTIC" = "yes"; then
	CFLAGS="$CFLAGS -ansi -pedantic -D__STRICT_ANSI__ -D_POSIX_SOURCE -D_POSIX_C_SOURCE -D_SVID_SOURCE"
fi

AC_DEFINE_UNQUOTED([CONFIG_GPG_HOME], ["${GNUPG_HOME}"], [gnupg home])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT