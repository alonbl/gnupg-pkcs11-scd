#
# Copyright (c) 2006 Zeljko Vrba <zvrba@globalnet.hr>
# Copyright (c) 2006 Alon Bar-Lev <alon.barlev@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     o Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     o Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     o Neither the name of the <ORGANIZATION> nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

AC_PREREQ(2.60)
AC_INIT(gnupg-pkcs11-scd, 0.03)
AM_INIT_AUTOMAKE(gnupg-pkcs11-scd, [$PACKAGE_VERSION])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([common.h])

# Checks for programs.
AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

HAVE_W32_SYSTEM="no"
CYGWIN="no"
case "${host}" in
	*-mingw32*)
    		AC_DEFINE(HAVE_W32_SYSTEM,1,[Defined if we run on a W32 API based system])
		HAVE_W32_SYSTEM="yes"
	;;
	*-cygwin*)
		AC_MSG_CHECKING([cygwin mode to use])
		CYGWIN="yes"
		if test "${CYGWIN_NATIVE}" = "yes"; then
			AC_MSG_RESULT([Using native win32])
			CFLAGS="${CFLAGS} -mno-cygwin"
			HAVE_W32_SYSTEM="yes"
		else
			AC_MSG_RESULT([Using cygwin])
		fi
	;;
	*)
	;;
esac

AC_ARG_ENABLE(pedantic,
	[  --enable-pedantic                 Enable pedantic compiler warnings, will not generate a working executable (debugging option)],
	[PEDANTIC="${enableval}"],
	[PEDANTIC="no"]
)

AC_ARG_WITH(openssl,
	[  --without-openssl                 Disable OpenSSL linkage],
	[WITH_OPENSSL="${withval}"],
	[WITH_OPENSSL="yes"]
)

AC_ARG_WITH(gnutls,
	[  --without-gnutls                  Disable GNUTLS linkage (OpenSSL will be used if both enabled)],
	[WITH_GNUTLS="${withval}"],
	[WITH_GNUTLS="yes"]
)

AC_ARG_WITH(system-config,
	[  --with-system-config=FILE         Define gnupg system wide config],
	[SYSTEM_CONFIG="${withval}"],
	[test "${HAVE_W32_SYSTEM}" = "yes" && SYSTEM_CONFIG="%SystemRoot%\\\\${PACKAGE}.conf" || SYSTEM_CONFIG="/etc/${PACKAGE}.conf"]
)

AC_ARG_WITH(gnupg-home,
	[  --with-gnupg-home=DIR             Define gnupg home],
	[GNUPG_HOME="${withval}"],
	[test "${HAVE_W32_SYSTEM}" = "yes" && GNUPG_HOME="~\\\\.gnupg" || GNUPG_HOME="~/.gnupg"]
)

AC_ARG_WITH(libgpg-error-prefix,
	[  --with-libgpg-error-prefix=DIR    Define libgpgp-error prefix],
	[LIBGPG_ERROR_PREFIX="${withval}"],
	[LIBGPG_ERROR_PREFIX="/usr" ]
)

AC_ARG_WITH(libassuan-prefix,
	[  --with-libassuan-prefix=DIR       Define libassuan prefix],
	[LIBASSUAN_PREFIX="${withval}"],
	[LIBASSUAN_PREFIX="/usr" ]
)

AC_ARG_WITH(libgcrypt-prefix,
	[  --with-libgcrypt-prefix=DIR       Define libgcrypt prefix],
	[LIBGCRYPT_PREFIX="${withval}"],
	[LIBGCRYPT_PREFIX="/usr" ]
)

AC_ARG_WITH(mem-check,
	[  --with-mem-check=TYPE             Build with debug memory checking, TYPE = valgrind],
	[MEMCHECK="$withval"]
)

if test "${HAVE_W32_SYSTEM}" = "yes"; then
	AC_CHECK_PROGS([MAN2HTML], [man2html])
	test -z "${MAN2HTML}" && AC_MSG_ERROR([man2html is required for win32])
fi

AC_FUNC_MKTIME
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	gettimeofday memmove memset socket strchr strdup strerror strrchr \
	snprintf \
])

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([pthread], [pthread_create])

AC_MSG_CHECKING([for libgpg-error])
if ! test -x "${LIBGPG_ERROR_PREFIX}/bin/gpg-error-config"; then
	AC_MSG_ERROR([Cannot locate libgpg-error])
else
	AC_MSG_RESULT([found])
	CFLAGS="${CFLAGS} `\"${LIBGPG_ERROR_PREFIX}/bin/gpg-error-config\" --cflags`"
	LIBS="${LIBS} `\"${LIBGPG_ERROR_PREFIX}/bin/gpg-error-config\" --libs`"
fi

AC_MSG_CHECKING([for libassuan])
if ! test -x "${LIBASSUAN_PREFIX}/bin/libassuan-config"; then
	AC_MSG_ERROR([Cannot locate libassuan])
else
	AC_MSG_RESULT([found])
	CFLAGS="${CFLAGS} `\"${LIBASSUAN_PREFIX}/bin/libassuan-config\" --cflags`"
	LIBS="${LIBS} `\"${LIBASSUAN_PREFIX}/bin/libassuan-config\" --libs`"
fi

AC_MSG_CHECKING([for libgcrypt])
if ! test -x "${LIBGCRYPT_PREFIX}/bin/libgcrypt-config"; then
	AC_MSG_ERROR([Cannot locate libgcrypt])
else
	AC_MSG_RESULT([found])
	CFLAGS="${CFLAGS} `\"${LIBGCRYPT_PREFIX}/bin/libgcrypt-config\" --cflags`"
	LIBS="${LIBS} `\"${LIBGCRYPT_PREFIX}/bin/libgcrypt-config\" --libs`"
fi

PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 0.9.7], [HAVE_OPENSSL="yes"], [HAVE_OPENSSL="no"])
if test "${HAVE_OPENSSL}" = "no"; then
	PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.7], [HAVE_OPENSSL="yes"], [HAVE_OPENSSL="no"])
fi

PKG_CHECK_MODULES([GNUTLS], [gnutls >= 1.4], [HAVE_GNUTLS="yes"], [HAVE_GNUTLS="no"])

PKG_CHECK_MODULES([PKCS11_HELPER], [libpkcs11-helper-1 >= 1.02],, [AC_MSG_ERROR([Cannot locate pkcs11-helper])])
PKCS11_HELPER_1_CHECK_FEATURES([threading token certificate engine_crypto])
CFLAGS="$CFLAGS ${PKCS11_HELPER_CFLAGS}"
LIBS="${LIBS} ${PKCS11_HELPER_LIBS}"

AC_MSG_CHECKING([cryptographic library to use])

if test "${WITH_OPENSSL}" = "yes" -a "${HAVE_OPENSSL}" != "yes"; then
	WITH_OPENSSL="no"
fi

if test "${WITH_GNUTLS}" = "yes" -a "${HAVE_GNUTLS}" != "yes"; then
	WITH_GNUTLS="no"
fi

if test "${WITH_OPENSSL}" = "no" -a "${WITH_GNUTLS}" = "no"; then
	AC_MSG_ERROR([Cannot locate OpenSSL or GNUTLS])
fi

if test "${WITH_OPENSSL}" = "yes"; then
	AC_MSG_RESULT([Using OpenSSL])
	AC_DEFINE(ENABLE_OPENSSL, 1, [Use OpenSSL library])
	CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
	LIBS="${LIBS} ${OPENSSL_LIBS}"
else
	AC_MSG_RESULT([Using GNUTLS])
	AC_DEFINE(ENABLE_GNUTLS, 1, [Use GNUTLS library])
	CFLAGS="${CFLAGS} ${GNUTLS_CFLAGS}"
	LIBS="${LIBS} ${GNUTLS_LIBS}"
fi

if test "${HAVE_W32_SYSTEM}" = "yes"; then
    AC_DEFINE(CONFIG_PATH_SEPARATOR, ['\\'], [System path separator])
else
    AC_DEFINE(CONFIG_PATH_SEPARATOR, ['/'], [System path separator])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "${HAVE_W32_SYSTEM}" = "yes")

# Checks for header files.
AC_HEADER_STDC
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_CHECK_HEADERS([[ \
	stdio.h \
	stdlib.h \
	stdargs.h \
	malloc.h \
	ctype.h \
	string.h \
	errno.h \
]])
AC_CHECK_HEADERS([ \
	signal.h \
	dlfcn.h \
	unistd.h \
])

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
	CFLAGS="${CFLAGS} -ansi -pedantic -D__STRICT_ANSI__ -D_POSIX_SOURCE -D_POSIX_C_SOURCE -D_SVID_SOURCE"
fi

if test "${HAVE_W32_SYSTEM}" = "yes"; then
	LIBS="${LIBS} -lkernel32 -lgdi32 -lws2_32"
fi

AC_DEFINE_UNQUOTED([CONFIG_GPG_HOME], ["${GNUPG_HOME}"], [gnupg home])
AC_DEFINE_UNQUOTED([CONFIG_SYSTEM_CONFIG], ["${SYSTEM_CONFIG}"], [system config])

AC_CONFIG_FILES([
	Makefile
	gnupg-pkcs11-scd.spec
])
AC_OUTPUT
