#
# Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>
# Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>
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

AC_PREREQ([2.60])

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [9])
define([PACKAGE_VERSION_FIX], [2])
define([PACKAGE_SUFFIX], [_master])

AC_INIT([gnupg-pkcs11-scd], [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([gnupg-pkcs11-scd/common.h])
AM_INIT_AUTOMAKE

GNUPG_PKCS11_SCD_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
GNUPG_PKCS11_SCD_VERSION_MINOR="PACKAGE_VERSION_MINOR"
GNUPG_PKCS11_SCD_VERSION_FIX="PACKAGE_VERSION_FIX"

AC_SUBST([GNUPG_PKCS11_SCD_VERSION_MAJOR])
AC_SUBST([GNUPG_PKCS11_SCD_VERSION_MINOR])
AC_SUBST([GNUPG_PKCS11_SCD_VERSION_FIX])

AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG
AC_CHECK_PROGS([M4], [m4])

AC_ARG_WITH(
	[cygwin-native],
	[AC_HELP_STRING([--with-cygwin-native], [compile native win32])],
	,
	[with_cygwin_native="no"]
)

test -z "${HAVE_W32_SYSTEM}" && HAVE_W32_SYSTEM="no"
test -z "${CYGWIN}" && CYGWIN="no"
case "${host}" in
	*-mingw*)
		AC_DEFINE([HAVE_W32_SYSTEM], [1], [Defined if we run on a W32 API based system])
		HAVE_W32_SYSTEM="yes"
	;;
	*-winnt*)
		AC_DEFINE([HAVE_W32_SYSTEM], [1], [Defined if we run on a W32 API based system])
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

AC_ARG_ENABLE(
	[strict],
	[AC_HELP_STRING([--enable-strict], [enable strict compiler warnings])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AC_HELP_STRING([--enable-pedantic], [enable pedantic compiler warnings])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[proxy],
	[AC_HELP_STRING([--enable-proxy], [enable gnupg-pkcs11-scd-proxy])],
	,
	[enable_proxy="no"]
)

AC_ARG_WITH(
	[proxy-socket],
	[AC_HELP_STRING([--with-proxy-socket=FILE], [set proxy socket @<:@LOCALSTATEDIR/run/gnupg-pkcs11-scd-proxy/cmd@:>@])],
	,
	[with_proxy_socket="\${localstatedir}/run/gnupg-pkcs11-scd-server/cmd"]
)

AC_ARG_WITH(
	[proxy-user],
	[AC_HELP_STRING([--with-proxy-user=USER], [set proxy user @<:@gnupg-pkcs11-scd-proxy@:>@])],
	,
	[with_proxy_user="gnupg-pkcs11-scd-proxy"]
)

AC_ARG_WITH(
	[proxy-user-group],
	[AC_HELP_STRING([--with-proxy-user-group=GROUP], [set proxy user group @<:@gnupg-pkcs11-scd-proxy@:>@])],
	,
	[with_proxy_user_group="gnupg-pkcs11-scd-proxy"]
)

AC_ARG_WITH(
	[proxy-group],
	[AC_HELP_STRING([--with-proxy-group=GROUP], [set proxy group @<:@gnupg-pkcs11@:>@])],
	,
	[with_proxy_group="gnupg-pkcs11"]
)

AC_ARG_WITH(
	[openssl],
	[AC_HELP_STRING([--without-openssl], [disable OpenSSL linkage)])],
	,
	[with_openssl="yes"]
)

AC_ARG_WITH(
	[gnutls],
	[AC_HELP_STRING([--without-gnutls], [disable GNUTLS linkage (OpenSSL will be used if both enabled)])],
	,
	[with_gnutls="yes"]
)

AC_ARG_WITH(
	[system-config],
	[AC_HELP_STRING([--with-system-config=FILE], [define gnupg system wide config])],
	[SYSTEM_CONFIG="${withval}"],
	[test "${HAVE_W32_SYSTEM}" = "yes" && SYSTEM_CONFIG="%SystemRoot%\\\\${PACKAGE}.conf" || SYSTEM_CONFIG="/etc/${PACKAGE}.conf"]
)

AC_ARG_WITH(
	[gnupg-home],
	[AC_HELP_STRING([--with-gnupg-home=DIR], [define gnupg home])],
	[GNUPG_HOME="${withval}"],
	[test "${HAVE_W32_SYSTEM}" = "yes" && GNUPG_HOME="~\\\\.gnupg" || GNUPG_HOME="~/.gnupg"]
)

AC_ARG_WITH(
	[libgpg-error-prefix],
	[AC_HELP_STRING([--with-libgpg-error-prefix=DIR], [define libgpgp-error prefix])],
	,
	[with_libgpg_error_prefix="/usr" ]
)

AC_ARG_WITH(
	[libassuan-prefix],
	[AC_HELP_STRING([--with-libassuan-prefix=DIR], [define libassuan prefix])],
	,
	[with_libassuan_prefix="/usr" ]
)

AC_ARG_WITH(
	[libgcrypt-prefix],
	[AC_HELP_STRING([--with-libgcrypt-prefix=DIR], [define libgcrypt prefix])],
	,
	[with_libgcrypt_prefix="/usr" ]
)

if test "${HAVE_W32_SYSTEM}" = "yes"; then
	AC_CHECK_PROGS([MAN2HTML], [man2html])
	test -z "${MAN2HTML}" && AC_MSG_ERROR([man2html is required for win32])
fi

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	CFLAGS="${CFLAGS} -ansi -pedantic -D__STRICT_ANSI__ -D_ISOC99_SOURCE -D_DEFAULT_SOURCE"
fi

if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra -Wpointer-arith -Wsign-compare -Wno-unused-parameter -Wno-unused-function"
fi

AC_FUNC_MKTIME
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	gettimeofday memmove memset socket strchr strdup strerror strrchr \
	snprintf timegm unsetenv \
])

AX_PTHREAD(, [AC_MSG_ERROR([Cannot find pthreads])])
CC="${PTHREAD_CC}"

AC_ARG_VAR([LIBGPG_ERROR_CFLAGS], [C compiler flags for libgpg-error])
AC_ARG_VAR([LIBGPG_ERROR_LIBS], [linker flags for libgpg-error])
if test -z "${LIBGPG_ERROR_LIBS}"; then
	AC_MSG_CHECKING([for libgpg-error])
	if ! test -x "${with_libgpg_error_prefix}/bin/gpg-error-config"; then
		AC_MSG_ERROR([Cannot locate libgpg-error])
	else
		AC_MSG_RESULT([found])
		LIBGPG_ERROR_CFLAGS="`\"${with_libgpg_error_prefix}/bin/gpg-error-config\" --cflags`"
		LIBGPG_ERROR_LIBS="`\"${with_libgpg_error_prefix}/bin/gpg-error-config\" --libs`"
	fi
fi

AC_ARG_VAR([LIBASSUAN_CFLAGS], [C compiler flags for libassuan])
AC_ARG_VAR([LIBASSUAN_LIBS], [linker flags for libassuan])
if test -z "${LIBASSUAN_LIBS}"; then
	AC_MSG_CHECKING([for libassuan])
	test -x "${with_libassuan_prefix}/bin/libassuan-config" || AC_MSG_ERROR([Cannot locate libassuan])
	"${with_libassuan_prefix}/bin/libassuan-config" --version | grep "^2\." > /dev/null || AC_MSG_ERROR([Need assuan-2])

	AC_MSG_RESULT([found])

	LIBASSUAN_CFLAGS="`\"${with_libassuan_prefix}/bin/libassuan-config\" --cflags`"
	LIBASSUAN_LIBS="`\"${with_libassuan_prefix}/bin/libassuan-config\" --libs`"
fi

AC_ARG_VAR([LIBGCRYPT_CFLAGS], [C compiler flags for libgcrypt])
AC_ARG_VAR([LIBGCRYPT_LIBS], [linker flags for libgcrypt])
if test -z "${LIBGCRYPT_LIBS}"; then
	AC_MSG_CHECKING([for libgcrypt])
	if ! test -x "${with_libgcrypt_prefix}/bin/libgcrypt-config"; then
		AC_MSG_ERROR([Cannot locate libgcrypt])
	else
		AC_MSG_RESULT([found])
		LIBGCRYPT_CFLAGS="`\"${with_libgcrypt_prefix}/bin/libgcrypt-config\" --cflags`"
		LIBGCRYPT_LIBS="`\"${with_libgcrypt_prefix}/bin/libgcrypt-config\" --libs`"
	fi
fi

PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 0.9.7], [HAVE_OPENSSL="yes"], [HAVE_OPENSSL="no"])
if test "${HAVE_OPENSSL}" = "no"; then
	PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.7], [HAVE_OPENSSL="yes"], [HAVE_OPENSSL="no"])
fi

PKG_CHECK_MODULES([GNUTLS], [gnutls >= 1.4], [HAVE_GNUTLS="yes"], [HAVE_GNUTLS="no"])

PKG_CHECK_MODULES([PKCS11_HELPER], [libpkcs11-helper-1 >= 1.02],, [AC_MSG_ERROR([Cannot locate pkcs11-helper])])
PKCS11_HELPER_1_CHECK_FEATURES([threading token certificate engine_crypto])

AC_MSG_CHECKING([cryptographic library to use])

if test "${with_openssl}" = "yes" -a "${HAVE_OPENSSL}" != "yes"; then
	with_openssl="no"
fi

if test "${with_gnutls}" = "yes" -a "${HAVE_GNUTLS}" != "yes"; then
	with_gnutls="no"
fi

if test "${with_openssl}" = "no" -a "${with_gnutls}" = "no"; then
	AC_MSG_ERROR([Cannot locate OpenSSL or GNUTLS])
fi

AC_SUBST([CONFIG_PROXY_SOCKET], [${with_proxy_socket}])
AC_SUBST([CONFIG_PROXY_USER], [${with_proxy_user}])
AC_SUBST([CONFIG_PROXY_USER_GROUP], [${with_proxy_user_group}])
AC_SUBST([CONFIG_PROXY_GROUP], [${with_proxy_group}])
AC_DEFINE_UNQUOTED([CONFIG_PROXY_GROUP], ["${with_proxy_group}"], [proxy group])
AM_CONDITIONAL([ENABLE_PROXY], [test "${enable_proxy}" = "yes"])

if test "${with_openssl}" = "yes"; then
	AC_MSG_RESULT([Using OpenSSL])
	AC_DEFINE([ENABLE_OPENSSL], [1], [Use OpenSSL library])
	CRYPTO_CFLAGS="${OPENSSL_CFLAGS}"
	CRYPTO_LIBS="${OPENSSL_LIBS}"
else
	AC_MSG_RESULT([Using GNUTLS])
	AC_DEFINE([ENABLE_GNUTLS], [1], [Use GNUTLS library])
	CRYPTO_CFLAGS="${GNUTLS_CFLAGS}"
	CRYPTO_LIBS="${GNUTLS_LIBS}"
fi
AC_SUBST([CRYPTO_CFLAGS])
AC_SUBST([CRYPTO_LIBS])

if test "${HAVE_W32_SYSTEM}" = "yes"; then
	AC_DEFINE([CONFIG_PATH_SEPARATOR], ['\\'], [System path separator])
else
	AC_DEFINE([CONFIG_PATH_SEPARATOR], ['/'], [System path separator])
fi
AM_CONDITIONAL([HAVE_W32_SYSTEM], [test "${HAVE_W32_SYSTEM}" = "yes"])

AC_HEADER_STDC
AC_C_CONST
AC_C_VOLATILE
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_CHECK_HEADERS([ \
	stdio.h \
	stdlib.h \
	stdargs.h \
	malloc.h \
	ctype.h \
	string.h \
	errno.h \
])
AC_CHECK_HEADERS([ \
	signal.h \
	dlfcn.h \
	unistd.h \
])
AC_CHECK_HEADERS([sys/ucred.h])

AC_CHECK_DECLS(
	[SO_PEERCRED],,,
	[[
		#include <sys/types.h>
		#include <sys/socket.h>
		#include <sys/un.h>
	]]
)
AC_CHECK_DECLS(
	[LOCAL_PEERCRED],,,
	[[
		#include <sys/types.h>
		#include <sys/socket.h>
		#include <sys/un.h>
		#ifdef HAVE_SYS_UCRED_H
		#include <sys/ucred.h>
		#endif
	]]
)

AC_DEFINE_UNQUOTED([CONFIG_GPG_HOME], ["${GNUPG_HOME}"], [gnupg home])
AC_DEFINE_UNQUOTED([CONFIG_SYSTEM_CONFIG], ["${SYSTEM_CONFIG}"], [system config])

AC_CONFIG_FILES([
	Makefile
	gnupg-pkcs11-scd-proxy/Makefile
	gnupg-pkcs11-scd-proxy/gnupg-pkcs11-scd-proxy.service.in
	gnupg-pkcs11-scd/Makefile
	distro/Makefile
	distro/debian/Makefile
	distro/rpm/Makefile
	distro/rpm/gnupg-pkcs11-scd.spec
])
AC_OUTPUT
