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

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)
CLEANFILES = \
	gnupg-pkcs11-scd.1.html \
	$(NULL)

AM_CFLAGS = \
	$(LIBGPG_ERROR_CFLAGS) \
	$(LIBASSUAN_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(PKCS11_HELPER_CFLAGS) \
	$(CRYPTO_CFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(NULL)
LDADD = \
	$(LIBGPG_ERROR_LIBS) \
	$(LIBASSUAN_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(PKCS11_HELPER_LIBS) \
	$(CRYPTO_LIBS) \
	$(PTHREAD_LIBS) \
	$(NULL)

bin_PROGRAMS = \
	gnupg-pkcs11-scd \
	$(NULL)
dist_doc_DATA = \
	gnupg-pkcs11-scd.conf.example \
	$(NULL)

gnupg_pkcs11_scd_SOURCES= \
	scdaemon.c \
	common.h common.c \
	strgetopt.h strgetopt.c \
	command.h command.c \
	encoding.h encoding.c \
	keyutil.h keyutil.c \
	dconfig.h dconfig.c \
	$(NULL)

if HAVE_W32_SYSTEM
EXTRA_DIST = \
	gnupg-pkcs11-scd.1 \
	$(NULL)
dist_man_MANS =
nodist_html_DATA = \
	gnupg-pkcs11-scd.1.html \
	$(NULL)

gnupg-pkcs11-scd.1.html: gnupg-pkcs11-scd.1
	$(MAN2HTML) < "$^" > "$@"
else
dist_man_MANS = \
	gnupg-pkcs11-scd.1 \
	$(NULL)
endif
