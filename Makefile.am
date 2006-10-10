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

# This option prevents autoreconf from overriding our COPYING and
# INSTALL targets:
AUTOMAKE_OPTIONS=foreign dist-bzip2

PKCS11_INCLUDES=pkcs11-headers/*.h cryptoki.h cryptoki-win32.h

bin_PROGRAMS=gnupg-pkcs11-scd
gnupg_pkcs11_scd_SOURCES= \
	common.h \
	scdaemon.h scdaemon.c \
	common.h common.c \
	command.h command.c \
	encoding.h encoding.c \
	keyutil.h keyutil.c \
	dconfig.h dconfig.c \
	pkcs11-helper.h pkcs11-helper.c pkcs11-helper-config.h \
	${PKCS11_INCLUDES}
dist_man_MANS=gnupg-pkcs11-scd.8
EXTRA_DIST=gnupg-pkcs11-scd.conf.example

