#
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
	$(NULKL)
CLEANFILES = \
	gnupg-pkcs11-scd-proxy.1.html \
	gnupg-pkcs11-scd-proxy.service \
	$(NULL)

SUFFIXES = .in

AM_CPPFLAGS = \
	-DCONFIG_PROXY_SOCKET='"@CONFIG_PROXY_SOCKET@"' \
	-DCONFIG_SCD_BIN='"$(bindir)/gnupg-pkcs11-scd"' \
	$(NULL)

if ENABLE_PROXY
bin_PROGRAMS = \
	gnupg-pkcs11-scd-proxy \
	gnupg-pkcs11-scd-proxy-server \
	$(NULL)
nodist_noinst_DATA = \
	gnupg-pkcs11-scd-proxy.service \
	$(NULL)
dist_man_MANS = \
	gnupg-pkcs11-scd-proxy.1 \
	$(NULL)
else
EXTRA_DIST = \
	gnupg-pkcs11-scd-proxy.1 \
	$(NULL)
endif

gnupg_pkcs11_scd_proxy_SOURCES= \
	gnupg-pkcs11-scd-proxy.c \
	$(NULL)

gnupg_pkcs11_scd_proxy_server_SOURCES= \
	gnupg-pkcs11-scd-proxy-server.c \
	$(NULL)


.in:
	sed \
		-e 's#@bindir_POST[@]#$(bindir)#g' \
		-e 's#@CONFIG_PROXY_SOCKET_POST[@]#$(CONFIG_PROXY_SOCKET)#g' \
		< $< > $@
