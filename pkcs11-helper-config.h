/*
 * Copyright (c) 2005-2006 Alon Bar-Lev.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PKCS11H_HELPER_CONFIG_H
#define __PKCS11H_HELPER_CONFIG_H

#if !defined(PKCS11H_NO_NEED_INCLUDE_CONFIG)

#include "common.h"

#endif /* PKCS11H_NO_NEED_INCLUDE_CONFIG */

#define ENABLE_PKCS11H_HELPER

#if defined(ENABLE_PKCS11H_HELPER)

#include <assert.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#if !defined(WIN32)
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/time.h>
#endif

#if defined(HAVE_CYGWIN)
#define PKCS11H_USE_CYGWIN
#endif

#if !defined(FALSE)
#define FALSE 0
#endif
#if !defined(TRUE)
#define TRUE (!FALSE)
#endif

typedef int PKCS11H_BOOL;

#if !defined(IN)
#define IN
#endif
#if !defined(OUT)
#define OUT
#endif

#if defined(ENABLE_OPENSSL)
#define ENABLE_PKCS11H_ENGINE_OPENSSL
#endif
#if defined(ENABLE_GNUTLS)
#define ENABLE_PKCS11H_ENGINE_GNUTLS
#endif

#define ENABLE_PKCS11H_DEBUG
#define ENABLE_PKCS11H_THREADING
#define ENABLE_PKCS11H_TOKEN
#undef  ENABLE_PKCS11H_DATA
#define ENABLE_PKCS11H_CERTIFICATE
#undef  ENABLE_PKCS11H_LOCATE
#define ENABLE_PKCS11H_ENUM
#define ENABLE_PKCS11H_SERIALIZATION
#undef  ENABLE_PKCS11H_SLOTEVENT
#undef  ENABLE_PKCS11H_OPENSSL
#undef  ENABLE_PKCS11H_STANDALONE

#define PKCS11H_ASSERT		assert

#if defined(ENABLE_PKCS11H_ENGINE_OPENSSL)
#include <openssl/x509.h>
#endif

#if defined(ENABLE_PKCS11H_ENGINE_GNUTLS)
#include <gnutls/x509.h>
#endif

#if defined(WIN32) || defined(PKCS11H_USE_CYGWIN)
#include "cryptoki-win32.h"
#else
#include "cryptoki.h"
#endif

#endif		/* ENABLE_PKCS11H_HELPER */
#endif		/* __PKCS11H_HELPER_CONFIG_H */
