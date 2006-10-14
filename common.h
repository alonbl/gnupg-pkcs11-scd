/*
 * Copyright (c) 2006 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __COMMON_H
#define __COMMON_H

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <gpg-error.h>
#include <assuan.h>
#include <gcrypt.h>
#if defined(HAVE_W32_SYSTEM)
#include <windows.h>
#else
#include <pthread.h>
#endif

#if defined(USE_VALGRIND)
#include "valgrind/memcheck.h"
#endif

typedef enum {
	LOG_DEBUG=0,
	LOG_INFO,
	LOG_WARNING,
	LOG_ERROR,
	LOG_FATAL
} common_log_t;

gpg_err_code_t common_map_pkcs11_error (int rv);
gpg_err_code_t common_map_assuan_error (int err);

void
common_set_log_stream (FILE *log);

FILE *
common_get_log_stream ();

void
common_vlog (
	common_log_t class,
	const char * const format,
	va_list args
);

void
common_log (
	common_log_t class,
	const char * const format,
	...
);

#endif
