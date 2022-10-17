/*
 * Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     o Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the <ORGANIZATION> nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __KEYUTIL_H
#define __KEYUTIL_H

#include "common.h"

typedef enum {
	KEYUTIL_KEY_TYPE_UNKNOWN,
	KEYUTIL_KEY_TYPE_RSA,
	KEYUTIL_KEY_TYPE_ECDSA_NAMED_CURVE
} keyutil_key_type_t;

typedef struct {
	keyutil_key_type_t type;
	union {
		struct {
			gcry_mpi_t n;
			gcry_mpi_t e;
		} rsa;

		struct {
			gcry_mpi_t q;
			char *named_curve;
			int named_curve_free;
		} ecdsa;
	} data;
} keyutil_keyinfo_t;

gpg_err_code_t
keyutil_get_cert_mpi (
	unsigned char *der,
	size_t len,
	keyutil_keyinfo_t *key_info
);

gpg_err_code_t
keyutil_get_cert_sexp (
	unsigned char *der,
	size_t len,
	gcry_sexp_t *p_sexp
);

char *keyutil_get_cert_hexgrip (gcry_sexp_t sexp);
void keyutil_keyinfo_init(keyutil_keyinfo_t *keyinfo, keyutil_key_type_t keytype);
void keyutil_keyinfo_free(keyutil_keyinfo_t *keyinfo);

#endif
