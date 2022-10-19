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
	KEYINFO_KEY_TYPE_INVALID = -1,
	KEYINFO_KEY_TYPE_UNKNOWN = 0,
	KEYINFO_KEY_TYPE_RSA,
	KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE
} keyinfo_key_type_t;

struct keyinfo_s;
typedef struct keyinfo_s *keyinfo;

struct keyinfo_data_list_s {
	struct keyinfo_data_list_s *next;
	unsigned char *type;
	unsigned char *tag;
	unsigned char *value;
	void (*value_free)(void *);
	void (*tag_free)(void *);
};
typedef struct keyinfo_data_list_s *keyinfo_data_list;


/**
 * Instantiate a new key
 */
keyinfo keyinfo_new(void);

/**
 * Free a key
 */
void keyinfo_free(keyinfo keyinfo);

/**
 * Get the Key Type (RSA, ECDSA) from a key
 */
keyinfo_key_type_t keyinfo_get_type(keyinfo keyinfo);

/**
 * Get the size of data which may be signed/encrypted
 */
ssize_t keyinfo_get_data_length(keyinfo keyinfo, size_t input_length);

/**
 * Parse a DER-encoded X.509 certificate into a key
 */
gpg_err_code_t keyinfo_from_der(keyinfo keyinfo, unsigned char *der, size_t len);

/**
 * Produce a libgcrypt S-expression representing a key
 */
gcry_sexp_t keyinfo_to_sexp(keyinfo keyinfo);

/**
 * Produce a "hexgrip" from a libgcrypt S-expression representing a key
 */
char *keyinfo_get_hexgrip(gcry_sexp_t sexp);

/**
 * Get the serialized form of a key, in parts as a linked list
 */
keyinfo_data_list keyinfo_get_key_data(keyinfo keyinfo);

/**
 * Free the list of serialized parts of a key
 */
void keyinfo_data_free(keyinfo_data_list list);


#endif
