/*
 * Copyright (c) 2006 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006 Alon Bar-Lev <alon.barlev@gmail.com>
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

#include "common.h"
#include <ctype.h>
#include "encoding.h"

/* p_target must be free () */

int
encoding_hex2bin (
	const char * const source,
	unsigned char * * const p_target,
	size_t * const p_target_size
) {
	unsigned char *target = NULL;
	const char *p;
	char buf[3] = {'\0', '\0', '\0'};
	int i = 0;

	p = source;
	*p_target = NULL;
	*p_target_size = 0;

	target = (unsigned char *)malloc (strlen (source) / 2);

	while (target != NULL && *p != '\x0') {
		if (isxdigit ((unsigned char)*p)) {
			buf[i%2] = *p;

			if ((i%2) == 1) {
				unsigned v;
				if (sscanf (buf, "%x", &v) != 1) {
					v = 0;
				}
				target[*p_target_size] = (char)(v & 0xff);
				(*p_target_size)++;
			}
			i++;
		}
		p++;
	}

	*p_target = target;

	return 1;
}

/* return string must be free() */
char *
encoding_bin2hex (
	const unsigned char * const source,
	const size_t source_size
) {
	static const char *x = "0123456789ABCDEF";
	char * target = NULL;
	size_t i;

	if ((target = (char *)malloc (source_size*2+1)) != NULL) {
		for (i=0;i<source_size;i++) {
			target[i*2] =   x[(source[i]&0xf0)>>4];
			target[i*2+1] = x[(source[i]&0x0f)>>0];
		}
		target[source_size*2] = '\x0';
	}

	return target;
}

/* p_str must by dynamic allocated */
int
encoding_strappend (
	char * * const p_str,
	char *s
) {
	char *p = (char *)realloc (*p_str, strlen (*p_str)+strlen(s)+1);
	if (p == NULL) {
		return 0;
	}
	*p_str = p;
	strcat (*p_str, s);
	return 1;
}

