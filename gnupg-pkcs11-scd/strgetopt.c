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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "strgetopt.h"

const char *
strgetopt_getopt(
	const char * const str,
	const struct strgetopt_option * const options
) {
	const char * p = str;

	while (*p != '\0') {
		const struct strgetopt_option *o;

		while (*p != '\0' && isspace(*p)) {
			p++;
		}

		if (*p == '-' && *(p+1) == '-') {
			const char *p1;
			const char *p2 = NULL;
			p += 2;

			p1 = p;
			while (*p1 != '\0' && (isalnum(*p1) || *p1 == '-')) {
				p1++;
			}

			if (p == p1) {
				break;
			}

			if (*p1 == '=') {
				p2 = p1 + 1;
				while (*p2 != '\0' && !isspace(*p2)) {
					p2++;
				}
			}

			for (o = options; o != NULL && o->name != NULL; o++) {
				if (strlen(o->name) == (size_t)(p1-p) && !strncmp(o->name, p, p1-p)) {
					if (o->has_arg == strgtopt_no_argument) {
						*o->found = 1;
					} else if (o->has_arg == strgtopt_optional_argument && p2 == NULL) {
						*o->value = strdup("");
					} else if (o->has_arg != strgtopt_no_argument && p2 != NULL) {

						if (*o->value != NULL) {
							free(*o->value);
							*o->value = NULL;
						}

						if ((*o->value = malloc(p2-p1)) == NULL) {
							goto cleanup;
						}

						memcpy(*o->value, p1 + 1, p2-p1-1);
						(*o->value)[p2-p1-1] = '\0';
					}
				}
			}

			p = p2 != NULL ? p2 : p1;
		} else {
			break;
		}
	}

	while (*p != '\0' && isspace(*p)) {
		p++;
	}

cleanup:

	return p;
}

void
strgetopt_free(
	const struct strgetopt_option * const options
) {
	const struct strgetopt_option *o;

	for (o = options; o->name != NULL; o++) {
		if (o->value) {
			free(*o->value);
		}
	}
}
