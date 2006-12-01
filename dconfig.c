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
#include <pkcs11-helper-1.0/pkcs11h-core.h>
#include "dconfig.h"

static
void
trim (char * const line) {
	char *p;

	if ((p = strchr (line, '#')) != NULL) {
		*p = '\x0';
	}

	p = line;
	while (*p != '\x0') {
		if (*p == '\t' || *p == '\r' || *p == '\n') {
			*p = ' ';
		}
		p++;
	}

	p = line;
	while (*p != '\x0' && *p == ' ') {
		p++;
	}
	memmove (line, p, strlen (p)+1);

	p = line + strlen (line) - 1;
	while (p > line && *p == ' ') {
		*p = '\x0';
		p--;
	}
}

static
int
prefix_is (const char * const s, const char * const p) {
	return !strncmp (s, p, strlen (p));
}

int
dconfig_read (const char * const _file, dconfig_data * const config) {
#if defined(HAVE_W32_SYSTEM)
	char file[1024];
#else
	const char *file = _file;
#endif
	char line[1024];
	FILE *fp = NULL;
	int ok = 1;

	memset (config, 0, sizeof (dconfig_data));
	config->pin_cache = PKCS11H_PIN_CACHE_INFINITE;

#if defined(HAVE_W32_SYSTEM)
	if (!ExpandEnvironmentStrings (_file, file, sizeof (file))) {
		ok = 0;
	}
#endif

	if (ok && (fp = fopen (file, "r")) == NULL) {
		ok = 0;
		common_log (LOG_ERROR, "Cannot open configuration file '%s'", file);
	}

	while (ok && fgets (line, sizeof (line), fp) != NULL) {
		trim (line);
		
		if (!strcmp (line, "")) {
		}
		else if (prefix_is (line, "log-file")) {
			char *p = strchr (line, ' ');
			trim (p);
			config->log_file = strdup (p);
		}
		else if (!strcmp (line, "verbose")) {
			config->verbose = 1;
		}
		else if (!strcmp (line, "debug-all")) {
			config->debug = 1;
		}
		else if (prefix_is (line, "providers ")) {
			char *p = strchr (line, ' ');
			char *p2;
			int entry = 0;
			
			while (entry < DCONFIG_MAX_PROVIDERS && (p2 = strchr (p, ',')) != NULL) {
				*p2 = '\x0';
				trim (p);
				if (strlen (p) > 0) {
					config->providers[entry++].name = strdup (p);
				}

				p = p2+1;
			}

			if (entry < DCONFIG_MAX_PROVIDERS) {
				trim (p);
				if (strlen (p) > 0) {
					config->providers[entry++].name = strdup (p);
				}
			}
		}
		else if (prefix_is (line, "pin-cache ")) {
			config->pin_cache = atoi (strchr (line, ' '));
		}
		else if (prefix_is (line, "provider-")) {
			char *name = strchr (line, '-')+1;
			char *p;
			
			if ((p = strchr (name, '-')) != NULL) {
				int entry;
				*p = '\x0';
				p++;

				entry = 0;
				while (
					entry < DCONFIG_MAX_PROVIDERS &&
					config->providers[entry].name != NULL &&
					strcmp (config->providers[entry].name, name)
				) {
					entry++;
				}

				if (entry < DCONFIG_MAX_PROVIDERS) {
					if (prefix_is (p, "library ")) {
						char *p2 = strchr (p, ' ') + 1;
						trim (p2);
						config->providers[entry].library = strdup (p2);
					}
					else if (!strcmp (p, "allow-protected-auth")) {
						config->providers[entry].allow_protected = 1;
					}
					else if (prefix_is (p, "private-mask ")) {
						char *p2 = strchr (p, ' ') + 1;
						trim (p2);
						sscanf (p2, "%x", &config->providers[entry].private_mask);
					}
					else if (!strcmp (p, "cert-private")) {
						config->providers[entry].cert_is_private = 1;
					}
					else {
						ok = 0;
						common_log (LOG_ERROR, "Invalid certificate attribute '%s'", p);
					}
				}
			}
		}
		else {
			ok = 0;
			common_log (LOG_ERROR, "Invalid option '%s'", line);
		}
	}

	if (fp != NULL) {
		fclose (fp);
		fp = NULL;
	}

	if (!ok) {
		dconfig_free (config);
	}

	return ok;
}

void
dconfig_print (const dconfig_data * const config) {
	int entry;

	common_log (LOG_DEBUG, "config: debug=%d, verbose=%d", config->debug, config->verbose);
	common_log (LOG_DEBUG, "config: pin_cache=%d", config->pin_cache);

	for (entry = 0;entry < DCONFIG_MAX_PROVIDERS;entry++) {
		if (config->providers[entry].name != NULL) {
			common_log (LOG_DEBUG, "config: provider: name=%s, library=%s, allow_protected=%d, cert_is_private=%d, private_mask=%08x", config->providers[entry].name, config->providers[entry].library, config->providers[entry].allow_protected, config->providers[entry].cert_is_private, config->providers[entry].private_mask);
		}
	}
}

void
dconfig_free (dconfig_data * const config) {
#define f(x) do { \
	if (x != NULL) { \
		free (x); \
		x = NULL; \
	} \
} while (0)

	int i;

	f (config->log_file);

	for (i=0;i<DCONFIG_MAX_PROVIDERS;i++) {
		f (config->providers->name); 
		f (config->providers->library);
	}

#undef f
}

