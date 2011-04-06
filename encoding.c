/*
 * Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006-2011 Alon Bar-Lev <alon.barlev@gmail.com>
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

/* From gnupg */

/*
  timegm() is a GNU function that might not be available everywhere.
  It's basically the inverse of gmtime() - you give it a struct tm,
  and get back a time_t.  It differs from mktime() in that it handles
  the case where the struct tm is UTC and the local environment isn't.

  Note, that this replacement implementaion is not thread-safe!

  Some BSDs don't handle the putenv("foo") case properly, so we use
  unsetenv if the platform has it to remove environment variables.
*/
#ifndef HAVE_TIMEGM
static char old_zone[1024];
time_t
timegm (struct tm *tm)
{
	time_t answer;
	char *zone;

	zone=getenv("TZ");
	putenv("TZ=UTC");
	tzset();
	answer=mktime(tm);
	if(zone) {
		if (strlen (old_zone) == 0) {
			snprintf(old_zone, sizeof(old_zone), "TZ=%s", zone);
			old_zone[sizeof(old_zone)-1] = '\0';
		}
		putenv (old_zone);
	}
	else {
#ifdef HAVE_UNSETENV
		unsetenv("TZ");
#else
		putenv("TZ");
#endif
	}

	tzset();

	return answer;
}
#endif /*!HAVE_TIMEGM*/

time_t
isotime2epoch (
	const char * const string
) {
	const char *s;
	int year, month, day, hour, minu, sec;
	struct tm tmbuf;
	int i;

	if (!*string)
		return (time_t)(-1);
	for (s=string, i=0; i < 8; i++, s++)
		if (!isdigit (*s))
			return (time_t)(-1);
	if (*s != 'T')
		return (time_t)(-1);
	for (s++, i=9; i < 15; i++, s++)
		if (!isdigit (*s))
			return (time_t)(-1);
	if ( !(!*s || (isascii (*s) && isspace(*s)) || *s == ':' || *s == ','))
		return (time_t)(-1);  /* Wrong delimiter.  */

	year  = (string[0]-'0') * 1000 + (string[1]-'0') * 100 + (string[2]-'0') * 10 + (string[3]-'0') * 1;
	month = (string[4]-'0') * 10 + (string[5]-'0');
	day   = (string[6]-'0') * 10 + (string[7]-'0');
	hour  = (string[9]-'0') * 10 + (string[10]-'0');
	minu  = (string[11]-'0') * 10 + (string[12]-'0');
	sec   = (string[13]-'0') * 10 + (string[14]-'0');

	/* Basic checks.  */
	if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31
		|| hour > 23 || minu > 59 || sec > 61 )
		return (time_t)(-1);

	memset (&tmbuf, 0, sizeof tmbuf);
	tmbuf.tm_sec  = sec;
	tmbuf.tm_min  = minu;
	tmbuf.tm_hour = hour;
	tmbuf.tm_mday = day;
	tmbuf.tm_mon  = month-1;
	tmbuf.tm_year = year - 1900;
	tmbuf.tm_isdst = -1;
	return timegm (&tmbuf);
}
