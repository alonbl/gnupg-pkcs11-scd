/*
 * Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006-2007 Alon Bar-Lev <alon.barlev@gmail.com>
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
#include <pkcs11-helper-1.0/pkcs11h-def.h>

static FILE *log_stream = NULL;

void
common_set_log_stream (FILE *log) {
	log_stream = log;
}

FILE *
common_get_log_stream (void) {
	return log_stream;
}

void
common_vlog (
	common_log_t class,
	const char * const format,
	va_list args
) {
	unsigned id;
#if defined(HAVE_W32_SYSTEM)
	id = 0;
#else
	id = (unsigned)pthread_self ();
#endif
	if (log_stream != NULL) {
		fprintf (log_stream, "%s[%u.%u]: ", PACKAGE, (unsigned)getpid (), id);
		vfprintf (log_stream, format, args);
		fputc ('\n', log_stream);
		fflush (log_stream);
		if (class == LOG_FATAL) {
			exit (1);
		}
	}
}

void
common_log (
	common_log_t class,
	const char * const format,
	...
) {
	if (log_stream != NULL) {
		va_list args;

		va_start (args, format);
		common_vlog (class, format, args);
		va_end (args);
	}
}

gpg_err_code_t
common_map_pkcs11_error (int rv) {
	gpg_err_code_t error;

	switch (rv) {
		case CKR_OK:
			error = GPG_ERR_NO_ERROR;
		break;
		case CKR_PIN_LOCKED:
			error = GPG_ERR_PIN_BLOCKED;
		break;
		case CKR_PIN_INCORRECT:
			error = GPG_ERR_BAD_PIN;
		break;
		case CKR_DEVICE_REMOVED:
			error = GPG_ERR_CARD_REMOVED;
		break;
		case CKR_KEY_TYPE_INCONSISTENT:
			error = GPG_ERR_WRONG_PUBKEY_ALGO;
		break;
		case CKR_KEY_FUNCTION_NOT_PERMITTED:
			error = GPG_ERR_WRONG_KEY_USAGE;
		break;
		case CKR_MECHANISM_INVALID:
			error = GPG_ERR_UNSUPPORTED_ALGORITHM;
		break;
		case CKR_CANCEL:
			error = GPG_ERR_CANCELED;
		break;
		default:
			error = GPG_ERR_CARD;
		break;
	}

	return error;
}

gpg_err_code_t
common_map_assuan_error (int err)
{
	gpg_err_code_t ec;

	if (gpg_err_source ((gpg_error_t)err)) {
		return (gpg_err_code_t)err;
	}

	switch (err) {
		case -1:
			ec = GPG_ERR_EOF;
		case ASSUAN_No_Error:
			ec = GPG_ERR_NO_ERROR;
		break;
		case ASSUAN_Canceled:
			ec = GPG_ERR_CANCELED;
		break;
		case ASSUAN_Invalid_Index:
			ec = GPG_ERR_INV_INDEX;
		break;
		case ASSUAN_Not_Implemented:
			ec = GPG_ERR_NOT_IMPLEMENTED;
		break;
		case ASSUAN_Server_Fault:
			ec = GPG_ERR_ASSUAN_SERVER_FAULT;
		break;
		case ASSUAN_No_Public_Key:
			ec = GPG_ERR_NO_PUBKEY;
		break;
		case ASSUAN_No_Secret_Key:
			ec = GPG_ERR_NO_SECKEY;
		break;
		case ASSUAN_Cert_Revoked:
			ec = GPG_ERR_CERT_REVOKED;
		break;
		case ASSUAN_No_CRL_For_Cert:
			ec = GPG_ERR_NO_CRL_KNOWN;       
		break;
		case ASSUAN_CRL_Too_Old:
			ec = GPG_ERR_CRL_TOO_OLD;        
		break;
		case ASSUAN_Not_Trusted:
			ec = GPG_ERR_NOT_TRUSTED;
		break;
		case ASSUAN_Card_Error:
			ec = GPG_ERR_CARD;
		break;
		case ASSUAN_Invalid_Card:
			ec = GPG_ERR_INV_CARD;
		break;
		case ASSUAN_No_PKCS15_App:
			ec = GPG_ERR_NO_PKCS15_APP;
		break;
		case ASSUAN_Card_Not_Present:
			ec = GPG_ERR_CARD_NOT_PRESENT;
		break;
		case ASSUAN_Not_Confirmed:
			ec = GPG_ERR_NOT_CONFIRMED;
		break;
		case ASSUAN_Invalid_Id:
			ec = GPG_ERR_INV_ID;
		break;
		case ASSUAN_Locale_Problem:
			ec = GPG_ERR_LOCALE_PROBLEM;
		break;
		default:
			ec = err < 100 ? GPG_ERR_ASSUAN_SERVER_FAULT : GPG_ERR_ASSUAN;
		break;
	}

	return ec;
}

