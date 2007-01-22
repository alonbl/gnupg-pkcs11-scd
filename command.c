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
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include "command.h"
#include "scdaemon.h"
#include "encoding.h"
#include "keyutil.h"

/**
   @file
   Implementation of assuan commands. Currently, only one card is supported,
   and the first one seen is used.

   In GnuPG, Certificate has both an ID and an associated keypar (identified
   by keygrip). All of these IDs are exchanged in hex-encoded form. We use
   displayName given by pkcs11helper (which is actually OpenSSL formatted DN
   from the certificate) as the certificate ID.
*/

static
gpg_err_code_t
get_cert_blob (
	assuan_context_t ctx,
	pkcs11h_certificate_id_t cert_id,
	unsigned char **p_blob,
	size_t *p_blob_size
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_t cert = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;

	*p_blob = NULL;
	*p_blob_size = 0;

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_create (
				cert_id,
				ctx,
				PKCS11H_PROMPT_MASK_ALLOW_ALL,
				PKCS11H_PIN_CACHE_INFINITE,
				&cert
			)
		)) != GPG_ERR_NO_ERROR ||
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_getCertificateBlob (
				cert,
				NULL,
				&blob_size
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((blob = (unsigned char *)malloc (blob_size)) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_getCertificateBlob (
				cert,
				blob,
				&blob_size
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	*p_blob = blob;
	*p_blob_size = blob_size;
	blob = NULL;

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (cert != NULL) {
		pkcs11h_certificate_freeCertificate (cert);
		cert = NULL;
	}

	if (blob != NULL) {
		free (blob);
		blob = NULL;
	}

	return error;
}

static
gpg_err_code_t
get_cert_sexp (
	assuan_context_t ctx,
	pkcs11h_certificate_id_t cert_id,
	gcry_sexp_t *p_sexp
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	gcry_sexp_t sexp = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;

	*p_sexp = NULL;

	if (
		(error = get_cert_blob (ctx, cert_id, &blob, &blob_size)) != GPG_ERR_NO_ERROR ||
		(error = keyutil_get_cert_sexp (blob, blob_size, &sexp)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	*p_sexp = sexp;
	sexp = NULL;

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (sexp != NULL) {
		gcry_sexp_release(sexp);
		sexp = NULL;
	}

	if (blob != NULL) {
		free (blob);
		blob = NULL;
	}

	return error;
}

/**
   Send status lines in the format

   S KEYPAIRINFO <hexstring_with_keygrip> <hexstring_with_id>
   S CERTINFO <certtype> <hexstring_with_id>

   If certificate is issuer, we set type to 102 (useful); otherwise it is
   assumed that we're in posession of private key, so the type is set to 101
   (trusted).  The certificate ID is percent-plus escaped displayName.
*/
static
int
send_certificate_list (
	assuan_context_t ctx,
	pkcs11h_certificate_id_list_t head,	/* list head */
	int is_issuer				/* true if issuer certificate */
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_list_t curr_cert;
	
	for (
		curr_cert = head;
		curr_cert != NULL;
		curr_cert = curr_cert->next
	) {
		char *certid = NULL;
		char *key_hexgrip = NULL;
		char *info_cert = NULL;
		gcry_sexp_t sexp = NULL;
		size_t ser_len;

		if ((error = get_cert_sexp (ctx, curr_cert->certificate_id, &sexp)) != GPG_ERR_NO_ERROR) {
			goto retry;
		}

		if ((key_hexgrip = keyutil_get_cert_hexgrip (sexp)) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto retry;
		}

		if (
			(error = common_map_pkcs11_error (
				pkcs11h_certificate_serializeCertificateId (
					NULL,
					&ser_len,
					curr_cert->certificate_id
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto retry;
		}

		if ((certid = (char *)malloc (ser_len)) == NULL	) {
			error = GPG_ERR_ENOMEM;
			goto retry;
		}

		if (
			(error = common_map_pkcs11_error (
				pkcs11h_certificate_serializeCertificateId (
					certid,
					&ser_len,
					curr_cert->certificate_id
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto retry;
		}

		if ((info_cert = strdup (is_issuer ? "102 " : "101 ")) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto retry;
		}

		if (!encoding_strappend (&info_cert, certid)) {
			error = GPG_ERR_ENOMEM;
			goto retry;
		}

		if (
			(error = common_map_assuan_error (
				assuan_write_status (
					ctx,
					"CERTINFO",
					info_cert
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto retry;
		}

		/* send keypairinfo if not issuer certificate */
		if(!is_issuer) {
			if (
				!encoding_strappend (&key_hexgrip, " ") ||
				!encoding_strappend (&key_hexgrip, certid)
			) {
				error = GPG_ERR_ENOMEM;
				goto retry;
			}

			if (
				(error = common_map_assuan_error (
					assuan_write_status (
						ctx,
						"KEYPAIRINFO",
						key_hexgrip
					)
				)) != GPG_ERR_NO_ERROR
			) {
				goto retry;
			}
		}

		error = GPG_ERR_NO_ERROR;

	retry:

		if (info_cert != NULL) {
			free (info_cert);
			info_cert = NULL;
		}

		if (certid != NULL) {
			free (certid);
			certid = NULL;
		}

		if (key_hexgrip != NULL) {
			free (key_hexgrip);
			key_hexgrip = NULL;
		}

		if (error != GPG_ERR_NO_ERROR) {
			goto cleanup;
		}
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	return error;
}

static void _cmd_free_data (cmd_data_t *data) {
	if (data != NULL) {
		if (data->data != NULL) {
			free (data->data);
			data->data = NULL;
		}
		free (data);
	}
}

void cmd_free_data (assuan_context_t ctx) {
	_cmd_free_data ((cmd_data_t *)assuan_get_pointer (ctx));
	assuan_set_pointer (ctx, NULL);
}

/**
   Returns the card serial number and internally enumerates all certificates.
   This function MUST be called before any other operation with the card.
*/
int cmd_serialno (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
#if defined(COMMENT)
	pkcs11h_token_id_list_t list = NULL;
	pkcs11h_token_id_list_t i;
#endif

	(void)line;

	/*
	 * @ALON
	 * I am amazed!!!!
	 *
	 * gpg-agent does not support more than one serial number!!!
	 * it does not matter anyhow, since we go by certificate_id
	 * but still... it is stupid!
	 */
	{
		char *serial_and_stamp = NULL;
		char *ser_token = "PKCS#11 TOKEN";

		/*
		 * serial number has to be hex-encoded data,
		 * followed by " 0"
		 */
		if (
			(serial_and_stamp = encoding_bin2hex (
				(unsigned char *)ser_token,
				strlen (ser_token)
			)) == NULL
		) {
			error = GPG_ERR_GENERAL;
			goto cleanup;
		}

		if (!encoding_strappend (&serial_and_stamp, " 0")) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		if (
			(error = common_map_assuan_error (
				assuan_write_status(
					ctx,
					"SERIALNO",
					serial_and_stamp
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}

		error = GPG_ERR_NO_ERROR;

	cleanup:

		if (serial_and_stamp != NULL) {
			free (serial_and_stamp);
			serial_and_stamp = NULL;
		}
	}

#if defined(COMMENT)
	if (
		(error = common_map_pkcs11_error (
			pkcs11h_token_enumTokenIds (
				PKCS11H_ENUM_METHOD_RELOAD,
				&list
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (list == NULL) {
		error = GPG_ERR_CARD_NOT_PRESENT;
		goto cleanup;
	}

	for (i=list;i!=NULL;i=i->next) {
		char *serial_and_stamp = NULL;
		char *ser_token = NULL;
		size_t ser_len;

		if (
			(error = common_map_pkcs11_error (
				pkcs11h_token_serializeTokenId (
					NULL,
					&ser_len,
					i->token_id
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto retry;
		}

		if ((ser_token = (char *)malloc (ser_len)) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto retry;
		}

		if (
			(error = common_map_pkcs11_error (
				pkcs11h_token_serializeTokenId (
					ser_token,
					&ser_len,
					i->token_id
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto retry;
		}

		/*
		 * serial number has to be hex-encoded data,
		 * followed by " 0"
		 */
		if (
			(serial_and_stamp = encoding_bin2hex (
				(unsigned char *)ser_token,
				strlen (ser_token)
			)) == NULL
		) {
			error = GPG_ERR_GENERAL;
			goto retry;
		}

		if (!encoding_strappend (&serial_and_stamp, " 0")) {
			error = GPG_ERR_ENOMEM;
			goto retry;
		}

		if (
			(error = common_map_assuan_error (
				assuan_write_status(
					ctx,
					"SERIALNO",
					serial_and_stamp
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto retry;
		}

		error = GPG_ERR_NO_ERROR;
	
	cleanup:

		if (serial_and_stamp != NULL) {
			free (serial_and_stamp);
			serial_and_stamp = NULL;
		}

		if (ser_token != NULL) {
			free (ser_token);
			ser_token = NULL;
		}
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (list != NULL) {
		pkcs11h_token_freeTokenIdList (list);
		list = NULL;
	}
#endif

	return gpg_error (error);
}

/** TODO: handle --force option! */
int cmd_learn (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	pkcs11h_certificate_id_list_t issuer_certificates = NULL;

	(void)line;

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_enumCertificateIds (
				PKCS11H_ENUM_METHOD_CACHE_EXIST,
				ctx,
				PKCS11H_PROMPT_MASK_ALLOW_ALL,
				&issuer_certificates,
				&user_certificates
			)
		)) != GPG_ERR_NO_ERROR ||
		(error = common_map_assuan_error (
			assuan_write_status (
				ctx,
				"APPTYPE",
				"PKCS11"
			)
		)) != GPG_ERR_NO_ERROR ||
		(error = common_map_assuan_error (
			send_certificate_list (
				ctx,
				user_certificates,
				0
			)
		)) != GPG_ERR_NO_ERROR ||
		(error = common_map_assuan_error (
			send_certificate_list (
				ctx,
				issuer_certificates,
				1
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (issuer_certificates != NULL) {
		pkcs11h_certificate_freeCertificateIdList (issuer_certificates);
		issuer_certificates = NULL;
	}

	if (user_certificates != NULL) {
		pkcs11h_certificate_freeCertificateIdList (user_certificates);
		user_certificates = NULL;
	}

	return gpg_error (error);
}

/**
   Return certificate contents. Line contains the percent-plus escaped
   certificate ID.
*/
int cmd_readcert (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_deserializeCertificateId (&cert_id, line)
		)) != GPG_ERR_NO_ERROR ||
		(error = get_cert_blob (ctx, cert_id, &blob, &blob_size)) != GPG_ERR_NO_ERROR ||
		(error = common_map_assuan_error (
			assuan_send_data (ctx, blob, blob_size)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (cert != NULL) {
		pkcs11h_certificate_freeCertificate (cert);
		cert = NULL;
	}

	if (cert_id != NULL) {
		pkcs11h_certificate_freeCertificateId (cert_id);
		cert_id = NULL;
	}

	if (blob != NULL) {
		free (blob);
		blob = NULL;
	}

	return gpg_error (error);
}

/** Read key given cert id in line. */
int cmd_readkey (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	gcry_sexp_t sexp = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_deserializeCertificateId (&cert_id, line)
		)) != GPG_ERR_NO_ERROR ||
		(error = get_cert_sexp (ctx, cert_id, &sexp)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((blob_size = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, NULL, 0)) == 0) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}

	if ((blob = (unsigned char *)malloc (blob_size)) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, blob, blob_size) == 0) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}

	if (
		(error = common_map_assuan_error (
			assuan_send_data(
				ctx,
				blob,
				gcry_sexp_canon_len (blob, 0, NULL, NULL)
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}
	
	error = GPG_ERR_NO_ERROR;

cleanup:

	if (sexp != NULL) {
		gcry_sexp_release(sexp);
		sexp = NULL;
	}

	if (cert_id != NULL) {
		pkcs11h_certificate_freeCertificateId (cert_id);
		cert_id = NULL;
	}

	if (blob != NULL) {
		free (blob);
		blob = NULL;
	}

	return gpg_error (error);
}

/** Store hex-encoded data from line to be signed/decrypted. */
int cmd_setdata (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	cmd_data_t *data = NULL;

	cmd_free_data (ctx);

	if ((strlen (line) % 2) != 0) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	if ((data = (cmd_data_t *)malloc (sizeof (cmd_data_t))) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	data->data = NULL;
	data->size = 0;

	if (!encoding_hex2bin (line, &data->data, &data->size)) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	assuan_set_pointer (ctx, data);
	data = NULL;

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (data != NULL) {
		_cmd_free_data (data);
		data = NULL;
	}

	return gpg_error (error);
}

/** Sign data (set by SETDATA) with certificate id in line. */
int cmd_pksign (assuan_context_t ctx, char *line)
{
	static unsigned const char sha1_oid[] = { /* 1.3.14.3.2.26 */
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
		0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
	};
	static unsigned const char rmd160_oid[] = { /* is 1.3.36.3.2.1 */
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
		0x02, 0x01, 0x05, 0x00, 0x04, 0x14
	};

	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	cmd_data_t *_data = data;
	int need_free__data = 0;
	int session_locked = 0;
	unsigned char *sig = NULL;
	size_t sig_len;

	if (
		data == NULL ||
		data->data == NULL
	) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	/*
	 * sender prefixed data with algorithm OID
	 */
	if (
		data->size == 20 + sizeof (sha1_oid) ||
		data->size == 20 + sizeof (rmd160_oid)
	) {
		if (
			memcmp (data->data, sha1_oid, sizeof (sha1_oid)) &&
			memcmp (data->data, rmd160_oid, sizeof (rmd160_oid))
		) {
			error = GPG_ERR_UNSUPPORTED_ALGORITHM;
			goto cleanup;
		}
	}
	else {
		/*
		 * unknown hash algorithm;
		 * gnupg's scdaemon forces to SHA1
		 */

		need_free__data = 1;

		if ((_data = (cmd_data_t *)malloc (sizeof (cmd_data_t))) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		if ((_data->data = (unsigned char *)malloc (data->size + sizeof (sha1_oid))) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		_data->size = 0;
		memmove (_data->data+_data->size, sha1_oid, sizeof (sha1_oid));
		_data->size += sizeof (sha1_oid);
		memmove (_data->data+_data->size, data->data, data->size);
		_data->size += data->size;
	}

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_deserializeCertificateId (&cert_id, line)
		)) != GPG_ERR_NO_ERROR ||
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_create (
				cert_id,
				ctx,
				PKCS11H_PROMPT_MASK_ALLOW_ALL,
				PKCS11H_PIN_CACHE_INFINITE,
				&cert
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_lockSession (cert)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}
	session_locked = 1;

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_signAny (
				cert,
				CKM_RSA_PKCS,
				_data->data,
				_data->size,
				NULL,
				&sig_len
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((sig = (unsigned char *)malloc (sig_len)) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_signAny (
				cert,
				CKM_RSA_PKCS,
				_data->data,
				_data->size,
				sig,
				&sig_len
			)
		)) != GPG_ERR_NO_ERROR ||
		(error = common_map_assuan_error (assuan_send_data(ctx, sig, sig_len))) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (session_locked) {
		pkcs11h_certificate_releaseSession (cert);
		session_locked = 0;
	}

	if (cert != NULL) {
		pkcs11h_certificate_freeCertificate (cert);
		cert = NULL;
	}

	if (cert_id != NULL) {
		pkcs11h_certificate_freeCertificateId (cert_id);
		cert_id = NULL;
	}

	if (sig != NULL) {
		free (sig);
		sig = NULL;
	}

	if (need_free__data) {
		_cmd_free_data (_data);
		_data = NULL;
	}

	return gpg_error (error);
}

/** Decrypt data (set by SETDATA) with certificate id in line. */
int cmd_pkdecrypt (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	unsigned char *ptext = NULL;
	size_t ptext_len;
	int session_locked = 0;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	
	if (
		data == NULL ||
		data->data == NULL
	) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_deserializeCertificateId (&cert_id, line)
		)) != GPG_ERR_NO_ERROR ||
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_create (
				cert_id,
				ctx,
				PKCS11H_PROMPT_MASK_ALLOW_ALL,
				PKCS11H_PIN_CACHE_INFINITE,
				&cert
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_lockSession (cert)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}
	session_locked = 1;

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_decryptAny (
				cert,
				CKM_RSA_PKCS, 
				data->data,
				data->size,
				NULL,
				&ptext_len
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((ptext = (unsigned char *)malloc (ptext_len)) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_decryptAny (
				cert,
				CKM_RSA_PKCS, 
				data->data,
				data->size,
				ptext,
				&ptext_len
			)
		)) != GPG_ERR_NO_ERROR ||
		(error = common_map_assuan_error (
			assuan_send_data(ctx, ptext, ptext_len))
		) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (session_locked) {
		pkcs11h_certificate_releaseSession (cert);
		session_locked = 0;
	}

	if (cert != NULL) {
		pkcs11h_certificate_freeCertificate (cert);
		cert = NULL;
	}

	if (cert_id != NULL) {
		pkcs11h_certificate_freeCertificateId (cert_id);
		cert_id = NULL;
	}

	if (ptext != NULL) {
		free (ptext);
		ptext = NULL;
	}

	return gpg_error (error);
}

/**
   pkcs11-helper neither supports getting random data, nor exports sufficient
   data to use raw PKCS#11.
*/
int cmd_random (assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;

	return gpg_error (GPG_ERR_INV_OP);
}

/** Not implemented. */
int cmd_checkpin (assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;

	return gpg_error (GPG_ERR_INV_OP);
}

int cmd_getinfo (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;

	if (!strcmp (line, "socket_name")) {
		const char *s = scdaemon_get_socket_name ();

		if (s == NULL) {
			error = GPG_ERR_INV_DATA;
		}
		else {
			error = common_map_assuan_error (assuan_send_data(ctx, s, strlen (s)));
		}
	}
	else {
		error = GPG_ERR_INV_DATA;
	}

	return gpg_error (error);
}

int cmd_restart (assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;

	return gpg_error (GPG_ERR_NO_ERROR);
}

