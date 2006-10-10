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

#include "common.h"
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
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	pkcs11h_certificate_t cert = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;
	CK_RV rv;

	*p_blob = NULL;
	*p_blob_size = 0;

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_create (
			cert_id,
			ctx,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&cert
		)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_getCertificateBlob (cert, NULL, &blob_size)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(blob = (unsigned char *)malloc (blob_size)) == NULL
	) {
		error = GPG_ERR_ENOMEM;
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_getCertificateBlob (cert, blob, &blob_size)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (error == GPG_ERR_NO_ERROR) {
		*p_blob = blob;
		*p_blob_size = blob_size;
		blob = NULL;
	}

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
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	gcry_sexp_t sexp = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;

	*p_sexp = NULL;

	if (error == GPG_ERR_NO_ERROR) {
		error = get_cert_blob (ctx, cert_id, &blob, &blob_size);
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = keyutil_get_cert_sexp (blob, blob_size, &sexp);
	}

	if (error == GPG_ERR_NO_ERROR) {
		*p_sexp = sexp;
		sexp = NULL;
	}

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
static int send_certificate_list (
	assuan_context_t ctx,
	pkcs11h_certificate_id_list_t head,	/* list head */
	int is_issuer				/* true if issuer certificate */
) {
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	pkcs11h_certificate_id_list_t curr_cert;
	CK_RV rv;
	
	for (
		curr_cert = head;
		error == GPG_ERR_NO_ERROR && curr_cert != NULL;
		curr_cert = curr_cert->next
	) {
		char *certid = NULL;
		char *key_hexgrip = NULL;
		char *info_cert = NULL;
		gcry_sexp_t sexp = NULL;
		size_t ser_len;

		if (error == GPG_ERR_NO_ERROR) {
			error = get_cert_sexp (ctx, curr_cert->certificate_id, &sexp);
		}

		if (
			error == GPG_ERR_NO_ERROR &&
			(key_hexgrip = keyutil_get_cert_hexgrip (sexp)) == NULL
		) {
			error = GPG_ERR_ENOMEM;
		}

		if (
			error == GPG_ERR_NO_ERROR &&
			(rv = pkcs11h_certificate_serializeCertificateId (
				NULL,
				&ser_len,
				curr_cert->certificate_id
			)) != CKR_OK
		) {
			rv = common_map_pkcs11_error (rv);
		}

		if (
			error == GPG_ERR_NO_ERROR &&
			(certid = (char *)malloc (ser_len)) == NULL
		) {
			error = GPG_ERR_ENOMEM;
		}

		if (
			error == GPG_ERR_NO_ERROR &&
			(rv = pkcs11h_certificate_serializeCertificateId (
				certid,
				&ser_len,
				curr_cert->certificate_id
			)) != CKR_OK
		) {
			error = common_map_pkcs11_error (rv);
		}

		if (
			error == GPG_ERR_NO_ERROR &&
			(info_cert = strdup (is_issuer ? "102 " : "101 ")) == NULL
		) {
			error = GPG_ERR_ENOMEM;
		}

		if (error == GPG_ERR_NO_ERROR) {
			encoding_strappend (&info_cert, certid);
		}

		if (error == GPG_ERR_NO_ERROR) {
			error = common_map_assuan_error (assuan_write_status(ctx, "CERTINFO", info_cert));
		}

		/* send keypairinfo if not issuer certificate */
		if(error == GPG_ERR_NO_ERROR && !is_issuer) {
			encoding_strappend (&key_hexgrip, " ");
			encoding_strappend (&key_hexgrip, certid);
			error = common_map_assuan_error (assuan_write_status (ctx, "KEYPAIRINFO", key_hexgrip));
		}
		
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
	}

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
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
#if defined(COMMENT)
	CK_RV rv;
	pkcs11h_token_id_list_t list = NULL;
	pkcs11h_token_id_list_t i;
#endif

	(void)line;

	/*
	 * @ALON
	 * I am amazied!!!!
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
			error == GPG_ERR_NO_ERROR &&
			(serial_and_stamp = encoding_bin2hex (
				(unsigned char *)ser_token,
				strlen (ser_token)
			)) == NULL
		) {
			error = GPG_ERR_GENERAL;
		}

		if (error == GPG_ERR_NO_ERROR) {
			encoding_strappend (&serial_and_stamp, " 0");
		}

		if (error == GPG_ERR_NO_ERROR) {
			error = common_map_assuan_error (
				assuan_write_status(
					ctx,
					"SERIALNO",
					serial_and_stamp
				)
			);
		}

		if (serial_and_stamp != NULL) {
			free (serial_and_stamp);
			serial_and_stamp = NULL;
		}
	}

#if defined(COMMENT)
	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_token_enumTokenIds (PKCS11H_ENUM_METHOD_RELOAD, &list)) != CKR_OK
	) {
		common_log (LOG_WARNING, "enumeration of tokens failed: %lx", rv);
		error = common_map_pkcs11_error (rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		list == NULL
	) {
		error = GPG_ERR_CARD_NOT_PRESENT;
	}

	for (i=list;error == GPG_ERR_NO_ERROR && i!=NULL;i=i->next) {
		char *serial_and_stamp = NULL;
		char *ser_token = NULL;
		size_t ser_len;

		if (
			error == GPG_ERR_NO_ERROR &&
			(rv = pkcs11h_token_serializeTokenId (NULL, &ser_len, i->token_id)) != CKR_OK
		) {
			error = common_map_pkcs11_error (rv);
		}

		if (
			error == GPG_ERR_NO_ERROR &&
			(ser_token = (char *)malloc (ser_len)) == NULL
		) {
			error = GPG_ERR_ENOMEM;
		}

		if (
			error == GPG_ERR_NO_ERROR &&
			(rv = pkcs11h_token_serializeTokenId (ser_token, &ser_len, i->token_id)) != CKR_OK
		) {
			error = common_map_pkcs11_error (rv);
		}

		/*
		 * serial number has to be hex-encoded data,
		 * followed by " 0"
		 */
		if (
			error == GPG_ERR_NO_ERROR &&
			(serial_and_stamp = encoding_bin2hex (
				(unsigned char *)ser_token,
				strlen (ser_token)
			)) == NULL
		) {
			error = GPG_ERR_GENERAL;
		}

		if (error == GPG_ERR_NO_ERROR) {
			encoding_strappend (&serial_and_stamp, " 0");
		}

		if (error == GPG_ERR_NO_ERROR) {
			error = common_map_assuan_error (
				assuan_write_status(
					ctx,
					"SERIALNO",
					serial_and_stamp
				)
			);
		}

		if (serial_and_stamp != NULL) {
			free (serial_and_stamp);
			serial_and_stamp = NULL;
		}

		if (ser_token != NULL) {
			free (ser_token);
			ser_token = NULL;
		}
	}

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
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	pkcs11h_certificate_id_list_t issuer_certificates = NULL;
	CK_RV rv;

	(void)line;

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_enumCertificateIds (
			PKCS11H_ENUM_METHOD_CACHE_EXIST,
			ctx,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			&issuer_certificates,
			&user_certificates
		)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = common_map_assuan_error (assuan_write_status(ctx, "APPTYPE", "PKCS11"));
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = send_certificate_list(ctx, user_certificates, 0);
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = send_certificate_list(ctx, issuer_certificates, 1);
	}

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
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;
	CK_RV rv;

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_deserializeCertificateId (&cert_id, line)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = get_cert_blob (ctx, cert_id, &blob, &blob_size);
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = common_map_assuan_error (assuan_send_data(ctx, blob, blob_size));
	}

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
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	pkcs11h_certificate_id_t cert_id = NULL;
	gcry_sexp_t sexp = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;
	CK_RV rv;

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_deserializeCertificateId (&cert_id, line)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = get_cert_sexp (ctx, cert_id, &sexp);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(blob_size = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, NULL, 0)) == 0
	) {
		error = GPG_ERR_BAD_KEY;
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(blob = (unsigned char *)malloc (blob_size)) == NULL
	) {
		error = GPG_ERR_ENOMEM;
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, blob, blob_size) == 0
	) {
		error = GPG_ERR_BAD_KEY;
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = common_map_assuan_error (
			assuan_send_data(
				ctx,
				blob,
				gcry_sexp_canon_len (blob, 0, NULL, NULL)
			)
		);
	}

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
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	cmd_data_t *data = NULL;

	cmd_free_data (ctx);

	if (
		error == GPG_ERR_NO_ERROR &&
		(strlen (line) % 2) != 0
	) {
		error = GPG_ERR_INV_DATA;
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(data = (cmd_data_t *)malloc (sizeof (cmd_data_t))) == NULL
	) {
		error = GPG_ERR_ENOMEM;
	}

	if (error == GPG_ERR_NO_ERROR) {
		data->data = NULL;
		data->size = 0;
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		!encoding_hex2bin (line, &data->data, &data->size)
	) {
		error = GPG_ERR_INV_DATA;
	}

	if (error == GPG_ERR_NO_ERROR) {
		assuan_set_pointer (ctx, data);
		data = NULL;
	}

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

	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	cmd_data_t *_data = data;
	int need_free__data = 0;
	unsigned char *sig = NULL;
	size_t sig_len;
	CK_RV rv;

	if (
		data == NULL ||
		data->data == NULL
	) {
		error = GPG_ERR_INV_DATA;
	}

	/*
	 * sender prefixed data with algorithm OID
	 */
	if (error == GPG_ERR_NO_ERROR) {
		if (
			data->size == 20 + sizeof (sha1_oid) ||
			data->size == 20 + sizeof (rmd160_oid)
		) {
			if (
				memcmp (data->data, sha1_oid, sizeof (sha1_oid)) &&
				memcmp (data->data, rmd160_oid, sizeof (rmd160_oid))
			) {
				error = GPG_ERR_UNSUPPORTED_ALGORITHM;
			}
		}
		else {
			/*
			 * unknown hash algorithm;
			 * gnupg's scdaemon forces to SHA1
			 */

			need_free__data = 1;

			if (
				error == GPG_ERR_NO_ERROR &&
				(_data = (cmd_data_t *)malloc (sizeof (cmd_data_t))) == NULL
			) {
				error = GPG_ERR_ENOMEM;
			}

			if (
				error == GPG_ERR_NO_ERROR &&
				(_data->data = (unsigned char *)malloc (data->size + sizeof (sha1_oid))) == NULL
			) {
				error = GPG_ERR_ENOMEM;
			}

			if (error == GPG_ERR_NO_ERROR) {
				_data->size = 0;
				memmove (_data->data+_data->size, sha1_oid, sizeof (sha1_oid));
				_data->size += sizeof (sha1_oid);
				memmove (_data->data+_data->size, data->data, data->size);
				_data->size += data->size;
			}
		}
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_deserializeCertificateId (&cert_id, line)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_create (
			cert_id,
			ctx,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&cert
		)) != CKR_OK
	) {
		error = common_map_pkcs11_error(rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_sign (
			cert,
			CKM_RSA_PKCS,
			_data->data,
			_data->size,
			NULL,
			&sig_len
		)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(sig = (unsigned char *)malloc (sig_len)) == NULL
	) {
		error = GPG_ERR_ENOMEM;
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_sign (
			cert,
			CKM_RSA_PKCS,
			_data->data,
			_data->size,
			sig,
			&sig_len
		)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = common_map_assuan_error (assuan_send_data(ctx, sig, sig_len));
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
	gpg_err_code_t error = GPG_ERR_NO_ERROR;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	unsigned char *ptext = NULL;
	size_t ptext_len;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	CK_RV rv;
	
	if (
		data == NULL ||
		data->data == NULL
	) {
		error = GPG_ERR_INV_DATA;
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_deserializeCertificateId (&cert_id, line)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_create (
			cert_id,
			ctx,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&cert
		)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_decrypt (
			cert,
			CKM_RSA_PKCS, 
			data->data,
			data->size,
			NULL,
			&ptext_len
		)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(ptext = (unsigned char *)malloc (ptext_len)) == NULL
	) {
		error = GPG_ERR_ENOMEM;
	}

	if (
		error == GPG_ERR_NO_ERROR &&
		(rv = pkcs11h_certificate_decrypt (
			cert,
			CKM_RSA_PKCS, 
			data->data,
			data->size,
			ptext,
			&ptext_len
		)) != CKR_OK
	) {
		error = common_map_pkcs11_error (rv);
	}

	if (error == GPG_ERR_NO_ERROR) {
		error = common_map_assuan_error (assuan_send_data(ctx, ptext, ptext_len));
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

/** Not yet implemented. */
int cmd_checkpin (assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;

	return gpg_error (GPG_ERR_INV_OP);
}

/** The multi-server mode is currently not supported. */
int cmd_getinfo (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_NO_ERROR;

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

