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

#include "common.h"
#include "strgetopt.h"
#include <pkcs11-helper-1.0/pkcs11.h>
#include <pkcs11-helper-1.0/pkcs11h-token.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include "command.h"
#include "encoding.h"
#include "keyutil.h"

#define _M2S(x) #x
#define M2S(x) _M2S(x)

/*
 * OpenPGP prefix
 * 11
 * P11
 * xxxxxxxx - sha1(token_id)
 * 1s
 */
#define OPENPGP_PKCS11_SERIAL "D27600012401" "11" "503131%8s" "1111"
#define OPENPGP_PKCS11_SERIAL_BYTES 4
#define OPENPGP_KEY_NAME_PREFIX "OPENPGP."
#define OPENPGP_SIGN 1
#define OPENPGP_ENCR 2
#define OPENPGP_AUTH 3

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
get_cert_keyinfo (
	assuan_context_t ctx,
	pkcs11h_certificate_id_t cert_id,
	keyinfo *p_keyinfo
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	keyinfo keyinfo;
	unsigned char *blob = NULL;
	size_t blob_size;

	*p_keyinfo = NULL;
	keyinfo = keyinfo_new();

	if (
		(error = get_cert_blob (ctx, cert_id, &blob, &blob_size)) != GPG_ERR_NO_ERROR ||
		(error = keyinfo_from_der (keyinfo, blob, blob_size)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	*p_keyinfo = keyinfo;
	keyinfo = NULL;

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (keyinfo != NULL) {
		keyinfo_free(keyinfo);
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
	keyinfo keyinfo = NULL;
	gcry_sexp_t sexp;

	error = get_cert_keyinfo(ctx, cert_id, &keyinfo);
	if (error != GPG_ERR_NO_ERROR) {
		goto cleanup;
	}

	sexp = keyinfo_to_sexp(keyinfo);
	if (sexp == NULL) {
		error = GPG_ERR_GENERAL;
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

	if (keyinfo != NULL) {
		keyinfo_free(keyinfo);
	}

	return error;
}

static
gpg_err_code_t
get_serial_of_tokenid(
	pkcs11h_token_id_t tokenid,
	char **serial
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	char *serialized = NULL;
	char *serialpart = NULL;
	unsigned char *digest = NULL;
	size_t n;

	*serial = NULL;

	if (
		(error = common_map_pkcs11_error(
			pkcs11h_token_serializeTokenId(
				NULL,
				&n,
				tokenid
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((serialized = (char *)malloc(n)) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (
		(error = common_map_pkcs11_error(
			pkcs11h_token_serializeTokenId(
				serialized,
				&n,
				tokenid
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((digest = (unsigned char *)malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA1))) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	gcry_md_hash_buffer(GCRY_MD_SHA1, digest, serialized, strlen(serialized));

	/*
	 * Take the first N bytes.
	 */
	if ((serialpart = encoding_bin2hex(digest, OPENPGP_PKCS11_SERIAL_BYTES)) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if ((*serial = malloc(strlen(OPENPGP_PKCS11_SERIAL) + OPENPGP_PKCS11_SERIAL_BYTES * 2 + 1)) == NULL) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	sprintf(*serial, OPENPGP_PKCS11_SERIAL, serialpart);

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (serialized != NULL) {
		free(serialized);
		serialized = NULL;
	}

	if (serialpart != NULL) {
		free(serialpart);
		serialpart = NULL;
	}

	if (digest != NULL) {
		free(digest);
		digest = NULL;
	}

	return error;
}
static
gpg_err_code_t
get_serial(
	assuan_context_t ctx,
	char **serial
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_token_id_list_t tokens = NULL;

	*serial = NULL;

	if (
		(error = common_map_pkcs11_error(
			pkcs11h_token_enumTokenIds(
				PKCS11H_ENUM_METHOD_CACHE_EXIST,
				&tokens
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	/*
	 * gpg supports only single card, let's take the first.
	 */
	if (tokens != NULL) {
		if ((error = get_serial_of_tokenid(tokens->token_id, serial)) != GPG_ERR_NO_ERROR) {
			goto cleanup;
		}
	}

	error = GPG_ERR_NO_ERROR;

cleanup:
	if (tokens != NULL) {
		pkcs11h_token_freeTokenIdList(tokens);
		tokens = NULL;
	}

	return error;
}

/**
   Send status lines in the format

   S KEYPAIRINFO <hexstring_with_keygrip> <hexstring_with_id>
   S CERTINFO <certtype> <hexstring_with_id>

   If certificate is issuer, we set type to 102 (useful); otherwise it is
   assumed that we're in possession of private key, so the type is set to 101
   (trusted).  The certificate ID is percent-plus escaped displayName.
*/
static
int
send_certificate_list (
	assuan_context_t ctx,
	pkcs11h_certificate_id_list_t head,	/* list head */
	int is_issuer				/* true if issuer certificate */
) {
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_list_t curr_cert;

	for (
		curr_cert = head;
		curr_cert != NULL;
		curr_cert = curr_cert->next
	) {
		char *certid = NULL;
		char *key_hexgrip = NULL;
		char *keypairinfo = NULL;
		char *gpginfo = NULL;
		char *info_cert = NULL;
		gcry_sexp_t sexp = NULL;
		size_t ser_len;
		char *key_prefix = NULL;
		char *nameinfo = NULL;

		if ((error = get_cert_sexp (ctx, curr_cert->certificate_id, &sexp)) != GPG_ERR_NO_ERROR) {
			goto retry;
		}

		if ((key_hexgrip = keyinfo_get_hexgrip (sexp)) == NULL) {
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
			data->config->openpgp_sign != NULL &&
			!strcmp (data->config->openpgp_sign, key_hexgrip)
		) {
			key_prefix = M2S(OPENPGP_SIGN) " ";
		}
		else if (
			data->config->openpgp_encr != NULL &&
			!strcmp (data->config->openpgp_encr, key_hexgrip)
		) {
			key_prefix = M2S(OPENPGP_ENCR) " ";
		}
		else if (
			data->config->openpgp_auth != NULL &&
			!strcmp (data->config->openpgp_auth, key_hexgrip)
		) {
			key_prefix = M2S(OPENPGP_AUTH) " ";
		}

		if (
			(nameinfo = strdup (key_hexgrip)) == NULL ||
			!encoding_strappend (&nameinfo, " ") ||
			!encoding_strappend (&nameinfo, curr_cert->certificate_id->displayName)
		) {
			error = GPG_ERR_ENOMEM;
			goto retry;
		}

		if (
			(error = assuan_write_status (
				ctx,
				"KEY-FRIEDNLY",
				nameinfo
			)) != GPG_ERR_NO_ERROR
		) {
			goto retry;
		}

		if (key_prefix != NULL) {
			if (
				(gpginfo = strdup (key_prefix)) == NULL ||
				!encoding_strappend (&gpginfo, key_hexgrip)
			) {
				error = GPG_ERR_ENOMEM;
				goto retry;
			}


			if (
				(error = assuan_write_status (
					ctx,
					"KEY-FPR",
					gpginfo
				)) != GPG_ERR_NO_ERROR
			) {
				goto retry;
			}

		}
		if (
			(error = assuan_write_status (
				ctx,
				"CERTINFO",
				info_cert
			)) != GPG_ERR_NO_ERROR
		) {
			goto retry;
		}

		/* send keypairinfo if not issuer certificate */
		if(!is_issuer) {
			if (
				(keypairinfo = strdup (key_hexgrip)) == NULL ||
				!encoding_strappend (&keypairinfo, " ") ||
				!encoding_strappend (&keypairinfo, certid)
			) {
				error = GPG_ERR_ENOMEM;
				goto retry;
			}

			if (
				(error = assuan_write_status (
					ctx,
					"KEYPAIRINFO",
					keypairinfo
				)) != GPG_ERR_NO_ERROR
			) {
				goto retry;
			}
		}

		error = GPG_ERR_NO_ERROR;

	retry:

		if (sexp != NULL) {
			gcry_sexp_release (sexp);
			sexp = NULL;
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

		if (keypairinfo != NULL) {
			free (keypairinfo);
			keypairinfo = NULL;
		}

		if (gpginfo != NULL) {
			free (gpginfo);
			gpginfo = NULL;
		}

		if (nameinfo != NULL) {
			free (nameinfo);
			nameinfo = NULL;
		}

		if (error == GPG_ERR_WRONG_PUBKEY_ALGO) {
			error = GPG_ERR_NO_ERROR;
		}

		if (error != GPG_ERR_NO_ERROR) {
			goto cleanup;
		}
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	return error;
}

int _get_certificate_by_name (assuan_context_t ctx, const char *name, int typehint, pkcs11h_certificate_id_t *p_cert_id, const char **p_key) {
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	gpg_err_code_t error = GPG_ERR_BAD_KEY;
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	pkcs11h_certificate_id_list_t curr_cert;
	pkcs11h_certificate_id_t cert_id = NULL;
	char *key_hexgrip = NULL;
	gcry_sexp_t sexp = NULL;
	const char *key = NULL;
	int type;

	*p_cert_id = NULL;
	if (p_key != NULL) {
		*p_key = NULL;
	}

	if (name == NULL) {
		type = typehint;
	}
	else if (	/* gnupg-2.0 mode */
		data->config->openpgp_sign != NULL ||
		data->config->openpgp_encr != NULL ||
		data->config->openpgp_auth != NULL
	) {
		type = typehint;
	}
	else if (strncmp (name, OPENPGP_KEY_NAME_PREFIX, strlen (OPENPGP_KEY_NAME_PREFIX))) {
		if ((error = common_map_pkcs11_error (
			pkcs11h_certificate_deserializeCertificateId (p_cert_id, name)
		)) == GPG_ERR_NO_ERROR) {
			goto cleanup;
		}
		key = name;
	}
	else {
		type = atoi(name + strlen (OPENPGP_KEY_NAME_PREFIX));
	}

	if (key == NULL) {
		switch (type) {
			case OPENPGP_SIGN:
				key = data->config->openpgp_sign;
			break;
			case OPENPGP_ENCR:
				key = data->config->openpgp_encr;
			break;
			case OPENPGP_AUTH:
				key = data->config->openpgp_auth;
			break;
			default:
				error = GPG_ERR_BAD_KEY;
				goto cleanup;
		}
	}

	if (key == NULL) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_enumCertificateIds (
				PKCS11H_ENUM_METHOD_CACHE_EXIST,
				ctx,
				PKCS11H_PROMPT_MASK_ALLOW_ALL,
				NULL,
				&user_certificates
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	for (
		curr_cert = user_certificates;
		curr_cert != NULL && cert_id == NULL;
		curr_cert = curr_cert->next
	) {

		if ((error = get_cert_sexp (ctx, curr_cert->certificate_id, &sexp)) != GPG_ERR_NO_ERROR) {
			goto cleanup;
		}

		if ((key_hexgrip = keyinfo_get_hexgrip (sexp)) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		if (!strcmp (key_hexgrip, key)) {
			if (
				(error = common_map_pkcs11_error (
					pkcs11h_certificate_duplicateCertificateId (
						&cert_id,
						curr_cert->certificate_id
					)
				)) != GPG_ERR_NO_ERROR
			) {
				goto cleanup;
			}
		}
	}

	if (cert_id == NULL) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}

	*p_cert_id = cert_id;
	cert_id = NULL;
	if (p_key != NULL) {
		*p_key = key;
	}
	error = GPG_ERR_NO_ERROR;

cleanup:

	if (sexp != NULL) {
		gcry_sexp_release(sexp);
		sexp = NULL;
	}

	if (key_hexgrip != NULL) {
		free (key_hexgrip);
		key_hexgrip = NULL;
	}

	if (user_certificates != NULL) {
		pkcs11h_certificate_freeCertificateIdList (user_certificates);
		user_certificates = NULL;
	}

	if (cert_id != NULL) {
		pkcs11h_certificate_freeCertificateId (cert_id);
		cert_id = NULL;
	}

	return error;
}

void cmd_free_data (assuan_context_t ctx) {
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	if (data->data != NULL) {
		free (data->data);
		data->data = NULL;
		data->size = 0;
	}
}

gpg_error_t cmd_null (assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;

	return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_serialno (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	char *serial = NULL;

	(void)line;

	if (
		(error = get_serial(ctx, &serial)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (serial != NULL) {
		char buffer[1024];

		sprintf(buffer, "%s 0", serial);

		if (
			(error = assuan_write_status (
				ctx,
				"SERIALNO",
				buffer
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (serial != NULL) {
		free(serial);
		serial = NULL;
	}

	return gpg_error (error);
}

/** TODO: handle --force option! */
gpg_error_t cmd_learn (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	pkcs11h_certificate_id_list_t issuer_certificates = NULL;
	char *serial = NULL;

	(void)line;

	if (
		(error = get_serial(ctx, &serial)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (
		(error = assuan_write_status (
			ctx,
			"SERIALNO",
			serial
		)) != GPG_ERR_NO_ERROR ||
		(error = assuan_write_status (
			ctx,
			"APPTYPE",
			"PKCS11"
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

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
		(error = send_certificate_list (
			ctx,
			user_certificates,
			0
		)) != GPG_ERR_NO_ERROR ||
		(error = send_certificate_list (
			ctx,
			issuer_certificates,
			1
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

	if (serial != NULL) {
		free(serial);
		serial = NULL;
	}

	return gpg_error (error);
}

/**
   Return certificate contents. Line contains the percent-plus escaped
   certificate ID.
*/
gpg_error_t cmd_readcert (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;
	const char *l;

	l = strgetopt_getopt(line, NULL);

	if (
		(error = _get_certificate_by_name (
			ctx,
			l,
			0,
			&cert_id,
			NULL
		)) != GPG_ERR_NO_ERROR ||
		(error = get_cert_blob (ctx, cert_id, &blob, &blob_size)) != GPG_ERR_NO_ERROR ||
		(error = assuan_send_data (ctx, blob, blob_size)) != GPG_ERR_NO_ERROR
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
gpg_error_t cmd_readkey (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	gcry_sexp_t sexp = NULL;
	unsigned char *blob = NULL;
	size_t blob_size;
	char *key_hexgrip = NULL;
	char *keypairinfo = NULL;
	const char *l;
	int info = 0;
	int info_only = 0;
	char *ser = NULL;
	size_t ser_len;
	const struct strgetopt_option options[] = {
		{"info", strgtopt_no_argument, NULL, &info},
		{"info-only", strgtopt_no_argument, NULL, &info_only},
		{NULL, 0, NULL, NULL}
	};

	l = strgetopt_getopt(line, options);

	if (
		(error = _get_certificate_by_name (
			ctx,
			l,
			0,
			&cert_id,
			NULL
		)) != GPG_ERR_NO_ERROR ||
		(error = get_cert_sexp (ctx, cert_id, &sexp)) != GPG_ERR_NO_ERROR
	) {
		error = GPG_ERR_NOT_FOUND;
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

	if (info || info_only) {
		if (
			(error = common_map_pkcs11_error (
				pkcs11h_certificate_serializeCertificateId (
					NULL,
					&ser_len,
					cert_id
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}

		if ((ser = (char *)malloc (ser_len)) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		if (
			(error = common_map_pkcs11_error (
				pkcs11h_certificate_serializeCertificateId (
					ser,
					&ser_len,
					cert_id
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
		if (
			(key_hexgrip = keyinfo_get_hexgrip (sexp)) == NULL ||
			(keypairinfo = strdup (key_hexgrip)) == NULL ||
			!encoding_strappend (&keypairinfo, " ") ||
			!encoding_strappend (&keypairinfo, ser)
		) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		if (
			(error = assuan_write_status (
				ctx,
				"KEYPAIRINFO",
				keypairinfo
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
	}

	if (!info_only) {
		if (
			(error = assuan_send_data(
				ctx,
				blob,
				gcry_sexp_canon_len (blob, 0, NULL, NULL)
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	strgetopt_free(options);

	if (sexp != NULL) {
		gcry_sexp_release(sexp);
		sexp = NULL;
	}

	if (key_hexgrip == NULL) {
		free(key_hexgrip);
		key_hexgrip = NULL;
	}

	if (keypairinfo == NULL) {
		free(keypairinfo);
		keypairinfo = NULL;
	}

	if (ser != NULL) {
		free(ser);
		ser = NULL;
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
gpg_error_t cmd_setdata (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	int append = 0;
	int index;
	size_t len;
	const char *l;

	const struct strgetopt_option options[] = {
		{"append", strgtopt_no_argument, NULL, &append},
		{NULL, 0, NULL, NULL}
	};

	l = strgetopt_getopt(line, options);

	if (!append) {
		cmd_free_data (ctx);
	}

	if (!encoding_hex2bin(l, NULL, &len)) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	if (!append) {
		index = 0;
		data->size = len;
		data->data = (unsigned char *)malloc(data->size);
	}
	else {
		index = data->size;
		data->size += len;
		data->data = (unsigned char *)realloc(data->data, data->size);
	}

	if (!encoding_hex2bin (l, data->data + index, NULL)) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	strgetopt_free(options);

	return gpg_error (error);
}

static CK_RV _pkcs11_keyinfo_mechanism(keyinfo keyinfo, CK_MECHANISM_TYPE_PTR pkcs11_mechanism) {
	if (keyinfo == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	switch (keyinfo_get_type(keyinfo)) {
		case KEYINFO_KEY_TYPE_RSA:
			*pkcs11_mechanism = CKM_RSA_PKCS;
			return CKR_OK;
		case KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE:
			*pkcs11_mechanism = CKM_ECDSA;
			return CKR_OK;
		case KEYINFO_KEY_TYPE_UNKNOWN:
			return CKR_GENERAL_ERROR;
		case KEYINFO_KEY_TYPE_INVALID:
			return CKR_GENERAL_ERROR;
	}

	return CKR_GENERAL_ERROR;
}

struct prefix_pkcs1 {
	const char *const name;
	const unsigned char der[32];
	const unsigned int der_size;
	const unsigned int hash_size;
};
static struct prefix_pkcs1 prefix_pkcs1_list[] = {
	{
		.name = "rmd160",
		.der = {
			/* (1.3.36.3.2.1) */
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
			0x02, 0x01, 0x05, 0x00, 0x04, 0x14
		},
		.der_size = 15,
		.hash_size = 20
	},
	{
		.name = "md5",
		.der = {
			/* (1.2.840.113549.2.5) */
			0x30, 0x2c, 0x30, 0x09, 0x06, 0x08, 0x2a, 0x86, 0x48,
			0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
		},
		.der_size = 18,
		.hash_size = 16
	},
	{
		.name = "sha1",
		.der = {
			/* (1.3.14.3.2.26) */
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
			0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
		},
		.der_size = 15,
		.hash_size = 20
	},
	{
		.name = "sha224",
		.der = {
			/* (2.16.840.1.101.3.4.2.4) */
			0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
			0x1C
		},
		.der_size = 19,
		.hash_size = 28
	},
	{
		.name = "sha256",
		.der = {
			/* (2.16.840.1.101.3.4.2.1) */
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
			0x20
		},
		.der_size = 19,
		.hash_size = 32
	},
	{
		.name = "sha384",
		.der = {
			/* (2.16.840.1.101.3.4.2.2) */
			0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
			0x30
		},
		.der_size = 19,
		.hash_size = 48
	},
	{
		.name = "sha512",
		.der = {
			/* (2.16.840.1.101.3.4.2.3) */
			0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
			0x40
		},
		.der_size = 19,
		.hash_size = 64
	},
	{
		.name = NULL,
		.der_size = 0,
		.hash_size = 0
	}
};

static
gpg_error_t _cmd_pksign_type (assuan_context_t ctx, char *line, int typehint)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	cmd_data_t *_data = data;
	int need_free__data = 0;
	int session_locked = 0;
	keyinfo keyinfo = NULL;
	unsigned char *sig = NULL;
	size_t sig_len;
	struct prefix_pkcs1 *inject = NULL;
	ssize_t data_effective_len, data_offset = 0;
	CK_MECHANISM_TYPE pkcs11_mechanism;
	int use_pkcs1;
	char *hash = NULL;
	int found_hash_algo = 0;
	const char *l;
	const struct strgetopt_option options[] = {
		{"hash", strgtopt_required_argument, &hash, NULL},
		{NULL, 0, NULL, NULL}
	};

	if (data->data == NULL) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	l = strgetopt_getopt(line, options);

	if (*l == '\x0') {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	if (
		(error = _get_certificate_by_name (
			ctx,
			l,
			typehint,
			&cert_id,
			NULL
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (
		(error = get_cert_keyinfo(ctx, cert_id, &keyinfo)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (_pkcs11_keyinfo_mechanism(keyinfo, &pkcs11_mechanism) != CKR_OK) {
		goto cleanup;
	}

	switch (pkcs11_mechanism) {
		case CKM_RSA_PKCS:
			use_pkcs1 = 1;
			break;
		case CKM_ECDSA:
			use_pkcs1 = 0;
			break;
		default:
			error = GPG_ERR_BAD_KEY;
			goto cleanup;
	}

	if (use_pkcs1) {
		/* Use PKCS1 framing if required by the mechanism */

		/*
		 * sender prefixed data with algorithm OID
		 */
		for (struct prefix_pkcs1 *prefix_pkcs1_check = prefix_pkcs1_list; prefix_pkcs1_check->name != NULL; prefix_pkcs1_check++) {
			if (hash != NULL) {
				if (strcmp(hash, prefix_pkcs1_check->name)) {
					continue;
				}

				if (data->size == prefix_pkcs1_check->hash_size) {
					inject = prefix_pkcs1_check;

					found_hash_algo = 1;

					break;
				}
			}

			if (data->size == (prefix_pkcs1_check->hash_size + prefix_pkcs1_check->der_size) &&
				!memcmp (data->data, prefix_pkcs1_check->der, prefix_pkcs1_check->der_size)) {

				inject = NULL;

				found_hash_algo = 1;

				break;
			}
		}

		if (!found_hash_algo) {
			/*
			 * If a hash algorithm was specified and it was not
			 * found, return in failure
			 */
			if (hash != NULL) {
				common_log (LOG_DEBUG, "unsupported hash algo (hash=%s,size=%d)", hash, data->size);
				error = GPG_ERR_UNSUPPORTED_ALGORITHM;
				goto cleanup;
			}

			/*
			 * unknown hash algorithm;
			 * gnupg's scdaemon forces to SHA1
			 */
			for (struct prefix_pkcs1 *prefix_pkcs1_check = prefix_pkcs1_list; prefix_pkcs1_check->name != NULL; prefix_pkcs1_check++) {
				if (!strcmp(prefix_pkcs1_check->name, "sha1")) {
					inject = prefix_pkcs1_check;

					break;
				}
			}

			/* When doing auth operation, hash algorithm prefix detection does not work
			 * but data always comes with algorithm appended, so do not append anything
			 * by default. */
			if (typehint == OPENPGP_AUTH) {
				inject = NULL;
			}
		}
	} else {
		/* Non-PKCS1 does not inject anything, but may need to remove wrapping */
		inject = NULL;

		/* Remove any existing PKCS1 prefix from to-be-signed data */
		for (struct prefix_pkcs1 *prefix_pkcs1_check = prefix_pkcs1_list; prefix_pkcs1_check->name != NULL; prefix_pkcs1_check++) {
			if (hash != NULL) {
				if (strcmp(hash, prefix_pkcs1_check->name)) {
					continue;
				}

				if (data->size == prefix_pkcs1_check->hash_size) {
					data_offset = 0;

					found_hash_algo = 1;

					break;
				}
			}

			if (data->size == (prefix_pkcs1_check->hash_size + prefix_pkcs1_check->der_size) &&
				!memcmp (data->data, prefix_pkcs1_check->der, prefix_pkcs1_check->der_size)) {

				data_offset = prefix_pkcs1_check->der_size;

				found_hash_algo = 1;

				break;
			}
		}

		if (!found_hash_algo) {
			common_log (LOG_DEBUG, "unsupported hash algo (hash=%s,size=%d)", hash, data->size);
			error = GPG_ERR_UNSUPPORTED_ALGORITHM;
			goto cleanup;
		}

		if (data_offset > 0) {
			if (data_offset > _data->size) {
				error = GPG_ERR_TRUNCATED;
				goto cleanup;
			}

			need_free__data = 1;

			if ((_data = (cmd_data_t *)malloc (sizeof (cmd_data_t))) == NULL) {
				error = GPG_ERR_ENOMEM;
				goto cleanup;
			}

			_data->size = data->size - data_offset;
			if ((_data->data = (unsigned char *)malloc (_data->size)) == NULL) {
				error = GPG_ERR_ENOMEM;
				goto cleanup;
			}

			memcpy(_data->data, data->data + data_offset, _data->size);
			data_offset = 0;
		}
	}

	if (inject != NULL) {
		const unsigned char *oid = inject->der;
		size_t oid_size = inject->der_size;

		need_free__data = 1;

		if ((_data = (cmd_data_t *)malloc (sizeof (cmd_data_t))) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		if ((_data->data = (unsigned char *)malloc (data->size + oid_size)) == NULL) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		_data->size = 0;
		memmove (_data->data+_data->size, oid, oid_size);
		_data->size += oid_size;
		memmove (_data->data+_data->size, data->data, data->size);
		_data->size += data->size;
	}

	if (
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

	data_effective_len = keyinfo_get_data_length(keyinfo, _data->size);
	if (data_effective_len < 0) {
		error = GPG_ERR_TRUNCATED;
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
				pkcs11_mechanism,
				_data->data,
				data_effective_len,
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
				pkcs11_mechanism,
				_data->data,
				data_effective_len,
				sig,
				&sig_len
			)
		)) != GPG_ERR_NO_ERROR ||
		(error = assuan_send_data(ctx, sig, sig_len)) != GPG_ERR_NO_ERROR
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

	if (keyinfo != NULL) {
		keyinfo_free(keyinfo);
		keyinfo = NULL;
	}

	if (sig != NULL) {
		free (sig);
		sig = NULL;
	}

	if (need_free__data) {
		if (_data != NULL) {
			free (_data->data);
			_data->data = NULL;
			free (_data);
			_data = NULL;
		}
	}

	strgetopt_free(options);

	return gpg_error (error);
}

/** Sign data (set by SETDATA) with certificate id in line. */
gpg_error_t cmd_pksign (assuan_context_t ctx, char *line)
{
	return _cmd_pksign_type(ctx, line, OPENPGP_SIGN);
}

/** Sign data (set by SETDATA) with certificate id in line. */
gpg_error_t cmd_pkauth (assuan_context_t ctx, char *line)
{
	return _cmd_pksign_type(ctx, line, OPENPGP_AUTH);
}

/** Decrypt data (set by SETDATA) with certificate id in line. */
gpg_error_t cmd_pkdecrypt (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	unsigned char *ptext = NULL;
	size_t ptext_len;
	int session_locked = 0;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	cmd_data_t _data;
	const char *l;

	l = strgetopt_getopt(line, NULL);

	if (
		data == NULL ||
		data->data == NULL
	) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	/*
	 * Guess.. taken from openpgp card implementation
	 * and java PKCS#11 provider.
	 */
	_data.data = data->data;
	_data.size = data->size;
	if (
		*_data.data == 0 && (
			_data.size == 129 ||
			_data.size == 193 ||
			_data.size == 257 ||
			_data.size == 385 ||
			_data.size == 513
		)
	) {
		_data.data++;
		_data.size--;
	}

	if (
		(error = _get_certificate_by_name (
			ctx,
			l,
			OPENPGP_ENCR,
			&cert_id,
			NULL
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (
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
				_data.data,
				_data.size,
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
				_data.data,
				_data.size,
				ptext,
				&ptext_len
			)
		)) != GPG_ERR_NO_ERROR ||
		(error = assuan_write_status(ctx, "PADDING", "0")) != GPG_ERR_NO_ERROR ||
		(error = assuan_send_data(ctx, ptext, ptext_len)) != GPG_ERR_NO_ERROR
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
gpg_error_t cmd_random (assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;

	return gpg_error (GPG_ERR_INV_OP);
}

/** Not implemented. */
gpg_error_t cmd_checkpin (assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;

	return gpg_error (GPG_ERR_INV_OP);
}

gpg_error_t cmd_getinfo (assuan_context_t ctx, char *line)
{
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	gpg_err_code_t error = GPG_ERR_GENERAL;
	const char *l;

	l = strgetopt_getopt(line, NULL);

	if (!strcmp (l, "version")) {
		char *s = PACKAGE_VERSION;
		error = assuan_send_data(ctx, s, strlen (s));
	}
	else if (!strcmp (l, "pid")) {
		char buf[50];
		snprintf (buf, sizeof (buf), "%lu", (unsigned long)getpid());
		error = assuan_send_data(ctx, buf, strlen (buf));
	}
	else if (!strcmp (l, "socket_name")) {
		const char *s = data->socket_name;

		if (s == NULL) {
			error = GPG_ERR_INV_DATA;
		}
		else {
			error = assuan_send_data(ctx, s, strlen (s));
		}
	}
	else if (!strcmp (l, "status")) {
		pkcs11h_certificate_id_list_t user_certificates = NULL;
		char flag = 'r';

		if (
			common_map_pkcs11_error (
				pkcs11h_certificate_enumCertificateIds (
					PKCS11H_ENUM_METHOD_CACHE_EXIST,
					ctx,
					PKCS11H_PROMPT_MASK_ALLOW_ALL,
					NULL,
					&user_certificates
				)
			) == GPG_ERR_NO_ERROR
		) {
			if (user_certificates != NULL) {
				flag = 'u';

				pkcs11h_certificate_freeCertificateIdList (user_certificates);
				user_certificates = NULL;
			}
		}

		error = assuan_send_data(ctx, &flag, 1);
	}
	else if (!strcmp (l, "reader_list")) {
		error = GPG_ERR_NO_DATA;
	}
	else {
		error = GPG_ERR_INV_DATA;
	}

	return gpg_error (error);
}

gpg_error_t cmd_keyinfo (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	pkcs11h_certificate_id_list_t curr_cert;
	char *list = NULL;
	int data_arg = 0;
	const char *l;
	char *serial;
	int found;
	int filter;

	const struct strgetopt_option options[] = {
		{"list", strgtopt_optional_argument, &list, NULL},
		{"data", strgtopt_no_argument, NULL, &data_arg},
		{NULL, 0, NULL, NULL}
	};

	l = strgetopt_getopt(line, options);

	if (list == NULL) {
	}
	else if (!strcmp(list, "")) {
		filter = 0;
	}
	else if (!strcmp(list, "auth")) {
		filter = OPENPGP_AUTH;
	}
	else if (!strcmp(list, "encr")) {
		filter = OPENPGP_ENCR;
	}
	else if (!strcmp(list, "sign")) {
		filter = OPENPGP_SIGN;
	}
	else {
		goto cleanup;
	}

	found = list != NULL;

	if (
		(error = common_map_pkcs11_error (
			pkcs11h_certificate_enumCertificateIds (
				PKCS11H_ENUM_METHOD_CACHE_EXIST,
				ctx,
				PKCS11H_PROMPT_MASK_ALLOW_ALL,
				NULL,
				&user_certificates
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	for (
		curr_cert = user_certificates;
		curr_cert != NULL;
		curr_cert = curr_cert->next
	) {
		char *certid = NULL;
		char *key_hexgrip = NULL;
		char *keyinfo_line = NULL;
		gcry_sexp_t sexp = NULL;
		size_t ser_len;
		int print = 0;

		if ((error = get_cert_sexp (ctx, curr_cert->certificate_id, &sexp)) != GPG_ERR_NO_ERROR) {
			goto retry;
		}

		if ((key_hexgrip = keyinfo_get_hexgrip (sexp)) == NULL) {
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

		if ((error = get_serial_of_tokenid(curr_cert->certificate_id->token_id, &serial)) != GPG_ERR_NO_ERROR) {
			goto cleanup;
		}

		if (list == NULL) {
			if (!strcmp(l, key_hexgrip)) {
				found=1;
				print=1;
			}
		}
		else {
			print=1;
		}

		if (data_arg &&  print) {
			if (
				(keyinfo_line = strdup (key_hexgrip)) == NULL ||
				!encoding_strappend (&keyinfo_line, " T ") ||
				!encoding_strappend (&keyinfo_line, serial) ||
				!encoding_strappend (&keyinfo_line, " ") ||
				!encoding_strappend (&keyinfo_line, certid)
			) {
				error = GPG_ERR_ENOMEM;
				goto retry;
			}

			if (
				(error = assuan_write_status(
					ctx,
					"KEYINFO",
					keyinfo_line
				)) != GPG_ERR_NO_ERROR
			) {
				goto cleanup;
			}
		}

		error = GPG_ERR_NO_ERROR;

	retry:
		if (sexp != NULL) {
			gcry_free (sexp);
			sexp = NULL;
		}

		if (keyinfo_line != NULL) {
			free (keyinfo_line);
			keyinfo_line = NULL;
		}

		if (certid != NULL) {
			free (certid);
			certid = NULL;
		}

		if (serial != NULL) {
			free(serial);
			serial = NULL;
		}

		if (key_hexgrip != NULL) {
			free (key_hexgrip);
			key_hexgrip = NULL;
		}

		if (error != GPG_ERR_NO_ERROR) {
			goto cleanup;
		}
	}

	error = found ? GPG_ERR_NO_ERROR : GPG_ERR_NOT_FOUND;

cleanup:

	strgetopt_free(options);

	if (user_certificates != NULL) {
		pkcs11h_certificate_freeCertificateIdList (user_certificates);
		user_certificates = NULL;
	}

	return gpg_error (error);
}

gpg_error_t cmd_restart (assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;

	return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_getattr (assuan_context_t ctx, char *line)
{
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	char *serial = NULL;
	gpg_err_code_t error = GPG_ERR_GENERAL;
	const char *l;
	int need_certificates = 0;
	keyinfo keyinfo = NULL;

	l = strgetopt_getopt(line, NULL);

	if (
		!strcmp (l, "KEY-FPR") ||
		!strcmp (l, "KEY-ATTR")
	) {
		need_certificates = 1;
	}

	if (need_certificates == 1) {
		if (
			(error = common_map_pkcs11_error (
				pkcs11h_certificate_enumCertificateIds (
					PKCS11H_ENUM_METHOD_CACHE_EXIST,
					ctx,
					PKCS11H_PROMPT_MASK_ALLOW_ALL,
					NULL,
					&user_certificates
				)
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
	}

	if (!strcmp (l, "SERIALNO")) {
		if (
			(error = get_serial(ctx, &serial)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}

		if (serial != NULL) {
			if (
				(error = assuan_write_status (
					ctx,
					"SERIALNO",
					serial
				)) != GPG_ERR_NO_ERROR
			) {
				goto cleanup;
			}
		}
	}
	else if (!strcmp (l, "KEY-FPR")) {
		if (
			(error = send_certificate_list (
				ctx,
				user_certificates,
				0
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
	}
	else if (!strcmp (l, "CHV-STATUS")) {
		if (
			(error = assuan_write_status(
				ctx,
				"CHV-STATUS",
				"1 1 1 1 1 1 1"
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
	}
	else if (!strcmp (l, "DISP-NAME")) {
		if (
			(error = assuan_write_status(
				ctx,
				"DISP-NAME",
				"PKCS#11"
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
	}
	else if (!strcmp (l, "KEY-ATTR")) {
		int i;
		char buffer[1024];
		const char *key_named_curve = NULL;
		int keyAlgo;
		int skip;

		for (
			pkcs11h_certificate_id_list_t curr_cert = user_certificates;
			curr_cert != NULL;
			curr_cert = curr_cert->next
		) {
			/* XXX:TODO: How do I know which key the KEY-ATTR is for ? */
			error = get_cert_keyinfo(ctx, curr_cert->certificate_id, &keyinfo);
			if (error != GPG_ERR_NO_ERROR) {
				goto cleanup;
			}

		}

		for (i=0;i<3;i++) {
			skip = 0;
			switch (keyinfo_get_type(keyinfo)) {
				case KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE:
					if (i == 1) {
						keyAlgo = 18 /* PUBKEY_ALGO_ECDH */;
						skip = 1;
						break;
					} else {
						keyAlgo = 19 /* PUBKEY_ALGO_ECDSA */;
					}

					key_named_curve = keyinfo_get_key_named_curve(keyinfo);
					if (key_named_curve == NULL) {
						skip = 1;

						break;
					}

					snprintf(buffer, sizeof(buffer), "%d %d %s", i + 1, keyAlgo, key_named_curve);
					break;
				case KEYINFO_KEY_TYPE_RSA:
					keyAlgo = GCRY_PK_RSA;

					snprintf(buffer, sizeof(buffer), "%d 1 %u %u %d", i+1, keyAlgo, keyinfo_get_key_length(keyinfo), 0);
					break;
				default:
					skip = 1;
					break;
			}

			if (skip == 1) {
				continue;
			}

			if (
				(error = assuan_write_status(
					ctx,
					"KEY-ATTR",
					buffer
				)) != GPG_ERR_NO_ERROR
			) {
				goto cleanup;
			}
		}
	}
	else if (!strcmp (l, "EXTCAP")) {
		int i;
		for (i=0;i<3;i++) {
			char buffer[1024];

			/* I am not sure what these are... */
			snprintf(buffer, sizeof(buffer), "gc=%d ki=%d fc=%d pd=%d mcl3=%u aac=%d sm=%d",
				0, 0, 0, 0, 2048, 0, 0);

			if (
				(error = assuan_write_status(
					ctx,
					"EXTCAP",
					buffer
				)) != GPG_ERR_NO_ERROR
			) {
				goto cleanup;
			}
		}
	}
	else {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (keyinfo != NULL) {
		keyinfo_free(keyinfo);
	}

	if (user_certificates != NULL) {
		pkcs11h_certificate_freeCertificateIdList (user_certificates);
		user_certificates = NULL;
	}

	if (serial != NULL) {
		free(serial);
		serial = NULL;
	}

	return gpg_error (error);
}

gpg_error_t cmd_setattr (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	const char *l;

	l = strgetopt_getopt(line, NULL);

	if (!strncmp (l, "CHV-STATUS-1 ", 13)) {
	}
	else {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	return gpg_error (error);
}

gpg_error_t cmd_genkey (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	keyinfo keyinfo;
	keyinfo_data_list key_parts = NULL, curr_key_part;
	unsigned char *n_hex = NULL;
	unsigned char *e_hex = NULL;
	char *part_resp = NULL;
	unsigned char *blob = NULL;
	char *serial = NULL;
	const char *key = NULL;
	size_t blob_size;
	char *timestamp = NULL;
	char _timestamp[100];
	const char *l;

	const struct strgetopt_option options[] = {
		{"timestamp", strgtopt_required_argument, &timestamp, NULL},
		{NULL, 0, NULL, NULL}
	};

	keyinfo = keyinfo_new();

	l = strgetopt_getopt(line, options);

	if (*l == '\x0') {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	if (timestamp == NULL) {
		sprintf (_timestamp, "%d", (int)time (NULL));
		timestamp = strdup(_timestamp);
	}

	if (
		(error = _get_certificate_by_name (
			ctx,
			NULL,
			atoi(l),
			&cert_id,
			&key
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (
		(error = assuan_write_status (
			ctx,
			"KEY-FPR",
			key
		)) != GPG_ERR_NO_ERROR ||
		(error = assuan_write_status(
			ctx,
			"KEY-CREATED-AT",
			timestamp
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((error = get_serial_of_tokenid(cert_id->token_id, &serial)) != GPG_ERR_NO_ERROR) {
		goto cleanup;
	}

	if (
		(error = assuan_write_status (
			ctx,
			"SERIALNO",
			serial
		)) != GPG_ERR_NO_ERROR ||
		(error = get_cert_blob (
			ctx,
			cert_id,
			&blob,
			&blob_size
		)) != GPG_ERR_NO_ERROR ||
		(error = keyinfo_from_der(
			keyinfo,
			blob,
			blob_size
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	key_parts = keyinfo_get_key_data(keyinfo);

	for (curr_key_part = key_parts; curr_key_part != NULL; curr_key_part = curr_key_part->next) {
		part_resp = strdup("");
		if (
			!encoding_strappend (&part_resp, (char *) curr_key_part->tag) ||
			!encoding_strappend (&part_resp, (char *) " ") ||
			!encoding_strappend (&part_resp, (char *) curr_key_part->value)
		) {
			error = GPG_ERR_ENOMEM;
			goto cleanup;
		}

		if (
			(error = assuan_write_status(
				ctx,
				(char *) curr_key_part->type,
				part_resp
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}

		free(part_resp);
		part_resp = NULL;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (part_resp != NULL) {
		free(part_resp);
	}

	if (key_parts != NULL) {
		keyinfo_data_free(key_parts);
		key_parts = NULL;
	}

	if (keyinfo != NULL) {
		keyinfo_free(keyinfo);
		keyinfo = NULL;
	}

	if (n_hex != NULL) {
		gcry_free (n_hex);
		n_hex = NULL;
	}

	if (e_hex != NULL) {
		gcry_free (e_hex);
		e_hex = NULL;
	}

	if (blob != NULL) {
		free (blob);
		blob = NULL;
	}

	if (cert_id != NULL) {
		pkcs11h_certificate_freeCertificateId (cert_id);
		cert_id = NULL;
	}

	if (serial != NULL) {
		free(serial);
		serial = NULL;
	}

	strgetopt_free(options);

	return gpg_error (error);
}

