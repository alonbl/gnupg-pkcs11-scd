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

		if (error != GPG_ERR_NO_ERROR) {
			goto cleanup;
		}
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	return error;
}

int _get_certificate_by_name (assuan_context_t ctx, char *name, int typehint, pkcs11h_certificate_id_t *p_cert_id, char **p_key) {
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	gpg_err_code_t error = GPG_ERR_BAD_KEY;
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	pkcs11h_certificate_id_list_t curr_cert;
	pkcs11h_certificate_id_t cert_id = NULL;
	char *key_hexgrip = NULL;
	gcry_sexp_t sexp = NULL;
	char *key = NULL;
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
		return common_map_pkcs11_error (
			pkcs11h_certificate_deserializeCertificateId (p_cert_id, name)
		);
	}
	else {
		type = atoi(name + strlen (OPENPGP_KEY_NAME_PREFIX));
	}

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

		if ((key_hexgrip = keyutil_get_cert_hexgrip (sexp)) == NULL) {
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

	if (
		(error = _get_certificate_by_name (
			ctx,
			line,
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

	if (
		(error = _get_certificate_by_name (
			ctx,
			line,
			0,
			&cert_id,
			NULL
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
		(error = assuan_send_data(
			ctx,
			blob,
			gcry_sexp_canon_len (blob, 0, NULL, NULL)
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
gpg_error_t cmd_setdata (assuan_context_t ctx, char *line)
{
	gpg_err_code_t error = GPG_ERR_GENERAL;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	int append = 0;
	int index;
	size_t len;

	while (*line != '\x0' && (isspace (*line) || *line == '-')) {
		if (*line == '-') {
			static const char *appendprm = "--append ";
			char *p = line;

			while (*line != '\x0' && !isspace (*line)) {
				line++;
			}
			line++;

			if (!strncmp (p, appendprm, strlen (appendprm))) {
				p += strlen (appendprm);
				append = 1;
			}
		}
		else {
			line++;
		}
	}

	if (!append) {
		cmd_free_data (ctx);
	}

	if (!encoding_hex2bin(line, NULL, &len)) {
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

	if (!encoding_hex2bin (line, data->data + index, NULL)) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	return gpg_error (error);
}

/** Sign data (set by SETDATA) with certificate id in line. */
gpg_error_t cmd_pksign (assuan_context_t ctx, char *line)
{
	static const unsigned char rmd160_prefix[] = /* (1.3.36.3.2.1) */
		{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
		0x02, 0x01, 0x05, 0x00, 0x04, 0x14  };
	static const unsigned char md5_prefix[] =   /* (1.2.840.113549.2.5) */
		{ 0x30, 0x2c, 0x30, 0x09, 0x06, 0x08, 0x2a, 0x86, 0x48,
		0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10  };
	static const unsigned char sha1_prefix[] =   /* (1.3.14.3.2.26) */
		{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
		0x02, 0x1a, 0x05, 0x00, 0x04, 0x14  };
	static const unsigned char sha224_prefix[] = /* (2.16.840.1.101.3.4.2.4) */
		{ 0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
		0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
		0x1C  };
	static const unsigned char sha256_prefix[] = /* (2.16.840.1.101.3.4.2.1) */
		{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20  };
	static const unsigned char sha384_prefix[] = /* (2.16.840.1.101.3.4.2.2) */
		{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
		0x00, 0x04, 0x30  };
	static const unsigned char sha512_prefix[] = /* (2.16.840.1.101.3.4.2.3) */
		{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
		0x00, 0x04, 0x40  };

	gpg_err_code_t error = GPG_ERR_GENERAL;
	pkcs11h_certificate_id_t cert_id = NULL;
	pkcs11h_certificate_t cert = NULL;
	cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
	cmd_data_t *_data = data;
	int need_free__data = 0;
	int session_locked = 0;
	unsigned char *sig = NULL;
	size_t sig_len;
	char hash[100] = "";
	enum {
		INJECT_NONE,
		INJECT_RMD160,
		INJECT_MD5,
		INJECT_SHA1,
		INJECT_SHA224,
		INJECT_SHA256,
		INJECT_SHA384,
		INJECT_SHA512
	} inject = INJECT_NONE;

	if (data->data == NULL) {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	while (*line != '\x0' && (isspace (*line) || *line == '-')) {
		if (*line == '-') {
			static const char *hashprm = "--hash=";
			char *p = line;

			while (*line != '\x0' && !isspace (*line)) {
				line++;
			}
			line++;

			if (!strncmp (p, hashprm, strlen (hashprm))) {
				p += strlen (hashprm);
				*(line-1) = '\0';
				snprintf (hash, sizeof(hash), "%s", p);
			}
		}
		else {
			line++;
		}
	}

	if (*line == '\x0') {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}
	/*
	 * sender prefixed data with algorithm OID
	 */
	if (strcmp(hash, "")) {
		if (!strcmp(hash, "rmd160") && data->size == (0x14 + sizeof(rmd160_prefix)) &&
			!memcmp (data->data, rmd160_prefix, sizeof (rmd160_prefix))) {
			inject = INJECT_NONE;
		}
		else if (!strcmp(hash, "rmd160") && data->size == 0x14) {
			inject = INJECT_RMD160;
		}
		else if (!strcmp(hash, "md5") && data->size == (0x10 + sizeof(md5_prefix)) &&
			!memcmp (data->data, md5_prefix, sizeof (md5_prefix))) {
			inject = INJECT_NONE;
		}
		else if (!strcmp(hash, "md5") && data->size == 0x10) {
			inject = INJECT_MD5;
		}
		else if (!strcmp(hash, "sha1") && data->size == (0x14 + sizeof(sha1_prefix)) &&
			!memcmp (data->data, sha1_prefix, sizeof (sha1_prefix))) {
			inject = INJECT_NONE;
		}
		else if (!strcmp(hash, "sha1") && data->size == 0x14) {
			inject = INJECT_SHA1;
		}
		else if (!strcmp(hash, "sha224") && data->size == (0x1c + sizeof(sha224_prefix)) &&
			!memcmp (data->data, sha224_prefix, sizeof (sha224_prefix))) {
			inject = INJECT_NONE;
		}
		else if (!strcmp(hash, "sha224") && data->size == 0x1c) {
			inject = INJECT_SHA224;
		}
		else if (!strcmp(hash, "sha256") && data->size == (0x20 + sizeof(sha256_prefix)) &&
			!memcmp (data->data, sha256_prefix, sizeof (sha256_prefix))) {
			inject = INJECT_NONE;
		}
		else if (!strcmp(hash, "sha256") && data->size == 0x20) {
			inject = INJECT_SHA256;
		}
		else if (!strcmp(hash, "sha384") && data->size == (0x30 + sizeof(sha384_prefix)) &&
			!memcmp (data->data, sha384_prefix, sizeof (sha384_prefix))) {
			inject = INJECT_NONE;
		}
		else if (!strcmp(hash, "sha384") && data->size == 0x30) {
			inject = INJECT_SHA384;
		}
		else if (!strcmp(hash, "sha512") && data->size == (0x40 + sizeof(sha512_prefix)) &&
			!memcmp (data->data, sha512_prefix, sizeof (sha512_prefix))) {
			inject = INJECT_NONE;
		}
		else if (!strcmp(hash, "sha512") && data->size == 0x40) {
			inject = INJECT_SHA512;
		}
		else {
			common_log (LOG_DEBUG, "unsupported hash algo (hash=%s,size=%d)", hash, data->size);
			error = GPG_ERR_UNSUPPORTED_ALGORITHM;
			goto cleanup;
		}
	}
	else {
		if (
			data->size == 0x10 + sizeof (md5_prefix) ||
			data->size == 0x14 + sizeof (sha1_prefix) ||
			data->size == 0x14 + sizeof (rmd160_prefix)
		) {
			if (
				memcmp (data->data, md5_prefix, sizeof (md5_prefix)) &&
				memcmp (data->data, sha1_prefix, sizeof (sha1_prefix)) &&
				memcmp (data->data, rmd160_prefix, sizeof (rmd160_prefix))
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
			inject = INJECT_SHA1;
		}
	}

	if (inject != INJECT_NONE) {
		const unsigned char *oid;
		size_t oid_size;
		switch (inject) {
			case INJECT_RMD160:
				oid = rmd160_prefix;
				oid_size = sizeof (rmd160_prefix);
			break;
			case INJECT_MD5:
				oid = md5_prefix;
				oid_size = sizeof (md5_prefix);
			break;
			case INJECT_SHA1:
				oid = sha1_prefix;
				oid_size = sizeof (sha1_prefix);
			break;
			case INJECT_SHA224:
				oid = sha224_prefix;
				oid_size = sizeof (sha224_prefix);
			break;
			case INJECT_SHA256:
				oid = sha256_prefix;
				oid_size = sizeof(sha256_prefix);
			break;
			case INJECT_SHA384:
				oid = sha384_prefix;
				oid_size = sizeof(sha384_prefix);
			break;
			case INJECT_SHA512:
				oid = sha512_prefix;
				oid_size = sizeof(sha512_prefix);
			break;
			default:
				error = GPG_ERR_INV_DATA;
				goto cleanup;
		}

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
		(error = _get_certificate_by_name (
			ctx,
			line,
			OPENPGP_SIGN,
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

	if (sig != NULL) {
		free (sig);
		sig = NULL;
	}

	if (need_free__data) {
		free (_data->data);
		_data->data = NULL;
		free (_data);
		_data = NULL;
	}

	return gpg_error (error);
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
	
	/* Start Mark Kolev update */
	if (_data.size >= (128-16) && _data.size < 128) /* 1024 bit key */
		fixuplen = 128 - _data.size;
	else if (_data.size >= (192-16) && _data.size < 192) /* 1536 bit key.  */
        	fixuplen = 192 - _data.size;
    	else if (_data.size >= (256-16) && _data.size < 256) /* 2048 bit key.  */
        	fixuplen = 256 - _data.size;
    	else if (_data.size >= (384-16) && _data.size < 384) /* 3072 bit key.  */
        	fixuplen = 384 - _data.size;
    	else if (_data.size >= (512-16) && _data.size < 512) /* 4096 bit key.  */
        	fixuplen = 512 - _data.size;
	else if (
		*_data.data == 0 && (
			_data.size == 129 ||
			_data.size == 193 ||
			_data.size == 257 ||
			_data.size == 385 ||
			_data.size == 513)) 
	{
		_data.data++;
		_data.size--;
	}
	else
		fixuplen = 0;

	if (fixuplen > 0)
	{
		newdata = malloc(fixuplen + _data.size);
		memset(newdata, 0, fixuplen);
		memcpy(newdata + fixuplen, _data.data, _data.size);
		_data.size = fixuplen + _data.size;
		_data.data = newdata;
	}
	/* end Mark Kolev update */
	if (
		(error = _get_certificate_by_name (
			ctx,
			line,
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

	if (!strcmp (line, "version")) {
		char *s = PACKAGE_VERSION;
		error = assuan_send_data(ctx, s, strlen (s));
	}
	else if (!strcmp (line, "pid")) {
		char buf[50];
		snprintf (buf, sizeof (buf), "%lu", (unsigned long)getpid());
		error = assuan_send_data(ctx, buf, strlen (buf));
	}
	else if (!strcmp (line, "socket_name")) {
		const char *s = data->socket_name;

		if (s == NULL) {
			error = GPG_ERR_INV_DATA;
		}
		else {
			error = assuan_send_data(ctx, s, strlen (s));
		}
	}
	else if (!strcmp (line, "status")) {
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
	else if (!strcmp (line, "reader_list")) {
		error = GPG_ERR_NO_DATA;
	}
	else {
		error = GPG_ERR_INV_DATA;
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

	if (!strcmp (line, "SERIALNO")) {
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
	else if (!strcmp (line, "KEY-FPR")) {
		if (
			(error = common_map_pkcs11_error (
				pkcs11h_certificate_enumCertificateIds (
					PKCS11H_ENUM_METHOD_CACHE_EXIST,
					ctx,
					PKCS11H_PROMPT_MASK_ALLOW_ALL,
					NULL,
					&user_certificates
				)
			)) != GPG_ERR_NO_ERROR ||
			(error = send_certificate_list (
				ctx,
				user_certificates,
				0
			)) != GPG_ERR_NO_ERROR
		) {
			goto cleanup;
		}
	}
	else if (!strcmp (line, "CHV-STATUS")) {
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
	else if (!strcmp (line, "DISP-NAME")) {
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
	else if (!strcmp (line, "KEY-ATTR")) {
		int i;
		for (i=0;i<3;i++) {
			char buffer[1024];

			/* I am not sure 2048 is right here... */
			snprintf(buffer, sizeof(buffer), "%d 1 %u %u %d", i+1, GCRY_PK_RSA, 2048, 0);

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
	else if (!strcmp (line, "EXTCAP")) {
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

	if (!strncmp (line, "CHV-STATUS-1 ", 13)) {
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
	gcry_mpi_t n_mpi = NULL;
	gcry_mpi_t e_mpi = NULL;
	unsigned char *n_hex = NULL;
	unsigned char *e_hex = NULL;
	char *n_resp = strdup ("n ");
	char *e_resp = strdup ("e ");
	unsigned char *blob = NULL;
	char *serial = NULL;
	char *key = NULL;
	size_t blob_size;
	char timestamp[100] = {0};

	while (*line != '\x0' && !isdigit (*line)) {
		if (*line == '-') {
			static const char *ts = "--timestamp=";
			char *p = line;

			while (*line != '\x0' && !isspace (*line)) {
				line++;
			}
			line++;

			if (!strncmp (p, ts, strlen (ts))) {
				p += strlen (ts);
				sprintf (timestamp, "%d", (int)isotime2epoch (p));
			}
		}
		else {
			line++;
		}
	}

	if (*line == '\x0') {
		error = GPG_ERR_INV_DATA;
		goto cleanup;
	}

	if (strlen (timestamp) == 0) {
		sprintf (timestamp, "%d", (int)time (NULL));
	}

	if (
		(error = _get_certificate_by_name (
			ctx,
			NULL,
			atoi(line),
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
		(error = keyutil_get_cert_mpi (
			blob,
			blob_size,
			&n_mpi,
			&e_mpi
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (
		gcry_mpi_aprint (
			GCRYMPI_FMT_HEX,
			&n_hex,
			NULL,
			n_mpi
		) ||
		gcry_mpi_aprint (
			GCRYMPI_FMT_HEX,
			&e_hex,
			NULL,
			e_mpi
		)
	) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}

	if (
		!encoding_strappend (&n_resp, (char *)n_hex) ||
		!encoding_strappend (&e_resp, (char *)e_hex)
	) {
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (
		(error = assuan_write_status(
			ctx,
			"KEY-DATA",
			n_resp
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if (
		(error = assuan_write_status(
			ctx,
			"KEY-DATA",
			e_resp
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	error = GPG_ERR_NO_ERROR;

cleanup:

	if (n_mpi != NULL) {
		gcry_mpi_release (n_mpi);
		n_mpi = NULL;
	}

	if (e_mpi != NULL) {
		gcry_mpi_release (e_mpi);
		e_mpi = NULL;
	}

	if (n_hex != NULL) {
		gcry_free (n_hex);
		n_hex = NULL;
	}

	if (e_hex != NULL) {
		gcry_free (e_hex);
		e_hex = NULL;
	}

	if (n_resp != NULL) {
		free (n_resp);
		n_resp = NULL;
	}

	if (e_resp != NULL) {
		free (e_resp);
		e_resp = NULL;
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

	return gpg_error (error);
}


