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
#if defined(ENABLE_GNUTLS)
#include <gnutls/x509.h>
#endif
#if defined(ENABLE_OPENSSL)
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#endif
#include "encoding.h"
#include "keyutil.h"

struct keyinfo_s {
	keyinfo_key_type_t type;
	union {
		struct {
			gcry_mpi_t n;
			gcry_mpi_t e;
		} rsa;

		struct {
			gcry_mpi_t q;
			char *named_curve;
			int named_curve_free;
		} ecdsa;
	} data;
};

/**
 * Initialize a KeyUtil KeyInfo Object
 */
void keyinfo_init(keyinfo keyinfo, keyinfo_key_type_t keytype) {
	keyinfo->type = keytype;

	if (keyinfo->type == KEYINFO_KEY_TYPE_RSA || keyinfo->type == KEYINFO_KEY_TYPE_UNKNOWN) {
		keyinfo->data.rsa.e = NULL;
		keyinfo->data.rsa.n = NULL;
	}

	if (keyinfo->type == KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE || keyinfo->type == KEYINFO_KEY_TYPE_UNKNOWN) {
		keyinfo->data.ecdsa.q = NULL;
		keyinfo->data.ecdsa.named_curve = NULL;
		keyinfo->data.ecdsa.named_curve_free = 0;
	}
}

/**
 * Allocate a new KeyInfo object
 */
keyinfo keyinfo_new(void) {
	keyinfo keyinfo;

	keyinfo = malloc(sizeof(*keyinfo));
	if (keyinfo == NULL) {
		return(NULL);
	}

	keyinfo_init(keyinfo, KEYINFO_KEY_TYPE_UNKNOWN);

	return(keyinfo);
}

/**
 * Free any resources held by a KeyUtil KeyInfo object.
 */
void keyinfo_free(keyinfo keyinfo) {
	if (keyinfo == NULL) {
		return;
	}

	switch (keyinfo->type) {
		case KEYINFO_KEY_TYPE_RSA:
			if (keyinfo->data.rsa.e) {
				gcry_mpi_release(keyinfo->data.rsa.e);
				keyinfo->data.rsa.e = NULL;
			}
			if (keyinfo->data.rsa.n) {
				gcry_mpi_release(keyinfo->data.rsa.n);
				keyinfo->data.rsa.n = NULL;
			}
			break;
		case KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE:
			if (keyinfo->data.ecdsa.q) {
				gcry_mpi_release(keyinfo->data.ecdsa.q);
				keyinfo->data.ecdsa.q = NULL;
			}
			if (keyinfo->data.ecdsa.named_curve) {
				if (keyinfo->data.ecdsa.named_curve_free) {
					free(keyinfo->data.ecdsa.named_curve);
				}
				keyinfo->data.ecdsa.named_curve = NULL;
			}
			break;
		case KEYINFO_KEY_TYPE_UNKNOWN:
			/* Nothing to do for unknown types */
			break;
		case KEYINFO_KEY_TYPE_INVALID:
			abort();
			break;
	}

	keyinfo->type = KEYINFO_KEY_TYPE_INVALID;

	free(keyinfo);
}

keyinfo_key_type_t keyinfo_get_type(keyinfo keyinfo) {
	if (keyinfo->type == KEYINFO_KEY_TYPE_INVALID) {
		abort();
	}

	return(keyinfo->type);
}

#if defined(ENABLE_OPENSSL)
#if OPENSSL_VERSION_NUMBER < 0x00908000L
typedef unsigned char *my_openssl_d2i_t;
#else
typedef const unsigned char *my_openssl_d2i_t;
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
static void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
	if (n != NULL) {
		*n = r->n;
	}
	if (e != NULL) {
		*e = r->e;
	}
	if (d != NULL) {
		*d = r->d;
	}
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
static int EVP_PKEY_get_base_id(const EVP_PKEY *pkey) {
	return(EVP_PKEY_type(pkey->type));
}
#endif

#endif

/**
 * Convert the public key from an X.509 certificate into an already-created
 * key object
 */
gpg_err_code_t
keyinfo_from_der(
	keyinfo keyinfo,
	unsigned char *der,
	size_t len
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	gcry_mpi_t n_mpi = NULL;
	gcry_mpi_t e_mpi = NULL;
	gcry_mpi_t q_mpi = NULL;
#if defined(ENABLE_GNUTLS)
	gnutls_x509_crt_t cert = NULL;
	gnutls_datum_t datum = {der, len};
	gnutls_datum_t m = {NULL, 0}, e = {NULL, 0};
#elif defined(ENABLE_OPENSSL)
	int check_result;
	X509 *x509 = NULL;
	EVP_PKEY *pubkey = NULL;
	EVP_PKEY_CTX *pubkey_ctx = NULL;
	RSA *rsa = NULL;
	EC_KEY *ec_key = NULL;
	const EC_POINT *ec_pubkey;
	const EC_GROUP *ec_group;
	const BIGNUM *n, *e;
	BN_CTX *q_ctx = NULL;
	char *n_hex = NULL, *e_hex = NULL, *q_hex = NULL;
#endif

#if defined(ENABLE_GNUTLS)
	if (gnutls_x509_crt_init (&cert) != GNUTLS_E_SUCCESS) {
		cert = NULL;
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}

	if (gnutls_x509_crt_get_pk_rsa_raw (cert, &m, &e) != GNUTLS_E_SUCCESS) {
		error = GPG_ERR_WRONG_PUBKEY_ALGO;
		m.data = NULL;
		e.data = NULL;
		goto cleanup;
	}

	if (
		gcry_mpi_scan(&n_mpi, GCRYMPI_FMT_USG, m.data, m.size, NULL) ||
		gcry_mpi_scan(&e_mpi, GCRYMPI_FMT_USG, e.data, e.size, NULL)
	) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
#elif defined(ENABLE_OPENSSL)
	if (!d2i_X509 (&x509, (my_openssl_d2i_t *)&der, len)) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}

	if ((pubkey = X509_get_pubkey (x509)) == NULL) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}

	pubkey_ctx = EVP_PKEY_CTX_new(pubkey, NULL);
	if (pubkey_ctx == NULL) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}

	/**
	 * Check the public key context
	 * 1 is success, -2 is not applicable
	 */
	check_result = EVP_PKEY_public_check(pubkey_ctx);
	if (check_result != 1 && check_result != -2) {
		error = GPG_ERR_WRONG_PUBKEY_ALGO;
		goto cleanup;
	}

	if (EVP_PKEY_get_base_id(pubkey) == EVP_PKEY_EC) {
		keyinfo_init(keyinfo, KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE);
	}

	if (EVP_PKEY_get_base_id(pubkey) == EVP_PKEY_RSA) {
		keyinfo_init(keyinfo, KEYINFO_KEY_TYPE_RSA);
	}

	switch (keyinfo->type) {
		case KEYINFO_KEY_TYPE_RSA:
			/* Warning: EVP_PKEY_get1_RSA is deprecated in OpenSSL 3.0 */
			if ((rsa = EVP_PKEY_get1_RSA(pubkey)) == NULL) {
				error = GPG_ERR_WRONG_PUBKEY_ALGO;
				goto cleanup;
			}

			RSA_get0_key(rsa, &n, &e, NULL);

			n_hex = BN_bn2hex (n);
			e_hex = BN_bn2hex (e);

			if(n_hex == NULL || e_hex == NULL) {
				error = GPG_ERR_BAD_KEY;
				goto cleanup;
			}

			if (
				gcry_mpi_scan (&n_mpi, GCRYMPI_FMT_HEX, n_hex, 0, NULL) ||
				gcry_mpi_scan (&e_mpi, GCRYMPI_FMT_HEX, e_hex, 0, NULL)
			) {
				error = GPG_ERR_BAD_KEY;
				goto cleanup;
			}
			break;
		case KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE:
			/* Warning: EVP_PKEY_get1_EC_KEY is deprecated in OpenSSL 3.0 */
			ec_key = EVP_PKEY_get1_EC_KEY(pubkey);
			if (ec_key == NULL) {
				error = GPG_ERR_BAD_KEY;
				goto cleanup;
			}

			/* Warning: EC_KEY_get0_public_key is deprecated in OpenSSL 3.0 */
			ec_pubkey = EC_KEY_get0_public_key(ec_key);
			if (ec_pubkey == NULL) {
				error = GPG_ERR_BAD_KEY;
				goto cleanup;
			}

			/* Warning: EC_KEY_get0_group is deprecated in OpenSSL 3.0 */
			ec_group = EC_KEY_get0_group(ec_key);
			if (ec_group == NULL) {
				error = GPG_ERR_BAD_KEY;
				goto cleanup;
			}

			q_ctx = BN_CTX_new();
			if (q_ctx == NULL) {
				error = GPG_ERR_SYSTEM_ERROR;
				goto cleanup;
			}

			q_hex = EC_POINT_point2hex(ec_group, ec_pubkey, EC_GROUP_get_point_conversion_form(ec_group), q_ctx);
			BN_CTX_free(q_ctx);

			if (q_hex == NULL) {
				error = GPG_ERR_BAD_KEY;
				goto cleanup;
			}

			if (gcry_mpi_scan (&q_mpi, GCRYMPI_FMT_HEX, q_hex, 0, NULL)) {
				error = GPG_ERR_BAD_KEY;
				goto cleanup;
			}
			break;
		case KEYINFO_KEY_TYPE_UNKNOWN:
			error = GPG_ERR_BAD_KEY;
			goto cleanup;
		case KEYINFO_KEY_TYPE_INVALID:
			abort();
			goto cleanup;
	}
#else
#error Invalid configuration.
#endif

	switch (keyinfo->type) {
		case KEYINFO_KEY_TYPE_RSA:
			keyinfo->data.rsa.n = n_mpi;
			n_mpi = NULL;

			keyinfo->data.rsa.e = e_mpi;
			e_mpi = NULL;

			error = GPG_ERR_NO_ERROR;
			break;
		case KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE:
			keyinfo->data.ecdsa.named_curve = "prime256v1"; /* XXX:TODO */
			keyinfo->data.ecdsa.named_curve_free = 0;

			keyinfo->data.ecdsa.q = q_mpi;
			q_mpi = NULL;

			error = GPG_ERR_NO_ERROR;
			break;
		case KEYINFO_KEY_TYPE_UNKNOWN:
			error = GPG_ERR_BAD_KEY;
			goto cleanup;
			break;
		case KEYINFO_KEY_TYPE_INVALID:
			abort();
			break;
	}

cleanup:

	if (n_mpi != NULL) {
		gcry_mpi_release (n_mpi);
		n_mpi = NULL;
	}

	if (e_mpi != NULL) {
		gcry_mpi_release (e_mpi);
		e_mpi = NULL;
	}

	if (q_mpi != NULL) {
		gcry_mpi_release (q_mpi);
		q_mpi = NULL;
	}

#if defined(ENABLE_GNUTLS)

	if (m.data != NULL) {
		gnutls_free (m.data);
		m.data = NULL;
	}

	if (e.data != NULL) {
		gnutls_free (e.data);
		e.data = NULL;
	}

	if (cert != NULL) {
		gnutls_x509_crt_deinit (cert);
		cert = NULL;
	}

#elif defined(ENABLE_OPENSSL)

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}

	if (pubkey_ctx) {
		EVP_PKEY_CTX_free(pubkey_ctx);
		pubkey_ctx = NULL;
	}

	if (pubkey != NULL) {
		EVP_PKEY_free(pubkey);
		pubkey = NULL;
	}

	if (rsa != NULL) {
		/* Warning: RSA_free is deprecated in OpenSSL 3.0 */
		RSA_free(rsa);
		rsa = NULL;
	}

	if (ec_key != NULL) {
		/* Warning: EC_KEY_free is deprecated in OpenSSL 3.0 */
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}

	if (n_hex != NULL) {
		OPENSSL_free (n_hex);
		n_hex = NULL;
	}

	if (e_hex != NULL) {
		OPENSSL_free (e_hex);
		e_hex = NULL;
	}

	if (q_hex != NULL) {
		OPENSSL_free (q_hex);
		q_hex = NULL;
	}

#else
#error Invalid configuration.
#endif

	return error;
}

gcry_sexp_t keyinfo_to_sexp(keyinfo keyinfo) {
	gcry_sexp_t sexp = NULL, complete_sexp = NULL;
	gcry_error_t sexp_build_result;

	switch (keyinfo->type) {
		case KEYINFO_KEY_TYPE_RSA:
			sexp_build_result = gcry_sexp_build(
				&sexp,
				NULL,
				"(public-key (rsa (n %m) (e %m)))",
				keyinfo->data.rsa.n,
				keyinfo->data.rsa.e
			);
			break;
		case KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE:
			sexp_build_result = gcry_sexp_build(
				&sexp,
				NULL,
				"(public-key (ecc (curve %s) (q %m)))",
				keyinfo->data.ecdsa.named_curve,
				keyinfo->data.ecdsa.q
			);
			break;
		case KEYINFO_KEY_TYPE_UNKNOWN:
			sexp_build_result = 1;
			break;
		case KEYINFO_KEY_TYPE_INVALID:
			abort();
			break;
	}

	if (sexp_build_result != 0) {
		goto cleanup;
	}

	complete_sexp = sexp;
	sexp = NULL;

cleanup:

	if (sexp != NULL) {
		gcry_sexp_release (sexp);
		sexp = NULL;
	}

	return complete_sexp;
}

#if 0
/**
   Calculate certid for the certificate. The certid is stored as hex-encoded,
   null-terminated string into certid which must be at least 41 bytes long.
   This is very primitive ID, just using the SHA1 of the whole certificate DER
   encoding. Currently not used.
*/
void cert_get_hexgrip(unsigned char *der, size_t len, char *certid)
{
	int ret;
	char grip[20];

	SHA1(der, len, grip);
	ret = bin2hex(hexgrip, 41, grip, 20);
	g_assert(ret == 20);
}
#endif

/** Calculate hex-encoded keygrip of public key in sexp. */
char *keyinfo_get_hexgrip (gcry_sexp_t sexp)
{
	char *ret = NULL;
	unsigned char grip[20];

	if (gcry_pk_get_keygrip (sexp, grip)) {
		ret = encoding_bin2hex (grip, sizeof (grip));
	}

	return ret;
}

void keyinfo_data_free(keyinfo_data_list list) {
	keyinfo_data_list next, curr;

	if (list == NULL) {
		return;
	}

	for (curr = list; curr != NULL; curr = next) {
		next = curr->next;

		free(curr);
	}
}

keyinfo_data_list keyinfo_get_key_data(keyinfo keyinfo) {
	keyinfo_data_list first = NULL, n_item = NULL, e_item = NULL, q_item = NULL;
	unsigned char *n_hex = NULL;
	unsigned char *e_hex = NULL;

	if (keyinfo->type == KEYINFO_KEY_TYPE_INVALID) {
		abort();
	}

	if (keyinfo->type != KEYINFO_KEY_TYPE_UNKNOWN) {
		return(NULL);
	}

	switch (keyinfo->type) {
		case KEYINFO_KEY_TYPE_RSA:
			if (
				gcry_mpi_aprint (
					GCRYMPI_FMT_HEX,
					&n_hex,
					NULL,
					keyinfo->data.rsa.n
				) ||
				gcry_mpi_aprint (
					GCRYMPI_FMT_HEX,
					&e_hex,
					NULL,
					keyinfo->data.rsa.e
				)
			) {
				break;
			}

			e_item = malloc(sizeof(*e_item));
			if (e_item == NULL) {
				break;
			}
			e_item->next = NULL;
			e_item->type = (unsigned char *) "KEY-DATA";
			e_item->tag = (unsigned char *) "e";
			e_item->value = e_hex;

			n_item = malloc(sizeof(*n_item));
			if (n_item == NULL) {
				break;
			}
			n_item->next = e_item;
			n_item->type = (unsigned char *) "KEY-DATA";
			e_item->tag = (unsigned char *) "n";
			n_item->value = n_hex;

			first = n_item;
			n_item = NULL;
			e_item = NULL;

			break;
		case KEYINFO_KEY_TYPE_ECDSA_NAMED_CURVE:
			break;
		case KEYINFO_KEY_TYPE_UNKNOWN:
			break;
		case KEYINFO_KEY_TYPE_INVALID:
			abort();
	}

	if (n_hex != NULL) {
		gcry_free(n_hex);
		n_hex = NULL;
	}

	if (e_hex != NULL) {
		gcry_free(e_hex);
		e_hex = NULL;
	}

	if (n_item != NULL) {
		free(n_item);
		n_item = NULL;
	}

	if (e_item != NULL) {
		free(e_item);
		e_item = NULL;
	}

	if (q_item != NULL) {
		free(q_item);
		q_item = NULL;
	}

	return(first);
}
