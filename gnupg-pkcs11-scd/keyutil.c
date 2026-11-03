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
#include <openssl/ec.h>
#endif
#include "encoding.h"
#include "keyutil.h"

gpg_err_code_t
keyutil_get_cert_mpi (
	unsigned char *der,
	size_t len,
	gcry_mpi_t *p_n_mpi,
	gcry_mpi_t *p_e_mpi
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	gcry_mpi_t n_mpi = NULL;
	gcry_mpi_t e_mpi = NULL;
#if defined(ENABLE_GNUTLS)
	gnutls_x509_crt_t cert = NULL;
	gnutls_datum_t datum = {der, len};
	gnutls_datum_t m = {NULL, 0}, e = {NULL, 0};
#elif defined(ENABLE_OPENSSL)
	X509 *x509 = NULL;
	EVP_PKEY *pubkey = NULL;
	RSA *rsa = NULL;
	const BIGNUM *n, *e;
	char *n_hex = NULL, *e_hex = NULL;
#endif

	*p_n_mpi = NULL;
	*p_e_mpi = NULL;

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
	if (!d2i_X509 (&x509, (const unsigned char **)&der, len)) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}

	if ((pubkey = X509_get_pubkey (x509)) == NULL) {
		error = GPG_ERR_WRONG_PUBKEY_ALGO;
		goto cleanup;
	}

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
#else
#error Invalid configuration.
#endif

	*p_n_mpi = n_mpi;
	n_mpi = NULL;
	*p_e_mpi = e_mpi;
	e_mpi = NULL;
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

	if (pubkey != NULL) {
		EVP_PKEY_free(pubkey);
		pubkey = NULL;
	}

	if (rsa != NULL) {
		RSA_free(rsa);
		rsa = NULL;
	}

	if (n_hex != NULL) {
		OPENSSL_free (n_hex);
		n_hex = NULL;
	}

	if (e_hex != NULL) {
		OPENSSL_free (e_hex);
		e_hex = NULL;
	}

#else
#error Invalid configuration.
#endif

	return error;
}
/* Read the named P-384 public key used by the Polish e-ID.  Keep this
 * separate from the RSA MPI interface, which is also used by GENKEY. */
static gpg_err_code_t
keyutil_get_p384_sexp (unsigned char *der, size_t len, gcry_sexp_t *p_sexp)
{
	gpg_err_code_t error = GPG_ERR_WRONG_PUBKEY_ALGO;
	unsigned char q[97] = { 0x04 };
	gcry_ctx_t ec = NULL;
	gcry_mpi_point_t point = NULL;
#if defined(ENABLE_GNUTLS)
	gnutls_x509_crt_t cert = NULL;
	gnutls_datum_t datum = { der, len };
	gnutls_datum_t x = { NULL, 0 }, y = { NULL, 0 };
	gnutls_ecc_curve_t curve;
	size_t x_skip, y_skip;
	if (gnutls_x509_crt_init (&cert) != GNUTLS_E_SUCCESS) {
		return GPG_ERR_ENOMEM;
	}
	if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}
	if (gnutls_x509_crt_get_pk_algorithm (cert, NULL) != GNUTLS_PK_EC) {
		goto cleanup;
	}
	if (gnutls_x509_crt_get_pk_ecc_raw (cert, &curve, &x, &y) != GNUTLS_E_SUCCESS) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
	if (curve != GNUTLS_ECC_CURVE_SECP384R1) {
		goto cleanup;
	}
	if (!x.data || !y.data || !x.size || !y.size) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
	/* Some raw MPI exports include a leading zero sign octet. */
	x_skip = x.size == 49 && x.data[0] == 0;
	y_skip = y.size == 49 && y.data[0] == 0;
	if (x.size - x_skip > 48 || y.size - y_skip > 48) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
	memcpy (q + 1 + 48 - (x.size - x_skip), x.data + x_skip, x.size - x_skip);
	memcpy (q + 1 + 96 - (y.size - y_skip), y.data + y_skip, y.size - y_skip);
#elif defined(ENABLE_OPENSSL)
	X509 *cert = NULL;
	EVP_PKEY *pubkey = NULL;
	EC_KEY *key = NULL;
	const EC_GROUP *group;
	const EC_POINT *pubpoint;
	if (!d2i_X509 (&cert, (const unsigned char **)&der, len)) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}
	pubkey = X509_get_pubkey (cert);
	if (!pubkey || EVP_PKEY_base_id (pubkey) != EVP_PKEY_EC) {
		goto cleanup;
	}
	key = EVP_PKEY_get1_EC_KEY (pubkey);
	if (!key) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
	group = EC_KEY_get0_group (key);
	pubpoint = EC_KEY_get0_public_key (key);
	if (!group || EC_GROUP_get_curve_name (group) != NID_secp384r1) {
		goto cleanup;
	}
	if (!pubpoint || EC_KEY_check_key (key) != 1 ||
		EC_POINT_point2oct (group, pubpoint, POINT_CONVERSION_UNCOMPRESSED,
			q, sizeof (q), NULL) != sizeof (q)) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
#endif
	if (gcry_sexp_build (p_sexp, NULL,
		"(public-key(ecc(curve %s)(q %b)))", "NIST P-384", (int)sizeof (q), q)) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
	/* Validate with the same curve implementation that computes the keygrip. */
	if (gcry_mpi_ec_new (&ec, *p_sexp, NULL) ||
		!(point = gcry_mpi_ec_get_point ("q", ec, 1)) ||
		!gcry_mpi_ec_curve_point (point, ec)) {
		gcry_sexp_release (*p_sexp);
		*p_sexp = NULL;
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
	error = GPG_ERR_NO_ERROR;

cleanup:
	if (point) gcry_mpi_point_release (point);
	if (ec) gcry_ctx_release (ec);
#if defined(ENABLE_GNUTLS)
	gnutls_free (x.data);
	gnutls_free (y.data);
	if (cert) gnutls_x509_crt_deinit (cert);
#elif defined(ENABLE_OPENSSL)
	EC_KEY_free (key);
	EVP_PKEY_free (pubkey);
	X509_free (cert);
#endif
	return error;
}

/** Convert an X.509 RSA or named P-384 public key to a libgcrypt S-expression. */
gpg_err_code_t
keyutil_get_cert_sexp (
	unsigned char *der,
	size_t len,
	gcry_sexp_t *p_sexp
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	gcry_mpi_t n_mpi = NULL;
	gcry_mpi_t e_mpi = NULL;
	gcry_sexp_t sexp = NULL;

	*p_sexp = NULL;

	if (
		(error = keyutil_get_cert_mpi (
			der,
			len,
			&n_mpi,
			&e_mpi
		)) != GPG_ERR_NO_ERROR
	) {
		if (error == GPG_ERR_WRONG_PUBKEY_ALGO) {
			error = keyutil_get_p384_sexp (der, len, p_sexp);
		}
		goto cleanup;
	}

	if (
		gcry_sexp_build (
			&sexp,
			NULL,
			"(public-key (rsa (n %m) (e %m)))",
			n_mpi,
			e_mpi
		)
	) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}

	*p_sexp = sexp;
	sexp = NULL;
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

	if (sexp != NULL) {
		gcry_sexp_release (sexp);
		sexp = NULL;
	}

	return error;
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
char *keyutil_get_cert_hexgrip (gcry_sexp_t sexp)
{
	char *ret = NULL;
	unsigned char grip[20];

	if (gcry_pk_get_keygrip (sexp, grip)) {
		ret = encoding_bin2hex (grip, sizeof (grip));
	}

	return ret;
}
