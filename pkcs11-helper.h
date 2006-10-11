/*
 * Copyright (c) 2005-2006 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, or the OpenIB.org BSD license.
 *
 * GNU General Public License (GPL) Version 2
 * ===========================================
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING[.GPL2] included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * OpenIB.org BSD license
 * =======================
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

/*
 * The routines in this file deal with providing private key cryptography
 * using RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki).
 *
 */

#ifndef __PKCS11H_HELPER_H
#define __PKCS11H_HELPER_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "pkcs11-helper-config.h"

#if !defined(USE_PKCS11H_OPENSSL) && !defined(USE_PKCS11H_GNUTLS)
#error PKCS#11: USE_PKCS11H_OPENSSL or USE_PKCS11H_GNUTLS must be defined
#endif

#if defined(ENABLE_PKCS11H_SLOTEVENT) && !defined(ENABLE_PKCS11H_THREADING)
#error PKCS#11: ENABLE_PKCS11H_SLOTEVENT requires ENABLE_PKCS11H_THREADING
#endif
#if defined(ENABLE_PKCS11H_OPENSSL) && !defined(ENABLE_PKCS11H_CERTIFICATE)
#error PKCS#11: ENABLE_PKCS11H_OPENSSL requires ENABLE_PKCS11H_CERTIFICATE
#endif

#define PKCS11H_LOG_DEBUG2	5
#define PKCS11H_LOG_DEBUG1	4
#define PKCS11H_LOG_INFO	3
#define PKCS11H_LOG_WARN	2
#define PKCS11H_LOG_ERROR	1
#define PKCS11H_LOG_QUITE	0

#define PKCS11H_PIN_CACHE_INFINITE	-1

#define PKCS11H_SIGNMODE_MASK_SIGN	(1<<0)
#define PKCS11H_SIGNMODE_MASK_RECOVER	(1<<1)

#define PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT	(1<<0)
#define PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT	(1<<1)
#define PKCS11H_PROMPT_MASK_ALLOW_ALL ( \
		PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT | \
		PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT \
	)

#define PKCS11H_SLOTEVENT_METHOD_AUTO		0
#define PKCS11H_SLOTEVENT_METHOD_TRIGGER	1
#define PKCS11H_SLOTEVENT_METHOD_POLL		2

#define PKCS11H_ENUM_METHOD_CACHE		0
#define PKCS11H_ENUM_METHOD_CACHE_EXIST		1
#define PKCS11H_ENUM_METHOD_RELOAD		2

typedef void (*pkcs11h_output_print_t)(
	IN void * const global_data,
	IN const char * const format,
	IN ...
)
#if __GNUC__ > 2
    __attribute__ ((format (printf, 2, 3)))
#endif
 ;

struct pkcs11h_token_id_s;
typedef struct pkcs11h_token_id_s *pkcs11h_token_id_t;

#if defined(ENABLE_PKCS11H_CERTIFICATE)

struct pkcs11h_certificate_id_s;
struct pkcs11h_certificate_s;
typedef struct pkcs11h_certificate_id_s *pkcs11h_certificate_id_t;
typedef struct pkcs11h_certificate_s *pkcs11h_certificate_t;

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_ENUM)

struct pkcs11h_token_id_list_s;
typedef struct pkcs11h_token_id_list_s *pkcs11h_token_id_list_t;

#if defined(ENABLE_PKCS11H_DATA)

struct pkcs11h_data_id_list_s;
typedef struct pkcs11h_data_id_list_s *pkcs11h_data_id_list_t;

#endif				/* ENABLE_PKCS11H_DATA */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

struct pkcs11h_certificate_id_list_s;
typedef struct pkcs11h_certificate_id_list_s *pkcs11h_certificate_id_list_t;

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_ENUM */

typedef void (*pkcs11h_hook_log_t)(
	IN void * const global_data,
	IN const unsigned flags,
	IN const char * const format,
	IN va_list args
);

typedef void (*pkcs11h_hook_slotevent_t)(
	IN void * const global_data
);

typedef PKCS11H_BOOL (*pkcs11h_hook_token_prompt_t)(
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry
);

typedef PKCS11H_BOOL (*pkcs11h_hook_pin_prompt_t)(
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const pin,
	IN const size_t pin_max
);

struct pkcs11h_token_id_s {
	char display[1024];
	char manufacturerID[sizeof (((CK_TOKEN_INFO *)NULL)->manufacturerID)+1];
	char model[sizeof (((CK_TOKEN_INFO *)NULL)->model)+1];
	char serialNumber[sizeof (((CK_TOKEN_INFO *)NULL)->serialNumber)+1];
	char label[sizeof (((CK_TOKEN_INFO *)NULL)->label)+1];
};

#if defined(ENABLE_PKCS11H_CERTIFICATE)

struct pkcs11h_certificate_id_s {
	pkcs11h_token_id_t token_id;

	char displayName[1024];
	CK_BYTE_PTR attrCKA_ID;
	size_t attrCKA_ID_size;

	unsigned char *certificate_blob;
	size_t certificate_blob_size;
};

#endif

#if defined(ENABLE_PKCS11H_ENUM)

struct pkcs11h_token_id_list_s {
	pkcs11h_token_id_list_t next;
	pkcs11h_token_id_t token_id;
};

#if defined(ENABLE_PKCS11H_DATA)

struct pkcs11h_data_id_list_s {
	pkcs11h_data_id_list_t next;

	char *application;
	char *label;
};

#endif				/* ENABLE_PKCS11H_DATA */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

struct pkcs11h_certificate_id_list_s {
	pkcs11h_certificate_id_list_t next;
	pkcs11h_certificate_id_t certificate_id;
};

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_OPENSSL)

typedef void (*pkcs11h_hook_openssl_cleanup_t) (
	IN const pkcs11h_certificate_t certificate
);

struct pkcs11h_openssl_session_s;
typedef struct pkcs11h_openssl_session_s *pkcs11h_openssl_session_t;

#endif				/* ENABLE_PKCS11H_OPENSSL */

/*
 * pkcs11h_getMessage - Get message by return value.
 *
 * Parameters:
 * 	rv		- Return value.
 */
const char *
pkcs11h_getMessage (
	IN const CK_RV rv
);

/*
 * pkcs11h_initialize - Inititalize helper interface.
 *
 * Must be called once, from main thread.
 * Defaults:
 * 	Protected authentication enabled.
 * 	PIN cached is infinite.
 */
CK_RV
pkcs11h_initialize ();

/*
 * pkcs11h_terminate - Terminate helper interface.
 *
 * Must be called once, from main thread, after all
 * related resources freed.
 */
CK_RV
pkcs11h_terminate ();

/*
 * pkcs11h_setLogLevel - Set current log level of the helper.
 *
 * Parameters:
 * 	flags		- current log level.
 *
 * The log level can be set to maximum, but setting it to lower
 * level will improve performance.
 */
void
pkcs11h_setLogLevel (
	IN const unsigned flags
);

/*
 * pkcs11h_getLogLevel - Get current log level.
 */
unsigned
pkcs11h_getLogLevel ();

/*
 * pkcs11h_setLogHook - Set a log callback.
 *
 * Parameters:
 * 	hook		- Callback.
 * 	pData		- Data to send to callback.
 */
CK_RV
pkcs11h_setLogHook (
	IN const pkcs11h_hook_log_t hook,
	IN void * const global_data
);

/*
 * pkcs11h_setSlotEventHook - Set a slot event callback.
 *
 * Parameters:
 * 	hook		- Callback.
 * 	pData		- Data to send to callback.
 *
 * Calling this function initialize slot event notifications, these
 * notifications can be started, but never terminate due to PKCS#11 limitation.
 *
 * In order to use slot events you must have threading enabled.
 */
CK_RV
pkcs11h_setSlotEventHook (
	IN const pkcs11h_hook_slotevent_t hook,
	IN void * const global_data
);

/*
 * pkcs11h_setTokenPromptHook - Set a token prompt callback.
 *
 * Parameters:
 * 	hook		- Callback.
 * 	pData		- Data to send to callback.
 */
CK_RV
pkcs11h_setTokenPromptHook (
	IN const pkcs11h_hook_token_prompt_t hook,
	IN void * const global_data
);

/*
 * pkcs11h_setPINPromptHook - Set a pin prompt callback.
 *
 * Parameters:
 * 	hook		- Callback.
 * 	pData		- Data to send to callback.
 */
CK_RV
pkcs11h_setPINPromptHook (
	IN const pkcs11h_hook_pin_prompt_t hook,
	IN void * const global_data
);

/*
 * pkcs11h_setProtectedAuthentication - Set global protected authentication mode.
 *
 * Parameters:
 * 	allow_protected_auth	- Allow protected authentication if enabled by token.
 */
CK_RV
pkcs11h_setProtectedAuthentication (
	IN const PKCS11H_BOOL allow_protected_auth
);

/*
 * pkcs11h_setPINCachePeriod - Set global PIN cache timeout.
 *
 * Parameters:
 * 	pin_cache_period	- Cache period in seconds, or PKCS11H_PIN_CACHE_INFINITE.
 */
CK_RV
pkcs11h_setPINCachePeriod (
	IN const int pin_cache_period
);

/*
 * pkcs11h_setMaxLoginRetries - Set global login retries attempts.
 *
 * Parameters:
 * 	max_retries		- Login retries handled by the helper.
 */
CK_RV
pkcs11h_setMaxLoginRetries (
	IN const unsigned max_retries
);

/*
 * pkcs11h_addProvider - Add a PKCS#11 provider.
 *
 * Parameters:
 * 	reference		- Reference name for this provider.
 * 	provider		- Provider library location.
 * 	allow_protected_auth	- Allow this provider to use protected authentication.
 * 	mask_sign_mode		- Provider signmode override.
 * 	slot_event_method	- Provider slot event method.
 * 	slot_poll_interval	- Slot event poll interval (If in polling mode).
 * 	cert_is_private		- Provider's certificate access should be done after login.
 *
 * This function must be called from the main thread.
 *
 * The global allow_protected_auth must be enabled in order to allow provider specific.
 * The mask_sign_mode can be 0 in order to automatically detect key sign mode.
 */
CK_RV
pkcs11h_addProvider (
	IN const char * const reference,
	IN const char * const provider_location,
	IN const PKCS11H_BOOL allow_protected_auth,
	IN const unsigned mask_sign_mode,
	IN const int slot_event_method,
	IN const int slot_poll_interval,
	IN const PKCS11H_BOOL cert_is_private
);

/*
 * pkcs11h_delProvider - Delete a PKCS#11 provider.
 *
 * Parameters:
 * 	reference		- Reference name for this provider.
 *
 * This function must be called from the main thread.
 */
CK_RV
pkcs11h_removeProvider (
	IN const char * const reference
);

/*
 * pkcs11h_forkFixup - Handle special case of Unix fork()
 *
 * This function should be called after fork is called. This is required
 * due to a limitation of the PKCS#11 standard.
 *
 * This function must be called from the main thread.
 *
 * The helper library handles fork automatically if ENABLE_PKCS11H_THREADING
 * is set on configuration file, by use of pthread_atfork.
 */
CK_RV
pkcs11h_forkFixup ();

/*
 * pkcs11h_plugAndPlay - Handle slot rescan.
 *
 * This function must be called from the main thread.
 *
 * PKCS#11 providers do not allow plug&play, plug&play can be established by
 * finalizing all providers and initializing them again.
 *
 * The cost of this process is invalidating all sessions, and require user
 * login at the next access.
 */
CK_RV
pkcs11h_plugAndPlay ();

/*
 * pkcs11h_token_freeTokenId - Free token_id object.
 *
 * Parameters:
 * 	token_id		- token_id.
 */
CK_RV
pkcs11h_token_freeTokenId (
	IN pkcs11h_token_id_t token_id
);

/*
 * pkcs11h_duplicateTokenId - Duplicate token_id object.
 *
 * Parameters:
 * 	to			- target.
 * 	from			- source.
 */
CK_RV
pkcs11h_token_duplicateTokenId (
	OUT pkcs11h_token_id_t * const to,
	IN const pkcs11h_token_id_t from
);

/*
 * pkcs11h_sameTokenId - Returns TRUE if same token id
 *
 * Parameters:
 * 	a			- a.
 * 	b			- b.
 */
PKCS11H_BOOL
pkcs11h_token_sameTokenId (
	IN const pkcs11h_token_id_t a,
	IN const pkcs11h_token_id_t b
);

/*
 * pkcs11h_token_login - Force login, avoid hooks.
 *
 * Parameters:
 * 	token_id		- Token to login into.
 * 	readonly		- Should session be readonly.
 * 	pin			- PIN to login, NULL for protected authentication
 */
CK_RV
pkcs11h_token_login (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL readonly,
	IN const char * const pin
);

#if defined(ENABLE_PKCS11H_SERIALIZATION)

/*
 * pkcs11h_serializeTokenId - Serialize token_id into string.
 *
 * Parameters:
 * 	sz			- Output string.
 * 	max			- Maximum string size.
 * 	token_id		- id to serialize
 *
 * sz may be NULL to get size
 */
CK_RV
pkcs11h_token_serializeTokenId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_token_id_t token_id
);

/*
 * pkcs11h_deserializeTokenId - Deserialize token_id from string.
 *
 * Parameters:
 * 	p_token_id		- id.
 * 	sz			- Input string
 */
CK_RV
pkcs11h_token_deserializeTokenId (
	OUT pkcs11h_token_id_t *p_token_id,
	IN const char * const sz
);

#endif				/* ENABLE_PKCS11H_SERIALIZATION */

#if defined(ENABLE_PKCS11H_TOKEN)

/*
 * pkcs11h_token_ensureAccess - Ensure token is accessible.
 *
 * Parameters:
 * 	token_id		- Token id object.
 * 	user_data		- Optional user data, to be passed to hooks.
 * 	mask_prompt		- Allow prompt.
 */
CK_RV
pkcs11h_token_ensureAccess (
	IN const pkcs11h_token_id_t token_id,
	IN void * const user_data,
	IN const unsigned mask_prompt
);

#endif				/* ENABLE_PKCS11H_TOKEN */

#if defined(ENABLE_PKCS11H_DATA)

/*
 * pkcs11h_data_get - get data object.
 *
 * Parameters:
 * 	token_id		- Token id object.
 * 	is_public		- Object is public.
 * 	application		- Object application attribute.
 * 	label			- Object label attribute.
 * 	user_data		- Optional user data, to be passed to hooks.
 * 	mask_prompt		- Allow prompt.
 * 	blob			- blob, set to NULL to get size.
 * 	p_blob_size		- blob size.
 */
CK_RV
pkcs11h_data_get (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL is_public,
	IN const char * const application,
	IN const char * const label,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT char * const blob,
	IN OUT size_t * const p_blob_size
);

/*
 * pkcs11h_data_put - put data object.
 *
 * Parameters:
 * 	token_id		- Token id object.
 * 	is_public		- Object is public.
 * 	application		- Object application attribute.
 * 	label			- Object label attribute.
 * 	user_data		- Optional user data, to be passed to hooks.
 * 	mask_prompt		- Allow prompt.
 * 	blob			- blob.
 * 	blob_size		- blob size.
 */
CK_RV
pkcs11h_data_put (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL is_public,
	IN const char * const application,
	IN const char * const label,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT char * const blob,
	IN const size_t blob_size
);

/*
 * pkcs11h_data_del - delete data object.
 *
 * Parameters:
 * 	token_id		- Token id object.
 * 	is_public		- Object is public.
 * 	application		- Object application attribute.
 * 	label			- Object label attribute.
 * 	user_data		- Optional user data, to be passed to hooks.
 * 	mask_prompt		- Allow prompt.
 */
CK_RV
pkcs11h_data_del (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL is_public,
	IN const char * const application,
	IN const char * const label,
	IN void * const user_data,
	IN const unsigned mask_prompt
);

#endif				/* ENABLE_PKCS11H_DATA */

#if defined(ENABLE_PKCS11H_CERTIFICATE)
/*======================================================================*
 * CERTIFICATE INTERFACE
 *======================================================================*/

/*
 * pkcs11h_certificate_freeCertificateId - Free certificate_id object.
 */
CK_RV
pkcs11h_certificate_freeCertificateId (
	IN pkcs11h_certificate_id_t certificate_id
);

/*
 * pkcs11h_duplicateCertificateId - Duplicate certificate_id object.
 */
CK_RV
pkcs11h_certificate_duplicateCertificateId (
	OUT pkcs11h_certificate_id_t * const to,
	IN const pkcs11h_certificate_id_t from
);

/*
 * pkcs11h_certificate_freeCertificate - Free certificate object.
 *
 * Parameters:
 * 	certificate		- Certificate ojbect.
 */
CK_RV
pkcs11h_certificate_freeCertificate (
	IN pkcs11h_certificate_t certificate
);

/*
 * pkcs11h_certificate_create - Create a certificate object out of certificate_id.
 *
 * Parameters:
 *	certificate_id		- Certificate id object to be based on.
 * 	user_data		- Optional user data, to be passed to hooks.
 * 	mask_prompt		- Allow prompt.
 *	pin_cache_period	- Session specific cache period.
 *	p_certificate		- Receives certificate object.
 *
 * The certificate id object may not specify the full certificate.
 * The certificate object must be freed by caller.
 */	
CK_RV
pkcs11h_certificate_create (
	IN const pkcs11h_certificate_id_t certificate_id,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	IN const int pin_cache_period,
	OUT pkcs11h_certificate_t * const p_certificate
);

/*
 * pkcs11h_certificate_getPromptMask - Extract user data out of certificate.
 *
 * Parameters:
 * 	certificate		- Certificate ojbect.
 *
 * Returns:
 * 	mask_prompt		- Allow prompt.
 *
 */
unsigned
pkcs11h_certificate_getPromptMask (
	IN const pkcs11h_certificate_t certificate
);

/*
 * pkcs11h_certificate_setPromptMask - Extract user data out of certificate.
 *
 * Parameters:
 * 	certificate		- Certificate ojbect.
 * 	mask_prompt		- Allow prompt.
 */
void
pkcs11h_certificate_setPromptMask (
	IN const pkcs11h_certificate_t certificate,
	IN const unsigned ask_prompt
);

/*
 * pkcs11h_certificate_getUserData - Extract user data out of certificate.
 *
 * Parameters:
 * 	certificate		- Certificate ojbect.
 *
 * Returns:
 * 	user_data		- Optional user data, to be passed to hooks.
 */
void *
pkcs11h_certificate_getUserData (
	IN const pkcs11h_certificate_t certificate
);

/*
 * pkcs11h_certificate_setUserData - Extract user data out of certificate.
 *
 * Parameters:
 * 	certificate		- Certificate ojbect.
 * 	user_data		- Optional user data, to be passed to hooks.
 */
void
pkcs11h_certificate_setUserData (
	IN const pkcs11h_certificate_t certificate,
	IN void * const user_data
);

/*
 * pkcs11h_certificate_getCertificateId - Get certifiate id object out of a certifiate
 *
 * Parameters:
 * 	certificate		- Certificate object.
 * 	p_certificate_id	- Certificate id object pointer.
 *
 * The certificate id must be freed by caller.
 */
CK_RV
pkcs11h_certificate_getCertificateId (
	IN const pkcs11h_certificate_t certificate,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
);

/*
 * pkcs11h_certificate_getCertificateBlob - Get the certificate blob out of the certificate object.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 * 	certificate_blob	- Buffer.
 * 	certificate_blob_size	- Buffer size.
 *
 * Buffer may be NULL in order to get size.
 */
CK_RV
pkcs11h_certificate_getCertificateBlob (
	IN const pkcs11h_certificate_t certificate,
	OUT unsigned char * const certificate_blob,
	IN OUT size_t * const p_certificate_blob_size
);

#if defined(ENABLE_PKCS11H_SERIALIZATION)

/*
 * pkcs11h_certificate_serializeCertificateId - Serialize certificate_id into a string
 *
 * Parametrs:
 * 	sz			- Output string.
 *	max			- Max buffer size.
 *	certificate_id		- id to serialize
 *
 * sz may be NULL in order to get size.
 */
CK_RV
pkcs11h_certificate_serializeCertificateId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_certificate_id_t certificate_id
);

/*
 * pkcs11h_certificate_deserializeCertificateId - Deserialize certificate_id out of string.
 *
 * Parameters:
 * 	p_certificate_id	- id.
 * 	sz			- Inut string
 */
CK_RV
pkcs11h_certificate_deserializeCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id,
	IN const char * const sz
);

#endif				/* ENABLE_PKCS11H_SERIALIZATION */

/*
 * pkcs11h_certificate_ensureCertificateAccess - Ensure certificate is accessible.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 */
CK_RV
pkcs11h_certificate_ensureCertificateAccess (
	IN const pkcs11h_certificate_t certificate
);

/*
 * pkcs11h_certificate_ensureKeyAccess - Ensure key is accessible.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 */
CK_RV
pkcs11h_certificate_ensureKeyAccess (
	IN const pkcs11h_certificate_t certificate
);

/*
 * pkcs11h_certificate_lockSession - Lock session for threded environment
 *
 * Parameters:
 * 	certificate		- Certificate object.
 *
 * This must be called on threaded environment, so both calls to _sign and
 * _signRecover and _decrypt will be from the same source.
 * Failing to lock session, will result with CKR_OPERATION_ACTIVE if
 * provider is good, or unexpected behaviour for others.
 *
 * It is save to call this also in none threaded environment, it will do nothing.
 * Call this also if you are doing one stage operation, since locking is not
 * done by method.
 */
CK_RV
pkcs11h_certificate_lockSession (
	IN const pkcs11h_certificate_t certificate
);

/*
 * pkcs11h_certificate_releaseSession - Releases session lock.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 *
 * See pkcs11h_certificate_lockSession.
 */
CK_RV
pkcs11h_certificate_releaseSession (
	IN const pkcs11h_certificate_t certificate
);

/*
 * pkcs11h_certificate_sign - Sign data.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 * 	mech_type		- PKCS#11 mechanism.
 *	source			- Buffer to sign.
 *	source_size		- Buffer size.
 *	target			- Target buffer, can be NULL to get size.
 *	target_size		- Target buffer size.
 */
CK_RV
pkcs11h_certificate_sign (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
);

/*
 * pkcs11h_certificate_signRecover - Sign data.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 * 	mech_type		- PKCS#11 mechanism.
 *	source			- Buffer to sign.
 *	source_size		- Buffer size.
 *	target			- Target buffer, can be NULL to get size.
 *	target_size		- Target buffer size.
 */
CK_RV
pkcs11h_certificate_signRecover (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
);

/*
 * pkcs11h_certificate_signAny - Sign data mechanism determined by key attributes.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 * 	mech_type		- PKCS#11 mechanism.
 *	source			- Buffer to sign.
 *	source_size		- Buffer size.
 *	target			- Target buffer, can be NULL to get size.
 *	target_size		- Target buffer size.
 */
CK_RV
pkcs11h_certificate_signAny (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
);

/*
 * pkcs11h_certificate_decrypt - Decrypt data.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 * 	mech_type		- PKCS#11 mechanism.
 *	source			- Buffer to sign.
 *	source_size		- Buffer size.
 *	target			- Target buffer, can be NULL to get size.
 *	target_size		- Target buffer size.
 */
CK_RV
pkcs11h_certificate_decrypt (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
);

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_LOCATE)
/*======================================================================*
 * LOCATE INTERFACE
 *======================================================================*/

#if defined(ENABLE_PKCS11H_TOKEN) || defined(ENABLE_PKCS11H_CERTIFICATE)

/*
 * pkcs11h_locate_token - Locate token based on atributes.
 *
 * Parameters:
 * 	slot_type		- How to locate slot.
 * 	slot			- Slot name.
 * 	user_data		- Optional user data, to be passed to hooks.
 * 	mask_prompt		- Allow prompt.
 * 	p_token_id		- Token object.
 *
 * Slot:
 * 	id	- Slot number.
 * 	name	- Slot name.
 * 	label	- Available token label.
 *
 * Caller must free token id.
 */
CK_RV
pkcs11h_locate_token (
	IN const char * const slot_type,
	IN const char * const slot,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_token_id_t * const p_token_id
);

#endif				/* ENABLE_PKCS11H_TOKEN || ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

/*
 * pkcs11h_locate_certificate - Locate certificate based on atributes.
 *
 * Parameters:
 * 	slot_type		- How to locate slot.
 * 	slot			- Slot name.
 * 	id_type			- How to locate object.
 * 	id			- Object name.
 * 	user_data		- Optional user data, to be passed to hooks.
 * 	mask_prompt		- Allow prompt.
 * 	p_certificate_id	- Certificate object.
 *
 * Slot:
 *	Same as pkcs11h_locate_token.
 *
 * Object:
 * 	id	- Certificate CKA_ID (hex string) (Fastest).
 * 	label	- Certificate CKA_LABEL (string).
 * 	subject	- Certificate subject (OpenSSL or gnutls DN).
 *
 * Caller must free certificate id.
 */
CK_RV
pkcs11h_locate_certificate (
	IN const char * const slot_type,
	IN const char * const slot,
	IN const char * const id_type,
	IN const char * const id,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
);

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_LOCATE */

#if defined(ENABLE_PKCS11H_ENUM)
/*======================================================================*
 * ENUM INTERFACE
 *======================================================================*/

#if defined(ENABLE_PKCS11H_TOKEN)

/*
 * pkcs11h_freeTokenIdList - Free certificate_id list.
 */
CK_RV
pkcs11h_token_freeTokenIdList (
	IN const pkcs11h_token_id_list_t token_id_list
);

/*
 * pkcs11h_token_enumTokenIds - Enumerate available tokens
 *
 * Parameters:
 * 	p_token_id_list		- A list of token ids.
 * 	
 * Caller must free the list.
 */
CK_RV
pkcs11h_token_enumTokenIds (
	IN const int method,
	OUT pkcs11h_token_id_list_t * const p_token_id_list
);

#endif				/* ENABLE_PKCS11H_TOKEN */

#if defined(ENABLE_PKCS11H_DATA)

/*
 * pkcs11h_data_freeDataIdList - free data object list..
 *
 * Parameters:
 * 	data_id_list		- list to free.
 */
CK_RV
pkcs11h_data_freeDataIdList (
	IN const pkcs11h_data_id_list_t data_id_list
);

/*
 * pkcs11h_data_enumDataObjects - get list of data objects.
 *
 * Parameters:
 * 	token_id		- token id.
 * 	is_public		- Get a list of public objects.
 * 	user_data		- Optional user data, to be passed to hooks.
 * 	mask_prompt		- Allow prompt.
 * 	p_data_id_list		- List location.
 */
CK_RV
pkcs11h_data_enumDataObjects (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL is_public,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_data_id_list_t * const p_data_id_list
);

#endif				/* ENABLE_PKCS11H_DATA */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

/*
 * pkcs11h_certificate_freeCertificateIdList - Free certificate_id list.
 */
CK_RV
pkcs11h_certificate_freeCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_list
);

/*
 * pkcs11h_certificate_enumTokenCertificateIds - Enumerate available certificates on specific token
 *
 * Parameters:
 * 	token_id		- Token id to enum.
 * 	method			- How to fetch certificates.
 * 	user_data		- Some user specific data.
 * 	mask_prompt		- Allow prompt.
 * 	p_cert_id_issuers_list	- Receives issues list, can be NULL.
 * 	p_cert_id_end_list	- Receives end certificates list.
 *
 * This function will likely take long time.
 *
 * Method can be one of the following:
 *	PKCS11H_ENUM_METHOD_CACHE
 *		Return available certificates, even if token was once detected and
 *		was removed.
 *	PKCS11H_ENUM_METHOD_CACHE_EXIST
 *		Return available certificates for available tokens only, don't
 *		read the contents of the token if already read, even if this token
 *		removed and inserted.
 *	PKCS11H_ENUM_METHOD_RELOAD
 *		Clear all caches and then enum.
 *
 * Caller must free the lists.
 */
CK_RV
pkcs11h_certificate_enumTokenCertificateIds (
	IN const pkcs11h_token_id_t token_id,
	IN const int method,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
);

/*
 * pkcs11h_enum_getCertificateIds - Enumerate available certificates.
 *
 * Parameters:
 * 	method			- How to fetch certificates.
 * 	user_data		- Some user specific data.
 * 	mask_prompt		- Allow prompt.
 * 	p_cert_id_issuers_list	- Receives issues list, can be NULL.
 * 	p_cert_id_end_list	- Receives end certificates list.
 *
 * This function will likely take long time.
 *
 * Method can be one of the following:
 *	PKCS11H_ENUM_METHOD_CACHE
 *		Return available certificates, even if token was once detected and
 *		was removed.
 *	PKCS11H_ENUM_METHOD_CACHE_EXIST
 *		Return available certificates for available tokens only, don't
 *		read the contents of the token if already read, even if this token
 *		removed and inserted.
 *	PKCS11H_ENUM_METHOD_RELOAD
 *		Clear all caches and then enum.
 *
 * Caller must free lists.
 */
CK_RV
pkcs11h_certificate_enumCertificateIds (
	IN const int method,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
);

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_ENUM */

#if defined(ENABLE_PKCS11H_OPENSSL)
/*======================================================================*
 * OPENSSL INTERFACE
 *======================================================================*/

/*
 * pkcs11h_openssl_createSession - Create OpenSSL session based on a certificate object.
 *
 * Parameters:
 * 	certificate		- Certificate object.
 *
 * The certificate object will be freed by the OpenSSL interface on session end.
 */
pkcs11h_openssl_session_t
pkcs11h_openssl_createSession (
	IN const pkcs11h_certificate_t certificate
);

/*
 * pkcs11h_openssl_getCleanupHook - Sets cleanup hook
 *
 * Parameters:
 * 	openssl_session		- session.
 */
pkcs11h_hook_openssl_cleanup_t
pkcs11h_openssl_getCleanupHook (
	IN const pkcs11h_openssl_session_t openssl_session
);

/*
 * pkcs11h_openssl_setCleanupHook - Sets cleanup hook
 *
 * Parameters:
 * 	openssl_session		- session.
 * 	cleanup			- hook.
 */
void
pkcs11h_openssl_setCleanupHook (
	IN const pkcs11h_openssl_session_t openssl_session,
	IN const pkcs11h_hook_openssl_cleanup_t cleanup
);

/*
 * pkcs11h_openssl_freeSession - Free OpenSSL session.
 *
 * Parameters:
 * 	openssl_session		- Session to free.
 *
 * The openssl_session object has a reference count just like other OpenSSL objects.
 */
void
pkcs11h_openssl_freeSession (
	IN const pkcs11h_openssl_session_t openssl_session
);

/*
 * pkcs11h_openssl_getRSA - Returns an RSA object out of the openssl_session object.
 *
 * Parameters:
 * 	openssl_session		- Session.
 */
RSA *
pkcs11h_openssl_getRSA (
	IN const pkcs11h_openssl_session_t openssl_session
);

/*
 * pkcs11h_openssl_getX509 - Returns an X509 object out of the openssl_session object.
 *
 * Parameters:
 * 	openssl_session		- Session.
 */
X509 *
pkcs11h_openssl_getX509 (
	IN const pkcs11h_openssl_session_t openssl_session
);

#endif				/* ENABLE_PKCS11H_OPENSSL */

#if defined(ENABLE_PKCS11H_STANDALONE)
/*======================================================================*
 * STANDALONE INTERFACE
 *======================================================================*/

void
pkcs11h_standalone_dump_slots (
	IN const pkcs11h_output_print_t my_output,
	IN void * const global_data,
	IN const char * const provider
);

void
pkcs11h_standalone_dump_objects (
	IN const pkcs11h_output_print_t my_output,
	IN void * const global_data,
	IN const char * const provider,
	IN const char * const slot,
	IN const char * const pin
);

#endif				/* ENABLE_PKCS11H_STANDALONE */

#ifdef __cplusplus
}
#endif

#endif				/* __PKCS11H_HELPER_H */
