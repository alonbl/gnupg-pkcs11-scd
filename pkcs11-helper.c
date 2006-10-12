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

/*
 * Changelog
 *
 * 2006.09.24
 * 	- (alonbl) Fix invalid certificate max size handling (Zeljko Vrba).
 * 	- (alonbl) Added object serialization.
 * 	- (alonbl) Added user data to hooks.
 * 	- (alonbl) Added a force login method.
 * 	- (alonbl) Added support for gnutls in addition to openssl.
 * 	- (alonbl) Fixup threading lock issues.
 * 	- (alonbl) Added support for duplicate serial tokens, based on label.
 * 	- (alonbl) Added workaround for OpenSC cards, OpenSC bug#108, thanks to Kaupo Arulo.
 * 	- (alonbl) Added a methods to lock session between two sign/decrypt operations.
 * 	- (alonbl) Modified openssl interface.
 * 	- (alonbl) Release 01.02.
 *
 * 2006.06.26
 * 	- (alonbl) Fix handling mutiple providers.
 * 	- (alonbl) Release 01.01.
 *
 * 2006.05.14
 * 	- (alonbl) First stable release.
 * 	- (alonbl) Release 01.00.
 *
 */

#include "pkcs11-helper-config.h"

#if defined(ENABLE_PKCS11H_HELPER)

#include "pkcs11-helper.h"

/*===========================================
 * Constants
 */

#if defined(USE_PKCS11H_OPENSSL)

#if OPENSSL_VERSION_NUMBER < 0x00907000L && defined(CRYPTO_LOCK_ENGINE)
# define RSA_get_default_method RSA_get_default_openssl_method
#else
# ifdef HAVE_ENGINE_GET_DEFAULT_RSA
#  include <openssl/engine.h>
#  if OPENSSL_VERSION_NUMBER < 0x0090704fL
#   define BROKEN_OPENSSL_ENGINE
#  endif
# endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x00907000L
#if !defined(RSA_PKCS1_PADDING_SIZE)
#define RSA_PKCS1_PADDING_SIZE 11
#endif
#endif

#endif

#define PKCS11H_INVALID_SLOT_ID		((CK_SLOT_ID)-1)
#define PKCS11H_INVALID_SESSION_HANDLE	((CK_SESSION_HANDLE)-1)
#define PKCS11H_INVALID_OBJECT_HANDLE	((CK_OBJECT_HANDLE)-1)

#define PKCS11H_DEFAULT_SLOTEVENT_POLL		5000
#define PKCS11H_DEFAULT_MAX_LOGIN_RETRY		3
#define PKCS11H_DEFAULT_PIN_CACHE_PERIOD	PKCS11H_PIN_CACHE_INFINITE

#define PKCS11H_SERIALIZE_INVALID_CHARS	"\\/\"'%&#@!?$* <>{}[]()`|"

enum _pkcs11h_private_op_e {
	_pkcs11h_private_op_sign=0,
	_pkcs11h_private_op_sign_recover,
	_pkcs11h_private_op_decrypt
};

/*===========================================
 * Macros
 */

#define PKCS11H_MSG_LEVEL_TEST(flags) (((unsigned int)flags) <= s_pkcs11h_loglevel)

#if defined(HAVE_CPP_VARARG_MACRO_ISO) && !defined(__LCLINT__)
# define PKCS11H_LOG(flags, ...) do { if (PKCS11H_MSG_LEVEL_TEST(flags)) _pkcs11h_log((flags), __VA_ARGS__); } while (FALSE)
# ifdef ENABLE_PKCS11H_DEBUG
#  define PKCS11H_DEBUG(flags, ...) do { if (PKCS11H_MSG_LEVEL_TEST(flags)) _pkcs11h_log((flags), __VA_ARGS__); } while (FALSE)
# else
#  define PKCS11H_DEBUG(flags, ...)
# endif
#elif defined(HAVE_CPP_VARARG_MACRO_GCC) && !defined(__LCLINT__)
# define PKCS11H_LOG(flags, args...) do { if (PKCS11H_MSG_LEVEL_TEST(flags)) _pkcs11h_log((flags), args); } while (FALSE)
# ifdef ENABLE_PKCS11H_DEBUG
#  define PKCS11H_DEBUG(flags, args...) do { if (PKCS11H_MSG_LEVEL_TEST(flags)) _pkcs11h_log((flags), args); } while (FALSE)
# else
#  define PKCS11H_DEBUG(flags, args...)
# endif
#else
# define PKCS11H_LOG _pkcs11h_log
# define PKCS11H_DEBUG _pkcs11h_log
#endif

/*===========================================
 * Types
 */

struct pkcs11h_provider_s;
struct pkcs11h_session_s;
struct pkcs11h_data_s;
typedef struct pkcs11h_provider_s *pkcs11h_provider_t;
typedef struct pkcs11h_session_s *pkcs11h_session_t;
typedef struct pkcs11h_data_s *pkcs11h_data_t;

#if defined(USE_PKCS11H_OPENSSL)

#if OPENSSL_VERSION_NUMBER < 0x00908000L
typedef unsigned char *pkcs11_openssl_d2i_t;
#else
typedef const unsigned char *pkcs11_openssl_d2i_t;
#endif

#endif

#if defined(ENABLE_PKCS11H_THREADING)

#define PKCS11H_COND_INFINITE	0xffffffff

#if defined(WIN32)
#define PKCS11H_THREAD_NULL	NULL
typedef HANDLE pkcs11h_cond_t;
typedef HANDLE pkcs11h_mutex_t;
typedef HANDLE pkcs11h_thread_t;
#else
#define PKCS11H_THREAD_NULL	0l
typedef pthread_mutex_t pkcs11h_mutex_t;
typedef pthread_t pkcs11h_thread_t;

typedef struct {
	pthread_cond_t cond;
	pthread_mutex_t mut;
} pkcs11h_cond_t;

typedef struct __pkcs11h_threading_mutex_entry_s {
	struct __pkcs11h_threading_mutex_entry_s *next;
	pkcs11h_mutex_t *p_mutex;
	PKCS11H_BOOL locked;
} *__pkcs11h_threading_mutex_entry_t;
#endif

typedef void * (*pkcs11h_thread_start_t)(void *);

typedef struct {
	pkcs11h_thread_start_t start;
	void *data;
} __pkcs11h_thread_data_t;

#endif				/* ENABLE_PKCS11H_THREADING */

struct pkcs11h_provider_s {
	pkcs11h_provider_t next;

	PKCS11H_BOOL enabled;
	char reference[1024];
	char manufacturerID[sizeof (((CK_TOKEN_INFO *)NULL)->manufacturerID)+1];
	
#if defined(WIN32)
	HANDLE handle;
#else
	void *handle;
#endif

	CK_FUNCTION_LIST_PTR f;
	PKCS11H_BOOL should_finalize;
	PKCS11H_BOOL allow_protected_auth;
	PKCS11H_BOOL cert_is_private;
	unsigned mask_sign_mode;
	int slot_event_method;
	int slot_poll_interval;

#if defined(ENABLE_PKCS11H_SLOTEVENT)
	pkcs11h_thread_t slotevent_thread;
#endif
};

struct pkcs11h_session_s {
	pkcs11h_session_t next;

	int reference_count;
	PKCS11H_BOOL valid;

	pkcs11h_provider_t provider;

	pkcs11h_token_id_t token_id;

	CK_SESSION_HANDLE session_handle;

	PKCS11H_BOOL allow_protected_auth_supported;
	int pin_cache_period;
	time_t pin_expire_time;

#if defined(ENABLE_PKCS11H_ENUM)
#if defined(ENABLE_PKCS11H_CERTIFICATE)
	pkcs11h_certificate_id_list_t cached_certs;
	PKCS11H_BOOL touch;
#endif
#endif

#if defined(ENABLE_PKCS11H_THREADING)
	pkcs11h_mutex_t mutex;
#endif
};

#if defined (ENABLE_PKCS11H_CERTIFICATE)

struct pkcs11h_certificate_s {

	pkcs11h_certificate_id_t id;
	int pin_cache_period;
	PKCS11H_BOOL pin_cache_populated_to_session;

	unsigned mask_sign_mode;

	pkcs11h_session_t session;
	CK_OBJECT_HANDLE key_handle;

	PKCS11H_BOOL operation_active;

#if defined(ENABLE_PKCS11H_THREADING)
	pkcs11h_mutex_t mutex;
#endif

	unsigned mask_prompt;
	void * user_data;
};

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

struct pkcs11h_data_s {
	PKCS11H_BOOL initialized;
	int pin_cache_period;

	pkcs11h_provider_t providers;
	pkcs11h_session_t sessions;

	struct {
		void * log_data;
		void * slotevent_data;
		void * token_prompt_data;
		void * pin_prompt_data;
		pkcs11h_hook_log_t log;
		pkcs11h_hook_slotevent_t slotevent;
		pkcs11h_hook_token_prompt_t token_prompt;
		pkcs11h_hook_pin_prompt_t pin_prompt;
	} hooks;

	PKCS11H_BOOL allow_protected_auth;
	unsigned max_retries;

#if defined(ENABLE_PKCS11H_THREADING)
	struct {
		pkcs11h_mutex_t global;
		pkcs11h_mutex_t session;
		pkcs11h_mutex_t cache;
	} mutexes;
#endif

#if defined(ENABLE_PKCS11H_SLOTEVENT)
	struct {
		PKCS11H_BOOL initialized;
		PKCS11H_BOOL should_terminate;
		PKCS11H_BOOL skip_event;
		pkcs11h_cond_t cond_event;
		pkcs11h_thread_t thread;
	} slotevent;
#endif
};

#if defined(ENABLE_PKCS11H_OPENSSL)
struct pkcs11h_openssl_session_s {
	int reference_count;
	PKCS11H_BOOL initialized;
	X509 *x509;
	RSA_METHOD smart_rsa;
	int (*orig_finish)(RSA *rsa);
	pkcs11h_certificate_t certificate;
	pkcs11h_hook_openssl_cleanup_t cleanup_hook;
};
#endif

/*======================================================================*
 * MEMORY INTERFACE
 *======================================================================*/

static
CK_RV
_pkcs11h_mem_malloc (
	OUT const void * * const p,
	IN const size_t s
);
static
CK_RV
_pkcs11h_mem_free (
	IN const void * * const p
);
static
CK_RV
_pkcs11h_mem_strdup (
	OUT const char * * const dest,
	IN const char * const src
);
static
CK_RV
_pkcs11h_mem_duplicate (
	OUT const void * * const dest,
	OUT size_t * const dest_size,
	IN const void * const src,
	IN const size_t mem_size
);

#if defined(ENABLE_PKCS11H_THREADING)
/*======================================================================*
 * THREADING INTERFACE
 *======================================================================*/

static
void
_pkcs11h_threading_sleep (
	IN const unsigned milli
);
static
CK_RV
_pkcs11h_threading_mutexInit (
	OUT pkcs11h_mutex_t * const mutex
);
static
CK_RV
_pkcs11h_threading_mutexLock (
	IN OUT pkcs11h_mutex_t *const mutex
);
static
CK_RV
_pkcs11h_threading_mutexRelease (
	IN OUT pkcs11h_mutex_t *const mutex
);
static
CK_RV
_pkcs11h_threading_mutexFree (
	IN OUT pkcs11h_mutex_t *const mutex
);
#if !defined(WIN32)
static
void
__pkcs1h_threading_mutexLockAll ();
static
void
__pkcs1h_threading_mutexReleaseAll ();
#endif
static
CK_RV
_pkcs11h_threading_condSignal (
	IN OUT pkcs11h_cond_t *const cond
);
static
CK_RV
_pkcs11h_threading_condInit (
	OUT pkcs11h_cond_t * const cond
);
static
CK_RV
_pkcs11h_threading_condWait (
	IN OUT pkcs11h_cond_t *const cond,
	IN const unsigned milli
);
static
CK_RV
_pkcs11h_threading_condFree (
	IN OUT pkcs11h_cond_t *const cond
);
static
CK_RV
_pkcs11h_threading_threadStart (
	OUT pkcs11h_thread_t * const thread,
	IN pkcs11h_thread_start_t const start,
	IN void * data
);
static
CK_RV
_pkcs11h_threading_threadJoin (
	IN pkcs11h_thread_t * const thread
);
#endif				/* ENABLE_PKCS11H_THREADING */

/*======================================================================*
 * COMMON INTERNAL INTERFACE
 *======================================================================*/

static
void
_pkcs11h_util_fixupFixedString (
	OUT char * const target,			/* MUST BE >= length+1 */
	IN const char * const source,
	IN const size_t length				/* FIXED STRING LENGTH */
);
static
CK_RV
_pkcs11h_util_hexToBinary (
	OUT unsigned char * const target,
	IN const char * const source,
	IN OUT size_t * const p_target_size
);
static
CK_RV
_pkcs11h_util_binaryToHex (
	OUT char * const target,
	IN const size_t target_size,
	IN const unsigned char * const source,
	IN const size_t source_size
);
CK_RV
_pkcs11h_util_escapeString (
	IN OUT char * const target,
	IN const char * const source,
	IN size_t * const max,
	IN const char * const invalid_chars
);
static
CK_RV
_pkcs11h_util_unescapeString (
	IN OUT char * const target,
	IN const char * const source,
	IN size_t * const max
);
static
void
_pkcs11h_log (
	IN const unsigned flags,
	IN const char * const format,
	IN ...
)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)))
#endif
    ;

static
CK_RV
_pkcs11h_session_getSlotList (
	IN const pkcs11h_provider_t provider,
	IN const CK_BBOOL token_present,
	OUT CK_SLOT_ID_PTR * const pSlotList,
	OUT CK_ULONG_PTR pulCount
);
static
CK_RV
_pkcs11h_session_getObjectAttributes (
	IN const pkcs11h_session_t session,
	IN const CK_OBJECT_HANDLE object,
	IN OUT const CK_ATTRIBUTE_PTR attrs,
	IN const unsigned count
);
static
CK_RV
_pkcs11h_session_freeObjectAttributes (
	IN OUT const CK_ATTRIBUTE_PTR attrs,
	IN const unsigned count
);
static
CK_RV
_pkcs11h_session_findObjects (
	IN const pkcs11h_session_t session,
	IN const CK_ATTRIBUTE * const filter,
	IN const CK_ULONG filter_attrs,
	OUT CK_OBJECT_HANDLE **const p_objects,
	OUT CK_ULONG *p_objects_found
);
static
CK_RV
_pkcs11h_token_getTokenId (
	IN const CK_TOKEN_INFO_PTR info,
	OUT pkcs11h_token_id_t * const p_token_id
);
static
CK_RV
_pkcs11h_token_newTokenId (
	OUT pkcs11h_token_id_t * const token_id
);
static
CK_RV
_pkcs11h_session_getSessionByTokenId (
	IN const pkcs11h_token_id_t token_id,
	OUT pkcs11h_session_t * const p_session
);
static
CK_RV
_pkcs11h_session_release (
	IN const pkcs11h_session_t session
);
static
CK_RV
_pkcs11h_session_reset (
	IN const pkcs11h_session_t session,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT CK_SLOT_ID * const p_slot
);
static
CK_RV
_pkcs11h_session_getObjectById (
	IN const pkcs11h_session_t session,
	IN const CK_OBJECT_CLASS class,
	IN const CK_BYTE_PTR id,
	IN const size_t id_size,
	OUT CK_OBJECT_HANDLE * const p_handle
);
static
CK_RV
_pkcs11h_session_validate (
	IN const pkcs11h_session_t session
);
static
CK_RV
_pkcs11h_session_touch (
	IN const pkcs11h_session_t session
);
static
CK_RV
_pkcs11h_session_login (
	IN const pkcs11h_session_t session,
	IN const PKCS11H_BOOL public_only,
	IN const PKCS11H_BOOL readonly,
	IN void * const user_data,
	IN const unsigned mask_prompt
);
static
CK_RV
_pkcs11h_session_logout (
	IN const pkcs11h_session_t session
);

static
void
_pkcs11h_hooks_default_log (
	IN void * const global_data,
	IN const unsigned flags,
	IN const char * const format,
	IN va_list args
);

static
PKCS11H_BOOL
_pkcs11h_hooks_default_token_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry
);

static
PKCS11H_BOOL
_pkcs11h_hooks_default_pin_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const pin,
	IN const size_t pin_max
);

#if !defined(WIN32)
#if defined(ENABLE_PKCS11H_THREADING)
static
void
__pkcs11h_threading_atfork_prepare  ();
static
void
__pkcs11h_threading_atfork_parent ();
static
void
__pkcs11h_threading_atfork_child ();
#endif
static
CK_RV
_pkcs11h_forkFixup ();
#endif

#if defined(ENABLE_PKCS11H_CERTIFICATE)
/*======================================================================*
 * CERTIFICATE INTERFACE
 *======================================================================*/

static
time_t
_pkcs11h_certificate_getExpiration (
	IN const unsigned char * const certificate,
	IN const size_t certificate_size
);
static
PKCS11H_BOOL
_pkcs11h_certificate_isBetterCertificate (
	IN const unsigned char * const current,
	IN const size_t current_size,
	IN const unsigned char * const newone,
	IN const size_t newone_size
);
static
CK_RV
_pkcs11h_certificate_newCertificateId (
	OUT pkcs11h_certificate_id_t * const certificate_id
);
static
CK_RV
_pkcs11h_certificate_getDN (
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const dn,
	IN const size_t dn_size
);
static
CK_RV
_pkcs11h_certificate_loadCertificate (
	IN const pkcs11h_certificate_t certificate
);
static
CK_RV
_pkcs11h_certificate_updateCertificateIdDescription (
	IN OUT pkcs11h_certificate_id_t certificate_id
);
static
CK_RV
_pkcs11h_certificate_getKeyAttributes (
	IN const pkcs11h_certificate_t certificate
);
static
CK_RV
_pkcs11h_certificate_validateSession (
	IN const pkcs11h_certificate_t certificate
);
static
CK_RV
_pkcs11h_certificate_resetSession (
	IN const pkcs11h_certificate_t certificate,
	IN const PKCS11H_BOOL public_only,
	IN const PKCS11H_BOOL session_mutex_locked
);
static
CK_RV
_pkcs11h_certificate_doPrivateOperation (
	IN const pkcs11h_certificate_t certificate,
	IN const enum _pkcs11h_private_op_e op,
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

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotId (
	IN const char * const slot,
	OUT pkcs11h_token_id_t * const p_token_id
);
static
CK_RV
_pkcs11h_locate_getTokenIdBySlotName (
	IN const char * const name,
	OUT pkcs11h_token_id_t * const p_token_id
);
static
CK_RV
_pkcs11h_locate_getTokenIdByLabel (
	IN const char * const label,
	OUT pkcs11h_token_id_t * const p_token_id
);

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_locate_getCertificateIdByLabel (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const label
);
static
CK_RV
_pkcs11h_locate_getCertificateIdBySubject (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const subject
);

#endif				/* ENABLE_PKCS11H_CERTIFICATE */
#endif				/* ENABLE_PKCS11H_LOCATE */

#if defined(ENABLE_PKCS11H_ENUM)
/*======================================================================*
 * ENUM INTERFACE
 *======================================================================*/

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_certificate_enumSessionCertificates (
	IN const pkcs11h_session_t session,
	IN void * const user_data,
	IN const unsigned mask_prompt
);
static
CK_RV
_pkcs11h_certificate_splitCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_all,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
);

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_ENUM */

#if defined(ENABLE_PKCS11H_SLOTEVENT)
/*======================================================================*
 * SLOTEVENT INTERFACE
 *======================================================================*/

static
unsigned long
_pkcs11h_slotevent_checksum (
	IN const unsigned char * const p,
	IN const size_t s
);
static
void *
_pkcs11h_slotevent_provider (
	IN void *p
);
static
void *
_pkcs11h_slotevent_manager (
	IN void *p
);
static
CK_RV
_pkcs11h_slotevent_init ();
static
CK_RV
_pkcs11h_slotevent_notify ();
static
CK_RV
_pkcs11h_slotevent_terminate ();

#endif				/* ENABLE_PKCS11H_SLOTEVENT */

#if defined(ENABLE_PKCS11H_OPENSSL)
/*======================================================================*
 * OPENSSL INTERFACE
 *======================================================================*/

static
int
_pkcs11h_openssl_finish (
	IN OUT RSA *rsa
);
#if OPENSSL_VERSION_NUMBER < 0x00907000L
static
int
_pkcs11h_openssl_dec (
	IN int flen,
	IN unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
);
static
int
_pkcs11h_openssl_sign (
	IN int type,
	IN unsigned char *m,
	IN unsigned int m_len,
	OUT unsigned char *sigret,
	OUT unsigned int *siglen,
	IN OUT RSA *rsa
);
#else
static
int
_pkcs11h_openssl_dec (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
);
static
int
_pkcs11h_openssl_sign (
	IN int type,
	IN const unsigned char *m,
	IN unsigned int m_len,
	OUT unsigned char *sigret,
	OUT unsigned int *siglen,
	IN OUT const RSA *rsa
);
#endif
static
pkcs11h_openssl_session_t
_pkcs11h_openssl_get_openssl_session (
	IN OUT const RSA *rsa
);  
static
pkcs11h_certificate_t
_pkcs11h_openssl_get_pkcs11h_certificate (
	IN OUT const RSA *rsa
);  
#endif				/* ENABLE_PKCS11H_OPENSSL */

/*==========================================
 * Static data
 */

#if defined(ENABLE_PKCS11H_THREADING)
#if !defined(WIN32)
static struct {
	pkcs11h_mutex_t mutex;
	__pkcs11h_threading_mutex_entry_t head;
} __s_pkcs11h_threading_mutex_list = {
	PTHREAD_MUTEX_INITIALIZER,
	NULL
};
#endif
#endif

pkcs11h_data_t s_pkcs11h_data = NULL;
unsigned int s_pkcs11h_loglevel = PKCS11H_LOG_INFO;

/*======================================================================*
 * PUBLIC INTERFACE
 *======================================================================*/

const char *
pkcs11h_getMessage (
	IN const CK_RV rv
) {
	switch (rv) {
		case CKR_OK: return "CKR_OK";
		case CKR_CANCEL: return "CKR_CANCEL";
		case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
		case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
		case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
		case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
		case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
		case CKR_NO_EVENT: return "CKR_NO_EVENT";
		case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
		case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
		case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
		case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
		case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
		case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
		case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
		case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
		case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
		case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
		case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
		case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
		case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
		case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
		case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
		case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
		case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
		case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
		case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
		case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
		case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
		case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
		case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
		case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
		case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
		case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
		case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
		case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
		case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
		case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
		case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
		case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
		case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
		case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
		case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
		case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
		case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
		case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
		case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
		case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
		case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
		case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
		case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
		case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
		case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
		case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
		case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
		case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
		case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
		case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
		case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
		case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
		case CKR_FUNCTION_REJECTED: return "CKR_FUNCTION_REJECTED";
		case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
		default: return "Unknown PKCS#11 error";
	}
}

CK_RV
pkcs11h_initialize () {

#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_RV rv = CKR_OK;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_initialize entry"
	);

	pkcs11h_terminate ();

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_malloc ((void*)&s_pkcs11h_data, sizeof (struct pkcs11h_data_s));
	}

#if defined(USE_PKCS11H_OPENSSL) || defined(ENABLE_PKCS11H_OPENSSL)
	OpenSSL_add_all_digests ();
#endif
#if defined(USE_PKCS11H_GNUTLS)
	if (
		rv == CKR_OK &&
		gnutls_global_init () != GNUTLS_E_SUCCESS
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif

#if defined(ENABLE_PKCS11H_THREADING)
	if (rv == CKR_OK) {
		rv = _pkcs11h_threading_mutexInit (&s_pkcs11h_data->mutexes.global); 
	}
	if (rv == CKR_OK) {
		rv = _pkcs11h_threading_mutexInit (&s_pkcs11h_data->mutexes.session); 
	}
	if (rv == CKR_OK) {
		rv = _pkcs11h_threading_mutexInit (&s_pkcs11h_data->mutexes.cache); 
	}
#if !defined(WIN32)
	if (
		rv == CKR_OK &&
		pthread_atfork (
			__pkcs11h_threading_atfork_prepare,
			__pkcs11h_threading_atfork_parent,
			__pkcs11h_threading_atfork_child
		)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		s_pkcs11h_data->max_retries = PKCS11H_DEFAULT_MAX_LOGIN_RETRY;
		s_pkcs11h_data->allow_protected_auth = TRUE;
		s_pkcs11h_data->pin_cache_period = PKCS11H_DEFAULT_PIN_CACHE_PERIOD;
		s_pkcs11h_data->initialized = TRUE;
	}

	if (rv == CKR_OK) {
		pkcs11h_setLogHook (_pkcs11h_hooks_default_log, NULL);
		pkcs11h_setTokenPromptHook (_pkcs11h_hooks_default_token_prompt, NULL);
		pkcs11h_setPINPromptHook (_pkcs11h_hooks_default_pin_prompt, NULL);
	}
	
#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.global);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_initialize return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_terminate () {

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_terminate entry"
	);

	if (s_pkcs11h_data != NULL) {
		pkcs11h_provider_t current_provider = NULL;

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Removing providers"
		);

		for (
			current_provider = s_pkcs11h_data->providers;
			current_provider != NULL;
			current_provider = current_provider->next
		) {
			pkcs11h_removeProvider (current_provider->reference);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.cache);
		_pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.session);
		_pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global);
#endif

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Releasing sessions"
		);

		while (s_pkcs11h_data->sessions != NULL) {
			pkcs11h_session_t current = s_pkcs11h_data->sessions;
			s_pkcs11h_data->sessions = s_pkcs11h_data->sessions->next;

#if defined(ENABLE_PKCS11H_THREADING)
			_pkcs11h_threading_mutexLock (&current->mutex);
#endif

			current->valid = FALSE;

			if (current->reference_count != 0) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Warning: Found session with references"
				);
			}

			if (current->token_id != NULL) {
				pkcs11h_token_freeTokenId (current->token_id);
				current->token_id = NULL;
			}

#if defined(ENABLE_PKCS11H_ENUM)
#if defined(ENABLE_PKCS11H_CERTIFICATE)
			pkcs11h_certificate_freeCertificateIdList (current->cached_certs);
#endif
#endif

			current->provider = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
			_pkcs11h_threading_mutexFree (&current->mutex);
#endif

			_pkcs11h_mem_free ((void *)&current);
		}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Terminating slotevent"
		);

		_pkcs11h_slotevent_terminate ();
#endif
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Marking as uninitialized"
		);
		
		s_pkcs11h_data->initialized = FALSE;

		while (s_pkcs11h_data->providers != NULL) {
			pkcs11h_provider_t current = s_pkcs11h_data->providers;
			s_pkcs11h_data->providers = s_pkcs11h_data->providers->next;

			_pkcs11h_mem_free ((void *)&current);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexFree (&s_pkcs11h_data->mutexes.cache);
		_pkcs11h_threading_mutexFree (&s_pkcs11h_data->mutexes.global); 
		_pkcs11h_threading_mutexFree (&s_pkcs11h_data->mutexes.session); 
#endif

#if defined(USE_PKCS11H_GNUTLS)
		gnutls_global_deinit ();
#endif

		_pkcs11h_mem_free ((void *)&s_pkcs11h_data);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_terminate return"
	);

	return CKR_OK;
}

void
pkcs11h_setLogLevel (
	IN const unsigned flags
) {
	s_pkcs11h_loglevel = flags;
}

unsigned
pkcs11h_getLogLevel () {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);

	return s_pkcs11h_loglevel;
}

CK_RV
pkcs11h_setLogHook (
	IN const pkcs11h_hook_log_t hook,
	IN void * const global_data
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (hook!=NULL);

	s_pkcs11h_data->hooks.log = hook;
	s_pkcs11h_data->hooks.log_data = global_data;

	return CKR_OK;
}

CK_RV
pkcs11h_setSlotEventHook (
	IN const pkcs11h_hook_slotevent_t hook,
	IN void * const global_data
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (hook!=NULL);

#if defined(ENABLE_PKCS11H_SLOTEVENT)
	s_pkcs11h_data->hooks.slotevent = hook;
	s_pkcs11h_data->hooks.slotevent_data = global_data;

	return _pkcs11h_slotevent_init ();
#else
	(void)global_data;

	return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}

CK_RV
pkcs11h_setPINPromptHook (
	IN const pkcs11h_hook_pin_prompt_t hook,
	IN void * const global_data
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (hook!=NULL);

	s_pkcs11h_data->hooks.pin_prompt = hook;
	s_pkcs11h_data->hooks.pin_prompt_data = global_data;

	return CKR_OK;
}

CK_RV
pkcs11h_setTokenPromptHook (
	IN const pkcs11h_hook_token_prompt_t hook,
	IN void * const global_data
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (hook!=NULL);

	s_pkcs11h_data->hooks.token_prompt = hook;
	s_pkcs11h_data->hooks.token_prompt_data = global_data;

	return CKR_OK;
}

CK_RV
pkcs11h_setPINCachePeriod (
	IN const int pin_cache_period
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);

	s_pkcs11h_data->pin_cache_period = pin_cache_period;

	return CKR_OK;
}

CK_RV
pkcs11h_setMaxLoginRetries (
	IN const unsigned max_retries
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);

	s_pkcs11h_data->max_retries = max_retries;

	return CKR_OK;
}

CK_RV
pkcs11h_setProtectedAuthentication (
	IN const PKCS11H_BOOL allow_protected_auth
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);

	s_pkcs11h_data->allow_protected_auth = allow_protected_auth;

	return CKR_OK;
}

CK_RV
pkcs11h_addProvider (
	IN const char * const reference,
	IN const char * const provider_location,
	IN const PKCS11H_BOOL allow_protected_auth,
	IN const unsigned mask_sign_mode,
	IN const int slot_event_method,
	IN const int slot_poll_interval,
	IN const PKCS11H_BOOL cert_is_private
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
#if defined(WIN32)
	int mypid = 0;
#else
	pid_t mypid = getpid ();
#endif
	pkcs11h_provider_t provider = NULL;
	CK_C_GetFunctionList gfl = NULL;
	CK_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (provider_location!=NULL);
	/*PKCS11H_ASSERT (szSignMode!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_addProvider entry pid=%d, reference='%s', provider_location='%s', allow_protected_auth=%d, mask_sign_mode=%08x, cert_is_private=%d",
		mypid,
		reference,
		provider_location,
		allow_protected_auth ? 1 : 0,
		mask_sign_mode,
		cert_is_private ? 1 : 0
	);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Adding provider '%s'-'%s'",
		reference,
		provider_location
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mem_malloc ((void *)&provider, sizeof (struct pkcs11h_provider_s))) == CKR_OK
	) {
		strncpy (
			provider->reference,
			reference,
			sizeof (provider->reference)-1
		);
		provider->reference[sizeof (provider->reference)-1] = '\x0';
		strncpy (
			provider->manufacturerID,
			(
			 	strlen (provider_location) < sizeof (provider->manufacturerID) ?
				provider_location :
				provider_location+strlen (provider_location)-sizeof (provider->manufacturerID)+1
			),
			sizeof (provider->manufacturerID)-1
		);
		provider->manufacturerID[sizeof (provider->manufacturerID)-1] = '\x0';
		provider->allow_protected_auth = allow_protected_auth;
		provider->mask_sign_mode = mask_sign_mode;
		provider->slot_event_method = slot_event_method;
		provider->slot_poll_interval = slot_poll_interval;
		provider->cert_is_private = cert_is_private;
	}
		
	if (rv == CKR_OK) {
#if defined(WIN32)
		provider->handle = LoadLibraryA (provider_location);
#else
		provider->handle = dlopen (provider_location, RTLD_NOW);
#endif
		if (provider->handle == NULL) {
			rv = CKR_FUNCTION_FAILED;
		}
	}

	if (rv == CKR_OK) {
#if defined(WIN32)
		gfl = (CK_C_GetFunctionList)GetProcAddress (
			provider->handle,
			"C_GetFunctionList"
		);
#else
		/*
		 * Make compiler happy!
		 */
		void *p = dlsym (
			provider->handle,
			"C_GetFunctionList"
		);
		memmove (
			&gfl, 
			&p,
			sizeof (void *)
		);
#endif
		if (gfl == NULL) {
			rv = CKR_FUNCTION_FAILED;
		}
	}

	if (rv == CKR_OK) {
		rv = gfl (&provider->f);
	}

	if (rv == CKR_OK) {
		if ((rv = provider->f->C_Initialize (NULL)) != CKR_OK) {
			if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				rv = CKR_OK;
			}
		}
		else {
			provider->should_finalize = TRUE;
		}
	}

	if (
		rv == CKR_OK &&
		(rv = provider->f->C_GetInfo (&info)) == CKR_OK
	) {
		_pkcs11h_util_fixupFixedString (
			provider->manufacturerID,
			(char *)info.manufacturerID,
			sizeof (info.manufacturerID)
		);
	}

	if (rv == CKR_OK) {
		provider->enabled = TRUE;
	}

	if (provider != NULL) {
		if (s_pkcs11h_data->providers == NULL) {
			s_pkcs11h_data->providers = provider;
		}
		else {
			pkcs11h_provider_t last = NULL;
	
			for (
				last = s_pkcs11h_data->providers;
				last->next != NULL;
				last = last->next
			);
			last->next = provider;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.global);
		mutex_locked = FALSE;
	}
#endif

#if defined(ENABLE_PKCS11H_SLOTEVENT)
	_pkcs11h_slotevent_notify ();
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Provider '%s' added rv=%ld-'%s'",
		reference,
		rv,
		pkcs11h_getMessage (rv)
	);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_addProvider return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_removeProvider (
	IN const char * const reference
) {
#if defined(ENABLE_PKCS11H_THREADING)
	pkcs11h_session_t current_session = NULL;
#endif
	pkcs11h_provider_t provider = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (reference!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_removeProvider entry reference='%s'",
		reference
	);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Removing provider '%s'",
		reference
	);

#if defined(ENABLE_PKCS11H_THREADING)
	_pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.cache);
	_pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.session);
	_pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global);

	for (
		current_session = s_pkcs11h_data->sessions;
		current_session != NULL;
		current_session = current_session->next
	) {
		_pkcs11h_threading_mutexLock (&current_session->mutex);
	}
#endif

	provider = s_pkcs11h_data->providers;
	while (
		rv == CKR_OK &&
		provider != NULL &&
		strcmp (reference, provider->reference)
	) {
		provider = provider->next;
	}

	if (rv == CKR_OK && provider == NULL) {
		rv = CKR_OBJECT_HANDLE_INVALID;
	}

	if (rv == CKR_OK) {
		provider->enabled = FALSE;
		provider->reference[0] = '\0';

		if (provider->should_finalize) {
			provider->f->C_Finalize (NULL);
			provider->should_finalize = FALSE;
		}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
		_pkcs11h_slotevent_notify ();
		
		/*
		 * Wait until manager join this thread
		 * this happens saldom so I can poll
		 */
		while (provider->slotevent_thread != PKCS11H_THREAD_NULL) {
			_pkcs11h_threading_sleep (500);
		}
#endif

		if (provider->f != NULL) {
			provider->f = NULL;
		}

		if (provider->handle != NULL) {
#if defined(WIN32)
			FreeLibrary (provider->handle);
#else
			dlclose (provider->handle);
#endif
			provider->handle = NULL;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	for (
		current_session = s_pkcs11h_data->sessions;
		current_session != NULL;
		current_session = current_session->next
	) {
		_pkcs11h_threading_mutexRelease (&current_session->mutex);
	}

	_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.cache);
	_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.session);
	_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.global);
#endif
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_removeProvider return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_forkFixup () {
#if defined(WIN32)
	return CKR_OK;
#else
#if defined(ENABLE_PKCS11H_THREADING)
	return CKR_OK;
#else
	return _pkcs11h_forkFixup ();
#endif
#endif
}

CK_RV
pkcs11h_plugAndPlay () {
#if defined(WIN32)
	int mypid = 0;
#else
	pid_t mypid = getpid ();
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup entry pid=%d",
		mypid
	);

	if (s_pkcs11h_data != NULL && s_pkcs11h_data->initialized) {
		pkcs11h_provider_t current;
#if defined(ENABLE_PKCS11H_SLOTEVENT)
		PKCS11H_BOOL slot_event_active = FALSE;
#endif

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global);
#endif
		for (
			current = s_pkcs11h_data->providers;
			current != NULL;
			current = current->next
		) {
			if (current->enabled) {
				current->f->C_Finalize (NULL);
			}
		}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
		if (s_pkcs11h_data->slotevent.initialized) {
			slot_event_active = TRUE;
			_pkcs11h_slotevent_terminate ();
		}
#endif

		for (
			current = s_pkcs11h_data->providers;
			current != NULL;
			current = current->next
		) {
			if (current->enabled) {
				current->f->C_Initialize (NULL);
			}
		}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
		if (slot_event_active) {
			_pkcs11h_slotevent_init ();
		}
#endif

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.global);
#endif
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_token_freeTokenId (
	IN pkcs11h_token_id_t token_id
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_freeTokenId entry certificate_id=%p",
		(void *)token_id
	);

	_pkcs11h_mem_free ((void *)&token_id);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_freeTokenId return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_token_duplicateTokenId (
	OUT pkcs11h_token_id_t * const to,
	IN const pkcs11h_token_id_t from
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (to!=NULL);
	PKCS11H_ASSERT (from!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_duplicateTokenId entry to=%p form=%p",
		(void *)to,
		(void *)from
	);

	*to = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)to,
			NULL,
			from,
			sizeof (struct pkcs11h_token_id_s)
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_duplicateTokenId return rv=%ld-'%s', *to=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*to
	);
	
	return rv;
}

PKCS11H_BOOL
pkcs11h_token_sameTokenId (
	IN const pkcs11h_token_id_t a,
	IN const pkcs11h_token_id_t b
) {
	PKCS11H_ASSERT (a!=NULL);
	PKCS11H_ASSERT (b!=NULL);

	return (
		!strcmp (a->manufacturerID, b->manufacturerID) &&
		!strcmp (a->model, b->model) &&
		!strcmp (a->serialNumber, b->serialNumber) &&
		!strcmp (a->label, b->label)
	);
}

#if defined(ENABLE_PKCS11H_SERIALIZATION)

CK_RV
pkcs11h_token_serializeTokenId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_token_id_t token_id
) {
	const char *sources[5];
	CK_RV rv = CKR_OK;
	size_t n;
	int e;

	/*PKCS11H_ASSERT (sz!=NULL); Not required*/
	PKCS11H_ASSERT (max!=NULL);
	PKCS11H_ASSERT (token_id!=NULL);

	{ /* Must be after assert */
		sources[0] = token_id->manufacturerID;
		sources[1] = token_id->model;
		sources[2] = token_id->serialNumber;
		sources[3] = token_id->label;
		sources[4] = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_serializeTokenId entry sz=%p, *max=%u, token_id=%p",
		sz,
		sz != NULL ? *max : 0,
		(void *)token_id
	);

	n = 0;
	for (e=0;rv == CKR_OK && sources[e] != NULL;e++) {
		size_t t;
		rv = _pkcs11h_util_escapeString (NULL, sources[e], &t, PKCS11H_SERIALIZE_INVALID_CHARS);
		n+=t;
	}

	if (sz != NULL) {
		if (*max < n) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			n = 0;
			for (e=0;sources[e] != NULL;e++) {
				size_t t = *max-n;
				_pkcs11h_util_escapeString (sz+n, sources[e], &t, PKCS11H_SERIALIZE_INVALID_CHARS);
				n+=t;
				sz[n-1] = '/';
			}
			sz[n-1] = '\x0';
		}
	}

	*max = n;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_serializeTokenId return rv=%ld-'%s', *max=%u, sz='%s'",
		rv,
		pkcs11h_getMessage (rv),
		*max,
		sz
	);

	return rv;
}

CK_RV
pkcs11h_token_deserializeTokenId (
	OUT pkcs11h_token_id_t *p_token_id,
	IN const char * const sz
) {
#define __PKCS11H_TARGETS_NUMBER 4
	struct {
		char *p;
		size_t s;
	} targets[__PKCS11H_TARGETS_NUMBER];

	pkcs11h_token_id_t token_id = NULL;
	char *p1 = NULL;
	char *_sz = NULL;
	int e;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (p_token_id!=NULL);
	PKCS11H_ASSERT (sz!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_deserializeTokenId entry p_token_id=%p, sz='%s'",
		(void *)p_token_id,
		sz
	);

	*p_token_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_strdup (
			(void *)&_sz,
			sz
		);
	}

	if (rv == CKR_OK) {
		p1 = _sz;
	}

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_token_newTokenId (&token_id)) == CKR_OK
	) {
		targets[0].p = token_id->manufacturerID;
		targets[0].s = sizeof (token_id->manufacturerID);
		targets[1].p = token_id->model;
		targets[1].s = sizeof (token_id->model);
		targets[2].p = token_id->serialNumber;
		targets[2].s = sizeof (token_id->serialNumber);
		targets[3].p = token_id->label;
		targets[3].s = sizeof (token_id->label);
	}

	for (e=0;rv == CKR_OK && e < __PKCS11H_TARGETS_NUMBER;e++) {
		size_t l;
		char *p2 = NULL;

		/*
		 * Don't search for last
		 * separator
		 */
		if (rv == CKR_OK) {
			if (e != __PKCS11H_TARGETS_NUMBER-1) {
				p2 = strchr (p1, '/');
				if (p2 == NULL) {
					rv = CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else {
					*p2 = '\x0';
				}
			}
		}

		if (rv == CKR_OK) {
			_pkcs11h_util_unescapeString (
				NULL,
				p1,
				&l
			);
		}

		if (rv == CKR_OK) {
			if (l > targets[e].s) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			}
		}

		if (rv == CKR_OK) {
			l = targets[e].s;
			_pkcs11h_util_unescapeString (
				targets[e].p,
				p1,
				&l
			);
		}

		if (rv == CKR_OK) {
			p1 = p2+1;
		}
	}

	if (rv == CKR_OK) {
		strncpy (
			token_id->display,
			token_id->label,
			sizeof (token_id->display)
		);
	}

	if (rv == CKR_OK) {
		*p_token_id = token_id;
		token_id = NULL;
	}

	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	if (token_id != NULL) {
		pkcs11h_token_freeTokenId (token_id);
	}

	return rv;
#undef __PKCS11H_TARGETS_NUMBER
}

#endif				/* ENABLE_PKCS11H_SERIALIZATION */

/*======================================================================*
 * MEMORY INTERFACE
 *======================================================================*/

static
CK_RV
_pkcs11h_mem_malloc (
	OUT const void * * const p,
	IN const size_t s
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (p!=NULL);
	PKCS11H_ASSERT (s!=0);

	*p = NULL;

	if (s > 0) {
		if (
			(*p = (void *)PKCS11H_MALLOC (s)) == NULL
		) {
			rv = CKR_HOST_MEMORY;
		}
		else {
			memset ((void *)*p, 0, s);
		}
	}

	return rv;
}

static
CK_RV
_pkcs11h_mem_free (
	IN const void * * const  p
) {
	PKCS11H_ASSERT (p!=NULL);

	PKCS11H_FREE ((void *)*p);
	*p = NULL;

	return CKR_OK;
}

static
CK_RV
_pkcs11h_mem_strdup (
	OUT const char * * const dest,
	IN const char * const src
) {
	return _pkcs11h_mem_duplicate (
		(void *)dest,
		NULL,
		src,
		strlen (src)+1
	);
}

static
CK_RV
_pkcs11h_mem_duplicate (
	OUT const void * * const dest,
	OUT size_t * const p_dest_size,
	IN const void * const src,
	IN const size_t mem_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (dest!=NULL);
	/*PKCS11H_ASSERT (dest_size!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (!(mem_size!=0&&src==NULL));

	*dest = NULL;
	if (p_dest_size != NULL) {
		*p_dest_size = 0;
	}

	if (src != NULL) {
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mem_malloc (dest, mem_size)) == CKR_OK
		) {
			if (p_dest_size != NULL) {
				*p_dest_size = mem_size;
			}
			memmove ((void*)*dest, src, mem_size);
		}
	}

	return rv;
}

#if defined(ENABLE_PKCS11H_THREADING)
/*======================================================================*
 * THREADING INTERFACE
 *======================================================================*/

static
void
_pkcs11h_threading_sleep (
	IN const unsigned milli
) {
#if defined(WIN32)
	Sleep (milli);
#else
	usleep (milli*1000);
#endif
}

static
CK_RV
_pkcs11h_threading_mutexInit (
	OUT pkcs11h_mutex_t * const mutex
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		(*mutex = CreateMutex (NULL, FALSE, NULL)) == NULL
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	{
		__pkcs11h_threading_mutex_entry_t entry = NULL;
		PKCS11H_BOOL mutex_locked = FALSE;

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_threading_mutexLock (&__s_pkcs11h_threading_mutex_list.mutex)) == CKR_OK
		) {
			mutex_locked = TRUE;
		}
		
		if (rv == CKR_OK) {
			rv = _pkcs11h_mem_malloc (
				(void *)&entry,
				sizeof (struct __pkcs11h_threading_mutex_entry_s)
			);
		}

		if (
			rv == CKR_OK &&
			pthread_mutex_init (mutex, NULL)
		) {
			rv = CKR_FUNCTION_FAILED;
		}

		if (rv == CKR_OK) {
			entry->p_mutex = mutex;
			entry->next = __s_pkcs11h_threading_mutex_list.head;
			__s_pkcs11h_threading_mutex_list.head = entry;
			entry = NULL;
		}

		if (entry != NULL) {
			_pkcs11h_mem_free ((void *)&entry);
		}

		if (mutex_locked) {
			_pkcs11h_threading_mutexRelease (&__s_pkcs11h_threading_mutex_list.mutex);
			mutex_locked = FALSE;
		}
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_threading_mutexLock (
	IN OUT pkcs11h_mutex_t *const mutex
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		WaitForSingleObject (*mutex, INFINITE) == WAIT_FAILED
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (
		rv == CKR_OK &&
		pthread_mutex_lock (mutex)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_threading_mutexRelease (
	IN OUT pkcs11h_mutex_t *const mutex
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		!ReleaseMutex (*mutex)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (
		rv == CKR_OK &&
		pthread_mutex_unlock (mutex)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_threading_mutexFree (
	IN OUT pkcs11h_mutex_t *const mutex
) {
#if defined(WIN32)
	if (*mutex != NULL) {
		CloseHandle (*mutex);
		*mutex = NULL;
	}
#else
	{
		__pkcs11h_threading_mutex_entry_t last = NULL;
		__pkcs11h_threading_mutex_entry_t entry = NULL;
		PKCS11H_BOOL mutex_locked = FALSE;

		if (_pkcs11h_threading_mutexLock (&__s_pkcs11h_threading_mutex_list.mutex) == CKR_OK) {
			mutex_locked = TRUE;
		}

		entry =  __s_pkcs11h_threading_mutex_list.head;
		while (
			entry != NULL &&
			entry->p_mutex != mutex
		) {
			last = entry;
			entry = entry->next;
		}

		if (entry != NULL) {
			if (last == NULL) {
				__s_pkcs11h_threading_mutex_list.head = entry->next;
			}
			else {
				last->next = entry->next;
			}
			_pkcs11h_mem_free ((void *)&entry);
		}

		pthread_mutex_destroy (mutex);

		if (mutex_locked) {
			_pkcs11h_threading_mutexRelease (&__s_pkcs11h_threading_mutex_list.mutex);
			mutex_locked = FALSE;
		}
	}
#endif
	return CKR_OK;
}

#if !defined(WIN32)
/*
 * This function is required in order
 * to lock all mutexes before fork is called,
 * and to avoid dedlocks.
 * The loop is required because there is no
 * way to lock all mutex in one system call...
 */
static
void
__pkcs1h_threading_mutexLockAll () {
	__pkcs11h_threading_mutex_entry_t entry = NULL;
	PKCS11H_BOOL mutex_locked = FALSE;
	PKCS11H_BOOL all_mutexes_locked = FALSE;

	if (_pkcs11h_threading_mutexLock (&__s_pkcs11h_threading_mutex_list.mutex) == CKR_OK) {
		mutex_locked = TRUE;
	}

	for (
		entry = __s_pkcs11h_threading_mutex_list.head;
		entry != NULL;
		entry = entry->next
	) {
		entry->locked = FALSE;
	}

	while (!all_mutexes_locked) {
		PKCS11H_BOOL ok = TRUE;
		
		for (
			entry = __s_pkcs11h_threading_mutex_list.head;
			entry != NULL && ok;
			entry = entry->next
		) {
			if (!pthread_mutex_trylock (entry->p_mutex)) {
				entry->locked = TRUE;
			}
			else {
				ok = FALSE;
			}
		}

		if (!ok) {
			for (
				entry = __s_pkcs11h_threading_mutex_list.head;
				entry != NULL;
				entry = entry->next
			) {
				if (entry->locked == TRUE) {
					pthread_mutex_unlock (entry->p_mutex);
					entry->locked = FALSE;
				}
			}

			_pkcs11h_threading_mutexRelease (&__s_pkcs11h_threading_mutex_list.mutex);
			_pkcs11h_threading_sleep (1000);
			_pkcs11h_threading_mutexLock (&__s_pkcs11h_threading_mutex_list.mutex);
		}
		else {
			all_mutexes_locked  = TRUE;
		}
	}

	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&__s_pkcs11h_threading_mutex_list.mutex);
		mutex_locked = FALSE;
	}
}

static
void
__pkcs1h_threading_mutexReleaseAll () {
	__pkcs11h_threading_mutex_entry_t entry = NULL;
	PKCS11H_BOOL mutex_locked = FALSE;

	if (_pkcs11h_threading_mutexLock (&__s_pkcs11h_threading_mutex_list.mutex) == CKR_OK) {
		mutex_locked = TRUE;
	}

	for (
		entry = __s_pkcs11h_threading_mutex_list.head;
		entry != NULL;
		entry = entry->next
	) {
		pthread_mutex_unlock (entry->p_mutex);
		entry->locked = FALSE;
	}

	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&__s_pkcs11h_threading_mutex_list.mutex);
		mutex_locked = FALSE;
	}
}
#endif

CK_RV
_pkcs11h_threading_condSignal (
	IN OUT pkcs11h_cond_t *const cond
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		!SetEvent (*cond)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (
		rv == CKR_OK &&
		(
			pthread_mutex_lock (&cond->mut) ||
			pthread_cond_signal (&cond->cond) ||
			pthread_mutex_unlock (&cond->mut)
		)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif

	return rv;
}

static
CK_RV
_pkcs11h_threading_condInit (
	OUT pkcs11h_cond_t * const cond
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		(*cond = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (
		rv == CKR_OK &&
		(
			pthread_mutex_init (&cond->mut, NULL) ||
			pthread_cond_init (&cond->cond, NULL) ||
			pthread_mutex_lock (&cond->mut)
		)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_threading_condWait (
	IN OUT pkcs11h_cond_t *const cond,
	IN const unsigned milli
) {
	CK_RV rv = CKR_OK;

#if defined(WIN32)
	DWORD dwMilli;

	if (milli == PKCS11H_COND_INFINITE) {
		dwMilli = INFINITE;
	}
	else {
		dwMilli = milli;
	}

	if (
		rv == CKR_OK &&
		WaitForSingleObject (*cond, dwMilli) == WAIT_FAILED
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (milli == PKCS11H_COND_INFINITE) {
		if (
			rv == CKR_OK &&
			pthread_cond_wait (&cond->cond, &cond->mut)
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	}
	else {
		struct timeval now;
		struct timespec timeout;

		if (
			rv == CKR_OK &&
			gettimeofday (&now, NULL)
		) {
			rv = CKR_FUNCTION_FAILED;
		}
		
		if (rv == CKR_OK) {
			timeout.tv_sec = now.tv_sec + milli/1000;
			timeout.tv_nsec = now.tv_usec*1000 + milli%1000;
		}
		
		if (
			rv == CKR_OK &&
			pthread_cond_timedwait (&cond->cond, &cond->mut, &timeout)
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_threading_condFree (
	IN OUT pkcs11h_cond_t *const cond
) {
#if defined(WIN32)
	CloseHandle (*cond);
	*cond = NULL;
#else
	pthread_mutex_unlock (&cond->mut);
#endif
	return CKR_OK;
}

#if defined(WIN32)
static
unsigned
__stdcall
__pkcs11h_thread_start (void *p) {
	__pkcs11h_thread_data_t *_data = (__pkcs11h_thread_data_t *)p;
	unsigned ret;

	ret = (unsigned)_data->start (_data->data);

	_pkcs11h_mem_free ((void *)&_data);

	return ret;
}
#else
static
void *
__pkcs11h_thread_start (void *p) {
	__pkcs11h_thread_data_t *_data = (__pkcs11h_thread_data_t *)p;
	void *ret;
	int i;

	/*
	 * Ignore any signal in
	 * this thread
	 */
	for (i=1;i<16;i++) {
		signal (i, SIG_IGN);
	}

	ret = _data->start (_data->data);

	_pkcs11h_mem_free ((void *)&_data);

	return ret;
}
#endif

static
CK_RV
_pkcs11h_threading_threadStart (
	OUT pkcs11h_thread_t * const thread,
	IN pkcs11h_thread_start_t const start,
	IN void * data
) {
	__pkcs11h_thread_data_t *_data = NULL;
	CK_RV rv = CKR_OK;

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_malloc (
			(void *)&_data,
			sizeof (__pkcs11h_thread_data_t)
		);
	}

	if (rv == CKR_OK) {
		_data->start = start;
		_data->data = data;
	}

#if defined(WIN32)
	{
		unsigned tmp;

		if (
			rv == CKR_OK &&
			(*thread = (HANDLE)_beginthreadex (
				NULL,
				0,
				__pkcs11h_thread_start,
				_data,
				0,
				&tmp
			)) == NULL
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	}
#else
	if (
		rv == CKR_OK &&
		pthread_create (thread, NULL, __pkcs11h_thread_start, _data)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_threading_threadJoin (
	IN pkcs11h_thread_t * const thread
) {
#if defined(WIN32)
	WaitForSingleObject (*thread, INFINITE);
	CloseHandle (*thread);
	*thread = NULL;
#else
	pthread_join (*thread, NULL);
	*thread = 0l;
#endif
	return CKR_OK;
}

#endif		/* ENABLE_PKCS11H_THREADING */

/*======================================================================*
 * COMMON INTERNAL INTERFACE
 *======================================================================*/

static
void
_pkcs11h_util_fixupFixedString (
	OUT char * const target,			/* MUST BE >= length+1 */
	IN const char * const source,
	IN const size_t length				/* FIXED STRING LENGTH */
) {
	char *p;

	PKCS11H_ASSERT (source!=NULL);
	PKCS11H_ASSERT (target!=NULL);
	
	p = target+length;
	memmove (target, source, length);
	*p = '\0';
	p--;
	while (p >= target && *p == ' ') {
		*p = '\0';
		p--;
	}
}

static
CK_RV
_pkcs11h_util_hexToBinary (
	OUT unsigned char * const target,
	IN const char * const source,
	IN OUT size_t * const p_target_size
) {
	size_t target_max_size;
	const char *p;
	char buf[3] = {'\0', '\0', '\0'};
	int i = 0;

	PKCS11H_ASSERT (source!=NULL);
	PKCS11H_ASSERT (target!=NULL);
	PKCS11H_ASSERT (p_target_size!=NULL);

	target_max_size = *p_target_size;
	p = source;
	*p_target_size = 0;

	while (*p != '\x0' && *p_target_size < target_max_size) {
		if (isxdigit ((unsigned char)*p)) {
			buf[i%2] = *p;

			if ((i%2) == 1) {
				unsigned v;
				if (sscanf (buf, "%x", &v) != 1) {
					v = 0;
				}
				target[*p_target_size] = v & 0xff;
				(*p_target_size)++;
			}

			i++;
		}
		p++;
	}

	if (*p != '\x0') {
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	else {
		return CKR_OK;
	}
}

static
CK_RV
_pkcs11h_util_binaryToHex (
	OUT char * const target,
	IN const size_t target_size,
	IN const unsigned char * const source,
	IN const size_t source_size
) {
	static const char *x = "0123456789ABCDEF";
	size_t i;

	PKCS11H_ASSERT (target!=NULL);
	PKCS11H_ASSERT (source!=NULL);

	if (target_size < source_size * 2 + 1) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	for (i=0;i<source_size;i++) {
		target[i*2] =   x[(source[i]&0xf0)>>4];
		target[i*2+1] = x[(source[i]&0x0f)>>0];
	}
	target[source_size*2] = '\x0';

	return CKR_OK;
}

CK_RV
_pkcs11h_util_escapeString (
	IN OUT char * const target,
	IN const char * const source,
	IN size_t * const max,
	IN const char * const invalid_chars
) {
	static const char *x = "0123456789ABCDEF";
	CK_RV rv = CKR_OK;
	const char *s = source;
	char *t = target;
	size_t n = 0;

	/*PKCS11H_ASSERT (target!=NULL); Not required*/
	PKCS11H_ASSERT (source!=NULL);
	PKCS11H_ASSERT (max!=NULL);

	while (rv == CKR_OK && *s != '\x0') {

		if (*s == '\\' || strchr (invalid_chars, *s) || !isgraph (*s)) {
			if (t != NULL) {
				if (n+4 > *max) {
					rv = CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else {
					t[0] = '\\';
					t[1] = 'x';
					t[2] = x[(*s&0xf0)>>4];
					t[3] = x[(*s&0x0f)>>0];
					t+=4;
				}
			}
			n+=4;
		}
		else {
			if (t != NULL) {
				if (n+1 > *max) {
					rv = CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else {
					*t = *s;
					t++;
				}
			}
			n+=1;
		}

		s++;
	}

	if (t != NULL) {
		if (n+1 > *max) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			*t = '\x0';
			t++;
		}
	}
	n++;

	*max = n;

	return rv;
}

static
CK_RV
_pkcs11h_util_unescapeString (
	IN OUT char * const target,
	IN const char * const source,
	IN size_t * const max
) {
	CK_RV rv = CKR_OK;
	const char *s = source;
	char *t = target;
	size_t n = 0;

	/*PKCS11H_ASSERT (target!=NULL); Not required*/
	PKCS11H_ASSERT (source!=NULL);
	PKCS11H_ASSERT (max!=NULL);

	while (rv == CKR_OK && *s != '\x0') {
		if (*s == '\\') {
			if (t != NULL) {
				if (n+1 > *max) {
					rv = CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else {
					char b[3];
					unsigned u;
					b[0] = s[2];
					b[1] = s[3];
					b[2] = '\x0';
					sscanf (b, "%08x", &u);
					*t = u&0xff;
					t++;
				}
			}
			s+=4;
		}
		else {
			if (t != NULL) {
				if (n+1 > *max) {
					rv = CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else {
					*t = *s;
					t++;
				}
			}
			s++;
		}

		n+=1;
	}

	if (t != NULL) {
		if (n+1 > *max) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			*t = '\x0';
			t++;
		}
	}
	n++;

	*max = n;

	return rv;
}

static
void
_pkcs11h_log (
	IN const unsigned flags,
	IN const char * const format,
	IN ...
) {
	va_list args;

	PKCS11H_ASSERT (format!=NULL);

	va_start (args, format);

	if (
		s_pkcs11h_data != NULL &&
		s_pkcs11h_data->initialized
	) { 
		if (PKCS11H_MSG_LEVEL_TEST (flags)) {
			if (s_pkcs11h_data->hooks.log == NULL) {
				_pkcs11h_hooks_default_log (
					NULL,
					flags,
					format,
					args
				);
			}
			else {
				s_pkcs11h_data->hooks.log (
					s_pkcs11h_data->hooks.log_data,
					flags,
					format,
					args
				);
			}
		}
	}

	va_end (args);
}

static
CK_RV
_pkcs11h_session_getSlotList (
	IN const pkcs11h_provider_t provider,
	IN const CK_BBOOL token_present,
	OUT CK_SLOT_ID_PTR * const pSlotList,
	OUT CK_ULONG_PTR pulCount
) {
	CK_SLOT_ID_PTR _slots = NULL;
	CK_ULONG _slotnum = 0;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (provider!=NULL);
	PKCS11H_ASSERT (pSlotList!=NULL);
	PKCS11H_ASSERT (pulCount!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_getSlotList entry provider=%p, token_present=%d, pSlotList=%p, pulCount=%p",
		(void *)provider,
		token_present,
		(void *)pSlotList,
		(void *)pulCount
	);

	*pSlotList = NULL;
	*pulCount = 0;

	if (
		rv == CKR_OK &&
		!provider->enabled
	) {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (rv == CKR_OK) {
		rv = provider->f->C_GetSlotList (
			token_present,
			NULL_PTR,
			&_slotnum
		);
	}

	if (rv == CKR_OK && _slotnum > 0) {
		rv = _pkcs11h_mem_malloc ((void *)&_slots, _slotnum * sizeof (CK_SLOT_ID));
	}

	if (rv == CKR_OK && _slotnum > 0) {
		rv = provider->f->C_GetSlotList (
			token_present,
			_slots,
			&_slotnum
		);
	}

	if (rv == CKR_OK) {
		*pSlotList = _slots;
		_slots = NULL;
		*pulCount = _slotnum;
	}

	if (_slots != NULL) {
		_pkcs11h_mem_free ((void *)&_slots);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_getSlotList return rv=%ld-'%s' *pulCount=%ld",
		rv,
		pkcs11h_getMessage (rv),
		*pulCount
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_getObjectAttributes (
	IN const pkcs11h_session_t session,
	IN const CK_OBJECT_HANDLE object,
	IN OUT const CK_ATTRIBUTE_PTR attrs,
	IN const unsigned count
) {
	/*
	 * THREADING:
	 * session->mutex must be locked
	 */
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (attrs!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_getObjectAttributes entry session=%p, object=%ld, attrs=%p, count=%u",
		(void *)session,
		object,
		(void *)attrs,
		count
	);

	if (
		rv == CKR_OK &&
		(rv = session->provider->f->C_GetAttributeValue (
			session->session_handle,
			object,
			attrs,
			count
		)) == CKR_OK
	) {
		unsigned i;
		for (i=0;rv == CKR_OK && i<count;i++) {
			if (attrs[i].ulValueLen == (CK_ULONG)-1) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else if (attrs[i].ulValueLen == 0) {
				attrs[i].pValue = NULL;
			}
			else {
				rv = _pkcs11h_mem_malloc (
					(void *)&attrs[i].pValue,
					attrs[i].ulValueLen
				);
			}
		}
	}

	if (rv == CKR_OK) {
		rv = session->provider->f->C_GetAttributeValue (
			session->session_handle,
			object,
			attrs,
			count
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_getObjectAttributes return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_freeObjectAttributes (
	IN OUT const CK_ATTRIBUTE_PTR attrs,
	IN const unsigned count
) {
	unsigned i;

	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (attrs!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_freeObjectAttributes entry attrs=%p, count=%u",
		(void *)attrs,
		count
	);

	for (i=0;i<count;i++) {
		if (attrs[i].pValue != NULL) {
			_pkcs11h_mem_free ((void *)&attrs[i].pValue);
			attrs[i].pValue = NULL;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_freeObjectAttributes return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_findObjects (
	IN const pkcs11h_session_t session,
	IN const CK_ATTRIBUTE * const filter,
	IN const CK_ULONG filter_attrs,
	OUT CK_OBJECT_HANDLE **const p_objects,
	OUT CK_ULONG *p_objects_found
) {
	/*
	 * THREADING:
	 * session->mutex must be locked
	 */
	PKCS11H_BOOL should_FindObjectsFinal = FALSE;

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_size = 0;
	CK_OBJECT_HANDLE objects_buffer[100];
	CK_ULONG objects_found;
	CK_OBJECT_HANDLE oLast = PKCS11H_INVALID_OBJECT_HANDLE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (!(filter==NULL && filter_attrs!=0) || filter!=NULL);
	PKCS11H_ASSERT (p_objects!=NULL);
	PKCS11H_ASSERT (p_objects_found!=NULL);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_findObjects entry session=%p, filter=%p, filter_attrs=%ld, p_objects=%p, p_objects_found=%p",
		(void *)session,
		(void *)filter,
		filter_attrs,
		(void *)p_objects,
		(void *)p_objects_found
	);

	*p_objects = NULL;
	*p_objects_found = 0;

	if (
		rv == CKR_OK &&
		(rv = session->provider->f->C_FindObjectsInit (
			session->session_handle,
			(CK_ATTRIBUTE *)filter,
			filter_attrs
		)) == CKR_OK
	) {
		should_FindObjectsFinal = TRUE;
	}

	while (
		rv == CKR_OK &&
		(rv = session->provider->f->C_FindObjects (
			session->session_handle,
			objects_buffer,
			sizeof (objects_buffer) / sizeof (CK_OBJECT_HANDLE),
			&objects_found
		)) == CKR_OK &&
		objects_found > 0
	) { 
		CK_OBJECT_HANDLE *temp = NULL;
		
		/*
		 * Begin workaround
		 *
		 * Workaround iKey bug
		 * It returns the same objects over and over
		 */
		if (oLast == objects_buffer[0]) {
			PKCS11H_LOG (
				PKCS11H_LOG_WARN,
				"PKCS#11: Bad PKCS#11 C_FindObjects implementation detected, workaround applied"
			);
			break;
		}
		oLast = objects_buffer[0];
		/* End workaround */
		
		if (
			(rv = _pkcs11h_mem_malloc (
				(void *)&temp,
				(objects_size+objects_found) * sizeof (CK_OBJECT_HANDLE)
			)) == CKR_OK
		) {
			if (objects != NULL) {
				memmove (
					temp,
					objects,
					objects_size * sizeof (CK_OBJECT_HANDLE)
				);
			}
			memmove (
				temp + objects_size,
				objects_buffer,
				objects_found * sizeof (CK_OBJECT_HANDLE)
			);
		}

		if (rv == CKR_OK) {
			_pkcs11h_mem_free ((void *)&objects);
			objects = temp;
			objects_size += objects_found;
			temp = NULL;
		}

		if (temp != NULL) {
			_pkcs11h_mem_free ((void *)&temp);
			temp = NULL;
		}
	}

	if (should_FindObjectsFinal) {
		session->provider->f->C_FindObjectsFinal (
			session->session_handle
		);
		should_FindObjectsFinal = FALSE;
	}
	
	if (rv == CKR_OK) {
		*p_objects = objects;
		*p_objects_found = objects_size;
		objects = NULL;
		objects_size = 0;
	}

	if (objects != NULL) {
		_pkcs11h_mem_free ((void *)&objects);
		objects = NULL;
		objects_size = 0;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_findObjects return rv=%ld-'%s', *p_objects_found=%ld",
		rv,
		pkcs11h_getMessage (rv),
		*p_objects_found
	);

	return rv;
}

static
CK_RV
_pkcs11h_token_getTokenId (
	IN const CK_TOKEN_INFO_PTR info,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_token_id_t token_id;
	CK_RV rv = CKR_OK;
	
	PKCS11H_ASSERT (info!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_token_getTokenId entry p_token_id=%p",
		(void *)p_token_id
	);

	*p_token_id = NULL;

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_token_newTokenId (&token_id)) == CKR_OK
	) {
		_pkcs11h_util_fixupFixedString (
			token_id->label,
			(char *)info->label,
			sizeof (info->label)
		);
		_pkcs11h_util_fixupFixedString (
			token_id->manufacturerID,
			(char *)info->manufacturerID,
			sizeof (info->manufacturerID)
		);
		_pkcs11h_util_fixupFixedString (
			token_id->model,
			(char *)info->model,
			sizeof (info->model)
		);
		_pkcs11h_util_fixupFixedString (
			token_id->serialNumber,
			(char *)info->serialNumber,
			sizeof (info->serialNumber)
		);
		strncpy (
			token_id->display,
			token_id->label,
			sizeof (token_id->display)
		);
	}

	if (rv == CKR_OK) {
		*p_token_id = token_id;
		token_id = NULL;
	}

	if (token_id != NULL) {
		_pkcs11h_mem_free ((void *)&token_id);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_token_getTokenId return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_token_newTokenId (
	OUT pkcs11h_token_id_t * const p_token_id
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_token_newTokenId entry p_token_id=%p",
		(void *)p_token_id
	);

	*p_token_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_malloc ((void *)p_token_id, sizeof (struct pkcs11h_token_id_s));
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_token_newTokenId return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_getSessionByTokenId (
	IN const pkcs11h_token_id_t token_id,
	OUT pkcs11h_session_t * const p_session
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL is_new_session = FALSE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (token_id!=NULL);
	PKCS11H_ASSERT (p_session!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_getSessionByTokenId entry token_id=%p, p_session=%p",
		(void *)token_id,
		(void *)p_session
	);

	*p_session = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.session)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		pkcs11h_session_t current_session;

		for (
			current_session = s_pkcs11h_data->sessions;
			current_session != NULL && session == NULL;
			current_session = current_session->next
		) {
			if (
				pkcs11h_token_sameTokenId (
					current_session->token_id,
					token_id
				)
			) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Using cached session"
				);
				session = current_session;
				session->reference_count++;
			}
		}
	}

	if (
		rv == CKR_OK &&
		session == NULL
	) {
		is_new_session = TRUE;
	}

	if (is_new_session) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Creating a new session"
		);

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mem_malloc ((void *)&session, sizeof (struct pkcs11h_session_s))) == CKR_OK
		) {
			session->reference_count = 1;
			session->session_handle = PKCS11H_INVALID_SESSION_HANDLE;
			
			session->pin_cache_period = s_pkcs11h_data->pin_cache_period;

		}

		if (rv == CKR_OK) {
			rv = pkcs11h_token_duplicateTokenId (
				&session->token_id,
				token_id
			);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (rv == CKR_OK) {
			rv = _pkcs11h_threading_mutexInit (&session->mutex);
		}
#endif

		if (rv == CKR_OK) {
			session->valid = TRUE;
			session->next = s_pkcs11h_data->sessions;
			s_pkcs11h_data->sessions = session;
		}
		else {
#if defined(ENABLE_PKCS11H_THREADING)
			_pkcs11h_threading_mutexFree (&session->mutex);
#endif
			_pkcs11h_mem_free ((void *)&session);
		}
	}

	if (rv == CKR_OK) {
		*p_session = session;
		session = NULL;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.session);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_getSessionByTokenId return rv=%ld-'%s', *p_session=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_session
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_release (
	IN const pkcs11h_session_t session
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (session->reference_count>=0);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_release entry session=%p",
		(void *)session
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	/*
	 * Never logout for now
	 */
	if (rv == CKR_OK) {
		if (session->reference_count > 0) {
			session->reference_count--;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_release return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_reset (
	IN const pkcs11h_session_t session,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT CK_SLOT_ID * const p_slot
) {
	PKCS11H_BOOL found = FALSE;

	CK_RV rv = CKR_OK;

	unsigned nRetry = 0;

	PKCS11H_ASSERT (session!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	PKCS11H_ASSERT (p_slot!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_reset entry session=%p, user_data=%p, mask_prompt=%08x, p_slot=%p",
		(void *)session,
		user_data,
		mask_prompt,
		(void *)p_slot
	);

	*p_slot = PKCS11H_INVALID_SLOT_ID;

	while (
		rv == CKR_OK &&
		!found
	) {
		pkcs11h_provider_t current_provider = NULL;

		for (
			current_provider = s_pkcs11h_data->providers;
			(
				rv == CKR_OK &&
				current_provider != NULL &&
				!found
			);
			current_provider = current_provider->next
		) {
			CK_SLOT_ID_PTR slots = NULL;
			CK_ULONG slotnum;
			CK_SLOT_ID slot_index;

			/*
			 * Skip all other providers,
			 * if one was set in the past
			 */
			if (
				session->provider != NULL &&
				session->provider != current_provider
			) {
				rv = CKR_CANCEL;
			}
		
			if (rv == CKR_OK) {
				rv = _pkcs11h_session_getSlotList (
					current_provider,
					CK_TRUE,
					&slots,
					&slotnum
				);
			}

			for (
				slot_index=0;
				(
					slot_index < slotnum &&
					rv == CKR_OK && 
					!found
				);
				slot_index++
			) {
				pkcs11h_token_id_t token_id = NULL;
				CK_TOKEN_INFO info;

				if (rv == CKR_OK) {
					rv = current_provider->f->C_GetTokenInfo (
						slots[slot_index],
						&info
					);
				}

				if (
					rv == CKR_OK &&
					(rv = _pkcs11h_token_getTokenId (
						&info,
						&token_id
					)) == CKR_OK &&
					pkcs11h_token_sameTokenId (
						session->token_id,
						token_id
					)
				) {
					found = TRUE;
					*p_slot = slots[slot_index];
					if (session->provider == NULL) {
						session->provider = current_provider;
						session->allow_protected_auth_supported = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0;
					}
				}

				if (rv != CKR_OK) {
					PKCS11H_DEBUG (
						PKCS11H_LOG_DEBUG1,
						"PKCS#11: Cannot get token information for provider '%s' slot %ld rv=%ld-'%s'",
						current_provider->manufacturerID,
						slots[slot_index],
						rv,
						pkcs11h_getMessage (rv)
					);

					/*
					 * Ignore error
					 */
					rv = CKR_OK;
				}

				if (token_id != NULL) {
					pkcs11h_token_freeTokenId (token_id);
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
					current_provider->manufacturerID,
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}

			if (slots != NULL) {
				_pkcs11h_mem_free ((void *)&slots);
				slots = NULL;
			}
		}

		if (rv == CKR_OK && !found && (mask_prompt & PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT) == 0) {
			rv = CKR_TOKEN_NOT_PRESENT;
		}

		if (
			rv == CKR_OK &&
			!found
		) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling token_prompt hook for '%s'",
				session->token_id->display
			);
	
			if (
				!s_pkcs11h_data->hooks.token_prompt (
					s_pkcs11h_data->hooks.token_prompt_data,
					user_data,
					session->token_id,
					nRetry++
				)
			) {
				rv = CKR_CANCEL;
			}

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: token_prompt returned %ld",
				rv
			);
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_reset return rv=%ld-'%s', *p_slot=%ld",
		rv,
		pkcs11h_getMessage (rv),
		*p_slot
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_getObjectById (
	IN const pkcs11h_session_t session,
	IN const CK_OBJECT_CLASS class,
	IN const CK_BYTE_PTR id,
	IN const size_t id_size,
	OUT CK_OBJECT_HANDLE * const p_handle
) {
	/*
	 * THREADING:
	 * session->mutex must be locked
	 */
	CK_ATTRIBUTE filter[] = {
		{CKA_CLASS, (void *)&class, sizeof (class)},
		{CKA_ID, (void *)id, id_size}
	};
	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;
	
	/*PKCS11H_ASSERT (session!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (id!=NULL);
	PKCS11H_ASSERT (p_handle!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_getObjectById entry session=%p, class=%ld, id=%p, id_size=%u, p_handle=%p",
		(void *)session,
		class,
		id,
		id_size,
		(void *)p_handle
	);

	*p_handle = PKCS11H_INVALID_OBJECT_HANDLE;

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (session);
	}

	if (rv == CKR_OK) { 
		rv = _pkcs11h_session_findObjects (
			session,
			filter,
			sizeof (filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	if (
		rv == CKR_OK &&
		objects_found == 0
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

	if (rv == CKR_OK) {
		*p_handle = objects[0];
	}

	if (objects != NULL) {
		_pkcs11h_mem_free ((void *)&objects);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_getObjectById return rv=%ld-'%s', *p_handle=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_handle
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_validate (
	IN const pkcs11h_session_t session
) {
	CK_RV rv = CKR_OK;

	/*PKCS11H_ASSERT (session!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_validate entry session=%p",
		(void *)session
	);

	if (
		rv == CKR_OK &&
		session == NULL
	) {
		rv = CKR_SESSION_HANDLE_INVALID;
	}

	if (
		rv == CKR_OK &&
		(
			session->provider == NULL ||
			!session->provider->enabled ||
			session->session_handle == PKCS11H_INVALID_SESSION_HANDLE
		)
	) {
		rv = CKR_SESSION_HANDLE_INVALID;
	}

	if (
		rv == CKR_OK &&
		session->pin_expire_time != (time_t)0 &&
		session->pin_expire_time < PKCS11H_TIME (NULL)
	) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Forcing logout due to pin timeout"
		);
		_pkcs11h_session_logout (session);
		rv = CKR_SESSION_HANDLE_INVALID;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_validate return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_touch (
	IN const pkcs11h_session_t session
) {
	/*
	 * THREADING:
	 * session->mutex must be locked
	 */
	PKCS11H_ASSERT (session!=NULL);

	if (session->pin_cache_period == PKCS11H_PIN_CACHE_INFINITE) {
		session->pin_expire_time = 0;
	}
	else {
		session->pin_expire_time = (
			PKCS11H_TIME (NULL) +
			(time_t)session->pin_cache_period
		);
	}

	return CKR_OK;
}

CK_RV
pkcs11h_token_login (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL readonly,
	IN const char * const pin
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_SLOT_ID slot = PKCS11H_INVALID_SLOT_ID;
	CK_ULONG pin_size = 0;
	CK_RV rv = CKR_OK;

	pkcs11h_session_t session = NULL;

	PKCS11H_ASSERT (token_id!=NULL);
	/*PKCS11H_ASSERT (pin!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_login entry token_id=%p, readonly=%d\n", 
		(void *)token_id,
		readonly ? 1 : 0
	);

	if (pin != NULL) {
		pin_size = strlen (pin);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_getSessionByTokenId (
			token_id,
			&session
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_logout (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_reset (session, NULL, 0, &slot);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_touch (session);
	}

	if (rv == CKR_OK) {
		rv = session->provider->f->C_OpenSession (
			slot,
			(
				CKF_SERIAL_SESSION |
				(readonly ? 0 : CKF_RW_SESSION)
			),
			NULL_PTR,
			NULL_PTR,
			&session->session_handle
		);
	}

	if (
		rv == CKR_OK &&
		(rv = session->provider->f->C_Login (
			session->session_handle,
			CKU_USER,
			(CK_UTF8CHAR_PTR)pin,
			pin_size
		)) != CKR_OK
	) {
		if (rv == CKR_USER_ALREADY_LOGGED_IN) {
			rv = CKR_OK;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_login return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_login (
	IN const pkcs11h_session_t session,
	IN const PKCS11H_BOOL is_publicOnly,
	IN const PKCS11H_BOOL readonly,
	IN void * const user_data,
	IN const unsigned mask_prompt
) {
	/*
	 * THREADING:
	 * session->mutex must be locked
	 */
	CK_SLOT_ID slot = PKCS11H_INVALID_SLOT_ID;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_login entry session=%p, is_publicOnly=%d, readonly=%d, user_data=%p, mask_prompt=%08x",
		(void *)session,
		is_publicOnly ? 1 : 0,
		readonly ? 1 : 0,
		user_data,
		mask_prompt
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_logout (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_reset (session, user_data, mask_prompt, &slot);
	}

	if (rv == CKR_OK) {
		rv = session->provider->f->C_OpenSession (
			slot,
			(
				CKF_SERIAL_SESSION |
				(readonly ? 0 : CKF_RW_SESSION)
			),
			NULL_PTR,
			NULL_PTR,
			&session->session_handle
		);
	}

	if (
		rv == CKR_OK &&
	   	(
			!is_publicOnly ||
			session->provider->cert_is_private
		)
	) {
		PKCS11H_BOOL login_succeeded = FALSE;
		unsigned nRetryCount = 0;

		if ((mask_prompt & PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT) == 0) {
			rv = CKR_USER_NOT_LOGGED_IN;

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling pin_prompt hook denied because of prompt mask"
			);
		}

		while (
			rv == CKR_OK &&
			!login_succeeded &&
			nRetryCount < s_pkcs11h_data->max_retries 
		) {
			CK_UTF8CHAR_PTR utfPIN = NULL;
			CK_ULONG lPINLength = 0;
			char pin[1024];

			if (
				rv == CKR_OK &&
				!(
					s_pkcs11h_data->allow_protected_auth  &&
					session->provider->allow_protected_auth &&
					session->allow_protected_auth_supported
				)
			) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Calling pin_prompt hook for '%s'",
					session->token_id->display
				);

				if (
					!s_pkcs11h_data->hooks.pin_prompt (
						s_pkcs11h_data->hooks.pin_prompt_data,
						user_data,
						session->token_id,
						nRetryCount,
						pin,
						sizeof (pin)
					)
				) {
					rv = CKR_CANCEL;
				}
				else {
					utfPIN = (CK_UTF8CHAR_PTR)pin;
					lPINLength = strlen (pin);
				}

				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: pin_prompt hook return rv=%ld",
					rv
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_session_touch (session);
			}

			if (
				rv == CKR_OK &&
				(rv = session->provider->f->C_Login (
					session->session_handle,
					CKU_USER,
					utfPIN,
					lPINLength
				)) != CKR_OK
			) {
				if (rv == CKR_USER_ALREADY_LOGGED_IN) {
					rv = CKR_OK;
				}
			}

			/*
			 * Clean PIN buffer
			 */
			memset (pin, 0, sizeof (pin));

			if (rv == CKR_OK) {
				login_succeeded = TRUE;
			}
			else if (
				rv == CKR_PIN_INCORRECT ||
				rv == CKR_PIN_INVALID
			) {
				/*
				 * Ignore these errors
				 * so retry can be performed
				 */
				rv = CKR_OK;
			}

			nRetryCount++;
		}

		/*
		 * Retry limit
		 */
		if (!login_succeeded && rv == CKR_OK) {
			rv = CKR_PIN_INCORRECT;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_login return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_session_logout (
	IN const pkcs11h_session_t session
) {
	/*
	 * THREADING:
	 * session->mutex must be locked
	 */
	/*PKCS11H_ASSERT (session!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_logout entry session=%p",
		(void *)session
	);

	if (
		session != NULL &&
		session->session_handle != PKCS11H_INVALID_SESSION_HANDLE
	) {
		CK_RV rv = CKR_OK;

		if (rv == CKR_OK) {
			if (session->provider != NULL) {
				session->provider->f->C_Logout (session->session_handle);
				session->provider->f->C_CloseSession (session->session_handle);
			}
			session->session_handle = PKCS11H_INVALID_SESSION_HANDLE;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_session_logout return"
	);

	return CKR_OK;
}

static
void
_pkcs11h_hooks_default_log (
	IN void * const global_data,
	IN const unsigned flags,
	IN const char * const format,
	IN va_list args
) {
	(void)global_data;
	(void)flags;
	(void)format;
	(void)args;
}

static
PKCS11H_BOOL
_pkcs11h_hooks_default_token_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry
) {
	/*PKCS11H_ASSERT (global_data) NOT NEEDED */
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	PKCS11H_ASSERT (token!=NULL);

	(void)global_data;
	(void)user_data;
	(void)retry;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_hooks_default_token_prompt global_data=%p, user_data=%p, display='%s'",
		global_data,
		user_data,
		token->display
	);

	return FALSE;
}

static
PKCS11H_BOOL
_pkcs11h_hooks_default_pin_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const pin,
	IN const size_t pin_max
) {
	/*PKCS11H_ASSERT (global_data) NOT NEEDED */
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	PKCS11H_ASSERT (token!=NULL);

	(void)global_data;
	(void)user_data;
	(void)retry;
	(void)pin;
	(void)pin_max;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_hooks_default_pin_prompt global_data=%p, user_data=%p, display='%s'",
		global_data,
		user_data,
		token->display
	);
	
	return FALSE;
}

#if !defined(WIN32)
#if defined(ENABLE_PKCS11H_THREADING)

static
void
__pkcs11h_threading_atfork_prepare  () {
	__pkcs1h_threading_mutexLockAll ();
}
static
void
__pkcs11h_threading_atfork_parent () {
	__pkcs1h_threading_mutexReleaseAll ();
}
static
void
__pkcs11h_threading_atfork_child () {
	__pkcs1h_threading_mutexReleaseAll ();
	_pkcs11h_forkFixup ();
}

#endif				/* ENABLE_PKCS11H_THREADING */

static
CK_RV
_pkcs11h_forkFixup () {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pid_t mypid = getpid ();

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup entry pid=%d",
		mypid
	);

	if (s_pkcs11h_data != NULL && s_pkcs11h_data->initialized) {
		pkcs11h_provider_t current;

#if defined(ENABLE_PKCS11H_THREADING)
		if (_pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global) == CKR_OK) {
			mutex_locked = TRUE;
		}
#endif

		for (
			current = s_pkcs11h_data->providers;
			current != NULL;
			current = current->next
		) {
			if (current->enabled) {
				current->f->C_Initialize (NULL);
			}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
			/*
			 * After fork we have no threads...
			 * So just initialized.
			 */
			if (s_pkcs11h_data->slotevent.initialized) {
				s_pkcs11h_data->slotevent.initialized = FALSE;
				_pkcs11h_slotevent_init ();
			}
#endif
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.global);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup return"
	);

	return CKR_OK;
}

#endif				/* !WIN32 */

#if defined(ENABLE_PKCS11H_TOKEN)
/*======================================================================*
 * TOKEN INTERFACE
 *======================================================================*/

CK_RV
pkcs11h_token_ensureAccess (
	IN const pkcs11h_token_id_t token_id,
	IN void * const user_data,
	IN const unsigned mask_prompt
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (token_id!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_ensureAccess entry token_id=%p, user_data=%p, mask_prompt=%08x",
		(void *)token_id,
		user_data,
		mask_prompt
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_getSessionByTokenId (
			token_id,
			&session
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		CK_SLOT_ID slot;

		rv = _pkcs11h_session_reset (
			session,
			user_data,
			mask_prompt,
			&slot
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_ensureAccess return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

#endif				/* ENABLE_PKCS11H_TOKEN */

#if defined(ENABLE_PKCS11H_DATA)
/*======================================================================*
 * DATA INTERFACE
 *======================================================================*/

static
CK_RV
_pkcs11h_data_getObject (
	IN const pkcs11h_session_t session,
	IN const char * const application,
	IN const char * const label,
	OUT CK_OBJECT_HANDLE * const p_handle
) {
	CK_OBJECT_CLASS class = CKO_DATA;
	CK_ATTRIBUTE filter[] = {
		{CKA_CLASS, (void *)&class, sizeof (class)},
		{CKA_APPLICATION, (void *)application, application == NULL ? 0 : strlen (application)},
		{CKA_LABEL, (void *)label, label == NULL ? 0 : strlen (label)}
	};
	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;
	
	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (application!=NULL);
	PKCS11H_ASSERT (label!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_data_getObject entry session=%p, application='%s', label='%s', p_handle=%p",
		(void *)session,
		application,
		label,
		(void *)p_handle
	);

	*p_handle = PKCS11H_INVALID_OBJECT_HANDLE;

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_findObjects (
			session,
			filter,
			sizeof (filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	if (
		rv == CKR_OK &&
		objects_found == 0
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

	if (rv == CKR_OK) {
		*p_handle = objects[0];
	}

	if (objects != NULL) {
		_pkcs11h_mem_free ((void *)&objects);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_data_getObject return rv=%ld-'%s', *p_handle=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_handle
	);

	return rv;
}

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
) {
	CK_ATTRIBUTE attrs[] = {
		{CKA_VALUE, NULL, 0}
	};
	CK_OBJECT_HANDLE handle = PKCS11H_INVALID_OBJECT_HANDLE;
	CK_RV rv = CKR_OK;

#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;
	size_t blob_size_max = 0;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (token_id!=NULL);
	PKCS11H_ASSERT (application!=NULL);
	PKCS11H_ASSERT (label!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	/*PKCS11H_ASSERT (blob!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_blob_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_get entry token_id=%p, application='%s', label='%s', user_data=%p, mask_prompt=%08x, blob=%p, *p_blob_size=%u",
		(void *)token_id,
		application,
		label,
		user_data,
		mask_prompt,
		blob,
		blob != NULL ? *p_blob_size : 0
	);

	if (blob != NULL) {
		blob_size_max = *p_blob_size;
	}
	*p_blob_size = 0;

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_getSessionByTokenId (
			token_id,
			&session
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_validate (session);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_data_getObject (
				session,
				application,
				label,
				&handle
			);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getObjectAttributes (
				session,
				handle,
				attrs,
				sizeof (attrs)/sizeof (CK_ATTRIBUTE)
			);
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Read data object failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				login_retry = TRUE;
				rv = _pkcs11h_session_login (
					session,
					is_public,
					TRUE,
					user_data,
					mask_prompt
				);
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	if (rv == CKR_OK) {
		*p_blob_size = attrs[0].ulValueLen;
	}

	if (rv == CKR_OK) {
		if (blob != NULL) {
			if (*p_blob_size > blob_size_max) {
				rv = CKR_BUFFER_TOO_SMALL;
			}
			else {
				memmove (blob, attrs[0].pValue, *p_blob_size);
			}
		}
	}

	_pkcs11h_session_freeObjectAttributes (
		attrs,
		sizeof (attrs)/sizeof (CK_ATTRIBUTE)
	);

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_get return rv=%ld-'%s', *p_blob_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_blob_size
	);

	return rv;
}

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
) {
	CK_OBJECT_CLASS class = CKO_DATA;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;

	CK_ATTRIBUTE attrs[] = {
		{CKA_CLASS, &class, sizeof (class)},
		{CKA_TOKEN, &ck_true, sizeof (ck_true)},
		{CKA_PRIVATE, is_public ? &ck_false : &ck_true, sizeof (CK_BBOOL)},
		{CKA_APPLICATION, (void *)application, strlen (application)},
		{CKA_LABEL, (void *)label, strlen (label)},
		{CKA_VALUE, blob, blob_size}
	};

	CK_OBJECT_HANDLE handle = PKCS11H_INVALID_OBJECT_HANDLE;
	CK_RV rv = CKR_OK;

#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (token_id!=NULL);
	PKCS11H_ASSERT (application!=NULL);
	PKCS11H_ASSERT (label!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	PKCS11H_ASSERT (blob!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_put entry token_id=%p, application='%s', label='%s', user_data=%p, mask_prompt=%08x, blob=%p, blob_size=%u",
		(void *)token_id,
		application,
		label,
		user_data,
		mask_prompt,
		blob,
		blob != NULL ? blob_size : 0
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_getSessionByTokenId (
			token_id,
			&session
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_validate (session);
		}

		if (rv == CKR_OK) {
			rv = session->provider->f->C_CreateObject (
				session->session_handle,
				attrs,
				sizeof (attrs)/sizeof (CK_ATTRIBUTE),
				&handle
			);
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Write data object failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				login_retry = TRUE;
				rv = _pkcs11h_session_login (
					session,
					is_public,
					FALSE,
					user_data,
					mask_prompt
				);
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_put return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_data_del (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL is_public,
	IN const char * const application,
	IN const char * const label,
	IN void * const user_data,
	IN const unsigned mask_prompt
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;
	CK_OBJECT_HANDLE handle = PKCS11H_INVALID_OBJECT_HANDLE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (token_id!=NULL);
	PKCS11H_ASSERT (application!=NULL);
	PKCS11H_ASSERT (label!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_del entry token_id=%p, application='%s', label='%s', user_data=%p, mask_prompt=%08x",
		(void *)token_id,
		application,
		label,
		user_data,
		mask_prompt
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_getSessionByTokenId (
			token_id,
			&session
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_validate (session);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_data_getObject (
				session,
				application,
				label,
				&handle
			);
		}

		if (rv == CKR_OK) {
			rv = session->provider->f->C_DestroyObject (
				session->session_handle,
				handle
			);
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Remove data object failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				login_retry = TRUE;
				rv = _pkcs11h_session_login (
					session,
					is_public,
					FALSE,
					user_data,
					mask_prompt
				);
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
		if (mutex_locked) {
			_pkcs11h_threading_mutexRelease (&session->mutex);
			mutex_locked = FALSE;
		}
#endif

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_del return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

#endif				/* ENABLE_PKCS11H_DATA */

#if defined(ENABLE_PKCS11H_CERTIFICATE)
/*======================================================================*
 * CERTIFICATE INTERFACE
 *======================================================================*/

static
time_t
_pkcs11h_certificate_getExpiration (
	IN const unsigned char * const certificate,
	IN const size_t certificate_size
) {
	/*
	 * This function compare the notAfter
	 * and select the most recent certificate
	 */

#if defined(USE_PKCS11H_OPENSSL)
	X509 *x509 = NULL;
#elif defined(USE_PKCS11H_GNUTLS)
	gnutls_x509_crt_t cert = NULL;
#endif
	time_t expire = (time_t)0;

	PKCS11H_ASSERT (certificate!=NULL);

#if defined(USE_PKCS11H_OPENSSL)
	x509 = X509_new ();

	if (x509 != NULL) {
		pkcs11_openssl_d2i_t d2i = (pkcs11_openssl_d2i_t)certificate;

		if (
			d2i_X509 (&x509, &d2i, certificate_size)
		) {
			ASN1_TIME *notBefore = X509_get_notBefore (x509);
			ASN1_TIME *notAfter = X509_get_notAfter (x509);

			if (
				notBefore != NULL &&
				notAfter != NULL &&
				X509_cmp_current_time (notBefore) <= 0 &&
				X509_cmp_current_time (notAfter) >= 0 &&
				notAfter->length >= 12
			) {
				struct tm tm1;
				time_t now = time (NULL);

				memset (&tm1, 0, sizeof (tm1));
				tm1.tm_year = (notAfter->data[ 0] - '0') * 10 + (notAfter->data[ 1] - '0') + 100;
				tm1.tm_mon  = (notAfter->data[ 2] - '0') * 10 + (notAfter->data[ 3] - '0') - 1;
				tm1.tm_mday = (notAfter->data[ 4] - '0') * 10 + (notAfter->data[ 5] - '0');
				tm1.tm_hour = (notAfter->data[ 6] - '0') * 10 + (notAfter->data[ 7] - '0');
				tm1.tm_min  = (notAfter->data[ 8] - '0') * 10 + (notAfter->data[ 9] - '0');
				tm1.tm_sec  = (notAfter->data[10] - '0') * 10 + (notAfter->data[11] - '0');

				tm1.tm_sec += (int)(mktime (localtime (&now)) - mktime (gmtime (&now)));

				expire = mktime (&tm1);
			}
		}
	}

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}
#elif defined(USE_PKCS11H_GNUTLS)
	if (gnutls_x509_crt_init (&cert) == GNUTLS_E_SUCCESS) {
		gnutls_datum_t datum = {(unsigned char *)certificate, certificate_size};

		if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {

			time_t activation_time = gnutls_x509_crt_get_activation_time (cert);
			time_t expiration_time = gnutls_x509_crt_get_expiration_time (cert);
			time_t now = time (NULL);

			if (
				now >= activation_time &&
				now <= expiration_time
			) {
				expire = expiration_time;
			}
		}
		gnutls_x509_crt_deinit (cert);
	}
#else
#error Invalid configuration
#endif

	return expire;
}

static
PKCS11H_BOOL
_pkcs11h_certificate_isBetterCertificate (
	IN const unsigned char * const current,
	IN const size_t current_size,
	IN const unsigned char * const newone,
	IN const size_t newone_size
) {
	PKCS11H_BOOL is_better = FALSE;

	/*PKCS11H_ASSERT (current!=NULL); NOT NEEDED */
	PKCS11H_ASSERT (newone!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_isBetterCertificate entry current=%p, current_size=%u, newone=%p, newone_size=%u",
		current,
		current_size,
		newone,
		newone_size
	);

	/*
	 * First certificae
	 * always select
	 */
	if (current_size == 0 || current == NULL) {
		is_better = TRUE;
	}
	else {
		time_t notAfterCurrent, notAfterNew;

		notAfterCurrent = _pkcs11h_certificate_getExpiration (
			current,
			current_size
		);
		notAfterNew = _pkcs11h_certificate_getExpiration (
			newone,
			newone_size
		);

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: _pkcs11h_certificate_isBetterCertificate notAfterCurrent='%s', notAfterNew='%s'",
			asctime (localtime (&notAfterCurrent)),
			asctime (localtime (&notAfterNew))
		);

		is_better = notAfterNew > notAfterCurrent;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_isBetterCertificate return is_better=%d",
		is_better ? 1 : 0
	);
	
	return is_better;
}

static
CK_RV
_pkcs11h_certificate_newCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_newCertificateId entry p_certificate_id=%p",
		(void *)p_certificate_id
	);

	*p_certificate_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_malloc ((void *)p_certificate_id, sizeof (struct pkcs11h_certificate_id_s));
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_newCertificateId return rv=%ld-'%s', *p_certificate_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_certificate_getDN (
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const dn,
	IN const size_t dn_size
) {
#if defined(USE_PKCS11H_OPENSSL)
	X509 *x509 = NULL;
	pkcs11_openssl_d2i_t d2i1;
#elif defined(USE_PKCS11H_GNUTLS)
	gnutls_x509_crt_t cert = NULL;
#endif

	PKCS11H_ASSERT (blob_size==0||blob!=NULL);
	PKCS11H_ASSERT (dn!=NULL);

	dn[0] = '\x0';

#if defined(USE_PKCS11H_OPENSSL)

	if (blob_size > 0) {
		x509 = X509_new ();

		d2i1 = (pkcs11_openssl_d2i_t)blob;
		if (d2i_X509 (&x509, &d2i1, blob_size)) {
			X509_NAME_oneline (
				X509_get_subject_name (x509),
				dn,
				dn_size
			);
		}

		if (x509 != NULL) {
			X509_free (x509);
			x509 = NULL;
		}
	}

#elif defined(USE_PKCS11H_GNUTLS)

	if (blob_size > 0) {
		if (gnutls_x509_crt_init (&cert) == GNUTLS_E_SUCCESS) {
			gnutls_datum_t datum = {(unsigned char *)blob, blob_size};

			if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
				size_t s = dn_size;
				if (
					gnutls_x509_crt_get_dn (
						cert,
						dn,
						&s
					) != GNUTLS_E_SUCCESS
				) {
					/* gnutls sets output parameters */
					dn[0] = '\x0';
				}
			}
			gnutls_x509_crt_deinit (cert);
		}
	}

#else
#error Invalid configuration
#endif

	return CKR_OK;
}

static
CK_RV
_pkcs11h_certificate_loadCertificate (
	IN const pkcs11h_certificate_t certificate
) {
	/*
	 * THREADING:
	 * certificate->mutex must be locked
	 */
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)},
		{CKA_ID, NULL, 0}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (certificate->id!=NULL);
	
	/* Must be after assert */
	cert_filter[1].pValue = certificate->id->attrCKA_ID;
	cert_filter[1].ulValueLen = certificate->id->attrCKA_ID_size;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_loadCertificate entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (certificate->session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_findObjects (
			certificate->session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_VALUE, NULL, 0}
		};

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_session_getObjectAttributes (
				certificate->session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			)) == CKR_OK
		) {
			if (
				_pkcs11h_certificate_isBetterCertificate (
					certificate->id->certificate_blob,
					certificate->id->certificate_blob_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				)
			) {
				if (certificate->id->certificate_blob != NULL) {
					_pkcs11h_mem_free ((void *)&certificate->id->certificate_blob);
				}

				rv = _pkcs11h_mem_duplicate (
					(void*)&certificate->id->certificate_blob,
					&certificate->id->certificate_blob_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				);
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
				certificate->session->provider->manufacturerID,
				objects[i],
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		_pkcs11h_session_freeObjectAttributes (
			attrs,
			sizeof (attrs) / sizeof (CK_ATTRIBUTE)
		);
	}
	
#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
		mutex_locked = FALSE;
	}
#endif

	if (
		rv == CKR_OK &&
		certificate->id->certificate_blob == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (objects != NULL) {
		_pkcs11h_mem_free ((void *)&objects);
	}

	/*
	 * No need to free allocated objects
	 * on error, since the certificate_id
	 * should be free by caller.
	 */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_loadCertificate return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_certificate_updateCertificateIdDescription (
	IN OUT pkcs11h_certificate_id_t certificate_id
) {
	static const char * separator = " on ";
	static const char * unknown = "UNKNOWN";

	PKCS11H_ASSERT (certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_updateCertificateIdDescription entry certificate_id=%p",
		(void *)certificate_id
	);

	certificate_id->displayName[0] = '\x0';

	_pkcs11h_certificate_getDN (
		certificate_id->certificate_blob,
		certificate_id->certificate_blob_size,
		certificate_id->displayName,
		sizeof (certificate_id->displayName)
	);

	if (strlen (certificate_id->displayName) == 0) {
		strncpy (
			certificate_id->displayName,
			unknown,
			sizeof (certificate_id->displayName)-1
		);
	}

	/*
	 * Try to avoid using snprintf,
	 * may be unavailable
	 */
	strncat (
		certificate_id->displayName,
		separator,
		sizeof (certificate_id->displayName)-1-strlen (certificate_id->displayName)
	);
	strncat (
		certificate_id->displayName,
		certificate_id->token_id->display,
		sizeof (certificate_id->displayName)-1-strlen (certificate_id->displayName)
	);
	certificate_id->displayName[sizeof (certificate_id->displayName) - 1] = '\0';

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_updateCertificateIdDescription return displayName='%s'",
		certificate_id->displayName
	);

	return CKR_OK;
}

static
CK_RV
_pkcs11h_certificate_getKeyAttributes (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;

	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_getKeyAttributes entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	certificate->mask_sign_mode = 0;

	while (rv == CKR_OK && !op_succeed) {
		CK_ATTRIBUTE key_attrs[] = {
			{CKA_SIGN, NULL, 0},
			{CKA_SIGN_RECOVER, NULL, 0}
		};

		/*
		 * Don't try invalid object
		 */
		if (
			rv == CKR_OK &&
			certificate->key_handle == PKCS11H_INVALID_OBJECT_HANDLE
		) {
			rv = CKR_OBJECT_HANDLE_INVALID;
		}

		if (rv == CKR_OK) {
			if (certificate->session->provider->mask_sign_mode != 0) {
				certificate->mask_sign_mode = certificate->session->provider->mask_sign_mode;
				op_succeed = TRUE;
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Key attributes enforced by provider (%08x)",
					certificate->mask_sign_mode
				);
			}
		}

		if (rv == CKR_OK && !op_succeed) {
			rv = _pkcs11h_session_getObjectAttributes (
				certificate->session,
				certificate->key_handle,
				key_attrs,
				sizeof (key_attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (rv == CKR_OK && !op_succeed) {
			CK_BBOOL *key_attrs_sign = (CK_BBOOL *)key_attrs[0].pValue;
			CK_BBOOL *key_attrs_sign_recover = (CK_BBOOL *)key_attrs[1].pValue;

			if (key_attrs_sign != NULL && *key_attrs_sign != CK_FALSE) {
				certificate->mask_sign_mode |= PKCS11H_SIGNMODE_MASK_SIGN;
			}
			if (key_attrs_sign_recover != NULL && *key_attrs_sign_recover != CK_FALSE) {
				certificate->mask_sign_mode |= PKCS11H_SIGNMODE_MASK_RECOVER;
			}
			if (certificate->mask_sign_mode == 0) {
				rv = CKR_KEY_TYPE_INCONSISTENT;
			}
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Key attributes loaded (%08x)",
				certificate->mask_sign_mode
			);
		}

		_pkcs11h_session_freeObjectAttributes (
			key_attrs,
			sizeof (key_attrs) / sizeof (CK_ATTRIBUTE)
		);

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get private key attributes failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_certificate_resetSession (
					certificate,
					FALSE,
					TRUE
				);

				login_retry = TRUE;
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked = FALSE;
	}
#endif
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_getKeyAttributes return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_certificate_validateSession (
	IN const pkcs11h_certificate_t certificate
) {
	/*
	 * THREADING:
	 * certificate->mutex must be locked
	 * certificate->session->mutex must be locked
	 */
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_validateSession entry certificate=%p",
		(void *)certificate
	);

	if (certificate->session == NULL) {
		rv = CKR_SESSION_HANDLE_INVALID;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (certificate->session);
	}

	if (rv == CKR_OK) {
		if (certificate->key_handle == PKCS11H_INVALID_OBJECT_HANDLE) {
			rv = CKR_OBJECT_HANDLE_INVALID;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_validateSession return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
_pkcs11h_certificate_resetSession (
	IN const pkcs11h_certificate_t certificate,
	IN const PKCS11H_BOOL public_only,
	IN const PKCS11H_BOOL session_mutex_locked
) {
	/*
	 * THREADING:
	 * certificate->mutex must be locked
	 */
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	PKCS11H_BOOL is_key_valid = FALSE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (certificate!=NULL);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_resetSession entry certificate=%p, public_only=%d, session_mutex_locked=%d",
		(void *)certificate,
		public_only ? 1 : 0,
		session_mutex_locked ? 1 : 0
	);

	if (rv == CKR_OK && certificate->session == NULL) {
		rv = _pkcs11h_session_getSessionByTokenId (certificate->id->token_id, &certificate->session);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		!session_mutex_locked &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		!certificate->pin_cache_populated_to_session
	) {
		certificate->pin_cache_populated_to_session = TRUE;

		if (certificate->pin_cache_period != PKCS11H_PIN_CACHE_INFINITE) {
			if (certificate->session->pin_cache_period != PKCS11H_PIN_CACHE_INFINITE) {
				if (certificate->session->pin_cache_period > certificate->pin_cache_period) {
					certificate->session->pin_expire_time = (
						certificate->session->pin_expire_time -
						(time_t)certificate->session->pin_cache_period +
						(time_t)certificate->pin_cache_period
					);
					certificate->session->pin_cache_period = certificate->pin_cache_period;
				}
			}
			else {
				certificate->session->pin_expire_time = (
					PKCS11H_TIME (NULL) +
					(time_t)certificate->pin_cache_period
				);
				certificate->session->pin_cache_period = certificate->pin_cache_period;
			}
		}	
	}

	/*
	 * First, if session seems to be valid
	 * and key handle is invalid (hard-set),
	 * try to fetch key handle,
	 * maybe the token is already logged in
	 */
	if (rv == CKR_OK) {
		if (
			certificate->session->session_handle != PKCS11H_INVALID_SESSION_HANDLE &&
			certificate->key_handle == PKCS11H_INVALID_OBJECT_HANDLE
		) {
			if (!public_only || certificate->session->provider->cert_is_private) {
				if (
					(rv = _pkcs11h_session_getObjectById (
						certificate->session,
						CKO_PRIVATE_KEY,
						certificate->id->attrCKA_ID,
						certificate->id->attrCKA_ID_size,
						&certificate->key_handle
					)) == CKR_OK
				) {
					is_key_valid = TRUE;
				}
				else {
					/*
					 * Ignore error
					 */
					rv = CKR_OK;
					certificate->key_handle = PKCS11H_INVALID_OBJECT_HANDLE;
				}
			}
		}
	}

	if (
		!is_key_valid &&
		rv == CKR_OK &&
		(rv = _pkcs11h_session_login (
			certificate->session,
			public_only,
			TRUE,
			certificate->user_data,
			certificate->mask_prompt
		)) == CKR_OK
	) {
		rv = _pkcs11h_certificate_updateCertificateIdDescription (certificate->id);
	}

	if (
		!is_key_valid &&
		rv == CKR_OK &&
		!public_only &&
		(rv = _pkcs11h_session_getObjectById (
			certificate->session,
			CKO_PRIVATE_KEY,
			certificate->id->attrCKA_ID,
			certificate->id->attrCKA_ID_size,
			&certificate->key_handle
		)) == CKR_OK
	) {
		is_key_valid = TRUE;
	}

	if (
		rv == CKR_OK &&
		!public_only &&
		!is_key_valid
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_resetSession return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_certificate_doPrivateOperation (
	IN const pkcs11h_certificate_t certificate,
	IN const enum _pkcs11h_private_op_e op,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_MECHANISM mech = {
		mech_type, NULL, 0
	};
	
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL login_retry = FALSE;
	PKCS11H_BOOL op_succeed = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_doPrivateOperation entry certificate=%p, op=%d, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		op,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {
		if (rv == CKR_OK && !certificate->operation_active) {
			rv = _pkcs11h_certificate_validateSession (certificate);
		}

		if (rv == CKR_OK && !certificate->operation_active) {
			switch (op) {
				case _pkcs11h_private_op_sign:
					rv = certificate->session->provider->f->C_SignInit (
						certificate->session->session_handle,
						&mech,
						certificate->key_handle
					);
				break;
				case _pkcs11h_private_op_sign_recover:
					rv = certificate->session->provider->f->C_SignRecoverInit (
						certificate->session->session_handle,
						&mech,
						certificate->key_handle
					);
				break;
				case _pkcs11h_private_op_decrypt:
					rv = certificate->session->provider->f->C_DecryptInit (
						certificate->session->session_handle,
						&mech,
						certificate->key_handle
					);
				break;
				default:
					rv = CKR_ARGUMENTS_BAD;
				break;
			}

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG2,
				"PKCS#11: _pkcs11h_certificate_doPrivateOperation init rv=%ld",
				rv
			);
		}

		if (rv == CKR_OK) {
			CK_ULONG size = *p_target_size;

			switch (op) {
				case _pkcs11h_private_op_sign:
					rv = certificate->session->provider->f->C_Sign (
						certificate->session->session_handle,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				case _pkcs11h_private_op_sign_recover:
					rv = certificate->session->provider->f->C_SignRecover (
						certificate->session->session_handle,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				case _pkcs11h_private_op_decrypt:
					rv = certificate->session->provider->f->C_Decrypt (
						certificate->session->session_handle,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				default:
					rv = CKR_ARGUMENTS_BAD;
				break;
			}

			*p_target_size = size;

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG2,
				"PKCS#11: _pkcs11h_certificate_doPrivateOperation op rv=%ld",
				rv
			);
		}
		
		if (
			target == NULL &&
			(
				rv == CKR_BUFFER_TOO_SMALL ||
				rv == CKR_OK
			)
		) {
			certificate->operation_active = TRUE;
			rv = CKR_OK;
		}
		else {
			certificate->operation_active = FALSE;
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			/*
			 * OpenSC workaround
			 * It still allows C_FindObjectsInit when
			 * token is removed/inserted but fails
			 * private key operation.
			 * So we force logout.
			 * bug#108 at OpenSC trac
			 */
			if (login_retry && rv == CKR_DEVICE_REMOVED) {
				login_retry = FALSE;
				_pkcs11h_session_logout (certificate->session);
			}

			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Private key operation failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				login_retry = TRUE;
				rv = _pkcs11h_certificate_resetSession (
					certificate,
					FALSE,
					TRUE
				);
			}
		}

	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_doPrivateOperation return rv=%ld-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_freeCertificateId (
	IN pkcs11h_certificate_id_t certificate_id
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificateId entry certificate_id=%p",
		(void *)certificate_id
	);

	if (certificate_id->attrCKA_ID != NULL) {
		_pkcs11h_mem_free ((void *)&certificate_id->attrCKA_ID);
	}
	if (certificate_id->certificate_blob != NULL) {
		_pkcs11h_mem_free ((void *)&certificate_id->certificate_blob);
	}
	if (certificate_id->token_id != NULL) {
		pkcs11h_token_freeTokenId (certificate_id->token_id);
		certificate_id->token_id = NULL;
	}
	_pkcs11h_mem_free ((void *)&certificate_id);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificateId return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_certificate_duplicateCertificateId (
	OUT pkcs11h_certificate_id_t * const to,
	IN const pkcs11h_certificate_id_t from
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (to!=NULL);
	PKCS11H_ASSERT (from!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_duplicateCertificateId entry to=%p form=%p",
		(void *)to,
		(void *)from
	);

	*to = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)to,
			NULL,
			from,
			sizeof (struct pkcs11h_certificate_id_s)
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)&(*to)->token_id,
			NULL,
			from->token_id,
			sizeof (struct pkcs11h_token_id_s)
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)&(*to)->attrCKA_ID,
			&(*to)->attrCKA_ID_size,
			from->attrCKA_ID,
			from->attrCKA_ID_size
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)&(*to)->certificate_blob,
			&(*to)->certificate_blob_size,
			from->certificate_blob,
			from->certificate_blob_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_duplicateCertificateId return rv=%ld-'%s', *to=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*to
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_setCertificateIdCertificateBlob (
	IN const pkcs11h_certificate_id_t certificate_id,
	IN const unsigned char * const blob,
	IN const size_t blob_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate_id!=NULL);
	PKCS11H_ASSERT (blob!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_setCertificateIdCertificateBlob entry certificate_id=%p",
		(void *)certificate_id
	);

	if (rv == CKR_OK && certificate_id->certificate_blob != NULL) {
		rv = _pkcs11h_mem_free ((void *)&certificate_id->certificate_blob);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void *)&certificate_id->certificate_blob,
			&certificate_id->certificate_blob_size,
			blob,
			blob_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_setCertificateIdCertificateBlob return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_freeCertificate (
	IN pkcs11h_certificate_t certificate
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificate entry certificate=%p",
		(void *)certificate
	);

	if (certificate != NULL) {
		if (certificate->session != NULL) {
			_pkcs11h_session_release (certificate->session);
		}
		pkcs11h_certificate_freeCertificateId (certificate->id);
		certificate->id = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexFree (&certificate->mutex);
#endif

		_pkcs11h_mem_free ((void *)&certificate);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificate return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_certificate_lockSession (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);

	if (rv == CKR_OK && certificate->session == NULL) {
		rv = _pkcs11h_session_getSessionByTokenId (certificate->id->token_id, &certificate->session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex);
	}

	return rv;
#else
	return CKR_OK;
#endif
}

CK_RV
pkcs11h_certificate_releaseSession (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);

	if (certificate->session != NULL) {
		rv = _pkcs11h_threading_mutexRelease (&certificate->session->mutex);
	}

	return rv;
#else
	return CKR_OK;
#endif
}

CK_RV
pkcs11h_certificate_sign (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_sign entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_doPrivateOperation (
			certificate,
			_pkcs11h_private_op_sign,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_sign return rv=%ld-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_signRecover (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signRecover entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_doPrivateOperation (
			certificate,
			_pkcs11h_private_op_sign_recover,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signRecover return rv=%ld-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_signAny (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL fSigned = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signAny entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (
		rv == CKR_OK &&
		certificate->mask_sign_mode == 0
	) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Getting key attributes"
		);
		rv = _pkcs11h_certificate_getKeyAttributes (certificate);
	}

	if (
		rv == CKR_OK &&
		!fSigned &&
		(certificate->mask_sign_mode & PKCS11H_SIGNMODE_MASK_SIGN) != 0
	) {
		rv = pkcs11h_certificate_sign (
			certificate,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);

		if (rv == CKR_OK) {
			fSigned = TRUE;
		}
		else if (
			rv == CKR_FUNCTION_NOT_SUPPORTED ||
			rv == CKR_KEY_FUNCTION_NOT_PERMITTED
		) {
			certificate->mask_sign_mode &= ~PKCS11H_SIGNMODE_MASK_SIGN;
			rv = CKR_OK;
		}
	}
	
	if (
		rv == CKR_OK &&
		!fSigned &&
		(certificate->mask_sign_mode & PKCS11H_SIGNMODE_MASK_RECOVER) != 0
	) {
		rv = pkcs11h_certificate_signRecover (
			certificate,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);

		if (rv == CKR_OK) {
			fSigned = TRUE;
		}
		else if (
			rv == CKR_FUNCTION_NOT_SUPPORTED ||
			rv == CKR_KEY_FUNCTION_NOT_PERMITTED
		) {
			certificate->mask_sign_mode &= ~PKCS11H_SIGNMODE_MASK_RECOVER;
			rv = CKR_OK;
		}
	}

	if (rv == CKR_OK && !fSigned) {
		rv = CKR_FUNCTION_FAILED;
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signAny return rv=%ld-'%s', *p_target_size=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_decrypt (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_decrypt entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_doPrivateOperation (
			certificate,
			_pkcs11h_private_op_decrypt,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_decrypt return rv=%ld-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_create (
	IN const pkcs11h_certificate_id_t certificate_id,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	IN const int pin_cache_period,
	OUT pkcs11h_certificate_t * const p_certificate
) {
	pkcs11h_certificate_t certificate = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	/*PKCS11H_ASSERT (user_data!=NULL); NOT NEEDED */
	PKCS11H_ASSERT (p_certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_create entry certificate_id=%p, user_data=%p, mask_prompt=%08x, pin_cache_period=%d, p_certificate=%p",
		(void *)certificate_id,
		user_data,
		mask_prompt,
		pin_cache_period,
		(void *)p_certificate
	);

	*p_certificate = NULL;

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mem_malloc ((void*)&certificate, sizeof (struct pkcs11h_certificate_s))) == CKR_OK
	) {
		certificate->user_data = user_data;
		certificate->mask_prompt = mask_prompt;
		certificate->key_handle = PKCS11H_INVALID_OBJECT_HANDLE;
		certificate->pin_cache_period = pin_cache_period;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (rv == CKR_OK) {
		rv = _pkcs11h_threading_mutexInit (&certificate->mutex);
	}
#endif

	if (rv == CKR_OK) {
		rv = pkcs11h_certificate_duplicateCertificateId (&certificate->id, certificate_id);
	}

	if (rv == CKR_OK) {
		*p_certificate = certificate;
		certificate = NULL;
	}

	if (certificate != NULL) {
#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexFree (&certificate->mutex);
#endif
		_pkcs11h_mem_free ((void *)&certificate);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_create return rv=%ld-'%s' *p_certificate=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate
	);
	
	return rv;
}

unsigned
pkcs11h_certificate_getPromptMask (
	IN const pkcs11h_certificate_t certificate
) {
	PKCS11H_ASSERT (certificate!=NULL);

	return certificate->mask_prompt;
}

void
pkcs11h_certificate_setPromptMask (
	IN const pkcs11h_certificate_t certificate,
	IN const unsigned mask_prompt
) {
	PKCS11H_ASSERT (certificate!=NULL);

	certificate->mask_prompt = mask_prompt;
}

void *
pkcs11h_certificate_getUserData (
	IN const pkcs11h_certificate_t certificate
) {
	PKCS11H_ASSERT (certificate!=NULL);

	return certificate->user_data;
}

void
pkcs11h_certificate_setUserData (
	IN const pkcs11h_certificate_t certificate,
	IN void * const user_data
) {
	PKCS11H_ASSERT (certificate!=NULL);

	certificate->user_data = user_data;
}

CK_RV
pkcs11h_certificate_getCertificateId (
	IN const pkcs11h_certificate_t certificate,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateId entry certificate=%p, certificate_id=%p",
		(void *)certificate,
		(void *)p_certificate_id
	);

	if (rv == CKR_OK) {
		rv = pkcs11h_certificate_duplicateCertificateId (
			p_certificate_id,
			certificate->id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateId return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_certificate_getCertificateBlob (
	IN const pkcs11h_certificate_t certificate,
	OUT unsigned char * const certificate_blob,
	IN OUT size_t * const p_certificate_blob_size
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_RV rv = CKR_OK;
	size_t certifiate_blob_size_max = 0;
	
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	/*PKCS11H_ASSERT (certificate_blob!=NULL); NOT NEEDED */
	PKCS11H_ASSERT (p_certificate_blob_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateBlob entry certificate=%p, certificate_blob=%p, *p_certificate_blob_size=%u",
		(void *)certificate,
		certificate_blob,
		certificate_blob != NULL ? *p_certificate_blob_size : 0
	);

	if (certificate_blob != NULL) {
		certifiate_blob_size_max = *p_certificate_blob_size;
	}
	*p_certificate_blob_size = 0;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK && certificate->id->certificate_blob == NULL) {
		PKCS11H_BOOL op_succeed = FALSE;
		PKCS11H_BOOL login_retry = FALSE;
		while (rv == CKR_OK && !op_succeed) {
			if (certificate->session == NULL) {
				rv = CKR_SESSION_HANDLE_INVALID;
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_certificate_loadCertificate (certificate);
			}

			if (rv == CKR_OK) {
				op_succeed = TRUE;
			}
			else {
				if (!login_retry) {
					login_retry = TRUE;
					rv = _pkcs11h_certificate_resetSession (
						certificate,
						TRUE,
						FALSE
					);
				}
			}
		}
	}
	
	if (
		rv == CKR_OK &&
		certificate->id->certificate_blob == NULL
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

	if (rv == CKR_OK) {
		_pkcs11h_certificate_updateCertificateIdDescription (certificate->id);
	}

	if (rv == CKR_OK) {
		*p_certificate_blob_size = certificate->id->certificate_blob_size;
	}

	if (certificate_blob != NULL) {
		if (
			rv == CKR_OK &&
			certificate->id->certificate_blob_size > certifiate_blob_size_max
		) {
			rv = CKR_BUFFER_TOO_SMALL;
		}
	
		if (rv == CKR_OK) {
			memmove (
				certificate_blob,
				certificate->id->certificate_blob,
				*p_certificate_blob_size
			);
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateBlob return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

#if defined(ENABLE_PKCS11H_SERIALIZATION)

CK_RV
pkcs11h_certificate_serializeCertificateId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_certificate_id_t certificate_id
) {
	CK_RV rv = CKR_OK;
	size_t saved_max = 0;
	size_t n = 0;
	size_t _max = 0;

	/*PKCS11H_ASSERT (sz!=NULL); Not required */
	PKCS11H_ASSERT (max!=NULL);
	PKCS11H_ASSERT (certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_serializeCertificateId entry sz=%p, *max=%u, certificate_id=%p",
		sz,
		sz != NULL ? *max : 0,
		(void *)certificate_id
	);

	if (sz != NULL) {
		saved_max = n = *max;
	}
	*max = 0;

	if (rv == CKR_OK) {
		rv = pkcs11h_token_serializeTokenId (
			sz,
			&n,
			certificate_id->token_id
		);
	}

	if (rv == CKR_OK) {
		_max = n + certificate_id->attrCKA_ID_size*2 + 1;
	}

	if (sz != NULL) {
		if (saved_max < _max) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
		}

		if (rv == CKR_OK) {
			sz[n-1] = '/';
			rv = _pkcs11h_util_binaryToHex (
				sz+n,
				saved_max-n,
				certificate_id->attrCKA_ID,
				certificate_id->attrCKA_ID_size
			);

		}
	}

	*max = _max;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_serializeCertificateId return rv=%ld-'%s', *max=%u, sz='%s'",
		rv,
		pkcs11h_getMessage (rv),
		*max,
		sz
	);

	return rv;
}

CK_RV
pkcs11h_certificate_deserializeCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id,
	IN const char * const sz
) {
	pkcs11h_certificate_id_t certificate_id = NULL;
	CK_RV rv = CKR_OK;
	char *p = NULL;
	char *_sz = NULL;

	PKCS11H_ASSERT (p_certificate_id!=NULL);
	PKCS11H_ASSERT (sz!=NULL);

	*p_certificate_id = NULL;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_deserializeCertificateId entry p_certificate_id=%p, sz='%s'",
		(void *)p_certificate_id,
		sz
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_strdup (
			(void *)&_sz,
			sz
		);
	}

	if (rv == CKR_OK) {
		p = _sz;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_newCertificateId (&certificate_id);
	}

	if (
		rv == CKR_OK &&
		(p = strrchr (_sz, '/')) == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (rv == CKR_OK) {
		*p = '\x0';
		p++;
	}

	if (rv == CKR_OK) {
		rv = pkcs11h_token_deserializeTokenId (
			&certificate_id->token_id,
			_sz
		);
	}

	if (rv == CKR_OK) {
		certificate_id->attrCKA_ID_size = strlen (p)/2;
	}

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mem_malloc (
			(void *)&certificate_id->attrCKA_ID,
			certificate_id->attrCKA_ID_size)
		) == CKR_OK
	) {
		rv = _pkcs11h_util_hexToBinary (
			certificate_id->attrCKA_ID,
			p,
			&certificate_id->attrCKA_ID_size
		);
	}

	if (rv == CKR_OK) {
		*p_certificate_id = certificate_id;
		certificate_id = NULL;
	}

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}

	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_deserializeCertificateId return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;

}

#endif				/* ENABLE_PKCS11H_SERIALIZATION */

CK_RV
pkcs11h_certificate_ensureCertificateAccess (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked_cert = FALSE;
	PKCS11H_BOOL mutex_locked_sess = FALSE;
#endif
	PKCS11H_BOOL validCert = FALSE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureCertificateAccess entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked_cert = TRUE;
	}
#endif

	if (!validCert && rv == CKR_OK) {
		CK_OBJECT_HANDLE h = PKCS11H_INVALID_OBJECT_HANDLE;

		if (certificate->session == NULL) {
			rv = CKR_SESSION_HANDLE_INVALID;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex)) == CKR_OK
		) {
			mutex_locked_sess = TRUE;
		}
#endif

		if (
			(rv = _pkcs11h_session_getObjectById (
				certificate->session,
				CKO_CERTIFICATE,
				certificate->id->attrCKA_ID,
				certificate->id->attrCKA_ID_size,
				&h
			)) == CKR_OK
		) {
			validCert = TRUE;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (mutex_locked_sess) {
			_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
			mutex_locked_sess = FALSE;
		}
#endif

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot access existing object rv=%ld-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}
	}

	if (!validCert && rv == CKR_OK) {
		if (
			(rv = _pkcs11h_certificate_resetSession (
				certificate,
				TRUE,
				FALSE
			)) == CKR_OK
		) {
			validCert = TRUE;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked_cert) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked_cert = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureCertificateAccess return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_ensureKeyAccess (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked_cert = FALSE;
	PKCS11H_BOOL mutex_locked_sess = FALSE;
#endif
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL valid_key = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureKeyAccess entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked_cert = TRUE;
	}
#endif

	if (!valid_key && rv == CKR_OK) {

		if (certificate->session == NULL) {
			rv = CKR_SESSION_HANDLE_INVALID;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex)) == CKR_OK
		) {
			mutex_locked_sess = TRUE;
		}
#endif

		if (
			(rv = _pkcs11h_session_getObjectById (
				certificate->session,
				CKO_PRIVATE_KEY,
				certificate->id->attrCKA_ID,
				certificate->id->attrCKA_ID_size,
				&certificate->key_handle
			)) == CKR_OK
		) {
			valid_key = TRUE;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (mutex_locked_sess) {
			_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
			mutex_locked_sess = FALSE;
		}
#endif

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot access existing object rv=%ld-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
			certificate->key_handle = PKCS11H_INVALID_OBJECT_HANDLE;
		}
	}

	if (!valid_key && rv == CKR_OK) {
		if (
			(rv = _pkcs11h_certificate_resetSession (
				certificate,
				FALSE,
				FALSE
			)) == CKR_OK
		) {
			valid_key = TRUE;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked_sess) {
		_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
		mutex_locked_sess = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureKeyAccess return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_LOCATE)
/*======================================================================*
 * LOCATE INTERFACE
 *======================================================================*/

#if defined(ENABLE_PKCS11H_TOKEN) || defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotId (
	IN const char * const slot,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;
	char reference[sizeof (((pkcs11h_provider_t)NULL)->reference)];

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (slot!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotId entry slot='%s', p_token_id=%p",
		slot,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	if (rv == CKR_OK) {
		if (strchr (slot, ':') == NULL) {
			reference[0] = '\0';
			selected_slot = atol (slot);
		}
		else {
			char *p;

			strncpy (reference, slot, sizeof (reference));
			reference[sizeof (reference)-1] = '\0';

			p = strchr (reference, ':');

			*p = '\0';
			p++;
			selected_slot = atol (p);
		}
	}
	
	if (rv == CKR_OK) {
		current_provider=s_pkcs11h_data->providers;
		while (
			current_provider != NULL &&
			reference[0] != '\0' &&		/* So first provider will be selected */
			strcmp (current_provider->reference, reference)
		) {
			current_provider = current_provider->next;
		}
	
		if (
			current_provider == NULL ||
			(
				current_provider != NULL &&
				!current_provider->enabled
			)
		) {
			rv = CKR_SLOT_ID_INVALID;
		}
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_token_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotId return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotName (
	IN const char * const name,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL found = FALSE;

	PKCS11H_ASSERT (name!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotName entry name='%s', p_token_id=%p",
		name,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	current_provider = s_pkcs11h_data->providers;
	while (
		current_provider != NULL &&
		rv == CKR_OK &&
		!found
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->enabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK &&
				!found
			);
			slot_index++
		) {
			CK_SLOT_INFO info;

			if (
				(rv = current_provider->f->C_GetSlotInfo (
					slots[slot_index],
					&info
				)) == CKR_OK
			) {
				char current_name[sizeof (info.slotDescription)+1];

				_pkcs11h_util_fixupFixedString (
					current_name,
					(char *)info.slotDescription,
					sizeof (info.slotDescription)
				);

				if (!strcmp (current_name, name)) {
					found = TRUE;
					selected_slot = slots[slot_index];
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get slot information for provider '%s' slot %ld rv=%ld-'%s'",
					current_provider->manufacturerID,
					slots[slot_index],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_mem_free ((void *)&slots);
			slots = NULL;
		}

		if (!found) {
			current_provider = current_provider->next;
		}
	}

	if (rv == CKR_OK && !found) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_token_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotName return rv=%ld-'%s' *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv; 
}

static
CK_RV
_pkcs11h_locate_getTokenIdByLabel (
	IN const char * const label,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL found = FALSE;

	PKCS11H_ASSERT (label!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdByLabel entry label='%s', p_token_id=%p",
		label,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	current_provider = s_pkcs11h_data->providers;
	while (
		current_provider != NULL &&
		rv == CKR_OK &&
		!found
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->enabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK &&
				!found
			);
			slot_index++
		) {
			CK_TOKEN_INFO info;

			if (rv == CKR_OK) {
				rv = current_provider->f->C_GetTokenInfo (
					slots[slot_index],
					&info
				);
			}

			if (rv == CKR_OK) {
				char current_label[sizeof (info.label)+1];
		
				_pkcs11h_util_fixupFixedString (
					current_label,
					(char *)info.label,
					sizeof (info.label)
				);

				if (!strcmp (current_label, label)) {
					found = TRUE;
					selected_slot = slots[slot_index];
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get token information for provider '%s' slot %ld rv=%ld-'%s'",
					current_provider->manufacturerID,
					slots[slot_index],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_mem_free ((void *)&slots);
			slots = NULL;
		}

		if (!found) {
			current_provider = current_provider->next;
		}
	}

	if (rv == CKR_OK && !found) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_token_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdByLabel return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

CK_RV
pkcs11h_locate_token (
	IN const char * const slot_type,
	IN const char * const slot,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_token_id_t * const p_token_id
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif

	pkcs11h_token_id_t dummy_token_id = NULL;
	pkcs11h_token_id_t token_id = NULL;
	PKCS11H_BOOL found = FALSE;
	
	CK_RV rv = CKR_OK;

	unsigned nRetry = 0;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (slot_type!=NULL);
	PKCS11H_ASSERT (slot!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locate_token entry slot_type='%s', slot='%s', user_data=%p, p_token_id=%p",
		slot_type,
		slot,
		user_data,
		(void *)p_token_id
	);

	*p_token_id = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_token_newTokenId (&dummy_token_id)) == CKR_OK
	) {
		/*
		 * Temperary slot id
		 */
		strcpy (dummy_token_id->display, "SLOT(");
		strncat (dummy_token_id->display, slot_type, sizeof (dummy_token_id->display)-1-strlen (dummy_token_id->display));
		strncat (dummy_token_id->display, "=", sizeof (dummy_token_id->display)-1-strlen (dummy_token_id->display));
		strncat (dummy_token_id->display, slot, sizeof (dummy_token_id->display)-1-strlen (dummy_token_id->display));
		strncat (dummy_token_id->display, ")", sizeof (dummy_token_id->display)-1-strlen (dummy_token_id->display));
		dummy_token_id->display[sizeof (dummy_token_id->display)-1] = 0;
	}

	while (rv == CKR_OK && !found) {
		if (!strcmp (slot_type, "id")) {
			rv = _pkcs11h_locate_getTokenIdBySlotId (
				slot,
				&token_id
			);
		}
		else if (!strcmp (slot_type, "name")) {
			rv = _pkcs11h_locate_getTokenIdBySlotName (
				slot,
				&token_id
			);
		}
		else if (!strcmp (slot_type, "label")) {
			rv = _pkcs11h_locate_getTokenIdByLabel (
				slot,
				&token_id
			);
		}
		else {
			rv = CKR_ARGUMENTS_BAD;
		}

		if (rv == CKR_OK) {
			found = TRUE;
		}

		/*
		 * Ignore error, since we have what we
		 * want in found.
		 */
		if (rv != CKR_OK && rv != CKR_ARGUMENTS_BAD) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: pkcs11h_locate_token failed rv=%ld-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			rv = CKR_OK;
		}

		if (rv == CKR_OK && !found && (mask_prompt & PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT) == 0) {
			rv = CKR_TOKEN_NOT_PRESENT;
		}

		if (rv == CKR_OK && !found) {

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling token_prompt hook for '%s'",
				dummy_token_id->display
			);
	
			if (
				!s_pkcs11h_data->hooks.token_prompt (
					s_pkcs11h_data->hooks.token_prompt_data,
					user_data,
					dummy_token_id,
					nRetry++
				)
			) {
				rv = CKR_CANCEL;
			}

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: token_prompt returned %ld",
				rv
			);
		}
	}

	if (rv == CKR_OK && !found) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (rv == CKR_OK) {
		*p_token_id = token_id;
		token_id = NULL;
	}

	if (dummy_token_id != NULL) {
		pkcs11h_token_freeTokenId (dummy_token_id);
		dummy_token_id = NULL;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.global);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locate_token return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

#endif				/* ENABLE_PKCS11H_TOKEN || ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_locate_getCertificateIdByLabel (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const label
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)},
		{CKA_LABEL, (CK_BYTE_PTR)label, strlen (label)}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (certificate_id!=NULL);
	PKCS11H_ASSERT (label!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdByLabel entry session=%p, certificate_id=%p, label='%s'",
		(void *)session,
		(void *)certificate_id,
		label
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_findObjects (
			session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_ID, NULL, 0},
			{CKA_VALUE, NULL, 0}
		};

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getObjectAttributes (
				session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (
			rv == CKR_OK &&
			_pkcs11h_certificate_isBetterCertificate (
				certificate_id->certificate_blob,
				certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			)
		) {
			if (certificate_id->attrCKA_ID != NULL) {
				_pkcs11h_mem_free ((void *)&certificate_id->attrCKA_ID);
			}
			if (certificate_id->certificate_blob != NULL) {
				_pkcs11h_mem_free ((void *)&certificate_id->certificate_blob);
			}
			rv = _pkcs11h_mem_duplicate (
				(void *)&certificate_id->attrCKA_ID,
				&certificate_id->attrCKA_ID_size,
				attrs[0].pValue,
				attrs[0].ulValueLen
			);
			rv = _pkcs11h_mem_duplicate (
				(void *)&certificate_id->certificate_blob,
				&certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			);
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
				session->provider->manufacturerID,
				objects[i],
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		_pkcs11h_session_freeObjectAttributes (
			attrs,
			sizeof (attrs) / sizeof (CK_ATTRIBUTE)
		);
	}
	
	if (
		rv == CKR_OK &&
		certificate_id->certificate_blob == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (objects != NULL) {
		_pkcs11h_mem_free ((void *)&objects);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	/*
	 * No need to free allocated objects
	 * on error, since the certificate_id
	 * should be free by caller.
	 */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdByLabel return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_locate_getCertificateIdBySubject (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const subject
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (certificate_id!=NULL);
	PKCS11H_ASSERT (subject!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdBySubject entry session=%p, certificate_id=%p, subject='%s'",
		(void *)session,
		(void *)certificate_id,
		subject
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_findObjects (
			session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_ID, NULL, 0},
			{CKA_VALUE, NULL, 0}
		};
		char current_subject[1024];
		current_subject[0] = '\0';

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getObjectAttributes (
				session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_certificate_getDN (
				attrs[1].pValue,
				attrs[1].ulValueLen,
				current_subject,
				sizeof (current_subject)
			);
		}

		if (
			rv == CKR_OK &&
			!strcmp (subject, current_subject) &&
			_pkcs11h_certificate_isBetterCertificate (
				certificate_id->certificate_blob,
				certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			)
		) {
			if (certificate_id->attrCKA_ID != NULL) {
				_pkcs11h_mem_free ((void *)&certificate_id->attrCKA_ID);
			}
			if (certificate_id->certificate_blob != NULL) {
				_pkcs11h_mem_free ((void *)&certificate_id->certificate_blob);
			}
			rv = _pkcs11h_mem_duplicate (
				(void *)&certificate_id->attrCKA_ID,
				&certificate_id->attrCKA_ID_size,
				attrs[0].pValue,
				attrs[0].ulValueLen
			);
			rv = _pkcs11h_mem_duplicate (
				(void *)&certificate_id->certificate_blob,
				&certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			);
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
				session->provider->manufacturerID,
				objects[i],
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		_pkcs11h_session_freeObjectAttributes (
			attrs,
			sizeof (attrs) / sizeof (CK_ATTRIBUTE)
		);
	}
	
	if (
		rv == CKR_OK &&
		certificate_id->certificate_blob == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (objects != NULL) {
		_pkcs11h_mem_free ((void *)&objects);
	}

	/*
	 * No need to free allocated objects
	 * on error, since the certificate_id
	 * should be free by caller.
	 */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdBySubject return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_locate_certificate (
	IN const char * const slot_type,
	IN const char * const slot,
	IN const char * const id_type,
	IN const char * const id,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_certificate_id_t certificate_id = NULL;
	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;
	
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (slot_type!=NULL);
	PKCS11H_ASSERT (slot!=NULL);
	PKCS11H_ASSERT (id_type!=NULL);
	PKCS11H_ASSERT (id!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locateCertificate entry slot_type='%s', slot='%s', id_type='%s', id='%s', user_data=%p, mask_prompt=%08x, p_certificate_id=%p",
		slot_type,
		slot,
		id_type,
		id,
		user_data,
		mask_prompt,
		(void *)p_certificate_id
	);

	*p_certificate_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_newCertificateId (&certificate_id);
	}

	if (rv == CKR_OK) {
		rv = pkcs11h_locate_token (
			slot_type,
			slot,
			user_data,
			mask_prompt,
			&certificate_id->token_id
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_getSessionByTokenId (
			certificate_id->token_id,
			&session
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {
		if (!strcmp (id_type, "id")) {
			certificate_id->attrCKA_ID_size = strlen (id)/2;

			if (certificate_id->attrCKA_ID_size == 0) {
				rv = CKR_FUNCTION_FAILED;
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_mem_malloc (
					(void*)&certificate_id->attrCKA_ID,
					certificate_id->attrCKA_ID_size
				)) == CKR_OK
			) {
				_pkcs11h_util_hexToBinary (
					certificate_id->attrCKA_ID,
					id,
					&certificate_id->attrCKA_ID_size
				);
			}
		}
		else if (!strcmp (id_type, "label")) {
			rv = _pkcs11h_locate_getCertificateIdByLabel (
				session,
				certificate_id,
				id
			);
		}
		else if (!strcmp (id_type, "subject")) {
			rv = _pkcs11h_locate_getCertificateIdBySubject (
				session,
				certificate_id,
				id
			);
		}
		else {
			rv = CKR_ARGUMENTS_BAD;
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get certificate failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_session_login (
					session,
					TRUE,
					TRUE,
					user_data,
					mask_prompt
				);

				login_retry = TRUE;
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.global);
		mutex_locked = FALSE;
	}
#endif

	if (rv == CKR_OK) {
		*p_certificate_id = certificate_id;
		certificate_id = NULL;
	}

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locateCertificate return rv=%ld-'%s' *p_certificate_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate_id
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_LOCATE */

#if defined(ENABLE_PKCS11H_ENUM)
/*======================================================================*
 * ENUM INTERFACE
 *======================================================================*/

#if defined(ENABLE_PKCS11H_TOKEN)

CK_RV
pkcs11h_token_freeTokenIdList (
	IN const pkcs11h_token_id_list_t token_id_list
) {
	pkcs11h_token_id_list_t _id = token_id_list;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	/*PKCS11H_ASSERT (token_id_list!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_freeTokenIdList entry token_id_list=%p",
		(void *)token_id_list
	);

	while (_id != NULL) {
		pkcs11h_token_id_list_t x = _id;
		_id = _id->next;
		if (x->token_id != NULL) {
			pkcs11h_token_freeTokenId (x->token_id);
		}
		x->next = NULL;
		_pkcs11h_mem_free ((void *)&x);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_freeTokenIdList return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_token_enumTokenIds (
	IN const int method,
	OUT pkcs11h_token_id_list_t * const p_token_id_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif

	pkcs11h_token_id_list_t token_id_list = NULL;
	pkcs11h_provider_t current_provider;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (p_token_id_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_enumTokenIds entry p_token_id_list=%p",
		(void *)p_token_id_list
	);

	*p_token_id_list = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.global)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	for (
		current_provider = s_pkcs11h_data->providers;
		(
			current_provider != NULL &&
			rv == CKR_OK
		);
		current_provider = current_provider->next
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->enabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK
			);
			slot_index++
		) {
			pkcs11h_token_id_list_t entry = NULL;
			CK_TOKEN_INFO info;

			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_malloc ((void *)&entry, sizeof (struct pkcs11h_token_id_list_s));
			}

			if (rv == CKR_OK) {
				rv = current_provider->f->C_GetTokenInfo (
					slots[slot_index],
					&info
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_token_getTokenId (
					&info,
					&entry->token_id
				);
			}

			if (rv == CKR_OK) {
				entry->next = token_id_list;
				token_id_list = entry;
				entry = NULL;
			}

			if (entry != NULL) {
				pkcs11h_token_freeTokenIdList (entry);
				entry = NULL;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_mem_free ((void *)&slots);
			slots = NULL;
		}
	}

	if (rv == CKR_OK && method == PKCS11H_ENUM_METHOD_CACHE) {
		pkcs11h_session_t session = NULL;

		for (
			session = s_pkcs11h_data->sessions;
			session != NULL && rv == CKR_OK;
			session = session->next
		) {
			pkcs11h_token_id_list_t entry = NULL;
			PKCS11H_BOOL found = FALSE;

			for (
				entry = token_id_list;
				entry != NULL && !found;
				entry = entry->next
			) {
				if (
					pkcs11h_token_sameTokenId (
						session->token_id,
						entry->token_id
					)
				) {
					found = TRUE;
				}
			}

			if (!found) {
				entry = NULL;

				if (rv == CKR_OK) {
					rv = _pkcs11h_mem_malloc (
						(void *)&entry,
						sizeof (struct pkcs11h_token_id_list_s)
					);
				}

				if (rv == CKR_OK) {
					rv = pkcs11h_token_duplicateTokenId (
						&entry->token_id,
						session->token_id
					);
				}

				if (rv == CKR_OK) {
					entry->next = token_id_list;
					token_id_list = entry;
					entry = NULL;
				}

				if (entry != NULL) {
					if (entry->token_id != NULL) {
						pkcs11h_token_freeTokenId (entry->token_id);
					}
					_pkcs11h_mem_free ((void *)&entry);
				}
			}
		}
	}

	if (rv == CKR_OK) {
		*p_token_id_list = token_id_list;
		token_id_list = NULL;
	}

	if (token_id_list != NULL) {
		pkcs11h_token_freeTokenIdList (token_id_list);
		token_id_list = NULL;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		rv = _pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.global);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_enumTokenIds return rv=%ld-'%s', *p_token_id_list=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)p_token_id_list
	);
	
	return rv;
}

#endif

#if defined(ENABLE_PKCS11H_DATA)

CK_RV
pkcs11h_data_freeDataIdList (
	IN const pkcs11h_data_id_list_t data_id_list
) {
	pkcs11h_data_id_list_t _id = data_id_list;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	/*PKCS11H_ASSERT (data_id_list!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeDataIdList entry token_id_list=%p",
		(void *)data_id_list
	);

	while (_id != NULL) {
		pkcs11h_data_id_list_t x = _id;
		_id = _id->next;

		if (x->application != NULL) {
			_pkcs11h_mem_free ((void *)&x->application);
		}
		if (x->label != NULL) {
			_pkcs11h_mem_free ((void *)&x->label);
		}
		_pkcs11h_mem_free ((void *)&x);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_freeDataIdList return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_data_enumDataObjects (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL is_public,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_data_id_list_t * const p_data_id_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	pkcs11h_data_id_list_t data_id_list = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (p_data_id_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_enumDataObjects entry token_id=%p, is_public=%d, user_data=%p, mask_prompt=%08x, p_data_id_list=%p",
		(void *)token_id,
		is_public ? 1 : 0,
		user_data,
		mask_prompt,
		(void *)p_data_id_list
	);

	*p_data_id_list = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_getSessionByTokenId (
			token_id,
			&session
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {

		CK_OBJECT_CLASS class = CKO_DATA;
		CK_ATTRIBUTE filter[] = {
			{CKA_CLASS, (void *)&class, sizeof (class)}
		};
		CK_OBJECT_HANDLE *objects = NULL;
		CK_ULONG objects_found = 0;

		CK_ULONG i;

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_validate (session);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_findObjects (
				session,
				filter,
				sizeof (filter) / sizeof (CK_ATTRIBUTE),
				&objects,
				&objects_found
			);
		}

		for (i = 0;rv == CKR_OK && i < objects_found;i++) {
			pkcs11h_data_id_list_t entry = NULL;

			CK_ATTRIBUTE attrs[] = {
				{CKA_APPLICATION, NULL, 0},
				{CKA_LABEL, NULL, 0}
			};

			if (rv == CKR_OK) {
				rv = _pkcs11h_session_getObjectAttributes (
					session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				);
			}
			
			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_malloc (
					(void *)&entry,
					sizeof (struct pkcs11h_data_id_list_s)
				);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_mem_malloc (
					(void *)&entry->application,
					attrs[0].ulValueLen+1
				)) == CKR_OK
			) {
				memmove (entry->application, attrs[0].pValue, attrs[0].ulValueLen);
				entry->application[attrs[0].ulValueLen] = '\0';
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_mem_malloc (
					(void *)&entry->label,
					attrs[1].ulValueLen+1
				)) == CKR_OK
			) {
				memmove (entry->label, attrs[1].pValue, attrs[1].ulValueLen);
				entry->label[attrs[1].ulValueLen] = '\0';
			}

			if (rv == CKR_OK) {
				entry->next = data_id_list;
				data_id_list = entry;
				entry = NULL;
			}

			_pkcs11h_session_freeObjectAttributes (
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);

			if (entry != NULL) {
				if (entry->application != NULL) {
					_pkcs11h_mem_free ((void *)&entry->application);
				}
				if (entry->label != NULL) {
					_pkcs11h_mem_free ((void *)&entry->label);
				}
				_pkcs11h_mem_free ((void *)&entry);
			}
		}

		if (objects != NULL) {
			_pkcs11h_mem_free ((void *)&objects);
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Enumerate data objects failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				login_retry = TRUE;
				rv = _pkcs11h_session_login (
					session,
					is_public,
					TRUE,
					user_data,
					mask_prompt
				);
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	if (rv == CKR_OK) {
		*p_data_id_list = data_id_list;
		data_id_list = NULL;
	}

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	if (data_id_list != NULL) {
		pkcs11h_data_freeDataIdList (data_id_list);
		data_id_list = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_enumDataObjects return rv=%ld-'%s', *p_data_id_list=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_data_id_list
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_DATA */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_certificate_enumSessionCertificates (
	IN const pkcs11h_session_t session,
	IN void * const user_data,
	IN const unsigned mask_prompt
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;

	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_enumSessionCertificates entry session=%p, user_data=%p, mask_prompt=%08x",
		(void *)session,
		user_data,
		mask_prompt
	);
	
	/* THREADS: NO NEED TO LOCK, GLOBAL CACHE IS LOCKED */
#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {
		CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
		CK_ATTRIBUTE cert_filter[] = {
			{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)}
		};

		CK_OBJECT_HANDLE *objects = NULL;
		CK_ULONG objects_found = 0;

		CK_ULONG i;

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_validate (session);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_findObjects (
				session,
				cert_filter,
				sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
				&objects,
				&objects_found
			);
		}
			
		for (i=0;rv == CKR_OK && i < objects_found;i++) {
			pkcs11h_certificate_id_t certificate_id = NULL;
			pkcs11h_certificate_id_list_t new_element = NULL;
			
			CK_ATTRIBUTE attrs[] = {
				{CKA_ID, NULL, 0},
				{CKA_VALUE, NULL, 0}
			};

			if (rv == CKR_OK) {
				rv = _pkcs11h_session_getObjectAttributes (
					session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_certificate_newCertificateId (&certificate_id)) == CKR_OK
			) {
				rv = pkcs11h_token_duplicateTokenId (
					&certificate_id->token_id,
					session->token_id
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_duplicate (
					(void*)&certificate_id->attrCKA_ID,
					&certificate_id->attrCKA_ID_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_duplicate (
					(void*)&certificate_id->certificate_blob,
					&certificate_id->certificate_blob_size,
					attrs[1].pValue,
					attrs[1].ulValueLen
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_certificate_updateCertificateIdDescription (certificate_id);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_mem_malloc (
					(void *)&new_element,
					sizeof (struct pkcs11h_certificate_id_list_s)
				)) == CKR_OK
			) {
				new_element->next = session->cached_certs;
				new_element->certificate_id = certificate_id;
				certificate_id = NULL;

				session->cached_certs = new_element;
				new_element = NULL;
			}

			if (certificate_id != NULL) {
				pkcs11h_certificate_freeCertificateId (certificate_id);
				certificate_id = NULL;
			}

			if (new_element != NULL) {
				_pkcs11h_mem_free ((void *)&new_element);
				new_element = NULL;
			}

			_pkcs11h_session_freeObjectAttributes (
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
					session->provider->manufacturerID,
					objects[i],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}
		}

		if (objects != NULL) {
			_pkcs11h_mem_free ((void *)&objects);
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get certificate attributes failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_session_login (
					session,
					TRUE,
					TRUE,
					user_data,
					(mask_prompt & PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT)
				);

				login_retry = TRUE;
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_enumSessionCertificates return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_certificate_splitCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_all,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
	typedef struct info_s {
		struct info_s *next;
		pkcs11h_certificate_id_t e;
#if defined(USE_PKCS11H_OPENSSL)
		X509 *x509;
#elif defined(USE_PKCS11H_GNUTLS)
		gnutls_x509_crt_t cert;
#endif
		PKCS11H_BOOL is_issuer;
	} *info_t;

	pkcs11h_certificate_id_list_t cert_id_issuers_list = NULL;
	pkcs11h_certificate_id_list_t cert_id_end_list = NULL;

	info_t head = NULL;
	info_t info = NULL;

	CK_RV rv = CKR_OK;

	/*PKCS11H_ASSERT (cert_id_all!=NULL); NOT NEEDED */
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_splitCertificateIdList entry cert_id_all=%p, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		(void *)cert_id_all,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

	if (rv == CKR_OK) {
		pkcs11h_certificate_id_list_t entry = NULL;

		for (
			entry = cert_id_all;
			entry != NULL && rv == CKR_OK;
			entry = entry->next
		) {
			info_t new_info = NULL;

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_mem_malloc ((void *)&new_info, sizeof (struct info_s))) == CKR_OK &&
				entry->certificate_id->certificate_blob != NULL
			) {
#if defined(USE_PKCS11H_OPENSSL)
				pkcs11_openssl_d2i_t d2i = (pkcs11_openssl_d2i_t)entry->certificate_id->certificate_blob;
#endif

				new_info->next = head;
				new_info->e = entry->certificate_id;
#if defined(USE_PKCS11H_OPENSSL)
				new_info->x509 = X509_new ();
				if (
					new_info->x509 != NULL &&
					!d2i_X509 (
						&new_info->x509,
						&d2i,
						entry->certificate_id->certificate_blob_size
					)
				) {
					X509_free (new_info->x509);
					new_info->x509 = NULL;
				}
#elif defined(USE_PKCS11H_GNUTLS)
				if (gnutls_x509_crt_init (&new_info->cert) != GNUTLS_E_SUCCESS) {
					/* gnutls sets output */
					new_info->cert = NULL;
				}
				else {
					gnutls_datum_t datum = {
						entry->certificate_id->certificate_blob,
						entry->certificate_id->certificate_blob_size
					};

					if (
						gnutls_x509_crt_import (
							new_info->cert,
							&datum,
							GNUTLS_X509_FMT_DER
						) != GNUTLS_E_SUCCESS
					) {
						gnutls_x509_crt_deinit (new_info->cert);
						new_info->cert = NULL;
					}
				}
#else
#error Invalid configuration.
#endif
				head = new_info;
				new_info = NULL;
			}
		}

	}

	if (rv == CKR_OK) {
		for (
			info = head;
			info != NULL;
			info = info->next
		) {
			info_t info2 = NULL;
#if defined(USE_PKCS11H_OPENSSL)
			EVP_PKEY *pub = X509_get_pubkey (info->x509);
#endif

			for (
				info2 = head;
				info2 != NULL && !info->is_issuer;
				info2 = info2->next
			) {
				if (info != info2) {
#if defined(USE_PKCS11H_OPENSSL)
					if (
						info->x509 != NULL &&
						info2->x509 != NULL &&
						!X509_NAME_cmp (
							X509_get_subject_name (info->x509),
							X509_get_issuer_name (info2->x509)
						) &&
						X509_verify (info2->x509, pub) == 1
					) {
						info->is_issuer = TRUE;
					}
#elif defined(USE_PKCS11H_GNUTLS)
					unsigned result;

					if (
						info->cert != NULL &&
						info2->cert != NULL &&
						gnutls_x509_crt_verify (
							info2->cert,
							&info->cert,
							1,
							0,
							&result
						) &&
						(result & GNUTLS_CERT_INVALID) == 0
					) {
						info->is_issuer = TRUE;
					}
#else
#error Invalid configuration.
#endif
				}

			}

#if defined(USE_PKCS11H_OPENSSL)
			if (pub != NULL) {
				EVP_PKEY_free (pub);
				pub = NULL;
			}
#endif
		}
	}

	if (rv == CKR_OK) {
		for (
			info = head;
			info != NULL && rv == CKR_OK;
			info = info->next
		) {
			pkcs11h_certificate_id_list_t new_entry = NULL;

			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_malloc (
					(void *)&new_entry,
					sizeof (struct pkcs11h_certificate_id_list_s)
				);
			}

			if (
				rv == CKR_OK &&
				(rv = pkcs11h_certificate_duplicateCertificateId (
					&new_entry->certificate_id,
					info->e
				)) == CKR_OK
			) {
				/*
				 * Should not free base list
				 */
				info->e = NULL;
			}

			if (rv == CKR_OK) {
				if (info->is_issuer) {
					new_entry->next = cert_id_issuers_list;
					cert_id_issuers_list = new_entry;
					new_entry = NULL;
				}
				else {
					new_entry->next = cert_id_end_list;
					cert_id_end_list = new_entry;
					new_entry = NULL;
				}
			}

			if (new_entry != NULL) {
				if (new_entry->certificate_id != NULL) {
					pkcs11h_certificate_freeCertificateId (new_entry->certificate_id);
				}
				_pkcs11h_mem_free ((void *)&new_entry);
			}
		}
	}

	if (rv == CKR_OK) {
		while (head != NULL) {
			info_t entry = head;
			head = head->next;

#if defined(USE_PKCS11H_OPENSSL)
			if (entry->x509 != NULL) {
				X509_free (entry->x509);
				entry->x509 = NULL;
			}
#elif defined(USE_PKCS11H_GNUTLS)
			if (entry->cert != NULL) {
				gnutls_x509_crt_deinit (entry->cert);
				entry->cert = NULL;
			}
#else
#error Invalid configuration.
#endif

			_pkcs11h_mem_free ((void *)&entry);
		}
	}

	if (rv == CKR_OK && p_cert_id_issuers_list != NULL ) {
		*p_cert_id_issuers_list = cert_id_issuers_list;
		cert_id_issuers_list = NULL;
	}

	if (rv == CKR_OK) {
		*p_cert_id_end_list = cert_id_end_list;
		cert_id_end_list = NULL;
	}

	if (cert_id_issuers_list != NULL) {
		pkcs11h_certificate_freeCertificateIdList (cert_id_issuers_list);
	}

	if (cert_id_end_list != NULL) {
		pkcs11h_certificate_freeCertificateIdList (cert_id_end_list);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_splitCertificateIdList return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_certificate_freeCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_list
) {
	pkcs11h_certificate_id_list_t _id = cert_id_list;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	/*PKCS11H_ASSERT (cert_id_list!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificateIdList entry cert_id_list=%p",
		(void *)cert_id_list
	);

	while (_id != NULL) {
		pkcs11h_certificate_id_list_t x = _id;
		_id = _id->next;
		if (x->certificate_id != NULL) {
			pkcs11h_certificate_freeCertificateId (x->certificate_id);
		}
		x->next = NULL;
		_pkcs11h_mem_free ((void *)&x);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificateIdList return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_certificate_enumTokenCertificateIds (
	IN const pkcs11h_token_id_t token_id,
	IN const int method,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	PKCS11H_ASSERT (token_id!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_enumTokenCertificateIds entry token_id=%p, method=%d, user_data=%p, mask_prompt=%08x, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		(void *)token_id,
		method,
		user_data,
		mask_prompt,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.cache)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_session_getSessionByTokenId (
			token_id,
			&session
		)) == CKR_OK
	) {
		if (method == PKCS11H_ENUM_METHOD_RELOAD) {
			pkcs11h_certificate_freeCertificateIdList (session->cached_certs);
			session->cached_certs = NULL;
		}

		if (session->cached_certs == NULL) {
			rv = _pkcs11h_certificate_enumSessionCertificates (session, user_data, mask_prompt);
		}
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_splitCertificateIdList (
			session->cached_certs,
			p_cert_id_issuers_list,
			p_cert_id_end_list
		);
	}

	if (session != NULL) {
		_pkcs11h_session_release (session);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.cache);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_enumTokenCertificateIds return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_enumCertificateIds (
	IN const int method,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_certificate_id_list_t cert_id_list = NULL;
	pkcs11h_provider_t current_provider;
	pkcs11h_session_t current_session;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->initialized);
	/*PKCS11H_ASSERT (user_data!=NULL); NOT NEEDED*/
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_enumCertificateIds entry method=%d, mask_prompt=%08x, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		method,
		mask_prompt,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&s_pkcs11h_data->mutexes.cache)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	for (
		current_session = s_pkcs11h_data->sessions;
		current_session != NULL;
		current_session = current_session->next
	) {
		current_session->touch = FALSE;
		if (method == PKCS11H_ENUM_METHOD_RELOAD) {
			pkcs11h_certificate_freeCertificateIdList (current_session->cached_certs);
			current_session->cached_certs = NULL;
		}
	}

	for (
		current_provider = s_pkcs11h_data->providers;
		(
			current_provider != NULL &&
			rv == CKR_OK
		);
		current_provider = current_provider->next
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->enabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK
			);
			slot_index++
		) {
			pkcs11h_session_t session = NULL;
			pkcs11h_token_id_t token_id = NULL;
			CK_TOKEN_INFO info;

			if (rv == CKR_OK) {
				rv = current_provider->f->C_GetTokenInfo (
					slots[slot_index],
					&info
				);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_token_getTokenId (
					&info,
					&token_id
				)) == CKR_OK &&
				(rv = _pkcs11h_session_getSessionByTokenId (
					token_id,
					&session
				)) == CKR_OK
			) {
				session->touch = TRUE;

				if (session->cached_certs == NULL) {
					rv = _pkcs11h_certificate_enumSessionCertificates (session, user_data, mask_prompt);
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get token information for provider '%s' slot %ld rv=%ld-'%s'",
					current_provider->manufacturerID,
					slots[slot_index],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}

			if (session != NULL) {
				_pkcs11h_session_release (session);
				session = NULL;
			}

			if (token_id != NULL) {
				pkcs11h_token_freeTokenId (token_id);
				token_id = NULL;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_mem_free ((void *)&slots);
			slots = NULL;
		}
	}

	for (
		current_session = s_pkcs11h_data->sessions;
		(
			current_session != NULL &&
			rv == CKR_OK
		);
		current_session = current_session->next
	) {
		if (
			method == PKCS11H_ENUM_METHOD_CACHE ||
			(
				(
					method == PKCS11H_ENUM_METHOD_RELOAD ||
					method == PKCS11H_ENUM_METHOD_CACHE_EXIST
				) &&
				current_session->touch
			)
		) {
			pkcs11h_certificate_id_list_t entry = NULL;

			for (
				entry = current_session->cached_certs;
				(
					entry != NULL &&
					rv == CKR_OK
				);
				entry = entry->next
			) {
				pkcs11h_certificate_id_list_t new_entry = NULL;

				if (
					rv == CKR_OK &&
					(rv = _pkcs11h_mem_malloc (
						(void *)&new_entry,
						sizeof (struct pkcs11h_certificate_id_list_s)
					)) == CKR_OK &&
					(rv = pkcs11h_certificate_duplicateCertificateId (
						&new_entry->certificate_id,
						entry->certificate_id
					)) == CKR_OK
				) {
					new_entry->next = cert_id_list;
					cert_id_list = new_entry;
					new_entry = NULL;
				}

				if (new_entry != NULL) {
					new_entry->next = NULL;
					pkcs11h_certificate_freeCertificateIdList (new_entry);
					new_entry = NULL;
				}
			}
		}
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_splitCertificateIdList (
			cert_id_list,
			p_cert_id_issuers_list,
			p_cert_id_end_list
		);
	}

	if (cert_id_list != NULL) {
		pkcs11h_certificate_freeCertificateIdList (cert_id_list);
		cert_id_list = NULL;
	}


#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&s_pkcs11h_data->mutexes.cache);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_enumCertificateIds return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_ENUM */

#if defined(ENABLE_PKCS11H_SLOTEVENT)
/*======================================================================*
 * SLOTEVENT INTERFACE
 *======================================================================*/

static
unsigned long
_pkcs11h_slotevent_checksum (
	IN const unsigned char * const p,
	IN const size_t s
) {
	unsigned long r = 0;
	size_t i;
	for (i=0;i<s;i++) {
		r += p[i];
	}
	return r;
}

static
void *
_pkcs11h_slotevent_provider (
	IN void *p
) {
	pkcs11h_provider_t provider = (pkcs11h_provider_t)p;
	CK_SLOT_ID slot;
	CK_RV rv = CKR_OK;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_provider provider='%s' entry",
		provider->manufacturerID
	);

	if (rv == CKR_OK && !provider->enabled) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
	}

	if (rv == CKR_OK) {

		if (provider->slot_poll_interval == 0) {
			provider->slot_poll_interval = PKCS11H_DEFAULT_SLOTEVENT_POLL;
		}

		/*
		 * If we cannot finalize, we cannot cause
		 * WaitForSlotEvent to terminate
		 */
		if (!provider->should_finalize) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Setup slotevent provider='%s' mode hardset to poll",
				provider->manufacturerID
			);
			provider->slot_event_method = PKCS11H_SLOTEVENT_METHOD_POLL;
		}

		if (
			provider->slot_event_method == PKCS11H_SLOTEVENT_METHOD_AUTO ||
			provider->slot_event_method == PKCS11H_SLOTEVENT_METHOD_TRIGGER
		) { 
			if (
				provider->f->C_WaitForSlotEvent (
					CKF_DONT_BLOCK,
					&slot,
					NULL_PTR
				) == CKR_FUNCTION_NOT_SUPPORTED
			) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Setup slotevent provider='%s' mode is poll",
					provider->manufacturerID
				);

				provider->slot_event_method = PKCS11H_SLOTEVENT_METHOD_POLL;
			}
			else {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Setup slotevent provider='%s' mode is trigger",
					provider->manufacturerID
				);

				provider->slot_event_method = PKCS11H_SLOTEVENT_METHOD_TRIGGER;
			}
		}
	}

	if (provider->slot_event_method == PKCS11H_SLOTEVENT_METHOD_TRIGGER) {
		while (
			!s_pkcs11h_data->slotevent.should_terminate &&
			provider->enabled &&
			rv == CKR_OK &&
			(rv = provider->f->C_WaitForSlotEvent (
				0,
				&slot,
				NULL_PTR
			)) == CKR_OK
		) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent provider='%s' event",
				provider->manufacturerID
			);

			_pkcs11h_threading_condSignal (&s_pkcs11h_data->slotevent.cond_event);
		}
	}
	else {
		unsigned long ulLastChecksum = 0;
		PKCS11H_BOOL is_first_time = TRUE;

		while (
			!s_pkcs11h_data->slotevent.should_terminate &&
			provider->enabled &&
			rv == CKR_OK
		) {
			unsigned long ulCurrentChecksum = 0;

			CK_SLOT_ID_PTR slots = NULL;
			CK_ULONG slotnum;

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent provider='%s' poll",
				provider->manufacturerID
			);

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_session_getSlotList (
					provider,
					TRUE,
					&slots,
					&slotnum
				)) == CKR_OK
			) {
				CK_ULONG i;
				
				for (i=0;i<slotnum;i++) {
					CK_TOKEN_INFO info;

					if (provider->f->C_GetTokenInfo (slots[i], &info) == CKR_OK) {
						ulCurrentChecksum += (
							_pkcs11h_slotevent_checksum (
								info.label,
								sizeof (info.label)
							) +
							_pkcs11h_slotevent_checksum (
								info.manufacturerID,
								sizeof (info.manufacturerID)
							) +
							_pkcs11h_slotevent_checksum (
								info.model,
								sizeof (info.model)
							) +
							_pkcs11h_slotevent_checksum (
								info.serialNumber,
								sizeof (info.serialNumber)
							)
						);
					}
				}
			}
			
			if (rv == CKR_OK) {
				if (is_first_time) {
					is_first_time = FALSE;
				}
				else {
					if (ulLastChecksum != ulCurrentChecksum) {
						PKCS11H_DEBUG (
							PKCS11H_LOG_DEBUG1,
							"PKCS#11: Slotevent provider='%s' event",
							provider->manufacturerID
						);

						_pkcs11h_threading_condSignal (&s_pkcs11h_data->slotevent.cond_event);
					}
				}
				ulLastChecksum = ulCurrentChecksum;
			}

			if (slots != NULL) {
				_pkcs11h_mem_free ((void *)&slots);
			}
			
			if (!s_pkcs11h_data->slotevent.should_terminate) {
				_pkcs11h_threading_sleep (provider->slot_poll_interval);
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_provider provider='%s' return",
		provider->manufacturerID
	);

	return NULL;
}

static
void *
_pkcs11h_slotevent_manager (
	IN void *p
) {
	PKCS11H_BOOL first_time = TRUE;

	(void)p;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_manager entry"
	);

	/*
	 * Trigger hook, so application may
	 * depend on initial slot change
	 */
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Calling slotevent hook"
	);
	s_pkcs11h_data->hooks.slotevent (s_pkcs11h_data->hooks.slotevent_data);

	while (
		first_time ||	/* Must enter wait or mutex will never be free */
		!s_pkcs11h_data->slotevent.should_terminate
	) {
		pkcs11h_provider_t current_provider;

		first_time = FALSE;

		/*
		 * Start each provider thread
		 * if not already started.
		 * This is required in order to allow
		 * adding new providers.
		 */
		for (
			current_provider = s_pkcs11h_data->providers;
			current_provider != NULL;
			current_provider = current_provider->next
		) {
			if (!current_provider->enabled) {
				if (current_provider->slotevent_thread == PKCS11H_THREAD_NULL) {
					_pkcs11h_threading_threadStart (
						&current_provider->slotevent_thread,
						_pkcs11h_slotevent_provider,
						current_provider
					);
				}
			}
			else {
				if (current_provider->slotevent_thread != PKCS11H_THREAD_NULL) {
					_pkcs11h_threading_threadJoin (&current_provider->slotevent_thread);
				}
			}
		}

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: _pkcs11h_slotevent_manager waiting for slotevent"
		);
		_pkcs11h_threading_condWait (&s_pkcs11h_data->slotevent.cond_event, PKCS11H_COND_INFINITE);

		if (s_pkcs11h_data->slotevent.skip_event) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent skipping event"
			);
			s_pkcs11h_data->slotevent.skip_event = FALSE;
		}
		else {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling slotevent hook"
			);
			s_pkcs11h_data->hooks.slotevent (s_pkcs11h_data->hooks.slotevent_data);
		}
	}

	{
		pkcs11h_provider_t current_provider;

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: _pkcs11h_slotevent_manager joining threads"
		);


		for (
			current_provider = s_pkcs11h_data->providers;
			current_provider != NULL;
			current_provider = current_provider->next
		) {
			if (current_provider->slotevent_thread != PKCS11H_THREAD_NULL) {
				_pkcs11h_threading_threadJoin (&current_provider->slotevent_thread);
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_manager return"
	);

	return NULL;
}

static
CK_RV
_pkcs11h_slotevent_init () {
	CK_RV rv = CKR_OK;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_init entry"
	);

	if (!s_pkcs11h_data->slotevent.initialized) {
		if (rv == CKR_OK) {
			rv = _pkcs11h_threading_condInit (&s_pkcs11h_data->slotevent.cond_event);
		}
		
		if (rv == CKR_OK) {
			rv = _pkcs11h_threading_threadStart (
				&s_pkcs11h_data->slotevent.thread,
				_pkcs11h_slotevent_manager,
				NULL
			);
		}
		
		if (rv == CKR_OK) {
			s_pkcs11h_data->slotevent.initialized = TRUE;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_init return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_slotevent_notify () {
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_notify entry"
	);

	if (s_pkcs11h_data->slotevent.initialized) {
		s_pkcs11h_data->slotevent.skip_event = TRUE;
		_pkcs11h_threading_condSignal (&s_pkcs11h_data->slotevent.cond_event);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_notify return"
	);

	return CKR_OK;
}

static
CK_RV
_pkcs11h_slotevent_terminate () {
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_terminate entry"
	);

	if (s_pkcs11h_data->slotevent.initialized) {
		s_pkcs11h_data->slotevent.should_terminate = TRUE;

		_pkcs11h_slotevent_notify ();

		if (s_pkcs11h_data->slotevent.thread != PKCS11H_THREAD_NULL) {
			_pkcs11h_threading_threadJoin (&s_pkcs11h_data->slotevent.thread);
		}

		_pkcs11h_threading_condFree (&s_pkcs11h_data->slotevent.cond_event);
		s_pkcs11h_data->slotevent.initialized = FALSE;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_terminate return"
	);

	return CKR_OK;
}

#endif

#if defined(ENABLE_PKCS11H_OPENSSL)
/*======================================================================*
 * OPENSSL INTERFACE
 *======================================================================*/

static
pkcs11h_openssl_session_t
_pkcs11h_openssl_get_openssl_session (
	IN OUT const RSA *rsa
) {
	pkcs11h_openssl_session_t session;
		
	PKCS11H_ASSERT (rsa!=NULL);
#if OPENSSL_VERSION_NUMBER < 0x00907000L
	session = (pkcs11h_openssl_session_t)RSA_get_app_data ((RSA *)rsa);
#else
	session = (pkcs11h_openssl_session_t)RSA_get_app_data (rsa);
#endif
	PKCS11H_ASSERT (session!=NULL);

	return session;
}

static
pkcs11h_certificate_t
_pkcs11h_openssl_get_pkcs11h_certificate (
	IN OUT const RSA *rsa
) {
	pkcs11h_openssl_session_t session = _pkcs11h_openssl_get_openssl_session (rsa);
	
	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (session->certificate!=NULL);

	return session->certificate;
}

#if OPENSSL_VERSION_NUMBER < 0x00907000L
static
int
_pkcs11h_openssl_dec (
	IN int flen,
	IN unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
#else
static
int
_pkcs11h_openssl_dec (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
#endif
	PKCS11H_ASSERT (from!=NULL);
	PKCS11H_ASSERT (to!=NULL);
	PKCS11H_ASSERT (rsa!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_dec entered - flen=%d, from=%p, to=%p, rsa=%p, padding=%d",
		flen,
		from,
		to,
		(void *)rsa,
		padding
	);

	PKCS11H_LOG (
		PKCS11H_LOG_ERROR,
		"PKCS#11: Private key decryption is not supported"
	);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_dec return"
	);

	return -1;
}

#if OPENSSL_VERSION_NUMBER < 0x00907000L
static
int
_pkcs11h_openssl_sign (
	IN int type,
	IN unsigned char *m,
	IN unsigned int m_len,
	OUT unsigned char *sigret,
	OUT unsigned int *siglen,
	IN OUT RSA *rsa
) {
#else
static
int
_pkcs11h_openssl_sign (
	IN int type,
	IN const unsigned char *m,
	IN unsigned int m_len,
	OUT unsigned char *sigret,
	OUT unsigned int *siglen,
	IN OUT const RSA *rsa
) {
#endif
	pkcs11h_certificate_t certificate = _pkcs11h_openssl_get_pkcs11h_certificate (rsa);
	PKCS11H_BOOL session_locked = FALSE;
	CK_RV rv = CKR_OK;

	int myrsa_size = 0;
	
	unsigned char *enc_alloc = NULL;
	unsigned char *enc = NULL;
	int enc_len = 0;

	PKCS11H_ASSERT (m!=NULL);
	PKCS11H_ASSERT (sigret!=NULL);
	PKCS11H_ASSERT (siglen!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_sign entered - type=%d, m=%p, m_len=%u, signret=%p, *signlen=%u, rsa=%p",
		type,
		m,
		m_len,
		sigret,
		sigret != NULL ? *siglen : 0,
		(void *)rsa
	);

	if (rv == CKR_OK) {
		myrsa_size=RSA_size(rsa);
	}

	if (type == NID_md5_sha1) {
		if (rv == CKR_OK) {
			enc = (unsigned char *)m;
			enc_len = m_len;
		}
	}
	else {
		X509_SIG sig;
		ASN1_TYPE parameter;
		X509_ALGOR algor;
		ASN1_OCTET_STRING digest;
		unsigned char *p = NULL;

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mem_malloc ((void*)&enc, myrsa_size+1)) == CKR_OK
		) {
			enc_alloc = enc;
		}
		
		if (rv == CKR_OK) {
			sig.algor = &algor;
		}

		if (
			rv == CKR_OK &&
			(sig.algor->algorithm = OBJ_nid2obj (type)) == NULL
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	
		if (
			rv == CKR_OK &&
			sig.algor->algorithm->length == 0
		) {
			rv = CKR_KEY_SIZE_RANGE;
		}
	
		if (rv == CKR_OK) {
			parameter.type = V_ASN1_NULL;
			parameter.value.ptr = NULL;
	
			sig.algor->parameter = &parameter;

			sig.digest = &digest;
			sig.digest->data = (unsigned char *)m;
			sig.digest->length = m_len;
		}
	
		if (
			rv == CKR_OK &&
			(enc_len=i2d_X509_SIG (&sig, NULL)) < 0
		) {
			rv = CKR_FUNCTION_FAILED;
		}

		/*
		 * d_X509_SIG increments pointer!
		 */
		p = enc;
	
		if (
			rv == CKR_OK &&
			(enc_len=i2d_X509_SIG (&sig, &p)) < 0
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	}

	if (
		rv == CKR_OK &&
		enc_len > (myrsa_size-RSA_PKCS1_PADDING_SIZE)
	) {
		rv = CKR_KEY_SIZE_RANGE;
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_certificate_lockSession (certificate)) == CKR_OK
	) {
		session_locked = TRUE;
	}

	if (rv == CKR_OK) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Performing signature"
		);

		*siglen = myrsa_size;

		if (
			(rv = pkcs11h_certificate_signAny (
				certificate,
				CKM_RSA_PKCS,
				enc,
				enc_len,
				sigret,
				siglen
			)) != CKR_OK
		) {
			PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		}
	}

	if (session_locked) {
		pkcs11h_certificate_releaseSession (certificate);
		session_locked = FALSE;
	}

	if (enc_alloc != NULL) {
		_pkcs11h_mem_free ((void *)&enc_alloc);
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_sign - return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK ? 1 : -1; 
}

static
int
_pkcs11h_openssl_finish (
	IN OUT RSA *rsa
) {
	pkcs11h_openssl_session_t openssl_session = _pkcs11h_openssl_get_openssl_session (rsa);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_finish - entered rsa=%p",
		(void *)rsa
	);

	RSA_set_app_data (rsa, NULL);
	
	if (openssl_session->orig_finish != NULL) {
		openssl_session->orig_finish (rsa);

#ifdef BROKEN_OPENSSL_ENGINE
		{
			/* We get called TWICE here, once for
			 * releasing the key and also for
			 * releasing the engine.
			 * To prevent endless recursion, FIRST
			 * clear rsa->engine, THEN call engine->finish
			 */
			ENGINE *e = rsa->engine;
			rsa->engine = NULL;
			if (e) {
				ENGINE_finish(e);
			}
		}
#endif
	}

	pkcs11h_openssl_freeSession (openssl_session);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_finish - return"
	);
	
	return 1;
}

X509 *
pkcs11h_openssl_getX509 (
	IN const pkcs11h_certificate_t certificate
) {
	unsigned char *certificate_blob = NULL;
	size_t certificate_blob_size = 0;
	X509 *x509 = NULL;
	CK_RV rv = CKR_OK;

	pkcs11_openssl_d2i_t d2i1 = NULL;
	PKCS11H_BOOL ok = TRUE;

	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getX509 - entry certificate=%p",
		(void *)certificate
	);

	if (
		ok &&
		(x509 = X509_new ()) == NULL
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Unable to allocate certificate object");
	}

	if (
		ok &&
		pkcs11h_certificate_getCertificateBlob (
			certificate,
			NULL,
			&certificate_blob_size
		) != CKR_OK
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot read X.509 certificate from token %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		ok &&
		(rv = _pkcs11h_mem_malloc ((void *)&certificate_blob, certificate_blob_size)) != CKR_OK
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot allocate X.509 memory %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		ok &&
		pkcs11h_certificate_getCertificateBlob (
			certificate,
			certificate_blob,
			&certificate_blob_size
		) != CKR_OK
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot read X.509 certificate from token %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	d2i1 = (pkcs11_openssl_d2i_t)certificate_blob;
	if (
		ok &&
		!d2i_X509 (&x509, &d2i1, certificate_blob_size)
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Unable to parse X.509 certificate");
	}

	if (!ok) {
		X509_free (x509);
		x509 = NULL;
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getX509 - return x509=%p",
		(void *)x509
	);

	return x509;
}

pkcs11h_openssl_session_t
pkcs11h_openssl_createSession (
	IN const pkcs11h_certificate_t certificate
) {
	pkcs11h_openssl_session_t openssl_session = NULL;
	PKCS11H_BOOL ok = TRUE;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_createSession - entry"
	);

	if (
		ok &&
		_pkcs11h_mem_malloc (
			(void*)&openssl_session,
			sizeof (struct pkcs11h_openssl_session_s)) != CKR_OK
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot allocate memory");
	}

	if (ok) {
		const RSA_METHOD *def = RSA_get_default_method();

		memmove (&openssl_session->smart_rsa, def, sizeof(RSA_METHOD));

		openssl_session->orig_finish = def->finish;

		openssl_session->smart_rsa.name = "pkcs11";
		openssl_session->smart_rsa.rsa_priv_dec = _pkcs11h_openssl_dec;
		openssl_session->smart_rsa.rsa_sign = _pkcs11h_openssl_sign;
		openssl_session->smart_rsa.finish = _pkcs11h_openssl_finish;
		openssl_session->smart_rsa.flags  = RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY;
		openssl_session->certificate = certificate;
		openssl_session->reference_count = 1;
	}

	if (!ok) {
		_pkcs11h_mem_free ((void *)&openssl_session);
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_createSession - return openssl_session=%p",
		(void *)openssl_session
	);

	return openssl_session;
}

pkcs11h_hook_openssl_cleanup_t
pkcs11h_openssl_getCleanupHook (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	PKCS11H_ASSERT (openssl_session!=NULL);

	return openssl_session->cleanup_hook;
}

void
pkcs11h_openssl_setCleanupHook (
	IN const pkcs11h_openssl_session_t openssl_session,
	IN const pkcs11h_hook_openssl_cleanup_t cleanup
) {
	PKCS11H_ASSERT (openssl_session!=NULL);

	openssl_session->cleanup_hook = cleanup;
}

void
pkcs11h_openssl_freeSession (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	PKCS11H_ASSERT (openssl_session!=NULL);
	PKCS11H_ASSERT (openssl_session->reference_count>0);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_freeSession - entry openssl_session=%p, count=%d",
		(void *)openssl_session,
		openssl_session->reference_count
	);

	openssl_session->reference_count--;
	
	if (openssl_session->reference_count == 0) {
		if (openssl_session->cleanup_hook != NULL) {
			openssl_session->cleanup_hook (openssl_session->certificate);
		}

		if (openssl_session->x509 != NULL) {
			X509_free (openssl_session->x509);
			openssl_session->x509 = NULL;
		}
		if (openssl_session->certificate != NULL) {
			pkcs11h_certificate_freeCertificate (openssl_session->certificate);
			openssl_session->certificate = NULL;
		}
		
		_pkcs11h_mem_free ((void *)&openssl_session);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_freeSession - return"
	);
}

RSA *
pkcs11h_openssl_session_getRSA (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	X509 *x509 = NULL;
	RSA *rsa = NULL;
	EVP_PKEY *pubkey = NULL;
	PKCS11H_BOOL ok = TRUE;

	PKCS11H_ASSERT (openssl_session!=NULL);
	PKCS11H_ASSERT (!openssl_session->initialized);
	PKCS11H_ASSERT (openssl_session!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getRSA - entry openssl_session=%p",
		(void *)openssl_session
	);
	
	/*
	 * Dup x509 so RSA will not hold session x509
	 */
	if (
		ok &&
		(x509 = pkcs11h_openssl_session_getX509 (openssl_session)) == NULL
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get certificate object");
	}

	if (
		ok &&
		(pubkey = X509_get_pubkey (x509)) == NULL
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get public key");
	}
	
	if (
		ok &&
		pubkey->type != EVP_PKEY_RSA
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Invalid public key algorithm");
	}

	if (
		ok &&
		(rsa = EVP_PKEY_get1_RSA (pubkey)) == NULL
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get RSA key");
	}

	if (ok) {
		RSA_set_method (rsa, &openssl_session->smart_rsa);
		RSA_set_app_data (rsa, openssl_session);
		openssl_session->reference_count++;
	}
	
#ifdef BROKEN_OPENSSL_ENGINE
	if (ok) {
		if (!rsa->engine) {
			rsa->engine = ENGINE_get_default_RSA();
		}

		ENGINE_set_RSA(ENGINE_get_default_RSA(), &openssl_session->smart_rsa);
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: OpenSSL engine support is broken! Workaround enabled");
	}
#endif
		
	if (ok) {
		rsa->flags |= RSA_FLAG_SIGN_VER;
		openssl_session->initialized = TRUE;
	}
	else {
		if (rsa != NULL) {
			RSA_free (rsa);
			rsa = NULL;
		}
	}

	/*
	 * openssl objects have reference
	 * count, so release them
	 */
	if (pubkey != NULL) {
		EVP_PKEY_free (pubkey);
		pubkey = NULL;
	}

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getRSA - return rsa=%p",
		(void *)rsa
	);

	return rsa;
}

X509 *
pkcs11h_openssl_session_getX509 (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	X509 *x509 = NULL;
	PKCS11H_BOOL ok = TRUE;
	
	PKCS11H_ASSERT (openssl_session!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getX509 - entry openssl_session=%p",
		(void *)openssl_session
	);

	if (
		ok &&
		openssl_session->x509 == NULL &&
		(openssl_session->x509 = pkcs11h_openssl_getX509 (openssl_session->certificate)) == NULL
	) {	
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get certificate object");
	}

	if (
		ok &&
		(x509 = X509_dup (openssl_session->x509)) == NULL
	) {
		ok = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot duplicate certificate object");
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getX509 - return x509=%p",
		(void *)x509
	);

	return x509;
}

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
) {
	CK_RV rv = CKR_OK;

	pkcs11h_provider_t pkcs11h_provider;

	PKCS11H_ASSERT (my_output!=NULL);
	/*PKCS11H_ASSERT (global_data) NOT NEEDED */
	PKCS11H_ASSERT (provider!=NULL);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot initialize interface %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			FALSE,
			(
				PKCS11H_SIGNMODE_MASK_SIGN |
				PKCS11H_SIGNMODE_MASK_RECOVER
			),
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			FALSE
		)) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot initialize provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	/*
	 * our provider is head
	 */
	if (rv == CKR_OK) {
		pkcs11h_provider = s_pkcs11h_data->providers;
		if (pkcs11h_provider == NULL || !pkcs11h_provider->enabled) {
			my_output (global_data, "PKCS#11: Cannot get provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_GENERAL_ERROR;
		}
	}

	if (rv == CKR_OK) {
		CK_INFO info;
		
		if ((rv = pkcs11h_provider->f->C_GetInfo (&info)) != CKR_OK) {
			my_output (global_data, "PKCS#11: Cannot get PKCS#11 provider information %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_OK;
		}
		else {
			char manufacturerID[sizeof (info.manufacturerID)+1];
	
			_pkcs11h_util_fixupFixedString (
				manufacturerID,
				(char *)info.manufacturerID,
				sizeof (info.manufacturerID)
			);
	
			my_output (
				global_data,
				(
					"Provider Information:\n"
					"\tcryptokiVersion:\t%u.%u\n"
					"\tmanufacturerID:\t\t%s\n"
					"\tflags:\t\t\t%08x\n"
					"\n"
				),
				info.cryptokiVersion.major,
				info.cryptokiVersion.minor,
				manufacturerID,
				(unsigned)info.flags
			);
		}
	}
	
	if (rv == CKR_OK) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;
		
		if (
			 _pkcs11h_session_getSlotList (
				pkcs11h_provider,
				CK_FALSE,
				&slots,
				&slotnum
			) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot get slot list %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
		}
		else {
			my_output (
				global_data,
				"The following slots are available for use with this provider.\n"
			);

#if defined(PKCS11H_PRM_SLOT_TYPE)
			my_output (
				global_data,
				(
					"Each slot shown below may be used as a parameter to a\n"
					"%s and %s options.\n"
				),
				PKCS11H_PRM_SLOT_TYPE,
				PKCS11H_PRM_SLOT_ID
			);
#endif

			my_output (
				global_data,
				(
					"\n"
					"Slots: (id - name)\n"
				)
			);

			for (slot_index=0;slot_index < slotnum;slot_index++) {
				CK_SLOT_INFO info;
	
				if (
					(rv = pkcs11h_provider->f->C_GetSlotInfo (
						slots[slot_index],
						&info
					)) == CKR_OK
				) {
					char current_name[sizeof (info.slotDescription)+1];
				
					_pkcs11h_util_fixupFixedString (
						current_name,
						(char *)info.slotDescription,
						sizeof (info.slotDescription)
					);
	
					my_output (global_data, "\t%lu - %s\n", slots[slot_index], current_name);
				}
			}
		}

		if (slots != NULL) {
			_pkcs11h_mem_free ((void *)&slots);
		}
	}
	
	pkcs11h_terminate ();
}

static
PKCS11H_BOOL
_pkcs11h_standalone_dump_objects_pin_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const pin,
	IN const size_t pin_max
) {
	(void)user_data;
	(void)token;

	/*
	 * Don't lock card
	 */
	if (retry == 0) {
		strncpy (pin, (char *)global_data, pin_max);
		return TRUE;
	}
	else {
		return FALSE;
	}
}

void
_pkcs11h_standalone_dump_objects_hex (
	IN const unsigned char * const p,
	IN const size_t p_size,
	OUT char * const sz,
	IN const size_t max,
	IN const char * const prefix
) {
	size_t j;

	sz[0] = '\0';

	for (j=0;j<p_size;j+=16) {
		char line[3*16+1];
		size_t k;

		line[0] = '\0';
		for (k=0;k<16 && j+k<p_size;k++) {
			sprintf (line+strlen (line), "%02x ", p[j+k]);
		}

		strncat (
			sz,
			prefix,
			max-1-strlen (sz)
		);
		strncat (
			sz,
			line,
			max-1-strlen (sz)
		);
		strncat (
			sz,
			"\n",
			max-1-strlen (sz)
		);
	}

	sz[max-1] = '\0';
}
	
void
pkcs11h_standalone_dump_objects (
	IN const pkcs11h_output_print_t my_output,
	IN void * const global_data,
	IN const char * const provider,
	IN const char * const slot,
	IN const char * const pin
) {
	CK_SLOT_ID s;
	CK_RV rv = CKR_OK;

	pkcs11h_provider_t pkcs11h_provider = NULL;
	pkcs11h_token_id_t token_id = NULL;
	pkcs11h_session_t session = NULL;

	PKCS11H_ASSERT (my_output!=NULL);
	/*PKCS11H_ASSERT (global_data) NOT NEEDED */
	PKCS11H_ASSERT (provider!=NULL);
	PKCS11H_ASSERT (slot!=NULL);
	PKCS11H_ASSERT (pin!=NULL);

	s = atoi (slot);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot initialize interface %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setPINPromptHook (_pkcs11h_standalone_dump_objects_pin_prompt, (void *)pin)) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot set hooks %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			FALSE,
			(
				PKCS11H_SIGNMODE_MASK_SIGN |
				PKCS11H_SIGNMODE_MASK_RECOVER
			),
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			FALSE
		)) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot initialize provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	/*
	 * our provider is head
	 */
	if (rv == CKR_OK) {
		pkcs11h_provider = s_pkcs11h_data->providers;
		if (pkcs11h_provider == NULL || !pkcs11h_provider->enabled) {
			my_output (global_data, "PKCS#11: Cannot get provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_GENERAL_ERROR;
		}
	}

	if (rv == CKR_OK) {
		CK_TOKEN_INFO info;
		
		if (
			(rv = pkcs11h_provider->f->C_GetTokenInfo (
				s,
				&info
			)) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot get token information for slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));
			/* Ignore this error */
			rv = CKR_OK;
		}
		else {
			char label[sizeof (info.label)+1];
			char manufacturerID[sizeof (info.manufacturerID)+1];
			char model[sizeof (info.model)+1];
			char serialNumberNumber[sizeof (info.serialNumber)+1];
			
			_pkcs11h_util_fixupFixedString (
				label,
				(char *)info.label,
				sizeof (info.label)
			);
			_pkcs11h_util_fixupFixedString (
				manufacturerID,
				(char *)info.manufacturerID,
				sizeof (info.manufacturerID)
			);
			_pkcs11h_util_fixupFixedString (
				model,
				(char *)info.model,
				sizeof (info.model)
			);
			_pkcs11h_util_fixupFixedString (
				serialNumberNumber,
				(char *)info.serialNumber,
				sizeof (info.serialNumber)
			);
	
			my_output (
				global_data,
				(
					"Token Information:\n"
					"\tlabel:\t\t%s\n"
					"\tmanufacturerID:\t%s\n"
					"\tmodel:\t\t%s\n"
					"\tserialNumber:\t%s\n"
					"\tflags:\t\t%08x\n"
					"\n"
				),
				label,
				manufacturerID,
				model,
				serialNumberNumber,
				(unsigned)info.flags
			);

#if defined(PKCS11H_PRM_SLOT_TYPE)
			my_output (
				global_data,
				(
					"You can access this token using\n"
					"%s \"label\" %s \"%s\" options.\n"
					"\n"
				),
				PKCS11H_PRM_SLOT_TYPE,
				PKCS11H_PRM_SLOT_ID,
				label
			);
#endif

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_token_getTokenId (
					&info,
					&token_id
				)) != CKR_OK
			) {
				my_output (global_data, "PKCS#11: Cannot get token id for slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));		
				rv = CKR_OK;
			}
		}
	}

	if (token_id != NULL) {
		if (
			(rv = _pkcs11h_session_getSessionByTokenId (
				token_id,
				&session
			)) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot session for token '%s' %ld-'%s'\n", token_id->display, rv, pkcs11h_getMessage (rv));		
			rv = CKR_OK;
		}
	}

	if (session != NULL) {
		CK_OBJECT_HANDLE *objects = NULL;
		CK_ULONG objects_found = 0;
		CK_ULONG i;

		if (
			(rv = _pkcs11h_session_login (
				session,
				FALSE,
				TRUE,
				NULL,
				PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT
			)) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot open session to token '%s' %ld-'%s'\n", session->token_id->display, rv, pkcs11h_getMessage (rv));
		}
	
		my_output (
			global_data,
			"The following objects are available for use with this token.\n"
		);

#if defined(PKCS11H_PRM_OBJ_TYPE)
		my_output (
			global_data,
			(
				"Each object shown below may be used as a parameter to\n"
				"%s and %s options.\n"
			),
			PKCS11H_PRM_OBJ_TYPE,
			PKCS11H_PRM_OBJ_ID
		);
#endif

		my_output (
			global_data,
			"\n"
		);

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_session_findObjects (
				session,
				NULL,
				0,
				&objects,
				&objects_found
			)) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot query objects for token '%s' %ld-'%s'\n", session->token_id->display, rv, pkcs11h_getMessage (rv));
		}
	
		for (i=0;rv == CKR_OK && i < objects_found;i++) {
			CK_OBJECT_CLASS attrs_class = 0;
			CK_ATTRIBUTE attrs[] = {
				{CKA_CLASS, &attrs_class, sizeof (attrs_class)}
			};

			if (
				_pkcs11h_session_getObjectAttributes (
					session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				) == CKR_OK
			) {
				if (attrs_class == CKO_CERTIFICATE) {
					CK_ATTRIBUTE attrs_cert[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0},
						{CKA_VALUE, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					unsigned char *attrs_value = NULL;
					int attrs_value_size = 0;
					char *attrs_label = NULL;
					char hex_id[1024];
					char subject[1024];
					char serialNumber[1024];
					time_t notAfter = 0;

					subject[0] = '\0';
					serialNumber[0] = '\0';


					if (
						_pkcs11h_session_getObjectAttributes (
							session,
							objects[i],
							attrs_cert,
							sizeof (attrs_cert) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_label,
							attrs_cert[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_cert[0].pValue;
						attrs_id_size = attrs_cert[0].ulValueLen;
						attrs_value = (unsigned char *)attrs_cert[2].pValue;
						attrs_value_size = attrs_cert[2].ulValueLen;

						memset (attrs_label, 0, attrs_cert[1].ulValueLen+1);
						memmove (attrs_label, attrs_cert[1].pValue, attrs_cert[1].ulValueLen);
						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							hex_id,
							sizeof (hex_id),
							"\t\t"
						);
					}

					if (attrs_value != NULL) {
#if defined(USE_PKCS11H_OPENSSL)
						X509 *x509 = NULL;
						BIO *bioSerial = NULL;
#elif defined(USE_PKCS11H_GNUTLS)
						gnutls_x509_crt_t cert = NULL;
#endif

						_pkcs11h_certificate_getDN (
							attrs_value,
							attrs_value_size,
							subject,
							sizeof (subject)
						);
						notAfter = _pkcs11h_certificate_getExpiration (
							attrs_value,
							attrs_value_size
						);
#if defined(USE_PKCS11H_OPENSSL)
						if ((x509 = X509_new ()) == NULL) {
							my_output (global_data, "Cannot create x509 context\n");
						}
						else {
							pkcs11_openssl_d2i_t d2i1 = (pkcs11_openssl_d2i_t)attrs_value;
							if (d2i_X509 (&x509, &d2i1, attrs_value_size)) {
								if ((bioSerial = BIO_new (BIO_s_mem ())) == NULL) {
									my_output (global_data, "Cannot create BIO context\n");
								}
								else {
									int n;

									i2a_ASN1_INTEGER(bioSerial, X509_get_serialNumber (x509));
									n = BIO_read (bioSerial, serialNumber, sizeof (serialNumber)-1);
									if (n<0) {
										serialNumber[0] = '\0';
									}
									else {
										serialNumber[n] = '\0';
									}
								}
							}
						}


						if (bioSerial != NULL) {
							BIO_free_all (bioSerial);
							bioSerial = NULL;
						}
						if (x509 != NULL) {
							X509_free (x509);
							x509 = NULL;
						}
#elif defined(USE_PKCS11H_GNUTLS)
						if (gnutls_x509_crt_init (&cert) == GNUTLS_E_SUCCESS) {
							gnutls_datum_t datum = {attrs_value, attrs_value_size};

							if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
								unsigned char ser[1024];
								size_t ser_size = sizeof (ser);
								if (gnutls_x509_crt_get_serial (cert, ser, &ser_size) == GNUTLS_E_SUCCESS) {
									_pkcs11h_util_binaryToHex (
										serialNumber,
										sizeof (serialNumber),
										ser,
										ser_size
									);
								}
							}
							gnutls_x509_crt_deinit (cert);
						}
#else
#error Invalid configuration.
#endif
					}

					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tCertificate\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
							"\tsubject:\t\t%s\n"
							"\tserialNumber:\t\t%s\n"
							"\tnotAfter:\t\t%s\n"
						),
						hex_id,
						attrs_label,
						subject,
						serialNumber,
						asctime (localtime (&notAfter))
					);

					_pkcs11h_mem_free ((void *)&attrs_label);

					_pkcs11h_session_freeObjectAttributes (
						attrs_cert,
						sizeof (attrs_cert) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_PRIVATE_KEY) {
					CK_BBOOL sign_recover = CK_FALSE;
					CK_BBOOL sign = CK_FALSE;
					CK_ATTRIBUTE attrs_key[] = {
						{CKA_SIGN, &sign, sizeof (sign)},
						{CKA_SIGN_RECOVER, &sign_recover, sizeof (sign_recover)}
					};
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					char *attrs_label = NULL;
					char hex_id[1024];

					pkcs11h_provider->f->C_GetAttributeValue (
						session->session_handle,
						objects[i],
						attrs_key,
						sizeof (attrs_key) / sizeof (CK_ATTRIBUTE)
					);

					if (
						_pkcs11h_session_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_key_common[0].pValue;
						attrs_id_size = attrs_key_common[0].ulValueLen;

						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);

						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							hex_id,
							sizeof (hex_id),
							"\t\t"
						);
							
					}

					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tPrivate Key\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
							"\tCKA_SIGN:\t\t%s\n"
							"\tCKA_SIGN_RECOVER:\t%s\n"
						),
						hex_id,
						attrs_label,
						sign ? "TRUE" : "FALSE",
						sign_recover ? "TRUE" : "FALSE"
					);

					_pkcs11h_mem_free ((void *)&attrs_label);

					_pkcs11h_session_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_PUBLIC_KEY) {
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					char *attrs_label = NULL;
					char hex_id[1024];

					if (
						_pkcs11h_session_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_key_common[0].pValue;
						attrs_id_size = attrs_key_common[0].ulValueLen;

						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);

						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							hex_id,
							sizeof (hex_id),
							"\t\t"
						);
							
					}

					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tPublic Key\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
						),
						hex_id,
						attrs_label
					);

					_pkcs11h_mem_free ((void *)&attrs_label);

					_pkcs11h_session_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_DATA) {
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_APPLICATION, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					char *attrs_application = NULL;
					char *attrs_label = NULL;

					if (
						_pkcs11h_session_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_application,
							attrs_key_common[0].ulValueLen+1
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						memset (attrs_application, 0, attrs_key_common[0].ulValueLen+1);
						memmove (attrs_application, attrs_key_common[0].pValue, attrs_key_common[0].ulValueLen);
						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);
					}

					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tData\n"
							"\tCKA_APPLICATION\t\t%s\n"
							"\tCKA_LABEL:\t\t%s\n"
						),
						attrs_application,
						attrs_label
					);

					_pkcs11h_mem_free ((void *)&attrs_application);
					_pkcs11h_mem_free ((void *)&attrs_label);

					_pkcs11h_session_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else {
					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tUnsupported\n"
						)
					);
				}
			}

			_pkcs11h_session_freeObjectAttributes (
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);

			/*
			 * Ignore any error and
			 * perform next iteration
			 */
			rv = CKR_OK;
		}
	
		if (objects != NULL) {
			_pkcs11h_mem_free ((void *)&objects);
		}

		/*
		 * Ignore this error
		 */
		rv = CKR_OK;
	}

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	if (token_id != NULL) {
		pkcs11h_token_freeTokenId (token_id);
		token_id = NULL;
	}
	
	pkcs11h_terminate ();
}

#endif				/* ENABLE_PKCS11H_STANDALONE */

#ifdef BROKEN_OPENSSL_ENGINE
static void broken_openssl_init() __attribute__ ((constructor));
static void  broken_openssl_init()
{
	SSL_library_init();
	ENGINE_load_openssl();
	ENGINE_register_all_RSA();
}
#endif

#else
static void dummy (void) {}
#endif				/* PKCS11H_HELPER_ENABLE */

