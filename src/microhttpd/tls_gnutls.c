/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2017 Daniel Pittman and Christian Grothoff

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file tls_gnutls.c
 * @brief GnuTLS-based TLS engine
 */

/* must come first */
#include "mhd_options.h"

#include <assert.h>
#include <gcrypt.h>

#include "internal.h"
#include "tls.h"

#ifdef GNUTLS_REQUIRE_GCRYPT
#if CRYPT_VERSION_NUMBER < 0x010600
#if defined(MHD_USE_POSIX_THREADS)
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#elif defined(MHD_W32_MUTEX_)

static int
gcry_w32_mutex_init (void **ppmtx)
{
  *ppmtx = malloc (sizeof (MHD_mutex_));

  if (NULL == *ppmtx)
    return ENOMEM;
  if (!MHD_mutex_init_ ((MHD_mutex_*)*ppmtx))
    {
      free (*ppmtx);
      *ppmtx = NULL;
      return EPERM;
    }

  return 0;
}


static int
gcry_w32_mutex_destroy (void **ppmtx)
{
  int res = (MHD_mutex_destroy_ ((MHD_mutex_*)*ppmtx)) ? 0 : EINVAL;
  free (*ppmtx);
  return res;
}


static int
gcry_w32_mutex_lock (void **ppmtx)
{
  return MHD_mutex_lock_ ((MHD_mutex_*)*ppmtx) ? 0 : EINVAL;
}


static int
gcry_w32_mutex_unlock (void **ppmtx)
{
  return MHD_mutex_unlock_ ((MHD_mutex_*)*ppmtx) ? 0 : EINVAL;
}


static struct gcry_thread_cbs gcry_threads_w32 = {
  (GCRY_THREAD_OPTION_USER | (GCRY_THREAD_OPTION_VERSION << 8)),
  NULL, gcry_w32_mutex_init, gcry_w32_mutex_destroy,
  gcry_w32_mutex_lock, gcry_w32_mutex_unlock,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

#endif /* defined(MHD_W32_MUTEX_) */
#endif /* CRYPT_VERSION_NUMBER < 0x010600 */
#endif /* GNUTLS_REQUIRE_GCRYPT */

void
MHD_TLS_gnutls_init (void)
{
#ifdef GNUTLS_REQUIRE_GCRYPT
#if GCRYPT_VERSION_NUMBER < 0x010600
#if defined(MHD_USE_POSIX_THREADS)
  if (0 != gcry_control (GCRYCTL_SET_THREAD_CBS,
                         &gcry_threads_pthread))
    MHD_PANIC (_("Failed to initialise multithreading in libgcrypt\n"));
#elif defined(MHD_W32_MUTEX_)
  if (0 != gcry_control (GCRYCTL_SET_THREAD_CBS,
                         &gcry_threads_w32))
    MHD_PANIC (_("Failed to initialise multithreading in libgcrypt\n"));
#endif /* defined(MHD_W32_MUTEX_) */
  gcry_check_version (NULL);
#else
  if (NULL == gcry_check_version ("1.6.0"))
    MHD_PANIC (_("libgcrypt is too old. MHD was compiled for libgcrypt 1.6.0 or newer\n"));
#endif
#endif /* GNUTLS_REQUIRE_GCRYPT */
  gnutls_global_init ();
}

void
MHD_TLS_gnutls_deinit (void)
{
  gnutls_global_deinit ();
}

static bool
MHD_TLS_gnutls_has_feature (enum MHD_TLS_FEATURE feature)
{
  switch (feature)
    {
    case MHD_TLS_FEATURE_CERT_CALLBACK:
#if GNUTLS_VERSION_MAJOR >= 3
      return true;
#else
      return false;
#endif
    case MHD_TLS_FEATURE_KEY_PASSWORD:
#if GNUTLS_VERSION_NUMBER >= 0x030111
      return true;
#else
      return false;
#endif
    default:
      return MHD_NO;
    }
}

static bool
MHD_TLS_gnutls_init_context (struct MHD_TLS_Context *context)
{
  int result;

  context->d.gnutls.client_cert_mode = MHD_TLS_CLIENT_CERTIFICATE_MODE_DISABLE;

  result = gnutls_priority_init (&context->d.gnutls.priority_cache,
                                 "NORMAL",
                                 NULL);
  if (GNUTLS_E_SUCCESS != result)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot initialize priority cache: %s\n"),
                           gnutls_strerror (result));
      goto cleanup;
    }

  result = gnutls_certificate_allocate_credentials (&context->d.gnutls.x509_cred);
  if (GNUTLS_E_SUCCESS != result)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot initialize credentials: %s\n"),
                           gnutls_strerror (result));
      goto cleanup;
    }

  return true;

cleanup:
  if (NULL != context->d.gnutls.x509_cred)
    gnutls_certificate_free_credentials (context->d.gnutls.x509_cred);
  if (NULL != context->d.gnutls.priority_cache)
    gnutls_priority_deinit (context->d.gnutls.priority_cache);
  return false;
}

static void
MHD_TLS_gnutls_deinit_context (struct MHD_TLS_Context * context)
{
  gnutls_certificate_free_credentials (context->d.gnutls.x509_cred);
  gnutls_priority_deinit (context->d.gnutls.priority_cache);
}

static bool
MHD_TLS_gnutls_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                           MHD_TLS_GetCertificateCallback cb)
{
#if GNUTLS_VERSION_MAJOR >= 3
  gnutls_certificate_set_retrieve_function2 (context->d.gnutls.x509_cred,
                                             (gnutls_certificate_retrieve_function2 *)cb);
  return true;
#else
  MHD_TLS_LOG_CONTEXT (context,
                       _("MHD_OPTION_HTTPS_CERT_CALLBACK requires building MHD with GnuTLS >= 3.0\n"));
  return false;
#endif
}

static bool
MHD_TLS_gnutls_set_context_dh_params (struct MHD_TLS_Context *context,
                                      const char *params)
{
  int result;
  gnutls_datum_t datum;
  gnutls_dh_params_t dh_params = NULL;

  result = gnutls_dh_params_init (&dh_params);
   if (GNUTLS_E_SUCCESS != result)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Error initializing DH parameters: %s\n"),
                           gnutls_strerror (result));
    return false;
  }

  datum.data = (unsigned char *) params;
  datum.size = strlen (params);
  result = gnutls_dh_params_import_pkcs3 (dh_params,
                                          &datum,
                                          GNUTLS_X509_FMT_PEM);
  if (GNUTLS_E_SUCCESS != result)
  {
    MHD_TLS_LOG_CONTEXT (context,
                         _("Bad Diffie-Hellman parameters format: %s\n"),
                         gnutls_strerror (result));
    goto cleanup;
  }

  gnutls_certificate_set_dh_params (context->d.gnutls.x509_cred,
                                    dh_params);

  result = GNUTLS_E_SUCCESS;

cleanup:
  gnutls_dh_params_deinit (dh_params);
  return (result == GNUTLS_E_SUCCESS);
}

static bool
MHD_TLS_gnutls_set_context_certificate (struct MHD_TLS_Context *context,
                                        const char *certificate,
                                        const char *private_key,
                                        const char *password)
{
  int result;
  gnutls_datum_t key;
  gnutls_datum_t cert;

  cert.data = (unsigned char *) certificate;
  cert.size = strlen (certificate);
  key.data = (unsigned char *)private_key;
  key.size = strlen (private_key);

  if (NULL != password)
    {
#if GNUTLS_VERSION_NUMBER >= 0x030111
      result = gnutls_certificate_set_x509_key_mem2 (context->d.gnutls.x509_cred,
                                                     &cert,
                                                     &key,
                                                     GNUTLS_X509_FMT_PEM,
                                                     password,
                                                     0);
#else
#ifdef HAVE_MESSAGES
      MHD_TLS_LOG_CONTEXT (context,
                           _("Failed to setup x509 certificate/key: pre 3.X.X version " \
                             "of GnuTLS does not support setting key password\n"));
#endif
      return false;
#endif
    }
  else
    {
      result = gnutls_certificate_set_x509_key_mem (context->d.gnutls.x509_cred,
                                                    &cert,
                                                    &key,
                                                    GNUTLS_X509_FMT_PEM);
    }

  if (GNUTLS_E_SUCCESS != result)
    {
#ifdef HAVE_MESSAGES
      MHD_TLS_LOG_CONTEXT (context,
                           _("GnuTLS failed to setup x509 certificate/key: %s\n"),
                           gnutls_strerror (result));
#endif
      return false;
    }

  return true;
}

static bool
MHD_TLS_gnutls_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                              const char *certificate)
{
  int result;
  gnutls_datum_t cert;

  cert.data = (unsigned char *) certificate;
  cert.size = strlen (certificate);
  result = gnutls_certificate_set_x509_trust_mem (context->d.gnutls.x509_cred,
                                                  &cert,
                                                  GNUTLS_X509_FMT_PEM);
  if (result < 0)
    {
	    MHD_TLS_LOG_CONTEXT (context,
		                       _("Bad trust certificate format\n"));
      return false;
    }

  return true;
}

static bool
MHD_TLS_gnutls_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                                    enum MHD_TLS_ClientCertificateMode mode)
{
  switch (mode)
    {
      case MHD_TLS_CLIENT_CERTIFICATE_MODE_DISABLE:
      case MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUEST:
      case MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUIRE:
        context->d.gnutls.client_cert_mode = mode;
        return true;
      default:
        MHD_TLS_LOG_CONTEXT (context,
                             _("Unsupported client certificate mode %u\n"),
                             mode);
        return false;
    }
}

static bool
MHD_TLS_gnutls_set_context_certificate_revocation_list (struct MHD_TLS_Context *context,
                                                        const char *crl)
{
  MHD_TLS_LOG_CONTEXT (context,
                       _("Setting CRL for GnuTLS not implemented yet\n"));

  return false;
}

static bool
MHD_TLS_gnutls_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                              const char *priorities)
{
  int result;

  if (NULL != context->d.gnutls.priority_cache) {
    gnutls_priority_deinit (context->d.gnutls.priority_cache);
    context->d.gnutls.priority_cache = NULL;
  }

  result = gnutls_priority_init (&context->d.gnutls.priority_cache,
                                 priorities,
                                 NULL);
  if (GNUTLS_E_SUCCESS != result)
    {
      MHD_TLS_LOG_CONTEXT (context,
			                     _("Setting priorities to `%s' failed: %s\n"),
                           priorities,
                           gnutls_strerror (result));
      return false;
    }

  return true;
}

static bool
MHD_TLS_gnutls_init_session (struct MHD_TLS_Session * session,
                             MHD_TLS_ReadCallback read_cb,
                             MHD_TLS_WriteCallback write_cb,
                             void *cb_data)
{
  int result;

  result = gnutls_init (&session->d.gnutls.session,
                        GNUTLS_SERVER
#if (GNUTLS_VERSION_NUMBER+0 >= 0x030402)
                        | GNUTLS_NO_SIGNAL
#endif /* GNUTLS_VERSION_NUMBER >= 0x030402 */
#if GNUTLS_VERSION_MAJOR >= 3
                        | GNUTLS_NONBLOCK
#endif /* GNUTLS_VERSION_MAJOR >= 3*/
                       );
  if (GNUTLS_E_SUCCESS != result)
    {
      MHD_TLS_LOG_SESSION (session,
			                     _("Cannot allocate session: %s\n"),
                           gnutls_strerror (result));
      return false;
    }

  result = gnutls_priority_set (session->d.gnutls.session,
                                 session->context->d.gnutls.priority_cache);
  if (GNUTLS_E_SUCCESS != result)
    {
      MHD_TLS_LOG_SESSION (session,
			                     _("Cannot set priority: %s\n"),
                           gnutls_strerror (result));
      goto cleanup;
    }

  result = gnutls_credentials_set (session->d.gnutls.session,
				                           GNUTLS_CRD_CERTIFICATE,
                                   session->context->d.gnutls.x509_cred);
  if (GNUTLS_E_SUCCESS != result)
    {
      MHD_TLS_LOG_SESSION (session,
			                     _("Cannot set credentials: %s\n"),
                           gnutls_strerror (result));
      goto cleanup;
    }

  if (MHD_TLS_CLIENT_CERTIFICATE_MODE_DISABLE != session->context->d.gnutls.client_cert_mode)
    {
      gnutls_certificate_request_t request;

      switch (session->context->d.gnutls.client_cert_mode)
        {
        case MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUEST:
          request = GNUTLS_CERT_REQUEST;
          break;
        case MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUIRE:
          request = GNUTLS_CERT_REQUIRE;
          break;
        default:
          assert (false);
          goto cleanup;
        }

        gnutls_certificate_server_set_request (session->d.gnutls.session,
                                               request);
        gnutls_session_set_verify_cert (session->d.gnutls.session,
                                        NULL,
                                        0);
   }

  gnutls_transport_set_ptr (session->d.gnutls.session,
                            cb_data);
  gnutls_transport_set_pull_function (session->d.gnutls.session,
                                      read_cb);
  gnutls_transport_set_push_function (session->d.gnutls.session,
                                      write_cb);

  return true;

cleanup:
  gnutls_deinit (session->d.gnutls.session);
  return false;
}

static void
MHD_TLS_gnutls_deinit_session (struct MHD_TLS_Session * session)
{
  gnutls_deinit (session->d.gnutls.session);
}

static void *
MHD_TLS_gnutls_get_specific_session (struct MHD_TLS_Session * session)
{
  return session->d.gnutls.session;
}

static enum MHD_TLS_ProtocolVersion
MHD_TLS_gnutls_get_session_protocol_version (struct MHD_TLS_Session *session)
{
  switch (gnutls_protocol_get_version (session->d.gnutls.session))
    {
    case GNUTLS_SSL3:
      return MHD_TLS_PROTOCOL_VERSION_SSL_V3;
    case GNUTLS_TLS1_0:
      MHD_TLS_PROTOCOL_VERSION_TLS_V1_0;
    case GNUTLS_TLS1_1:
      return MHD_TLS_PROTOCOL_VERSION_TLS_V1_1;
    case GNUTLS_TLS1_2:
      return MHD_TLS_PROTOCOL_VERSION_TLS_V1_2;
    default:
      return MHD_TLS_PROTOCOL_VERSION_UNKNOWN;
    }
}

static enum MHD_TLS_CipherAlgorithm
MHD_TLS_gnutls_get_session_cipher_algorithm (struct MHD_TLS_Session *session)
{
  switch (gnutls_cipher_get (session->d.gnutls.session))
    {
    case GNUTLS_CIPHER_NULL:
      return MHD_TLS_CIPHER_ALGORITHM_NULL;
    case GNUTLS_CIPHER_ARCFOUR_128:
      return MHD_TLS_CIPHER_ALGORITHM_RC4_128;
    case GNUTLS_CIPHER_3DES_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_3DES_EDE_112_CBC;
    case GNUTLS_CIPHER_AES_128_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_AES_128_CBC;
    case GNUTLS_CIPHER_AES_256_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_AES_256_CBC;
    case GNUTLS_CIPHER_ARCFOUR_40:
      return MHD_TLS_CIPHER_ALGORITHM_RC4_40;
    case GNUTLS_CIPHER_CAMELLIA_128_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_CAMELLIA_128_CBC;
    case GNUTLS_CIPHER_CAMELLIA_256_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_CAMELLIA_256_CBC;
    case GNUTLS_CIPHER_AES_192_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_AES_192_CBC;
    case GNUTLS_CIPHER_AES_128_GCM:
      return MHD_TLS_CIPHER_ALGORITHM_AES_128_GCM;
    case GNUTLS_CIPHER_AES_256_GCM:
      return MHD_TLS_CIPHER_ALGORITHM_AES_256_GCM;
    case GNUTLS_CIPHER_CAMELLIA_192_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_CAMELLIA_192_CBC;
    case GNUTLS_CIPHER_CAMELLIA_128_GCM:
      return MHD_TLS_CIPHER_ALGORITHM_CAMELLIA_128_GCM;
    case GNUTLS_CIPHER_CAMELLIA_256_GCM:
      return MHD_TLS_CIPHER_ALGORITHM_CAMELLIA_256_GCM;
    case GNUTLS_CIPHER_RC2_40_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_RC2_40_CBC;
    case GNUTLS_CIPHER_DES_CBC:
      return MHD_TLS_CIPHER_ALGORITHM_DES_56_CBC;
    case GNUTLS_CIPHER_AES_128_CCM:
      return MHD_TLS_CIPHER_ALGORITHM_AES_128_CCM;
    case GNUTLS_CIPHER_AES_256_CCM:
      return MHD_TLS_CIPHER_ALGORITHM_AES_256_CCM;
    case GNUTLS_CIPHER_AES_128_CCM_8:
      return MHD_TLS_CIPHER_ALGORITHM_AES_128_8_CCM;
    case GNUTLS_CIPHER_AES_256_CCM_8:
      return MHD_TLS_CIPHER_ALGORITHM_AES_256_8_CCM;
    case GNUTLS_CIPHER_CHACHA20_POLY1305:
      return MHD_TLS_CIPHER_ALGORITHM_CHACHA20_POLY1305_256;
    default:
      return MHD_TLS_CIPHER_ALGORITHM_UNKNOWN;
    }
}

static ssize_t
MHD_TLS_gnutls_session_handshake (struct MHD_TLS_Session * session)
{
  int result;

  result = gnutls_handshake (session->d.gnutls.session);
  if (GNUTLS_E_SUCCESS == result)
    return 0;

  if ((GNUTLS_E_AGAIN == result) ||
      (GNUTLS_E_INTERRUPTED == result))
    return MHD_TLS_IO_WANTS_READ;

  MHD_TLS_LOG_SESSION (session,
                       _("Session handskake failed\n"));
  return MHD_TLS_IO_UNKNOWN_ERROR;
}

static ssize_t
MHD_TLS_gnutls_session_close (struct MHD_TLS_Session * session)
{
  int result;

  result = gnutls_bye (session->d.gnutls.session, GNUTLS_SHUT_WR);
  if (GNUTLS_E_SUCCESS == result)
    return 0;

  if ((GNUTLS_E_AGAIN == result) ||
      (GNUTLS_E_INTERRUPTED == result))
    return MHD_TLS_IO_WANTS_READ;

  MHD_TLS_LOG_SESSION (session,
                       _("Session close failed\n"));
  return MHD_TLS_IO_UNKNOWN_ERROR;
}

static bool
MHD_TLS_gnutls_session_wants_read (struct MHD_TLS_Session *session)
{
	return (0 == gnutls_record_get_direction (session->d.gnutls.session));
}

static bool
MHD_TLS_gnutls_session_wants_write (struct MHD_TLS_Session *session)
{
	return (0 != gnutls_record_get_direction (session->d.gnutls.session));
}

static size_t
MHD_TLS_gnutls_session_read_pending (struct MHD_TLS_Session *session)
{
  return gnutls_record_check_pending (session->d.gnutls.session);
}

static ssize_t
MHD_TLS_gnutls_session_read (struct MHD_TLS_Session * session,
                              void *buf,
                              size_t size)
{
  ssize_t result;

  result = gnutls_record_recv (session->d.gnutls.session,
                               buf,
                               size);
  if (result > 0)
    return result;

  if ((GNUTLS_E_AGAIN == result) ||
      (GNUTLS_E_INTERRUPTED == result))
    {
      return MHD_TLS_IO_WANTS_READ;
    }

  return MHD_TLS_IO_UNKNOWN_ERROR;
}

static ssize_t
MHD_TLS_gnutls_session_write (struct MHD_TLS_Session * session,
                               const void *buf,
                               size_t size)
{
  ssize_t result;

  result = gnutls_record_send (session->d.gnutls.session,
                               buf,
                               size);
  if (result > 0)
    return result;

  if ((GNUTLS_E_AGAIN == result) ||
      (GNUTLS_E_INTERRUPTED == result))
    {
      return MHD_TLS_IO_WANTS_WRITE;
    }

  return MHD_TLS_IO_UNKNOWN_ERROR;
}

const struct MHD_TLS_Engine tls_engine_gnutls =
{
  "GnuTLS",
  MHD_TLS_ENGINE_TYPE_GNUTLS,
  MHD_TLS_gnutls_has_feature,
  MHD_TLS_gnutls_init_context,
  MHD_TLS_gnutls_deinit_context,
  MHD_TLS_gnutls_set_context_certificate_cb,
  MHD_TLS_gnutls_set_context_dh_params,
  MHD_TLS_gnutls_set_context_certificate,
  MHD_TLS_gnutls_set_context_trust_certificate,
  MHD_TLS_gnutls_set_context_client_certificate_mode,
  MHD_TLS_gnutls_set_context_certificate_revocation_list,
  MHD_TLS_gnutls_set_context_cipher_priorities,
  MHD_TLS_gnutls_init_session,
  MHD_TLS_gnutls_deinit_session,
  MHD_TLS_gnutls_get_specific_session,
  MHD_TLS_gnutls_get_session_protocol_version,
  MHD_TLS_gnutls_get_session_cipher_algorithm,
  MHD_TLS_gnutls_session_handshake,
  MHD_TLS_gnutls_session_close,
  MHD_TLS_gnutls_session_wants_read,
  MHD_TLS_gnutls_session_wants_write,
  MHD_TLS_gnutls_session_read_pending,
  MHD_TLS_gnutls_session_read,
  MHD_TLS_gnutls_session_write
};
