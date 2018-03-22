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
 * @file tls_openssl.c
 * @brief OpenSSL-based TLS engine
 */

/* must come first */
#include "mhd_options.h"

#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "internal.h"
#include "tls.h"

static const char session_context[16] = {
  '\xf8', '\x5e', '\x97', '\xfe', '\x74', '\xd0', '\x49', '\xbf',
  '\x9d', '\x70', '\xf3', '\x4e', '\x0f', '\xe8', '\x68', '\xd8'
};

typedef ssize_t
(*BIO_ReadCallback) (void *context,
                     void *buf,
                     size_t size);
typedef ssize_t
(*BIO_WriteCallback) (void *context,
                      const void *buf,
                      size_t size);

static int
cb_bio_write (BIO *bio,
              const char *buf,
              int size);
static int
cb_bio_read (BIO *bio,
             char *buf,
             int size);
static int
cb_bio_puts (BIO *bio,
             const char *s);
static long
cb_bio_ctrl (BIO *bio,
             int cmd,
             long num,
             void *ptr);
static int
cb_bio_new (BIO *bio);
static int
cb_bio_free (BIO *bio);

struct CB_BIO
{
  BIO_ReadCallback read_cb;
  BIO_WriteCallback write_cb;
  void *context;
};

#if OPENSSL_VERSION_NUMBER < 0x10100000

static BIO_METHOD cb_bio_methods =
{
    (0x80000000|BIO_TYPE_SOURCE_SINK), /* avoid conflict with builtin BIO's. */
    "MHD",
    cb_bio_write,
    cb_bio_read,
    cb_bio_puts,
    NULL,
    cb_bio_ctrl,
    cb_bio_new,
    cb_bio_free,
};

#define BIO_set_init(bio, v) do { \
  (bio)->init = (v); \
} while (0)

#define BIO_set_data(bio, data) do { \
  (bio)->ptr = (data); \
} while (0)

#define BIO_get_data(bio) ((bio)->ptr)

#else /* OpenSSL >= 1.1.0 */

static BIO_METHOD * cb_bio_methods = NULL;

#endif /* OpenSSL >= 1.1.0 */

static int
cb_bio_write (BIO *bio, const char *buf, int size)
{
  int result;
  struct CB_BIO *cb = (struct CB_BIO *)BIO_get_data(bio);

  if (0 > size || (0 < size && NULL == buf))
    return -1;

  BIO_clear_retry_flags (bio);
  result = cb->write_cb (cb->context,
                         buf,
                         size);
  if (result >= 0)
    return result;

  if (MHD_SCKT_ERR_IS_EAGAIN_ (MHD_socket_get_error_ ()))
    BIO_set_retry_write (bio);

  return -1;
}

static int
cb_bio_read (BIO *bio, char *buf, int size)
{
  int result;
  struct CB_BIO *cb = (struct CB_BIO *)BIO_get_data(bio);

  if (0 > size || (0 < size && NULL == buf))
    return -1;

  BIO_clear_retry_flags (bio);
result = cb->read_cb (cb->context,
                        buf,
                        size);
  if (result >= 0)
    return result;

  if (MHD_SCKT_ERR_IS_EAGAIN_ (MHD_socket_get_error_ ()))
    BIO_set_retry_read (bio);

  return -1;
}

static int
cb_bio_puts (BIO *bio, const char *str)
{
  if (NULL == str)
    return -1;

  return cb_bio_write (bio,
                       str,
                       strlen (str));
}

static long
cb_bio_ctrl (BIO *bio, int cmd, long num, void *ptr)
{
  switch (cmd)
    {
    case BIO_CTRL_FLUSH:
      return 1;
    default:
      return 0;
    }
}

static int
cb_bio_new (BIO *bio)
{
  struct CB_BIO *cb;

  cb = (struct CB_BIO *) OPENSSL_malloc (sizeof (struct CB_BIO));
  if (NULL == cb)
    return 0;

  cb->read_cb = NULL;
  cb->write_cb = NULL;
  cb->context = NULL;
  BIO_set_data(bio, cb);

  return 1;
}

static int
cb_bio_free (BIO *bio)
{
  OPENSSL_free (BIO_get_data(bio));
  BIO_set_data(bio, NULL);

  return 1;
}

static BIO *
BIO_new_cb (BIO_ReadCallback read_cb,
            BIO_WriteCallback write_cb,
            void *context)
{
  BIO *bio;
  struct CB_BIO *cb;

  if (NULL == read_cb || NULL == write_cb)
    return NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000
  bio = BIO_new (&cb_bio_methods);
#else /* OpenSSL >= 1.1.0 */
  bio = BIO_new (cb_bio_methods);
#endif /* OpenSSL >= 1.1.0 */
  if (NULL == bio)
    return (NULL);

  cb = (struct CB_BIO *) BIO_get_data(bio);
  cb->read_cb = read_cb;
  cb->write_cb = write_cb;
  cb->context = context;
  BIO_set_init(bio, 1);

  return bio;
}

static MHD_mutex_ *locks;

static void
crypto_locking_callback (int mode,
                         int type,
                         const char *file,
                         int line)
{
  if (mode & CRYPTO_LOCK)
    MHD_mutex_lock_chk_ (&locks[type]);
  else
    MHD_mutex_unlock_chk_ (&locks[type]);
}

#if defined(MHD_USE_POSIX_THREADS)

static unsigned long
crypto_thread_id (void)
{
  return (unsigned long) pthread_self ();
}

#elif defined(MHD_W32_MUTEX_)

static unsigned long
crypto_thread_id (void)
{
  return (unsigned long) GetCurrentThreadId ();
}

#endif

static void
threads_init (void)
{
  size_t i;

  locks = OPENSSL_malloc (CRYPTO_num_locks () * sizeof (MHD_mutex_));
  if (NULL == locks)
    MHD_PANIC (_("Cannot allocate locks for OpenSSL\n"));

  for (i = 0; i < CRYPTO_num_locks (); i++)
    MHD_mutex_init_ (&locks[i]);

  CRYPTO_set_id_callback (crypto_thread_id);
  CRYPTO_set_locking_callback (crypto_locking_callback);
}

static void
threads_deinit (void)
{
  size_t i;

  CRYPTO_set_locking_callback (NULL);
  CRYPTO_set_id_callback (NULL);
  for (i = 0; i < CRYPTO_num_locks (); i++)
    MHD_mutex_destroy_chk_ (&locks[i]);
  OPENSSL_free (locks);
}

void
MHD_TLS_openssl_init (void)
{
  SSL_library_init ();
  SSL_load_error_strings (),
  threads_init ();

#if OPENSSL_VERSION_NUMBER >= 0x10100000
  cb_bio_methods = BIO_meth_new (BIO_get_new_index () | BIO_TYPE_SOURCE_SINK, "MHD");
  if (NULL == cb_bio_methods ||
      !BIO_meth_set_write (cb_bio_methods, cb_bio_write) ||
      !BIO_meth_set_read (cb_bio_methods, cb_bio_read) ||
      !BIO_meth_set_puts (cb_bio_methods, cb_bio_puts) ||
      !BIO_meth_set_ctrl (cb_bio_methods, cb_bio_ctrl) ||
      !BIO_meth_set_create (cb_bio_methods, cb_bio_new) ||
      !BIO_meth_set_destroy (cb_bio_methods, cb_bio_free))
    MHD_PANIC (_("Cannot create OpenSSL BIO\n"));
#endif /* OpenSSL >= 1.1.0 */
}

void
MHD_TLS_openssl_deinit (void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000
  BIO_meth_free (cb_bio_methods);
#endif /* OpenSSL >= 1.1.0 */
  threads_deinit ();
  ERR_free_strings ();
  EVP_cleanup ();
}

static bool
MHD_TLS_openssl_has_feature (enum MHD_TLS_FEATURE feature)
{
  switch (feature)
    {
    case MHD_TLS_FEATURE_CERT_CALLBACK:
    case MHD_TLS_FEATURE_KEY_PASSWORD:
      return true;
    default:
      break;
    }
  return MHD_NO;
}

static bool
MHD_TLS_openssl_init_context (struct MHD_TLS_Context *context)
{
  context->d.openssl.context = SSL_CTX_new (SSLv23_server_method ());
  if (NULL == context->d.openssl.context)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot allocate SSL context\n"));
      return false;
    }

  if (!SSL_CTX_set_default_verify_paths (context->d.openssl.context))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot set default verify paths\n"));
      SSL_CTX_free (context->d.openssl.context);
      return false;
    }

  if (!SSL_CTX_set_ecdh_auto (context->d.openssl.context, 1))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot set ECDH selection to automatic\n"));
      SSL_CTX_free (context->d.openssl.context);
      return false;
    }

  if (!SSL_CTX_set_session_id_context (context->d.openssl.context,
                                       session_context,
                                       sizeof(session_context)))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot set session context\n"));
      SSL_CTX_free (context->d.openssl.context);
      return false;
    }

  return true;
}

static void
MHD_TLS_openssl_deinit_context (struct MHD_TLS_Context * context)
{
  SSL_CTX_free (context->d.openssl.context);
}

static bool
MHD_TLS_openssl_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                            MHD_TLS_GetCertificateCallback cb)
{
  SSL_CTX_set_cert_cb (context->d.openssl.context,
                       (int (*)(SSL *, void *))cb,
                       NULL);
  return true;
}

static bool
MHD_TLS_openssl_set_context_dh_params (struct MHD_TLS_Context *context,
                                       const char *params)
{
  DH *dh = NULL;
  BIO *bio;

  bio = BIO_new_mem_buf (params, -1);
  if (NULL != bio)
    {
      dh = PEM_read_bio_DHparams (bio,
          NULL,
          0,
          NULL);
      BIO_free_all (bio);
    }
  if (NULL == dh)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Bad Diffie-Hellman parameters format\n"));
      return false;
    }
  if (!SSL_CTX_set_tmp_dh (context->d.openssl.context,
                           dh))
  {
    MHD_TLS_LOG_CONTEXT (context,
                         _("Cannot set Diffie-Hellman parameters\n"));
    DH_free (dh);
    return false;
  }
  DH_free (dh);

  return true;
}

static bool
MHD_TLS_openssl_set_context_certificate (struct MHD_TLS_Context *context,
                                         const char *certificate,
                                         const char *private_key,
                                         const char *password)
{
  bool result = false;
  BIO *bio;
  STACK_OF(X509_INFO) *info_sk = NULL;
  X509_INFO *info;
  EVP_PKEY *key = NULL;
  int cert_count = 0;
  int idx;

  bio = BIO_new_mem_buf (certificate, -1);
  if (NULL != bio)
    {
      info_sk = PEM_X509_INFO_read_bio (bio, NULL, NULL, NULL);
      BIO_free_all (bio);
    }
  if (NULL == info_sk)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Bad server certificate format\n"));
      goto cleanup;
    }

  for (idx = 0; idx < sk_X509_INFO_num (info_sk); ++idx)
    {
      info = sk_X509_INFO_value (info_sk, idx);
      if (NULL != info->x509)
        {
          /* The first certificate is server certificate. It may be followed by
           * intermediate or even root CA certificates. */
          if (cert_count == 0)
            {
              if (!SSL_CTX_use_certificate (context->d.openssl.context,
                                            info->x509))
                {
                  MHD_TLS_LOG_CONTEXT (context,
                                       _("Cannot set server certificate\n"));
                  goto cleanup;
                }
            }

          if (!X509_STORE_add_cert (SSL_CTX_get_cert_store (context->d.openssl.context),
                                                            info->x509))
            {
              unsigned long error = ERR_peek_last_error ();

              /* Certificate may be in trust certificate chain too. */
              if (ERR_LIB_X509 == ERR_GET_LIB (error) &&
                  X509_R_CERT_ALREADY_IN_HASH_TABLE == ERR_GET_REASON (error))
                ERR_clear_error ();
              else
                {
                  MHD_TLS_LOG_CONTEXT (context,
                                       _("Cannot add CA certificate to store\n"));
                  goto cleanup;
                }
            }
          else
            info->x509 = NULL;

          cert_count++;
        }
    }

  if (cert_count == 0)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("No server certificate found\n"));
      goto cleanup;
    }

  bio = BIO_new_mem_buf (private_key, -1);
  if (NULL != bio)
    {
      key = PEM_read_bio_PrivateKey (bio,
                                     NULL,
                                     NULL,
                                     (void *)password);
      BIO_free_all (bio);
    }
  if (NULL == key)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Bad server key format or invalid password\n"));
      goto cleanup;
    }
  if (!SSL_CTX_use_PrivateKey (context->d.openssl.context,
                               key))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot set server private key\n"));
      goto cleanup;
    }

  result = true;

cleanup:
  if (NULL != key)
    EVP_PKEY_free (key);

  if (NULL != info_sk)
    sk_X509_INFO_pop_free (info_sk, X509_INFO_free);

  return result;
}

static bool
MHD_TLS_openssl_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                               const char *certificate)
{
  bool result = false;
  BIO *bio;
  STACK_OF(X509_INFO) *info_sk = NULL;
  X509_INFO *info;
  int cert_count = 0;
  int idx;

  bio = BIO_new_mem_buf (certificate, -1);
  if (NULL != bio)
    {
      info_sk = PEM_X509_INFO_read_bio (bio, NULL, NULL, NULL);
      BIO_free_all (bio);
    }

  if (NULL == info_sk)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Bad trust certificate format\n"));
      goto cleanup;
    }

  for (idx = 0; idx < sk_X509_INFO_num (info_sk); ++idx)
    {
      info = sk_X509_INFO_value (info_sk, idx);
      if (NULL != info->x509)
        {
          /* The first certificate is our CA certificate. It may be followed by
           * other intermediate or even root CA certificates. */
          if (cert_count == 0)
            {
              /* Set the correct CA for client authentication. */
              if (!SSL_CTX_add_client_CA (context->d.openssl.context,
                                          info->x509))
                {
                  MHD_TLS_LOG_CONTEXT (context,
                                       _("Cannot add CA to client certificate request\n"));
                  goto cleanup;
                }
            }

          if (!X509_STORE_add_cert (SSL_CTX_get_cert_store (context->d.openssl.context),
                                                            info->x509))
            {
              unsigned long error = ERR_peek_last_error ();

              /* Certificate may be in server certificate chain too. */
              if (ERR_LIB_X509 == ERR_GET_LIB (error) &&
                  X509_R_CERT_ALREADY_IN_HASH_TABLE == ERR_GET_REASON (error))
                ERR_clear_error ();
              else
                {
                  MHD_TLS_LOG_CONTEXT (context,
                                       _("Cannot add CA certificate to store\n"));
                  goto cleanup;
                }
            }
          else
            info->x509 = NULL;

          cert_count++;
        }
    }

  if (cert_count == 0)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("No trust certificate found\n"));
      goto cleanup;
    }

  result = true;

cleanup:
  if (NULL != info_sk)
    sk_X509_INFO_pop_free (info_sk, X509_INFO_free);

  return result;
}

static bool
MHD_TLS_openssl_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                                     enum MHD_TLS_ClientCertificateMode mode)
{
  int openssl_mode;

  switch (mode)
    {
    case MHD_TLS_CLIENT_CERTIFICATE_MODE_DISABLE:
      openssl_mode = SSL_VERIFY_NONE;
      break;
    case MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUEST:
      openssl_mode = SSL_VERIFY_PEER;
      break;
    case MHD_TLS_CLIENT_CERTIFICATE_MODE_REQUIRE:
      openssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      break;
    default:
      MHD_TLS_LOG_CONTEXT (context,
                           _("Unsupported client certificate mode %d\n"),
                           mode);
      return false;
    }

  SSL_CTX_set_verify (context->d.openssl.context,
                      openssl_mode,
                      NULL);

  return true;
}

static bool
MHD_TLS_openssl_set_context_certificate_revocation_list (struct MHD_TLS_Context *context,
                                                         const char *crl)
{
  bool result = false;
  BIO *bio = NULL;
  STACK_OF(X509_INFO) *info_sk = NULL;
  X509_INFO *info;
  int crl_count = 0;
  int idx;

  bio = BIO_new_mem_buf (crl, -1);
  if (NULL != bio)
    {
      info_sk = PEM_X509_INFO_read_bio (bio, NULL, NULL, NULL);
      BIO_free_all (bio);
    }

  if (NULL == info_sk)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Bad certificate revocation list format\n"));
      goto cleanup;
    }

  for (idx = 0; idx < sk_X509_INFO_num (info_sk); ++idx)
    {
      info = sk_X509_INFO_value (info_sk, idx);
      if (NULL != info->crl)
        {
          if (!X509_STORE_add_crl (SSL_CTX_get_cert_store (context->d.openssl.context),
                                                            info->crl))
            {
              MHD_TLS_LOG_CONTEXT (context,
                                   _("Cannot add certificate revocation list to store\n"));
              goto cleanup;
            }
          else
            info->crl = NULL;

          crl_count++;
        }
    }

  if (crl_count == 0)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("No certificate revocation list found\n"));
      goto cleanup;
    }

  X509_STORE_set_flags(SSL_CTX_get_cert_store (context->d.openssl.context),
                                               X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

  result = true;

cleanup:
  if (NULL != info_sk)
    sk_X509_INFO_pop_free (info_sk, X509_INFO_free);

  return result;
}

static bool
MHD_TLS_openssl_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                               const char *priorities)
{
  if (0 == SSL_CTX_set_cipher_list (context->d.openssl.context,
                                    priorities))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Setting priorities to `%s' failed\n"),
                           priorities);
      return false;
    }

  return true;
}

static bool
MHD_TLS_openssl_init_session (struct MHD_TLS_Session * session,
                              MHD_TLS_ReadCallback read_cb,
                              MHD_TLS_WriteCallback write_cb,
                              void *cb_data)
{
  BIO *bio;

  session->d.openssl.session = SSL_new (session->context->d.openssl.context);
  if (NULL == session ->d.openssl.session)
    {
      MHD_TLS_LOG_SESSION(session,
                          _("Cannot allocate SSL session\n"));
      return false;
    }

  bio = BIO_new_cb (read_cb,
                    write_cb,
                    cb_data);
  if (NULL == bio)
    {
      MHD_TLS_LOG_SESSION(session,
                          _("Cannot create BIO\n"));
      SSL_free (session->d.openssl.session);
      return false;
    }

  SSL_set_bio (session->d.openssl.session,
               bio,
               bio);

  return true;
}

static void
MHD_TLS_openssl_deinit_session (struct MHD_TLS_Session * session)
{
  SSL_free (session->d.openssl.session);
}

static void *
MHD_TLS_openssl_get_specific_session (struct MHD_TLS_Session * session)
{
  return session->d.openssl.session;
}

static enum MHD_TLS_ProtocolVersion
MHD_TLS_openssl_get_session_protocol_version (struct MHD_TLS_Session *session)
{
  const char *version;

  version = SSL_get_version (session->d.openssl.session);
  if (0 == strcmp ("SSLv3",
                   version))
    return MHD_TLS_PROTOCOL_VERSION_SSL_V3;
  else if (0 == strcmp ("TLSv1",
                        version))
    return MHD_TLS_PROTOCOL_VERSION_TLS_V1_0;
  else if (0 == strcmp ("TLSv1.1",
                        version))
    return MHD_TLS_PROTOCOL_VERSION_TLS_V1_1;
  else if (0 == strcmp ("TLSv1.2",
                        version))
    return MHD_TLS_PROTOCOL_VERSION_TLS_V1_2;
  else
    return MHD_TLS_PROTOCOL_VERSION_UNKNOWN;
}

static enum MHD_TLS_CipherAlgorithm
MHD_TLS_openssl_get_session_cipher_algorithm (struct MHD_TLS_Session *session)
{
  const SSL_CIPHER *cipher;

  cipher = SSL_get_current_cipher (session->d.openssl.session);
  if (NULL == cipher)
    return MHD_TLS_CIPHER_ALGORITHM_UNKNOWN;

  switch (SSL_CIPHER_get_id (cipher))
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_NULL_WITH_MD5:
    case SSL2_CK_NULL:
#endif /* OpenSSL < 1.1.0 */
    case SSL3_CK_RSA_NULL_MD5:
    case SSL3_CK_RSA_NULL_SHA:
    case TLS1_CK_RSA_WITH_NULL_SHA256:
    case TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA:
    case TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA:
    case TLS1_CK_ECDH_RSA_WITH_NULL_SHA:
    case TLS1_CK_ECDHE_RSA_WITH_NULL_SHA:
    case TLS1_CK_ECDH_anon_WITH_NULL_SHA:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_PSK_WITH_NULL_SHA256:
    case TLS1_CK_PSK_WITH_NULL_SHA384:
    case TLS1_CK_DHE_PSK_WITH_NULL_SHA256:
    case TLS1_CK_DHE_PSK_WITH_NULL_SHA384:
    case TLS1_CK_RSA_PSK_WITH_NULL_SHA256:
    case TLS1_CK_RSA_PSK_WITH_NULL_SHA384:
    case TLS1_CK_PSK_WITH_NULL_SHA:
    case TLS1_CK_DHE_PSK_WITH_NULL_SHA:
    case TLS1_CK_RSA_PSK_WITH_NULL_SHA:
    case TLS1_CK_ECDHE_PSK_WITH_NULL_SHA:
    case TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256:
    case TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_RC4_128_EXPORT40_WITH_MD5:
#endif /* OpenSSL < 1.1.0 */
    case SSL3_CK_RSA_RC4_40_MD5:
    case SSL3_CK_ADH_RC4_40_MD5:
      return MHD_TLS_CIPHER_ALGORITHM_RC4_40;

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5:
    case TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA:
      return MHD_TLS_CIPHER_ALGORITHM_RC4_56;
#endif /* OpenSSL < 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_RC4_128_WITH_MD5:
#endif /* OpenSSL < 1.1.0 */
    case SSL3_CK_RSA_RC4_128_MD5:
    case SSL3_CK_RSA_RC4_128_SHA:
    case SSL3_CK_ADH_RC4_128_MD5:
    case TLS1_CK_PSK_WITH_RC4_128_SHA:
#if OPENSSL_VERSION_NUMBER < 0x10100000
    case TLS1_CK_DHE_DSS_WITH_RC4_128_SHA:
#endif /* OpenSSL < 1.1.0 */
    case TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA:
    case TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA:
    case TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA:
    case TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA:
    case TLS1_CK_ECDH_anon_WITH_RC4_128_SHA:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_DHE_PSK_WITH_RC4_128_SHA:
    case TLS1_CK_RSA_PSK_WITH_RC4_128_SHA:
    case TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_RC4_128;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305:
    case TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
    case TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305:
    case TLS1_CK_PSK_WITH_CHACHA20_POLY1305:
    case TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305:
    case TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305:
    case TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305:
      return MHD_TLS_CIPHER_ALGORITHM_CHACHA20_POLY1305_256;
#endif /* OpenSSL >= 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5:
#endif /* OpenSSL < 1.1.0 */
    case SSL3_CK_RSA_RC2_40_MD5:
      return MHD_TLS_CIPHER_ALGORITHM_RC2_40_CBC;

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5:
      return MHD_TLS_CIPHER_ALGORITHM_RC2_56_CBC;
#endif /* OpenSSL < 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_RC2_128_CBC_WITH_MD5:
      return MHD_TLS_CIPHER_ALGORITHM_RC2_128_CBC;
#endif /* OpenSSL < 1.1.0 */

    case SSL3_CK_RSA_DES_40_CBC_SHA:
    case SSL3_CK_DH_DSS_DES_40_CBC_SHA:
    case SSL3_CK_DH_RSA_DES_40_CBC_SHA:
    case SSL3_CK_EDH_DSS_DES_40_CBC_SHA:
    case SSL3_CK_EDH_RSA_DES_40_CBC_SHA:
    case SSL3_CK_ADH_DES_40_CBC_SHA:
      return MHD_TLS_CIPHER_ALGORITHM_DES_40_CBC;

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_DES_64_CBC_WITH_MD5:
    case SSL2_CK_DES_64_CBC_WITH_SHA:
    case SSL2_CK_DES_64_CFB64_WITH_MD5_1:
#endif /* OpenSSL < 1.1.0 */
    case SSL3_CK_RSA_DES_64_CBC_SHA:
    case SSL3_CK_DH_DSS_DES_64_CBC_SHA:
    case SSL3_CK_DH_RSA_DES_64_CBC_SHA:
    case SSL3_CK_EDH_DSS_DES_64_CBC_SHA:
    case SSL3_CK_EDH_RSA_DES_64_CBC_SHA:
    case SSL3_CK_ADH_DES_64_CBC_SHA:
#if OPENSSL_VERSION_NUMBER < 0x10100000
    case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:
    case TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA:
#endif /* OpenSSL < 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_DES_56_CBC;

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_IDEA_128_CBC_WITH_MD5:
#endif /* OpenSSL < 1.1.0 */
    case SSL3_CK_RSA_IDEA_128_SHA:
      return MHD_TLS_CIPHER_ALGORITHM_IDEA_128_CBC;

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_DES_192_EDE3_CBC_WITH_MD5:
    case SSL2_CK_DES_192_EDE3_CBC_WITH_SHA:
#endif /* OpenSSL < 1.1.0 */
    case SSL3_CK_RSA_DES_192_CBC3_SHA:
    case SSL3_CK_DH_DSS_DES_192_CBC3_SHA:
    case SSL3_CK_DH_RSA_DES_192_CBC3_SHA:
    case SSL3_CK_EDH_DSS_DES_192_CBC3_SHA:
    case SSL3_CK_EDH_RSA_DES_192_CBC3_SHA:
    case SSL3_CK_ADH_DES_192_CBC_SHA:
    case TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA:
    case TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
    case TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA:
    case TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA:
    case TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA:
    case TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA:
    case TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
    case TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
    case TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_3DES_EDE_112_CBC;

    case TLS1_CK_RSA_WITH_SEED_SHA:
    case TLS1_CK_DH_DSS_WITH_SEED_SHA:
    case TLS1_CK_DH_RSA_WITH_SEED_SHA:
    case TLS1_CK_DHE_DSS_WITH_SEED_SHA:
    case TLS1_CK_DHE_RSA_WITH_SEED_SHA:
    case TLS1_CK_ADH_WITH_SEED_SHA:
      return MHD_TLS_CIPHER_ALGORITHM_SEED_128_CBC;

    case TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA:
    case TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
    case TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
    case TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
    case TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
    case TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
    case TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_CAMELLIA_128_CBC;

    case TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA:
    case TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
    case TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
    case TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
    case TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
    case TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256:
    case TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
    case TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
    case TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
    case TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
    case TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256:
    case TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
    case TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
    case TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
    case TLS1_CK_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
    case TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384:
    case TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
    case TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
    case TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_CAMELLIA_256_CBC;

    case TLS1_CK_PSK_WITH_AES_128_CBC_SHA:
    case TLS1_CK_RSA_WITH_AES_128_SHA:
    case TLS1_CK_DH_DSS_WITH_AES_128_SHA:
    case TLS1_CK_DH_RSA_WITH_AES_128_SHA:
    case TLS1_CK_DHE_DSS_WITH_AES_128_SHA:
    case TLS1_CK_DHE_RSA_WITH_AES_128_SHA:
    case TLS1_CK_ADH_WITH_AES_128_SHA:
    case TLS1_CK_RSA_WITH_AES_128_SHA256:
    case TLS1_CK_DH_DSS_WITH_AES_128_SHA256:
    case TLS1_CK_DH_RSA_WITH_AES_128_SHA256:
    case TLS1_CK_DHE_DSS_WITH_AES_128_SHA256:
    case TLS1_CK_DHE_RSA_WITH_AES_128_SHA256:
    case TLS1_CK_ADH_WITH_AES_128_SHA256:
    case TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA:
    case TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA:
    case TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA:
    case TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
    case TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256:
    case TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256:
    case TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256:
    case TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA:
    case TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256:
    case TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA:
    case TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256:
    case TLS1_CK_PSK_WITH_AES_128_CBC_SHA256:
    case TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA:
    case TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_AES_128_CBC;

    case TLS1_CK_PSK_WITH_AES_256_CBC_SHA:
    case TLS1_CK_RSA_WITH_AES_256_SHA:
    case TLS1_CK_DH_DSS_WITH_AES_256_SHA:
    case TLS1_CK_DH_RSA_WITH_AES_256_SHA:
    case TLS1_CK_DHE_DSS_WITH_AES_256_SHA:
    case TLS1_CK_DHE_RSA_WITH_AES_256_SHA:
    case TLS1_CK_ADH_WITH_AES_256_SHA:
    case TLS1_CK_RSA_WITH_AES_256_SHA256:
    case TLS1_CK_DH_DSS_WITH_AES_256_SHA256:
    case TLS1_CK_DH_RSA_WITH_AES_256_SHA256:
    case TLS1_CK_DHE_DSS_WITH_AES_256_SHA256:
    case TLS1_CK_DHE_RSA_WITH_AES_256_SHA256:
    case TLS1_CK_ADH_WITH_AES_256_SHA256:
    case TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA:
    case TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA:
    case TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA:
    case TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
    case TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384:
    case TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384:
    case TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384:
    case TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA:
    case TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA:
    case TLS1_CK_PSK_WITH_AES_256_CBC_SHA384:
    case TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384:
    case TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384:
    case TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA:
    case TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_AES_256_CBC;

    case TLS1_CK_RSA_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_ADH_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_PSK_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256:
    case TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_AES_128_GCM;

    case TLS1_CK_RSA_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_ADH_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_PSK_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384:
    case TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384:
#endif /* OpenSSL >= 1.1.0 */
      return MHD_TLS_CIPHER_ALGORITHM_AES_256_GCM;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    case TLS1_CK_RSA_WITH_AES_128_CCM:
    case TLS1_CK_DHE_RSA_WITH_AES_128_CCM:
    case TLS1_CK_PSK_WITH_AES_128_CCM:
    case TLS1_CK_DHE_PSK_WITH_AES_128_CCM:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM:

      return MHD_TLS_CIPHER_ALGORITHM_AES_128_CCM;

    case TLS1_CK_RSA_WITH_AES_256_CCM:
    case TLS1_CK_DHE_RSA_WITH_AES_256_CCM:
    case TLS1_CK_PSK_WITH_AES_256_CCM:
    case TLS1_CK_DHE_PSK_WITH_AES_256_CCM:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM:
      return MHD_TLS_CIPHER_ALGORITHM_AES_256_CCM;

    case TLS1_CK_RSA_WITH_AES_128_CCM_8:
    case TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8:
    case TLS1_CK_PSK_WITH_AES_128_CCM_8:
    case TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8:
      return MHD_TLS_CIPHER_ALGORITHM_AES_128_8_CCM;

    case TLS1_CK_RSA_WITH_AES_256_CCM_8:
    case TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8:
    case TLS1_CK_PSK_WITH_AES_256_CCM_8:
    case TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8:
    case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8:
      return MHD_TLS_CIPHER_ALGORITHM_AES_256_8_CCM;
#endif /* OpenSSL >= 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000
    case SSL2_CK_RC4_64_WITH_MD5:
#endif /* OpenSSL < 1.1.0 */
    default:
      return MHD_TLS_CIPHER_ALGORITHM_UNKNOWN;
    }
}

static ssize_t
MHD_TLS_openssl_session_handshake (struct MHD_TLS_Session * session)
{
  int result;
  int error;
  unsigned long err_error;

  /* reset errors */
  ERR_clear_error();

  result = SSL_accept (session->d.openssl.session);
  error = SSL_get_error (session->d.openssl.session, result);

  if (result == 1)
    return 0;

  switch (error)
    {
    case SSL_ERROR_WANT_READ:
      return MHD_TLS_IO_WANTS_READ;
    case SSL_ERROR_WANT_WRITE:
      return MHD_TLS_IO_WANTS_WRITE;
    default:
      MHD_TLS_LOG_SESSION (session,
                           _("Session handshake failed, SSL_accept: %d, SSL_get_error: %d\n"),
                           result,
                           error);
      err_error = ERR_get_error();

      while (err_error != 0) {
        MHD_TLS_LOG_SESSION (session,
                             _("Session handshake failed, SSL_accept: %d, ERR_get_error: %lu\n\tlib: %s\n\tfunc: %s\n\treason: %s\n"),
                             result,
                             err_error,
                             ERR_lib_error_string(err_error),
                             ERR_func_error_string(err_error),
                             ERR_reason_error_string(err_error));

        err_error = ERR_get_error();
      }
      return MHD_TLS_IO_UNKNOWN_ERROR;
    }
}

static ssize_t
MHD_TLS_openssl_session_close (struct MHD_TLS_Session * session)
{
  int result;
  int error;
  unsigned long err_error;

    /* reset errors */
    ERR_clear_error();

  result = SSL_shutdown (session->d.openssl.session);
  if (result == 1)
    return 0;
  else if (result == 0)
    return MHD_TLS_IO_WANTS_READ;

  error = SSL_get_error (session->d.openssl.session, result);
  switch (error)
    {
    case SSL_ERROR_WANT_READ:
      return MHD_TLS_IO_WANTS_READ;
    case SSL_ERROR_WANT_WRITE:
      return MHD_TLS_IO_WANTS_WRITE;
    default:
      err_error = ERR_get_error();
      while (err_error != 0) {
        MHD_TLS_LOG_SESSION (session,
                             _("Session close failed, SSL_get_error: %d\n\tlib: %s\n\tfunc: %s\n\treason: %s\n"),
                             error,
                             ERR_lib_error_string(err_error),
                             ERR_func_error_string(err_error),
                             ERR_reason_error_string(err_error));

        err_error = ERR_get_error();
      }

      return MHD_TLS_IO_UNKNOWN_ERROR;
    }
}

static bool
MHD_TLS_openssl_session_wants_read (struct MHD_TLS_Session *session)
{
  return SSL_want_read (session->d.openssl.session);
}

static bool
MHD_TLS_openssl_session_wants_write (struct MHD_TLS_Session *session)
{
  return SSL_want_write (session->d.openssl.session);
}

static size_t
MHD_TLS_openssl_session_read_pending (struct MHD_TLS_Session *session)
{
  return (size_t) SSL_pending (session->d.openssl.session);
}

static ssize_t
MHD_TLS_openssl_session_read (struct MHD_TLS_Session * session,
                              void *buf,
                              size_t size)
{
  ssize_t result;

  if (size > INT_MAX)
    size = INT_MAX;

  result = SSL_read (session->d.openssl.session,
                     buf,
                     (int)size);
  if (result > 0)
    return result;

  switch (SSL_get_error (session->d.openssl.session, result))
    {
    case SSL_ERROR_WANT_READ:
      return MHD_TLS_IO_WANTS_READ;

    case SSL_ERROR_WANT_WRITE:
      return MHD_TLS_IO_WANTS_WRITE;

    case SSL_ERROR_ZERO_RETURN:
      return MHD_TLS_IO_SESSION_CLOSED;

    default:
      return MHD_TLS_IO_UNKNOWN_ERROR;
    }
}

static ssize_t
MHD_TLS_openssl_session_write (struct MHD_TLS_Session * session,
                               const void *buf,
                               size_t size)
{
  ssize_t result;

  if (size > INT_MAX)
    size = INT_MAX;

  result = SSL_write (session->d.openssl.session,
                      buf,
                      (int)size);
  if (result > 0)
    return result;

  switch (SSL_get_error (session->d.openssl.session, result))
    {
    case SSL_ERROR_WANT_READ:
      return MHD_TLS_IO_WANTS_READ;

    case SSL_ERROR_WANT_WRITE:
      return MHD_TLS_IO_WANTS_WRITE;

    case SSL_ERROR_ZERO_RETURN:
      return MHD_TLS_IO_SESSION_CLOSED;

    default:
      return MHD_TLS_IO_UNKNOWN_ERROR;
    }
}

const struct MHD_TLS_Engine tls_engine_openssl =
{
  "OpenSSL",
  MHD_TLS_ENGINE_TYPE_OPENSSL,
  MHD_TLS_openssl_has_feature,
  MHD_TLS_openssl_init_context,
  MHD_TLS_openssl_deinit_context,
  MHD_TLS_openssl_set_context_certificate_cb,
  MHD_TLS_openssl_set_context_dh_params,
  MHD_TLS_openssl_set_context_certificate,
  MHD_TLS_openssl_set_context_trust_certificate,
  MHD_TLS_openssl_set_context_client_certificate_mode,
  MHD_TLS_openssl_set_context_certificate_revocation_list,
  MHD_TLS_openssl_set_context_cipher_priorities,
  MHD_TLS_openssl_init_session,
  MHD_TLS_openssl_deinit_session,
  MHD_TLS_openssl_get_specific_session,
  MHD_TLS_openssl_get_session_protocol_version,
  MHD_TLS_openssl_get_session_cipher_algorithm,
  MHD_TLS_openssl_session_handshake,
  MHD_TLS_openssl_session_close,
  MHD_TLS_openssl_session_wants_read,
  MHD_TLS_openssl_session_wants_write,
  MHD_TLS_openssl_session_read_pending,
  MHD_TLS_openssl_session_read,
  MHD_TLS_openssl_session_write
};
