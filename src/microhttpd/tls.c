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
 * @file tls.c
 * @brief TLS engine
 */

/* must come first */
#include "mhd_options.h"

#include <assert.h>

#include "internal.h"
#include "tls.h"
#include "mhd_compat.h"

static const struct MHD_TLS_Engine *engines[MHD_TLS_ENGINE_TYPE_MAX + 1];

#ifdef HAVE_MESSAGES

void
MHD_TLS_LOG_CONTEXT (struct MHD_TLS_Context *context,
                     const char *format,
                     ...)
{
  va_list args;

  va_start (args,
            format);
  MHD_TLS_log_context_va (context,
                          format,
                          args);
  va_end (args);
}

void
MHD_TLS_LOG_SESSION (struct MHD_TLS_Session *session,
                     const char *format,
                     ...)
{
  va_list args;

  va_start (args,
            format);
  MHD_TLS_log_context_va (session->context,
                          format,
                          args);
  va_end (args);
}

#endif /* HAVE_MESSAGES */

void
MHD_TLS_global_init (void)
{
#ifdef ENABLE_GNUTLS
  if (NULL == engines[MHD_TLS_ENGINE_TYPE_GNUTLS])
    {
      MHD_TLS_gnutls_init ();
      engines[MHD_TLS_ENGINE_TYPE_GNUTLS] = &tls_engine_gnutls;
    }
#endif /* ENABLE_GNUTLS */

#ifdef ENABLE_OPENSSL
  if (NULL == engines[MHD_TLS_ENGINE_TYPE_OPENSSL])
    {
      MHD_TLS_openssl_init ();
      engines[MHD_TLS_ENGINE_TYPE_OPENSSL] = &tls_engine_openssl;
    }
#endif /* ENABLE_OPENSSL */
}

void
MHD_TLS_global_deinit (void)
{
#ifdef ENABLE_GNUTLS
  if (NULL != engines[MHD_TLS_ENGINE_TYPE_GNUTLS])
    {
      MHD_TLS_gnutls_deinit ();
      engines[MHD_TLS_ENGINE_TYPE_GNUTLS] = NULL;
    }
#endif /* ENABLE_GNUTLS */

#ifdef ENABLE_OPENSSL
  if (NULL != engines[MHD_TLS_ENGINE_TYPE_OPENSSL])
    {
      MHD_TLS_openssl_deinit ();
      engines[MHD_TLS_ENGINE_TYPE_OPENSSL] = NULL;
    }
#endif /* ENABLE_OPENSSL */
}

bool
MHD_TLS_engine_has_feature (const struct MHD_TLS_Engine *engine,
                            enum MHD_TLS_FEATURE feature)
{
  if (NULL == engine)
    return false;
  return engine->has_feature (feature);
}

const struct MHD_TLS_Engine *
MHD_TLS_lookup_engine (enum MHD_TLS_EngineType type)
{
  if (type > MHD_TLS_ENGINE_TYPE_MAX)
    return NULL;
  return engines[type];
}

struct MHD_TLS_Context *
MHD_TLS_create_context (const struct MHD_TLS_Engine *engine,
                        MHD_LogCallback log_cb,
                        void *log_data,
                        MHD_TLS_FreeCallback free_log_data_cb)
{
  struct MHD_TLS_Context *context;

  if (NULL == engine)
    return NULL;

  if (NULL == log_cb && (NULL != log_data || NULL != free_log_data_cb))
    return NULL;

  context = MHD_calloc_ (1, sizeof (struct MHD_TLS_Context));
  if (NULL == context)
    return NULL;

  context->engine = engine;
  context->log_cb = log_cb;
  context->log_data = log_data;
  context->free_log_data_cb = free_log_data_cb;

  if (!engine->init_context (context))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Engine %s failed to initialize TLS context\n"),
                           engine->name);
      free (context);
      return NULL;
    }

  return context;
}

void
MHD_TLS_log_context (struct MHD_TLS_Context *context,
                     const char *format,
                     ...)
{
  if (NULL == context)
    return;

  if (context->log_cb != NULL)
    {
      va_list args;

      va_start (args, format);
      context->log_cb (context->log_data, format, args);
      va_end (args);
    }
}

void
MHD_TLS_log_context_va (struct MHD_TLS_Context *context,
                        const char *format,
                        va_list args)
{
  if (NULL == context)
    return;

  if (context->log_cb != NULL)
      context->log_cb (context->log_data, format, args);
}

void
MHD_TLS_del_context (struct MHD_TLS_Context *context)
{
  if (NULL == context)
    return;

  context->engine->deinit_context (context);
  if (NULL != context->log_data && NULL != context->free_log_data_cb)
    context->free_log_data_cb (context->log_data);
  free (context);
}

bool
MHD_TLS_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                    MHD_TLS_GetCertificateCallback cb)
{
  if (NULL == context)
    return false;

  return context->engine->set_context_certificate_cb (context,
                                                      cb);
}

bool
MHD_TLS_set_context_dh_params (struct MHD_TLS_Context *context,
                               const char *params)
{
  if (NULL == context)
    return false;

  if (NULL == params)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid DH parameters\n"));
      return false;
    }

  return context->engine->set_context_dh_params(context,
                                                params);
}

bool
MHD_TLS_set_context_certificate (struct MHD_TLS_Context *context,
                                 const char *certificate,
                                 const char *private_key,
                                 const char *password)
{
  if (NULL == context)
    return false;

  if (NULL == certificate)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid certificate\n"));
      return false;
    }

  if (NULL == private_key)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid private key\n"));
      return false;
    }

  return context->engine->set_context_certificate(context,
                                                  certificate,
                                                  private_key,
                                                  password);
}

bool
MHD_TLS_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                       const char *certificate)
{
  if (NULL == context)
    return false;

  if (NULL == certificate)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid certificate\n"));
      return false;
    }

  return context->engine->set_context_trust_certificate(context,
                                                        certificate);
}

bool
MHD_TLS_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                             enum MHD_TLS_ClientCertificateMode mode)
{
  if (NULL == context)
    return false;

  if (mode > MHD_TLS_CLIENT_CERTIFICATE_MODE_MAX)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid client certificate mode %u\n"),
                           mode);
      return false;
    }

  return context->engine->set_context_client_certificate_mode (context,
                                                               mode);
}

bool
MHD_TLS_set_context_certificate_revocation_list (struct MHD_TLS_Context *context,
                                                 const char *crl)
{
  if (NULL == context)
    return false;

  if (NULL == crl)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid certificate revocation list\n"));
      return false;
    }

  return context->engine->set_context_certificate_revocation_list(context,
                                                                  crl);
}

bool
MHD_TLS_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                       const char *priorities)
{
  if (NULL == context)
    return false;

  if (NULL == priorities)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Invalid priorities\n"));
      return false;
    }

  return context->engine->set_context_cipher_priorities(context,
                                                        priorities);
}

struct MHD_TLS_Session *
MHD_TLS_create_session (struct MHD_TLS_Context * context,
                        MHD_TLS_ReadCallback read_cb,
                        MHD_TLS_WriteCallback write_cb,
                        void *cb_data,
                        MHD_TLS_FreeCallback free_data_cb)
{
  struct MHD_TLS_Session *session;

  if (NULL == context)
    return NULL;

  if (NULL == read_cb || NULL == write_cb)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Missing read or write callback for TLS session\n"));
      return NULL;
    }

  session = MHD_calloc_ (1, sizeof (struct MHD_TLS_Session));
  if (NULL == session)
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Cannot allocate TLS session\n"));
      return NULL;
    }

  session->context = context;
  session->cb_data = cb_data;
  session->free_cb_data_cb = free_data_cb;

  if (!context->engine->init_session (session,
                                      read_cb,
                                      write_cb,
                                      cb_data))
    {
      MHD_TLS_LOG_CONTEXT (context,
                           _("Engine %s failed to initialize TLS session\n"),
                           context->engine->name);
      free (session);
      return NULL;
    }

  return session;
}

void
MHD_TLS_del_session (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return;

  session->context->engine->deinit_session (session);
  if (NULL != session->cb_data && NULL != session->free_cb_data_cb)
    session->free_cb_data_cb (session->cb_data);
  free (session);
}

void *
MHD_TLS_get_specific_session (struct MHD_TLS_Session * session)
{
  if (NULL == session)
    return NULL;
  return session->context->engine->get_specific_session (session);
}

enum MHD_TLS_ProtocolVersion
MHD_TLS_get_session_protocol_version (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return MHD_TLS_PROTOCOL_VERSION_UNKNOWN;
  return session->context->engine->get_session_protocol_version (session);
}

enum MHD_TLS_CipherAlgorithm
MHD_TLS_get_session_cipher_algorithm (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return MHD_TLS_CIPHER_ALGORITHM_UNKNOWN;
  return session->context->engine->get_session_cipher_algorithm (session);
}

ssize_t
MHD_TLS_session_handshake (struct MHD_TLS_Session * session)
{
  if (NULL == session)
    return MHD_TLS_IO_INVALID_PARAMS;

  return session->context->engine->session_handshake (session);
}

ssize_t
MHD_TLS_session_close (struct MHD_TLS_Session * session)
{
  if (NULL == session)
    return MHD_TLS_IO_INVALID_PARAMS;

  return session->context->engine->session_close (session);
}


bool
MHD_TLS_session_wants_read (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return false;

  return session->context->engine->session_wants_read (session);
}

bool
MHD_TLS_session_wants_write (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return false;

  return session->context->engine->session_wants_write (session);
}

size_t
MHD_TLS_session_read_pending (struct MHD_TLS_Session *session)
{
  if (NULL == session)
    return 0;

  return session->context->engine->session_read_pending (session);
}

ssize_t
MHD_TLS_session_read (struct MHD_TLS_Session * session,
                      void *buf,
                      size_t size)
{
  if (NULL == session)
    return MHD_TLS_IO_INVALID_PARAMS;
  if (0 == size)
    return 0;
  if (NULL == buf)
    return MHD_TLS_IO_INVALID_PARAMS;

  if (size > SSIZE_MAX)
    size = SSIZE_MAX;

  return session->context->engine->session_read (session,
                                                 buf,
                                                 size);
}

ssize_t
MHD_TLS_session_write (struct MHD_TLS_Session * session,
                       const void *buf,
                       size_t size)
{
  if (NULL == session)
    return MHD_TLS_IO_INVALID_PARAMS;
  if (0 == size)
    return 0;
  if (NULL == buf)
    return MHD_TLS_IO_INVALID_PARAMS;

  if (size > SSIZE_MAX)
    size = SSIZE_MAX;

  return session->context->engine->session_write (session,
                                                  buf,
                                                  size);
}
