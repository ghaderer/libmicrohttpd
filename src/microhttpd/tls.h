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
 * @file tls.h
 * @brief TLS engine
 *
 * We provide a simple abstraction of the TLS functions we need to set up a TLS
 * connection, and transfer data over it. Except for #MHD_TLS_global_init and
 * #MHD_TLS_global_deinit, all functions are thread-safe as long as you don't
 * share a context or session between multiple threads. A few functions may
 * have relaxed rules which will be indicated in their description.
 *
 * I/O operations on TLS sessions are always in non-blocking mode.
 */

#ifndef TLS_H
#define TLS_H

/* must come first */
#include "mhd_options.h"

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif

#include "platform.h"
#include "microhttpd.h"

#ifdef HTTPS_SUPPORT

struct MHD_TLS_Engine;
struct MHD_TLS_Context;
struct MHD_TLS_Session;

/**
 * @brief Callback to free opaque data.
 */
typedef void
(*MHD_TLS_FreeCallback)(void *data);

/**
 * @brief Callback to get a certificate.
 */
typedef int
(*MHD_TLS_GetCertificateCallback)();

/**
 * @brief Callback to read data from the transport layer.
 *
 * @return -1 on error and set errno, the number of bytes read on success.
 */
typedef ssize_t
(*MHD_TLS_ReadCallback) (void *context,
                         void *buf,
                         size_t size);

/**
 * @brief Callback to write data to the transport layer.
 *
 * @return -1 on error and set errno, the number of bytes written on success.
 */
typedef ssize_t
(*MHD_TLS_WriteCallback) (void *context,
                          const void *buf,
                          size_t size);

/**
 * @name Special return values for session read/write functions.
 * @{
 */

/**
 * @brief An unknown error occured.
 */
#define MHD_TLS_IO_UNKNOWN_ERROR ((ssize_t)-1)

/**
 * @brief Invalid parameters.
 */
#define MHD_TLS_IO_INVALID_PARAMS ((ssize_t)-2)

/**
 * @brief Session was closed (closure alert occured).
 */
#define MHD_TLS_IO_SESSION_CLOSED ((ssize_t)-3)

/**
 * @brief Session wants to read more data.
 *
 * You must do whatever is necessary to fetch more data and repeat the call.
 */
#define MHD_TLS_IO_WANTS_READ ((ssize_t)-4)

/**
 * @brief Session wants to write more data.
 *
 * You must do whatever is necessary to free space in the output queue and
 * repeat the call.
 */
#define MHD_TLS_IO_WANTS_WRITE ((ssize_t)-5)

/** @} */

#ifdef ENABLE_GNUTLS
#include "tls_gnutls.h"
#endif

#ifdef ENABLE_OPENSSL
#include "tls_openssl.h"
#endif

/**
 * @brief TLS engine structure.
 *
 * It contains an engine's implementation as a set of engine-specific
 * functions. Context and sessions functions must be thread-safe as long as
 * they're not called on the same context or session object.
 */
struct MHD_TLS_Engine
{
  /**
   * @brief Human-readable engine name.
   *
   * It must be statically-allocated. It's only used for debugging purposes.
   */
  const char *name;

  /**
   * @brief Engine type.
   */
  enum MHD_TLS_EngineType type;

  /**
   * @brief Test if an engine supports a given feature.
   *
   * @param feature A TLS feature.
   *
   * @return @c true if supported, @c false otherwise.
   *
   * @sa #MHD_TLS_engine_has_feature
   */
  bool (*has_feature)(enum MHD_TLS_FEATURE feature);

  /**
   * @brief Initialize the engine-specific data of a TLS context.
   *
   * The engine-independent attributes are already initialized.
   *
   * @param context TLS context.
   *
   * @return @c true on success, @c false on failure.
   *
   * @sa #MHD_TLS_create_context
   */
  bool (*init_context) (struct MHD_TLS_Context *context);

  /**
   * @brief Releases the engine-specific data of a TLS context.
   *
   * The engine-independent attributes are still initialized.
   *
   * @param context TLS context.
   *
   * @sa #MHD_TLS_del_context
   */
  void (*deinit_context) (struct MHD_TLS_Context * context);

  /**
   * @brief Set a certificate selection callback.
   *
   * @param context TLS context.
   * @param cb Certificate selection callback, or @c NULL to unset.
   *
   * @see #MHD_TLS_set_context_certificate_cb
   */
  bool (*set_context_certificate_cb) (struct MHD_TLS_Context *context,
                                      MHD_TLS_GetCertificateCallback cb);

  /**
   * @brief Set Diffie-Hellman parameters.
   *
   * @param context TLS context.
   * @param params DH parameters in PEM format.
   *
   * @return @c true on success, @c false otherwise.
   *
   * @see #MHD_TLS_set_context_dh_params
   */
  bool (*set_context_dh_params) (struct MHD_TLS_Context *context,
                                 const char *params);

  /**
   * @brief Set the server certificate and private key.
   *
   * @param context TLS context.
   * @param certificate X.509 certificate in PEM format.
   * @param private_key Private key in PEM format.
   * @param password Private key password or @c NULL if not password-protected.
   *
   * @return @c true on success, @c false otherwise.
   *
   * @see #MHD_TLS_set_context_certificate
   */
  bool (*set_context_certificate) (struct MHD_TLS_Context *context,
                                   const char *certificate,
                                   const char *private_key,
                                   const char *password);

  /**
   * @brief Set trust certificates for client certificate verification.
   *
   * @param context TLS context.
   * @param certificate Certificate chain in PEM format.
   *
   * @return @c true on success, @c false otherwise.
   *
   * @see #MHD_TLS_set_context_trust_certificate
   */
  bool (*set_context_trust_certificate) (struct MHD_TLS_Context *context,
                                         const char *certificate);

  /**
   * @brief Set the client certificate mode.
   *
   * @param context TLS context.
   * @param mode Don't ask, request or require a client certificate.
   *
   * @return @c true on success, @c false otherwise.
   *
   * @sa #MHD_TLS_set_context_client_certificate_mode
   */
  bool (*set_context_client_certificate_mode) (struct MHD_TLS_Context *context,
                                               enum MHD_TLS_ClientCertificateMode mode);

  /**
   * @brief Set certificate revocation list for client certificate verification.
   *
   * @param context TLS context.
   * @param crl Certificate revocation list in PEM format.
   *
   * @return @c true on success, @c false otherwise.
   *
   * @see #MHD_TLS_set_context_certificate_revocation_list
   */
  bool (*set_context_certificate_revocation_list) (struct MHD_TLS_Context *context,
                                                   const char *crl);

  /**
   * @brief Set the priorities to use on encyption, key exchange and MAC
   * algorithms.
   *
   * @param context TLS context.
   * @param priorities Priority description string.
   *
   * @return @c true on success, @c false otherwise.
   *
   * @sa #MHD_TLS_set_context_cipher_priorities
   */
  bool (*set_context_cipher_priorities) (struct MHD_TLS_Context *context,
                                         const char *priorities);

  /**
   * @brief Create a TLS session.
   *
   * The engine-independent attributes are already initialized.
   *
   * This function must be thread-safe even when using the same context.
   *
   * @param context TLS context.
   * @param read_cb Callback to read data from the transport layer.
   * @param write_cb Callback to write data to the transport layer.
   * @param cb_data Opaque data for read/write callbacks.
   *
   * @return @c true on success, @c false otherwise.
   *
   * @sa #MHD_TLS_create_session
   */
  bool (*init_session) (struct MHD_TLS_Session * session,
                        MHD_TLS_ReadCallback read_cb,
                        MHD_TLS_WriteCallback write_cb,
                        void *cb_data);

  /**
   * @brief Delete a TLS session.
   *
   * The engine-independent attributes are still initialized.
   *
   * @param session TLS session.
   *
   * @sa #MHD_TLS_del_session
   */
  void (*deinit_session) (struct MHD_TLS_Session * session);

  /**
   * @brief Get the engine-specific session.
   *
   * @param session TLS session.
   *
   * @return Engine-specific session. The pointer must remain valid until the
   * session is deleted.
   *
   * @sa #MHD_TLS_get_specific_session
   */
  void * (*get_specific_session) (struct MHD_TLS_Session * session);

  /**
   * @brief Get the version of the currently used protocol.
   *
   * @param session TLS session.
   *
   * @return Protocol version.
   *
   * @sa #MHD_TLS_get_session_protocol_version
   */
  enum MHD_TLS_ProtocolVersion (*get_session_protocol_version) (struct MHD_TLS_Session *session);

  /**
   * @brief Get the currently used cipher algorithm.
   *
   * @param session TLS session.
   *
   * @return Cipher algorithm.
   *
   * @sa #MHD_TLS_get_session_cipher_algorithm
   */
  enum MHD_TLS_CipherAlgorithm (*get_session_cipher_algorithm) (struct MHD_TLS_Session *session);

  /**
   * @brief Make a TLS handshake a set up the TLS connection.
   *
   * @param session TLS session.
   *
   * @return
   * - 0 on success.
   * - A @c MHD_TLS_IO_XXX error code otherwise.
   *
   * @sa #MHD_TLS_session_handshake
   */
  ssize_t (*session_handshake) (struct MHD_TLS_Session * session);

  /**
   * @brief Tear down the TLS connection.
   *
   * @param session TLS session.
   *
   * @return
   * - 0 on success.
   * - A @c MHD_TLS_IO_XXX error code otherwise.
   *
   * @sa #MHD_TLS_session_close
   */
  ssize_t (*session_close) (struct MHD_TLS_Session * session);

  /**
   * @brief Test if the TLS sessions needs to read more data.
   *
   * @param session TLS session.
   *
   * @return @c true if it needs to read data, @c false otherwise.
   *
   * @sa #MHD_TLS_session_wants_read
   */
  bool (*session_wants_read) (struct MHD_TLS_Session * session);

  /**
   * @brief Test if the TLS sessions needs to write data.
   *
   * @param session TLS session.
   *
   * @return @c true if it needs to write data, @c false otherwise.
   *
   * @sa #MHD_TLS_session_wants_write
   */
  bool (*session_wants_write) (struct MHD_TLS_Session * session);

  /**
   * @brief Test if we can read application data out of the TLS connection.
   *
   * @param session TLS session.
   *
   * @return How many bytes are available for reading.
   *
   * @sa #MHD_TLS_session_read_pending
   */
  size_t (*session_read_pending) (struct MHD_TLS_Session *session);

  /**
   * @brief Read application data out of the TLS connection.
   *
   * @param session TLS session.
   * @param buf Where to store application data.
   * @param size Maximum number of bytes to return.
   *
   * @return
   * - The number of bytes returned on success.
   * - 0 if no data is available.
   * - A @c MHD_TLS_IO_XXX error code otherwise.
   *
   * @sa #MHD_TLS_session_read
   */
  ssize_t (*session_read) (struct MHD_TLS_Session * session,
                           void *buf,
                           size_t size);

  /**
   * @brief Write application data to the TLS connection.
   *
   * @param session TLS session.
   * @param buf Application data.
   * @param size How many bytes to write.
   *
   * @return
   * - The number of bytes written on success.
   * - A @c MHD_TLS_IO_XXX error code otherwise.
   *
   * @sa #MHD_TLS_session_write
   */
  ssize_t (*session_write) (struct MHD_TLS_Session * session,
                            const void *buf,
                            size_t size);
};

/**
 * @brief TLS context.
 *
 * It stores information which is shared among all sessions. Changing a context
 * has an undefined behavior on existing sessions. Don't do it!
 *
 * It provides a logging callback to keep this code insulated of the daemon
 * logging mechanism and ease unit testing. If you don't explicitly set a
 * callback, messages will be discarded.
 */
struct MHD_TLS_Context
{
  /**
   * @brief Engine which created this context.
   */
  const struct MHD_TLS_Engine * engine;

  /* The following fields are set by @c MHD_TLS_set_context_logging_cb(). */

  /**
   * @brief Logging callback.
   */
  MHD_LogCallback log_cb;

  /**
   * @brief Opaque data for logging callback.
   */
  void *log_data;

  /**
   * @brief Function to free @c log_data.
   */
  MHD_TLS_FreeCallback free_log_data_cb;

  /**
   * @brief Engine-specific data.
   */
  union
  {
#ifdef ENABLE_GNUTLS
    struct MHD_GnuTLS_Context gnutls;
#endif
#ifdef ENABLE_OPENSSL
    struct MHD_OpenSSL_Context openssl;
#endif
  } d;
};

/**
 * @brief TLS session.
 *
 * It stores information which is specific to a given connection.
 */
struct MHD_TLS_Session
{
  /**
   * @brief Context which created this session.
   */
  struct MHD_TLS_Context * context;

  /**
   * @brief Opaque data for read/write callbacks.
   */
  void * cb_data;

  /**
   * @brief Function to free @c cb_data.
   */
  MHD_TLS_FreeCallback free_cb_data_cb;

  /**
   * @brief Engine-specific data.
   */
  union
  {
#ifdef ENABLE_GNUTLS
    struct MHD_GnuTLS_Session gnutls;
#endif
#ifdef ENABLE_OPENSSL
    struct MHD_OpenSSL_Session openssl;
#endif
  } d;
};

#ifdef HAVE_MESSAGES

/**
 * @brief Send a message to the context's logging callback.
 *
 * @param context TLS context.
 * @param format printf-like format string.
 * @param ... Format arguments.
 */
void
MHD_TLS_LOG_CONTEXT (struct MHD_TLS_Context *context,
                     const char *format,
                     ...);

/**
 * @brief Send a message to the session's context's logging callback.
 *
 * @param session TLS session.
 * @param format printf-like format string.
 * @param ... Format arguments.
 */
void
MHD_TLS_LOG_SESSION (struct MHD_TLS_Session *session,
                     const char *format,
                     ...);

#else /* !HAVE_MESSAGES */

/**
 * @brief Drop a message.
 *
 * @param context TLS context.
 * @param format printf-like format string.
 * @param ... Format arguments.
 */
#define MHD_TLS_LOG_CONTEXT(context, format, ...) do {} while(false)

/**
 * @brief Drop a message.
 *
 * @param session TLS session.
 * @param format printf-like format string.
 * @param ... Format arguments.
 */
#define MHD_TLS_LOG_SESSION(session, format, ...) do {} while(false)

#endif /* !HAVE_MESSAGES */

/**
 * @brief Initialize all TLS engines.
 *
 * If an engine fails to initialize, the program's execution is aborted. You
 * can safely call it several times.
 */
void
MHD_TLS_global_init (void);

/**
 * @brief Release the resources used by all TLS engines.
 *
 * You can safely call it several times, and even if #MHD_TLS_global_init has
 * not been called yet.
 */
void
MHD_TLS_global_deinit (void);

/**
 * @brief Get an engine's implementation.
 *
 * @param type Engine type.
 *
 * @return @c NULL if the engine type is not supported, the engine's
 * implementation otherwise.
 */
const struct MHD_TLS_Engine *
MHD_TLS_lookup_engine (enum MHD_TLS_EngineType type);

/**
 * @brief Test if an engine supports a given feature.
 *
 * @param engine TLS engine.
 * @param feature A TLS feature.
 *
 * @return @c true if supported, @c false otherwise.
 */
bool
MHD_TLS_engine_has_feature (const struct MHD_TLS_Engine *engine,
                            enum MHD_TLS_FEATURE feature);

/**
 * @brief Create a TLS context.
 *
 * @param engine Engine implementation.
 * @param cb Logging callback.
 * @param data Opaque data for logging callback.
 * @param free_data_cb Callback to free opaque data.
 *
 * @return @c NULL on failure, a TLS context otherwise.
 */
struct MHD_TLS_Context *
MHD_TLS_create_context (const struct MHD_TLS_Engine *engine,
                        MHD_LogCallback cb,
                        void *data,
                        MHD_TLS_FreeCallback free_data_cb);

/**
 * @brief Delete a TLS context.
 *
 * You are responsible for deleting all TLS sessions allocated with this
 * context first. If you don't, the behavior is undefined.
 *
 * If the context is @c NULL, it does nothing.
 *
 * @param context TLS context.
 */
void
MHD_TLS_del_context (struct MHD_TLS_Context *context);


/**
 * @brief Send a message to the context's logging callback.
 *
 * @param context TLS context.
 * @param format printf-like format string.
 * @param ... Format arguments.
 */
void
MHD_TLS_log_context (struct MHD_TLS_Context *context,
                     const char *format,
                     ...);

/**
 * @brief Send a message to the context's logging callback.
 *
 * @param context TLS context.
 * @param format printf-like format string.
 * @param args Format arguments.
 */
void
MHD_TLS_log_context_va (struct MHD_TLS_Context *context,
                        const char *format,
                        va_list args);

/**
 * @brief Set a certificate selection callback.
 *
 * For GnuTLS, it must be a pointer of type @c
 * gnutls_certificate_retrieve_function2.
 *
 * For OpenSSL, it must have the signature expected by @c
 * SSL_CTX_set_cert_cb(). It will receive the OpenSSL SSL session as its first
 * parameter. The second parameter will always be @c NULL.
 *
 * This callback will be called even if a certificate is set by
 * #MHD_TLS_set_context_certificate.
 *
 * @param context TLS context.
 * @param cb Certificate selection callback, or @c NULL to unset.
 *
 * @see #MHD_TLS_FEATURE_CERT_CALLBACK
 */
bool
MHD_TLS_set_context_certificate_cb (struct MHD_TLS_Context *context,
                                    MHD_TLS_GetCertificateCallback cb);

/**
 * @brief Set Diffie-Hellman parameters.
 *
 * @param context TLS context.
 * @param params DH parameters in PEM format.
 *
 * @return @c true on success, @c false otherwise.
 */
bool
MHD_TLS_set_context_dh_params (struct MHD_TLS_Context *context,
                               const char *params);

/**
 * @brief Set the server certificate and private key.
 *
 * @param context TLS context.
 * @param certificate X.509 certificate in PEM format.
 * @param private_key Private key in PEM format.
 * @param password Private key password or @c NULL if not password-protected.
 *
 * @return @c true on success, @c false otherwise.
 *
 * @see #MHD_TLS_FEATURE_KEY_PASSWORD
 */
bool
MHD_TLS_set_context_certificate (struct MHD_TLS_Context *context,
                                 const char *certificate,
                                 const char *private_key,
                                 const char *password);

/**
 * @brief Set trust certificates for client certificate verification.
 *
 * @param context TLS context.
 * @param certificate Certificate chain in PEM format.
 *
 * @return @c true on success, @c false otherwise.
 */
bool
MHD_TLS_set_context_trust_certificate (struct MHD_TLS_Context *context,
                                       const char *certificate);

/**
 * @brief Set the client certificate mode.
 *
 * By default, we don't request a client certificate. But you can request one and
 * even make it mandatory.
 *
 * @param context TLS context.
 * @param mode Don't ask, request or require a client certificate.
 *
 * @return @c true on success, @c false otherwise.
 */
bool
MHD_TLS_set_context_client_certificate_mode (struct MHD_TLS_Context *context,
                                             enum MHD_TLS_ClientCertificateMode mode);

/**
 * @brief Set the client certificate revocation list for client certificate verification.
 *
 * By default, client certificates are not checked for revocation. But you can provide
 * a certificate revocation list (CRL) to explicitly make client certificate verification
 * fail for specific certificates (revoke certificates).
 *
 * @param context TLS context.
 * @param crl Certificate revocation list in PEM format.
 *
 * @return @c true on success, @c false otherwise.
 */
bool
MHD_TLS_set_context_certificate_revocation_list (struct MHD_TLS_Context *context,
                                                 const char *crl);

/**
 * @brief Set the priorities to use on encyption, key exchange and MAC
 * algorithms.
 *
 * For GnuTLS, it must use the format expected by @c gnutls_priority_init. It
 * defaults to "NORMAL".
 *
 * For OpenSSL, it must use the format expected by @c SSL_CTX_set_cipher_list.
 *
 * @param context TLS context.
 * @param priorities Priority description string.
 *
 * @return @c true on success, @c false otherwise.
 */
bool
MHD_TLS_set_context_cipher_priorities (struct MHD_TLS_Context *context,
                                       const char *priorities);

/**
 * @brief Create a TLS session.
 *
 * A TLS session maintains per-connection TLS state information. It manages TLS
 * handshakes and other TLS messages transparently. You just have to call
 * #MHD_TLS_session_handshake to set up a TLS connection, call
 * #MHD_TLS_session_read or #MHD_TLS_session_write to read or write data over
 * the TLS connection, then #MHD_TLS_session_close to forcibly close it.  Note
 * that it won't close the TCP connection as we don't even know about it.
 *
 * To read or write data, the TLS session will call user-provided callbacks.
 * They must run in non-blocking mode.
 *
 * This function is thread-safe even when using the same context.
 *
 * @param context TLS context.
 * @param read_cb Callback to read data from the transport layer.
 * @param write_cb Callback to write data to the transport layer.
 * @param cb_data Opaque data for read/write callbacks.
 * @param free_data_cb Callback to free opaque data.
 *
 * @return @c NULL on failure, a TLS session otherwise.
 */
struct MHD_TLS_Session *
MHD_TLS_create_session (struct MHD_TLS_Context * context,
                        MHD_TLS_ReadCallback read_cb,
                        MHD_TLS_WriteCallback write_cb,
                        void *cb_data,
                        MHD_TLS_FreeCallback free_data_cb);

/**
 * @brief Delete a TLS session.
 *
 * @param session TLS session.
 */
void
MHD_TLS_del_session (struct MHD_TLS_Session *session);

/**
 * @brief Get the engine-specific session.
 *
 * For GnuTLS, it returns a @c gnutls_session_t object.
 *
 * For OpenSSL, is returns a @c SSL object.
 *
 * @param session TLS session.
 *
 * @return Engine-specific session. The pointer is guaranteed to remain valid
 * until the session is deleted.
 */
void *
MHD_TLS_get_specific_session (struct MHD_TLS_Session * session);

/**
 * @brief Get the version of the currently used protocol.
 *
 * @param session TLS session.
 *
 * @return Protocol version.
 */
enum MHD_TLS_ProtocolVersion
MHD_TLS_get_session_protocol_version (struct MHD_TLS_Session *session);

/**
 * @brief Get the currently used cipher algorithm.
 *
 * @param session TLS session.
 *
 * @return Cipher algorithm.
 */
enum MHD_TLS_CipherAlgorithm
MHD_TLS_get_session_cipher_algorithm (struct MHD_TLS_Session *session);

/**
 * @brief Make a TLS handshake a set up the TLS connection.
 *
 * If the TLS session needs to read data but not enough data is available, it
 * will return #MHD_TLS_IO_WANTS_READ. You must do whatever is necessary to
 * get more data and call this function again.
 *
 * If the TLS session needs to write data but it could not because the output
 * queue is fill, it will return #MHD_TLS_IO_WANTS_WRITE. You must do whatever
 * is necessary to free space and call this function again.
 *
 * @param session TLS session.
 *
 * @return
 * - 0 on success.
 * - A @c MHD_TLS_IO_XXX error code otherwise.
 */
ssize_t
MHD_TLS_session_handshake (struct MHD_TLS_Session * session);

/**
 * @brief Tear down the TLS connection.
 *
 * @param session TLS session.
 *
 * @return
 * - 0 on success.
 * - A @c MHD_TLS_IO_XXX error code otherwise.
 *
 * @sa #MHD_TLS_session_handshake
 */
ssize_t
MHD_TLS_session_close (struct MHD_TLS_Session * session);

/**
 * @brief Test if the TLS sessions needs to read more data.
 *
 * It means the read callback was not able to provide enough data. Fetch more
 * data and repeat your operation (handshake, read or close).
 *
 * @param session TLS session.
 *
 * @return @c true if it needs to read data, @c false otherwise.
 *
 * @sa #MHD_TLS_session_handshake
 */
bool
MHD_TLS_session_wants_read (struct MHD_TLS_Session *session);

/**
 * @brief Test if the TLS sessions needs to write data.
 *
 * It means the write callback was not able to write all the data. Free space
 * in the output queue and repeat your operation (handshake, write or close).
 *
 * @param session TLS session.
 *
 * @return @c true if it needs to write data, @c false otherwise.
 *
 * @sa #MHD_TLS_session_handshake
 */
bool
MHD_TLS_session_wants_write (struct MHD_TLS_Session *session);

/**
 * @brief Test if we can read application data out of the TLS connection.
 *
 * If it's the case, it means calling #MHD_TLS_session_read will return data.
 *
 * @param session TLS session.
 *
 * @return How many bytes are available for reading.
 */
size_t
MHD_TLS_session_read_pending (struct MHD_TLS_Session *session);

/**
 * @brief Read application data out of the TLS connection.
 *
 * @param session TLS session.
 * @param buf Where to store application data.
 * @param size Maximum number of bytes to return.
 *
 * @return
 * - The number of bytes returned on success.
 * - 0 if no data is available.
 * - A @c MHD_TLS_IO_XXX error code otherwise.
 *
 * @sa #MHD_TLS_session_read_pending, #MHD_TLS_session_handshake
 */
ssize_t MHD_TLS_session_read (struct MHD_TLS_Session * session,
                              void *buf,
                              size_t size);

/**
 * @brief Write application data to the TLS connection.
 *
 * @param session TLS session.
 * @param buf Application data.
 * @param size How many bytes to write.
 *
 * @return
 * - The number of bytes written on success.
 * - A @c MHD_TLS_IO_XXX error code otherwise.
 *
 * @sa #MHD_TLS_session_handshake
 */
ssize_t MHD_TLS_session_write (struct MHD_TLS_Session * session,
                               const void *buf,
                               size_t size);

#endif /* HTTPS_SUPPORT */

#endif
