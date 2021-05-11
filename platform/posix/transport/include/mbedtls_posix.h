/*
 * AWS IoT Device SDK for Embedded C 202103.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef MBEDTLS_POSIX_H_
#define MBEDTLS_POSIX_H_

/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/

/* Logging related header files are required to be included in the following order:
 * 1. Include the header file "logging_levels.h".
 * 2. Define LIBRARY_LOG_NAME and  LIBRARY_LOG_LEVEL.
 * 3. Include the header file "logging_stack.h".
 */

/* Include header that defines log levels. */
#include "logging_levels.h"

/* Logging configuration for the transport interface implementation which uses
 * OpenSSL and Sockets. */
#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME     "MBEDTLS"
#endif
#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_DEBUG
#endif

#include "logging_stack.h"

/************ End of logging configuration ****************/

// /* OpenSSL include. */
// #include <openssl/ssl.h>

/* Transport includes. */
#include "transport_interface.h"

/* Socket include. */
#include "sockets_posix.h"

/* mbed TLS includes. */
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"

/**
 * @brief Secured connection context.
 */
typedef struct SSLContext
{
    mbedtls_ssl_config config;
    mbedtls_ssl_context context;
    mbedtls_x509_crt_profile certProfile;
    mbedtls_x509_crt rootCa;
    mbedtls_x509_crt clientCert;
    mbedtls_pk_context privKey;
    mbedtls_entropy_context entropyContext;
    mbedtls_ctr_drbg_context ctrDrgbContext;
} SSLContext_t;

/**
 * @brief Parameters for the transport-interface
 * implementation that uses OpenSSL and POSIX sockets.
 *
 * @note For this transport implementation, the socket descriptor and
 * SSL context is used.
 */
typedef struct TlsTransportParams
{
    SSLContext_t sslContext;
    mbedtls_net_context networkContext;
} TlsTransportParams_t;

/**
 * @brief TLS Connect / Disconnect return status.
 */
typedef enum TlsTransportStatus
{
    TLS_TRANSPORT_SUCCESS = 0,         /**< Function successfully completed. */
    TLS_TRANSPORT_INVALID_PARAMETER,   /**< At least one parameter was invalid. */
    TLS_TRANSPORT_INSUFFICIENT_MEMORY, /**< Insufficient memory required to establish connection. */
    TLS_TRANSPORT_INVALID_CREDENTIALS, /**< Provided credentials were invalid. */
    TLS_TRANSPORT_HANDSHAKE_FAILED,    /**< Performing TLS handshake with server failed. */
    TLS_TRANSPORT_INTERNAL_ERROR,      /**< A call to a system API resulted in an internal error. */
    TLS_TRANSPORT_CONNECT_FAILURE      /**< Initial connection to the server failed. */
} TlsTransportStatus_t;


/**
 * @brief Contains the credentials necessary for tls connection setup.
 */
typedef struct NetworkCredentials
{
    const uint8_t * pRootCaPath;     /**< @brief String representing a trusted server root certificate. */
    const uint8_t * pClientCertPath; /**< @brief String representing the client certificate. */
    const uint8_t * pPrivateKeyPath; /**< @brief String representing the client certificate's private key. */
    const uint8_t * pHostname;       /**< @brief Size associated with #NetworkCredentials.pPrivateKey. */
} NetworkCredentials_t;

/**
 * @brief Sets up a TLS session on top of a TCP connection using the OpenSSL API.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 * @param[in] pServerInfo Server connection info.
 * @param[in] pOpensslCredentials Credentials for the TLS connection.
 * @param[in] sendTimeoutMs Timeout for transport send.
 * @param[in] recvTimeoutMs Timeout for transport recv.
 *
 * @note A timeout of 0 means infinite timeout.
 *
 * @return #OPENSSL_SUCCESS on success;
 * #OPENSSL_INVALID_PARAMETER, #OPENSSL_INVALID_CREDENTIALS,
 * #OPENSSL_INVALID_CREDENTIALS, #OPENSSL_SYSTEM_ERROR on failure.
 */
TlsTransportStatus_t MBedTLS_Connect( NetworkContext_t * pNetworkContext,
                                 const ServerInfo_t * pServerInfo,
                                 const NetworkCredentials_t * pNetworkCredentials,
                                 uint32_t sendTimeoutMs,
                                 uint32_t recvTimeoutMs );

/**
 * @brief Closes a TLS session on top of a TCP connection using the OpenSSL API.
 *
 * @param[out] pNetworkContext The output parameter to end the TLS session and
 * clean the created network context.
 *
 * @return #OPENSSL_SUCCESS on success; #OPENSSL_INVALID_PARAMETER on failure.
 */
TlsTransportStatus_t MBedTLS_Disconnect( const NetworkContext_t * pNetworkContext );

/**
 * @brief Receives data over an established TLS session using the OpenSSL API.
 *
 * This can be used as #TransportInterface.recv function for receiving data
 * from the network.
 *
 * @param[in] pNetworkContext The network context created using Openssl_Connect API.
 * @param[out] pBuffer Buffer to receive network data into.
 * @param[in] bytesToRecv Number of bytes requested from the network.
 *
 * @return Number of bytes received if successful; negative value to indicate failure.
 * A return value of zero represents that the receive operation can be retried.
 */
int32_t MBedTLS_Recv( NetworkContext_t * pNetworkContext,
                      void * pBuffer,
                      size_t bytesToRecv );

/**
 * @brief Sends data over an established TLS session using the OpenSSL API.
 *
 * This can be used as the #TransportInterface.send function to send data
 * over the network.
 *
 * @param[in] pNetworkContext The network context created using Openssl_Connect API.
 * @param[in] pBuffer Buffer containing the bytes to send over the network stack.
 * @param[in] bytesToSend Number of bytes to send over the network.
 *
 * @return Number of bytes sent if successful; negative value on error.
 *
 * @note This function does not return zero value because it cannot be retried
 * on send operation failure.
 */
int32_t MBedTLS_Send( NetworkContext_t * pNetworkContext,
                      const void * pBuffer,
                      size_t bytesToSend );

#endif /* ifndef MBEDTLS_POSIX_H_ */
