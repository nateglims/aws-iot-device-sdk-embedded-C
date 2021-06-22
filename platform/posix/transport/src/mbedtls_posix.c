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

/* Standard includes. */
#include <assert.h>
#include <string.h>
#include <stdlib.h>

/* POSIX socket include. */
#include <unistd.h>

/* Transport interface include. */
#include "transport_interface.h"

#include "mbedtls_posix.h"

#if defined( MBEDTLS_DEBUG_C )
    #include "mbedtls/debug.h"
#endif

static void my_debug( void * ctx,
                      int level,
                      const char * file,
                      int line,
                      const char * str )
{
    ( ( void ) level );

    printf( "%s:%04d: %s", file, line, str );
    fflush( stdout );
}

struct NetworkContext
{
    TlsTransportParams_t * pParams;
};


/*-----------------------------------------------------------*/

int32_t MBedTLS_Recv( NetworkContext_t * pNetworkContext,
                      void * pBuffer,
                      size_t bytesToRecv )
{
    int ret = 0;

    LogDebug( ( "recv: receiving %d bytes\n", ( int ) bytesToRecv ) );

    ret = mbedtls_ssl_read( &( pNetworkContext->pParams->sslContext.context ), pBuffer, bytesToRecv );

    /* Can be retried. */
    if( ( ret == MBEDTLS_ERR_SSL_TIMEOUT ) ||
        ( ret == MBEDTLS_ERR_SSL_WANT_READ ) ||
        ( ret == MBEDTLS_ERR_SSL_WANT_WRITE ) )
    {
        ret = 0;
    }
    else if( ret < 0 )
    {
        LogError( ( "failed\n  ! mbedtls_ssl_read returned -0x%x\n\n", ( unsigned int ) -ret ) );
    }

    LogDebug( ( "recv: retvalue %d\n", ret ) );
    return ret;
}
/*-----------------------------------------------------------*/

int32_t MBedTLS_Send( NetworkContext_t * pNetworkContext,
                      const void * pBuffer,
                      size_t bytesToSend )
{
    int ret = 0;

    LogDebug( ( "send: sending %d bytes\n", ( int ) bytesToSend ) );

    ret = mbedtls_ssl_write( &( pNetworkContext->pParams->sslContext.context ), pBuffer, bytesToSend );

    /* Retriable. */
    if( ( ret == MBEDTLS_ERR_SSL_TIMEOUT ) ||
        ( ret == MBEDTLS_ERR_SSL_WANT_READ ) ||
        ( ret == MBEDTLS_ERR_SSL_WANT_WRITE ) )
    {
        ret = 0;
    }
    else if( ret < 0 )
    {
        LogError( ( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret ) );
    }

    LogDebug( ( "send: retvalue %d\n", ret ) );
    return ret;
}

TlsTransportStatus_t MBedTLS_Disconnect( const NetworkContext_t * pNetworkContext )
{
    int ret = 0;
    TlsTransportStatus_t exit_code = TLS_TRANSPORT_SUCCESS;

    ret = mbedtls_ssl_close_notify( &( pNetworkContext->pParams->sslContext.context ) );

    if( ( ret == MBEDTLS_ERR_SSL_WANT_READ ) ||
        ( ret == MBEDTLS_ERR_SSL_WANT_READ ) )
    {
        LogInfo( ( "Close mostly successful." ) );
        goto exit;
    }

    if( ret == 0 )
    {
        LogInfo( ( "Close successful." ) );
    }
    else
    {
        exit_code = TLS_TRANSPORT_INTERNAL_ERROR;
        LogError( ( " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret ) );
    }

exit:
    mbedtls_net_free( &( pNetworkContext->pParams->networkContext ) );
    return TLS_TRANSPORT_SUCCESS;
}

/*-----------------------------------------------------------*/

TlsTransportStatus_t MBedTLS_Connect( NetworkContext_t * pNetworkContext,
                                      const ServerInfo_t * pServerInfo,
                                      const NetworkCredentials_t * pNetworkCredentials,
                                      uint32_t sendTimeoutMs,
                                      uint32_t recvTimeoutMs )
{
    int exit_code = TLS_TRANSPORT_INTERNAL_ERROR;
    int ret = 1;

    ret = mbedtls_net_connect(
        &( pNetworkContext->pParams->networkContext ),
        pNetworkCredentials->pHostname,
        "8883",
        MBEDTLS_NET_PROTO_TCP
        );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! (root) mbedtls_net_connect returned %d\n\n", ret ) );
        goto exit;
    }

    while( ( ret = mbedtls_ssl_handshake( &( pNetworkContext->pParams->sslContext.context ) ) ) != 0 )
    {
        if( ( ret != MBEDTLS_ERR_SSL_WANT_READ ) && ( ret != MBEDTLS_ERR_SSL_WANT_WRITE ) )
        {
            LogError( ( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", ( unsigned int ) -ret ) );
            goto exit;
        }
    }

    ret = 0;
    ret = mbedtls_ssl_get_verify_result( &( pNetworkContext->pParams->sslContext.context ) );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! mbedtls_ssl_handshake returned 0x%x\n\n", ret ) );
        goto exit;
    }

    LogInfo( ( "Shook hands." ) );

    exit_code = TLS_TRANSPORT_SUCCESS;
exit:
    return exit_code;
}

TlsTransportStatus_t MBedTLS_Init( NetworkContext_t * pNetworkContext,
                                   const ServerInfo_t * pServerInfo,
                                   const NetworkCredentials_t * pNetworkCredentials,
                                   uint32_t sendTimeoutMs,
                                   uint32_t recvTimeoutMs )
{
    int exit_code = TLS_TRANSPORT_INTERNAL_ERROR;
    int ret = 1;

    #if defined( MBEDTLS_DEBUG_C )
        mbedtls_debug_set_threshold( 4 );
    #endif

    mbedtls_net_init( &( pNetworkContext->pParams->networkContext ) );
    mbedtls_ssl_init( &( pNetworkContext->pParams->sslContext.context ) );
    mbedtls_ssl_config_init( &( pNetworkContext->pParams->sslContext.config ) );
    mbedtls_x509_crt_init( &( pNetworkContext->pParams->sslContext.rootCa ) );
    mbedtls_x509_crt_init( &( pNetworkContext->pParams->sslContext.clientCert ) );
    mbedtls_pk_init( &( pNetworkContext->pParams->sslContext.privKey ) );
    mbedtls_ctr_drbg_init( &( pNetworkContext->pParams->sslContext.ctrDrgbContext ) );

    mbedtls_entropy_init( &( pNetworkContext->pParams->sslContext.entropyContext ) );
    ret = mbedtls_ctr_drbg_seed( &( pNetworkContext->pParams->sslContext.ctrDrgbContext ),
                                 mbedtls_entropy_func,
                                 &( pNetworkContext->pParams->sslContext.entropyContext ),
                                 NULL,
                                 0 );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret ) );
        goto exit;
    }

    ret = mbedtls_ssl_config_defaults( &( pNetworkContext->pParams->sslContext.config ),
                                       MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT
                                       );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret ) );
        goto exit;
    }

    mbedtls_ssl_conf_authmode( &( pNetworkContext->pParams->sslContext.config ), MBEDTLS_SSL_VERIFY_REQUIRED );
    mbedtls_ssl_conf_rng(
        &( pNetworkContext->pParams->sslContext.config ),
        mbedtls_ctr_drbg_random,
        &( pNetworkContext->pParams->sslContext.ctrDrgbContext )
        );
    mbedtls_ssl_conf_dbg( &pNetworkContext->pParams->sslContext.config, my_debug, stdout );

    mbedtls_ssl_conf_read_timeout(
        &( pNetworkContext->pParams->sslContext.config ),
        recvTimeoutMs
        );

    ret = mbedtls_x509_crt_parse_file(
        &( pNetworkContext->pParams->sslContext.rootCa ),
        pNetworkCredentials->pRootCaPath
        );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! (root) mbedtls_x509_crt_parse_file returned %d\n\n", ret ) );
        LogError( ( "  ! cert path: %s\n\n", pNetworkCredentials->pRootCaPath ) );
        goto exit;
    }

    mbedtls_ssl_conf_ca_chain(
        &( pNetworkContext->pParams->sslContext.config ),
        &( pNetworkContext->pParams->sslContext.rootCa ),
        NULL
        );

    ret = mbedtls_x509_crt_parse_file(
        &( pNetworkContext->pParams->sslContext.clientCert ),
        pNetworkCredentials->pClientCertPath
        );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! (client) mbedtls_x509_crt_parse_file returned %d\n\n", ret ) );
        LogError( ( "  ! cert path: %s\n\n", pNetworkCredentials->pClientCertPath ) );
        goto exit;
    }

    ret = mbedtls_pk_parse_keyfile(
        &( pNetworkContext->pParams->sslContext.privKey ),
        pNetworkCredentials->pPrivateKeyPath,
        NULL
        );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! mbedtls_pk_parse_keyfile returned %d\n\n", ret ) );
        goto exit;
    }

    ret = mbedtls_ssl_conf_own_cert(
        &( pNetworkContext->pParams->sslContext.config ),
        &( pNetworkContext->pParams->sslContext.clientCert ),
        &( pNetworkContext->pParams->sslContext.privKey )
        );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret ) );
        goto exit;
    }

    /* Skipped: ALPN and TLS MFLN */

    ret = mbedtls_ssl_setup(
        &( pNetworkContext->pParams->sslContext.context ),
        &( pNetworkContext->pParams->sslContext.config )
        );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret ) );
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(
        &( pNetworkContext->pParams->sslContext.context ),
        pNetworkCredentials->pHostname
        );

    if( ret != 0 )
    {
        LogError( ( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret ) );
        goto exit;
    }

    mbedtls_ssl_set_bio(
        &( pNetworkContext->pParams->sslContext.context ),
        &( pNetworkContext->pParams->networkContext ),
        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout
        );

    exit_code = TLS_TRANSPORT_SUCCESS;
exit:
    return exit_code;
}
