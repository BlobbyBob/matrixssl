/**
 *      @file    matrixsslGetSet.c
 *      @version $Format:%h%d$
 *
 *      Add-on API for accessing MatrixSSL structures without direct access
 *      to structure members. Use of this API will slightly enlarge the
 *      MatrixSSL binary but will enable building software that is not
 *      dependent on exact binary layout of structures such as ssl_t.
 */

/*
 *      Copyright (c) 2019 Verimatrix
 *      Copyright (c) 2013-2019 INSIDE Secure Corporation
 *      All Rights Reserved
 *
 *      This file can be edited to modify exact set of accessor functions
 *      provided.
 *
 *      The copyright notice above does not evidence any actual or intended
 *      publication of such source code.
 *
 *      This Module contains Proprietary Information of INSIDE and should be
 *      treated as Confidential.
 *
 *      The information in this file is provided for the exclusive use of the
 *      licensees of INSIDE. Such users have the right to use, modify,
 *      and incorporate this code into products for purposes authorized by the
 *      license agreement provided they include this notice and the associated
 *      copyright notice with any such product.
 *
 *      The information in this file is provided "AS IS" without warranty.
 */

#include "matrixsslImpl.h"
#include "matrixsslGetSet.h"
#include "osdep_stddef.h"
#ifdef MATRIX_LOG_GET
# include "osdep_stdio.h"
#endif
#ifdef MATRIX_LOG_SET
# include "osdep_stdio.h"
#endif


/* Get value of ssl_t member userPtr. */
void *matrixSslGetUserPtr(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->userPtr is %p\n", (void*)(uintptr_t) (ssl->userPtr));
#endif
        return ssl->userPtr;
    }

    return NULL;
}

/* Set value of ssl_t member userPtr. */
psRes_t matrixSslSetUserPtr(ssl_t *ssl, void *value)
{
    psRes_t res = PS_ARG_FAIL;

    if (ssl != NULL)
    {
        ssl->userPtr = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("ssl->userPtr=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of ssl_t member userDataPtr. */
void *matrixSslGetUserDataPtr(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->userDataPtr is %p\n", (void*)(uintptr_t) (ssl->userDataPtr));
#endif
        return ssl->userDataPtr;
    }

    return NULL;
}

/* Set value of ssl_t member userDataPtr. */
psRes_t matrixSslSetUserDataPtr(ssl_t *ssl, void *value)
{
    psRes_t res = PS_ARG_FAIL;

    if (ssl != NULL)
    {
        ssl->userDataPtr = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("ssl->userDataPtr=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of ssl_t member sec.cert. */
# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_IDENTITY_CERTIFICATES) || defined(USE_CERT_VALIDATE)
psX509Cert_t *matrixSslGetCerts(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->sec.cert is %p\n", (void*)(uintptr_t) (ssl->sec.cert));
#endif
        return ssl->sec.cert;
    }

    return NULL;
}
#  endif /* USE_IDENTITY_CERTIFICATES */
# endif  /* USE_ONLY_PSK_CIPHER_SUITE */

/* Get value of ssl_t member cipher. */
const sslCipherSpec_t *matrixSslGetCipher(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->cipher is %p\n", (void*)(uintptr_t) (ssl->cipher));
#endif
        return ssl->cipher;
    }

    return NULL;
}

/* Get value of ssl_t member sid. */
sslSessionId_t *matrixSslGetSid(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->sid is %p\n", (void*)(uintptr_t) (ssl->sid));
#endif
        return ssl->sid;
    }

    return NULL;
}

/* Get value of ssl_t member activeReadCipher. */
const sslCipherSpec_t *matrixSslGetActiveReadCipher(const ssl_t *ssl)
{
# ifdef USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->activeReadCipher is %p\n", (void*)(uintptr_t) (ssl->activeReadCipher));
#endif
        return ssl->activeReadCipher;
    }
#endif /* USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE */

    return NULL;
}

/* Get value of ssl_t member activeWriteCipher. */
const sslCipherSpec_t *matrixSslGetActiveWriteCipher(const ssl_t *ssl)
{
# ifdef USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->activeWriteCipher is %p\n", (void*)(uintptr_t) (ssl->activeWriteCipher));
#endif
        return ssl->activeWriteCipher;
    }
#endif /* USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE */

    return NULL;
}

/* Get value of ssl_t member flags. */
uint32_t matrixSslGetFlags(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->flags is %p\n", (void*)(uintptr_t) (ssl->flags));
#endif
        return ssl->flags;
    }

    return 0;
}

/* Get value of ssl_t member hsState. */
uint8_t matrixSslGetHsState(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->hsState is %p\n", (void*)(uintptr_t) (ssl->hsState));
#endif
        return ssl->hsState;
    }

    return 0;
}

/* Get value of ssl_t member decState. */
uint8_t matrixSslGetDecState(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->decState is %p\n", (void*)(uintptr_t) (ssl->decState));
#endif
        return ssl->decState;
    }

    return 0;
}

/* Get value of ssl_t member encState. */
uint8_t matrixSslGetEncState(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->encState is %p\n", (void*)(uintptr_t) (ssl->encState));
#endif
        return ssl->encState;
    }

    return 0;
}

#ifdef USE_ECC
/* Get value of ssl_t member ecInfo.ecFlags. */
uint32 matrixSslGetEcInfoEcFlags(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->ecInfo.ecFlags is %p\n", (void*)(uintptr_t) (ssl->ecInfo.ecFlags));
#endif
        return ssl->ecInfo.ecFlags;
    }

    return 0;
}

/* Get value of ssl_t member ecInfo.ecCurveId. */
uint32 matrixSslGetEcInfoEcCurveId(const ssl_t *ssl)
{
    if (ssl != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("ssl->ecInfo.ecCurveId is %p\n", (void*)(uintptr_t) (ssl->ecInfo.ecCurveId));
#endif
        return ssl->ecInfo.ecCurveId;
    }

    return 0;
}
#endif

/* Get value of sslCipherSpec_t member ident. */
uint16_t matrixSslCipherSpecGetIdent(const sslCipherSpec_t *cipher)
{
    if (cipher != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cipher->ident is %p\n", (void*)(uintptr_t) (cipher->ident));
#endif
        return cipher->ident;
    }

    return 0;
}

/* Get value of sslCipherSpec_t member type. */
uint16_t matrixSslCipherSpecGetType(const sslCipherSpec_t *cipher)
{
    if (cipher != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cipher->type is %p\n", (void*)(uintptr_t) (cipher->type));
#endif
        return cipher->type;
    }

    return 0;
}

/* Get value of sslCipherSpec_t member flags. */
uint32_t matrixSslCipherSpecGetFlags(const sslCipherSpec_t *cipher)
{
    if (cipher != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cipher->flags is %p\n", (void*)(uintptr_t) (cipher->flags));
#endif
        return cipher->flags;
    }

    return 0;
}

/* Get value of sslCipherSpec_t member macSize. */
uint8_t matrixSslCipherSpecGetMacSize(const sslCipherSpec_t *cipher)
{
    if (cipher != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cipher->macSize is %p\n", (void*)(uintptr_t) (cipher->macSize));
#endif
        return cipher->macSize;
    }

    return 0;
}

/* Get value of sslCipherSpec_t member keySize. */
uint8_t matrixSslCipherSpecGetKeySize(const sslCipherSpec_t *cipher)
{
    if (cipher != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cipher->keySize is %p\n", (void*)(uintptr_t) (cipher->keySize));
#endif
        return cipher->keySize;
    }

    return 0;
}

/* Get value of sslCipherSpec_t member ivSize. */
uint8_t matrixSslCipherSpecGetIvSize(const sslCipherSpec_t *cipher)
{
    if (cipher != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cipher->ivSize is %p\n", (void*)(uintptr_t) (cipher->ivSize));
#endif
        return cipher->ivSize;
    }

    return 0;
}

/* Get value of sslCipherSpec_t member blockSize. */
uint8_t matrixSslCipherSpecGetBlockSize(const sslCipherSpec_t *cipher)
{
    if (cipher != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cipher->blockSize is %p\n", (void*)(uintptr_t) (cipher->blockSize));
#endif
        return cipher->blockSize;
    }

    return 0;
}

psSizeL_t matrixSslSessOptsSizeof(void)
{
    return (psSizeL_t)sizeof(sslSessOpts_t);
}

void matrixSslSessOptsInit(sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
        /* Default initialization: all zeroized. */
        Memset(sessopts, 0, matrixSslSessOptsSizeof());
    }
}

void matrixSslSessOptsUninit(sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
        /* Zeroize contents upon freeing. */
        Memset(sessopts, 0, matrixSslSessOptsSizeof());
    }
}

void matrixSslSessOptsFree(sslSessOpts_t *sessopts)
{
    matrixSslSessOptsUninit(sessopts);
    Free(sessopts);
}

sslSessOpts_t *matrixSslSessOptsNew(void)
{
    sslSessOpts_t *sessopts;

    sessopts = Malloc(matrixSslSessOptsSizeof());
    matrixSslSessOptsInit(sessopts);
    return sessopts;
}

/* Get value of sslSessOpts_t member OCSPstapling. */
short matrixSslSessOptsGetOCSPstapling(const sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sessopts->OCSPstapling is %p\n", (void*)(uintptr_t) (sessopts->OCSPstapling));
#endif
        return sessopts->OCSPstapling;
    }

    return 0;
}

/* Set value of sslSessOpts_t member OCSPstapling. */
psRes_t matrixSslSessOptsSetOCSPstapling(sslSessOpts_t *sessopts, short value)
{
    psRes_t res = PS_ARG_FAIL;

    if (sessopts != NULL)
    {
        sessopts->OCSPstapling = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("sessopts->OCSPstapling=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of sslSessOpts_t member ecFlags. */
int32 matrixSslSessOptsGetEcFlags(const sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sessopts->ecFlags is %p\n", (void*)(uintptr_t) (sessopts->ecFlags));
#endif
        return sessopts->ecFlags;
    }

    return -1;
}

/* Set value of sslSessOpts_t member ecFlags. */
psRes_t matrixSslSessOptsSetEcFlags(sslSessOpts_t *sessopts, int32 value)
{
    psRes_t res = PS_ARG_FAIL;

    if (sessopts != NULL)
    {
        sessopts->ecFlags = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("sessopts->ecFlags=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of sslSessOpts_t member useExtCvSigOp. */
int32 matrixSslSessOptsGetUseExtCvSigOp(const sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sessopts->useExtCvSigOp is %p\n", (void*)(uintptr_t) (sessopts->useExtCvSigOp));
#endif
        return sessopts->useExtCvSigOp;
    }

    return -1;
}

/* Set value of sslSessOpts_t member useExtCvSigOp. */
psRes_t matrixSslSessOptsSetUseExtCvSigOp(sslSessOpts_t *sessopts, int32 value)
{
    psRes_t res = PS_ARG_FAIL;

    if (sessopts != NULL)
    {
        sessopts->useExtCvSigOp = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("sessopts->useExtCvSigOp=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of sslSessOpts_t member userPtr. */
void *matrixSslSessOptsGetUserPtr(const sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sessopts->userPtr is %p\n", (void*)(uintptr_t) (sessopts->userPtr));
#endif
        return sessopts->userPtr;
    }

    return NULL;
}

/* Set value of sslSessOpts_t member userPtr. */
psRes_t matrixSslSessOptsSetUserPtr(sslSessOpts_t *sessopts, void *value)
{
    psRes_t res = PS_ARG_FAIL;

    if (sessopts != NULL)
    {
        sessopts->userPtr = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("sessopts->userPtr=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of sslSessOpts_t member memAllocPtr. */
void *matrixSslSessOptsGetMemAllocPtr(const sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sessopts->memAllocPtr is %p\n", (void*)(uintptr_t) (sessopts->memAllocPtr));
#endif
        return sessopts->memAllocPtr;
    }

    return NULL;
}

/* Set value of sslSessOpts_t member memAllocPtr. */
psRes_t matrixSslSessOptsSetMemAllocPtr(sslSessOpts_t *sessopts, void *value)
{
    psRes_t res = PS_ARG_FAIL;

    if (sessopts != NULL)
    {
        sessopts->memAllocPtr = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("sessopts->memAllocPtr=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of sslSessOpts_t member bufferPool. */
psPool_t *matrixSslSessOptsGetBufferPool(const sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sessopts->bufferPool is %p\n", (void*)(uintptr_t) (sessopts->bufferPool));
#endif
        return sessopts->bufferPool;
    }

    return NULL;
}

/* Set value of sslSessOpts_t member bufferPool. */
psRes_t matrixSslSessOptsSetBufferPool(sslSessOpts_t *sessopts, psPool_t *value)
{
    psRes_t res = PS_ARG_FAIL;

    if (sessopts != NULL)
    {
        sessopts->bufferPool = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("sessopts->bufferPool=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of sslSessOpts_t member keep_peer_cert_der. */
int32 matrixSslSessOptsGetKeepPeerCertDer(const sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sessopts->keep_peer_cert_der is %p\n", (void*)(uintptr_t) (sessopts->keep_peer_cert_der));
#endif
        return sessopts->keep_peer_cert_der;
    }

    return -1;
}

/* Set value of sslSessOpts_t member keep_peer_cert_der. */
psRes_t matrixSslSessOptsSetKeepPeerCertDer(sslSessOpts_t *sessopts, int32 value)
{
    psRes_t res = PS_ARG_FAIL;

    if (sessopts != NULL)
    {
        sessopts->keep_peer_cert_der = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("sessopts->keep_peer_cert_der=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of sslSessOpts_t member keep_peer_certs. */
int32 matrixSslSessOptsGetKeepPeerCerts(const sslSessOpts_t *sessopts)
{
    if (sessopts != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sessopts->keep_peer_certs is %p\n", (void*)(uintptr_t) (sessopts->keep_peer_certs));
#endif
        return sessopts->keep_peer_certs;
    }

    return -1;
}

/* Set value of sslSessOpts_t member keep_peer_certs. */
psRes_t matrixSslSessOptsSetKeepPeerCerts(sslSessOpts_t *sessopts, int32 value)
{
    psRes_t res = PS_ARG_FAIL;

    if (sessopts != NULL)
    {
        sessopts->keep_peer_certs = value;
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("sessopts->keep_peer_certs=%p\n", (void*)(uintptr_t) (value));
#endif
    }

    return res;
}

/* Get value of sslSessionId_t member id. */
const unsigned char *matrixSslSessionIdGetId(const sslSessionId_t *sid)
{
    if (sid != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sid->id is %p\n", (void*)(uintptr_t) (sid->id));
#endif
        return sid->id;
    }

    return NULL;
}

/* Set value of sslSessionId_t member id. */
psRes_t matrixSslSessionIdSetId(sslSessionId_t *sid,
                                const unsigned char *sessionId,
                                psSizeL_t sessionIdSize)
{
    psRes_t res = PS_ARG_FAIL;

    if (sid != NULL && sessionIdSize <= SSL_MAX_SESSION_ID_SIZE)
    {
        Memset(sid->id, 0, SSL_MAX_SESSION_ID_SIZE);
        Memcpy(sid->id, sessionId, sessionIdSize);
        res = PS_SUCCESS;
#ifdef MATRIX_LOG_SET
        Printf("ssl->id=0x");
        {
            psSizeL_t i;

            for(i = 0; i < sessionIdSize; i++)
            {
                Printf("%02x", sessionId[i]);
            }
        }
        Printf("\n");
#endif
    }

    return res;
}

/* Get value of sslSessionId_t member masterSecret. */
const unsigned char *matrixSslSessionIdGetMasterSecret(const sslSessionId_t *sid)
{
    if (sid != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sid->masterSecret is %p\n", (void*)(uintptr_t) (sid->masterSecret));
#endif
        return sid->masterSecret;
    }

    return NULL;
}

/* Get value of sslSessionId_t member cipherId. */
uint32 matrixSslSessionIdGetCipherId(const sslSessionId_t *sid)
{
    if (sid != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("sid->cipherId is %p\n", (void*)(uintptr_t) (sid->cipherId));
#endif
        return sid->cipherId;
    }

    return 0;
}

/* The following functions are for crypto library. */

# ifdef USE_X509
#  ifdef USE_CERT_PARSE
/* Get value of psX509Cert_t member pubKeyAlgorithm. */
int32 psX509CertGetPubKeyAlgorithm(const psX509Cert_t *cert)
{
    if (cert != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cert->pubKeyAlgorithm is %p\n", (void*)(uintptr_t) (cert->pubKeyAlgorithm));
#endif
        return cert->pubKeyAlgorithm;
    }

    return -1;
}

/* Get value of psX509Cert_t member publicKey.keysize. */
psSize_t psX509CertGetPubKeySize(const psX509Cert_t *cert)
{
    if (cert != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cert->publicKey.keysize is %p\n", (void*)(uintptr_t) (cert->publicKey.keysize));
#endif
        return cert->publicKey.keysize;
    }

    return 0;
}

/* Get value of psX509Cert_t member publicKey.type. */
uint8_t psX509CertGetPubKeyType(const psX509Cert_t *cert)
{
    if (cert != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cert->publicKey.type is %p\n", (void*)(uintptr_t) (cert->publicKey.type));
#endif
        return cert->publicKey.type;
    }

    return 0;
}
#  endif  /* USE_CERT_PARSE */

/* Get value of psX509Cert_t member sigAlgorithm. */
int32 psX509CertGetSigAlgorithm(const psX509Cert_t *cert)
{
    if (cert != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cert->sigAlgorithm is %p\n", (void*)(uintptr_t) (cert->sigAlgorithm));
#endif
        return cert->sigAlgorithm;
    }

    return -1;
}

/* Get value of psX509Cert_t member certAlgorithm. */
int32 psX509CertGetCertAlgorithm(const psX509Cert_t *cert)
{
    if (cert != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cert->certAlgorithm is %p\n", (void*)(uintptr_t) (cert->certAlgorithm));
#endif
        return cert->certAlgorithm;
    }

    return -1;
}

/* Get value of psX509Cert_t member unparsedBin. */
unsigned char *psX509CertGetUnparsedBin(const psX509Cert_t *cert)
{
    if (cert != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cert->unparsedBin is %p\n", (void*)(uintptr_t) (cert->unparsedBin));
#endif
        return cert->unparsedBin;
    }

    return NULL;
}

/* Get value of psX509Cert_t member binLen. */
psSize_t psX509CertGetBinLen(const psX509Cert_t *cert)
{
    if (cert != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cert->binLen is %p\n", (void*)(uintptr_t) (cert->binLen));
#endif
        return cert->binLen;
    }

    return 0;
}

/* Get value of psX509Cert_t member next. */
psX509Cert_t *psX509CertGetNext(const psX509Cert_t *cert)
{
    if (cert != NULL)
    {
#ifdef MATRIX_LOG_GET
    Printf("cert->next is %p\n", (void*)(uintptr_t) (cert->next));
#endif
        return cert->next;
    }

    return NULL;
}
# endif /* USE_X509 */

/******************************************************************************/
