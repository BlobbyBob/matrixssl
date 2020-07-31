/**
 *      @file    matrixsslGetSet.h
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

#ifndef _h_MATRIXSSL_GETSET
# define _h_MATRIXSSL_GETSET

# ifdef __cplusplus
extern "C" {
# endif

#ifndef _h_MATRIXSSL
# include "matrixsslApi.h"
#endif /* _h_MATRIXSSL */


void *matrixSslGetUserPtr(const ssl_t *ssl);
psRes_t matrixSslSetUserPtr(ssl_t *ssl, void *value);

void *matrixSslGetUserDataPtr(const ssl_t *ssl);
psRes_t matrixSslSetUserDataPtr(ssl_t *ssl, void *value);

# ifndef USE_ONLY_PSK_CIPHER_SUITE
#  if defined(USE_IDENTITY_CERTIFICATES) || defined(USE_CERT_VALIDATE)
psX509Cert_t *matrixSslGetCerts(const ssl_t *ssl);
#  endif /* USE_IDENTITY_CERTIFICATES */
# endif  /* USE_ONLY_PSK_CIPHER_SUITE */

const sslCipherSpec_t *matrixSslGetCipher(const ssl_t *ssl);

sslSessionId_t *matrixSslGetSid(const ssl_t *ssl);

const sslCipherSpec_t *matrixSslGetActiveReadCipher(const ssl_t *ssl);

const sslCipherSpec_t *matrixSslGetActiveWriteCipher(const ssl_t *ssl);

uint32_t matrixSslGetFlags(const ssl_t *ssl);

uint8_t matrixSslGetHsState(const ssl_t *ssl);

uint8_t matrixSslGetDecState(const ssl_t *ssl);

uint8_t matrixSslGetEncState(const ssl_t *ssl);

# ifdef USE_ECC
uint32 matrixSslGetEcInfoEcFlags(const ssl_t *ssl);

uint32 matrixSslGetEcInfoEcCurveId(const ssl_t *ssl);
# endif

uint16_t matrixSslCipherSpecGetIdent(const sslCipherSpec_t *cipher);

uint16_t matrixSslCipherSpecGetType(const sslCipherSpec_t *cipher);

uint32_t matrixSslCipherSpecGetFlags(const sslCipherSpec_t *cipher);

uint8_t matrixSslCipherSpecGetMacSize(const sslCipherSpec_t *cipher);

uint8_t matrixSslCipherSpecGetKeySize(const sslCipherSpec_t *cipher);

uint8_t matrixSslCipherSpecGetIvSize(const sslCipherSpec_t *cipher);

uint8_t matrixSslCipherSpecGetBlockSize(const sslCipherSpec_t *cipher);

/* Dynamically allocate sslSessOpts_t.
 */
sslSessOpts_t *matrixSslSessOptsNew(void);

/* Free dynamically allocated sslSessOpts_t.
 */
void matrixSslSessOptsFree(sslSessOpts_t *sessopts);

/* Get size of sslSessOpts_t.

   It is recommended to use
   sslSessOpts_t *matrixSslSessOptsNew() for allocation
   of sslSessOpts_t. This function can be used
   to implement alternative allocation
   facilities, which do not use heap,
   such as allocation via alloc().
*/
psSizeL_t matrixSslSessOptsSizeof(void);

/* Initialize sslSessOpts_t.

   This function can be used to manually
   initialize sslSessOpts_t.
   It is recommended to use
   sslSessOpts_t *matrixSslSessOptsNew() for allocation
   and initialization.
 */
void matrixSslSessOptsInit(sslSessOpts_t *sessopts);

/* Uninitialize sslSessOpts_t.

   This function can be used to manually
   deinitialize sslSessOpts_t.
   It is recommended to use
   sslSessOpts_t *matrixSslSessOptsFree() for deallocation
   including deinitialization.
 */
void matrixSslSessOptsUninit(sslSessOpts_t *sessopts);

short matrixSslSessOptsGetOCSPstapling(const sslSessOpts_t *sessopts);
psRes_t matrixSslSessOptsSetOCSPstapling(sslSessOpts_t *sessopts, short value);

int32 matrixSslSessOptsGetEcFlags(const sslSessOpts_t *sessopts);
psRes_t matrixSslSessOptsSetEcFlags(sslSessOpts_t *sessopts, int32 value);

int32 matrixSslSessOptsGetUseExtCvSigOp(const sslSessOpts_t *sessopts);
psRes_t matrixSslSessOptsSetUseExtCvSigOp(sslSessOpts_t *sessopts, int32 value);

void *matrixSslSessOptsGetUserPtr(const sslSessOpts_t *sessopts);
psRes_t matrixSslSessOptsSetUserPtr(sslSessOpts_t *sessopts, void *value);

void *matrixSslSessOptsGetMemAllocPtr(const sslSessOpts_t *sessopts);
psRes_t matrixSslSessOptsSetMemAllocPtr(sslSessOpts_t *sessopts, void *value);

psPool_t *matrixSslSessOptsGetBufferPool(const sslSessOpts_t *sessopts);
psRes_t matrixSslSessOptsSetBufferPool(sslSessOpts_t *sessopts, psPool_t *value);

int32 matrixSslSessOptsGetKeepPeerCertDer(const sslSessOpts_t *sessopts);
psRes_t matrixSslSessOptsSetKeepPeerCertDer(sslSessOpts_t *sessopts, int32 value);

int32 matrixSslSessOptsGetKeepPeerCerts(const sslSessOpts_t *sessopts);
psRes_t matrixSslSessOptsSetKeepPeerCerts(sslSessOpts_t *sessopts, int32 value);

const unsigned char *matrixSslSessionIdGetId(const sslSessionId_t *sid);
psRes_t matrixSslSessionIdSetId(sslSessionId_t *sid,
                                const unsigned char *sessionId,
                                psSizeL_t sessionIdSize);

const unsigned char *matrixSslSessionIdGetMasterSecret(const sslSessionId_t *sid);

uint32 matrixSslSessionIdGetCipherId(const sslSessionId_t *sid);

/* The following functions are for crypto library. */

# ifdef USE_X509
#  ifdef USE_CERT_PARSE
int32 psX509CertGetPubKeyAlgorithm(const psX509Cert_t *cert);

psSize_t psX509CertGetPubKeySize(const psX509Cert_t *cert);

uint8_t psX509CertGetPubKeyType(const psX509Cert_t *cert);
#  endif /* USE_CERT_PARSE*/

int32 psX509CertGetSigAlgorithm(const psX509Cert_t *cert);

int32 psX509CertGetCertAlgorithm(const psX509Cert_t *cert);

unsigned char *psX509CertGetUnparsedBin(const psX509Cert_t *cert);

psSize_t psX509CertGetBinLen(const psX509Cert_t *cert);

psX509Cert_t *psX509CertGetNext(const psX509Cert_t *cert);
# endif /* USE_X509 */

# ifdef __cplusplus
}
# endif

/******************************************************************************/

#endif /* _h_MATRIXSSL_GETSET */
