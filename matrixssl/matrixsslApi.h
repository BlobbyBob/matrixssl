/**
 *      @file    matrixsslApi.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      Implementations interacting with the matrixssl library should
 *      only use the APIs and definitions used in this file.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#ifndef _h_MATRIXSSL
# define _h_MATRIXSSL

# ifdef __cplusplus
extern "C" {
# endif

# include "matrixsslApiPre.h" /* Preamble. */
# include "matrixsslApiVer.h" /* Protocol version constants and macros. */
# include "matrixsslCheck.h" /* Do sanity checks on configuration. */
# include "matrixsslApiRet.h" /* Return codes. */
# include "matrixsslApiAlert.h" /* Constants for TLS protocol alerts. */
# include "matrixsslApiCipher.h" /* Ciphersuite ID constants. */
# include "matrixsslApiLimits.h" /* Global minima and maxima. */
# include "matrixsslApiExt.h" /* TLS extension IDs. */
# include "matrixsslApiCipher.h" /* Ciphersuite IDs. */
# include "matrixsslApiTypes.h" /* TLS and configuration data types. */

/* For API documentation, see the separate MatrixSSL APIs manual. */

/* Library initialization. */
# define matrixSslOpen() \
    matrixSslOpenWithConfig(MATRIXSSL_CONFIG)
PSPUBLIC int32 matrixSslOpenWithConfig(
        const char *config);
PSPUBLIC void matrixSslClose(void);

/* Key and certificate loading. */
PSPUBLIC int32 matrixSslNewKeys(
        sslKeys_t **keys,
        void *poolUserPtr);
PSPUBLIC void matrixSslDeleteKeys(
        sslKeys_t *keys);
PSPUBLIC int32_t matrixSslLoadKeys(
        sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32_t matrixSslLoadKeysMem(
        sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32_t matrixSslLoadPsk(
        sslKeys_t *keys,
        const unsigned char key[SSL_PSK_MAX_KEY_SIZE],
        uint8_t keyLen,
        const unsigned char id[SSL_PSK_MAX_ID_SIZE],
        uint8_t idLen);
PSPUBLIC int32_t matrixSslLoadTls13Psk(
        sslKeys_t *keys,
        const unsigned char *key,
        psSize_t keyLen,
        const unsigned char *id,
        psSize_t idLen,
        const psTls13SessionParams_t *params);
PSPUBLIC int32 matrixSslLoadPkcs12(
        sslKeys_t *keys,
        const unsigned char *p12File,
        const unsigned char *importPass,
        int32 ipasslen,
        const unsigned char *macPass,
        int32 mpasslen,
        int32 flags);
PSPUBLIC int32 matrixSslLoadPkcs12Mem(
        sslKeys_t *keys,
        const unsigned char *p12Buf,
        int32 p12Len,
        const unsigned char *importPass,
        int32 ipasslen,
        const unsigned char *macPass,
        int32 mpasslen,
        int32 flags);
PSPUBLIC int32_t matrixSslLoadOCSPResponse(
        sslKeys_t *keys,
        const unsigned char *OCSPResponseBuf,
        psSize_t OCSPResponseBufLen);

/* Session configuration (matrixSslSessOpts* API). */
PSPUBLIC int32_t matrixSslSessOptsSetServerTlsVersionRange(
        sslSessOpts_t *options,
        psProtocolVersion_t low,
        psProtocolVersion_t high);
PSPUBLIC int32_t matrixSslSessOptsSetServerTlsVersions(
        sslSessOpts_t *options,
        const psProtocolVersion_t versions[],
        int32_t versionsLen);
PSPUBLIC int32_t matrixSslSessOptsSetClientTlsVersionRange(
        sslSessOpts_t *options,
        psProtocolVersion_t low,
        psProtocolVersion_t high);
PSPUBLIC int32_t matrixSslSessOptsSetClientTlsVersions(
        sslSessOpts_t *options,
        const psProtocolVersion_t versions[],
        int32_t versionsLen);
PSPUBLIC int32_t matrixSslSessOptsSetKeyExGroups(
        sslSessOpts_t *options,
        uint16_t *namedGroups,
        psSize_t namedGroupsLen,
        psSize_t numClientHelloKeyShares);
PSPUBLIC int32_t matrixSslSessOptsSetSigAlgs(
        sslSessOpts_t *options,
        uint16_t *sigAlgs,
        psSize_t sigAlgsLen);
PSPUBLIC int32_t matrixSslSessOptsSetSigAlgsCert(
        sslSessOpts_t *options,
        uint16_t *sigAlgs,
        psSize_t sigAlgsLen);
PSPUBLIC int32_t matrixSslSessOptsSetMinDhBits(
        sslSessOpts_t *options,
        psSize_t minDhBits);

/* Configuring session resumption. */
PSPUBLIC int32 matrixSslNewSessionId(
        sslSessionId_t **sid,
        void *poolUserPtr);
PSPUBLIC void  matrixSslClearSessionId(
        sslSessionId_t *sid);
PSPUBLIC void  matrixSslDeleteSessionId(
        sslSessionId_t *sid);
PSPUBLIC int32 matrixSslLoadSessionTicketKeys(
        sslKeys_t *keys,
        const unsigned char name[16],
        const unsigned char *symkey,
        short symkeyLen,
        const unsigned char *hashkey,
        short hashkeyLen);
PSPUBLIC int32 matrixSslDeleteSessionTicketKey(
        sslKeys_t * keys,
        unsigned char name[16]);
PSPUBLIC void matrixSslSetSessionTicketCallback(
        sslKeys_t *keys,
        int32 (*ticket_cb)(void *,
                unsigned char[16], short));

/* Configuring extensions. */
PSPUBLIC void matrixSslRegisterSNICallback(
        ssl_t *ssl,
        sniCb_t sni_cb);
PSPUBLIC int32 matrixSslCreateSNIext(
        psPool_t *pool,
        unsigned char *host,
        int32 hostLen,
        unsigned char **extOut,
        int32 *extLen);
PSPUBLIC void matrixSslRegisterALPNCallback(
        ssl_t *ssl,
        void (*srv_alpn_cb)(void *ssl,
                short protoCount,
                char *proto[MAX_PROTO_EXT],
                int32 protoLen[MAX_PROTO_EXT],
                int32 *index));
PSPUBLIC int32 matrixSslCreateALPNext(
        psPool_t *pool,
        int32 protoCount,
        unsigned char *proto[],
        int32 protoLen[],
        unsigned char **extOut,
        int32 *extLen);

/* Custom ClientHello extensions. */
PSPUBLIC int32 matrixSslNewHelloExtension(
        tlsExtension_t **extension,
        void *poolUserPtr);
PSPUBLIC int32 matrixSslLoadHelloExtension(
        tlsExtension_t *extension,
        unsigned char *extData,
        uint32 length,
        uint32 extType);
PSPUBLIC void matrixSslDeleteHelloExtension(
        tlsExtension_t *extension);

/* Creating and deleting sessions. */
PSPUBLIC int32_t matrixSslNewClientSession(
        ssl_t **ssl,
        const sslKeys_t *keys,
        sslSessionId_t *sid,
        const psCipher16_t cipherSpec[],
        uint8_t cSpecLen,
        sslCertCb_t certCb,
        const char *expectedName,
        tlsExtension_t *extensions,
        sslExtCb_t extCb,
        sslSessOpts_t *options);
PSPUBLIC int32_t matrixSslNewServerSession(
        ssl_t **ssl,
        const sslKeys_t *keys,
        sslCertCb_t certCb,
        sslSessOpts_t *options);
PSPUBLIC int32_t matrixSslNewServer(
        ssl_t **ssl,
        pubkeyCb_t pubkeyCb,
        pskCb_t pskCb,
        sslCertCb_t certCb,
        sslSessOpts_t *options);
PSPUBLIC void matrixSslDeleteSession(
        ssl_t *ssl);

/* Handshaking and communicating (the main TLS API). */
PSPUBLIC int32 matrixSslGetReadbuf(
        ssl_t *ssl,
        unsigned char **buf);
PSPUBLIC int32 matrixSslGetReadbufOfSize(
        ssl_t *ssl,
        int32 size,
        unsigned char **buf);
PSPUBLIC int32 matrixSslReceivedData(
        ssl_t *ssl,
        uint32 bytes,
        unsigned char **ptbuf,
        uint32 *ptlen);
PSPUBLIC int32 matrixSslGetOutdata(
        ssl_t *ssl,
        unsigned char **buf);
PSPUBLIC int32  matrixSslProcessedData(
        ssl_t *ssl,
        unsigned char **ptbuf,
        uint32 *ptlen);
PSPUBLIC int32 matrixSslSentData(
        ssl_t *ssl,
        uint32 bytes);
PSPUBLIC int32 matrixSslGetWritebuf(
        ssl_t *ssl,
        unsigned char **buf,
        uint32 reqLen);
PSPUBLIC int32 matrixSslEncodeWritebuf(
        ssl_t *ssl,
        uint32 len);
PSPUBLIC int32 matrixSslEncodeToOutdata(
        ssl_t *ssl,
        unsigned char *buf,
        uint32 len);
PSPUBLIC int32 matrixSslEncodeToUserBuf(
        ssl_t *ssl,
        unsigned char *ptBuf,
        uint32 ptLen,
        unsigned char *ctBuf,
        uint32 *ctLen);
PSPUBLIC int32 matrixSslEncodeClosureAlert(
        ssl_t *ssl);
PSPUBLIC void matrixSslGetAnonStatus(
        ssl_t *ssl,
        int32 *anonArg);
#  define SSL_OPTION_FULL_HANDSHAKE           1
PSPUBLIC int32_t matrixSslEncodeRehandshake(
        ssl_t *ssl,
        sslKeys_t *keys,
        sslCertCb_t certCb,
        uint32_t sessionOption,
        const psCipher16_t cipherSpec[],
        uint8_t cSpecLen);
PSPUBLIC int32_t matrixSslGetEarlyDataStatus(
        ssl_t *ssl);
PSPUBLIC int32_t matrixSslGetMaxEarlyData(
        ssl_t *ssl);
PSPUBLIC psProtocolVersion_t matrixSslGetNegotiatedVersion(
        ssl_t *ssl);
PSPUBLIC psBool_t matrixSslHandshakeIsComplete(
        const ssl_t *ssl);

/** Configuration options for a single connection. */
PSPUBLIC int32 matrixSslDisableRehandshakes(
        ssl_t *ssl);
PSPUBLIC int32 matrixSslReEnableRehandshakes(
        ssl_t *ssl);
PSPUBLIC int32 matrixSslSetCipherSuiteEnabledStatus(
        ssl_t *ssl,
        psCipher16_t cipherId,
        uint32 status);
PSPUBLIC void matrixSslRegisterSecurityCallback(
        ssl_t *ssl,
        securityCb_t cb);
PSPUBLIC int32_t matrixSslSetSecurityProfile(
        ssl_t *ssl,
        psPreDefinedSecProfile_t profile);
PSPUBLIC int32_t matrixSslSetTls13BlockPadding(
        ssl_t *ssl,
        psSizeL_t blockSize);

/* MatrixDTLS API. */
PSPUBLIC int32 matrixDtlsSentData(
        ssl_t *ssl,
        uint32 bytes);
PSPUBLIC int32 matrixDtlsGetOutdata(
        ssl_t *ssl,
        unsigned char **buf);
PSPUBLIC int32 matrixDtlsSetPmtu(
        int32 pmtu);
PSPUBLIC int32 matrixDtlsGetPmtu(
        void);

/* Certificate validation APIs.
   For documentation, see the MatrixSSL Certificates and CRLs manual. */
extern int32 matrixValidateCerts(
        psPool_t *pool,
        psX509Cert_t *subjectCerts,
        psX509Cert_t *issuerCerts,
        char *expectedName,
        psX509Cert_t **foundIssuer,
        void *pkiData,
        void *userPoolPtr);
extern int32 matrixValidateCertsExt(
        psPool_t *pool,
        psX509Cert_t *subjectCerts,
        psX509Cert_t *issuerCerts,
        char *expectedName,
        psX509Cert_t **foundIssuer,
        void *pkiData,
        void *userPoolPtr,
        const matrixValidateCertsOptions_t *options);

/* Misc. utility APIs. */
PSPUBLIC psProtocolVersion_t matrixSslVersionFromMinorDigit(
        uint16_t digit);
PSPUBLIC psX509Cert_t* sslKeysGetCACerts(
        const sslKeys_t *keys);
PSPUBLIC char* matrixSslGetExpectedName(
        const ssl_t *ssl);
PSPUBLIC sslKeys_t *matrixSslGetKeys(
        ssl_t *ssl);
PSPUBLIC psBool_t matrixSslTlsVersionRangeSupported(
        psProtocolVersion_t low,
        psProtocolVersion_t high);

/******************************************************************************/


/* Register a callback function called to select the client identity to be
   used for TLS client authentication of a session. If the 'identityCb' has
   been set, the identities provided via 'keys' argument for
   matrixSslNewClientSession are not used. See documentation of
   'sslIdentityCb_t' type for details. The implementation of sslIdentityCb
   shall use function matrixSslSetClientIdentity() to take the keys into
   use.

   @param[in] ssl pointer to the session
   @param[in] identityCb callback function for identity selection
*/
PSPUBLIC void matrixSslRegisterClientIdentityCallback(
        ssl_t *ssl,
        sslIdentityCb_t identityCb);

/* Use the 'keys' as a key-pair and certificate for the client identity for
   the TLS session. The matrix library will take a reference to the keys, and
   thus the keys need to remain valid until end of the session, and the
   application will need to delete the keys explicitly. See: matrixSslNewKeys,
   matrixSslLoadKeys, matrixSslDeleteKeys.

   This function MUST be called to select the keys. The keys may also be
   updated into original keys given to matrixSslNewClientSession(), but
   regarless, those must be indicated using this function.

   The identity keys set shall only have one key-pair set. If there are
   multiple keys, this function will return false and has no effect. In
   success, the function returns true.

   @param[in] ssl pointer to the session
   @param[in] keys selected for client authentication (may be NULL).
*/
PSPUBLIC psBool_t matrixSslSetClientIdentity(
        ssl_t *ssl,
        const sslKeys_t *keys);

#  ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
#   include "psExt.h"
/** Enable external signing for the CertificateVerify message.

    This function is used to turn on the USE_EXT_CERTIFICATE_SIGNING feature
    for a given SSL session struct. After the feature has been turned on,
    MatrixSSL will delegate computation of the CertificateVerify message
    to the caller.

    @param[in] ssl Pointer to the SSL session struct.
    @retval ::PS_SUCCESS Operation was successfull.
 */
PSPUBLIC int32_t matrixSslEnableExtCvSignature(ssl_t *ssl);

/** Disable external signing for the CertificateVerify message.

    This function is used to turn off the USE_EXT_CERTIFICATE_SIGNING feature
    for a given SSL session struct. After the feature has been turned off,
    MatrixSSL will again compute the CertificateVerify signature internally.

    @param[in] ssl Pointer to the SSL session struct.
    @retval ::PS_SUCCESS Operation was successfull.
 */
PSPUBLIC int32_t matrixSslDisableExtCvSignature(ssl_t *ssl);

/** Check whether an external signature for the CertificateVerify
    message is needed.

    When the SSL state machine is in the pending state
    (matrixSslReceivedData has returned PS_PENDING), this function can
    be used to check whether the pending operation is the signing
    of the handshake_messages hash for the CertificateVerify handshake
    message, using the client's private key.

    If this function returns PS_TRUE, the handshake_messages hash
    should be fetched with matrixSslGetHSMessagesHash, signed with the
    client's private key and copied to MatrixSSL using
    matrixSslSetCvSignature.

    @param[in] ssl Pointer to the SSL session struct.
    @retval ::PS_TRUE The SSL state machine is waiting for the CertificateVerify signature.
    @retval ::PS_FALSE The SSL state machine is not in the pending state or the pending operation is not the CertificateVerify signature.
 */
PSPUBLIC int32_t matrixSslNeedCvSignature(ssl_t *ssl);

/** Fetch the handshake_messages hash.

    This function will fetch the hash of all handshake messages seen
    so far until the CertificateVerify message. The signature of this
    hash is to be included in the CertificateVerify.

    This function will return the raw digest; it will not return a DigestInfo structure.

    @param[in] ssl Pointer to the SSL session struct.
    @param[in,out] hash Pointer to a buffer where the handshake_messages hash will be copied.
    @param[in,out] hash_len (In:) length of the hash buffer, (Out:) length of the handshake_messages hash.
    @retval ::PS_SUCCESS The operation was successfull.
    @retval ::PS_OUTPUT_LENGTH The output buffer is too small. The function should be called again with a larger output buffer.
    @retval ::PS_FAILURE The SSL state machine is in incorrect state.
 */
PSPUBLIC int32_t matrixSslGetHSMessagesHash(ssl_t *ssl,
        unsigned char *hash,
        size_t *hash_len);

/** Get the signature algorithm (RSA or ECDSA) to be used for signing the handshake_messages hash.

    This convenience function can be used to query which signature algorithm (RSA or ECDSA)
    should be used for signing the handshake_messages hash. The algorithm type will be the same
    as in the client certificate. Calling this function is not strictly necessary, since the
    client will know the algorithm to use, but is included as a convenience.

    @param[in] ssl Pointer to the SSL session struct.
    @retval ::PS_RSA The required signature algorithm is RSA.
    @retval ::PS_ECC The required signature algorithm is ECDSA.
    @retval ::PS_FAILURE The SSL state machine is in incorrect state.
 */
PSPUBLIC int32_t matrixSslGetCvSignatureAlg(ssl_t *ssl);

/*
   Return size of the public key in the client certificate. This can be used
   as an estimate of private key / signature size when using external
   Cv signature generation.

   Note: This function is intentionally undocumented.

   There should be no need to call this, since the client program should know
   the size of the private key it is using. Useful for testing, however.
 */
PSPUBLIC int32_t matrixSslGetPubKeySize(ssl_t *ssl);

/** Assign the signature of the handshake_messages hash to the CertificateVerify message.

    When RSA is used as the signature algorithm, the signature scheme
    to use depends on the TLS protocol version. For TLS 1.2 (RFC
    5246), the RSA signature scheme must be RSASSA-PKCS1-v1_5 (RFC
    3447). For TLS <1.2 (RFC 4346), PKCS #1 RSA Encryption with block
    type 1 encoding must be used. Note that the RSASSA-PKCS1-v1_5
    scheme requires the hash value to be wrapped within a DigestInfo
    structure and the signature is computed over the DigestInfo. To
    determine which TLS version has been negotiated for the current
    handshake, hash length returned by matrixSslGetHSMessagesHash can
    be used: hash length 36 indicates TLS <1.2, other hash lengths
    indicate TLS 1.2.

    When ECDSA is used as the signature algorithm, the signature must
    be computed according to ANS X9.62 / RFC 4492.

    @param[in] ssl Pointer to the SSL session struct.
    @param[in] sig The signature of the handshake_messages hash.
    @param[in] sig_len The length of the signature.

    @retval ::PS_SUCCESS The operation was successfull.
    @retval ::PS_FAILURE The SSL state machine is in incorrect state.
    @retval ::PS_MEM_FAIL Out of memory.
 */
PSPUBLIC int32_t matrixSslSetCvSignature(ssl_t *ssl,
        const unsigned char *sig,
        const size_t sig_len);
#  endif /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

#ifdef USE_EXT_CLIENT_CERT_KEY_LOADING

/** Returns PS_TRUE when the client program should load a new client cert. */
PSPUBLIC psBool_t matrixSslNeedClientCert(ssl_t *ssl);

/** Returns PS_TRUE when the client program should load a new priv key. */
PSPUBLIC psBool_t matrixSslNeedClientPrivKey(ssl_t *ssl);

/** Returns the certificate/keypair selectors (the server's acceptable
    certificate issuers and key types).

    The function shall only be called in case matrixSslNeedClientCert() has
    returned true.

    There are two alternative methods for selecting the key to use; the
    original way of modifying the 'keys' given as argument to
    matrixSslNewClientSession(), followed by a call to
    matrixSslClientCertUpdated(), or by issuing a call to
    matrixSslSetClientIdentity() with a new key chain to use

    @param[in] ssl pointer to the session
    @retval sslKeySelectInfo_t structure describing the required key.
*/
PSPUBLIC const sslKeySelectInfo_t *matrixSslGetClientKeySelectInfo(ssl_t *ssl);

/** Client program acknowledges the client key change by calling these after
    updating ssl->keys. */
PSPUBLIC psBool_t matrixSslClientCertUpdated(ssl_t *ssl);
PSPUBLIC psBool_t matrixSslClientPrivKeyUpdated(ssl_t *ssl);
#endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */


/* Algorithm-specific key loading functions. */
PSPUBLIC int32 matrixSslLoadDhParams(
        sslKeys_t *keys,
        const char *paramFile);
PSPUBLIC int32 matrixSslLoadDhParamsMem(
        sslKeys_t *keys,
        const unsigned char *dhBin,
        int32 dhBinLen);
PSPUBLIC int32 matrixSslLoadRsaKeysExt(
        sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *trustedCAFile,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32 matrixSslLoadRsaKeys(
        sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *trustedCAFile);
PSPUBLIC int32 matrixSslLoadRsaKeysMemExt(
        sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *trustedCABuf,
        int32 trustedCALen,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32 matrixSslLoadRsaKeysMem(
        sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *trustedCABuf,
        int32 trustedCALen);
PSPUBLIC int32 matrixSslLoadEcKeys(
        sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile);
PSPUBLIC int32 matrixSslLoadEcKeysExt(
        sslKeys_t *keys,
        const char *certFile,
        const char *privFile,
        const char *privPass,
        const char *CAfile,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32 matrixSslLoadEcKeysMemExt(
        sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen,
        matrixSslLoadKeysOpts_t *opts);
PSPUBLIC int32 matrixSslLoadEcKeysMem(
        sslKeys_t *keys,
        const unsigned char *certBuf,
        int32 certLen,
        const unsigned char *privBuf,
        int32 privLen,
        const unsigned char *CAbuf,
        int32 CAlen);

# ifdef __cplusplus
}
# endif

/******************************************************************************/

#endif /* _h_MATRIXSSL */

/******************************************************************************/
