/**
 *      @file    matrixsslApiTypes.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      This sub-header of matrixsslApi.h contains type definitions
 *      needed when using the matrixSsl* API.
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

#ifndef _h_MATRIXSSL_API_TYPES
# define _h_MATRIXSSL_API_TYPES

/* Forward declarations for opaque types. */
typedef struct ssl ssl_t;
typedef struct sslKeys sslKeys_t;
typedef struct sslSec sslSec_t;
typedef struct sslRec sslRec_t;
typedef struct sslCipherSpec sslCipherSpec_t;
typedef struct tlsExtension tlsExtension_t;
typedef struct sslSessionId sslSessionId_t;
typedef struct psTls13SessionParams psTls13SessionParams_t;
typedef struct psTls13Psk psTls13Psk_t;
typedef struct psOcspResponse psOcspResponse_t;

/** Type of the expectedName parameter (expected peer identity)
    that is passed to matrixValidateCerts or matrixSslNewClientSession.
    These can be used to specify the field in the peer certificate
    against which expectedName is to be matched. */
typedef enum
{
    NAME_TYPE_ANY = 0,        /* Default. Checked against everything listed below.
                                 This option exists for compatibility with earlier
                                 versions, where no attempt was made to distinguish
                                 between different types of expectedNames.
                                 New applications should prefer to pick one of the
                                 more specific types below. */
    NAME_TYPE_HOSTNAME,       /* Checked against the dNSName field and the
                                 subject commonName. This is the default. */
    NAME_TYPE_CN,             /* Checked against the subject commonName.
                                 Note that by default, the subject commonName will only
                                 be checked when there are no supported fields
                                 in the SAN. The flag
                                 VCERTS_MFLAG_ALWAYS_CHECK_SUBJECT_CN can be used
                                 to force a commonName check. */
    NAME_TYPE_SAN_DNS,        /* Checked against the dNSName field. */
    NAME_TYPE_SAN_EMAIL,      /* Checked against the rfc822Name field. */
    NAME_TYPE_SAN_IP_ADDRESS, /* Checked against the iPAddress field. */
} expectedNameType_t;

/* flags for matrixValidateCertsOptions_t: */
/**
   Validate the expectedName argument against a subset of the
   GeneralName rules for DNS, Email and IP types _before_ trying
   to find for expectedName in the cert. Note that this is only
   applicable if expectedName is a GeneralName, i.e. when using
   any of the VCERTS_MFLAG_SAN flags.
 */
# define VCERTS_FLAG_VALIDATE_EXPECTED_GENERAL_NAME 0x01

/**
   Skip the expectedName matching. This is useful e.g. when
   matrixValidateCerts is called by the TLS server to validate
   a client certificate. The client name is usually not known
   in this case.
 */
# define VCERTS_FLAG_SKIP_EXPECTED_NAME_VALIDATION 0x02

/**
   Enable matrixValidateCertsExt to perform an independent validation
   of the certificate date ranges. Dates of the subject cert chain
   and the found issuer cert are validated against the current
   system time.

   By default, MatrixSSL only checks the certificate date validity
   during certificate parsing, setting the PS_CERT_AUTH_FAIL_DATE_FLAG
   flag in cert->authFailFlags when date validation fails. This flag
   will be noticed by matrixValidateCertsExt (but only for subject
   certs, not the found issuer cert). In some applications, the delay
   between parsing and the actual chain validation can be long. In such
   situations, it is useful to re-perform the date validation
   in matrixValidateCertsExt.
*/
#  define VCERTS_FLAG_REVALIDATE_DATES 0x04

/* mFlags for matrixValidateCertsOptions_t: */
/**
   If expectedName is a hostname, always attempt to match it
   with the subject CN, even if a supported, but non-matching
   subjectAltName was presented.
   Without this flag, the CN is checked only when no supported SAN
   was presented. This default behaviour is in accordance with
   Section 6.4.4 of RFC 6125, and this flag overrides it.
 */
# define VCERTS_MFLAG_ALWAYS_CHECK_SUBJECT_CN 0x01

/**
   Use case-insensitive match for the the whole email address
   in the rfc822Name field of the SAN. Without this flag,
   case-sensitive matching is used for the local-part and
   case-insensitive matching for the host-part, in accordance
   with RFC 5280.
   This flag requires VCERTS_MFLAG_SAN_MATCH_RFC822NAME.
 */
# define VCERTS_MFLAG_SAN_EMAIL_CASE_INSENSITIVE_LOCAL_PART 0x02

/** Certificate validation options. */
typedef struct
{
    expectedNameType_t nameType; /* Type of expectedName. */
    uint64_t flags; /* General flags for controling the validation
                       prodecure. The allowed flags have the
                       VCERTS_FLAG_ prefix. */
    uint32_t mFlags; /* Flags for controlling how expectedName should
                        be matched. The allowed flags have the
                        USE VCERTS_MFLAG prefix. */
    int32_t max_verify_depth; /* Maximum allowed depth for the peer's
                                 cert chain. 0 : unrestricted,
                                 1: only a single (self-signed) cert allowed,
                                 2: peer cert + 1 root CA
                                 3: peer cert + 1 CA + 1 root CA, etc. */
} matrixValidateCertsOptions_t;

/** sslSessOpts_t: session options. A pointer to this struct is passed
    to matrixSslNewServerSession and matrixSslNewClientSession.
    This struct should be accessed using the matrixSslSessOpts* API
    when possible. */
typedef struct
{
     /* Priority list of supported protocol versions*/
    uint32_t supportedVersions[TLS_MAX_SUPPORTED_VERSIONS];
    psSize_t supportedVersionsLen;
    /* Client: 1 to send status_request */
    short OCSPstapling;
    /* Elliptic curve set (SSL_OPT_SECP192R1 etc.) */
    int32 ecFlags;
    /* Client: sign the handshake messages hash in CertificateVerify
       using the external security token API. */
    int32 useExtCvSigOp;
    uint16_t tls13SupportedSigAlgsCert[TLS_MAX_SIGNATURE_ALGORITHMS];
    psSize_t tls13SupportedSigAlgsCertLen;
    /* For server this defines what is the max early data value for the
       new session tickets. Not used for clients. */
    psSize_t tls13SessionMaxEarlyData;
    /* Initial value of ssl->userPtr during NewSession */
    void *userPtr;
    /* Will be passed to psOpenPool for each call related to this session */
    void *memAllocPtr;
    /* Optional mem pool for inbuf and outbuf */
    psPool_t *bufferPool;
    /* Keep raw DER of peer certs */
    int32 keep_peer_cert_der;
    /* Keep peer cert chain until the session is deleted  */
    int32 keep_peer_certs;
    /* Certificate validation options. */
    matrixValidateCertsOptions_t validateCertsOpts;
    /* Initial value of ssl->userDataPtr during NewSession. */
    void *userDataPtr;
    /* List of key exchange groups to support. */
    uint16_t tls13SupportedGroups[TLS_1_3_MAX_GROUPS];
    psSize_t tls13SupportedGroupsLen;
    /* Number of key shares to send in TLS 1.3 ClientHellos. */
    psSize_t tls13NumClientHelloKeyShares;
    /* Supported signature algorithms. */
    uint16_t supportedSigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS];
    psSize_t supportedSigAlgsLen;

    psSizeL_t tls13PadLen;
    psSizeL_t tls13BlockSize;
    psBool_t tls13CiphersuitesEnabledClient;
    psSize_t minDhBits;

    short ticketResumption; /* Client: 1 to use.  Server N/A */
    short maxFragLen; /* Client: 512 etc..  Server: -1 to disable */
    short truncHmac; /* Client: 1 to use.  Server: -1 to disable */
    short extendedMasterSecret; /* On by default.  -1 to disable */
    short trustedCAindication; /* Client: 1 to use */
    short fallbackScsv; /* Client: 1 to use */
    int32 versionFlag; /* The SSL_FLAGS_TLS_ version (+ DTLS flag here) */
} sslSessOpts_t;

/** matrixSslLoadKeysOpts_t: options for matrixSslLoadKeys. */
typedef struct {
    uint32_t flags; /* LOAD_KEYS_OPT_* */
    int32_t key_type;
    uint32_t privAsset; /* Used with RoT (#define USE_ROT_CRYPTO). */
    psCurve16_t privAssetCurveId;
    psSize_t privAssetModulusNBytes;
} matrixSslLoadKeysOpts_t;
#define LOAD_KEYS_OPT_ALLOW_OUT_OF_DATE_CERT_PARSE (1 << 0)

/** Structure for passing client-side key and cert selection requirements
    to the sslIdentityCb_t type callback function. The structure is filled
    with information from the server's CertificateRequest message.
*/
typedef struct
{
    /* Number of End Entity certificate supplying certificate authorities
       accepted by the peer. Both arrays caNames, and caNameLens have this
       many elements. */
    psSize_t nCas;

    /* Array of certificate authority names, binary DER encoding, as received
       from the peer. Each element caNames[N] is a binary string whose lenght
       is caNameLens[N] octets.

       These names can be memcmp()'d with values available from the
       certificate subject/issuer names. */
    const unsigned char **caNames;
    psSize_t *caNameLens;

    /* Supported signature algorithm masks for transport and
       certificate chains (latter for TLS1.3) */
    uint32_t peerSigAlgMask;
    uint32_t peerCertSigAlgMask;

    /* Algorithms supported by peer for session signature. The values are one
       of SignatureAndHashAlgorithm for TLS12, and one of SignatureScheme
       values for TLS13 The selected identity key needs to be usable for
       producing authentication signature with this identified algoritm
       combination. */
    psSize_t peerSigAlgsLen;
    uint16_t peerSigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS];

    /* Algorithms supported by peer for certificate chains. If the session is
       not TLS13 (or beyond), number of algorithms is always 0. */
    psSize_t peerCertSigAlgsLen;
    uint16_t peerCertSigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS];
} sslKeySelectInfo_t;

/* Callback function of this type is called from the matrix library after it
   has performed certificate path construction/validation for the certificate
   presented by the peer (either the web server cert, or the client
   certificate. This function can accept or reject the tls connection on its
   discretion.

   Allowed return values:
   * PS_SUCCCESS:
     connection is OK - returning this will clear any pending from
     potentially failed certificate validation.
   * SSL_ALLOW_ANON_CONNECTION:
     connection is accepted, but is later considered as anonymous
   * >0 TLS alert to send to the peer (one of SSL_ALERT_ codes)
   * <0 Internal error; sending SSL_ALERT_INTERNAL_ERROR to peer. */
typedef int32_t (*sslCertCb_t)(
        ssl_t *ssl,
        psX509Cert_t *cert,
        int32_t alert);

/* Identity callback type.

   Callback function with signature of sslIdentityCb will be caled from the
   matrix library to obtain key material for TLS client authentication. The
   'ssl' identifies the handshake to authenticate, and 'keySpec' identifies
   the key (type, certificate issuer) accepted by the peer.

   If this callback is set, it will be exclusively used for arranging
   keys used for client authentication, regardless if identities
   (keys) were provided when calling matrixSslNewClientSession().

   The callback shall use function matrixSslSetClientIdentity() to
   select the keys.

   The callback must return 0 on success and < 0 on failure (when key
   or cert could not be loaded).
*/
typedef int32_t (*sslIdentityCb_t)(
        ssl_t *ssl,
        const sslKeySelectInfo_t *keySpec);

/* TLS extension callback type.

   Callback function of this type is called from the matrix library to report
   each received TLS Hello Extension for the application */
typedef int32_t (*sslExtCb_t)(
        ssl_t *ssl,
        uint16_t extType,
        uint8_t extLen,
        void *e);

/* sslPubkeyId_t structure is given as a key selector to pubkeyCB_t type
   function used for selecting the identity key pair for the SSL server. */
typedef struct
{
    unsigned short keyType;
    unsigned short hashAlg;
    unsigned short curveFlags;
    unsigned short dhParamsRequired;
    /* Name of the (virtual)server the peer connected to. The pubkeyCb should
       return a certificate having this name as its subject name CN, or as a
       subjectAltName. */
    char *serverName;
} sslPubkeyId_t;

/* Public key callback type.

   The public key callback is called from the library on the
   TLS server side to retrieve a keypair to use for server authentication for
   the connection described by 'ssl' using algoritms specified by 'keyId'.

   This callback is not called, if the server side session was created using
   matrixSslNewServerSession() and the server identity keys were already
   provided during that call.

   This callback may be called multiple times with different 'keyId' (key
   types in particular) for each 'ssl' connection. The callback is not called
   for the same session after it has returned non-null value (found usable
   keypair).

   The function shall return a sslKeys_t instance, or a NULL pointer in case
   suitable keys are not found. */
typedef sslKeys_t *(*pubkeyCb_t)(
        ssl_t *ssl,
        const sslPubkeyId_t *keyId);

/* PSK callback type.

   The PSK callback is called from the library to retrieve
   shared secret corresponding to the pskId from the application key
   storage. The application returns returns PS_SUCCESS and fills in the key
   into psk, and key length into pskLen if the key corresponding to the given
   pskId is found. If key is not found, a negative error code shall be
   returned resulting into aborted handshake. */
typedef int32_t (*pskCb_t)(
        ssl_t *ssl,
        const unsigned char pskId[SSL_PSK_MAX_ID_SIZE],
        uint8_t pskIdLen,
        unsigned char *psk[SSL_PSK_MAX_KEY_SIZE],
        uint8_t *pskLen);

/* OCSP callback type. */
typedef int32_t (*ocspCb_t)(
        ssl_t *ssl,
        psOcspResponse_t *response,
        psX509Cert_t *cert,
        int32_t status);

/* SNI callback type. The SNI callback is called from the matrix library on the
   server side to retrieve server Identity Keys corresponding to the virtual
   hostname received from the TLS ServerNameIndication. The callback shall
   fill into newKeys the key material to use. The provided key material, if
   any, shall be allocated using matrixSslNewKeys(), and the matrix library
   will take care of freeing the keys when they are no longer needed.

   Note, that if both sniCb and pubkeyCb have been set, and sniCb provides key
   material, the pubkeyCb will not be called. */
typedef void (*sniCb_t)(
        void *ssl,
        char *hostname,
        int32 hostnameLen,
        sslKeys_t **newKeys);

/** Security operation IDs. */
typedef enum
{
    secop_undefined = 0,
    secop_symmetric_encrypt,
    secop_hmac,
    secop_hash_for_sig,
    secop_rsa_encrypt,
    secop_rsa_decrypt,
    secop_rsa_sign,
    secop_rsa_verify,
    secop_rsa_load_key,
    secop_ecdsa_sign,
    secop_ecdsa_verify,
    secop_ecdsa_load_key,
    secop_dh_import_pub,
    secop_ecdh_import_pub,
    secop_proto_version_check,
    secop_sigalg_check,
    secop_cipher_check
} psSecOperation_t;

/** Security callback.
    This function will be called by MatrixSSL or Matrix Crypto to query
    the permissibility of an operation. */
typedef psRes_t (*securityCb_t)(
        void *ctx, /* Pointer to either ssl_t or crypto_t */
        psSecOperation_t op, /* Crypto/TLS op, e.g. CRYPTO_OP_RSA_PKCS1_5_SIGN. */
        psSizeL_t nbits, /* Bits to use in the operation (key size or similar.) */
        void *extraData); /* Extra decision-making info; format depends on op. */

/** Pre-defined security profiles. */
typedef enum
{
    secprofile_default = 0,
    secprofile_wpa3_1_0_enterprise_192 = 1
} psPreDefinedSecProfile_t;

#endif
