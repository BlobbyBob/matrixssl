/**
 *      @file    simpleClient.c
 *      @version $Format:%h%d$
 *
 *      Simple MatrixSSL blocking client example.
 *      - TLS 1.2 and TLS 1.3 only
 *      - P-256 only
 *      - ECDHE/ECDSA or RSA key transport
 *      - Only 1 simultaneous connection.
 */
/*
 *      Copyright (c) 2013-2019 INSIDE Secure Corporation
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

#include "matrixssl/matrixsslApi.h"

# if defined(USE_CLIENT_SIDE_SSL) && (defined(USE_TLS_1_2) || defined(USE_TLS_1_3)) && (defined(USE_SECP256R1) || defined(USE_RSA)) && (defined(USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) || defined(USE_TLS_RSA_WITH_AES_128_GCM_SHA256) || defined(USE_TLS_AES_128_GCM_SHA256)) && defined(USE_IDENTITY_CERTIFICATES)

# include <sys/types.h>
# include <sys/socket.h>
# include <unistd.h>
# include <arpa/inet.h>

/* Key material. */
# ifdef USE_ECC
#  include "testkeys/EC/256_EC.h"
#  include "testkeys/EC/256_EC_KEY.h"
#  include "testkeys/EC/256_EC_CA.h"
#  ifdef USE_SECP384R1
#   include "testkeys/EC/384_EC_SHA384.h"
#   include "testkeys/EC/384_EC_KEY.h"
#   include "testkeys/EC/384_EC_CA_SHA384.h"
#  endif
#  ifdef USE_SECP521R1
#   include "testkeys/EC/521_EC_SHA512.h"
#   include "testkeys/EC/521_EC_KEY.h"
#   include "testkeys/EC/521_EC_CA_SHA512.h"
#  endif
#  include "testkeys/EC/ALL_EC_CAS.h"
# endif
# ifdef USE_RSA
#  include "testkeys/RSA/2048_RSA.h"
#  include "testkeys/RSA/2048_RSA_KEY.h"
#  include "testkeys/RSA/2048_RSA_CA.h"
#  include "testkeys/RSA/3072_RSA_CA.h"
# endif

# ifdef SERVER_IP_ADDRESS
#  define TO_STRING_INNER(x) #x
#  define TO_STRING(x) TO_STRING_INNER(x)
static const char *ip_address_str = TO_STRING(SERVER_IP_ADDRESS);
# else
static const char *ip_address_str = "127.0.0.1";
# endif

# ifndef SERVER_PORT
#  define SERVER_PORT 4433
# endif

/* Number of TLS connections to attempt. Connections after the
   first one will try to use session resumption. */
# ifndef NUM_TLS_CONNECTIONS
#  define NUM_TLS_CONNECTIONS 1
# endif

void cleanup(ssl_t *ssl, sslKeys_t *keys);
int load_keys(sslKeys_t *keys);

/* Certificate callback. See section 6 in the API manual for details.
   In this test, we do no extra checks of our own; we simply accept
   the result of MatrixSSL's internal certificate validation. */
static int32_t certCb(ssl_t *ssl, psX509Cert_t *cert, int32_t alert)
{
    return alert;
}

static unsigned char g_httpRequestHdr[] = "GET ./index.html HTTP/1.0\r\n"
    "Host: localhost\r\n"
    "User-Agent: MatrixSSL 4.0.1\r\n"
    "Accept: */*\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

# ifdef USE_ROT_CRYPTO
#  include "../../crypto-rot/rot/include/api_val.h"
static uint32_t g_longTermAssets[] = { VAL_ASSETID_INVALID,
                                       VAL_ASSETID_INVALID };
#  define IX_ECC 0
#  define IX_RSA 1

/* If enabled, getLongTermPrivAsset shall be called to fetch a
   private key asset ID. If not enabled, a plaintext test key
   shall be used. */
#  define LOAD_PRIVKEY_ASSET

#  ifdef LOAD_PRIVKEY_ASSET
uint32_t getLongTermPrivAsset(int keyType);
extern ValStatus_t psRotAssetFree(ValAssetId_t *asset);
#  endif /* LOAD_PRIVKEY_ASSET */
# endif /* USE_ROT_CRYPTO */

/* Send application data over an established TLS connection. */
static int32_t sendAppData(ssl_t *ssl,
        unsigned char *data,
        size_t dataLen)
{
    int32_t rc;
    unsigned char *buf;

    /* Get pointer to the internal plaintext buffer and fill
       it with the plaintext data. */
    rc = matrixSslGetWritebuf(ssl, &buf, dataLen);
    if (rc < dataLen)
    {
        return PS_FAILURE;
    }
    memcpy(buf, data, dataLen);

    /* Encrypt. */
    rc = matrixSslEncodeWritebuf(ssl, dataLen);
    if (rc < 0)
    {
        return PS_FAILURE;
    }
    /* Ask the main loop to send it over the wire. */
    return MATRIXSSL_REQUEST_SEND;
}

int main(int argc, char **argv)
{
    uint16_t sigAlgs[] = {
# ifdef USE_ECC
        sigalg_ecdsa_secp256r1_sha256,
#  ifdef USE_SECP384R1
        sigalg_ecdsa_secp384r1_sha384,
#  endif
#  ifdef USE_SECP521R1
        sigalg_ecdsa_secp521r1_sha512,
#  endif
# endif
# ifdef USE_RSA
#  ifdef USE_PKCS1_PSS
        sigalg_rsa_pss_rsae_sha256,
#    ifdef USE_SHA384
        sigalg_rsa_pss_rsae_sha384,
#    endif
#  endif
        sigalg_rsa_pkcs1_sha256
# endif
    };
    int32_t sigAlgsLen = sizeof(sigAlgs)/sizeof(sigAlgs[0]);
    psCipher16_t ciphersuites[] = {
# ifdef USE_TLS_1_3
        TLS_AES_128_GCM_SHA256,
# endif
# ifdef USE_ECC
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
# endif
# ifdef USE_RSA
#  ifdef USE_ECC
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
#  endif
        TLS_RSA_WITH_AES_128_GCM_SHA256
# endif
    };
    int32_t ciphersuitesLen = sizeof(ciphersuites)/sizeof(ciphersuites[0]);
    psProtocolVersion_t versions[] =
    {
# ifdef USE_TLS_1_3
        v_tls_1_3,
# endif
# ifdef USE_TLS_1_2
        v_tls_1_2
# endif
    };
    int32_t versionsLen = sizeof(versions)/sizeof(versions[0]);
    sslSessOpts_t opts;
    sslKeys_t *keys = NULL;
    int32_t rc;
    uint32_t len;
    ssl_t *ssl = NULL;
    unsigned char *buf;
    ssize_t nrecv, nsent;
    int fd;
    struct sockaddr_in addr;
    sslSessionId_t *sid;
    int i;
    int num_resumptions = 0;

    rc = matrixSslOpen();
    if (rc < 0)
    {
        return EXIT_FAILURE;
    }

    /* Create new session ID structure for session resumption purposes. */
    rc = matrixSslNewSessionId(&sid, NULL);
    if (rc < 0)
    {
        return EXIT_FAILURE;
    }

    /* Allocate a new key structure.  */
    rc = matrixSslNewKeys(&keys, NULL);
    if (rc < 0)
    {
        cleanup(ssl, keys);
        return EXIT_FAILURE;
    }

    /* Load key material into 'keys'. The called function is a simple
       wrapper for matrixSslLoadKeysMem. */
    rc = load_keys(keys);
    if (rc < 0)
    {
        cleanup(ssl, keys);
        return EXIT_FAILURE;
    }

    /* Setup session options. */
    Memset(&opts, 0, sizeof(opts)); /* Important. */

    /* Set supported protocol versions. */
    rc = matrixSslSessOptsSetClientTlsVersions(
            &opts,
            versions,
            versionsLen);
    if (rc < 0)
    {
        printf("matrixSslSessOptsSetClientTlsVersions failed: %d\n", rc);
        cleanup(ssl, keys);
        return EXIT_FAILURE;
    }

# ifdef USE_ECC
    /* Set supported ECC curves for signatures and key exchange
       The RoT Edition only supports the P-256, P-384 and P-521
       curves. */
    opts.ecFlags = IS_SECP256R1;
# ifdef USE_SECP384R1
    opts.ecFlags |= IS_SECP384R1;
# endif
# ifdef USE_SECP521R1
    opts.ecFlags |= IS_SECP521R1;
# endif
# endif

    /* Set supported signature algorithms. */
    rc = matrixSslSessOptsSetSigAlgs(
            &opts,
            sigAlgs,
            sigAlgsLen);
    if (rc < 0)
    {
        printf("matrixSslSessOptsSetSigAlgs failed: %d\n", rc);
        cleanup(ssl, keys);
        return EXIT_FAILURE;
    }

    for (i = 0; i < NUM_TLS_CONNECTIONS; i++)
    {
        /* Create a new session and the ClientHello message. */
        rc = matrixSslNewClientSession(
                &ssl,
                keys,
                sid,
                ciphersuites,
                ciphersuitesLen,
                certCb,
                NULL,
                NULL,
                NULL,
                &opts);
        if (rc < 0)
        {
            printf("matrixSslNewClientSession failed: %d\n", rc);
            cleanup(ssl, keys);
            return EXIT_FAILURE;
        }

        /* Open the TCP connection. */
        Memset((char *) &addr, 0x0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((short) SERVER_PORT);
        addr.sin_addr.s_addr = inet_addr(ip_address_str);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1)
        {
            printf("socket failed: %d\n", fd);
            cleanup(ssl, keys);
            return EXIT_FAILURE;
        }
        printf("Connecting to %s: %d\n", ip_address_str, SERVER_PORT);
        rc = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
        if (rc < 0)
        {
            close(fd);
            printf("connect failed: %d\n", rc);
            cleanup(ssl, keys);
            return EXIT_FAILURE;
        }

    WRITE_MORE:
        /* Get pointer to the output data to send. */
        rc = matrixSslGetOutdata(ssl, &buf);
        while (rc > 0)
        {
            len = rc;

            /* Send it over the wire. */
            nsent = send(fd, buf, len, 0);
            if (nsent <= 0)
            {
                printf("send() failed\n");
                goto out_fail;
            }

            /* Inform the TLS library how much we managed to send.
               Return code will tell us of what to do next. */
            rc = matrixSslSentData(ssl, nsent);
            if (rc < 0)
            {
                printf("matrixSslSentData failed: %d\n", rc);
                goto out_fail;
            }
            else if (rc == MATRIXSSL_REQUEST_CLOSE)
            {
                printf("Closing connection\n");
                goto out_ok;
            }
            else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
            {
                printf("Handshake complete\n");
                /* Send app data over the encrypted connection. */
                rc = sendAppData(
                        ssl,
                        g_httpRequestHdr,
                        strlen((const char *)g_httpRequestHdr));
                if (rc < 0)
                {
                    goto out_fail;
                }
                goto WRITE_MORE;
            }
            /* rc == PS_SUCCESS. */

            /* More data to send? */
            rc = matrixSslGetOutdata(ssl, &buf);
        }

READ_MORE:
        /* Get pointer to buffer where incoming data should be read into. */
        rc = matrixSslGetReadbuf(ssl, &buf);
        if (rc < 0)
        {
            goto out_fail;
        }
        len = rc;

        /* Read data from the wire. */
        nrecv = recv(fd, buf, len, 0);
        if (nrecv < 0)
        {
            goto out_fail;
        }

        /* Ask the TLS library to process the data we read.
           Return code will tell us what to do next. */
        rc = matrixSslReceivedData(
                ssl,
                nrecv,
                &buf,
                &len);
        if (rc < 0)
        {
            goto out_fail;
        }
        else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
        {
            printf("Handshake complete\n");
            /* Send app data over the encrypted connection. */
            rc = sendAppData(
                    ssl,
                    g_httpRequestHdr,
                    strlen((const char *)g_httpRequestHdr));
            if (rc < 0)
            {
                goto out_fail;
            }
            goto WRITE_MORE;
        }
        else if (rc == MATRIXSSL_REQUEST_SEND)
        {
            /* Handshake messages or an alert have been encoded.
               These need to be sent over the wire. */
            goto WRITE_MORE;
        }
        else if (rc == MATRIXSSL_REQUEST_RECV)
        {
            /* Handshake still in progress. Need more messages
               from the peer. */
            goto READ_MORE;
        }
        else if (rc == MATRIXSSL_APP_DATA)
        {
            /* We received encrypted application data from the peer. */
# ifdef SIMPLE_CLIENT_PRINT_DECRYPTED_APP_DATA
            /* For test purposes, just print it out. */
            psTraceBytes("Decrypted app data", buf, len);
# endif
            /* Inform the TLS library that we "processed" the data. */
            rc = matrixSslProcessedData(
                    ssl,
                    &buf,
                    &len);
            if (rc < 0)
            {
                goto out_fail;
            }

            /* This test ends after successful reception of encrypted
               app data from the peer. */
            goto out_ok;
        }

out_ok:
        rc = PS_SUCCESS;
        if (matrixSslIsResumedSession(ssl))
        {
            num_resumptions++;
        }
        if (NUM_TLS_CONNECTIONS > 1)
        {
            /* Delete connection object. */
            matrixSslDeleteSession(ssl);
            ssl = NULL;
        }
    } /* end for (int i = 0; i < NUM_TLS_CONNECTIONS; i++). */

    printf("Performed %d TLS connection(s):\n" \
            " %d Full session establishment(s)\n" \
            " %d Resumed session(s)\n",
            i,
            i - num_resumptions,
            num_resumptions);

out_fail:
    cleanup(ssl, keys);
    close(fd);
    matrixSslDeleteSessionId(sid);

    if (rc == PS_SUCCESS)
    {
        return EXIT_SUCCESS;
    }
    else
    {
        return EXIT_FAILURE;
    }
}

# ifdef LOAD_PRIVKEY_ASSET
extern ValStatus_t psRotAssetFree(ValAssetId_t *asset);
# endif

void cleanup(ssl_t *ssl, sslKeys_t *keys)
{

    if (ssl)
    {
        matrixSslDeleteSession(ssl);
    }
    if (keys)
    {
        matrixSslDeleteKeys(keys);
    }

# ifdef LOAD_PRIVKEY_ASSET
    psRotAssetFree(&g_longTermAssets[IX_ECC]);
    psRotAssetFree(&g_longTermAssets[IX_RSA]);
# endif

    matrixSslClose();
}

/* Load certificate and key material.
   When using RoT, the private keys can also be provided in the form
   of a long term asset IDs. */
int load_keys(sslKeys_t *keys)
{
# ifdef LOAD_PRIVKEY_ASSET
#  ifdef USE_ECC
    ValAssetId_t privAssetEcdsa = VAL_ASSETID_INVALID;
#  endif
    ValAssetId_t privAssetRsa = VAL_ASSETID_INVALID;
# else
#  ifdef USE_ECC
    uint32_t privAssetEcdsa = 0;
#  endif
    uint32_t privAssetRsa = 0;
# endif
    int32_t rc;
    matrixSslLoadKeysOpts_t keyOpts;

    (void)privAssetRsa;

# ifdef LOAD_PRIVKEY_ASSET
#  ifdef USE_ECC
    privAssetEcdsa = getLongTermPrivAsset(PS_ECC);
#  endif
#  ifdef USE_RSA
    privAssetRsa = getLongTermPrivAsset(PS_RSA);
#  endif /* USE_RSA */
# endif /* LOAD_PRIVKEY_ASSET */

    memset(&keyOpts, 0, sizeof(keyOpts));

# ifdef USE_ECC
    keyOpts.privAssetCurveId = IANA_SECP256R1;
    keyOpts.key_type = PS_ECC;
    keyOpts.privAsset = privAssetEcdsa;
    rc = matrixSslLoadKeysMem(
            keys,
            EC256,
            EC256_SIZE,
            EC256KEY,
            EC256KEY_SIZE,
            ECCAS,
            sizeof(ECCAS),
            &keyOpts);
    if (rc < 0)
    {
        printf("matrixSslLoadKeysMemRot failed: %d\n", rc);
        return PS_FAILURE;
    }
# endif

#  ifdef USE_SECP384R1
    keyOpts.privAssetCurveId = IANA_SECP384R1;
    keyOpts.key_type = PS_ECC;
    keyOpts.privAsset = 0;
    rc = matrixSslLoadKeysMem(
            keys,
            EC384,
            EC384_SIZE,
            EC384KEY,
            EC384KEY_SIZE,
            ECCAS,
            sizeof(ECCAS),
            &keyOpts);
    if (rc < 0)
    {
        printf("matrixSslLoadKeysMemRot failed: %d\n", rc);
        return PS_FAILURE;
    }
#  endif

#  ifdef USE_SECP521R1
    keyOpts.privAssetCurveId = IANA_SECP521R1;
    keyOpts.key_type = PS_ECC;
    keyOpts.privAsset = 0;
    rc = matrixSslLoadKeysMem(
            keys,
            EC521,
            EC521_SIZE,
            EC521KEY,
            EC521KEY_SIZE,
            ECCAS,
            sizeof(ECCAS),
            &keyOpts);
    if (rc < 0)
    {
        printf("matrixSslLoadKeysMemRot failed: %d\n", rc);
        return PS_FAILURE;
    }
#  endif

    /* If RSA is enabled in the compile-time config, also load
       RSA keys and CA certs. */
#  ifdef USE_RSA
    keyOpts.privAssetModulusNBytes = 256;
    keyOpts.key_type = PS_RSA;
    keyOpts.privAsset = privAssetRsa;
    rc = matrixSslLoadKeysMem(
            keys,
            RSA2048,
            RSA2048_SIZE,
            RSA2048KEY,
            RSA2048KEY_SIZE,
            RSA2048CA,
            RSA2048CA_SIZE,
            &keyOpts);
    if (rc < 0)
    {
        printf("matrixSslLoadKeysMemRot failed: %d\n", rc);
        return PS_FAILURE;
    }
#  endif

    return PS_SUCCESS;
}

# ifdef LOAD_PRIVKEY_ASSET
/* Return the RoT asset ID of the long-term private key asset. */
uint32_t getLongTermPrivAsset(int keyType)
{
    int32_t rc;
    psPubKey_t key;
# ifdef USE_ECC
    const psEccCurve_t *curve;
# endif
    ValAssetId_t asset;

    /*
      Test implementation: simply load the key from plaintext.
*/
    switch (keyType)
    {
# ifdef USE_ECC
    case PS_ECC:
        rc = getEccParamById(IANA_SECP256R1, &curve);
        if (rc != PS_SUCCESS)
        {
            return VAL_ASSETID_INVALID;
        }
        key.key.ecc.rotKeyType = ps_ecc_key_type_ecdsa;
        rc = psEccParsePrivKey(
                NULL,
                EC256KEY,
                EC256KEY_SIZE,
                &key.key.ecc,
                curve);
        if (rc != PS_SUCCESS)
        {
            return VAL_ASSETID_INVALID;
        }

        asset = key.key.ecc.privAsset;
        g_longTermAssets[IX_ECC] = asset;

        /* Clear everything else from the key, except the asset ID. */
        key.key.ecc.longTermPrivAsset = PS_TRUE;
        psEccClearKey(&key.key.ecc);

        break;
# endif
# ifdef USE_RSA
    case PS_RSA:
        rc = psRsaParsePkcs1PrivKey(
                NULL,
                RSA2048KEY,
                RSA2048KEY_SIZE,
                &key.key.rsa);
        if (rc != PS_SUCCESS)
        {
            return VAL_ASSETID_INVALID;
        }
        asset = key.key.rsa.privSigAsset;
        g_longTermAssets[IX_RSA] = asset;

        /* Clear everything else from the key, except the asset ID. */
        key.key.rsa.longTermPrivAsset = PS_TRUE;
        psRsaClearKey(&key.key.rsa);

        break;
# endif
    default:
        printf("Unsupported key type\n");
        return VAL_ASSETID_INVALID;
    }

    return asset;
}
# endif /* # LOAD_PRIVKEY_ASSET */

# else
int main(int argc, char **argv)
{
#  ifndef USE_CLIENT_SIDE_SSL
    printf("This test requires USE_CLIENT_SIDE_SSL\n");
#  endif
#  ifndef USE_TLS_1_2
    printf("This test requires USE_TLS_1_2\n");
#  endif
#  if !defined(USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) && !defined(USE_TLS_RSA_WITH_AES_128_GCM_SHA256)
    printf("This test requires USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 " \
            "or USE_TLS_RSA_WITH_AES_128_GCM_SHA256\n");
#  endif
#  ifndef USE_IDENTITY_CERTIFICATES
    printf("This test requires USE_IDENTITY_CERTIFICATES\n");
#  endif
    return 1;
}
# endif /* USE_CLIENT_SIDE_SSL && USE_TLS_1_2 && USE_SECP256R1 && USE_SHA256 && USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 && USE_IDENTITY_CERTIFICATES */
