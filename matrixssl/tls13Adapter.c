/**
 *      @file    tls13Adapter.c
 *      @version $Format:%h%d$
 *
 *      Adapter layer for internal TLS 1.3 APIs.
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

# include "matrixsslImpl.h"

# ifndef DEBUG_TLS_1_3_ADAPTER
#  define DEBUG_TLS_1_3_ADAPTER
# endif

# ifdef USE_TLS_1_3_ONLY

/* TLS 1.3 code doesn't use pkaAfter. */
void freePkaAfter(ssl_t *ssl)
{
    (void)ssl;
}

void clearFlightList(ssl_t *ssl)
{
    flightEncode_t *msg, *next;

    msg = ssl->flightEncode;
    while (msg)
    {
        next = msg->next;
        psFree(msg, ssl->flightPool);
        msg = next;
    }
    ssl->flightEncode = NULL;
}

/* In TLS 1.3, tls13WriteClientHello is used instead. */
int32_t matrixSslEncodeClientHello(ssl_t *ssl,
        sslBuf_t *out,
        const psCipher16_t cipherSpec[],
        uint8_t cipherSpecLen,
        uint32 *requiredLen,
        tlsExtension_t *userExt,
        sslSessOpts_t *options)
{
    (void)ssl;
    (void)out;
    (void)cipherSpec;
    (void)cipherSpecLen;
    (void)requiredLen;
    (void)userExt;
    (void)options;

    return MATRIXSSL_SUCCESS;
}

int32 matrixSslGetEncodedSize(ssl_t *ssl, uint32 len)
{
# ifdef USE_TLS_1_3
    uint32 ptLen = len;
# endif

    len += ssl->recordHeadLen;

    if (ssl->flags & SSL_FLAGS_WRITE_SECURE)
    {
        len += ssl->enMacSize;

        /* Add AEAD overhead. */
        len += AEAD_TAG_LEN(ssl);

        /* TLS 1.3 does not send any part of the nonce over the
           wire, but requires one additional byte and possibly
           room for the padding. */
        if (ssl->tls13BlockSize > 0)
        {
            ssl->tls13PadLen = tls13GetPadLen(ssl, ptLen);
        }
        len += 1; /* InnerPlaintext.type */
        len += ssl->tls13PadLen; /* InnerPlaintext.zeros */
    }

    return len;
}

int32 matrixSslEncode(ssl_t *ssl,
        unsigned char *buf,
        uint32 size,
        unsigned char *ptBuf,
        uint32 *len)
{
    return tls13EncodeAppData(ssl, buf, size, ptBuf, len);
}

/**
  Return PS_TRUE if sigAlg is in peerSigAlgs, PS_FALSE otherwise.

  peerSigAlgs should be the a set of masks we created after
  parsing the peer's supported_signature_algorithms list
  in ClientHello or CertificateRequest.
*/
psBool_t peerSupportsSigAlg(int32_t sigAlg,
        uint16_t peerSigAlgs)
{
    uint16_t yes;

    if (sigAlg == OID_MD5_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_MD5_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA1_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA1_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA256_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA256_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA384_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA384_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA512_RSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA512_RSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA1_ECDSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA1_ECDSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA256_ECDSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA256_ECDSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA384_ECDSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA384_ECDSA_MASK) != 0);
    }
    else if (sigAlg == OID_SHA512_ECDSA_SIG)
    {
        yes = ((peerSigAlgs & HASH_SIG_SHA512_ECDSA_MASK) != 0);
    }
    else
    {
        return PS_FALSE; /* Unknown/unsupported sig alg. */
    }

    if (yes)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

int32 psGenerateServerRandom(ssl_t *ssl)
{
    if (psGetPrngLocked(ssl->sec.serverRandom,
                    SSL_HS_RANDOM_SIZE, ssl->userPtr) < 0)
    {
        return MATRIXSSL_ERROR;
    }

    return PS_SUCCESS;
}

int32_t sslInitHSHash(ssl_t *ssl)
{
    if (ssl->tls13IncorrectDheKeyShare)
    {
        /* Don't allow second ClientHello after HelloRetryRequest
           to reset the hash. */
        return 0;
    }
    /* Always has to init all hashes since we don't know with what
       version we end up with. */
    tls13TranscriptHashInit(ssl);

    return PS_SUCCESS;
}

int32 sslEncodeClosureAlert(ssl_t *ssl,
        sslBuf_t *out,
        uint32 *reqLen)
{
    if (ssl->flags & SSL_FLAGS_ERROR)
    {
        return MATRIXSSL_ERROR;
    }
    return tls13EncodeAlert(ssl,
            SSL_ALERT_CLOSE_NOTIFY,
            out,
            reqLen);
}

static
int32 encryptFlight(ssl_t *ssl,
        unsigned char **end)
{
    flightEncode_t *msg, *remove;
    int32_t rc;

    msg = ssl->flightEncode;
    while (msg)
    {
        rc = tls13EncryptMessage(ssl, msg, end);
        if (rc < 0)
        {
            psTraceInfo("encryptFlightTls13 failed\n");
            clearFlightList(ssl);
            return rc;
        }
        if (rc < 0)
        {
            psTraceIntInfo("Error encrypting record from flight %d\n", rc);
            clearFlightList(ssl);
            return rc;
        }
        remove = msg;
        ssl->flightEncode = msg = msg->next;
        psFree(remove, ssl->flightPool);
    }

    clearFlightList(ssl);

    return PS_SUCCESS;
}

int32 sslEncodeResponse(ssl_t *ssl,
        psBuf_t *out,
        uint32 *requiredLen)
{
    int32_t rc;
    uint32 alertReqLen;

    rc = tls13EncodeResponse(ssl, out, requiredLen);
    if (rc == SSL_FULL)
    {
        *requiredLen = tls13EstimateNextFlightSize(ssl);
        psTraceIntInfo("Need larger write buffer: %d\n", *requiredLen);
        /* Return to matrixSslReceivedData for buffer enlargement.
           Next time, we shall continue from where we left. */
        ssl->tls13NextMsgRequiredLen = 0;
        return SSL_FULL;
    }
    else if (rc < 0)
    {
        psTraceIntInfo("ERROR: Handshake flight creation failed %d\n", rc);

        /* The TLS 1.3 code should set a suitable alert. */
        psAssert(ssl->err != SSL_ALERT_NONE);

        out->end = out->start;
        alertReqLen = out->size;

        /* Going recursive to send the alert. */
        return sslEncodeResponse(ssl, out, &alertReqLen);
    }

    if (ssl->flightEncode)
    {
        rc = encryptFlight(ssl, &out->end);
        if (rc < 0)
        {
            return rc;
        }
    }

    return rc;
}

# endif /* USE_TLS_1_3_ONLY */
