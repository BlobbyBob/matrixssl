/**
 *      @file    tls13TrHashBuffered.c
 *      @version $Format:%h%d$
 *
 *      TLS 1.3 Transcript-Hash, also called session hash or handshake hash.
 *      Buffered implementation.
 */
/*
 *      Copyright (c) 2018 Rambus Inc.
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
 *      commercial license for this software may be purchased from Rambus at
 *      http://www.rambus.com/
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

#include "matrixsslImpl.h"

#ifdef USE_BUFFERED_HS_HASH

# ifdef USE_TLS_1_3

# ifndef DEBUG_TLS_1_3_TRANSCRIPT_HASH
#  define DEBUG_TLS_1_3_TRANSCRIPT_HASH
# endif

static inline int32_t getHashAlg(ssl_t *ssl)
{
    /* Only supporting the ciphersuites defined in the TLS 1.3 draft spec.
       Only SHA-256 and SHA-384. */
    if (ssl->cipher == NULL)
    {
        return OID_SHA256_ALG;
    }

    if (ssl->cipher->flags & CRYPTO_FLAGS_SHA3)
    {
        return OID_SHA384_ALG;
    }
    else
    {
        return OID_SHA256_ALG;
    }
}

int32_t tls13TranscriptHashInit(ssl_t *ssl)
{
    if (ssl->hsMsgBuf.start == NULL)
    {
# ifdef DEBUG_TLS_1_3_TRANSCRIPT_HASH
        psTraceInfo("tls13TranscriptHashInit\n");
# endif
        return sslInitHSHash(ssl);
    }
    return 0;
}

int32_t tls13TranscriptHashReinit(ssl_t *ssl)
{
    int32_t rc;
    int32_t alg;
    unsigned char messageHash[1 + 3 + MAX_TLS_1_3_HASH_SIZE];
    psSize_t messageHashLen;

    alg = getHashAlg(ssl);

    psTraceInfo("tls13TranscriptHashReinit\n");

    /*
      When the server responds to a
      ClientHello with a HelloRetryRequest, the value of ClientHello1 is
      replaced with a special synthetic handshake message of handshake type
      "message_hash" containing Hash(ClientHello1).  I.e.,

      Transcript-Hash(ClientHello1, HelloRetryRequest, ... MN) =
         Hash(message_hash ||        // Handshake type
              00 00 Hash.length ||   // Handshake message length (bytes)
              Hash(ClientHello1) ||  // Hash of ClientHello1
              HelloRetryRequest ... MN)
    */
    rc = tls13TranscriptHashFinish(ssl, ssl->sec.tls13TrHashSnapshotCH1);
    if (rc < 0)
    {
        return rc;
    }
    rc = tls13TranscriptHashInit(ssl);
    if (rc < 0)
    {
        return rc;
    }

    messageHashLen = 4; /* Header. */
    messageHash[0] = 254;
    messageHash[1] = messageHash[2] = 0;
    if (alg == OID_SHA256_ALG)
    {
        messageHash[3] = SHA256_HASH_SIZE;
        Memcpy(messageHash + 4,
                ssl->sec.tls13TrHashSnapshotCH1,
                SHA256_HASH_SIZE);
        messageHashLen += SHA256_HASH_SIZE;
    }
    else
    {
        messageHash[3] = SHA384_HASH_SIZE;
        Memcpy(messageHash + 4,
                ssl->sec.tls13TrHashSnapshotCH1,
                SHA384_HASH_SIZE);
        messageHashLen += SHA384_HASH_SIZE;
    }

    rc = tls13TranscriptHashUpdate(ssl,
            messageHash,
            messageHashLen);
    if (rc < 0)
    {
        return rc;
    }

    /* Caller should now call update for HelloRetryRequest. */

    return MATRIXSSL_SUCCESS;
}

int32_t tls13TranscriptHashUpdate(ssl_t *ssl,
        const unsigned char *in,
        psSize_t len)
{
# ifdef DEBUG_TLS_1_3_TRANSCRIPT_HASH
    int32_t alg = getHashAlg(ssl);

    psTracePrintTranscriptHashUpdate(ssl, in, len, alg);
# endif

    return sslUpdateHSHash(ssl, in, len);
}

int32_t tls13TranscriptHashFinish(ssl_t *ssl,
        unsigned char *out)
{
    int32_t rc;

# ifdef DEBUG_TLS_1_3_TRANSCRIPT_HASH
        psTraceInfo("tls13TranscriptHashFinish\n");
# endif

    rc = sslSnapshotHSHash(
            ssl,
            out,
            PS_FALSE,
            PS_FALSE);
    if (rc < 0)
    {
        return rc;
    }

    /**/
    sslFreeHSHash(ssl);
    return 0;
}

int32_t tls13TranscriptHashSnapshotAlg(ssl_t *ssl,
        int32_t alg,
        unsigned char *out)
{
    return sslSnapshotHSHash(
            ssl,
            out,
            PS_FALSE,
            PS_FALSE);
}

int32_t tls13TranscriptHashSnapshot(ssl_t *ssl,
        unsigned char *out)
{
    int32_t alg = getHashAlg(ssl);

# ifdef DEBUG_TLS_1_3_TRANSCRIPT_HASH
        psTraceInfo("tls13TranscriptHashSnapshot\n");
# endif

    return tls13TranscriptHashSnapshotAlg(ssl, alg, out);
}

# endif /* USE_TLS_1_3 */

# endif /* USE_BUFFERED_HS_HASH */
