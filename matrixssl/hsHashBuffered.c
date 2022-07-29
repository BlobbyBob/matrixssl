/**
 *      @file    hsHashBuffered.c
 *      @version $Format:%h%d$
 *
 *      Buffered handshake hash implementation for TLS.
 */
/*
 *      Copyright (c) 2013-2019 Rambus Inc.
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

# define FINISHED_LABEL_SIZE 15
# define LABEL_CLIENT        "client finished"
# define LABEL_SERVER        "server finished"

# ifndef HS_MSG_BUF_INITIAL_SIZE
#  define HS_MSG_BUF_INITIAL_SIZE 2048
# endif
# ifndef HS_MSG_BUF_SIZE_INCREMENT
#  define HS_MSG_BUF_SIZE_INCREMENT 1024
# endif

# ifndef DEBUG_HS_HASH_ROT
/* #  define DEBUG_HS_HASH_ROT */ /* Enable hex dump of hashed data. */
# endif

int32_t sslInitHSHash(ssl_t *ssl)
{
    ssl->hsMsgBuf.start = psMalloc(ssl->hsPool, HS_MSG_BUF_INITIAL_SIZE);
    if (ssl->hsMsgBuf.start == NULL)
    {
        psTraceErrr("Out of mem in sslInitHSHash\n");
        return PS_MEM_FAIL;
    }
    ssl->hsMsgBuf.size = HS_MSG_BUF_INITIAL_SIZE;
    ssl->hsMsgBuf.buf = ssl->hsMsgBuf.start;
    ssl->hsMsgBuf.end = ssl->hsMsgBuf.start + ssl->hsMsgBuf.size;

    return PS_SUCCESS;
}

void sslFreeHSHash(ssl_t *ssl)
{
    if (ssl->hsMsgBuf.buf - ssl->hsMsgBuf.start > 0)
    {
        psTraceIntInfo("Total handshake message size: %tu bytes\n",
                ssl->hsMsgBuf.buf - ssl->hsMsgBuf.start);
    }
    psFree(ssl->hsMsgBuf.start, ssl->hsPool);
    ssl->hsMsgBuf.start = NULL;
    ssl->hsMsgBuf.end = NULL;
    ssl->hsMsgBuf.buf = NULL;
    ssl->hsMsgBuf.size = 0;
    ssl->hsMsgCHtoCKELen = 0;
}

/******************************************************************************/
/**
    Add the given data to the running hash of the handshake messages.
    @param[in,out] ssl TLS context
    @param[in] in Pointer to handshake data to hash.
    @param[in] len Number of bytes of handshake data to hash.
    @return < 0 on failure.
 */
int32_t sslUpdateHSHash(ssl_t *ssl, const unsigned char *in, psSize_t len)
{
    psSizeL_t bufferedLen, remainingLen;
    unsigned char *tmp;
    psSizeL_t newLen;

    if (ssl->hsMsgBuf.buf == NULL || ssl->hsMsgBuf.size <= 0)
    {
        return PS_ARG_FAIL;
    }

#ifdef USE_TLS_1_3
    /* If we just received ClientHello, so no version has been negoatiated
       yet. Instead, check for TLS 1.3 support. */
    if (anyTls13VersionSupported(ssl) &&
        (ssl->hsState == SSL_HS_CLIENT_HELLO))
    {
        /* Postpone updating the hash. This is because if the CH contains
           any PSK binders, we need to hash it in two parts in order to
           generate the binder key. We shall update the hash either in
           tls13VerifyBinder, if binders are present, or in
           parseSSLHandshake if not. */
        if (ssl->sec.tls13CHLen == 0)
        {
            ssl->sec.tls13CHStart = in;
            ssl->sec.tls13CHLen = len;
            psTraceBytes("Postponing Tr-Hash", in, len);
            return PS_SUCCESS;
        }
    }
#endif

    remainingLen = ssl->hsMsgBuf.end - ssl->hsMsgBuf.buf;
    if (len > remainingLen)
    {
        psTraceInfo("Out of buffer in sslUpdateHSHash\n");

        bufferedLen = ssl->hsMsgBuf.buf - ssl->hsMsgBuf.start;
        newLen = bufferedLen;
        while (newLen < bufferedLen + len)
        {
            newLen += HS_MSG_BUF_SIZE_INCREMENT;
        }
        tmp = psRealloc(ssl->hsMsgBuf.start, newLen, ssl->hsPool);
        if (tmp == NULL)
        {
            psTraceErrr("Realloc failed in sslUpdateHSHash\n");
            return PS_MEM_FAIL;
        }
        ssl->hsMsgBuf.start = tmp;
        ssl->hsMsgBuf.buf = ssl->hsMsgBuf.start + bufferedLen;
        ssl->hsMsgBuf.size = newLen;
        ssl->hsMsgBuf.end = ssl->hsMsgBuf.start + ssl->hsMsgBuf.size;
        psTraceIntInfo("New HS hash buffer size: %zu\n", newLen);
    }

# ifdef DEBUG_HS_HASH_ROT
    psTraceBytes("sslUpdateHSHash", in, len);
# endif

    Memcpy(ssl->hsMsgBuf.buf, in, len);
    ssl->hsMsgBuf.buf += len;

    return PS_SUCCESS;
}

# if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
int32 sslSha1RetrieveHSHash(ssl_t *ssl, unsigned char *out)
{
    Memcpy(out, ssl->sec.sha1Snapshot, SHA1_HASH_SIZE);
    return SHA1_HASH_SIZE;
}

int32 sslSha384RetrieveHSHash(ssl_t *ssl, unsigned char *out)
{
    Memcpy(out, ssl->sec.sha384Snapshot, SHA384_HASH_SIZE);
    return SHA384_HASH_SIZE;
}

int32 sslSha512RetrieveHSHash(ssl_t *ssl, unsigned char *out)
{
    Memcpy(out, ssl->sec.sha512Snapshot, SHA512_HASH_SIZE);
    return SHA512_HASH_SIZE;
}
# endif /* USE_SERVER_SIDE_SSL && USE_CLIENT_AUTH */

int32_t sslSnapshotHSHash(ssl_t *ssl,
        unsigned char *out,
        psBool_t sender,
        psBool_t isFinishedHash)
{
    unsigned char tmp[FINISHED_LABEL_SIZE + SHA384_HASH_SIZE];
    psSizeL_t hashLen;
    int32_t hashAlgId;
    psDigestContext_t ctx;
    uint32_t flags;

    if (isFinishedHash)
    {
        /* The server uses the server label when sending, the client uses
           the client label when sending. Vice versa when receiving. */
        if (ssl->flags & SSL_FLAGS_SERVER)
        {
            Memcpy(tmp,
                    sender ? LABEL_SERVER : LABEL_CLIENT,
                    FINISHED_LABEL_SIZE);
        }
        else
        {
            Memcpy(tmp,
                    sender ? LABEL_CLIENT : LABEL_SERVER,
                    FINISHED_LABEL_SIZE);
        }
    }

    if (ssl->cipher->flags & CRYPTO_FLAGS_SHA3)
    {
        hashLen = SHA384_HASH_SIZE;
        hashAlgId = OID_SHA384_ALG;
        flags = CRYPTO_FLAGS_SHA3;
    }
    else
    {
        hashLen = SHA256_HASH_SIZE;
        hashAlgId = OID_SHA256_ALG;
        flags = CRYPTO_FLAGS_SHA2;
    }

    psHashInit(&ctx, hashAlgId, NULL);
    psHashUpdate(
            &ctx,
            ssl->hsMsgBuf.start,
            ssl->hsMsgBuf.buf - ssl->hsMsgBuf.start);

    if (isFinishedHash)
    {
        /* Produce verify_data for the Finished message. */
        psHashFinal(&ctx, tmp + FINISHED_LABEL_SIZE);
        return prf2(
                ssl->sec.masterSecret,
                SSL_HS_MASTER_SIZE,
                tmp,
                FINISHED_LABEL_SIZE + hashLen,
                out,
                TLS_HS_FINISHED_SIZE,
                flags);
    }
    else
    {
        /* Produce a raw handshake hash. */
        psHashFinal(&ctx, tmp);
        Memcpy(out, tmp, hashLen);
    }

    return hashLen;
}

int32_t extMasterSecretSnapshotHSHash(ssl_t *ssl, unsigned char *out,
    uint32 *outLen)
{
    uint32_t len;

    len = sslSnapshotHSHash(ssl, out, PS_TRUE, PS_FALSE);
    *outLen = len;

    ssl->hsMsgCHtoCKELen = ssl->hsMsgBuf.buf - ssl->hsMsgBuf.start;

    return *outLen;
}
#endif /* USE_BUFFERED_HS_HASH */

/******************************************************************************/
