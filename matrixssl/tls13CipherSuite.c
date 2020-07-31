/**
 *      @file    tls13CipherSuite.c
 *      @version $Format:%h%d$
 *
 *      Functions for TLS 1.3 ciphersuites.
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

#include "matrixsslImpl.h"

# ifdef USE_TLS_1_3

/*
  5.3.  Per-Record Nonce:

  The per-record nonce for the AEAD
  construction is formed as follows:

  1.  The 64-bit record sequence number is encoded in network byte
  order and padded to the left with zeros to iv_length.

  2.  The padded sequence number is XORed with the static
  client_write_iv or server_write_iv, depending on the role.
*/
static inline
void tls13MakeWriteNonce(ssl_t *ssl, unsigned char nonceOut[12])
{
    psSize_t i;

    Memset(nonceOut, 0, 12);
    Memcpy(nonceOut + 4, ssl->sec.seq, 8);
    for (i = 0; i < 12; i++)
    {
        nonceOut[i] ^= ssl->sec.tls13WriteIv[i];
    }
}

static inline
void tls13MakeReadNonce(ssl_t *ssl, unsigned char nonceOut[12])
{
    psSize_t i;

    Memset(nonceOut, 0, 12);
    Memcpy(nonceOut + 4, ssl->sec.remSeq, 8);
    for (i = 0; i < 12; i++)
    {
        nonceOut[i] ^= ssl->sec.tls13ReadIv[i];
    }
}

static inline
void tls13MakeEncryptAad(ssl_t *ssl, unsigned char aadOut[5])
{
    aadOut[0] = SSL_RECORD_TYPE_APPLICATION_DATA;
    aadOut[1] = 0x03;
    aadOut[2] = 0x03;
    aadOut[3] = (ssl->outRecLen & 0xff00) >> 8;
    aadOut[4] = (ssl->outRecLen & 0xff);
}

static inline
void tls13MakeDecryptAad(ssl_t *ssl, unsigned char aadOut[5])
{
    aadOut[0] = SSL_RECORD_TYPE_APPLICATION_DATA;
    aadOut[1] = 0x03;
    aadOut[2] = 0x03;
    aadOut[3] = (ssl->rec.len & 0xff00) >> 8;
    aadOut[4] = (ssl->rec.len & 0xff);
}

#ifdef CL_EncryptAuthTls13

/* Allocate and load Key and State Assets from CL local storage, so
   that this application doesn't have to care about memory
   management.  */
static CL_RV tls13_aesgcm_assets(psAesGcm_t *gcm)
{
    CL_AssetAllocateExInfo_t exinfo = {0};
    CL_RV rv;

    exinfo.flags |= CL_ASSET_ALLOCATE_EX_LOCAL;
    rv = CL_AssetAllocateEx((CL_ALLOCATE_EXTRA_POLICY |
                             CL_POLICY_ALGO_GCM_AES_ENCRYPT |
                             CL_POLICY_ALGO_GCM_AES_DECRYPT),
                            gcm->keylength, &exinfo, &gcm->multipart_gcm_key);
    if (rv == CLR_OK)
    {
        rv = CL_AssetLoadValue(gcm->multipart_gcm_key, gcm->key, gcm->keylength);
    }
    if (rv == CLR_OK)
    {
        rv = CL_AssetAllocateEx((CL_ALLOCATE_EXTRA_POLICY |
                                 CL_POLICY_FLAG_TEMPORARY |
                                 CL_POLICY_FLAG_EXPORTABLE),
                                CL_ASSET_STATE_MIN_LENGTH, &exinfo, &gcm->multipart_gcm_state);
    }
    if (rv != CLR_OK)
    {
        CL_AssetFree(gcm->multipart_gcm_key);
        CL_AssetFree(gcm->multipart_gcm_state);
    }
    return rv;
}
#endif

int32 csAesGcmInitTls13(sslSec_t *sec, int32 type, uint32 keysize)
{
    int32 err = 0;
#ifdef CL_EncryptAuthTls13
    psAesGcm_t *gcm;
#endif

    if (type == INIT_ENCRYPT_CIPHER)
    {
        Memset(&sec->encryptCtx.aesgcm, 0, sizeof(psAesGcm_t));
        if ((err = psAesInitGCM(&sec->encryptCtx.aesgcm, sec->writeKey,
                 keysize)) < 0)
        {
            return err;
        }
#ifdef CL_EncryptAuthTls13
        gcm = &sec->encryptCtx.aesgcm;
        gcm->algo = CL_ALGO_GCM_AES_ENCRYPT;
        gcm->tlsInfo = CL_Tls13ContextNew();
        CL_Tls13ContextSetWriteIv(gcm->tlsInfo, sec->tls13WriteIv);
        CL_Tls13ContextSetSeq(gcm->tlsInfo, sec->seq);
        err = tls13_aesgcm_assets(gcm) != CLR_OK;
#endif
    }
    else
    {
        Memset(&sec->decryptCtx.aesgcm, 0, sizeof(psAesGcm_t));
        if ((err = psAesInitGCM(&sec->decryptCtx.aesgcm, sec->readKey,
                 keysize)) < 0)
        {
            return err;
        }
#ifdef CL_EncryptAuthTls13
        gcm = &sec->decryptCtx.aesgcm;
        gcm->algo = CL_ALGO_GCM_AES_DECRYPT;
        gcm->tlsInfo = CL_Tls13ContextNew();
        CL_Tls13ContextSetWriteIv(gcm->tlsInfo, sec->tls13ReadIv);
        CL_Tls13ContextSetSeq(gcm->tlsInfo, sec->remSeq);
        err = tls13_aesgcm_assets(gcm) != CLR_OK;
#endif

    }
    return err;
}

static inline void psAesIncrSec(unsigned char *seq)
{
    int i;

    for (i = (TLS_AEAD_SEQNB_LEN - 1); i >= 0; i--)
    {
        seq[i]++;
        if (seq[i] != 0)
        {
            break;
        }
    }
}

#ifdef CL_EncryptAuthTls13

/* XXX: consider dispatching here based on underlying FL version. See
   TODO above. */

psResSize_t csAesGcmEncryptTls13(void *pssl,
                                 unsigned char *pt, unsigned char *ct,
                                 uint32 ptLen)
{
    ssl_t *ssl = pssl;
    psAesGcm_t *gcm;
    CL_DataOutPtr_t tag = ct + ptLen;
    CL_DataLen_t tagLen = 16;
    CL_DataLen_t aadLen = 5;
    unsigned char aadBuf[5];
    CL_DataInPtr_t aad = (CL_DataInPtr_t)aadBuf;
    CL_RV rv;

    gcm = &ssl->sec.encryptCtx.aesgcm;

    tls13MakeEncryptAad(ssl, aadBuf);
    rv = CLS_EncryptAuthTls13(flps_getCLS(),
                              gcm->multipart_gcm_key,
                              gcm->multipart_gcm_state,
                              gcm->tlsInfo,
                              gcm->algo,
                              aad, aadLen,
                              pt, ptLen,
                              ct,
                              tag, tagLen);
    if (rv == CLR_OK)
    {
        /* encrypted; commit to packet, increment sequence (the encrypt did that for tlsInfo) */
        /* XXX: maybe copy out the tlsInfo ... */
        psAesIncrSec(ssl->sec.seq);
        psAssert(memcmp(ssl->sec.seq, gcm->tlsInfo->Seq, 8) == 0);
    }
    return rv == CLR_OK ? ptLen : PS_FAILURE;
}

/* inLen includes tag */
psResSize_t csAesGcmDecryptTls13(void *pssl,
                                 unsigned char *ct, unsigned char *pt,
                                 uint32 inLen)
{
    ssl_t *ssl = pssl;
    psAesGcm_t *gcm;
    CL_DataOutPtr_t tag;
    CL_DataLen_t tagLen = 16;
    unsigned char aadBuf[5];
    CL_DataInPtr_t aad = (CL_DataInPtr_t)aadBuf;
    CL_DataLen_t aadLen = 5;
    CL_RV rv;
    ssize_t ptLen;

    ptLen = (inLen - tagLen);
    if (ptLen <= 0)
    {
        return PS_LIMIT_FAIL;
    }

    tag = ct + ptLen;
    gcm = &ssl->sec.decryptCtx.aesgcm;

    if (!USING_TLS_1_3_AAD(ssl))
    {
        aadLen = 0;
        aad = NULL;
    }
    else
    {
        tls13MakeDecryptAad(ssl, aadBuf);
    }
    /* Assume the caller has already verified ssl->sec.seq == ssl->sec.remSeq */
    psAssert(memcmp(ssl->sec.remSeq, gcm->tlsInfo->Seq, 8) == 0);
    rv = CLS_DecryptAuthTls13(flps_getCLS(),
                              gcm->multipart_gcm_key,
                              gcm->multipart_gcm_state,
                              gcm->tlsInfo,
                              gcm->algo,
                              aad, aadLen,
                              ct, ptLen,
                              tag, tagLen,
                              pt);

    if (rv == CLR_OK)
    {
        /* OK, commit to packet, increment sequence (the decrypt did that for tlsInfo) */
        psAesIncrSec(ssl->sec.remSeq);
        psAssert(memcmp(ssl->sec.remSeq, gcm->tlsInfo->Seq, 8) == 0);
    }
    return rv == CLR_OK ? ptLen : PS_FAILURE;
}
#else /* CL_EncryptAuthTls13 */

int32 csAesGcmEncryptTls13(void *ssl, unsigned char *pt,
        unsigned char *ct, uint32 ptLen)
{
    ssl_t *lssl = ssl;
    psAesGcm_t *ctx;
    unsigned char nonce[12];
    unsigned char aad[5];

    if (ptLen == 0)
    {
        return PS_SUCCESS;
    }

    ctx = &lssl->sec.encryptCtx.aesgcm;

    tls13MakeWriteNonce(lssl, nonce);

    if (USING_TLS_1_3_AAD(lssl))
    {
        tls13MakeEncryptAad(lssl, aad);
        psAesReadyGCM(ctx, nonce, aad, 5);
    }
    else
    {
        /* Before draft 25, no AAD was used. */
        psAesReadyGCM(ctx, nonce, NULL, 0);
    }
    psAesEncryptGCM(ctx, pt, ct, ptLen);
    psAesGetGCMTag(ctx, 16, ct + ptLen);

    /* Normally HMAC would increment the sequence */
    psAesIncrSec(lssl->sec.seq);

#ifdef DEBUG_TLS_1_3_GCM
    psTraceBytes("csAesGcmEncryptTls13 output with tag", ct,
            ptLen + TLS_GCM_TAG_LEN);
    psTraceBytes("Encrypt AAD", aad, 5);
#endif

    return ptLen;
}

int32 csAesGcmDecryptTls13(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psAesGcm_t *ctx;
    int32 ctLen, bytes;
    unsigned char nonce[12];
    unsigned char aad[5];

    ctLen = len - TLS_GCM_TAG_LEN;
    if (ctLen <= 0)
    {
        return PS_LIMIT_FAIL;
    }

    ctx = &lssl->sec.decryptCtx.aesgcm;

    tls13MakeReadNonce(lssl, nonce);

    if (USING_TLS_1_3_AAD(lssl))
    {
        tls13MakeDecryptAad(lssl, aad);
        psAesReadyGCM(ctx, nonce, aad, 5);
    }
    else
    {
        /* Before draft 25, no AAD was used. */
        psAesReadyGCM(ctx, nonce, NULL, 0);
    }

    if ((bytes = psAesDecryptGCM(ctx, ct, len, pt, ctLen)) < 0)
    {
        return -1;
    }
    psAesIncrSec(lssl->sec.remSeq);

#ifdef DEBUG_TLS_1_3_GCM
    psTraceBytes("csAesGcmDecryptTls13 output with tag", ct,
            ctLen);
    psTraceBytes("Decrypt AAD", aad, 5);
#endif

    return bytes;
}
#endif /* CL_EncryptAuthTls13 */

#if defined(USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE)  || defined(USE_CHACHA20_POLY1305_IETF)
int32 csChacha20Poly1305IetfEncryptTls13(void *ssl, unsigned char *pt,
    unsigned char *ct, uint32 len)
{
    ssl_t *lssl = ssl;
    psChacha20Poly1305Ietf_t *ctx;
    unsigned char nonce[TLS_AEAD_NONCE_MAXLEN];
    unsigned char aad[5];
    int32 ptLen;

    if (len == 0)
    {
        return PS_SUCCESS;
    }

    ptLen = len;
    ctx = &lssl->sec.encryptCtx.chacha20poly1305ietf;

    tls13MakeWriteNonce(lssl, nonce);
    if (USING_TLS_1_3_AAD(lssl))
    {
        tls13MakeEncryptAad(lssl, aad);
    }

#  ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceInfo("Entering csChacha20Poly1305IetfEncrypt IETF\n");
#  endif
    if (sizeof(lssl->sec.writeIV) < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH)
    {
        return PS_LIMIT_FAIL;
    }
    if (sizeof(nonce) < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH)
    {
        return PS_LIMIT_FAIL;
    }

# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceBytes("nonce", nonce, CHACHA20POLY1305_IETF_IV_FIXED_LENGTH);
    psTraceBytes("pt", pt, ptLen);
# endif

    /* Perform encryption and authentication tag computation */
    (void)psChacha20Poly1305IetfEncrypt(
            ctx,
            pt,
            ptLen,
            nonce,
            aad,
            5,
            ct);

# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceBytes("ct", ct, ptLen);
    psTraceBytes("tag", ct + ptLen, TLS_CHACHA20_POLY1305_IETF_TAG_LEN);
    psTraceBytes("aad", aad, 5);
# endif

    /* Normally HMAC would increment the sequence */
    psAesIncrSec(lssl->sec.seq);
    return len;
}

int32 csChacha20Poly1305IetfDecryptTls13(void *ssl, unsigned char *ct,
    unsigned char *pt, uint32 len)
{
    ssl_t *lssl = ssl;
    psChacha20Poly1305Ietf_t *ctx;
    int32 bytes;
#  ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    int32 ctLen;
#  endif
    unsigned char nonce[TLS_AEAD_NONCE_MAXLEN];
    unsigned char aad[5];

    ctx = &lssl->sec.decryptCtx.chacha20poly1305ietf;

    tls13MakeReadNonce(lssl, nonce);
    if (USING_TLS_1_3_AAD(lssl))
    {
        tls13MakeDecryptAad(lssl, aad);
    }

    /* Check https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-06 */

#  ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    psTraceInfo("Entering csChacha20Poly1305IetfDecrypt IETF\n");
#  endif

    if (sizeof(lssl->sec.readIV) < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH)
    {
        return PS_LIMIT_FAIL;
    }
    if (sizeof(nonce) < CHACHA20POLY1305_IETF_IV_FIXED_LENGTH)
    {
        return PS_LIMIT_FAIL;
    }

    /* Update length of encrypted data: we have to remove tag's length */
    if (len < TLS_CHACHA20_POLY1305_IETF_TAG_LEN)
    {
        return PS_LIMIT_FAIL;
    }
# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    ctLen = len - TLS_CHACHA20_POLY1305_IETF_TAG_LEN;
    psTraceBytes("nonce", nonce, CHACHA20POLY1305_IETF_IV_FIXED_LENGTH);
    psTraceBytes("ct", ct, ctLen);
    psTraceBytes("tag", ct + ctLen, TLS_CHACHA20_POLY1305_IETF_TAG_LEN);
    psTraceBytes("aad", aad, 5);
# endif

    /* --- Check authentication tag and decrypt data ---// */
    if ((bytes = psChacha20Poly1305IetfDecrypt(ctx,
                            ct,
                            len,
                            nonce,
                            aad,
                            5,
                            pt)) < 0)
    {
# ifdef DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE
        psTraceInfo("Decrypt NOK\n");
# endif
        return -1;
    }
    psAesIncrSec(lssl->sec.remSeq);

    return bytes + TLS_CHACHA20_POLY1305_IETF_TAG_LEN;
}
#endif /* DEBUG_CHACHA20_POLY1305_IETF_CIPHER_SUITE */

int32_t tls13GetCipherHmacAlg(ssl_t *ssl)
{
    if (ssl->cipher->ident == 0)
    {
        return 0;
    }

    if (ssl->cipher->flags & CRYPTO_FLAGS_SHA3)
    {
        return HMAC_SHA384;
    }
    else
    {
        return HMAC_SHA256;
    }
}

psResSize_t tls13GetCipherHashSize(ssl_t *ssl)
{
    return (psGetOutputBlockLength(tls13GetCipherHmacAlg(ssl)));
}

int32_t tls13CipherIdToHmacAlg(uint32_t cipherId)
{
    switch(cipherId)
    {
    case TLS_AES_128_GCM_SHA256:
    case TLS_CHACHA20_POLY1305_SHA256:
    case TLS_AES_128_CCM_SHA_256:
    case TLS_AES_128_CCM_8_SHA256:
        return HMAC_SHA256;
    case TLS_AES_256_GCM_SHA384:
        return HMAC_SHA384;
    }

    return 0;
}

psBool_t isTls13Ciphersuite(uint16_t suite)
{
    switch (suite)
    {
    case TLS_AES_128_GCM_SHA256:
    case TLS_CHACHA20_POLY1305_SHA256:
    case TLS_AES_128_CCM_SHA_256:
    case TLS_AES_128_CCM_8_SHA256:
    case TLS_AES_256_GCM_SHA384:
        return PS_TRUE;
    default:
        return PS_FALSE;
    }
}
# endif /* USE_TLS_1_3 */
