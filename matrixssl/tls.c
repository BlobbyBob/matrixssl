/**
 *      @file    tls.c
 *      @version $Format:%h%d$
 *
 *      TLS (SSLv3.1+) specific code.
 *      http://www.faqs.org/rfcs/rfc2246.html
 *      Primarily dealing with secret generation, message authentication codes
 *      and handshake hashing.
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

#ifdef USE_NATIVE_TLS_ALGS
/******************************************************************************/
# ifdef USE_TLS
/******************************************************************************/

#  define LABEL_SIZE          13
#  define LABEL_MASTERSEC     "master secret"
#  define LABEL_KEY_BLOCK     "key expansion"

#  define LABEL_EXT_SIZE          22
#  define LABEL_EXT_MASTERSEC     "extended master secret"


static int32_t genKeyBlock(ssl_t *ssl)
{
    unsigned char msSeed[SSL_HS_RANDOM_SIZE * 2 + LABEL_SIZE];
    uint32 reqKeyLen;
    int32_t rc = PS_FAIL;

    Memcpy(msSeed, LABEL_KEY_BLOCK, LABEL_SIZE);
    Memcpy(msSeed + LABEL_SIZE, ssl->sec.serverRandom,
        SSL_HS_RANDOM_SIZE);
    Memcpy(msSeed + LABEL_SIZE + SSL_HS_RANDOM_SIZE,
        ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);

    /* We must generate enough key material to fill the various keys */
    reqKeyLen = 2 * ssl->cipher->macSize +
                2 * ssl->cipher->keySize +
                2 * ssl->cipher->ivSize;
#  ifdef USE_EAP_FAST
    /**
        Generate master secret with tprf.
        Make space for additional key material (session key seed).
        @see https://tools.ietf.org/html/rfc4851#section-5.1
     */
    if (ssl->flags & SSL_FLAGS_EAP_FAST)
    {
        if (ssl->sid == NULL)
        {
            goto L_RETURN;
        }
        /* sid->masterSecret actually holds pac-key. Use tprf() here
           to derive session masterSecret, now that we're about to use it.
           masterSecret is also used after this for the finished message hash */
        rc = tprf(ssl->sid->masterSecret, EAP_FAST_PAC_KEY_LEN,
            msSeed + LABEL_SIZE, 2 * SSL_HS_RANDOM_SIZE,
            ssl->sec.masterSecret);
        if (rc < 0)
        {
            goto L_RETURN;
        }
        reqKeyLen += EAP_FAST_SESSION_KEY_SEED_LEN;
    }
#  endif

    /* Ensure there's enough room */
    if (reqKeyLen > SSL_MAX_KEY_BLOCK_SIZE)
    {
        rc = PS_MEM_FAIL;
        goto L_RETURN;
    }

#  ifdef USE_TLS_1_2
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
    {
        if ((rc = prf2(ssl->sec.masterSecret, SSL_HS_MASTER_SIZE, msSeed,
                 (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.keyBlock,
                 reqKeyLen, ssl->cipher->flags)) < 0)
        {
            goto L_RETURN;
        }
    }
#   ifndef USE_ONLY_TLS_1_2
    else
    {
        if ((rc = prf(ssl->sec.masterSecret, SSL_HS_MASTER_SIZE, msSeed,
                 (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.keyBlock,
                 reqKeyLen)) < 0)
        {
            goto L_RETURN;
        }
    }
#   endif
#  else
    if ((rc = prf(ssl->sec.masterSecret, SSL_HS_MASTER_SIZE, msSeed,
             (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.keyBlock,
             reqKeyLen)) < 0)
    {
        goto L_RETURN;
    }
#  endif
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        ssl->sec.rMACptr = ssl->sec.keyBlock;
        ssl->sec.wMACptr = ssl->sec.rMACptr + ssl->cipher->macSize;
        ssl->sec.rKeyptr = ssl->sec.wMACptr + ssl->cipher->macSize;
        ssl->sec.wKeyptr = ssl->sec.rKeyptr + ssl->cipher->keySize;
        ssl->sec.rIVptr = ssl->sec.wKeyptr + ssl->cipher->keySize;
        ssl->sec.wIVptr = ssl->sec.rIVptr + ssl->cipher->ivSize;
#  ifdef USE_EAP_FAST
        if (ssl->flags & SSL_FLAGS_EAP_FAST)
        {
            ssl->sec.eap_fast_session_key_seed = ssl->sec.wIVptr + ssl->cipher->ivSize;
        }
#  endif
    }
    else
    {
        ssl->sec.wMACptr = ssl->sec.keyBlock;
        ssl->sec.rMACptr = ssl->sec.wMACptr + ssl->cipher->macSize;
        ssl->sec.wKeyptr = ssl->sec.rMACptr + ssl->cipher->macSize;
        ssl->sec.rKeyptr = ssl->sec.wKeyptr + ssl->cipher->keySize;
        ssl->sec.wIVptr = ssl->sec.rKeyptr + ssl->cipher->keySize;
        ssl->sec.rIVptr = ssl->sec.wIVptr + ssl->cipher->ivSize;
#  ifdef USE_EAP_FAST
        if (ssl->flags & SSL_FLAGS_EAP_FAST)
        {
            ssl->sec.eap_fast_session_key_seed = ssl->sec.rIVptr + ssl->cipher->ivSize;
        }
#  endif
    }

    rc = SSL_HS_MASTER_SIZE;

L_RETURN:
    memzero_s(msSeed, sizeof(msSeed));
    if (rc < 0)
    {
        memzero_s(ssl->sec.masterSecret, SSL_HS_MASTER_SIZE);
        memzero_s(ssl->sec.keyBlock, SSL_MAX_KEY_BLOCK_SIZE);
    }
    return rc;
}

/******************************************************************************/
/*
 *      Generates all key material.
 */
int32_t tlsDeriveKeys(ssl_t *ssl)
{
    unsigned char msSeed[SSL_HS_RANDOM_SIZE * 2 + LABEL_SIZE];
    int32_t rc = PS_FAIL;

#  ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS && ssl->retransmit == 1)
    {
        /* The keyblock is still valid from the first pass */
        return SSL_HS_MASTER_SIZE;
    }
#  endif
/*
    If this session is resumed, we want to reuse the master secret to
    regenerate the key block with the new random values.
 */
    if (ssl->flags & SSL_FLAGS_RESUMED)
    {
        return genKeyBlock(ssl);
    }
#  ifdef USE_EAP_FAST
    /* We should only do EAP_FAST key derivation on resumed connections */
    if (ssl->flags & SSL_FLAGS_EAP_FAST)
    {
        return PS_FAIL;
    }
#  endif

/*
    master_secret = PRF(pre_master_secret, "master secret",
        client_random + server_random);
 */
    Memcpy(msSeed, LABEL_MASTERSEC, LABEL_SIZE);
    Memcpy(msSeed + LABEL_SIZE, ssl->sec.clientRandom,
        SSL_HS_RANDOM_SIZE);
    Memcpy(msSeed + LABEL_SIZE + SSL_HS_RANDOM_SIZE,
        ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);

#  ifdef USE_TLS_1_2
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
    {
        if ((rc = prf2(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
                 (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.masterSecret,
                 SSL_HS_MASTER_SIZE, ssl->cipher->flags)) < 0)
        {
            return rc;
        }
#   ifndef USE_ONLY_TLS_1_2
    }
    else
    {
        if ((rc = prf(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
                 (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.masterSecret,
                 SSL_HS_MASTER_SIZE)) < 0)
        {
            return rc;
        }
#   endif
    }
#  else
    if ((rc = prf(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
             (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.masterSecret,
             SSL_HS_MASTER_SIZE)) < 0)
    {
        return rc;
    }
#  endif

#  ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
/*
        May need premaster for retransmits.  DTLS will free this when handshake
        is known to be complete
 */
        return genKeyBlock(ssl);
    }
#  endif /* USE_DTLS */
/*
     premaster is now allocated for DH reasons.  Can free here
 */
    psFree(ssl->sec.premaster, ssl->hsPool);
    ssl->sec.premaster = NULL;
    ssl->sec.premasterSize = 0;

    return genKeyBlock(ssl);
}

/* Master secret generation if extended_master_secret extension is used */
int32_t tlsExtendedDeriveKeys(ssl_t *ssl)
{
    unsigned char msSeed[SHA384_HASHLEN + LABEL_EXT_SIZE];
    unsigned char hash[SHA384_HASHLEN];
    uint32_t outLen;
    int32_t rc = PS_FAIL;

#  ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS && ssl->retransmit == 1)
    {
        /* The keyblock is still valid from the first pass */
        return SSL_HS_MASTER_SIZE;
    }
#  endif
/*
    If this session is resumed, we should reuse the master_secret to
    regenerate the key block with the new random values. We should not
    be here regenerating the master_secret!
 */
    if (ssl->extFlags.extended_master_secret == 0 ||
        ssl->flags & SSL_FLAGS_RESUMED)
    {
        psTraceInfo("Invalid invokation of extended key derivation.\n");
        return PS_FAIL;
    }
#  ifdef USE_EAP_FAST
    /* We should only do EAP_FAST key derivation on resumed connections */
    if (ssl->flags & SSL_FLAGS_EAP_FAST)
    {
        return PS_FAIL;
    }
#  endif

    extMasterSecretSnapshotHSHash(ssl, hash, &outLen);
/*
    master_secret = PRF(pre_master_secret, "extended master secret",
        session_hash);
 */
    Memcpy(msSeed, LABEL_EXT_MASTERSEC, LABEL_EXT_SIZE);
    Memcpy(msSeed + LABEL_EXT_SIZE, hash, outLen);

#  ifdef USE_TLS_1_2
    if (ssl->flags & SSL_FLAGS_TLS_1_2)
    {
        if ((rc = prf2(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
                 outLen + LABEL_EXT_SIZE, ssl->sec.masterSecret,
                 SSL_HS_MASTER_SIZE, ssl->cipher->flags)) < 0)
        {
            return rc;
        }
#   ifndef USE_ONLY_TLS_1_2
    }
    else
    {
        if ((rc = prf(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
                 outLen + LABEL_EXT_SIZE, ssl->sec.masterSecret,
                 SSL_HS_MASTER_SIZE)) < 0)
        {
            return rc;
        }
#   endif
    }
#  else
    if ((rc = prf(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
             outLen + LABEL_EXT_SIZE, ssl->sec.masterSecret,
             SSL_HS_MASTER_SIZE)) < 0)
    {
        return rc;
    }
#  endif

#  ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
/*
        May need premaster for retransmits.  DTLS will free this when handshake
        is known to be complete
 */
        return genKeyBlock(ssl);
    }
#  endif /* USE_DTLS */
/*
     premaster is now allocated for DH reasons.  Can free here
 */
    psFree(ssl->sec.premaster, ssl->hsPool);
    ssl->sec.premaster = NULL;
    ssl->sec.premasterSize = 0;

    return genKeyBlock(ssl);
}

#  ifdef USE_SHA_MAC

#    ifdef USE_HMAC_TLS
#     ifdef USE_HMAC_TLS_LUCKY13_COUNTERMEASURE
/*
  Lucky13 countermeasure needs to perform more work than necessary
  to mask the timing side-channel. We shall take the additional dummy
  data from the end of the real input buffer in order to make cache
  timing analysis harder. This function computes the max amount of
  data that can be read after the plaintext.
*/

static
uint32_t computeLucky13WorkAmount(ssl_t *ssl,
        int32 mode,
        uint32_t ptLen)
{
    uint32_t macLen, ivLen, padLen, extraWorkLen;

    /* Lucky13 countermeasure only needed when decrypting. */
    if (mode != HMAC_VERIFY)
    {
        return ptLen;
    }

    /*
      Note: ssl->cipher->{macSize,ivSize} are the corresponding
      values for the negotiated cipher. During renegotiation,
      the negotiated cipher may be different than the currently
      active cipher.
    */
    macLen = ssl->deMacSize;
    ivLen = ssl->deIvSize;
    padLen = ssl->rec.len - macLen - ivLen - ptLen - 1;

    /* Should not get here unless we're using a block cipher. */
    psAssert(macLen > 0);

# ifdef DEBUG_LUCKY13
    Printf("record len : %d\n", ssl->rec.len);
    Printf("ivLen: %u\n", ivLen);
    Printf("ptLen: %u\n", ptLen);
    Printf("macLen: %u\n", macLen);
    Printf("padLen: %u\n", padLen);
    Printf("adding: %u\n", macLen + padLen);
# endif

    /*
      The input buffer has at least MAClen + padding len
      extra bytes after the plaintext. The minimum amount is the
      exact amount when this is the final record in the buffer.
*/
    extraWorkLen = macLen + padLen;
    return ptLen + extraWorkLen;
}
#     endif
#    endif

#   ifdef USE_SHA1
/******************************************************************************/
/*
    TLS sha1 HMAC generate/verify
 */
int32_t tlsHMACSha1(ssl_t *ssl, int32 mode, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac)
{
#    ifndef USE_HMAC_TLS
    psHmacSha1_t ctx;
#    endif
    unsigned char *key, *seq;
    unsigned char majVer, minVer, tmp[5];
    int32 i;
#    ifdef USE_DTLS
    unsigned char dtls_seq[8];
#    endif /* USE_DTLS */
#    ifdef USE_HMAC_TLS
    uint32 alt_len;
#    endif /* USE_HMAC_TLS */

    majVer = ssl->majVer;
    minVer = ssl->minVer;

    if (mode == HMAC_CREATE)
    {
        key = ssl->sec.writeMAC;
        seq = ssl->sec.seq;
    }
    else     /* HMAC_VERIFY */
    {
        key = ssl->sec.readMAC;
        seq = ssl->sec.remSeq;
    }

    /* Sanity */
    if (key == NULL)
    {
        return PS_FAILURE;
    }

#    ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        if (mode == HMAC_CREATE)
        {
            seq = dtls_seq;
            Memcpy(dtls_seq, ssl->epoch, 2);
            Memcpy(dtls_seq + 2, ssl->rsn, 6);
        }
        else     /* HMAC_VERIFY */
        {
            seq = dtls_seq;
            Memcpy(dtls_seq, ssl->rec.epoch, 2);
            Memcpy(dtls_seq + 2, ssl->rec.rsn, 6);
        }
    }
#    endif /* USE_DTLS */

    /*
      ssl->rec.len = length of TLSCiphertext (outer record) contents
      len = length of TLSCompressed.fragment. For block ciphers,
            len = rec.len - len(IV) - len(MAC) - len(padding) - 1.

      When using the NULL cipher, TLSCiphertext == TLSCompressed.
      When not using compression, TLSCompressed == TLSPlaintext.

      RFC 5246, 6.2.3.1: The MAC is generated as:
      MAC(MAC_write_key, seq_num +
                            TLSCompressed.type +
                            TLSCompressed.version +
                            TLSCompressed.length +
                            TLSCompressed.fragment);

      So the total amount of bytes to MAC is:
      8 (64-bit sequence number)
      +5 (TLSCompressed header)
      +len (TLSCompressed.fragment)

      When not using compression, TLSCompressed.fragment is the
      same as TLSPlaintext.fragment. Thus, the maximum number
      of bytes to MAC, when not using compression, is
      16384 + 8 + 5 = 16397.

      The Lucky thirteen name comes from the fact that 8 + 5 = 13.
    */
    tmp[0] = type;
    tmp[1] = majVer;
    tmp[2] = minVer;
    tmp[3] = (len & 0xFF00) >> 8;
    tmp[4] = len & 0xFF;

#    ifdef USE_HMAC_TLS
#     ifdef USE_HMAC_TLS_LUCKY13_COUNTERMEASURE
    /* Lucky13 countermeasure is only used on the decryption side. */
    alt_len = computeLucky13WorkAmount(ssl, mode, len);
#     else
    alt_len = len;
#     endif
    (void) psHmacSha1Tls(key, SHA1_HASH_SIZE,
        seq, 8,
        tmp, 5,
        data, len, alt_len,
        mac);
#    else
    if (psHmacSha1Init(&ctx, key, SHA1_HASH_SIZE) < 0)
    {
        return PS_FAIL;
    }
    psHmacSha1Update(&ctx, seq, 8);
    psHmacSha1Update(&ctx, tmp, 5);
    psHmacSha1Update(&ctx, data, len);
    psHmacSha1Final(&ctx, mac);
#    endif
    /* Update seq (only for normal TLS) */
    for (i = 7; i >= 0; i--)
    {
        seq[i]++;
        if (seq[i] != 0)
        {
            break;
        }
    }
    return PS_SUCCESS;
}
#   endif /* USE_SHA1 */

#   if defined(USE_HMAC_SHA256) || defined(USE_HMAC_SHA384)
/******************************************************************************/
/*
    TLS sha256/sha384 HMAC generate/verify
 */
int32_t tlsHMACSha2(ssl_t *ssl, int32 mode, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac, int32 hashLen)
{
#    ifndef USE_HMAC_TLS
    psHmac_t ctx;
#    endif
    unsigned char *key, *seq;
    unsigned char majVer, minVer, tmp[5];
    int32 i;
#    ifdef USE_DTLS
    unsigned char dtls_seq[8];
#    endif /* USE_DTLS */
#    ifdef USE_HMAC_TLS
    uint32 alt_len;
#    endif /* USE_HMAC_TLS */

    majVer = ssl->majVer;
    minVer = ssl->minVer;

    if (mode == HMAC_CREATE)
    {
        key = ssl->sec.writeMAC;
        seq = ssl->sec.seq;
    }
    else     /* HMAC_VERIFY */
    {
        key = ssl->sec.readMAC;
        seq = ssl->sec.remSeq;
    }
    /* Sanity */
    if (key == NULL)
    {
        return PS_FAILURE;
    }

#    ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        if (mode == HMAC_CREATE)
        {
            seq = dtls_seq;
            Memcpy(dtls_seq, ssl->epoch, 2);
            Memcpy(dtls_seq + 2, ssl->rsn, 6);
        }
        else     /* HMAC_VERIFY */
        {
            seq = dtls_seq;
            Memcpy(dtls_seq, ssl->rec.epoch, 2);
            Memcpy(dtls_seq + 2, ssl->rec.rsn, 6);
        }
    }
#    endif /* USE_DTLS */

    tmp[0] = type;
    tmp[1] = majVer;
    tmp[2] = minVer;
    tmp[3] = (len & 0xFF00) >> 8;
    tmp[4] = len & 0xFF;

#    ifdef USE_HMAC_TLS
#     ifdef USE_HMAC_TLS_LUCKY13_COUNTERMEASURE
    /* Lucky13 countermeasure is only used on the decryption side. */
    alt_len = computeLucky13WorkAmount(ssl, mode, len);
#     else
    alt_len = len;
#     endif
    (void) psHmacSha2Tls(key, hashLen,
        seq, 8,
        tmp, 5,
        data, len, alt_len,
        mac, hashLen);
#    else
    switch (hashLen)
    {
    case SHA256_HASHLEN:
        if (psHmacInit(&ctx, HMAC_SHA256, key, hashLen) < 0)
        {
            return PS_FAIL;
        }
        break;
    case SHA384_HASHLEN:
        if (psHmacInit(&ctx, HMAC_SHA384, key, hashLen) < 0)
        {
            return PS_FAIL;
        }
        break;
    default:
        return PS_FAIL;
    }
    psHmacUpdate(&ctx, seq, 8);
    psHmacUpdate(&ctx, tmp, 5);
    psHmacUpdate(&ctx, data, len);
    psHmacFinal(&ctx, mac);
#    endif
    /* Update seq (only for normal TLS) */
    for (i = 7; i >= 0; i--)
    {
        seq[i]++;
        if (seq[i] != 0)
        {
            break;
        }
    }
    return PS_SUCCESS;
}
#   endif /* USE_SHA256 || USE_SHA384 */
#  endif  /* USE_SHA_MAC */

#  ifdef USE_MD5
#   ifdef USE_MD5_MAC
/******************************************************************************/
/*
    TLS MD5 HMAC generate/verify
 */
int32_t tlsHMACMd5(ssl_t *ssl, int32 mode, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac)
{
    psHmacMd5_t ctx;
    unsigned char *key, *seq;
    unsigned char majVer, minVer, tmp[5];
    int32 i;

    majVer = ssl->majVer;
    minVer = ssl->minVer;

    if (mode == HMAC_CREATE)
    {
        key = ssl->sec.writeMAC;
        seq = ssl->sec.seq;
    }
    else     /* HMAC_VERIFY */
    {
        key = ssl->sec.readMAC;
        seq = ssl->sec.remSeq;
    }
    /* Sanity */
    if (key == NULL)
    {
        return PS_FAILURE;
    }

    if (psHmacMd5Init(&ctx, key, MD5_HASH_SIZE) < 0)
    {
        return PS_FAIL;
    }
#    ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        if (mode == HMAC_CREATE)
        {
            psHmacMd5Update(&ctx, ssl->epoch, 2);
            psHmacMd5Update(&ctx, ssl->rsn, 6);
        }
        else     /* HMAC_VERIFY */
        {
            psHmacMd5Update(&ctx, ssl->rec.epoch, 2);
            psHmacMd5Update(&ctx, ssl->rec.rsn, 6);
        }
    }
    else
    {
#    endif /* USE_DTLS */
    psHmacMd5Update(&ctx, seq, 8);
    for (i = 7; i >= 0; i--)
    {
        seq[i]++;
        if (seq[i] != 0)
        {
            break;
        }
    }
#    ifdef USE_DTLS
}
#    endif /* USE_DTLS */

    tmp[0] = type;
    tmp[1] = majVer;
    tmp[2] = minVer;
    tmp[3] = (len & 0xFF00) >> 8;
    tmp[4] = len & 0xFF;
    psHmacMd5Update(&ctx, tmp, 5);
    psHmacMd5Update(&ctx, data, len);
    psHmacMd5Final(&ctx, mac);

    return PS_SUCCESS;
}
#   endif /* USE_MD5_MAC */
#  endif  /* USE_MD5 */
# endif   /* USE_TLS */

int32 sslCreateKeys(ssl_t *ssl)
{
# ifdef USE_TLS
    if (ssl->flags & SSL_FLAGS_TLS)
    {
        return tlsDeriveKeys(ssl);
    }
    else
    {
#  ifndef DISABLE_SSLV3
        return sslDeriveKeys(ssl);
#  else
        return PS_ARG_FAIL;
#  endif /* DISABLE_SSLV3 */
    }
# else /* SSLv3 only below */
#  ifndef DISABLE_SSLV3
    return sslDeriveKeys(ssl);
#  endif /* DISABLE_SSLV3 */
# endif  /* USE_TLS */
}

/******************************************************************************/
/*
    Cipher suites are chosen before they are activated with the
    ChangeCipherSuite message.  Additionally, the read and write cipher suites
    are activated at different times in the handshake process.  The following
    APIs activate the selected cipher suite callback functions.
 */
int32 sslActivateReadCipher(ssl_t *ssl)
{

    ssl->decrypt = ssl->cipher->decrypt;
    ssl->verifyMac = ssl->cipher->verifyMac;
    ssl->nativeDeMacSize = ssl->cipher->macSize;
# ifdef USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    ssl->activeReadCipher = ssl->cipher;
# endif

    if (ssl->extFlags.truncated_hmac)
    {
        if (ssl->cipher->macSize > 0)   /* Only for HMAC-based ciphers */
        {
            ssl->deMacSize = 10;
        }
        else
        {
            ssl->deMacSize = ssl->cipher->macSize;
        }
    }
    else
    {
        ssl->deMacSize = ssl->cipher->macSize;
    }
    ssl->deBlockSize = ssl->cipher->blockSize;
    ssl->deIvSize = ssl->cipher->ivSize;
/*
    Reset the expected incoming sequence number for the new suite
 */
    Memset(ssl->sec.remSeq, 0x0, sizeof(ssl->sec.remSeq));

    if (ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL)
    {
        /* Sanity */
        if (ssl->sec.rKeyptr == NULL && ssl->sec.rMACptr == NULL)
        {
            psTraceErrr("sslActivateReadCipher sanity fail\n");
            return PS_FAILURE;
        }
        ssl->flags |= SSL_FLAGS_READ_SECURE;

# ifdef USE_TLS_1_2
        if (ssl->deMacSize == 0)
        {
            /* Need a concept for AEAD read and write start times for the
                cases surrounding changeCipherSpec if moving from one suite
                to another */
            ssl->flags |= SSL_FLAGS_AEAD_R;
            if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA)
            {
                ssl->flags &= ~SSL_FLAGS_NONCE_R;
            }
            else
            {
                ssl->flags |= SSL_FLAGS_NONCE_R;
            }
        }
        else
        {
            ssl->flags &= ~SSL_FLAGS_AEAD_R;
            ssl->flags &= ~SSL_FLAGS_NONCE_R;
        }
# endif
/*
        Copy the newly activated read keys into the live buffers
 */
        if (ssl->sec.rMACptr)
            Memcpy(ssl->sec.readMAC, ssl->sec.rMACptr, ssl->deMacSize);
        if (ssl->sec.rKeyptr)
            Memcpy(ssl->sec.readKey, ssl->sec.rKeyptr, ssl->cipher->keySize);
        if (ssl->sec.rIVptr)
            Memcpy(ssl->sec.readIV, ssl->sec.rIVptr, ssl->cipher->ivSize);
# ifdef DEBUG_TLS_MAC
        psTracePrintTlsKeys(ssl);
# endif /* DEBUG_TLS_MAC */

/*
        set up decrypt contexts
 */
        if (ssl->cipher->init)
        {
            if (ssl->cipher->init(&(ssl->sec), INIT_DECRYPT_CIPHER,
                    ssl->cipher->keySize) < 0)
            {
                psTraceErrr("Unable to initialize read cipher suite\n");
                return PS_FAILURE;
            }
        }

    }
    return PS_SUCCESS;
}

int32 sslActivateWriteCipher(ssl_t *ssl)
{
# ifdef USE_DTLS
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        if (ssl->retransmit == 0)
        {
            ssl->oencrypt = ssl->encrypt;
            ssl->ogenerateMac = ssl->generateMac;
            ssl->oenMacSize = ssl->enMacSize;
            ssl->oenNativeHmacSize = ssl->nativeEnMacSize;
            ssl->oenBlockSize = ssl->enBlockSize;
            ssl->oenIvSize = ssl->enIvSize;
            Memcpy(ssl->owriteMAC, ssl->sec.writeMAC, ssl->enMacSize);
            Memcpy(&ssl->oencryptCtx, &ssl->sec.encryptCtx,
                sizeof(psCipherContext_t));
            Memcpy(ssl->owriteIV, ssl->sec.writeIV, ssl->cipher->ivSize);
        }
    }
# endif /* USE_DTLS */

    ssl->encrypt = ssl->cipher->encrypt;
    ssl->generateMac = ssl->cipher->generateMac;
    ssl->nativeEnMacSize = ssl->cipher->macSize;
# ifdef USE_CHACHA20_POLY1305_IETF_CIPHER_SUITE
    ssl->activeWriteCipher = ssl->cipher;
# endif

    if (ssl->extFlags.truncated_hmac)
    {
        if (ssl->cipher->macSize > 0)   /* Only for HMAC-based ciphers */
        {
            ssl->enMacSize = 10;
        }
        else
        {
            ssl->enMacSize = ssl->cipher->macSize;
        }
    }
    else
    {
        ssl->enMacSize = ssl->cipher->macSize;
    }
    ssl->enBlockSize = ssl->cipher->blockSize;
    ssl->enIvSize = ssl->cipher->ivSize;
/*
    Reset the outgoing sequence number for the new suite
 */
    Memset(ssl->sec.seq, 0x0, sizeof(ssl->sec.seq));
    if (ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL)
    {
        ssl->flags |= SSL_FLAGS_WRITE_SECURE;

# ifdef USE_TLS_1_2
        if (ssl->enMacSize == 0)
        {
            /* Need a concept for AEAD read and write start times for the
                cases surrounding changeCipherSpec if moving from one suite
                to another */
            ssl->flags |= SSL_FLAGS_AEAD_W;
            if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA)
            {
                ssl->flags &= ~SSL_FLAGS_NONCE_W;
            }
            else
            {
                ssl->flags |= SSL_FLAGS_NONCE_W;
            }
        }
        else
        {
            ssl->flags &= ~SSL_FLAGS_AEAD_W;
            ssl->flags &= ~SSL_FLAGS_NONCE_W;
        }
# endif

/*
        Copy the newly activated write keys into the live buffers
 */
        Memcpy(ssl->sec.writeMAC, ssl->sec.wMACptr, ssl->enMacSize);
        Memcpy(ssl->sec.writeKey, ssl->sec.wKeyptr, ssl->cipher->keySize);
        Memcpy(ssl->sec.writeIV, ssl->sec.wIVptr, ssl->cipher->ivSize);
# ifdef DEBUG_TLS_MAC
        psTracePrintTlsKeys(ssl);
# endif /* DEBUG_TLS_MAC */

/*
        set up encrypt contexts
 */
        if (ssl->cipher->init)
        {
            if (ssl->cipher->init(&(ssl->sec), INIT_ENCRYPT_CIPHER,
                    ssl->cipher->keySize) < 0)
            {
                psTraceErrr("Unable to init write cipher suite\n");
                return PS_FAILURE;
            }
        }
    }
    return PS_SUCCESS;
}

/******************************************************************************/
#endif /* USE_NATIVE_TLS_ALGS */


#ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
/*
    Allocate a tlsExtension_t structure
 */
int32 matrixSslNewHelloExtension(tlsExtension_t **extension, void *userPoolPtr)
{
    psPool_t *pool = NULL;
    tlsExtension_t *ext;

    ext = psMalloc(pool, sizeof(tlsExtension_t));
    if (ext == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memset(ext, 0x0, sizeof(tlsExtension_t));
    ext->pool = pool;

    *extension = ext;
    return PS_SUCCESS;
}

void psCopyHelloExtension(tlsExtension_t *destination,
        const tlsExtension_t *source)
{
    const tlsExtension_t *src;
    tlsExtension_t *dst;

    psAssert(source != NULL && destination != NULL);
    psAssert(source != destination);

    src = source;
    dst = destination;

    while (1)
    {
        dst->pool = src->pool;
        dst->extType = src->extType;
        dst->extLen = src->extLen;
        dst->extData = psMalloc(src->pool, src->extLen);
        Memcpy(dst->extData, src->extData, src->extLen);
        if (src->next)
        {
            dst->next = psMalloc(src->pool, sizeof(*dst->next));
            dst = dst->next;
            src = src->next;
        }
        else
        {
            dst->next = NULL;
            break;
        }
    }
}

/*
  Make a deep copy of the extension struct for re-sending
  during renegotiations and TLS 1.3 HelloRetryRequest responses.
*/
void psAddUserExtToSession(ssl_t *ssl,
        const tlsExtension_t *ext)
{
    if (ext == NULL)
    {
        ssl->userExt = NULL;
        return;
    }
    if (ssl->userExt == ext)
    {
        return;
    }
    ssl->userExt = psMalloc(ssl->hsPool, sizeof(tlsExtension_t));
    psCopyHelloExtension(ssl->userExt, ext);
}

/******************************************************************************/
/*
    Free a tlsExtension_t structure and any extensions that have been loaded
 */
void matrixSslDeleteHelloExtension(tlsExtension_t *extension)
{
    tlsExtension_t *next, *ext;

    if (extension == NULL)
    {
        return;
    }
    ext = extension;
        /* Free first one */
    if (ext->extData)
    {
        psFree(ext->extData, ext->pool);
    }
    next = ext->next;
    psFree(ext, ext->pool);
    /* Free others */
    while (next)
    {
        ext = next;
        next = ext->next;
        if (ext->extData)
        {
            psFree(ext->extData, ext->pool);
        }
        psFree(ext, ext->pool);
    }
    return;
}

/*****************************************************************************/
/*
    Add an outgoing CLIENT_HELLO extension to a tlsExtension_t structure
    that was previously allocated with matrixSslNewHelloExtension
 */
int32 matrixSslLoadHelloExtension(tlsExtension_t *ext,
    unsigned char *extension, uint32 length, uint32 extType)
{
    tlsExtension_t *current, *new;

    if (ext == NULL || (length > 0 && extension == NULL))
    {
        return PS_ARG_FAIL;
    }
/*
    Find first empty spot in ext.  This is determined by extLen since even
    an empty extension will have a length of 1 for the 0
 */
    current = ext;
    while (current->extLen != 0)
    {
        if (current->next != NULL)
        {
            current = current->next;
            continue;
        }
        new = psMalloc(ext->pool, sizeof(tlsExtension_t));
        if (new == NULL)
        {
            return PS_MEM_FAIL;
        }
        Memset(new, 0, sizeof(tlsExtension_t));
        new->pool = ext->pool;
        current->next = new;
        current = new;
    }
/*
    Supports an empty extension which is really a one byte 00:
        ff 01 00 01 00  (two byte type, two byte len, one byte 00)

    This will either be passed in as a NULL 'extension' with a 0 length - OR -
    A pointer to a one byte 0x0 and a length of 1.  In either case, the
    structure will identify the ext with a length of 1 and a NULL data ptr
 */
    current->extType = extType;
    if (length > 0)
    {
        current->extLen = length;
        if (length == 1 && extension[0] == '\0')
        {
            current->extLen = 1;
        }
        else
        {
            current->extData = psMalloc(ext->pool, length);
            if (current->extData == NULL)
            {
                return PS_MEM_FAIL;
            }
            Memcpy(current->extData, extension, length);
        }
    }
    else if (length == 0)
    {
        current->extLen = 1;
    }

    return PS_SUCCESS;
}
#endif /* USE_CLIENT_SIDE_SSL */

#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
#ifndef USE_ONLY_PSK_CIPHER_SUITE
/**
  Return PS_TRUE if sigAlg is in peerSigAlgs, PS_FALSE otherwise.

  peerSigAlgs should be the a set of masks we created after
  parsing the peer's supported_signature_algorithms list
  in ClientHello or CertificateRequest.
*/
psBool_t peerSupportsSigAlg(int32_t sigAlg,
                            uint16_t peerSigAlgs
                            /* , psSize_t peerSigAlgsLen) */
                            )
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

/**
  Return PS_TRUE when we support sigAlg for signature generation,
  PS_FALSE otherwise.

  Compile-time switches as well as FIPS or non-FIPS mode is taken
  into account.

  @param[in] sigAlg The signature algorithm whose support is to
  be checked.
  @param[in] pubKeyAlgorithm The public key algorithm of our
  private/public key pair (OID_RSA_KEY_ALG or OID_ECDSA_KEY_ALG.)
*/
psBool_t weSupportSigAlg(int32_t sigAlg,
                         int32_t pubKeyAlgorithm)
{
    uint16_t we_support = 0;
    uint16_t is_non_fips = 0; /* 1 if not allowed in FIPS mode for
                                 signature generation. */

    PS_VARIABLE_SET_BUT_UNUSED(is_non_fips);

#ifndef USE_RSA
    if (pubKeyAlgorithm == OID_RSA_KEY_ALG)
    {
        return PS_FALSE;
    }
#endif
#ifndef USE_ECC
    if (pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        return PS_FALSE;
    }
#endif

    if (pubKeyAlgorithm == OID_RSA_KEY_ALG)
    {
        if (sigAlg == OID_MD2_RSA_SIG || sigAlg == OID_MD5_RSA_SIG)
        {
            /* No support for generating RSA-MD2 or RSA-MD5 signatures. */
            is_non_fips = 1;
            we_support = 0;
        }
        else if (sigAlg == OID_SHA1_RSA_SIG)
        {
            is_non_fips = 1;
#ifdef USE_SHA1
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA256_RSA_SIG)
        {
#ifdef USE_SHA256
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA384_RSA_SIG)
        {
#ifdef USE_SHA384
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA512_RSA_SIG)
        {
#ifdef USE_SHA512
            we_support = 1;
#endif
        }
        else
        {
            /* Our key does not support this algorithm. */
            return PS_FALSE;
        }
    }
    else if (pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        if (sigAlg == OID_SHA1_ECDSA_SIG)
        {
#ifdef USE_SHA1
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA256_ECDSA_SIG)
        {
#ifdef USE_SHA256
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA384_ECDSA_SIG)
        {
#ifdef USE_SHA384
            we_support = 1;
#endif
        }
        else if (sigAlg == OID_SHA512_ECDSA_SIG)
        {
#ifdef USE_SHA512
            we_support = 1;
#endif
        }
        else
        {
            /* Our key does not support this algorithm. */
            return PS_FALSE;
        }
    }
    else
    {
        return PS_FALSE; /* Unsupported public key alg, e.g. DSA. */
    }

    /* The basic capability is there. Now do some further checks
       if needed. */

    if (we_support)
    {
        return PS_TRUE;
    }
    else
    {
        return PS_FALSE;
    }
}

/** Return PS_TRUE when:
   - We support sigAlg for signature generation.
   - sigAlg is in peerSigAlgs.

   @param[in] sigAlg The signature algorithm whose support to check.
   @param[in] pubKeyAlgorithm The public key algorithm of our key.
   @param[in] peerSigAlgs The masks of the sigAlgs supported by the
     peer. This should be the one parsed from the peer's
     supported_signature_algorithms list in CertificateVerify or
     CertificateRequest. In this case, sigAlg \in peerSigAlgs
     means that the peer supports sigAlg for signature verification.
*/
psBool_t canUseSigAlg(int32_t sigAlg,
        int32_t pubKeyAlgorithm,
        uint16_t peerSigAlgs)
{
    return (weSupportSigAlg(sigAlg, pubKeyAlgorithm) &&
            peerSupportsSigAlg(sigAlg, peerSigAlgs));
}

/**
  Upgrade to a more secure signature algorithm. If the algorithm
  is already the strongest possible for the key type (i.e.
  RSA-SHA-512 or ECDSA-SHA-512) change to the most popular
  one (i.e. RSA-SHA-256 or ECDSA-SHA-256).
*/
int32_t upgradeSigAlg(int32_t sigAlg, int32_t pubKeyAlgorithm)
{
    /*
      RSA:
      MD2 -> SHA256
      MD5 -> SHA256
      SHA1 -> SHA256
      SHA256 -> SHA384
      SHA384 -> SHA512
      SHA512 -> SHA256
    */
    if (pubKeyAlgorithm == OID_RSA_KEY_ALG)
    {
        if (sigAlg == OID_MD2_RSA_SIG ||
                sigAlg == OID_MD5_RSA_SIG ||
                sigAlg == OID_SHA1_RSA_SIG)
        {
            return OID_SHA256_RSA_SIG;
        }
        else if (sigAlg == OID_SHA256_RSA_SIG)
        {
            return OID_SHA384_RSA_SIG;
        }
        else if (sigAlg == OID_SHA384_RSA_SIG)
        {
            return OID_SHA512_RSA_SIG;
        }
        else if (sigAlg == OID_SHA512_RSA_SIG)
        {
            return OID_SHA256_RSA_SIG;
        }
        else
        {
            return PS_UNSUPPORTED_FAIL;
        }
    }
    /*
      ECDSA:
      SHA1 -> SHA256
      SHA256 -> SHA384
      SHA384 -> SHA512
      SHA512 -> SHA256
    */
    else if (pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        if (sigAlg == OID_SHA1_ECDSA_SIG)
        {
            return OID_SHA256_ECDSA_SIG;
        }
        else if (sigAlg == OID_SHA256_ECDSA_SIG)
        {
            return OID_SHA384_ECDSA_SIG;
        }
        else if (sigAlg == OID_SHA384_ECDSA_SIG)
        {
            return OID_SHA512_ECDSA_SIG;
        }
        else if (sigAlg == OID_SHA512_ECDSA_SIG)
        {
            return OID_SHA256_ECDSA_SIG;
        }
        else
        {
            return PS_UNSUPPORTED_FAIL;
        }
    }
    else
    {
        return PS_UNSUPPORTED_FAIL;
    }
}

static
int32_t sigAlgRsaToEcdsa(int32_t sigAlg)
{
    if (sigAlg == OID_SHA1_RSA_SIG)
    {
        return OID_SHA1_ECDSA_SIG;
    }
    if (sigAlg == OID_SHA256_RSA_SIG)
    {
        return OID_SHA256_ECDSA_SIG;
    }
    if (sigAlg == OID_SHA384_RSA_SIG)
    {
        return OID_SHA384_ECDSA_SIG;
    }
    if (sigAlg == OID_SHA512_RSA_SIG)
    {
        return OID_SHA512_ECDSA_SIG;
    }
    else
    {
        return OID_SHA256_ECDSA_SIG;
    }
}

static
int32_t ecdsaToRsa(int32_t sigAlg)
{
    if (sigAlg == OID_SHA1_ECDSA_SIG)
    {
        return OID_SHA1_RSA_SIG;
    }
    if (sigAlg == OID_SHA256_ECDSA_SIG)
    {
        return OID_SHA256_RSA_SIG;
    }
    if (sigAlg == OID_SHA384_ECDSA_SIG)
    {
        return OID_SHA384_RSA_SIG;
    }
    if (sigAlg == OID_SHA512_ECDSA_SIG)
    {
        return OID_SHA512_RSA_SIG;
    }
    else
    {
        return OID_SHA256_RSA_SIG;
    }
}

/**
  Determine signature algorithm to use in the CertificateVerify or
  ServerKeyExchange handshake messages in TLS 1.2.

  TODO: add support for RSASSA-PSS.

  This function should only be called when using TLS 1.2.

  @param[in] certSigAlg The signature algorithm with which our
  certificate was signed.
  @param[in] keySize The size of our private key in bytes. For RSA,
  this is modulus; for ECDSA, this is the curve size.
  @param[in] pubKeyAlgorithm The public key algorithm to use for
  authentication. This should the same algorithm our public/private key
  pair is meant for. Must be either OID_RSA_KEY_ALG or
  OID_ECDSA_KEY_ALG.
  @param[in] peerSigAlg The list of signature algorithm masks
  the peer supports (e.g. HASH_SIG_SHA*_RSA_MASK). This should
  be the list created during parsing of the ClientHello or
  CertificateRequest message.
  @return The signature algorithm to use.
*/
int32_t chooseSigAlgInt(int32_t certSigAlg,
        psSize_t keySize,
        int32_t keyAlgorithm,
        uint16_t peerSigAlgs)
{
    int32 a = certSigAlg;
    psResSize_t hashLen;

#ifndef USE_RSA
    if (keyAlgorithm == OID_RSA_KEY_ALG)
    {
        return PS_UNSUPPORTED_FAIL;
    }
#endif
#ifndef USE_ECC
    if (keyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        return PS_UNSUPPORTED_FAIL;
    }
#endif

    /*
      We are going to use certSigAlg as the basis of our choice.
      This is because the SSL layer must ensure anyway that the peer
      supports this algorithm.
    */
    if (keyAlgorithm == OID_RSA_KEY_ALG)
    {
        if (certSigAlg == OID_SHA1_ECDSA_SIG ||
                certSigAlg == OID_SHA256_ECDSA_SIG ||
                certSigAlg == OID_SHA384_ECDSA_SIG ||
                certSigAlg == OID_SHA512_ECDSA_SIG)
        {
            /* Pubkey is RSA, but cert is signed with ECDSA.
               Convert certSigAlg to corresponding RSA alg. */
            a = ecdsaToRsa(certSigAlg);
        }
    }
    else if (keyAlgorithm == OID_ECDSA_KEY_ALG)
    {
        if (certSigAlg != OID_SHA1_ECDSA_SIG &&
                certSigAlg != OID_SHA256_ECDSA_SIG &&
                certSigAlg != OID_SHA384_ECDSA_SIG &&
                certSigAlg != OID_SHA512_ECDSA_SIG)
        {
            /* Pubkey is ECDSA, but cert is signed with RSA.
               Convert to corresponding ECDSA alg. */
            a = sigAlgRsaToEcdsa(certSigAlg);
        }
    }

    hashLen = psSigAlgToHashLen(a);
    if (hashLen < 0)
    { /* unknown sigAlg; error on hashLen */
        return hashLen;
    }

    /*
      For RSA signatures, RFC 5746 allows to pick any hash algorithm,
      as long as it is supported by the peer, i.e. included in the
      peer's signature_algorithms list.

      We use this opportunity to switch from the insecure MD5 and
      SHA-1 to SHA-256, if possible. We don't want to contribute
      to the longevity of obsolete hash algorithms.
    */
    if (psIsInsecureSigAlg(a, keyAlgorithm, keySize, hashLen)
        || !canUseSigAlg(a, keyAlgorithm, peerSigAlgs))
    {
        /* Try to upgrade: This won't select inscure ones. */
        a = upgradeSigAlg(a, keyAlgorithm);
        if (!canUseSigAlg(a, keyAlgorithm, peerSigAlgs))
        {
            /* Stil not supported. Try the next alternative. */
            a = upgradeSigAlg(a, keyAlgorithm);
            if (!canUseSigAlg(a, keyAlgorithm, peerSigAlgs))
            {
                /* Unable to upgrade insecure alg. Have to use the
                   server cert sig alg. */
                a = certSigAlg;
                psTraceIntInfo("Fallback to certificate sigAlg: %d\n", a);
            }
        }
    }
    psTraceIntInfo("Chose sigAlg %d\n", a);
    return a;
}

int32_t chooseSigAlg(psX509Cert_t *cert,
        psPubKey_t *privKey,
        uint16_t peerSigAlgs)
{
    int32 pubKeyAlg;

# ifdef USE_CERT_PARSE
    pubKeyAlg = cert->pubKeyAlgorithm;
# else
    if (privKey->type == PS_RSA)
    {
        pubKeyAlg = OID_RSA_KEY_ALG;
    }
    else if (privKey->type == PS_ECC)
    {
        pubKeyAlg = OID_ECDSA_KEY_ALG;
    }
    else
    {
        return PS_UNSUPPORTED_FAIL;
    }
# endif /* USE_CERT_PARSE */

    return chooseSigAlgInt(cert->sigAlgorithm,
            privKey->keysize,
            pubKeyAlg,
            peerSigAlgs);
}


/* Return the TLS 1.2 SignatureAndHashAlgorithm encoding for the
   given algorithm OID. */
int32_t getSignatureAndHashAlgorithmEncoding(uint16_t sigAlgOid,
     unsigned char *octet1,
     unsigned char *octet2,
     uint16_t *hashSize)
{
    unsigned char b1, b2;
    uint16_t hLen = 0;

     switch (sigAlgOid)
    {
#ifdef USE_SHA1
    case OID_SHA1_ECDSA_SIG:
        b1 = 0x2; /* SHA-1 */
        b2 = 0x3; /* ECDSA */
        hLen = SHA1_HASH_SIZE;
        break;
    case OID_SHA1_RSA_SIG:
        b1 = 0x2; /* SHA-1 */
        b2 = 0x1; /* RSA */
        hLen = SHA1_HASH_SIZE;
        break;
#endif
#ifdef USE_SHA256
    case OID_SHA256_ECDSA_SIG:
        b1 = 0x4; /* SHA-256 */
        b2 = 0x3; /* ECDSA */
        hLen = SHA256_HASH_SIZE;
        break;
    case OID_SHA256_RSA_SIG:
        b1 = 0x4; /* SHA-256 */
        b2 = 0x1; /* RSA */
        hLen = SHA256_HASH_SIZE;
        break;
#endif
#ifdef USE_SHA384
    case OID_SHA384_ECDSA_SIG:
        b1 = 0x5; /* SHA-384 */
        b2 = 0x3; /* ECDSA */
        hLen = SHA384_HASH_SIZE;
        break;
    case OID_SHA384_RSA_SIG:
        b1 = 0x5; /* SHA-384 */
        b2 = 0x1; /* RSA */
        hLen = SHA384_HASH_SIZE;
        break;
#endif
#ifdef USE_SHA512
    case OID_SHA512_ECDSA_SIG:
        b1 = 0x6; /* SHA-512 */
        b2 = 0x3; /* ECDSA */
        hLen = SHA512_HASH_SIZE;
        break;
    case OID_SHA512_RSA_SIG:
        b1 = 0x6; /* SHA-512 */
        b2 = 0x1; /* RSA */
        hLen = SHA512_HASH_SIZE;
        break;
#endif
    default:
        return PS_UNSUPPORTED_FAIL; /* algorithm not supported */
    }

     if (octet1 && octet2 && hashSize)
     {
         *octet1 = b1;
         *octet2 = b2;
         *hashSize = hLen;
         return PS_SUCCESS;
     }
     return PS_ARG_FAIL;
}
#endif /* ! USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

/* Helper function that searches for an uint16 item in an array */
int32_t findFromUint16Array(const uint16_t *a,
        psSize_t aLen,
        const uint16_t b)
{
    psSize_t i;
    for (i = 0; i < aLen; i++)
    {
        if (a[i] == b)
        {
            return i;
        }
    }
    return PS_FAILURE;
}

/* Helper function that determines whether TLS minor version is supported */
psBool_t tlsVersionSupported(ssl_t *ssl, const uint8_t minVersion)
{
    psSize_t i;
    for (i = 0; i < ssl->supportedVersionsLen; i++)
    {
        if ((ssl->supportedVersions[i] & 0xff) == minVersion)
        {
            return PS_TRUE;
        }
    }
    return PS_FALSE;
}

psBool_t anyTls13VersionSupported(ssl_t *ssl)
{
    return tlsVersionSupported(ssl, tls_v_1_3) ||
        tlsVersionSupported(ssl, tls_v_1_3_draft_22) ||
        tlsVersionSupported(ssl, tls_v_1_3_draft_23) ||
        tlsVersionSupported(ssl, tls_v_1_3_draft_24) ||
        tlsVersionSupported(ssl, tls_v_1_3_draft_26) ||
        tlsVersionSupported(ssl, tls_v_1_3_draft_28);
}

psBool_t anyNonTls13VersionSupported(ssl_t *ssl)
{
    return tlsVersionSupported(ssl, tls_v_1_2) ||
        tlsVersionSupported(ssl, tls_v_1_1) ||
        tlsVersionSupported(ssl, tls_v_1_0);
}

# ifdef USE_TLS_1_3
psBool_t tlsVersionSupportedByPeer(ssl_t *ssl, const uint8_t minVersion)
{
    psSize_t i;
    for (i = 0; i < ssl->tls13PeerSupportedVersionsLen; i++)
    {
        if ((ssl->tls13PeerSupportedVersions[i] & 0xff) == minVersion)
        {
            return PS_TRUE;
        }
    }
    return PS_FALSE;
}

psBool_t anyTls13VersionSupportedByPeer(ssl_t *ssl)
{
    return tlsVersionSupportedByPeer(ssl, tls_v_1_3) ||
        tlsVersionSupportedByPeer(ssl, tls_v_1_3_draft_22) ||
        tlsVersionSupportedByPeer(ssl, tls_v_1_3_draft_23) ||
        tlsVersionSupportedByPeer(ssl, tls_v_1_3_draft_24) ||
        tlsVersionSupportedByPeer(ssl, tls_v_1_3_draft_26) ||
        tlsVersionSupportedByPeer(ssl, tls_v_1_3_draft_28);
}

psBool_t peerOnlySupportsTls13(ssl_t *ssl)
{
    if (anyTls13VersionSupportedByPeer(ssl)
            && !tlsVersionSupportedByPeer(ssl, TLS_1_0_MIN_VER)
            && !tlsVersionSupportedByPeer(ssl, TLS_1_1_MIN_VER)
            && !tlsVersionSupportedByPeer(ssl, TLS_1_2_MIN_VER))
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}

psBool_t weOnlySupportTls13(ssl_t *ssl)
{
    if (anyTls13VersionSupported(ssl)
            && !tlsVersionSupported(ssl, TLS_1_0_MIN_VER)
            && !tlsVersionSupported(ssl, TLS_1_1_MIN_VER)
            && !tlsVersionSupported(ssl, TLS_1_2_MIN_VER))
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}
# endif /* USE_TLS_1_3 */


/******************************************************************************/
