/**
 *      @file    pubkey_sign.c
 *      @version $Format:%h%d$
 *
 *      Algorithm-independent signing API.
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

#include "../cryptoImpl.h"

#if defined(USE_RSA) || defined(USE_ECC)

# ifndef DEBUG_PUBKEY_SIGN
/* #  define DEBUG_PUB_KEY_SIGN */
# endif

# ifdef USE_ECC
static inline
int32_t psSignHashEcdsaInternal(psPool_t *pool,
        psPubKey_t *privKey,
        int32_t sigAlg,
        const unsigned char *in,
        psSize_t inLen,
        unsigned char **out,
        psSize_t *outLen,
        psSignOpts_t *opts)
{
    unsigned char tmp[140];
    psSize_t sigLen;
    int32_t rc;

    sigLen = sizeof(tmp);
    rc = psEccDsaSign(pool, &privKey->key.ecc,
            in, inLen,
            tmp, &sigLen,
            0, NULL);
    if (rc < 0)
    {
        return rc;
    }

    *out = psMalloc(pool, sigLen);
    if (*out == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memcpy(*out, tmp, sigLen);
    *outLen = sigLen;

    return PS_SUCCESS;
}
# endif /* USE_ECC */

# ifdef USE_RSA
int32_t psSignHashRsa(psPool_t *pool,
        psPubKey_t *privKey,
        int32_t sigAlg,
        const unsigned char *in,
        psSize_t inLen,
        unsigned char **out,
        psSize_t *outLen,
        psSignOpts_t *opts)
{
    int32_t rc;
    unsigned char *sig;
    psSize_t sigLen;

    sigLen = privKey->keysize;
    sig = psMalloc(pool, sigLen);
    if (sig == NULL)
    {
        return PS_MEM_FAIL;
    }

    rc = psRsaEncryptPriv(pool,
            &privKey->key.rsa,
            in,
            inLen,
            sig,
            sigLen,
            NULL);
    if (rc != PS_SUCCESS)
    {
        psFree(sig, pool);
        return rc;
    }

    *out = sig;
    *outLen = sigLen;

    return PS_SUCCESS;
}
# endif /* USE_RSA */

int32_t psSignHash(psPool_t *pool,
        psPubKey_t *privKey,
        int32_t sigAlg,
        const unsigned char *in,
        psSize_t inLen,
        unsigned char **out,
        psSize_t *outLen,
        psSignOpts_t *opts)
{

    switch (sigAlg)
    {
# ifdef USE_ECC
    case OID_SHA256_ECDSA_SIG:
    case OID_SHA384_ECDSA_SIG:
    case OID_SHA512_ECDSA_SIG:
        return psSignHashEcdsaInternal(pool, privKey, sigAlg,
                in, inLen, out, outLen, opts);
# endif /* USE_ECC */
# ifdef USE_PKCS1_PSS
    case OID_RSASSA_PSS:
        return psRsaPssSignHash(pool, privKey, sigAlg,
                in, inLen, out, outLen, opts);
# endif /* USE_PKCS1_PSS */
# ifdef USE_RSA
    case OID_SHA256_RSA_SIG:
    case OID_SHA384_RSA_SIG:
    case OID_SHA512_RSA_SIG:
        return psSignHashRsa(pool, privKey, sigAlg,
                in, inLen, out, outLen, opts);
# endif
    default:
        return PS_UNSUPPORTED_FAIL;
    }
}

int32_t psSign(psPool_t *pool,
        psPubKey_t *privKey,
        int32_t sigAlg,
        const unsigned char *in,
        psSizeL_t inLen,
        unsigned char **out,
        psSize_t *outLen,
        psSignOpts_t *opts)
{
    int32_t rc;
    unsigned char *sigOut = NULL;
# ifdef USE_ED25519
    psSizeL_t sigLen;
# endif
    psSize_t sigLenPsSize = 0;

# ifdef DEBUG_PUBKEY_SIGN
    psTraceBytes("psSign in", in, inLen);
# endif

    switch (sigAlg)
    {
# ifdef USE_ED25519
    case OID_ED25519_KEY_ALG:
        /* Ed25519 is used to sign arbitrary data directly without
           pre-hashing. */
        sigOut = psMalloc(pool, 64);
        if (sigOut == NULL)
        {
            psTraceCrypto("Out of mem in psSign\n");
            return PS_MEM_FAIL;
        }
        rc = psEd25519Sign(in,
                inLen,
                sigOut,
                &sigLen,
                privKey->key.ed25519.priv,
                privKey->key.ed25519.pub);
        psAssert(sigLen == 64);
        *outLen = sigLen;
        break;
# endif /* USE_ED25519 */
    default:
        /* All sig algs other than Ed25519 operate on hashes. */
        rc = psSignHash(pool,
                privKey,
                sigAlg,
                in,
                inLen,
                &sigOut,
                &sigLenPsSize,
                opts);
        *outLen = sigLenPsSize;
    }

    *out = sigOut;

# ifdef DEBUG_PUBKEY_SIGN
    psTraceBytes("psSign out", *out, sigLen);
# endif

    return rc;
}
psRes_t psComputeHashForSig(const unsigned char *dataBegin,
    psSizeL_t dataLen,
    int32_t signatureAlgorithm,
    unsigned char hashOut[SHA512_HASH_SIZE],
    psSize_t *hashOutLen)
{
    psDigestContext_t hash;

    if (hashOut == NULL || hashOutLen == NULL)
    {
        return PS_ARG_FAIL;
    }

    if (dataLen < 1)
    {
        return PS_ARG_FAIL;
    }

    switch (signatureAlgorithm)
    {
# ifdef ENABLE_MD5_SIGNED_CERTS
#  ifdef USE_MD2
    case OID_MD2_RSA_SIG:
        if (*hashOutLen < MD5_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psMd2Init(&hash.md2);
        if (psMd2Update(&hash.md2, dataBegin, dataLen) < 0)
        {
            return PS_FAILURE;
        }
        if (psMd2Final(&hash.md2, hashOut) < 0)
        {
            return PS_FAILURE;
        }
        *hashOutLen = MD5_HASH_SIZE;
        break;
#  endif /* USE_MD2 */
    case OID_MD5_RSA_SIG:
        if (*hashOutLen < MD5_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        if (psMd5Init(&hash.md5) < 0)
        {
            return PS_FAILURE;
        }
        psMd5Update(&hash.md5, dataBegin, dataLen);
        psMd5Final(&hash.md5, hashOut);
        *hashOutLen = MD5_HASH_SIZE;
        break;
# endif /* ENABLE_MD5_SIGNED_CERTS */
    case OID_SHA1_RSA_SIG:
    case OID_SHA1_RSA_SIG2:
    case OID_SHA1_ECDSA_SIG:
        if (*hashOutLen < SHA1_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha1PreInit(&hash.sha1);
        psSha1Init(&hash.sha1);
        psSha1Update(&hash.sha1, dataBegin, dataLen);
        psSha1Final(&hash.sha1, hashOut);
        *hashOutLen = SHA1_HASH_SIZE;
        break;
#ifdef USE_SHA224
    case OID_SHA224_RSA_SIG:
    case OID_SHA224_ECDSA_SIG:
        if (*hashOutLen < SHA224_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha224PreInit(&hash.sha256);
        psSha224Init(&hash.sha256);
        psSha224Update(&hash.sha256, dataBegin, dataLen);
        psSha224Final(&hash.sha256, hashOut);
        *hashOutLen = SHA224_HASH_SIZE;
        break;
#endif /* USE_SHA224 */
    case OID_SHA256_RSA_SIG:
    case OID_SHA256_ECDSA_SIG:
        if (*hashOutLen < SHA256_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha256PreInit(&hash.sha256);
        psSha256Init(&hash.sha256);
        psSha256Update(&hash.sha256, dataBegin, dataLen);
        psSha256Final(&hash.sha256, hashOut);
        *hashOutLen = SHA256_HASH_SIZE;
        break;
# ifdef USE_SHA384
    case OID_SHA384_RSA_SIG:
    case OID_SHA384_ECDSA_SIG:
        if (*hashOutLen < SHA384_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha384PreInit(&hash.sha384);
        psSha384Init(&hash.sha384);
        psSha384Update(&hash.sha384, dataBegin, dataLen);
        psSha384Final(&hash.sha384, hashOut);
        *hashOutLen = SHA384_HASH_SIZE;
        break;
# endif
# ifdef USE_SHA512
    case OID_SHA512_RSA_SIG:
    case OID_SHA512_ECDSA_SIG:
        if (*hashOutLen < SHA512_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha512PreInit(&hash.sha512);
        psSha512Init(&hash.sha512);
        psSha512Update(&hash.sha512, dataBegin, dataLen);
        psSha512Final(&hash.sha512, hashOut);
        *hashOutLen = SHA512_HASH_SIZE;
        break;
# endif
    default:
        psTraceCrypto("Unsupported sig alg\n");
        return PS_UNSUPPORTED_FAIL;
    }

    return PS_SUCCESS;
}

#endif /* USE_RSA || USE_ECC */
