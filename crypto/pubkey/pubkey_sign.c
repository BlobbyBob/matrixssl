/**
 *      @file    pubkey_sign.c
 *      @version $Format:%h%d$
 *
 *      Algorithm-independent signing API.
 */
/*
 *      Copyright (c) 2013-2018 Rambus Inc.
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
    unsigned char tmp[142];
    unsigned char *outBuf = tmp;
    psSize_t sigLen = sizeof(tmp);
    int32_t rc;
    uint8_t includeSize = 0;
    psBool_t usePreAllocatedOutBuf = PS_FALSE;

    if (opts && (opts->flags & PS_SIGN_OPTS_USE_PREALLOCATED_OUTBUF))
    {
        usePreAllocatedOutBuf = PS_TRUE;
    }
    if (opts && (opts->flags & PS_SIGN_OPTS_ECDSA_INCLUDE_SIZE))
    {
        includeSize = 1;
    }

    sigLen = sizeof(tmp);

    rc = psEccDsaSign(pool,
            &privKey->key.ecc,
            in,
            inLen,
            outBuf,
            &sigLen,
            includeSize,
            opts ? opts->userData : NULL);

    if (rc < 0)
    {
        return rc;
    }

    if (!usePreAllocatedOutBuf)
    {
        *out = psMalloc(pool, sigLen);
    }
    /* Check also the preallocated pointer. */
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
    unsigned char tmp[512];
    unsigned char *sig;
    psSize_t sigLen;
    psBool_t usePreAllocatedOutBuf = PS_FALSE;

    if (opts && (opts->flags & PS_SIGN_OPTS_USE_PREALLOCATED_OUTBUF))
    {
        usePreAllocatedOutBuf = PS_TRUE;
    }

    sigLen = privKey->keysize;

    if (usePreAllocatedOutBuf)
    {
        sig = tmp;
    }
    else
    {
        sig = psMalloc(pool, sigLen);
        if (sig == NULL)
        {
            return PS_MEM_FAIL;
        }
    }

    if (sigAlg == OID_RSA_TLS_SIG_ALG)
    {
        /* TLS 1.0/1.1 style RSA signature. */
        rc = psRsaEncryptPriv(pool,
                &privKey->key.rsa,
                in,
                inLen,
                sig,
                sigLen,
                opts ? opts->userData : NULL);
    }
    else
    {
        /* PKCS #1.5 signature. */
        rc = privRsaEncryptSignedElement(pool,
                &privKey->key.rsa,
                in,
                inLen,
                sig,
                sigLen,
                opts ? opts->userData : NULL);
    }
    if (rc != PS_SUCCESS)
    {
        if (!usePreAllocatedOutBuf)
        {
            psFree(sig, pool);
        }
        return rc;
    }

    if (usePreAllocatedOutBuf)
    {
        Memcpy(*out, sig, sigLen);
    }
    else
    {
        *out = sig;
        *outLen = sigLen;
    }

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
    case OID_ECDSA_TLS_SIG_ALG:
        if (privKey->type == PS_ECC || privKey->type == PS_ED25519)
        {
            return psSignHashEcdsaInternal(pool, privKey, sigAlg,
                in, inLen, out, outLen, opts);
        }
        break;
# endif /* USE_ECC */
# ifdef USE_SM2
    case OID_SM3_SM2_SIG:
        if (privKey->type == PS_ECC)
        {
            return psSignHashEcdsaInternal(pool, privKey, sigAlg,
                in, inLen, out, outLen, opts);
        }
	break;
# endif
# ifdef USE_RSA
#  ifdef USE_PKCS1_PSS
    case OID_RSASSA_PSS:
        if (privKey->type == PS_RSA)
        {
            return psRsaPssSignHash(pool, privKey, sigAlg,
                in, inLen, out, outLen, opts);
        }
        break;
#  endif /* USE_PKCS1_PSS */
    case OID_SHA256_RSA_SIG:
    case OID_SHA384_RSA_SIG:
    case OID_SHA512_RSA_SIG:
    case OID_RSA_TLS_SIG_ALG:
    case OID_RSA_PKCS15_SIG_ALG:
        if (privKey->type == PS_RSA)
        {
            return psSignHashRsa(pool, privKey, sigAlg,
                in, inLen, out, outLen, opts);
        }
# endif
    default:
        break;
    }
    psTraceCrypto("Invalid privKey type or sigAlg in psSignHash\n");
    return PS_UNSUPPORTED_FAIL;
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
# if defined(USE_SM2) && defined(USE_SM3)
    unsigned char sm3_out[SM3_HASH_SIZE] = { 0 };
    psSize_t sm3_out_len = SM3_HASH_SIZE;
# endif
# ifdef DEBUG_PUBKEY_SIGN
    psTraceBytes("psSign in", in, inLen);
# endif

    if (opts && (opts->flags & PS_SIGN_OPTS_USE_PREALLOCATED_OUTBUF))
    {
        sigOut = *out;
    }

    switch (sigAlg)
    {
# ifdef USE_ED25519
    case OID_ED25519_KEY_ALG:
        /* Ed25519 is used to sign arbitrary data directly without
           pre-hashing. */
        if (privKey->type != PS_ED25519)
        {
            psTraceCrypto("Invalid privKey type in psSign\n");
            return PS_MEM_FAIL;
        }
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
# if defined(USE_SM2) && defined(USE_SM3)
        if (opts && (opts->flags & PS_SIGN_OPTS_SM2_SIGN))
        {
            psComputeHashForSm2(in, inLen,
                    &privKey->key.ecc,
                    "1234567812345678", 16,
                    sm3_out, &sm3_out_len);
            rc = psSignHash(pool,
                    privKey,
                    OID_SM3_SM2_SIG,
                    sm3_out,
                    sm3_out_len,
                    &sigOut,
                    &sigLenPsSize,
                    opts);
        }
        else
# endif
        {
            rc = psSignHash(pool,
                    privKey,
                    sigAlg,
                    in,
                    inLen,
                    &sigOut,
                    &sigLenPsSize,
                    opts);
        }
        *outLen = sigLenPsSize;
    }

    *out = sigOut;

# ifdef DEBUG_PUBKEY_SIGN
    psTraceBytes("psSign out", *out, sigLen);
# endif

    return rc;
}

#if defined(USE_SM2) && defined(USE_SM3)
psRes_t psComputeHashForSm2(const unsigned char *dataBegin,
    psSizeL_t dataLen,
    const psEccKey_t *key,
    const char *id,
    psSizeL_t idLen,
    unsigned char hashOut[SM3_HASH_SIZE],
    psSize_t *hashOutLen)
{
    unsigned char hashTmp[SM3_HASH_SIZE];
    unsigned char idBits[2];
    psDigestContext_t hash;
    unsigned char parameters[] =
    {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFC, 0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
        0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7, 0xF3, 0x97,
        0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41,
        0x4D, 0x94, 0x0E, 0x93, 0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19,
        0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A,
        0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7, 0xBC, 0x37, 0x36, 0xA2,
        0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69,
        0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
    };

    if (*hashOutLen < SM3_HASH_SIZE)
    {
        return PS_OUTPUT_LENGTH;
    }
    *hashOutLen = SM3_HASH_SIZE;
    idBits[0] = ((idLen * 8) >> 8) % 256;
    idBits[1] = (idLen * 8) % 256;

    psSm3PreInit(&hash.u.sm3);
    psSm3Init(&hash.u.sm3);
    psSm3Update(&hash.u.sm3, idBits, 2);
    psSm3Update(&hash.u.sm3, id, idLen);
    psSm3Update(&hash.u.sm3, parameters, sizeof(parameters));
    psSm3Update(&hash.u.sm3, key->pubvalue, key->pubvalue_len);
    psSm3Final(&hash.u.sm3, hashTmp);

    psSm3PreInit(&hash.u.sm3);
    psSm3Init(&hash.u.sm3);
    psSm3Update(&hash.u.sm3, hashTmp, SM3_HASH_SIZE);
    psSm3Update(&hash.u.sm3, dataBegin, dataLen);
    psSm3Final(&hash.u.sm3, hashOut);
    return PS_SUCCESS;
}
#endif

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
        psMd2Init(&hash.u.md2);
        if (psMd2Update(&hash.u.md2, dataBegin, dataLen) < 0)
        {
            return PS_FAILURE;
        }
        if (psMd2Final(&hash.u.md2, hashOut) < 0)
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
        if (psMd5Init(&hash.u.md5) < 0)
        {
            return PS_FAILURE;
        }
        psMd5Update(&hash.u.md5, dataBegin, dataLen);
        psMd5Final(&hash.u.md5, hashOut);
        *hashOutLen = MD5_HASH_SIZE;
        break;
# endif /* ENABLE_MD5_SIGNED_CERTS */
# ifdef USE_SHA1
    case OID_SHA1_RSA_SIG:
    case OID_SHA1_RSA_SIG2:
    case OID_SHA1_ECDSA_SIG:
        if (*hashOutLen < SHA1_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha1PreInit(&hash.u.sha1);
        psSha1Init(&hash.u.sha1);
        psSha1Update(&hash.u.sha1, dataBegin, dataLen);
        psSha1Final(&hash.u.sha1, hashOut);
        *hashOutLen = SHA1_HASH_SIZE;
        break;
#endif
#ifdef USE_SHA224
    case OID_SHA224_RSA_SIG:
    case OID_SHA224_ECDSA_SIG:
        if (*hashOutLen < SHA224_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha224PreInit(&hash.u.sha256);
        psSha224Init(&hash.u.sha256);
        psSha224Update(&hash.u.sha256, dataBegin, dataLen);
        psSha224Final(&hash.u.sha256, hashOut);
        *hashOutLen = SHA224_HASH_SIZE;
        break;
#endif /* USE_SHA224 */
    case OID_SHA256_RSA_SIG:
    case OID_SHA256_ECDSA_SIG:
        if (*hashOutLen < SHA256_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha256PreInit(&hash.u.sha256);
        psSha256Init(&hash.u.sha256);
        psSha256Update(&hash.u.sha256, dataBegin, dataLen);
        psSha256Final(&hash.u.sha256, hashOut);
        *hashOutLen = SHA256_HASH_SIZE;
        break;
# ifdef USE_SHA384
    case OID_SHA384_RSA_SIG:
    case OID_SHA384_ECDSA_SIG:
        if (*hashOutLen < SHA384_HASH_SIZE)
        {
            return PS_OUTPUT_LENGTH;
        }
        psSha384PreInit(&hash.u.sha384);
        psSha384Init(&hash.u.sha384);
        psSha384Update(&hash.u.sha384, dataBegin, dataLen);
        psSha384Final(&hash.u.sha384, hashOut);
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
        psSha512PreInit(&hash.u.sha512);
        psSha512Init(&hash.u.sha512);
        psSha512Update(&hash.u.sha512, dataBegin, dataLen);
        psSha512Final(&hash.u.sha512, hashOut);
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
