/**
 *      @file    rsa_pub.c
 *      @version $Format:%h%d$
 *
 *      RSA public key operations.
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

/******************************************************************************/
/* TODO - the following functions are not implementation layer specific...
    move to a common file?

    Matrix-specific starts at #ifdef USE_MATRIX_RSA
 */

#define ASN_OVERHEAD_LEN_RSA_SHA2   19
#define ASN_OVERHEAD_LEN_RSA_SHA1   15

#ifdef USE_MATRIX_RSA
int32_t pubRsaDecryptSignedElement(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    int32_t signatureAlgorithm, rc;

    rc = psHashLenToSigAlg(outlen, PS_RSA);
    if (rc < 0)
    {
        return rc;
    }

    signatureAlgorithm = rc;

    return pubRsaDecryptSignedElementExt(pool, key, in, inlen,
        out, outlen,
        signatureAlgorithm, data);
}

int32_t pubRsaDecryptSignedElementExt(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    int32_t signatureAlgorithm, void *data)
{
    unsigned char *c, *front, *end;
    uint16_t outlenWithAsn, len, plen;
    int32_t oi, rc;

    /* The      issue here is that the standard RSA decryption routine requires
       the user to know the output length (usually just a hash size).  With
       these "digitally signed elements" there is an algorithm
       identifier surrounding the hash so we use the known magic numbers as
       additional lengths of the wrapper since it is a defined ASN sequence,
       ASN algorithm oid, and ASN octet string */
    if (outlen == SHA256_HASH_SIZE)
    {
        outlenWithAsn = SHA256_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA2;
    }
    else if (outlen == SHA1_HASH_SIZE)
    {
        outlenWithAsn = SHA1_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA1;
    }
    else if (outlen == SHA384_HASH_SIZE)
    {
        outlenWithAsn = SHA384_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA2;
    }
    else if (outlen == SHA512_HASH_SIZE)
    {
        outlenWithAsn = SHA512_HASH_SIZE + ASN_OVERHEAD_LEN_RSA_SHA2;
    }
    else
    {
        psTraceIntCrypto("Unsupported decryptSignedElement hash %d\n", outlen);
        return PS_FAILURE;
    }

    front = c = psMalloc(pool, outlenWithAsn);
    if (front == NULL)
    {
        return PS_MEM_FAIL;
    }

    if ((rc = psRsaDecryptPub(pool, key, in, inlen, c, outlenWithAsn, data)) < 0)
    {
        psFree(front, pool);
        psTraceCrypto("Couldn't public decrypt signed element\n");
        return rc;
    }

    /* Parse it */
    end = c + outlenWithAsn;

    /* @note Below we do a typecast to const to avoid a compiler warning,
        although it should be fine to pass a non const pointer into an
        api declaring it const, since it is just the API declaring the
        contents will not be modified within the API. */
    if (getAsnSequence((const unsigned char **) &c,
            (uint16_t) (end - c), &len) < 0)
    {
        psTraceCrypto("Couldn't parse signed element sequence\n");
        psFree(front, pool);
        return PS_FAILURE;
    }
    if (getAsnAlgorithmIdentifier((const unsigned char **) &c,
            (uint16_t) (end - c), &oi, &plen) < 0)
    {
        psTraceCrypto("Couldn't parse signed element octet string\n");
        psFree(front, pool);
        return PS_FAILURE;
    }

    if (oi == OID_SHA256_ALG)
    {
        psAssert(outlen == SHA256_HASH_SIZE);
    }
    else if (oi == OID_SHA1_ALG)
    {
        psAssert(outlen == SHA1_HASH_SIZE);
    }
    else if (oi == OID_SHA384_ALG)
    {
        psAssert(outlen == SHA384_HASH_SIZE);
    }
# ifdef USE_MD2
    else if (oi == OID_MD2_ALG)
    {
        psAssert(outlen == MD5_HASH_SIZE);
    }
# endif /* USE_MD2 */
# ifdef USE_MD5
    else if (oi == OID_MD5_ALG)
    {
        psAssert(outlen == MD5_HASH_SIZE);
    }
# endif /* USE_MD5 */
    else
    {
        psAssert(outlen == SHA512_HASH_SIZE);
    }

    /* Note the last test here requires the buffer to be exactly outlen bytes */
    if ((end - c) < 1 || (*c++ != ASN_OCTET_STRING) ||
        getAsnLength((const unsigned char **) &c, (uint16_t) (end - c), &len) < 0 ||
        (uint32_t) (end - c) != outlen)
    {

        psTraceCrypto("Couldn't parse signed element octet string\n");
        psFree(front, pool);
        return PS_FAILURE;
    }
    /* Will finally be sitting at the hash now */
    Memcpy(out, c, outlen);
    psFree(front, pool);
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    RSA public encryption. This is used by a public key holder to do
    key exchange with the private key holder, which can access the key using
    psRsaDecryptPriv().

    @param[in] pool Pool to use for temporary memory allocation for this op.
    @param[in] key RSA key to use for this operation.
    @param[in] in Pointer to allocated buffer to encrypt.
    @param[in] inlen Number of bytes pointed to by 'in' to encrypt.
    @param[out] out Pointer to allocated buffer to store encrypted data.
    @param[in] expected output length
    @param[in] data TODO Hardware context.

    @return 0 on success, < 0 on failure.
 */
int32_t psRsaEncryptPub(psPool_t *pool, psRsaKey_t *key,
    const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    int32_t err;
    psSize_t size;

    size = key->size;
    if (outlen < size)
    {
        psTraceCrypto("Error on bad outlen parameter to psRsaEncryptPub\n");
        return PS_ARG_FAIL;
    }

    if ((err = pkcs1Pad(in, inlen, out, size, PS_PRIVKEY, data))
        < PS_SUCCESS)
    {
        psTraceCrypto("Error padding psRsaEncryptPub. Likely data too long\n");
        return err;
    }
    if ((err = psRsaCrypt(pool, key, out, size, out, &outlen,
             PS_PUBKEY, data)) < PS_SUCCESS)
    {
        psTraceCrypto("Error performing psRsaEncryptPub\n");
        return err;
    }
    if (outlen != size)
    {
        psTraceCrypto("Encrypted size error in psRsaEncryptPub\n");
        return PS_FAILURE;
    }
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    RSA public decryption. This is used by a public key holder to verify
    a signature by the private key holder, who signs using psRsaEncryptPriv().

    @param[in] pool Pool to use for temporary memory allocation for this op.
    @param[in] key RSA key to use for this operation.
    @param[in,out] in Pointer to allocated buffer to encrypt.
    @param[in] inlen Number of bytes pointed to by 'in' to encrypt.
    @param[out] out Pointer to allocated buffer to store encrypted data.
    @param[in] outlen length of expected output.
    @param[in] data TODO Hardware context.

    @return 0 on success, < 0 on failure.

    TODO -fix
    @note this function writes over the 'in' buffer
 */
int32_t psRsaDecryptPub(psPool_t *pool, psRsaKey_t *key,
    unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    void *data)
{
    int32_t err;
    psSize_t ptLen;

    if (inlen != key->size)
    {
        psTraceCrypto("Error on bad inlen parameter to psRsaDecryptPub\n");
        return PS_ARG_FAIL;
    }
    ptLen = inlen;
    if ((err = psRsaCrypt(pool, key, in, inlen, in, &ptLen,
             PS_PUBKEY, data)) < PS_SUCCESS)
    {
        psTraceCrypto("Error performing psRsaDecryptPub\n");
        return err;
    }
    if (ptLen != inlen)
    {
        psTraceIntCrypto("Decrypted size error in psRsaDecryptPub %d\n", ptLen);
        return PS_FAILURE;
    }
    if ((err = pkcs1Unpad(in, inlen, out, outlen, PS_PUBKEY)) < 0)
    {
        return err;
    }
    return PS_SUCCESS;
}

# ifdef USE_PKCS1_PSS
psRes_t psRsaPssVerify(psPool_t *pool,
    const unsigned char *msgIn,
    psSizeL_t msgInLen,
    const unsigned char *sig,
    psSize_t sigLen,
    psPubKey_t *key,
    int32_t signatureAlgorithm,
    psBool_t *verifyResult,
    psVerifyOptions_t *opts)
{
    int32_t pssVerificationOk = 0;
    unsigned char *em;
    psSize_t emLen;
    int32_t rc = PS_SUCCESS;

    if (opts == NULL)
    {
        return PS_ARG_FAIL;
    }
    em = psMalloc(pool, key->keysize);
    if (em == NULL)
    {
        return PS_MEM_FAIL;
    }
    emLen = key->keysize;
    rc = psRsaCrypt(pool,
            &key->key.rsa,
            sig, sigLen,
            em, &emLen,
            PS_PUBKEY,
            NULL);
    if (rc < 0)
    {
        psFree(em, pool);
        return rc;
    }
    rc = psPkcs1PssDecode(pool,
            msgIn,
            msgInLen,
            em,
            emLen,
            opts->rsaPssSaltLen,
            opts->rsaPssHashAlg,
            key->keysize * 8,
            &pssVerificationOk);
    if (rc < 0)
    {
        psTraceCrypto("psRsaPssVerify: error decrypting signature\n");
        psFree(em, pool);
        rc = PS_FAILURE;
        goto out;
    }
    psFree(em, pool);

    if (pssVerificationOk == 1)
    {
        *verifyResult = PS_TRUE;
    }
    else
    {
        psTraceCrypto("psRsaPssVerify: signature verification failed\n");
        rc = PS_VERIFICATION_FAILED;
        *verifyResult = PS_FALSE;
    }

out:
    return rc;
}
# endif /* USE_PKCS1_PSS */

#endif  /* USE_MATRIX_RSA */

/******************************************************************************/

