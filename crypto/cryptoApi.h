/**
 *	@file    cryptoApi.h
 *	@version $Format:%h%d$
 *
 *	Prototypes for the Matrix crypto public APIs.
 */
/*
 *	Copyright (c) 2013-2016 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software
 *	into proprietary programs.  If you are unable to comply with the GPL, a
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/
 *
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *	See the GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#ifndef _h_PS_CRYPTOAPI
#define _h_PS_CRYPTOAPI

#ifdef __cplusplus
extern "C" {
#endif

#include "core/coreApi.h" /* Must be included first */
#include "cryptoConfig.h" /* Must be included second */
#include "cryptolib.h"

/******************************************************************************/
/**
	Public return codes.
	These are in addition to those in core/
	Failure codes MUST be < 0
	@note The range for crypto error codes must be between -30 and -49
*/
#define	PS_PARSE_FAIL			-31
/**
	@note Any future additions to certificate authentication failures
	must be carried through to MatrixSSL code
*/
#define PS_CERT_AUTH_PASS			PS_TRUE
#define	PS_CERT_AUTH_FAIL_BC		-32 /* BasicConstraint failure */
#define	PS_CERT_AUTH_FAIL_DN		-33 /* DistinguishedName failure */
#define	PS_CERT_AUTH_FAIL_SIG		-34 /* Signature validation failure */
#define PS_CERT_AUTH_FAIL_REVOKED	-35 /* Revoked via CRL */
#define	PS_CERT_AUTH_FAIL			-36 /* Generic cert auth fail */
#define PS_CERT_AUTH_FAIL_EXTENSION -37 /* extension permission problem */
#define PS_CERT_AUTH_FAIL_PATH_LEN	-38 /* pathLen exceeded */
#define PS_CERT_AUTH_FAIL_AUTHKEY	-39 /* subjectKeyid != issuer authKeyid */

#define PS_SIGNATURE_MISMATCH	-40 /* Algorithms all work but sig not a match */

#define PS_AUTH_FAIL			-41 /* An AEAD or HASH authentication fail */

/* Set as authStatusFlags to certificate callback when authStatus
	is PS_CERT_AUTH_FAIL_EXTENSION */
#define PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG	0x01
#define PS_CERT_AUTH_FAIL_EKU_FLAG			0x02
#define PS_CERT_AUTH_FAIL_SUBJECT_FLAG		0x04
#define PS_CERT_AUTH_FAIL_DATE_FLAG			0x08

/******************************************************************************/
/**
	Build the configuration string with the relevant build options for
	runtime validation of compile-time configuration.
*/
#if defined PSTM_X86 || defined PSTM_X86_64 || defined PSTM_ARM || \
	defined PSTM_MIPS
 #define PSTM_ASM_CONFIG_STR "Y"
#else
 #define PSTM_ASM_CONFIG_STR "N"
#endif
#ifdef PSTM_64BIT
 #define PSTM_64_CONFIG_STR "Y"
#else
 #define PSTM_64_CONFIG_STR "N"
#endif
#ifdef USE_AESNI_CRYPTO
 #define AESNI_CONFIG_STR "Y"
#else
 #define AESNI_CONFIG_STR "N"
#endif
 #define HW_PKA_CONFIG_STR "N"
 #define PKCS11_CONFIG_STR "N"
 #define FIPS_CONFIG_STR "N"

#define PSCRYPTO_CONFIG \
	"Y" \
	PSTM_ASM_CONFIG_STR \
	PSTM_64_CONFIG_STR \
	AESNI_CONFIG_STR \
	HW_PKA_CONFIG_STR \
	PKCS11_CONFIG_STR \
	FIPS_CONFIG_STR \
	PSCORE_CONFIG

/******************************************************************************/
/*
	Crypto module open/close
*/
PSPUBLIC int32_t psCryptoOpen(const char *config);
PSPUBLIC void psCryptoClose(void);

/******************************************************************************/
/*
	Abstract Cipher API
	Handles symmetric crypto, aead ciphers, hashes and macs.
*/
typedef enum {

	AES_CBC_ENC = 1,
	AES_CBC_DEC,
	AES_GCM_ENC,
	AES_GCM_DEC,
	CHACHA20_POLY1305_ENC,
	CHACHA20_POLY1305_DEC,
	ARC4,
	DES3,
	IDEA,
	SEED,

	HASH_MD2,
	HASH_MD5,
	HASH_SHA1,
	HASH_MD5SHA1,
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512,

	HMAC_MD5,
	HMAC_SHA1,
	HMAC_SHA256,
	HMAC_SHA384,

} psCipherType_e;

/******************************************************************************/
/*
	Symmetric Cipher Algorithms
*/
#ifdef USE_AES

#define PS_AES_ENCRYPT	0x1
#define PS_AES_DECRYPT	0x2

#ifdef USE_AES_BLOCK
/******************************************************************************/
PSPUBLIC int32_t psAesInitBlockKey(psAesKey_t *key,
						const unsigned char ckey[AES_MAXKEYLEN], uint8_t keylen,
						uint32_t flags);
PSPUBLIC void psAesEncryptBlock(psAesKey_t *key, const unsigned char *pt,
						unsigned char *ct);
PSPUBLIC void psAesDecryptBlock(psAesKey_t *key, const unsigned char *ct,
						unsigned char *pt);
PSPUBLIC void psAesClearBlockKey(psAesKey_t *key);
#endif

#ifdef USE_AES_CBC
/******************************************************************************/
PSPUBLIC int32_t psAesInitCBC(psAesCbc_t *ctx,
						const unsigned char IV[AES_IVLEN],
						const unsigned char key[AES_MAXKEYLEN], uint8_t keylen,
						uint32_t flags);
PSPUBLIC void psAesDecryptCBC(psAesCbc_t *ctx,
						const unsigned char *ct, unsigned char *pt,
						uint32_t len);
PSPUBLIC void psAesEncryptCBC(psAesCbc_t *ctx,
						const unsigned char *pt, unsigned char *ct,
						uint32_t len);
PSPUBLIC void psAesClearCBC(psAesCbc_t *ctx);
#endif

#ifdef USE_AES_GCM
/******************************************************************************/
PSPUBLIC int32_t psAesInitGCM(psAesGcm_t *ctx,
						const unsigned char key[AES_MAXKEYLEN], uint8_t keylen);
PSPUBLIC void psAesReadyGCM(psAesGcm_t *ctx,
						const unsigned char IV[AES_IVLEN],
						const unsigned char *aad, uint16_t aadLen);
PSPUBLIC void psAesEncryptGCM(psAesGcm_t *ctx,
						const unsigned char *pt, unsigned char *ct,
						uint32_t len);
PSPUBLIC int32_t psAesDecryptGCM(psAesGcm_t *ctx,
						const unsigned char *ct, uint32_t ctLen,
						unsigned char *pt, uint32_t ptLen);

PSPUBLIC void psAesDecryptGCMtagless(psAesGcm_t *ctx,
						const unsigned char *ct, unsigned char *pt,
						uint32_t len);
PSPUBLIC void psAesGetGCMTag(psAesGcm_t *ctx,
						uint8_t tagBytes, unsigned char tag[AES_BLOCKLEN]);
PSPUBLIC void psAesClearGCM(psAesGcm_t *ctx);

#endif /* USE_AES_GCM */



#endif /* USE_AES */

#ifdef USE_CHACHA20_POLY1305
/******************************************************************************/
PSPUBLIC int32_t psChacha20Poly1305Init(psChacha20Poly1305_t *ctx,
				const unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES],
				uint8_t keylen);
PSPUBLIC void psChacha20Poly1305Ready(psChacha20Poly1305_t *ctx,
				const unsigned char IV[crypto_aead_chacha20poly1305_NPUBBYTES+4],
				const unsigned char *aad, uint16_t aadLen);
PSPUBLIC void psChacha20Poly1305Encrypt(psChacha20Poly1305_t *ctx,
				const unsigned char *pt, unsigned char *ct,uint32_t len);

PSPUBLIC int32_t psChacha20Poly1305Decrypt(psChacha20Poly1305_t *ctx,
				const unsigned char *ct, uint32_t ctLen,
				unsigned char *pt, uint32_t ptLen);

PSPUBLIC void psChacha20Poly1305DecryptTagless(psChacha20Poly1305_t *ctx,
				const unsigned char *ct, unsigned char *pt,
				uint32_t len);

PSPUBLIC void psChacha20Poly1305GetTag(psChacha20Poly1305_t *ctx,
				uint8_t tagBytes,
				unsigned char tag[crypto_aead_chacha20poly1305_ABYTES]);
PSPUBLIC void psChacha20Poly1305Clear(psChacha20Poly1305_t *ctx);
#endif

#ifdef USE_3DES
/******************************************************************************/
PSPUBLIC int32_t psDes3Init(psDes3_t *ctx, const unsigned char IV[DES3_IVLEN],
						const unsigned char key[DES3_KEYLEN]);
PSPUBLIC void psDes3Decrypt(psDes3_t *ctx, const unsigned char *ct,
						unsigned char *pt, uint32_t len);
PSPUBLIC void psDes3Encrypt(psDes3_t *ctx, const unsigned char *pt,
						unsigned char *ct, uint32_t len);
PSPUBLIC void psDes3Clear(psDes3_t *ctx);
#endif

/******************************************************************************/
/*
	Hash Digest Algorithms
*/
#ifdef USE_MD5
/******************************************************************************/
PSPUBLIC int32_t psMd5Init(psMd5_t *md5);
PSPUBLIC void psMd5Update(psMd5_t *md5, const unsigned char *buf, uint32_t len);
PSPUBLIC void psMd5Final(psMd5_t *md, unsigned char hash[MD5_HASHLEN]);
#endif

#ifdef USE_SHA1
/******************************************************************************/
PSPUBLIC int32_t psSha1Init(psSha1_t *sha1);
PSPUBLIC void psSha1Update(psSha1_t *sha1,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha1Final(psSha1_t *sha1, unsigned char hash[SHA1_HASHLEN]);
#ifdef USE_CL_DIGESTS
PSPUBLIC void psSha1Sync(psSha1_t *ctx, int sync_all);
PSPUBLIC void psSha1Cpy(psSha1_t *ctx, const psSha1_t *ctx_in);
#else
static __inline void psSha1Sync(psSha1_t *ctx, int sync_all)
{
}
static __inline void psSha1Cpy(psSha1_t *d, const psSha1_t *s)
{
	memcpy(d, s, sizeof(psSha1_t));
}
#endif /* USE_CL_DIGESTS */
#endif /* USE_SHA1 */

#ifdef USE_MD5SHA1
/******************************************************************************/
PSPUBLIC int32_t psMd5Sha1Init(psMd5Sha1_t *md);
PSPUBLIC void psMd5Sha1Update(psMd5Sha1_t *md,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psMd5Sha1Final(psMd5Sha1_t *md,
				unsigned char hash[MD5SHA1_HASHLEN]);
static __inline void psMd5Sha1Sync(psMd5Sha1_t *ctx, int sync_all)
{
}
static __inline void psMd5Sha1Cpy(psMd5Sha1_t *d, const psMd5Sha1_t *s)
{
	memcpy(d, s, sizeof(psMd5Sha1_t));
}
#endif /* USE_MD5SHA1 */

#ifdef USE_SHA256
/******************************************************************************/

PSPUBLIC int32_t psSha256Init(psSha256_t *sha256);
PSPUBLIC void psSha256Update(psSha256_t *sha256,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha256Final(psSha256_t *sha256,
				unsigned char hash[SHA256_HASHLEN]);
#ifdef USE_CL_DIGESTS
PSPUBLIC void psSha256Sync(psSha256_t * md, int sync_all);
PSPUBLIC void psSha256Cpy(psSha256_t * d, const psSha256_t * s);
#else
static __inline void psSha256Sync(psSha256_t * md, int sync_all)
{
}
static __inline void psSha256Cpy(psSha256_t * d, const psSha256_t * s)
{
	memcpy(d, s, sizeof(psSha256_t));
}
#endif /* USE_CL_DIGESTS */
#endif /* USE_SHA256 */

/******************************************************************************/
#ifdef USE_SHA384
PSPUBLIC int32_t psSha384Init(psSha384_t *sha384);
PSPUBLIC void psSha384Update(psSha384_t *sha384,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha384Final(psSha384_t *sha384,
				unsigned char hash[SHA384_HASHLEN]);
#ifdef USE_CL_DIGESTS
PSPUBLIC void psSha384Sync(psSha384_t * md, int sync_all);
PSPUBLIC void psSha384Cpy(psSha384_t * d, const psSha384_t * s);
#else
static __inline void psSha384Sync(psSha384_t * md, int sync_all)
{
}
static __inline void psSha384Cpy(psSha384_t * d, const psSha384_t * s)
{
	memcpy(d, s, sizeof(psSha384_t));
}
#endif /* USE_CL_DIGESTS */
#endif /* USE_SHA384 */

#ifdef USE_SHA512
/******************************************************************************/
PSPUBLIC int32_t psSha512Init(psSha512_t *md);
PSPUBLIC void psSha512Update(psSha512_t *md,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psSha512Final(psSha512_t *md,
				unsigned char hash[SHA512_HASHLEN]);
#ifdef USE_CL_DIGESTS
PSPUBLIC void psSha512Sync(psSha512_t * md, int sync_all);
PSPUBLIC void psSha512Cpy(psSha512_t * d, const psSha512_t * s);
#else
static __inline void psSha512Sync(psSha512_t * md, int sync_all)
{
}
static __inline void psSha512Cpy(psSha512_t * d, const psSha512_t * s)
{
	memcpy(d, s, sizeof(psSha512_t));
}
#endif /* USE_CL_DIGESTS */
#endif /* USE_SHA512 */

/******************************************************************************/
/*
	HMAC Algorithms
*/
/* Generic HMAC algorithms, specify cipher by type. */
PSPUBLIC int32_t psHmacInit(psHmac_t *ctx, psCipherType_e type,
				const unsigned char *key, uint16_t keyLen);
PSPUBLIC void psHmacUpdate(psHmac_t *ctx,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacFinal(psHmac_t *ctx,
				unsigned char hash[MAX_HASHLEN]);

#ifdef USE_HMAC_MD5
/******************************************************************************/
PSPUBLIC int32_t psHmacMd5(const unsigned char *key, uint16_t keyLen,
				const unsigned char *buf, uint32_t len,
				unsigned char hash[MD5_HASHLEN],
				unsigned char *hmacKey, uint16_t *hmacKeyLen);
PSPUBLIC int32_t psHmacMd5Init(psHmacMd5_t *ctx,
				const unsigned char *key, uint16_t keyLen);
PSPUBLIC void psHmacMd5Update(psHmacMd5_t *ctx,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacMd5Final(psHmacMd5_t *ctx,
				unsigned char hash[MD5_HASHLEN]);
#endif

#ifdef USE_HMAC_SHA1
/******************************************************************************/
PSPUBLIC int32_t psHmacSha1(const unsigned char *key, uint16_t keyLen,
				const unsigned char *buf, uint32_t len,
				unsigned char hash[SHA1_HASHLEN],
				unsigned char *hmacKey, uint16_t *hmacKeyLen);
#ifdef USE_HMAC_TLS
PSPUBLIC int32_t psHmacSha1Tls(const unsigned char *key, uint32_t keyLen,
							   const unsigned char *buf1, uint32_t len1,
							   const unsigned char *buf2, uint32_t len2,
							   const unsigned char *buf3, uint32_t len3,
							   uint32_t len3_alt, unsigned char *hmac);
#endif
PSPUBLIC int32_t psHmacSha1Init(psHmacSha1_t *ctx,
				const unsigned char *key, uint16_t keyLen);
PSPUBLIC void psHmacSha1Update(psHmacSha1_t *ctx,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacSha1Final(psHmacSha1_t *ctx,
				unsigned char hash[SHA1_HASHLEN]);
#endif

#ifdef USE_HMAC_SHA256
/******************************************************************************/
PSPUBLIC int32_t psHmacSha256(const unsigned char *key, uint16_t keyLen,
				const unsigned char *buf, uint32_t len,
				unsigned char hash[SHA256_HASHLEN],
				unsigned char *hmacKey, uint16_t *hmacKeyLen);
#ifdef USE_HMAC_TLS
PSPUBLIC int32 psHmacSha2Tls(const unsigned char *key, uint32 keyLen,
							 const unsigned char *buf1, uint32 len1,
							 const unsigned char *buf2, uint32 len2,
							 const unsigned char *buf3, uint32 len3,
							 uint32 len3_alt, unsigned char *hmac,
							 uint32 hashSize);
#endif
PSPUBLIC int32_t psHmacSha256Init(psHmacSha256_t *ctx,
				const unsigned char *key, uint16_t keyLen);
PSPUBLIC void psHmacSha256Update(psHmacSha256_t *ctx,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacSha256Final(psHmacSha256_t *ctx,
				unsigned char hash[SHA256_HASHLEN]);
#endif
#ifdef USE_HMAC_SHA384
/******************************************************************************/
PSPUBLIC int32_t psHmacSha384(const unsigned char *key, uint16_t keyLen,
				const unsigned char *buf, uint32_t len,
				unsigned char hash[SHA384_HASHLEN],
				unsigned char *hmacKey, uint16_t *hmacKeyLen);
PSPUBLIC int32_t psHmacSha384Init(psHmacSha384_t *ctx,
				const unsigned char *key, uint16_t keyLen);
PSPUBLIC void psHmacSha384Update(psHmacSha384_t *ctx,
				const unsigned char *buf, uint32_t len);
PSPUBLIC void psHmacSha384Final(psHmacSha384_t *ctx,
				unsigned char hash[SHA384_HASHLEN]);
#endif



/******************************************************************************/
/*
	Private Key Parsing
	PKCS#1 - RSA specific
	PKCS#8 - General private key storage format
*/
#ifdef USE_PRIVATE_KEY_PARSING
#ifdef MATRIX_USE_FILE_SYSTEM
#ifdef USE_RSA
PSPUBLIC int32_t pkcs1ParsePrivFile(psPool_t *pool, const char *fileName,
				const char *password, psRsaKey_t *key);
#endif
PSPUBLIC int32_t pkcs1DecodePrivFile(psPool_t *pool, const char *fileName,
				const char *password, unsigned char **DERout, uint16_t *DERlen);
#endif /* MATRIX_USE_FILESYSTEM */
#ifdef USE_PKCS8
PSPUBLIC int32 pkcs8ParsePrivBin(psPool_t *pool, unsigned char *p,
				int32 size, char *pass, psPubKey_t *key);
#if defined(MATRIX_USE_FILE_SYSTEM) && defined (USE_PKCS12)
PSPUBLIC int32 psPkcs12Parse(psPool_t *pool, psX509Cert_t **cert,
				psPubKey_t *privKey, const unsigned char *file, int32 flags,
				unsigned char *importPass, int32 ipasslen,
				unsigned char *privkeyPass, int32 kpasslen);
#endif
#endif /* USE_PKCS8 */
#endif /* USE_PRIVATE_KEY_PARSING */

#ifdef USE_PKCS5
/******************************************************************************/
/*
	PKCS#5 PBKDF v1 and v2 key generation
*/
PSPUBLIC void pkcs5pbkdf1(unsigned char *pass, uint32 passlen,
				unsigned char *salt, int32 iter, unsigned char *key);
PSPUBLIC void pkcs5pbkdf2(unsigned char *password, uint32 pLen,
				 unsigned char *salt, uint32 sLen, int32 rounds,
				 unsigned char *key, uint32 kLen);
#endif /* USE_PKCS5 */

/******************************************************************************/
/*
	Public Key Cryptography
*/
#if defined(USE_RSA) || defined(USE_ECC) || defined(USE_DH)
PSPUBLIC int32_t psInitPubKey(psPool_t *pool, psPubKey_t *key, uint8_t type);
PSPUBLIC void psClearPubKey(psPubKey_t *key);
PSPUBLIC int32_t psNewPubKey(psPool_t *pool, uint8_t type, psPubKey_t **key);
PSPUBLIC void psDeletePubKey(psPubKey_t **key);
PSPUBLIC int32_t psParseUnknownPrivKey(psPool_t *pool, int pemOrDer,
			char *keyfile, char *password, psPubKey_t *privkey);
#endif

#ifdef USE_RSA
/******************************************************************************/

PSPUBLIC int32_t psRsaInitKey(psPool_t *pool, psRsaKey_t *key);
PSPUBLIC void psRsaClearKey(psRsaKey_t *key);
PSPUBLIC int32_t psRsaCopyKey(psRsaKey_t *to, const psRsaKey_t *from);

PSPUBLIC int32_t psRsaParsePkcs1PrivKey(psPool_t *pool,
				const unsigned char *p, uint16_t size,
				psRsaKey_t *key);
PSPUBLIC int32_t psRsaParseAsnPubKey(psPool_t *pool,
				const unsigned char **pp, uint16_t len,
				psRsaKey_t *key, unsigned char sha1KeyHash[SHA1_HASHLEN]);
PSPUBLIC uint16_t psRsaSize(const psRsaKey_t *key);
PSPUBLIC int32_t psRsaCmpPubKey(const psRsaKey_t *k1, const psRsaKey_t *k2);

PSPUBLIC int32_t psRsaEncryptPriv(psPool_t *pool, psRsaKey_t *key,
				const unsigned char *in, uint16_t inlen,
				unsigned char *out, uint16_t outlen,
				void *data);
PSPUBLIC int32_t psRsaEncryptPub(psPool_t *pool, psRsaKey_t *key,
				const unsigned char *in, uint16_t inlen,
				unsigned char *out, uint16_t outlen,
				void *data);
PSPUBLIC int32_t psRsaDecryptPriv(psPool_t *pool, psRsaKey_t *key,
				unsigned char *in, uint16_t inlen,
				unsigned char *out, uint16_t outlen,
				void *data);
PSPUBLIC int32_t psRsaDecryptPub(psPool_t *pool, psRsaKey_t *key,
				unsigned char *in, uint16_t inlen,
				unsigned char *out, uint16_t outlen,
				void *data);


PSPUBLIC int32_t psRsaCrypt(psPool_t *pool, psRsaKey_t *key,
				const unsigned char *in, uint16_t inlen,
				unsigned char *out, uint16_t *outlen,
				uint8_t type, void *data);

PSPUBLIC int32_t pubRsaDecryptSignedElement(psPool_t *pool, psRsaKey_t *key,
				unsigned char *in, uint16_t inlen,
				unsigned char *out, uint16_t outlen,
				void *data);
PSPUBLIC int32_t privRsaEncryptSignedElement(psPool_t *pool, psRsaKey_t *key,
				const unsigned char *in, uint16_t inlen,
				unsigned char *out, uint16_t outlen,
				void *data);
#ifdef USE_PKCS1_OAEP
PSPUBLIC int32 pkcs1OaepEncode(psPool_t *pool, const unsigned char *msg,
				uint32 msglen, const unsigned char *lparam,
				uint32 lparamlen, unsigned char *seed, uint32 seedLen,
				uint32 modulus_bitlen, int32 hash_idx,
				unsigned char *out, uint16_t *outlen);
PSPUBLIC int32 pkcs1OaepDecode(psPool_t *pool, const unsigned char *msg,
				uint32 msglen, const unsigned char *lparam, uint32 lparamlen,
				uint32 modulus_bitlen, int32 hash_idx,
				unsigned char *out, uint16_t *outlen);
#endif /* USE_PKCS1_OAEP */
#ifdef USE_PKCS1_PSS
PSPUBLIC int32 pkcs1PssEncode(psPool_t *pool, const unsigned char *msghash,
			uint32 msghashlen, unsigned char *salt, uint32 saltlen,
			int32 hash_idx,	uint32 modulus_bitlen, unsigned char *out,
			uint16_t *outlen);
PSPUBLIC int32 pkcs1PssDecode(psPool_t *pool, const unsigned char *msghash,
			uint32 msghashlen, const unsigned char *sig, uint32 siglen,
			uint32 saltlen, int32 hash_idx, uint32 modulus_bitlen, int32 *res);
#endif /* USE_PKCS1_PSS */
#endif /* USE_RSA */

#ifdef USE_ECC
/******************************************************************************/

PSPUBLIC int32_t psEccInitKey(psPool_t *pool, psEccKey_t *key,
				const psEccCurve_t *curve);
PSPUBLIC void psEccClearKey(psEccKey_t *key);
PSPUBLIC int32_t psEccNewKey(psPool_t *pool, psEccKey_t **key,
				const psEccCurve_t *curve);
PSPUBLIC void psEccDeleteKey(psEccKey_t **key);
PSPUBLIC int32 psEccCopyKey(psEccKey_t *to, psEccKey_t *from);
PSPUBLIC uint8_t psEccSize(const psEccKey_t *key);

PSPUBLIC int32_t psEccGenKey(psPool_t *pool, psEccKey_t *key,
				const psEccCurve_t *curve, void *usrData);

PSPUBLIC int32_t psEccParsePrivKey(psPool_t *pool,
				const unsigned char *keyBuf, uint16_t keyBufLen,
				psEccKey_t *keyPtr, const psEccCurve_t *curve);
PSPUBLIC int32_t psEccParsePrivFile(psPool_t *pool,
				const char *fileName, const char *password,
				psEccKey_t *key);

PSPUBLIC int32_t psEccX963ImportKey(psPool_t *pool,
				const unsigned char *in, uint16_t inlen,
				psEccKey_t *key, const psEccCurve_t *curve);
PSPUBLIC int32_t psEccX963ExportKey(psPool_t *pool, const psEccKey_t *key,
				unsigned char *out, uint16_t *outlen);

PSPUBLIC int32_t psEccGenSharedSecret(psPool_t *pool,
				const psEccKey_t *privKey, const psEccKey_t *pubKey,
				unsigned char *outbuf, uint16_t *outlen, void *usrData);

PSPUBLIC int32_t psEccDsaSign(psPool_t *pool, const psEccKey_t *privKey,
				const unsigned char *buf, uint16_t buflen,
				unsigned char *sig, uint16_t *siglen,
				uint8_t includeSize, void *usrData);
PSPUBLIC int32_t psEccDsaVerify(psPool_t *pool, const psEccKey_t *key,
				const unsigned char *buf, uint16_t bufLen,
				const unsigned char *sig, uint16_t siglen,
				int32_t *status, void *usrData);
#endif /* USE_ECC */

#ifdef USE_DH
/******************************************************************************/
/*
	PKCS#3 - Diffie-Hellman parameters
*/
PSPUBLIC int32_t pkcs3ParseDhParamBin(psPool_t *pool,
				const unsigned char *dhBin, uint16_t dhBinLen,
				psDhParams_t *params);
#ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32_t pkcs3ParseDhParamFile(psPool_t *pool,const char *fileName,
				psDhParams_t *params);
#endif
PSPUBLIC int32_t psDhExportParameters(psPool_t *pool,
				const psDhParams_t *params,
				unsigned char **pp, uint16_t *pLen,
				unsigned char **pg, uint16_t *gLen);
PSPUBLIC void pkcs3ClearDhParams(psDhParams_t *params);

PSPUBLIC int32_t psDhImportPubKey(psPool_t *pool,
				const unsigned char *inbuf, uint16_t inlen,
				psDhKey_t *key);
PSPUBLIC int32_t psDhExportPubKey(psPool_t *pool, const psDhKey_t *key,
					unsigned char *out, uint16_t *outlen);
PSPUBLIC void psDhClearKey(psDhKey_t *key);
PSPUBLIC uint16_t psDhSize(const psDhKey_t *key);

PSPUBLIC int32_t psDhGenKey(psPool_t *pool, uint16_t keysize,
				const unsigned char *pBin, uint16_t pLen,
				const unsigned char *gBin, uint16_t gLen,
				psDhKey_t *key, void *usrData);
PSPUBLIC int32_t psDhGenKeyInts(psPool_t *pool, uint16_t keysize,
				const pstm_int *p, const pstm_int *g,
				psDhKey_t *key, void *usrData);

PSPUBLIC int32_t psDhGenSharedSecret(psPool_t *pool,
				const psDhKey_t *privKey, const psDhKey_t *pubKey,
				const unsigned char *pBin, uint16_t pBinLen,
				unsigned char *out, uint16_t *outlen, void *usrData);

#endif /* USE_DH */

#ifdef USE_X509
/******************************************************************************/
/*
	X.509 Certificate support
*/
PSPUBLIC int32 psX509ParseCertFile(psPool_t *pool, char *fileName,
					psX509Cert_t **outcert, int32 flags);
PSPUBLIC int32 psX509ParseCert(psPool_t *pool, const unsigned char *pp, uint32 size,
					psX509Cert_t **outcert, int32 flags);
PSPUBLIC void psX509FreeCert(psX509Cert_t *cert);
#ifdef USE_CERT_PARSE
PSPUBLIC int32 psX509AuthenticateCert(psPool_t *pool, psX509Cert_t *subjectCert,
					psX509Cert_t *issuerCert, psX509Cert_t **foundIssuer,
					void *hwCtx, void *poolUserPtr);
#endif
#ifdef USE_CRL
PSPUBLIC int32 psX509ParseCrl(psPool_t *pool, psX509Cert_t *CA, int append,
					unsigned char *crlBin, int32 crlBinLen, void *poolUserPtr);
#endif /* USE_CRL */
#endif /* USE_X509 */

/******************************************************************************/
/*
	Pseudorandom Number Generation
*/
PSPUBLIC int32_t psInitPrng(psRandom_t *ctx, void *userPtr);
PSPUBLIC int32_t psGetPrng(psRandom_t *ctx, unsigned char *bytes, uint16_t size,
						void *userPtr);


/******************************************************************************/
/*
	Deprecated Algorithms
*/
#ifdef USE_ARC4
/******************************************************************************/
PSPUBLIC int32_t psArc4Init(psArc4_t *ctx,
				const unsigned char *key, uint8_t keylen);
PSPUBLIC void psArc4(psArc4_t *ctx, const unsigned char *in,
				unsigned char *out, uint32_t len);
PSPUBLIC void psArc4Clear(psArc4_t *ctx);
#endif

#ifdef USE_SEED
/******************************************************************************/
PSPUBLIC int32_t psSeedInit(psSeed_t *ctx, const unsigned char IV[SEED_IVLEN],
						const unsigned char key[SEED_KEYLEN]);
PSPUBLIC void psSeedDecrypt(psSeed_t *ctx, const unsigned char *ct,
						unsigned char *pt, uint32_t len);
PSPUBLIC void psSeedEncrypt(psSeed_t *ctx, const unsigned char *pt,
						unsigned char *ct, uint32_t len);
PSPUBLIC void psSeedClear(psSeed_t *ctx);
#endif

#ifdef USE_IDEA
/******************************************************************************/
PSPUBLIC int32_t psIdeaInit(psIdea_t *ctx, const unsigned char IV[IDEA_IVLEN],
						const unsigned char key[IDEA_KEYLEN]);
PSPUBLIC void psIdeaDecrypt(psIdea_t *ctx, const unsigned char *ct,
						unsigned char *pt, uint32_t len);
PSPUBLIC void psIdeaEncrypt(psIdea_t *ctx, const unsigned char *pt,
						unsigned char *ct, uint32_t len);
PSPUBLIC void psIdeaClear(psIdea_t *ctx);
#endif

#ifdef USE_RC2
/******************************************************************************/
PSPUBLIC int32_t psRc2Init(psRc2Cbc_t *ctx, const unsigned char *IV,
						const unsigned char *key, uint8_t keylen);
PSPUBLIC int32_t psRc2Decrypt(psRc2Cbc_t *ctx, const unsigned char *ct,
						unsigned char *pt, uint32_t len);
PSPUBLIC int32_t psRc2Encrypt(psRc2Cbc_t *ctx, const unsigned char *pt,
						unsigned char *ct, uint32_t len);
#endif

#ifdef USE_MD4
/******************************************************************************/
PSPUBLIC void psMd4Init(psMd4_t *md);
PSPUBLIC void psMd4Update(psMd4_t *md, const unsigned char *buf, uint32_t len);
PSPUBLIC int32_t psMd4Final(psMd4_t *md, unsigned char *hash);
#endif

#ifdef USE_MD2
/******************************************************************************/
PSPUBLIC void psMd2Init(psMd2_t *md);
PSPUBLIC int32_t psMd2Update(psMd2_t *md, const unsigned char *buf,
					uint32_t len);
PSPUBLIC int32_t psMd2Final(psMd2_t *md, unsigned char *hash);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _h_PS_CRYPTOAPI */

/******************************************************************************/

