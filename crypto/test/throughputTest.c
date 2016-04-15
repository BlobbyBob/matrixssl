/**
 *	@file    throughputTest.c
 *	@version $Format:%h%d$
 *
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

#include "crypto/cryptoApi.h"

#define	DATABYTES_AMOUNT	100 * 1048576	/* # x 1MB (1024-byte variety) */

#define TINY_CHUNKS		16
#define SMALL_CHUNKS	256
#define MEDIUM_CHUNKS	1024
#define LARGE_CHUNKS	4096
#define HUGE_CHUNKS		16 * 1024

static unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static unsigned char key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };


enum {
	AES_ENC_ALG = 1,
	AES_DEC_ALG,
	AES_GCM_ALG,
	ARC4_ALG,
	DES3_ALG,
	SEED_ALG,
	IDEA_ALG,

	AES_HMAC_ALG,
	AES_HMAC256_ALG,

	SHA1_ALG,
	SHA256_ALG,
	SHA384_ALG,
	SHA512_ALG,
	MD5_ALG
};

#if defined(USE_HMAC_SHA1) || defined(USE_HMAC_SHA256)
static void runWithHmac(psCipherContext_t *ctx, psHmac_t *hmac,
				int32 hashSize, int32 chunk, int32 alg)
{
	psTime_t			start, end;
	unsigned char		*dataChunk;
	int32				bytesSent, bytesToSend, round;
	unsigned char		mac[MAX_HASH_SIZE];
#ifdef USE_HIGHRES_TIME
	int32				mod;
	int64				diffu;
#else
	int32				diffm;
#endif

	dataChunk = psMalloc(NULL, chunk);
	memset(dataChunk, 0x0, chunk);
	bytesToSend = (DATABYTES_AMOUNT / chunk) * chunk;
	bytesSent = 0;

	switch (alg) {
#ifdef USE_AES
#ifdef USE_HMAC_SHA1
	case AES_HMAC_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
#ifdef USE_HMAC_TLS
			static unsigned char hmacKey[64] = { 0, };
			unsigned char mac[20];
			psHmacSha1Tls(hmacKey, 20, dataChunk, chunk,
						  NULL, 0, NULL, 0, 0, mac);
#else
			psHmacSha1Update(&hmac->u.sha1, dataChunk, chunk);
#endif
			psAesEncryptCBC(&ctx->aes, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psHmacSha1Final(&hmac->u.sha1, mac);
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_HMAC_SHA256
	case AES_HMAC256_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
#ifdef USE_HMAC_TLS
			static unsigned char hmacKey[64] = { 0, };
			unsigned char mac[32];
			psHmacSha2Tls(hmacKey, 32, dataChunk, chunk,
						  NULL, 0, NULL, 0, 0, mac, 32);
#else
			psHmacSha256Update(&hmac->u.sha256, dataChunk, chunk);
#endif
			psAesEncryptCBC(&ctx->aes, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psHmacSha256Final(&hmac->u.sha256, mac);
		psGetTime(&end, NULL);
		break;
#endif
#endif
	default:
		printf("Skipping HMAC Test\n");
		return;
	}

#ifdef USE_HIGHRES_TIME
	diffu = psDiffUsecs(start, end);
	round = (bytesToSend / diffu);
	mod = (bytesToSend % diffu);
	printf("%d byte chunks in %lld usecs total for rate of %d.%d MB/sec\n",
		chunk, (unsigned long long)diffu, round, mod);
#else
	diffm = psDiffMsecs(start, end, NULL);
	round = (bytesToSend / diffm) / 1000;
	printf("%d byte chunks in %d msecs total for rate of %d MB/sec\n",
		chunk, diffm, round);
#endif
}
#endif /* USE_HMAC */

static void runTime(psCipherContext_t *ctx, psCipherGivContext_t *ctx_giv,
					int32 chunk, int32 alg)
{
	psTime_t			start, end;
	unsigned char		*dataChunk;
	int32				bytesSent, bytesToSend, round;
#ifdef USE_HIGHRES_TIME
	int32				mod;
	int64				diffu;
#else
	int32				diffm;
#endif

	dataChunk = psMalloc(NULL, chunk + 16);
	memset(dataChunk, 0x0, chunk);
	bytesToSend = (DATABYTES_AMOUNT / chunk) * chunk;
	bytesSent = 0;

	switch(alg) {
#ifdef USE_AES_CBC
	case AES_ENC_ALG:
		printf("Encrypt ");
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psAesEncryptCBC(&ctx->aes, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
		break;
	case AES_DEC_ALG:
		printf("Decrypt ");
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psAesDecryptCBC(&ctx->aes, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_AES_GCM
	case AES_GCM_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psAesEncryptGCM(&ctx->aesgcm, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psAesGetGCMTag(&ctx->aesgcm, 16, dataChunk);
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_ARC4
	case ARC4_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psArc4(&ctx->arc4, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_3DES
	case DES3_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psDes3Encrypt(&ctx->des3, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_SEED
	case SEED_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSeedEncrypt(&ctx->seed, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_IDEA
	case IDEA_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psIdeaEncrypt(&ctx->idea, dataChunk, dataChunk, chunk);
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
		break;
#endif
	default:
		return;
	}

	psFree(dataChunk, NULL);

#ifdef USE_HIGHRES_TIME
	diffu = psDiffUsecs(start, end);
	round = (bytesToSend / diffu);
	mod = (bytesToSend % diffu);
	printf("%d byte chunks in %lld usecs total for rate of %d.%d MB/sec\n",
		chunk, (unsigned long long)diffu, round, mod);
#else
	diffm = psDiffMsecs(start, end, NULL);
	round = (bytesToSend / diffm) / 1000;
	printf("%d byte chunks in %d msecs total for rate of %d MB/sec\n",
		chunk, diffm, round);
#endif

}

/******************************************************************************/
#ifdef USE_AES_CBC
static int32 psAesTestCBC(void)
{
	int32				err;
	psCipherContext_t	eCtx;

#if defined(USE_MATRIX_AES_CBC) && !defined(PS_AES_IMPROVE_PERF_INCREASE_CODESIZE)
	_psTrace("##########\n#\n# ");
	_psTrace("AES speeds can be improved by enabling\n# ");
	_psTrace("PS_AES_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
	_psTrace("#\n#\n#########\n");
#endif

	_psTrace("***** AES-128 CBC *****\n");
	if ((err = psAesInitCBC(&eCtx.aes, iv, key, 16, PS_AES_ENCRYPT)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  returned %d\n", err);
 		return err;
	}
	runTime(&eCtx, NULL, TINY_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, SMALL_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, MEDIUM_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, AES_DEC_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, AES_DEC_ALG);
	psAesClearCBC(&eCtx.aes);

	_psTrace("***** AES-192 CBC *****\n");
	if ((err = psAesInitCBC(&eCtx.aes, iv, key, 24, PS_AES_ENCRYPT)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  returned %d\n", err);
 		return err;
	}
	runTime(&eCtx, NULL, TINY_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, SMALL_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, MEDIUM_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, AES_DEC_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, AES_DEC_ALG);
	psAesClearCBC(&eCtx.aes);

	_psTrace("***** AES-256 CBC *****\n");
	if ((err = psAesInitCBC(&eCtx.aes, iv, key, 32, PS_AES_ENCRYPT)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  returned %d\n", err);
 		return err;
	}
	runTime(&eCtx, NULL, TINY_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, SMALL_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, MEDIUM_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, AES_DEC_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, AES_ENC_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, AES_DEC_ALG);
	psAesClearCBC(&eCtx.aes);

	return 0;
}

#if defined(USE_HMAC_SHA1) || defined(USE_HMAC_SHA256)
static int32 psAesTestCBCHmac(void)
{
	int32				err;
	psCipherContext_t	eCtx;
	psHmac_t			hCtx;

#if defined(USE_MATRIX_AES_CBC) && !defined(PS_AES_IMPROVE_PERF_INCREASE_CODESIZE)
	_psTrace("##########\n#\n# ");
	_psTrace("AES speeds can be improved by enabling\n# ");
	_psTrace("PS_AES_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
	_psTrace("#\n#\n#########\n");
#endif

#ifdef USE_HMAC_SHA1
	_psTrace("***** AES-128 CBC + SHA1-HMAC *****\n");
	if ((err = psAesInitCBC(&eCtx.aes, iv, key, 16, PS_AES_ENCRYPT)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  returned %d\n", err);
 		return err;
	}
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, TINY_CHUNKS, AES_HMAC_ALG);
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, SMALL_CHUNKS, AES_HMAC_ALG);
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, MEDIUM_CHUNKS, AES_HMAC_ALG);
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, LARGE_CHUNKS, AES_HMAC_ALG);
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, HUGE_CHUNKS, AES_HMAC_ALG);
	psAesClearCBC(&eCtx.aes);

	_psTrace("***** AES-256 CBC + SHA1-HMAC *****\n");
	if ((err = psAesInitCBC(&eCtx.aes, iv, key, 32, PS_AES_ENCRYPT)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  returned %d\n", err);
 		return err;
	}
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, TINY_CHUNKS, AES_HMAC_ALG);
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, SMALL_CHUNKS, AES_HMAC_ALG);
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, MEDIUM_CHUNKS, AES_HMAC_ALG);
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, LARGE_CHUNKS, AES_HMAC_ALG);
	psHmacSha1Init(&hCtx.u.sha1, key, SHA1_HASH_SIZE);
	runWithHmac(&eCtx, &hCtx, 0, HUGE_CHUNKS, AES_HMAC_ALG);
	psAesClearCBC(&eCtx.aes);
#endif

#ifdef USE_HMAC_SHA256
	_psTrace("***** AES-128 CBC + SHA256-HMAC *****\n");
	if ((err = psAesInitCBC(&eCtx.aes, iv, key, 16, PS_AES_ENCRYPT)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  returned %d\n", err);
 		return err;
	}
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, TINY_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, SMALL_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, MEDIUM_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, LARGE_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, HUGE_CHUNKS, AES_HMAC256_ALG);
	psAesClearCBC(&eCtx.aes);

	_psTrace("***** AES-256 CBC + SHA256-HMAC *****\n");
	if ((err = psAesInitCBC(&eCtx.aes, iv, key, 32, PS_AES_ENCRYPT)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  returned %d\n", err);
 		return err;
	}
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, TINY_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, SMALL_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, MEDIUM_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, LARGE_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	runWithHmac(&eCtx, &hCtx, SHA256_HASH_SIZE, HUGE_CHUNKS, AES_HMAC256_ALG);
	psHmacSha256Init(&hCtx.u.sha256, key, 32);
	psAesClearCBC(&eCtx.aes);
#endif

	return 0;
}
#endif /* USE_HMAC */

/******************************************************************************/

#ifdef USE_AES_GCM
int32 psAesTestGCM(void)
{
	int32				err;
    psCipherContext_t	eCtx;
	psCipherGivContext_t eCtxGiv;

	memset(&eCtxGiv, 0, sizeof(eCtxGiv));

#ifndef USE_LIBSODIUM_AES_GCM
	_psTrace("***** AES-GCM-128 *****\n");
	if ((err = psAesInitGCM(&eCtx.aesgcm, key, 16)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  psAesInitGCM returned %d\n", err);
 		return err;
	}
	psAesReadyGCM(&eCtx.aesgcm, iv, iv, 16);
	runTime(&eCtx, &eCtxGiv, TINY_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, &eCtxGiv, SMALL_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, &eCtxGiv, MEDIUM_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, &eCtxGiv, LARGE_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, &eCtxGiv, HUGE_CHUNKS, AES_GCM_ALG);
#else
	_psTrace("***** Skipping AES-GCM-128 *****\n");
#endif /* !USE_LIBSODIUM */

	_psTrace("***** AES-GCM-256 *****\n");
	if ((err = psAesInitGCM(&eCtx.aesgcm, key, 32)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  psAesInitGCM returned %d\n", err);
 		return err;
	}
	psAesReadyGCM(&eCtx.aesgcm, iv, iv, 16);
	runTime(&eCtx, &eCtxGiv, TINY_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, &eCtxGiv, SMALL_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, &eCtxGiv, MEDIUM_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, &eCtxGiv, LARGE_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, &eCtxGiv, HUGE_CHUNKS, AES_GCM_ALG);

	psAesClearGCM(&eCtx.aesgcm);

	return PS_SUCCESS;
}
#endif /* USE_AES_GCM */

#endif /* USE_AES */

/******************************************************************************/
#ifdef USE_3DES
int32 psDes3Test(void)
{
	psCipherContext_t	eCtx;

#if defined(USE_MATRIX_3DES) && !defined(PS_3DES_IMPROVE_PERF_INCREASE_CODESIZE)
	_psTrace("##########\n#\n# ");
	_psTrace("3DES speeds can be improved by enabling\n# ");
	_psTrace("PS_3DES_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
	_psTrace("#\n#\n#########\n");
#endif

	psDes3Init(&eCtx.des3, iv, key);

	runTime(&eCtx, NULL, TINY_CHUNKS, DES3_ALG);
	runTime(&eCtx, NULL, SMALL_CHUNKS, DES3_ALG);
	runTime(&eCtx, NULL, MEDIUM_CHUNKS, DES3_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, DES3_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, DES3_ALG);

	psDes3Clear(&eCtx.des3);

	return 0;
}
#endif /* USE_3DES */
/******************************************************************************/

#ifdef USE_ARC4
int32 psArc4Test(void)
{
	psCipherContext_t	eCtx;

	psArc4Init(&eCtx.arc4, key, 16);

	runTime(&eCtx, NULL, TINY_CHUNKS, ARC4_ALG);
	runTime(&eCtx, NULL, SMALL_CHUNKS, ARC4_ALG);
	runTime(&eCtx, NULL, MEDIUM_CHUNKS, ARC4_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, ARC4_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, ARC4_ALG);

	psArc4Clear(&eCtx.arc4);

	return 0;
}
#endif /* USE_ARC4 */


/******************************************************************************/
#ifdef USE_SEED
int32 psSeedTest(void)
{
	psCipherContext_t	eCtx;

	psSeedInit(&eCtx.seed, iv, key);

	runTime(&eCtx, NULL, TINY_CHUNKS, SEED_ALG);
	runTime(&eCtx, NULL, SMALL_CHUNKS, SEED_ALG);
	runTime(&eCtx, NULL, MEDIUM_CHUNKS, SEED_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, SEED_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, SEED_ALG);

	psSeedClear(&eCtx.seed);

	return PS_SUCCESS;
}
#endif /* USE_SEED */
/******************************************************************************/
#ifdef USE_IDEA
int32 psIdeaTest(void)
{
	psCipherContext_t	eCtx;

	psIdeaInit(&eCtx.idea, iv, key);

	runTime(&eCtx, NULL, TINY_CHUNKS, IDEA_ALG);
	runTime(&eCtx, NULL, SMALL_CHUNKS, IDEA_ALG);
	runTime(&eCtx, NULL, MEDIUM_CHUNKS, IDEA_ALG);
	runTime(&eCtx, NULL, LARGE_CHUNKS, IDEA_ALG);
	runTime(&eCtx, NULL, HUGE_CHUNKS, IDEA_ALG);

	psIdeaClear(&eCtx.idea);

	return PS_SUCCESS;
}
#endif /* USE_IDEA */
/******************************************************************************/

void runDigestTime(psDigestContext_t *ctx, int32 chunk, int32 alg)
{
	psTime_t			start, end;
	unsigned char		*dataChunk;
	unsigned char		hashout[64];
	int32				bytesSent, bytesToSend, round;
#ifdef USE_HIGHRES_TIME
	int32				mod;
	int64				diffu;
#else
	int32				diffm;
#endif

	dataChunk = psMalloc(NULL, chunk);
	bytesToSend = (DATABYTES_AMOUNT / chunk) * chunk;
	bytesSent = 0;

	switch (alg) {
#ifdef USE_SHA1
	case SHA1_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha1Update(&ctx->sha1, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha1Final(&ctx->sha1, hashout);
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_SHA256
	case SHA256_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha256Update(&ctx->sha256, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha256Final(&ctx->sha256, hashout);
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_SHA384
	case SHA384_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha384Update(&ctx->sha384, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha384Final(&ctx->sha384, hashout);
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_SHA512
	case SHA512_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha512Update(&ctx->sha512, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha512Final(&ctx->sha512, hashout);
		psGetTime(&end, NULL);
		break;
#endif
#ifdef USE_MD5
	case MD5_ALG:
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psMd5Update(&ctx->md5, dataChunk, chunk);
			bytesSent += chunk;
		}
		psMd5Final(&ctx->md5, hashout);
		psGetTime(&end, NULL);
		break;
#endif
	default:
		printf("Skipping Digest Tests\n");
		return;
	}

#ifdef USE_HIGHRES_TIME
	diffu = psDiffUsecs(start, end);
	round = (bytesToSend / diffu);
	mod = (bytesToSend % diffu);
	printf("%d byte chunks in %lld usecs total for rate of %d.%d MB/sec\n",
		chunk, (unsigned long long)diffu, round, mod);
#else
	diffm = psDiffMsecs(start, end, NULL);
	round = (bytesToSend / diffm) / 1000;
	printf("%d byte chunks in %d msecs total for rate of %d MB/sec\n",
		chunk, diffm, round);
#endif

}

/******************************************************************************/
#ifdef USE_SHA1
int32  psSha1Test(void)
{
	psDigestContext_t	ctx;
#if defined(USE_MATRIX_SHA1) && !defined(PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE)
	_psTrace("##########\n#\n# ");
	_psTrace("SHA-1 speeds can be improved by enabling\n# ");
	_psTrace("PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
	_psTrace("#\n#\n#########\n");
#endif


	psSha1Init(&ctx.sha1);
	runDigestTime(&ctx, TINY_CHUNKS, SHA1_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA1_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA1_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA1_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA1_ALG);

	return PS_SUCCESS;
}

#endif /* USE_SHA1 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_SHA256
int32 psSha256Test(void)
{
	psDigestContext_t	ctx;

	psSha256Init(&ctx.sha256);
	runDigestTime(&ctx, TINY_CHUNKS, SHA256_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA256_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA256_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA256_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA256_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SHA256 */
/******************************************************************************/

#ifdef USE_SHA384
int32 psSha384Test(void)
{
	psDigestContext_t	ctx;

	psSha384Init(&ctx.sha384);
	runDigestTime(&ctx, TINY_CHUNKS, SHA384_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA384_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA384_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA384_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA384_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SHA384 */


#ifdef USE_SHA512
int32  psSha512Test(void)
{
	psDigestContext_t	ctx;

	psSha512Init(&ctx.sha512);
	runDigestTime(&ctx, TINY_CHUNKS, SHA512_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA512_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA512_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA512_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA512_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SHA512 */


/******************************************************************************/
#ifdef USE_MD5
int32 psMd5Test(void)
{
	psDigestContext_t	ctx;
#if defined(USE_MATRIX_MD5) && !defined(PS_MD5_IMPROVE_PERF_INCREASE_CODESIZE)
	_psTrace("##########\n#\n# ");
	_psTrace("MD5 speeds can be improved by enabling\n# ");
	_psTrace("PS_MD5_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
	_psTrace("#\n#\n#########\n");
#endif

	psMd5Init(&ctx.md5);
	runDigestTime(&ctx, TINY_CHUNKS, MD5_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, MD5_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, MD5_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, MD5_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, MD5_ALG);

	return PS_SUCCESS;
}
#endif /* USE_MD5 */
/******************************************************************************/

/******************************************************************************/
#ifdef  USE_MD4
int32 psMd4Test(void)
{
	return PS_SUCCESS;
}
#endif /* USE_MD4 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD2
int32 psMd2Test(void)
{
	return PS_SUCCESS;
}
#endif /* USE_MD2 */
/******************************************************************************/

/******************************************************************************/

typedef struct {
	int32	(*fn)(void);
	char	name[64];
} test_t;

static test_t tests[] = {
#ifdef USE_AES
{psAesTestCBC, "***** AES-CBC TESTS *****"},
#if defined(USE_HMAC_SHA1) || defined(USE_HMAC_SHA256)
{psAesTestCBCHmac, "***** AES-CBC + HMAC TESTS *****"},
#endif
#ifdef USE_AES_GCM
{psAesTestGCM, "***** AES-GCM TESTS *****"},
#endif
#else
{NULL, "AES"},
#endif

#ifdef USE_3DES
{psDes3Test
#else
{NULL
#endif
, "***** 3DES TESTS *****"},

#ifdef USE_SEED
{psSeedTest
#else
{NULL
#endif
, "***** SEED TESTS *****"},

#ifdef USE_IDEA
{psIdeaTest
#else
{NULL
#endif
, "***** IDEA TESTS *****"},

#ifdef USE_ARC4
{psArc4Test
#else
{NULL
#endif
, "***** RC4 TESTS *****"},


#ifdef USE_SHA1
{psSha1Test
#else
{NULL
#endif
, "***** SHA1 TESTS *****"},

#ifdef USE_SHA256
{psSha256Test
#else
{NULL
#endif
, "***** SHA256 TESTS *****"},

#ifdef USE_SHA384
{psSha384Test
#else
{NULL
#endif
, "***** SHA384 TESTS *****"},

#ifdef USE_SHA512
{psSha512Test
#else
{NULL
#endif
, "***** SHA512 TESTS *****"},

#ifdef USE_MD5
{psMd5Test
#else
{NULL
#endif
, "***** MD5 TESTS *****"},

#ifdef USE_MD4
{psMd4Test
#else
{NULL
#endif
, "***** MD4 TESTS *****"},

#ifdef USE_MD2
{psMd2Test
#else
{NULL
#endif
, "***** MD2 TESTS *****"},

{NULL, ""}
};

/******************************************************************************/
/*
	Main
*/

int main(int argc, char **argv)
{
	int32		i;

	if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS) {
		_psTrace("Failed to initialize library:  psCryptoOpen failed\n");
		return -1;
	}

	for (i = 0; *tests[i].name; i++) {
		if (tests[i].fn) {
			_psTraceStr("%s\n", tests[i].name);
			tests[i].fn();
		} else {
			_psTraceStr("%s: SKIPPED\n", tests[i].name);
		}
	}
	psCryptoClose();

#ifdef WIN32
	_psTrace("Press any key to close");
	getchar();
#endif

	return 0;
}
