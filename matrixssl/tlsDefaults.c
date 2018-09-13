/**
 *      @file    tlsDefaults.c
 *      @version $Format:%h%d$
 *
 *      Default value getters for TLS configuration
 *
 */
/*
 *      Copyright (c) 2018 INSIDE Secure Corporation
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

#include "matrixsslImpl.h"

/*
  Note that the order of sig_algs in the arrays is also the
  priority order.

  Generally, no compile-time checks for algorithm support needed
  here, because the lists are never sent as such: an algorithm
  is only added to the final run-time list if psIsAlgSupported
  returns true
*/

/*
  TLS1.2 uses the same list both for certificates and CertificateVerify.
  This list is used for case where only TLS1.2 is enabled.

  Note that even though the sigalg_ constants represent TLS 1.3
  SignatureScheme enum values, they are backwards compatible with
  TLS 1.2 SignatureAndHashAlgorithm enum values. For example,
  sigalg_ecdsa_secp256r1_sha256 (0x0403) means sha256_ecdsa in TLS 1.2
  (TLS 1.2 does not specify the curve to use.)
*/
static const uint16_t tls12SigAlgs[] = {

    sigalg_rsa_pkcs1_sha256,
    sigalg_rsa_pkcs1_sha384,
    sigalg_rsa_pkcs1_sha512,
    sigalg_ecdsa_secp256r1_sha256,
    sigalg_ecdsa_secp384r1_sha384,
    sigalg_ecdsa_secp521r1_sha512,
#if 0
    /* this this is a lie - code to verify such signature; fails on client side SKE decode that can't handle
       PSS. */
    sigalg_rsa_pss_rsae_sha256,
    sigalg_rsa_pss_rsae_sha384,
    sigalg_rsa_pss_rsae_sha512,
    sigalg_rsa_pss_pss_sha256,
    sigalg_rsa_pss_pss_sha384,
    sigalg_rsa_pss_pss_sha512,
#endif
    sigalg_rsa_pkcs1_sha1,
    sigalg_ecdsa_sha1,
    0
};

/* TLS1.3 uses separate lists for certificates and CertificateVerify.
   This list is for the TLS1.3 SIGNATURE_ALGORITHMS. */
static const uint16_t tls13SigAlgs[] = {
    sigalg_ecdsa_secp256r1_sha256,
    sigalg_ecdsa_secp384r1_sha384,
    sigalg_ecdsa_secp521r1_sha512,
# ifdef USE_ED25519
    sigalg_ed25519,
# endif
    sigalg_rsa_pss_rsae_sha256,
    sigalg_rsa_pss_rsae_sha384,
    sigalg_rsa_pss_rsae_sha512,
    sigalg_rsa_pss_pss_sha256,
    sigalg_rsa_pss_pss_sha384,
    sigalg_rsa_pss_pss_sha512,
    0
};

/* This list is used for TLS1.3 SIGNATURE_ALGORITHMS_CERT and
   case where both TLS1.2 and TLS1.3 are enabled */
static const uint16_t allSigAlgs[] = {
    sigalg_rsa_pkcs1_sha256,
    sigalg_rsa_pkcs1_sha384,
    sigalg_rsa_pkcs1_sha512,
    sigalg_ecdsa_secp256r1_sha256,
    sigalg_ecdsa_secp384r1_sha384,
    sigalg_ecdsa_secp521r1_sha512,
# ifdef USE_ED25519
    sigalg_ed25519,
# endif
    sigalg_rsa_pss_rsae_sha256,
    sigalg_rsa_pss_rsae_sha384,
    sigalg_rsa_pss_rsae_sha512,
    sigalg_rsa_pss_pss_sha256,
    sigalg_rsa_pss_pss_sha384,
    sigalg_rsa_pss_pss_sha512,
    sigalg_rsa_pkcs1_sha1,
    sigalg_ecdsa_sha1,
    0
};

int32 getDefaultSigAlgs(ssl_t *ssl)
{
    psSize_t i = 0, j = 0;
    psBool_t tls12Enabled = tlsVersionSupported(ssl, tls_v_1_2);
    psBool_t tls13Enabled = anyTls13VersionSupported(ssl);
# ifdef USE_DTLS

    /* DTLS 1.2 should use the TLS 1.2 list. */
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        if (ssl->minVer == DTLS_1_2_MIN_VER)
        {
            tls12Enabled = PS_TRUE;
        }
    }
# endif /* USE_DTLS */

    if (tls12Enabled && !tls13Enabled)
    {
        while (tls12SigAlgs[i] != 0)
        {
            if (psIsSigAlgSupported(tls12SigAlgs[i]))
            {
                if (j >= TLS_MAX_SIGNATURE_ALGORITHMS)
                {
                    psTraceErrr("Error: Too large set of default sig_alg! " \
                                "Increase TLS_MAX_SIGNATURE_ALGORITHMS\n");
                    return MATRIXSSL_ERROR;
                }
                ssl->supportedSigAlgs[j] = tls12SigAlgs[i];
                ssl->supportedSigAlgsLen++;
                j++;
            }
            i++;
        }
    }
    else if (!tls12Enabled && tls13Enabled)
    {
        while (tls13SigAlgs[i] != 0)
        {
            if (psIsSigAlgSupported(tls13SigAlgs[i]))
            {
                if (j >= TLS_MAX_SIGNATURE_ALGORITHMS)
                {
                    psTraceErrr("Error: Too large set of default sig_alg! " \
                                "Increase TLS_MAX_SIGNATURE_ALGORITHMS\n");
                    return MATRIXSSL_ERROR;
                }
                ssl->supportedSigAlgs[j] = tls13SigAlgs[i];
                ssl->supportedSigAlgsLen++;
                j++;
            }
            i++;
        }
    }
    else if (tls12Enabled && tls13Enabled)
    {
        while (allSigAlgs[i] != 0)
        {
            if (psIsSigAlgSupported(allSigAlgs[i]))
            {
                if (j >= TLS_MAX_SIGNATURE_ALGORITHMS)
                {
                    psTraceErrr("Error: Too large set of default sig_alg! " \
                                "Increase TLS_MAX_SIGNATURE_ALGORITHMS\n");
                    return MATRIXSSL_ERROR;
                }
                ssl->supportedSigAlgs[j] = allSigAlgs[i];
                ssl->supportedSigAlgsLen++;
                j++;
            }
            i++;
        }
    }
    else
    {
        /* The stack wants to always send the SIGNATURE_ALGORITHMS extension
           even with TLS version < 1.2 so we must include something to it */
        ssl->supportedSigAlgs[0] = sigalg_rsa_pkcs1_sha256;
        ssl->supportedSigAlgsLen = 1;
    }
    return MATRIXSSL_SUCCESS;
}

#ifdef USE_TLS_1_3
int32 tls13GetDefaultSigAlgsCert(ssl_t *ssl)
{
    psSize_t i = 0,j = 0;
    while (allSigAlgs[i] != 0)
    {
        if (psIsSigAlgSupported(allSigAlgs[i]))
        {
            if (j >= TLS_MAX_SIGNATURE_ALGORITHMS)
            {
                psTraceErrr("Error: Too large set of default sig_alg_cert! " \
                            "Increase TLS_MAX_SIGNATURE_ALGORITHMS\n");
                return MATRIXSSL_ERROR;
            }
            ssl->tls13SupportedSigAlgsCert[j] = allSigAlgs[i];
            ssl->tls13SupportedSigAlgsCertLen++;
            j++;
        }
        i++;
    }
    return MATRIXSSL_SUCCESS;
}

int32 tls13GetDefaultGroups(ssl_t *ssl)
{
    psSize_t i = 0;
# ifdef USE_X25519
    psBool_t useX25519 = PS_TRUE;
# endif

    ssl->tls13SupportedGroups[i++] = namedgroup_secp256r1;
    ssl->tls13SupportedGroups[i++] = namedgroup_secp384r1;
# ifdef USE_X25519
    if (useX25519)
    {
        ssl->tls13SupportedGroups[i++] = namedgroup_x25519;
    }
# endif
    ssl->tls13SupportedGroups[i++] = namedgroup_secp521r1;
    ssl->tls13SupportedGroupsLen = i;
    ssl->tls13NumClientHelloKeyShares = 1;
    return MATRIXSSL_SUCCESS;
}
#endif

/* Gets default cipher suite list. The function allocates
   memory and saves the list to cipherSuites and puts
   the length to cipherSuitesLen. It is the caller's responsibility
   to free the allocated buffer */
int32 getDefaultCipherSuites(ssl_t *ssl, psPool_t *pool,
                             unsigned char** cipherSuites,
                             psSize_t *cipherSuitesLen)
{
    if (ssl == NULL || cipherSuites == NULL ||
        cipherSuites == NULL || cipherSuitesLen == NULL)
    {
        return PS_ARG_FAIL;
    }
    *cipherSuitesLen = sslGetCipherSpecListLen(ssl);
    if (*cipherSuitesLen <= 0)
    {
        psTraceErrr("No enabled cipher suites\n");
        return PS_FAILURE;
    }
    if ((*cipherSuites = psMalloc(pool, *cipherSuitesLen)) == NULL)
    {
        return PS_MEM_FAIL;
    }
    /* Use default cipher suites */
    *cipherSuitesLen = sslGetCipherSpecList(ssl, *cipherSuites,
                                      *cipherSuitesLen,
                                      0);
    if (*cipherSuitesLen == 0)
    {
        return PS_FAILURE;
    }
    return PS_SUCCESS;
}

int32 getClientDefaultVersions(ssl_t *ssl)
{
#ifdef USE_TLS_1_3
    uint32_t j;
#endif

#ifdef USE_TLS
# ifndef DISABLE_TLS_1_0
    ssl->majVer = TLS_MAJ_VER;
    ssl->minVer = TLS_MIN_VER;
# endif
# if defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
    ssl->majVer = TLS_MAJ_VER;
    ssl->minVer = TLS_1_1_MIN_VER;
    ssl->flags |= SSL_FLAGS_TLS_1_1;
# endif     /* USE_TLS_1_1 */
# ifdef USE_TLS_1_2
    ssl->majVer = TLS_MAJ_VER;
    ssl->minVer = TLS_1_2_MIN_VER;
    ssl->flags |= SSL_FLAGS_TLS_1_2 | SSL_FLAGS_TLS_1_1;
# endif
# ifdef USE_TLS_1_3
    /* Set TLS1.3 as the highest priority but allow all others
     * as well. For now, add both the RFC and draft 28. */
    ssl->majVer = TLS_MAJ_VER;
    ssl->minVer = TLS_1_2_MIN_VER;

    j = 0;
    ssl->supportedVersionsLen = 0;

#define ADD_SUPPORTED_VER(ssl, maj, min)                \
    do                                                  \
    {                                                   \
        ssl->flags |= tlsMinVerToVersionFlag(min);      \
        ssl->supportedVersions[j++] = (maj << 8) | min; \
        ssl->supportedVersionsLen++;                    \
    } while(0)

    ADD_SUPPORTED_VER(ssl, TLS_MAJ_VER, TLS_1_3_MIN_VER);
    ADD_SUPPORTED_VER(ssl, TLS_1_3_DRAFT_MAJ_VER, TLS_1_3_DRAFT_28_MIN_VER);
    ADD_SUPPORTED_VER(ssl, TLS_MAJ_VER, TLS_1_2_MIN_VER);
#  if !defined(DISABLE_TLS_1_1)
    ADD_SUPPORTED_VER(ssl, TLS_MAJ_VER, TLS_1_1_MIN_VER);
#  endif
#  if !defined(DISABLE_TLS_1_0)
    ADD_SUPPORTED_VER(ssl, TLS_MAJ_VER, TLS_MIN_VER);
#  endif
# endif /* USE_TLS_1_3 */

    if (ssl->majVer == 0)
    {
        /* USE_TLS enabled but all DISABLE_TLS versions are enabled so
            use SSLv3.  Compile time tests would catch if no versions
            are enabled at all */
        ssl->majVer = SSL3_MAJ_VER;
        ssl->minVer = SSL3_MIN_VER;
    }
    else
    {
        ssl->flags |= SSL_FLAGS_TLS;
    }

# ifdef USE_DTLS
    /* ssl->flags will have already been set above.  Just set version */
    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        ssl->minVer = DTLS_MIN_VER;
        ssl->majVer = DTLS_MAJ_VER;
#  ifdef USE_TLS_1_2
        ssl->minVer = DTLS_1_2_MIN_VER;
#  endif
    }
# endif     /* USE_DTLS */

#else /* USE_TLS */
    ssl->majVer = SSL3_MAJ_VER;
    ssl->minVer = SSL3_MIN_VER;
#endif      /* USE_TLS */
    return MATRIXSSL_SUCCESS;
}

int32 getServerDefaultVersions(ssl_t *ssl)
{
    uint32_t j;
    j = 0;
    ssl->supportedVersionsLen = 0;
#ifdef USE_TLS_1_3
    /* For now, add both the RFC and draft 28.*/
    ssl->supportedVersions[j] = (TLS_MAJ_VER << 8) | TLS_1_3_MIN_VER;
    ssl->supportedVersionsLen++;
    j++;
    ssl->supportedVersions[j] = (TLS_1_3_DRAFT_MAJ_VER << 8) |
                                 TLS_1_3_DRAFT_28_MIN_VER;
    ssl->supportedVersionsLen++;
    j++;
#endif
#ifndef DISABLE_TLS_1_2
    ssl->supportedVersions[j] = (TLS_MAJ_VER << 8) |
                                 TLS_1_2_MIN_VER;
    ssl->supportedVersionsLen++;
    j++;
#endif
#ifndef DISABLE_TLS_1_1
    ssl->supportedVersions[j] = (TLS_MAJ_VER << 8) |
                                 TLS_1_1_MIN_VER;
    ssl->supportedVersionsLen++;
    j++;
#endif
#ifndef DISABLE_TLS_1_0
    ssl->supportedVersions[j] = (TLS_MAJ_VER << 8) |
                                 TLS_MIN_VER;
    ssl->supportedVersionsLen++;
    j++;
#endif
    return MATRIXSSL_SUCCESS;
}
