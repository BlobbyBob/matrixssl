/**
 *      @file    hsNegotiateVersion.c
 *      @version $Format:%h%d$
 *
 *      Functions for SSL/TLS version negotiation. Some of this code was
 *      originally in hsDecode.c
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

#include "matrixsslImpl.h"

int32_t checkClientHelloVersion(ssl_t *ssl,
                                unsigned char *serverHighestMinor)
{
    unsigned char compareMin, compareMaj;

# ifndef USE_SSL_PROTOCOL_VERSIONS_OTHER_THAN_3
    /* RFC 5246 Suggests to accept all RSA minor versions, but only
       major version 0x03 (SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3 etc) */
    if (ssl->reqMajVer != 0x03
#  ifdef USE_DTLS
        && ssl->reqMajVer != DTLS_MAJ_VER
#  endif /* USE_DTLS */
        )
    {
        /* Consider invalid major version protocol version error. */
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTraceErrr("Won't support client's SSL major version\n");
        return MATRIXSSL_ERROR;
    }
# endif /* USE_SSL_PROTOCOL_VERSIONS_OTHER_THAN_3 */

    /*  Client should always be sending highest supported protocol.  Server
        will reply with a match or a lower version if enabled (or forced). */
    if (ssl->majVer != 0)
    {
        /* If our forced server version is a later protocol than their
            request, we have to exit */
        if (ssl->reqMinVer < ssl->minVer)
        {
            ssl->err = SSL_ALERT_PROTOCOL_VERSION;
            psTraceErrr("Won't support client's SSL version\n");
            return MATRIXSSL_ERROR;
        }
# ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            /* DTLS specfication somehow assigned minimum version of DTLS 1.0
                as 255 so there was nowhere to go but down in DTLS 1.1 so
                that is 253 and requires the opposite test from above */
            if (ssl->reqMinVer > ssl->minVer)
            {
                ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                psTraceErrr("Won't support client's DTLS version\n");
                return MATRIXSSL_ERROR;
            }
        }
# endif
        /* Otherwise we just set our forced version to act like it was
            what the client wanted in order to move through the standard
            negotiation. */
        compareMin = ssl->minVer;
        compareMaj = ssl->majVer;
        /* Set the highest version to the version explicitly set */
        *serverHighestMinor = ssl->minVer;
    }
    else
    {
        compareMin = ssl->reqMinVer;
        compareMaj = ssl->reqMajVer;
        /* If no explicit version was set for the server, use the highest supported */
        *serverHighestMinor = TLS_HIGHEST_MINOR;
    }

    if (compareMaj >= SSL3_MAJ_VER)
    {
        ssl->majVer = compareMaj;
# ifdef USE_TLS
        if (compareMin >= TLS_MIN_VER)
        {
#  ifndef DISABLE_TLS_1_0
            /* Allow TLS 1.0, unless specifically disabled. */
            if (tlsVersionSupported(ssl, tls_v_1_0))
            {
                ssl->minVer = TLS_MIN_VER;
                ssl->flags |= SSL_FLAGS_TLS;
            }
#  endif
#  ifdef USE_TLS_1_1 /* TLS_1_1 */
#   ifdef USE_TLS_1_1_TOGGLE
            if (tlsVersionSupported(ssl, tls_v_1_1))
            {
#   endif
                if (compareMin >= TLS_1_1_MIN_VER)
                {
#   ifndef DISABLE_TLS_1_1
                    ssl->minVer = TLS_1_1_MIN_VER;
                    ssl->flags |= SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS;
#   endif
                }
#   ifdef USE_TLS_1_1_TOGGLE
            }
#   endif
#   ifdef USE_TLS_1_2
#    ifdef USE_TLS_1_2_TOGGLE
            /* Prefer TLS 1.2, unless specifically disabled. */
            if (tlsVersionSupported(ssl, tls_v_1_2))
            {
#    endif /* USE_TLS_1_2_TOGGLE */
                if (compareMin == TLS_1_2_MIN_VER)
                {
                    ssl->minVer = TLS_1_2_MIN_VER;
                    ssl->flags |= SSL_FLAGS_TLS_1_2 | SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS;
                }
#    ifdef USE_TLS_1_2_TOGGLE
            }
#    endif /* USE_TLS_1_2_TOGGLE */
#    ifdef USE_DTLS
            if (ssl->flags & SSL_FLAGS_DTLS)
            {
                if (compareMin == DTLS_1_2_MIN_VER)
                {
                    ssl->minVer = DTLS_1_2_MIN_VER;
                }
            }
#    endif
#   endif /* USE_TLS_1_2 */
#  endif  /* USE_TLS_1_1 */
            if (ssl->minVer == 0)
            {
                /* TLS versions are disabled.  Go SSLv3 if available. */
#  ifdef DISABLE_SSLV3
                ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                return MATRIXSSL_ERROR;
#  else
                ssl->minVer = SSL3_MIN_VER;
#  endif
            }
        }
        else if (compareMin == 0)
        {
#  ifdef DISABLE_SSLV3
            ssl->err = SSL_ALERT_PROTOCOL_VERSION;
            psTraceErrr("Client wanted to talk SSLv3 but it's disabled\n");
            return MATRIXSSL_ERROR;
#  else
            ssl->minVer = SSL3_MIN_VER;
#  endif    /* DISABLE_SSLV3 */
        }
#  ifdef USE_DTLS
        if (ssl->flags & SSL_FLAGS_DTLS)
        {
            if (compareMin < DTLS_1_2_MIN_VER)
            {
                ssl->err = SSL_ALERT_PROTOCOL_VERSION;
                psTraceErrr("Error: incorrect DTLS required version\n");
                return MATRIXSSL_ERROR;
            }
            ssl->minVer = DTLS_MIN_VER;
#   ifdef USE_TLS_1_2
#    ifdef USE_TLS_1_2_TOGGLE
            /* Prefer TLS 1.2, unless specifically disabled. */
            if (tlsVersionSupported(ssl, tls_v_1_2))
            {
#    endif /* USE_TLS_1_2_TOGGLE */
                if (compareMin == DTLS_1_2_MIN_VER)
                {
                    ssl->flags |= SSL_FLAGS_TLS_1_2 | SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS;
                    ssl->minVer = DTLS_1_2_MIN_VER;
                }
#    ifdef USE_TLS_1_2_TOGGLE
            }
#    endif /* USE_TLS_1_2_TOGGLE */
#    ifdef USE_DTLS
            if (ssl->flags & SSL_FLAGS_DTLS)
            {
                if (compareMin == DTLS_1_2_MIN_VER)
                {
                    ssl->minVer = DTLS_1_2_MIN_VER;
                }
            }
#    endif /* USE_DTLS */
#   endif  /* USE_TLS_1_2 */

        }
#  endif /* USE_DTLS */
# else
        ssl->minVer = SSL3_MIN_VER;

# endif /* USE_TLS */

    }
    else
    {
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTraceIntInfo("Unsupported ssl version: %d\n", compareMaj);
        return MATRIXSSL_ERROR;
    }

    return PS_SUCCESS;
}

# ifndef DISABLE_SSLV3
int32_t ssl3CheckServerHelloVersion(ssl_t *ssl)
{
    psAssert(ssl->reqMajVer == SSL3_MAJ_VER);

    /*  Server minVer now becomes OUR initial requested version.
        This is used during the creation of the premaster where
        this initial requested version is part of the calculation.
        The RFC actually says to use the original requested version
        but no implemenations seem to follow that and just use the
        agreed upon one. */
    ssl->reqMinVer = ssl->minVer;
    ssl->minVer = SSL3_MIN_VER;
    ssl->flags &= ~SSL_FLAGS_TLS;
#   ifdef USE_TLS_1_1
    ssl->flags &= ~SSL_FLAGS_TLS_1_1;
#   endif   /* USE_TLS_1_1 */
#   ifdef USE_TLS_1_2
    ssl->flags &= ~SSL_FLAGS_TLS_1_2;
#   endif /* USE_TLS_1_2 */
}
# endif  /* DISABLE_SSLV3 */

# ifdef USE_TLS
int32_t tlsCheckServerHelloVersion(ssl_t *ssl)
{
    psAssert(ssl->reqMajVer == TLS_MAJ_VER);

    if (ssl->reqMinVer == ssl->minVer)
    {
        return MATRIXSSL_SUCCESS;
    }
    else
    {
        /* Server is trying to change (downgrade) the protocol version. */
        /* Check if the requested version is in the supported
           version list. */
        if (!tlsVersionSupported(ssl, ssl->reqMinVer))
        {
            ssl->err = SSL_ALERT_PROTOCOL_VERSION;
            psTraceErrr("Error: version downgrade attempt by server" \
                    " rejected:\nServerHello.server_version <" \
                    " ClientHello.client_version\n");
            return MATRIXSSL_ERROR;
        }

        /* At this point we know that we support the requested version. */
#  ifdef USE_TLS_1_2
        if (ssl->reqMinVer == TLS_1_2_MIN_VER)
        {
            ssl->reqMinVer = ssl->minVer;
            ssl->minVer = TLS_1_2_MIN_VER;
            ssl->flags &= ~SSL_FLAGS_TLS_1_1;
            return MATRIXSSL_SUCCESS;
        }
#  endif /* USE_TLS_1_2 */
#  if defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
        else if (ssl->reqMinVer == TLS_1_1_MIN_VER)
        {
            ssl->reqMinVer = ssl->minVer;
            ssl->minVer = TLS_1_1_MIN_VER;
            ssl->flags &= ~SSL_FLAGS_TLS_1_2;
            return MATRIXSSL_SUCCESS;
        }
#  endif /* USE_TLS_1_1 && !DISABLE_TLS_1_1*/
#  ifndef DISABLE_TLS_1_0
        else if (ssl->reqMinVer == TLS_MIN_VER)
        {
            ssl->reqMinVer = ssl->minVer;
            ssl->minVer = TLS_MIN_VER;
            ssl->flags &= ~SSL_FLAGS_TLS_1_2;
            ssl->flags &= ~SSL_FLAGS_TLS_1_1;
            return MATRIXSSL_SUCCESS;
        }
#  endif /* DISABLE_TLS_1_0 */
        else
        {
            return MATRIXSSL_ERROR;
        }
    }
}
#endif /* USE_TLS */

#ifdef USE_DTLS
int32_t dtlsCheckServerHelloVersion(ssl_t *ssl)
{
    psAssert(ssl->reqMajVer == DTLS_MAJ_VER);

    if (ssl->flags & SSL_FLAGS_DTLS)
    {
        if (ssl->reqMinVer == DTLS_MIN_VER &&
                ssl->minVer == DTLS_1_2_MIN_VER)
        {
            ssl->reqMinVer = ssl->minVer;
            ssl->minVer = DTLS_MIN_VER;
            ssl->flags &= ~SSL_FLAGS_TLS_1_2;
            return MATRIXSSL_SUCCESS;
        }
    }

    return MATRIXSSL_ERROR;
}
#endif /* USE_DTLS */

/** Check whether the protocol version selected by the server can
    be supported for this handshake.

    @precond: ssl->reqMajVer, ssl->reqMinVer contains the version parsed
    from ServerHello.server_version (called ServerHello.legacy_version
    in TLS 1.3).
*/
int32_t checkServerHelloVersion(ssl_t *ssl)
{
    int32_t rc = MATRIXSSL_ERROR;

    /* Check that we have a common major version. For example,
       do not allow the server to select DTLS when we tried to
       connect using TLS. */
    if (ssl->reqMajVer != ssl->majVer)
    {
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTraceIntInfo("Unsupported ssl version: %d\n", ssl->reqMajVer);
        return MATRIXSSL_ERROR;
    }

    /* Easy case: server chose our preferred version. */
    if (ssl->reqMinVer == ssl->minVer)
    {
        return MATRIXSSL_SUCCESS;
    }

    /* Now handle downgrades. */
    switch(ssl->reqMajVer)
    {
# ifdef USE_TLS
    case TLS_MAJ_VER:
        rc = tlsCheckServerHelloVersion(ssl);
        break;
# endif
# ifdef USE_DTLS
    case DTLS_MAJ_VER:
        rc = dtlsCheckServerHelloVersion(ssl);
        break;
# endif
    default:
        rc = MATRIXSSL_ERROR;
    }

 # ifndef DISABLE_SSLV3
    if (rc != MATRIXSSL_SUCCESS
            && ssl->reqMinVer == SSL3_MIN_VER
            && ssl->minVer >= TLS_MIN_VER)
    {
        rc = sslv3CheckServerHelloVersion(ssl);
    }
# endif /* !DISABLE_SSLV3 */

    if (rc != MATRIXSSL_SUCCESS)
    {
        /* Wasn't able to settle on a common protocol */
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTracePrintProtocolVersion(INDENT_HS_MSG,
                "Unsupported protocol version",
                ssl->reqMajVer, ssl->reqMinVer, PS_TRUE);
        return MATRIXSSL_ERROR;
    }

    return MATRIXSSL_SUCCESS;
}

# ifdef USE_TLS_1_3
int32_t checkSupportedVersions(ssl_t *ssl)
{
    int32 rc;
    uint16_t selectedVersion = 0;
    uint16_t forbiddenVer[16] = {0};
    psSize_t forbiddenVerLen = 0;
    psSize_t i = 0;

    if (!ssl->gotTls13CiphersuiteInCH)
    {
        /* Forbid TLS 1.3 if the client did not provide any TLS 1.3
           ciphersuites. */
        forbiddenVer[i++] = TLS_1_3_DRAFT_22_VER;
        forbiddenVer[i++] = TLS_1_3_DRAFT_23_VER;
        forbiddenVer[i++] = TLS_1_3_DRAFT_24_VER;
        forbiddenVer[i++] = TLS_1_3_DRAFT_26_VER;
        forbiddenVer[i++] = TLS_1_3_DRAFT_28_VER;
        forbiddenVer[i++] = TLS_1_3_VER;
        forbiddenVerLen = i;
    }

    /* Choose version from the intersection of our and the client's
       version list. */
    rc = tls13IntersectionPrioritySelect(ssl->supportedVersions,
            ssl->supportedVersionsLen,
            ssl->tls13PeerSupportedVersions,
            ssl->tls13PeerSupportedVersionsLen,
            forbiddenVer,
            forbiddenVerLen,
            &selectedVersion);
    if (rc < 0)
    {
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        psTraceErrr("Could not find common protocol version\n");
        return MATRIXSSL_ERROR;
    }

    switch (selectedVersion & 0xff)
    {
        case TLS_1_0_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_0_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_0;
            break;
        case TLS_1_1_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_1_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_1;
            break;
        case TLS_1_2_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_2_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_2;
            break;
        case TLS_1_3_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_2_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_3 |
                          SSL_FLAGS_TLS_1_3_NEGOTIATED;
            ssl->tls13NegotiatedMinorVer = selectedVersion & 0xff;
            break;
        case TLS_1_3_DRAFT_22_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_2_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_3_DRAFT_22 |
                          SSL_FLAGS_TLS_1_3_NEGOTIATED;
            ssl->tls13NegotiatedMinorVer = selectedVersion & 0xff;
            break;
        case TLS_1_3_DRAFT_23_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_2_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_3_DRAFT_23 |
                          SSL_FLAGS_TLS_1_3_NEGOTIATED;
            ssl->tls13NegotiatedMinorVer = selectedVersion & 0xff;
            break;
        case TLS_1_3_DRAFT_24_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_2_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_3_DRAFT_24 |
                          SSL_FLAGS_TLS_1_3_NEGOTIATED;
            ssl->tls13NegotiatedMinorVer = selectedVersion & 0xff;
            break;
        case TLS_1_3_DRAFT_26_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_2_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_3_DRAFT_26 |
                          SSL_FLAGS_TLS_1_3_NEGOTIATED;
            ssl->tls13NegotiatedMinorVer = selectedVersion & 0xff;
            break;
        case TLS_1_3_DRAFT_28_MIN_VER:
            ssl->majVer = TLS_MAJ_VER;
            ssl->minVer = TLS_1_2_MIN_VER;
            ssl->flags |= SSL_FLAGS_TLS_1_3_DRAFT_28 |
                          SSL_FLAGS_TLS_1_3_NEGOTIATED;
            ssl->tls13NegotiatedMinorVer = selectedVersion & 0xff;
            break;
        default:
            ssl->err = SSL_ALERT_PROTOCOL_VERSION;
            psTraceErrr("Unsupported protocol version\n");
            return MATRIXSSL_ERROR;
    }

    return PS_SUCCESS;
}

/* Check the TLS 1.3 downgrade protection mechanism. */
int32_t performTls13DowngradeCheck(ssl_t *ssl)
{
    if (weOnlySupportTls13(ssl))
    {
        /* Don't allow the server to downgrade to an earlier version
           if we only support 1.3. This check is needed, because the
           legacy_version check above (checkServerHelloVersion) only
           works if not using TLS 1.3. */
        psTraceErrr("Server downgrade to earlier proto version " \
                "rejected: we only support TLS 1.3\n");
        ssl->err = SSL_ALERT_PROTOCOL_VERSION;
        return MATRIXSSL_ERROR;
    }

    if (tlsVersionSupported(ssl, TLS_1_3_MIN_VER))
    {
        /* TLS 1.3 downgrade protection: if we support (non-draft)
           TLS 1.3 and the server chose <1.3, check that the last 8
           bytes of server_random do NOT contain a special value used by
           the server to indicate that it also supports TLS 1.3. */
        if (!Memcmp(ssl->sec.serverRandom + 24,
                        TLS13_DOWNGRADE_PROT_TLS12, 8) ||
                !Memcmp(ssl->sec.serverRandom + 24,
                        TLS13_DOWNGRADE_PROT_TLS11_OR_BELOW, 8))
        {
            psTraceErrr("Server downgrade to earlier proto version " \
                    "rejected: both parties support TLS 1.3\n");
            ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
            return MATRIXSSL_ERROR;
        }
    }

    return MATRIXSSL_SUCCESS;
}
#endif /* USE_TLS_1_3 */
/* end of file hsNegotiateVersion.c */
