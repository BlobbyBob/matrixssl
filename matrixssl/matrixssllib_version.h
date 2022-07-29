/**
 *      @file    matrixssllib_version.h
 *      @version $Format:%h%d$
 *
 *      Internal header file used for the MatrixSSL implementation.
 *      Only modifiers of the library should be intersted in this file.
 *      This file contains protocol version related macros and constants.
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

#ifndef _h_MATRIXSSLLIB_VERSION
# define _h_MATRIXSSLLIB_VERSION

/*
  Note: psProtocolVersion_t values are defined in matrixsslApi.h.

  Note: we could store all version lists as a single variable. But
  typically the version lists imply priority order. There is no easy
  way to store priority order in a flag variable.
*/

/* Convert from MatrixSSL internal ID to official on-the-wire ID */
# define ENCODE_VER(ver) ( ver ## _enc )
# define ENCODE_MIN_VER(ver) ( ver ## _enc & 0xff )
# define ENCODE_MAJ_VER(ver) (( ver ## _enc & 0xff00 ) >> 8)
uint16_t psEncodeVersion(psProtocolVersion_t ver);
uint8_t psEncodeVersionMin(psProtocolVersion_t ver);
uint8_t psEncodeVersionMaj(psProtocolVersion_t ver);

/* Convert from official on-the-wire ID to MatrixSSL internal ID. */
psProtocolVersion_t psVerFromEncoding(uint16_t enc);
psProtocolVersion_t psVerFromEncodingMajMin(uint8_t maj, uint8_t min);
# define VER_FROM_ENC(enc) psVerFromEncoding(enc))

/*
  Note: the following conversion macros are typically called from only
  one function in the code, so code duplication is not an issue.
  We define the macros here, so that all version ID stuff is in the
  same place. This makes e.g. adding new versions easier in the future.
*/

/* Get raw version identifier without attributes. */
# define VER_GET_RAW(ver)                       \
    ((ver) & 0x00ffffff)

/* Is version a less (i.e. earlier) than version b? */
# define VER_LT(a, b) ((VER_GET_RAW(a) < VER_GET_RAW(b)))

/* Is version a greater (i.e. later) than version b? */
# define VER_GT(a, b) ((VER_GET_RAW(a) > VER_GET_RAW(b)))

/** Return the lowest version enabled in ver. */
psProtocolVersion_t psVerGetLowest(psProtocolVersion_t ver, int allowDtls);
psProtocolVersion_t psVerGetLowestTls(psProtocolVersion_t ver);

/** Return the highest version enabled in ver. */
psProtocolVersion_t psVerGetHighest(psProtocolVersion_t ver, int allowDtls);
psProtocolVersion_t psVerGetHighestTls(psProtocolVersion_t ver);

/** Convert from the example client/server command line version ID
    to MatrixSSL internal ID. */
# define DIGIT_TO_VER(ver)                                              \
    (ver == 1) ? v_tls_1_0 :                                            \
    (ver == 2) ? v_tls_1_1 :                                            \
    (ver == 3) ? v_tls_1_2 :                                            \
    (ver == 4) ? v_tls_1_3 :                                            \
    (ver == 22) ? v_tls_1_3_draft_22 :                                  \
    (ver == 23) ? v_tls_1_3_draft_23 :                                  \
    (ver == 24) ? v_tls_1_3_draft_24 :                                  \
    (ver == 26) ? v_tls_1_3_draft_26 :                                  \
    (ver == 28) ? v_tls_1_3_draft_28 :                                  \
    v_undefined

/* Convert from MatrixSSL internal ID to string. */
# define VER_TO_STR(ver)                                                \
    (ver == v_undefined) ? "undefined" :                            \
    (ver == v_ssl_3_0) ? "SSL 3.0" :                                    \
    (ver == v_tls_1_0) ? "TLS 1.0" :                                    \
    (ver == v_tls_1_1) ? "TLS 1.1" :                                    \
    (ver == v_tls_1_2) ? "TLS 1.2" :                                    \
    (ver == v_tls_1_3) ? "TLS 1.3" :                                    \
    (ver == v_tls_1_3_draft_22) ? "TLS 1.3 draft 22" :                  \
    (ver == v_tls_1_3_draft_23) ? "TLS 1.3 draft 23" :                  \
    (ver == v_tls_1_3_draft_24) ? "TLS 1.3 draft 24" :                  \
    (ver == v_tls_1_3_draft_26) ? "TLS 1.3 draft 26" :                  \
    (ver == v_tls_1_3_draft_28) ? "TLS 1.3 draft 28" :                  \
    (ver == v_dtls_1_0) ? "DTLS 1.0" :                                  \
    (ver == v_dtls_1_2) ? "DTLS 1.2" :                                  \
    "unknown/unsupported version identifier"

/** Convert from official version ID to string. */
# define ENCODED_VER_TO_STR(ver)                                        \
    (ver == v_undefined_enc) ? "undefined" :                        \
    (ver == v_ssl_3_0_enc) ? "SSL 3.0" :                                \
    (ver == v_tls_1_0_enc) ? "TLS 1.0" :                                \
    (ver == v_tls_1_1_enc) ? "TLS 1.1" :                                \
    (ver == v_tls_1_2_enc) ? "TLS 1.2" :                                \
    (ver == v_tls_1_3_enc) ? "TLS 1.3" :                                \
    (ver == v_tls_1_3_draft_22_enc) ? "TLS 1.3 draft 22" :              \
    (ver == v_tls_1_3_draft_23_enc) ? "TLS 1.3 draft 23" :              \
    (ver == v_tls_1_3_draft_24_enc) ? "TLS 1.3 draft 24" :              \
    (ver == v_tls_1_3_draft_26_enc) ? "TLS 1.3 draft 26" :              \
    (ver == v_tls_1_3_draft_28_enc) ? "TLS 1.3 draft 28" :              \
    (ver == v_dtls_1_0_enc) ? "DTLS 1.0" :                              \
    (ver == v_dtls_1_2_enc) ? "DTLS 1.2" :                              \
    "unknown/unsupported version encoding"

/** Convert from MatrixSSL internal ID to (deprecated) version flag. */
int32_t psVerToFlag(psProtocolVersion_t ver);
# define VER_TO_FLAG(ver) \
    (psVerToFlag(ver))

/** Convert from (deprecated) version flag values to intenal ID. */
psProtocolVersion_t psFlagToVer(int32_t flag);
# define FLAG_TO_VER(flag) \
    (psFlagToVer(flag))

/** Is "ver" supported by the build-time configuration? */
# define VER_SUPPORTED_BY_BUILD(ver) \
    ((ver) & v_compiled_in)
# define COMPILED_IN_VER(ver) \
    VER_SUPPORTED_BY_BUILD(ver)

/** Setters and getters. All access to variables of type psProtocolVersion_t
    should be via these.

    The ones that print out a message look like they could produce some
    unnecessary code duplication. But psTrace* only produces code when
    tracing is enabled, which is probably not the case in a footprint-critical
    environment. */
# define ADD_VER(var, ver) \
    ((var) |= (ver))
# define SET_ACTV_VER(ssl, ver)                                         \
    do                                                                  \
    {                                                                   \
        (ssl)->activeVersion = (ver);                                   \
        psTracePrintProtocolVersionNew(0,                               \
                MATRIX_IS_SERVER(ssl) ? "Server activated" : "Client activated", \
                (ssl)->activeVersion,                                   \
                PS_TRUE);                                               \
    }                                                                   \
    while (0)
# define SET_NGTD_VER(ssl, ver)                                         \
    do                                                                  \
    {                                                                   \
        ((ssl)->activeVersion = ((ver) | v_tls_negotiated));            \
        psTracePrintProtocolVersionNew(0,                               \
                MATRIX_IS_SERVER(ssl) ? "Server negotiated" : "Client negotiated", \
                (ssl)->activeVersion,                                   \
             PS_TRUE);                                                  \
    }                                                                   \
    while (0)
# define RESET_NGTD_VER(ssl)                                            \
    do                                                                  \
    {                                                                   \
        ((ssl)->activeVersion = ((ssl)->activeVersion & ~v_tls_negotiated)); \
        psTracePrintProtocolVersionNew(0,                               \
                MATRIX_IS_SERVER(ssl) ? "Server unnegotiated" : "Client unnegotiated", \
                (ssl)->activeVersion,                                   \
                PS_TRUE);                                               \
    }                                                                   \
    while (0)
# define RESET_ACTV_VER(ssl)                                            \
    do                                                                  \
    {                                                                   \
        psTracePrintProtocolVersionNew(0,                               \
                MATRIX_IS_SERVER(ssl) ? "Server deactivated" : "Client deactivated", \
                (ssl)->activeVersion,                                   \
                PS_TRUE);                                               \
        (ssl)->activeVersion = v_undefined;                         \
    }                                                                   \
    while (0)

# define SET_SUPP_VER(ssl, ver) \
    ((ssl)->supportedVersions = (ver))
# define ADD_SUPP_VER(ssl, ver) \
    ADD_VER((ssl)->supportedVersions, ver)
# define ADD_SUPP_VER_PRIORITY(ssl, ver) \
    ((ssl)->supportedVersionsPriority[(ssl)->supportedVersionsPriorityLen++] = (ver))

# define GET_NGTD_VER(ssl) \
    ((ssl)->activeVersion)
# define GET_ACTV_VER(ssl) \
    ((ssl)->activeVersion)
# define GET_SUPP_VER(ssl) \
    ((ssl)->supportedVersions)

# ifdef USE_TLS_1_3
# define ADD_PEER_SUPP_VER(ssl, ver) \
    ((ssl)->supportedVersionsPeer |= (ver))
# define ADD_PEER_SUPP_VER_PRIORITY(ssl, ver) \
    ((ssl)->peerSupportedVersionsPriority[(ssl)->peerSupportedVersionsPriorityLen++] = (ver))
# define GET_PEER_SUPP_VER(ssl) \
    ((ssl)->supportedVersionsPeer)
# endif /* USE_TLS_1_3 */

/* Is "ver" supported by us? */
#  define SUPP_VER(ssl, ver) ((ssl)->supportedVersions & (ver))

# ifdef USE_TLS_1_3
/* Is "ver" supported by the peer? */
#  define PEER_SUPP_VER(ssl, ver) ((ssl)->supportedVersionsPeer & (ver))
# endif

/* Is "ver" the active version (the spec we are complying with, but
   which we may not have negotiated yet with the peer)? */
#  define ACTV_VER(ssl, ver) \
    ((ssl)->activeVersion & (ver))

/* Has version negotiation completed succesfully? */
#  define NGTD(ssl) \
    ((ssl)->activeVersion & v_tls_negotiated)

#  define VersionNegotiationComplete(ssl) \
        NGTD(ssl)

/* Has "ver" been succesfully negotiated with the peer? */
#  define NGTD_VER(ssl, ver) \
    (ACTV_VER(ssl,ver) && ((ssl)->activeVersion & v_tls_negotiated))

# define USING_TLS_1_2(ssl) \
    (ACTV_VER(ssl, v_tls_1_2)) ? PS_TRUE : PS_FALSE)
#  define USING_TLS_1_3(ssl) \
    (ACTV_VER(ssl, v_tls_1_3_any) ? PS_TRUE : PS_FALSE)
#  define USING_ONLY_TLS_1_3(ssl) \
    (GET_ACTV_VER(ssl) == v_tls_1_3)

/*
  Does the currently active TLS 1.3 version use AAD?

  Note that we don't require the version to be negotiated yet.
  This is because we may be trying to encrypt early data using
  a PSK-derived key. The PSK may not necessarily have associated
  version information and even if it did, we do not store the draft
  version.
*/
#  define USING_TLS_1_3_AAD(SSL) ((SSL)->activeVersion & v_tls_1_3_aad)

/*
  Convenience macros for min and max version from build-time config.
  Note that these map to MatrixSSL's internal version identifiers,
  i.e. to v_tls_*.
*/
# if defined(USE_TLS_1_3) && !defined(DISABLE_TLS_1_3)
#  define MAX_ENABLED_TLS_VER v_tls_1_3
#  define MIN_ENABLED_TLS_1_3_DRAFT_VERSION v_tls_1_3_draft_23
#  define MAX_ENABLED_TLS_1_3_DRAFT_VERSION v_tls_1_3_draft_28
# elif defined(USE_TLS_1_2) && !defined(DISABLE_TLS_1_2)
#  define MAX_ENABLED_TLS_VER v_tls_1_2
# elif defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
#  define MAX_ENABLED_TLS_VER v_tls_1_1
# elif defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
#  define MAX_ENABLED_TLS_VER v_tls_1_0
# elif !defined(DISABLE_SSLV3)
#  define MAX_ENABLED_TLS_VER v_ssl_3_0
# endif

# if !defined(DISABLE_SSLV3)
#  define MIN_ENABLED_TLS_VER v_ssl_3_0
# elif defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
#  define MIN_ENABLED_TLS_VER v_tls_1_0
# elif defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
#  define MIN_ENABLED_TLS_VER v_tls_1_1
# elif defined(USE_TLS_1_2) && !defined(DISABLE_TLS_1_2)
#  define MIN_ENABLED_TLS_VER v_tls_1_2
# elif defined(USE_TLS_1_3) && !defined(DISABLE_TLS_1_3)
#  define MIN_ENABLED_TLS_VER MIN_ENABLED_TLS_1_3_DRAFT_VERSION
# endif

/** Version flags can still be used to select the versions to support.
    This is deprecated, but still allowed in order not to break
    backwards compatibility. The version flags are translated to
    MatrixSSL internal IDs during session configuration. */
/** Any version flag. */
# ifdef USE_TLS_1_3_DRAFT_SPEC
#  define ANY_VERSION_FLAG                      \
    (SSL_FLAGS_TLS_1_0                          \
            | SSL_FLAGS_TLS_1_1                 \
            | SSL_FLAGS_TLS_1_2                 \
            | SSL_FLAGS_TLS_1_3                 \
            | SSL_FLAGS_TLS_1_3_DRAFT_22        \
            | SSL_FLAGS_TLS_1_3_DRAFT_23        \
            | SSL_FLAGS_TLS_1_3_DRAFT_24        \
            | SSL_FLAGS_TLS_1_3_DRAFT_26        \
            | SSL_FLAGS_TLS_1_3_DRAFT_28        \
            | SSL_FLAGS_DTLS)
# else
#  define ANY_VERSION_FLAG                      \
    (SSL_FLAGS_TLS_1_0                          \
            | SSL_FLAGS_TLS_1_1                 \
            | SSL_FLAGS_TLS_1_2                 \
            | SSL_FLAGS_TLS_1_3                 \
            | SSL_FLAGS_DTLS)
# endif
#endif /* _h_MATRIXSSLLIB_VERSION */
