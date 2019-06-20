/**
 *      @file    matrixsslApiVer.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      This sub-header of matrixsslApi.h contains protocol version related
 *      defines.
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

#ifndef _h_MATRIXSSL_API_VER
# define _h_MATRIXSSL_API_VER

/**
    - USE_TLS versions must 'stack' for compiling purposes
        - must enable TLS if enabling TLS 1.1
        - must enable TLS 1.1 if enabling TLS 1.2
      However, TLS 1.3 can be enabled without the earlier versions by using
      defining USE_TLS_1_3_ONLY.

    - Use the DISABLE_TLS_ defines to disallow specific protocols at runtime
        that have been enabled via USE_TLS_.

    The USE_TLS_1_x_AND_ABOVE simplifies this configuration.
    @security To enable SSL3.0, see below.
 */
# define USE_TLS        /**< DO NOT DISABLE @security NIST_MAY */
# define USE_TLS_1_1    /**< DO NOT DISABLE @security NIST_SHALL */
# define USE_TLS_1_2    /**< DO NOT DISABLE @security NIST_SHOULD */
# define DISABLE_SSLV3  /**< DO NOT DISABLE, undef below if required
                           @security NIST_SHALL_NOT */

#  if defined USE_TLS_1_3_ONLY
#    define USE_TLS_1_3
#    undef USE_TLS_1_2
#    undef USE_TLS_1_1
#    undef USE_TLS
#    define DISABLE_TLS_1_2
#    define DISABLE_TLS_1_1
#    define DISABLE_TLS_1_0
#  elif defined USE_TLS_1_2_AND_ABOVE
#   ifndef DISABLE_TLS_1_3
#    define USE_TLS_1_3
#   endif
#   define USE_TLS_1_2
#   define DISABLE_TLS_1_1
#   define DISABLE_TLS_1_0
#  elif defined USE_TLS_1_1_AND_ABOVE
#    ifndef DISABLE_TLS_1_3
#   define USE_TLS_1_3
#    endif
#   define USE_TLS_1_2
#   define DISABLE_TLS_1_0
#  elif defined USE_TLS_1_0_AND_ABOVE
#    ifndef DISABLE_TLS_1_3
#     define USE_TLS_1_3
#    endif
#   define USE_TLS_1_2
#   define USE_TLS_1_1
/** @security undef DISABLE_SSLV3 here if required */
#  else
#   error Must define USE_TLS_1_x_AND_ABOVE
#  endif

/* Type used for storing protocol versions. */
typedef uint32_t psProtocolVersion_t;

/* Official on-the-wire version identifiers. */
enum PACKED
{
    v_undefined_enc = 0,
    v_ssl_3_0_enc = 0x0300,
    v_tls_1_0_enc = 0x0301,
    v_tls_1_1_enc = 0x0302,
    v_tls_1_2_enc = 0x0303,
    v_tls_1_3_enc = 0x0304,
    v_tls_1_3_draft_22_enc = 0x7f16,
    v_tls_1_3_draft_23_enc = 0x7f17,
    v_tls_1_3_draft_24_enc = 0x7f18,
    v_tls_1_3_draft_26_enc = 0x7f1a,
    v_tls_1_3_draft_28_enc = 0x7f1c,
    v_dtls_1_0_enc = 0xfeff,
    v_dtls_1_2_enc = 0xfefd
};

/** A version v can be either:
    1. Supported by the compile-time config
    --> if (v & v_compiled_in)
    2. Supported for the current connection
    --> if (SUPP_VER(ssl, v))
    3. The active version
    --> if (ACTV_VER(ssl, v))
    4. The negotiated version
    --> if (NGTD_VER(ssl, v))

    An activated version is the version we are currently following.
    This affects e.g. the format of our ClientHello, whether or not
    to allow sending early data, and whether to expect the peer's
    hello message to have TLS or DTLS style record headers.

    An active version becomes negotiated when we have sufficient
    information from the peer to know that it also supports the
    version.
*/

/** Bits 0 to 23 are reserved for versions. */
#define VER_MAX_BIT 23

/** Bits 24 to 31 are reserved for version attributes. */
#define VER_ATTRIB_MAX_BIT 31

/* MatrixSSL's internal protocol version identifiers. */
enum PACKED
{
    v_undefined = 0,

    /** Versions. The ordering of the numeric values of the enumerators
        MUST correspond to the chronological order in which the
        protocol specifications were published, for example:
        v_tls_1_1 < v_tls_1_2. This affects e.g. the default
        priority order. */
    v_ssl_3_0 = 1ULL << 0,
    v_tls_1_0 = 1ULL << 1,
    v_tls_1_1 = 1ULL << 2,
    v_dtls_1_0 = 1ULL << 3,
    v_tls_1_2 = 1ULL << 4,
    v_dtls_1_2 = 1ULL << 5,
    v_tls_1_3_draft_22 = 1ULL << 6,
    v_tls_1_3_draft_23 = 1ULL << 7,
    v_tls_1_3_draft_24 = 1ULL << 8,
    v_tls_1_3_draft_26 = 1ULL << 9,
    v_tls_1_3_draft_28 = 1ULL << 10,
    v_tls_1_3 = 1ULL << 11,

    /** Version attributes. */
    v_tls_negotiated = 1ULL << 24, /* Version negotiation complete? */

    /** Version combinations. */

    /** Any supported TLS 1.3 draft version. */
    v_tls_1_3_draft_any = (v_tls_1_3_draft_22
            | v_tls_1_3_draft_23
            | v_tls_1_3_draft_24
            | v_tls_1_3_draft_26
            | v_tls_1_3_draft_28),
    /** Any supported TLS 1.3 version. */
    v_tls_1_3_any = (v_tls_1_3
            | v_tls_1_3_draft_any),
    /** Any supported TLS version. */
    v_tls_any = (v_tls_1_0 | v_tls_1_1 | v_tls_1_2 | v_tls_1_3_any),
    /** Any DTLS version. */
    v_dtls_any = (v_dtls_1_0 | v_dtls_1_2),
    /** Any supported legacy version (TLS <1.3) */
    v_tls_legacy = (v_tls_1_0 | v_tls_1_1 | v_tls_1_2 | v_dtls_any),
    /** Any supported TLS 1.3 version that uses AAD in record encryption. */
    v_tls_1_3_aad = (v_tls_1_3
            | v_tls_1_3_draft_26
            | v_tls_1_3_draft_28),
    /** Any supported TLS 1.3 version that uses 51 as key_share ID */
    v_tls_1_3_key_share_51 = (v_tls_1_3
            | v_tls_1_3_draft_23
            | v_tls_1_3_draft_24
            | v_tls_1_3_draft_26
            | v_tls_1_3_draft_28),
    /** Any supported version that uses an explicit IV in CBC mode. */
    v_tls_explicit_iv = (v_dtls_1_0 | v_dtls_1_2 | v_tls_1_1 | v_tls_1_2),
    /** Any recommended TLS version. TODO: remove draft #28 once the
        RFC version becomes widely supported enough. */
    v_tls_recommended = (v_tls_1_2 | v_tls_1_3 | v_tls_1_3_draft_28),
    /** Any recommended DTLS version. */
    v_dtls_recommended = v_dtls_1_2,
    /** Any version that allows SHA-2 based ciphersuites. */
    v_tls_sha2 = (v_tls_1_2 | v_tls_1_3_any | v_dtls_1_2),
    /** Any version that does NOT allow SHA-2 based ciphersuites. */
    v_tls_no_sha2 = (v_ssl_3_0 | v_tls_1_0 | v_tls_1_1 | v_dtls_1_0),
    /** Any version that may need the BEAST workaround. */
    v_tls_need_beast_workaround = (v_ssl_3_0 | v_tls_1_0),
    /** Any version that uses the unsupported_extension alert. */
    v_tls_with_unsupported_extension_alert = (v_tls_1_2
            | v_dtls_1_2
            | v_tls_1_3_any),
    /** Any version that uses HMAC instead of a custom MAC construction. */
    v_tls_with_hmac = (v_tls_any | v_dtls_any),
    /** Any version that supports the signature_algorithms extension. */
    v_tls_with_signature_algorithms = (v_tls_1_2
            | v_tls_1_3_any
            | v_dtls_1_2),
    /** Any version that supports PKCS #1.5 sigs in CV and SKE. */
    v_tls_with_pkcs15_auth = (v_tls_1_2 | v_dtls_1_2),
    /** Any version that uses the TLS 1.2 PRF. */
    v_tls_with_tls_1_2_prf = (v_tls_1_2 | v_dtls_1_2),
    /** Any version supported by build-time-config. */
    v_compiled_in = (0
# if !defined(DISABLE_SSLV3)
            | v_ssl_3_0
# endif
# if defined(USE_TLS) && !defined(DISABLE_TLS_1_0)
            | v_tls_1_0
# endif
# if defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
            | v_tls_1_1
# if defined(USE_DTLS)
            | v_dtls_1_0
# endif
# endif
# if defined(USE_TLS_1_2) && !defined(DISABLE_TLS_1_2)
            | v_tls_1_2
# if defined(USE_DTLS)
            | v_dtls_1_2
# endif
# endif
# if defined(USE_TLS_1_3) && !defined(DISABLE_TLS_1_3)
            | v_tls_1_3_any
# endif
                         )
};

/* Version flags. These are deprecated; psProtocolVersion_t and the
   related APIs should be used instead. */
# define SSL_FLAGS_SSLV3         (1U << 10)
# define SSL_FLAGS_TLS           (1U << 11)
# define SSL_FLAGS_TLS_1_0       SSL_FLAGS_TLS  /* For naming consistency */
# define SSL_FLAGS_TLS_1_1       (1U << 12)
# define SSL_FLAGS_TLS_1_2       (1U << 13)
# define SSL_FLAGS_DTLS          (1U << 14)
# define SSL_FLAGS_TLS_1_3       (1U << 15)
# define SSL_FLAGS_TLS_1_3_DRAFT_22 (1U << 26)
# define SSL_FLAGS_TLS_1_3_DRAFT_23 (1U << 27)
# define SSL_FLAGS_TLS_1_3_DRAFT_24 (1U << 28)
# define SSL_FLAGS_TLS_1_3_DRAFT_26 (1U << 29)
# define SSL_FLAGS_TLS_1_3_DRAFT_28 (1U << 30)
# define SSL_FLAGS_TLS_1_3_NEGOTIATED (1U << 31)

#endif
