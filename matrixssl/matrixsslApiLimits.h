/**
 *      @file    matrixsslApiLimits.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      This sub-header of matrixsslApi.h contains minimum and maximum
 *      buffer size and other limits.
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

#ifndef _h_MATRIXSSL_API_LIMITS
# define _h_MATRIXSSL_API_LIMITS

/* Maximum SSL/TLS record size, per specification. */
# define SSL_MAX_PLAINTEXT_LEN 0x4000 /* 16KB */
# define SSL_MAX_RECORD_LEN SSL_MAX_PLAINTEXT_LEN + 2048
# define SSL_MAX_BUF_SIZE 0xffff /* 65536. This must be enough for
                                    entire outgoing flight */
/*
  From section 5.2. of the TLS 1.3 spec.
  Assuming a fullsize TLSPlaintext.fragment, TLSInnerPlaintext adds
  1 type octet and TLSCiphertext adds at most 255 AEAD overhead.
*/
# define TLS_1_3_MAX_PLAINTEXT_FRAGMENT_LEN 16384 /* 2^14 */
# define TLS_1_3_MAX_INNER_PLAINTEXT_LEN 16385 /* 2^14 + 1 */
# define TLS_1_3_MAX_CIPHERTEXT_LEN 16640 /* 2^14 + 1 + 255 */

/*
    Maximum buffer sizes for static SSL array types
 */
# define SSL_MAX_MAC_SIZE 48/* SHA384 */
# define SSL_MAX_IV_SIZE 16
# define SSL_MAX_BLOCK_SIZE 16
# define SSL_MAX_SYM_KEY_SIZE 32
# define MAX_TLS_1_3_HASH_SIZE SHA384_HASHLEN

/* Maximum number of simultaneous TLS versions supported */
# define TLS_MAX_SUPPORTED_VERSIONS 16
/* TLS 1.3: maximum number of algorithms in signature_algorithms extension. */
# define TLS_MAX_SIGNATURE_ALGORITHMS 32
/* TLS 1.3: maximum number of cipher suites to support in clientHello */
# define TLS_1_3_MAX_CIPHER_SUITES 8
/* TLS 1.3: maximum number of groups. */
# define TLS_1_3_MAX_GROUPS 32

/* Maximum number of compiled-in ciphers that can be disabled
   at run-time using the matrixSslSetCiphersuiteEnabledStatus API. */
# define SSL_MAX_DISABLED_CIPHERS 32

/*
    TLS implementations supporting these ciphersuites MUST support
    arbitrary PSK identities up to 128 octets in length, and arbitrary
    PSKs up to 64 octets in length.  Supporting longer identities and
    keys is RECOMMENDED.
 */
# define SSL_PSK_MAX_KEY_SIZE 64  /* Must be < 256 due to 'idLen' */
# define SSL_PSK_MAX_ID_SIZE 128 /* Must be < 256 due to 'idLen' */
# define SSL_PSK_MAX_HINT_SIZE 32  /* ServerKeyExchange hint is non-standard */

/* How large the ALPN extension arrary is.  Number of protos client can talk */
# define MAX_PROTO_EXT 8

/*
    Maximum key block size for any defined cipher
    This must be validated if new ciphers are added
    Value is largest total among all cipher suites for
        2*macSize + 2*keySize + 2*ivSize
    Rounded up to nearest PRF block length. We aren't really
        rounding, but just adding another block length for simplicity.
 */
# ifdef USE_TLS_1_2
#  define SSL_MAX_KEY_BLOCK_SIZE ((2 * 48) + (2 * 32) + (2 * 16) + SHA256_HASH_SIZE)
# else
#  define SSL_MAX_KEY_BLOCK_SIZE ((2 * 48) + (2 * 32) + (2 * 16) + SHA1_HASH_SIZE)
# endif
# ifdef USE_EAP_FAST
#  define EAP_FAST_SESSION_KEY_SEED_LEN   40
#  define EAP_FAST_PAC_KEY_LEN            32
#  undef SSL_MAX_KEY_BLOCK_SIZE
#  define SSL_MAX_KEY_BLOCK_SIZE      ((2 * 48) + (2 * 32) + (2 * 16) + \
                                       SHA256_HASH_SIZE + \
                                       EAP_FAST_SESSION_KEY_SEED_LEN)
# endif

/*
    Master secret is 48 bytes, sessionId is 32 bytes max
 */
# define     SSL_HS_MASTER_SIZE      48
# define     SSL_MAX_SESSION_ID_SIZE 32

#endif
