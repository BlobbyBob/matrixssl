/**
 *      @file    matrixsslApiExt.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      This sub-header of matrixsslApi.h contains TLS extension IDs.
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

#ifndef _h_MATRIXSSL_API_EXT
# define _h_MATRIXSSL_API_EXT

/* IANA numbers for supported TLS extensions. */
# define EXT_SNI                              0
# define EXT_SERVER_NAME                      0 /* SNI renamed in TLS 1.3 */
# define EXT_MAX_FRAGMENT_LEN                 1
# define EXT_TRUSTED_CA_KEYS                  3
# define EXT_TRUNCATED_HMAC                   4
# define EXT_STATUS_REQUEST                   5 /* OCSP */
# define EXT_ELLIPTIC_CURVE                  10 /* Client-send only */
# define EXT_SUPPORTED_GROUPS                10 /* ELLIPTIC_CURVE renamed in 1.3 */
# define EXT_ELLIPTIC_POINTS                 11
# define EXT_SIGNATURE_ALGORITHMS            13
# define EXT_ALPN                            16
# define EXT_SIGNED_CERTIFICATE_TIMESTAMP    18
# define EXT_EXTENDED_MASTER_SECRET          23
# define EXT_SESSION_TICKET                  35
# define EXT_KEY_SHARE_PRE_DRAFT_23          40 /* Up to 1.3 draft 22 */
# define EXT_PRE_SHARED_KEY                  41
# define EXT_EARLY_DATA                      42
# define EXT_SUPPORTED_VERSIONS              43
# define EXT_COOKIE                          44
# define EXT_PSK_KEY_EXCHANGE_MODES          45
# define EXT_CERTIFICATE_AUTHORITIES         47
# define EXT_OID_FILTERS                     48
# define EXT_POST_HANDSHAKE_AUTH             49
# define EXT_SIGNATURE_ALGORITHMS_CERT       50
# define EXT_KEY_SHARE                       51 /* Since 1.3 draft 23. */
# define EXT_RENEGOTIATION_INFO              0xFF01

#endif
