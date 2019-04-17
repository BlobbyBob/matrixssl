/**
 *      @file    matrixsslApiTls.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      This sub-header of matrixsslApi.h contains alert constants.
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

#ifndef _h_MATRIXSSL_API_ALERT
# define _h_MATRIXSSL_API_ALERT

# define SSL_ALERT_LEVEL_WARNING             1
# define SSL_ALERT_LEVEL_FATAL               2

# define SSL_ALERT_CLOSE_NOTIFY              0
# define SSL_ALERT_UNEXPECTED_MESSAGE        10
# define SSL_ALERT_BAD_RECORD_MAC            20
# define SSL_ALERT_DECRYPTION_FAILED         21/* Do not use, per RFC 5246 */
# define SSL_ALERT_RECORD_OVERFLOW           22
# define SSL_ALERT_DECOMPRESSION_FAILURE     30
# define SSL_ALERT_HANDSHAKE_FAILURE         40
# define SSL_ALERT_NO_CERTIFICATE            41
# define SSL_ALERT_BAD_CERTIFICATE           42
# define SSL_ALERT_UNSUPPORTED_CERTIFICATE   43
# define SSL_ALERT_CERTIFICATE_REVOKED       44
# define SSL_ALERT_CERTIFICATE_EXPIRED       45
# define SSL_ALERT_CERTIFICATE_UNKNOWN       46
# define SSL_ALERT_ILLEGAL_PARAMETER         47
# define SSL_ALERT_UNKNOWN_CA                48
# define SSL_ALERT_ACCESS_DENIED             49
# define SSL_ALERT_DECODE_ERROR              50
# define SSL_ALERT_DECRYPT_ERROR             51
# define SSL_ALERT_PROTOCOL_VERSION          70
# define SSL_ALERT_INSUFFICIENT_SECURITY     71
# define SSL_ALERT_INTERNAL_ERROR            80
# define SSL_ALERT_INAPPROPRIATE_FALLBACK    86
# define SSL_ALERT_NO_RENEGOTIATION          100
# define SSL_ALERT_UNSUPPORTED_EXTENSION     110
# define SSL_ALERT_UNRECOGNIZED_NAME         112
# define SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE   113
# define SSL_ALERT_UNKNOWN_PSK_IDENTITY      115
# define SSL_ALERT_NO_APP_PROTOCOL           120

/* Additional ssl alert value, indicating no error has ocurred.  */
# define SSL_ALERT_NONE              255/* No error */

/*
    Use as return code in user validation callback to allow
    anonymous connections to proceed.
    MUST NOT OVERLAP WITH ANY OF THE ALERT CODES ABOVE
 */
# define SSL_ALLOW_ANON_CONNECTION           254

#endif
