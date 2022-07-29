/**
 *      @file    matrixsslApiVer.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      This sub-header of matrixsslApi.h contains return codes.
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

#ifndef _h_MATRIXSSL_API_RET
# define _h_MATRIXSSL_API_RET

/* Main matrixSsl* API return codes. */
# define MATRIXSSL_SUCCESS PS_SUCCESS /* Generic success */
# define MATRIXSSL_ERROR PS_PROTOCOL_FAIL /* Generic SSL error */
# define MATRIXSSL_REQUEST_SEND 1 /* API produced data to be sent */
# define MATRIXSSL_REQUEST_RECV 2 /* API requres more data to continue */
# define MATRIXSSL_REQUEST_CLOSE 3 /* API indicates clean close is req'd */
# define MATRIXSSL_APP_DATA 4 /* App data is avail. to caller */
# define MATRIXSSL_HANDSHAKE_COMPLETE 5 /* Handshake completed */
# define MATRIXSSL_RECEIVED_ALERT 6 /* An alert was received */
# define MATRIXSSL_APP_DATA_COMPRESSED 7 /* App data must be inflated */

/* TLS 1.3 specific return codes. */
#  define MATRIXSSL_EARLY_DATA_ACCEPTED 8
#  define MATRIXSSL_EARLY_DATA_REJECTED 9
#  define MATRIXSSL_EARLY_DATA_SENT 10
#  define MATRIXSSL_EARLY_DATA_NOT_SENT 11

/* Negative return codes must be between -50 and -69 in the MatrixSSL module */
# define SSL_FULL -50 /* must call sslRead before decoding */
# define SSL_PARTIAL -51 /* more data reqired to parse full msg */
# define SSL_SEND_RESPONSE -52 /* decode produced output data */
# define SSL_PROCESS_DATA -53 /* succesfully decoded application data */
# define SSL_ALERT -54 /* we've decoded an alert */
# define SSL_FILE_NOT_FOUND -55 /* File not found */
# define SSL_MEM_ERROR PS_MEM_FAIL /* Memory allocation failure */
# ifdef USE_DTLS
#  define DTLS_MUST_FRAG -60 /* Message must be fragmented */
#  define DTLS_RETRANSMIT -61/* Received a duplicate hs msg from peer */
# endif /* USE_DTLS */
# define SSL_ENCODE_RESPONSE -62 /* Need to encode a response. */
# define SSL_NO_TLS_1_3 -63  /* We advertised TLS 1.3, but server
                                chose TLS <1.3. */

#endif
