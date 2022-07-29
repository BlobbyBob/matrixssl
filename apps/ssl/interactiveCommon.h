/**
 *      @file    interactiveCommon.h
 *      @version $Format:%h%d$
 *
 *      Common parts of interactiveClient.c and interactiveServer.c
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

int get_user_input(char *buf, int buf_len);
int get_user_input_char(char *c, char defaultChoice);
int32_t getAppDataFromUser(ssl_t *ssl,
        unsigned char *data,
        size_t *dataLen);
int32_t askSendAppData(ssl_t *ssl);
psRes_t getUserProtocolVersion(psProtocolVersion_t *verOut);
psRes_t getUserKeyPair(const unsigned char **cert,
        int32_t *certLen,
        const unsigned char **key,
        int32_t *keyLen,
        int32_t *keyType,
        int32_t *pskLen);
int load_keys(sslKeys_t *keys);
psRes_t getEncodingFunc(void);
psRes_t getUserSigAlgs(uint16_t *sigAlgs, psSize_t *numSigAlgs);
psRes_t getUserCiphersuites(psCipher16_t *ciphersuites,
        psSize_t *numCiphersuites);
psRes_t getMaximumFragmentLength(short *maxFragLen);
psRes_t getServerAddress(char *addr_out, int *addr_out_len);
psRes_t getServerPort(int *port_out);
psRes_t getServerName(
        char *name_out,
        int name_out_len,
        char *ip_addr);
psRes_t getAllowAnon(psBool_t *allow);
psRes_t getUserFirstSender(void);
