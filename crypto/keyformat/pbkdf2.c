/**
 *      @file    pbkdf2.c
 *      @version $Format:%h%d$
 *
 *      PBKDF2.
 */

/*
 *      Copyright (c) 2020 Rambus Inc.
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

#include "../cryptoImpl.h"

#ifdef USE_PRIVATE_KEY_PARSING
#  ifdef MATRIX_USE_FILE_SYSTEM
#   ifdef USE_PKCS8
#    ifdef USE_PKCS12

int32 pkcs12pbkdf2(psPool_t *pool, int32 hash_alg,
                   const unsigned char *password, uint32 passLen,
                   const unsigned char *salt, int saltLen, uint32 keyLen,
                   uint16 count,  unsigned char **out)
{
    psTraceCrypto("PBES2 key derivation not supported.\n");
    return PS_PARSE_FAIL;
}

#    endif /* USE_PKCS12 */
#   endif /* USE_PKCS8 */
#  endif /* MATRIX_USE_FILE_SYSTEM */
#endif /* USE_PRIVATE_KEY_PARSING */
/******************************************************************************/
