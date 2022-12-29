/**
 *      @file    pkcs12Test.c
 *      @version $Format:%h%d$
 *
 *      Test program that tries out the new extensions to pkcs12 parsing.
 */
/*
 *      Copyright (c) 2020 INSIDE Secure Corporation
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
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L
#endif

#include "matrixssl/matrixsslImpl.h"
#include <stdlib.h>

#include "osdep_stdio.h"

void test_parse_pfx(int32 expected_rc,
                    const char* file,
                    const char* pass, int32 passlen,
                    const char* mpass, int32 mpasslen)
{
    sslKeys_t *keys = NULL;
    int32 rc = 0;

    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        _psTrace("MatrixSSL library key init failure. Exiting\n");
        return;
    }

    rc = matrixSslLoadPkcs12(keys,
        (unsigned char*)file,
        (const unsigned char*)pass,
        passlen,
        (const unsigned char*)mpass,
        mpasslen,
        0);
    if (rc == expected_rc)
    {
        Printf("SUCCESS: File %s parsed with expected return value: %d\n", file, rc);
    }
    else
    {
        Printf("FAIL: File %s parsed with return value %d, expected %d\n",
               file, rc, expected_rc);
    }

    matrixSslDeleteKeys(keys);
}

int main()
{
    int rc = 0;
    Printf("Parsing self generated files.\n");
    /*
     Generated with:
     openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
     openssl pkcs12 -export -inkey key.pem -in cert.pem -out test.pfx \
            -keypbe aes-256-cbc -macalg sha256 -certpbe NONE
    */
    test_parse_pfx(PS_SUCCESS,
                   "pfx/test-onepass.pfx", "1234", 4, NULL, 0);

    /* Test wrong password */
    test_parse_pfx(PS_FAILURE,
                   "pfx/test-onepass.pfx", "0000", 4, NULL, 0);

    /*
     Generated with:
     openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
     openssl pkcs12 -export -inkey key.pem -in cert.pem -out test.pfx \
            -keypbe aes-256-cbc -macalg sha256 -certpbe NONE -twopass
    */
    test_parse_pfx(PS_SUCCESS,
                   "pfx/test-twopass.pfx", "1234", 4, "2345", 4);

    /* Test wrong encryption password. */
    test_parse_pfx(PS_FAILURE,
                   "pfx/test-twopass.pfx", "0000", 4, "2345", 4);

    /* Test wrong authentication password. */
    test_parse_pfx(PS_AUTH_FAIL,
                   "pfx/test-twopass.pfx", "1234", 4, "0000", 4);

    /*
      Same as pfx/test-twopass.pfx, but one bit corrupted in integrity hash.
    */
    test_parse_pfx(PS_AUTH_FAIL,
                   "pfx/test-onepass-corrupt.pfx", "1234", 4, NULL, 0);

    /*
      Same as pfx/test-twopass.pfx, but one bit corrupted in the middle of file.
    */
    test_parse_pfx(PS_AUTH_FAIL,
                   "pfx/test-twopass-corrupt.pfx", "1234", 4, "2345", 4);

    return rc;
}
