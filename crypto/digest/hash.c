/**
 *      @file    hash.c
 *      @version $Format:%h%d$
 *
 *      Algorithm-independent psHash API implementation.
 *      Supports SHA-256, SHA-384 and SHA-512.
 */
/*
 *      Copyright (c) 2013-2019 Rambus Inc.
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

#include "../cryptoImpl.h"

psRes_t psHashInit(psDigestContext_t *ctx,
        int32_t hashAlgId,
        psHashOpts_t *opts)
{
    (void) opts;

    Memset(ctx, 0, sizeof(*ctx));
    ctx->hashAlgId = hashAlgId;

    switch (ctx->hashAlgId)
    {
    case OID_SHA256_ALG:
        return psSha256Init(&ctx->u.sha256);
        break;
# ifdef USE_SHA384
    case OID_SHA384_ALG:
        return psSha384Init(&ctx->u.sha384);
        break;
# endif
# ifdef USE_SHA512
    case OID_SHA512_ALG:
        return psSha512Init(&ctx->u.sha512);
        break;
# endif
    default:
        psTraceIntCrypto("Unsupported hash len in psHashInit: %zu\n",
                ctx->hashAlgId);
        return PS_UNSUPPORTED_FAIL;
    }

    return PS_SUCCESS;
}

psRes_t psHashUpdate(psDigestContext_t *ctx,
        const unsigned char *data,
        psSizeL_t dataLen)
{
    switch (ctx->hashAlgId)
    {
    case OID_SHA256_ALG:
        psSha256Update(&ctx->u.sha256, data, dataLen);
        break;
# ifdef USE_SHA384
    case OID_SHA384_ALG:
        psSha384Update(&ctx->u.sha384, data, dataLen);
        break;
# endif
# ifdef USE_SHA512
    case OID_SHA512_ALG:
        psSha512Update(&ctx->u.sha512, data, dataLen);
        break;
# endif
    default:
        psTraceIntCrypto("Unsupported hash len in psHashUpdate: %zu\n",
                ctx->hashAlgId);
        return PS_UNSUPPORTED_FAIL;
    }

    return PS_SUCCESS;
}

psRes_t psHashFinal(psDigestContext_t *ctx,
        unsigned char *hashOut)
{
    switch (ctx->hashAlgId)
    {
    case OID_SHA256_ALG:
        psSha256Final(&ctx->u.sha256, hashOut);
        break;
# ifdef USE_SHA384
    case OID_SHA384_ALG:
        psSha384Final(&ctx->u.sha384, hashOut);
        break;
# endif
# ifdef USE_SHA512
    case OID_SHA512_ALG:
        psSha512Final(&ctx->u.sha512, hashOut);
        break;
# endif
    default:
        psTraceIntCrypto("Unsupported hash len in psHashFinal: %zu\n",
                ctx->hashAlgId);
        return PS_UNSUPPORTED_FAIL;
    }

    return PS_SUCCESS;
}
