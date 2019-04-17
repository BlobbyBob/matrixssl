/**
 *      @file    pubkey_matrix.h
 *      @version $Format:%h%d$
 *
 *      MatrixSSL Crypto Implementation for RSA, DH and ECC.
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
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

#ifndef _h_MATRIX_PUBKEY
# define _h_MATRIX_PUBKEY

/******************************************************************************/

# ifdef USE_MATRIX_RSA

typedef struct
{
    pstm_int e, d, N, qP, dP, dQ, p, q;
    psPool_t *pool;
    psSize_t size;          /* Size of the key in bytes */
    uint8_t optimized;      /* Set if optimized */
# ifdef USE_ROT_RSA
    ValAssetId_t privSigAsset;
    ValAssetId_t pubSigAsset;
    ValAssetId_t privEncAsset;
    ValAssetId_t pubEncAsset;
# endif
} psRsaKey_t;

# endif

/******************************************************************************/

# ifdef USE_MATRIX_ECC

/**
    An ECC curve.
    Including size, name, and domain parameters.
 */
typedef struct
{
    uint8_t size;        /**< The size of the curve in octets */
    psCurve16_t curveId; /**< IANA named curve id for TLS use */
    uint8_t isOptimized; /**< 1 if optimized with field param A=-3. */
    uint32_t OIDsum;     /**< Internal Matrix OID */
    const char *name;    /**< name of curve */
    /* These below constitute the domain parameters */
    const char *prime;   /**< prime defining the curve field (ascii hex) */
    const char *A;       /**< The field's A param (ascii hex) */
    const char *B;       /**< The field's B param (ascii hex) */
    const char *order;   /**< The order of the curve (ascii hex) */
    const char *Gx;      /**< The x coordinate of the base point (ascii hex) */
    const char *Gy;      /**< The y coordinate of the base point (ascii hex) */
} psEccCurve_t;

/**
    A point on a ECC curve, stored in Jacbobian format such that
    (x,y,z) => (x/z^2, y/z^3, 1) when interpretted as affine.
 */
typedef struct
{
    pstm_int x; /* The x co-ordinate */
    pstm_int y; /* The y co-ordinate */
    pstm_int z; /* The z co-ordinate */
    psPool_t *pool;
} psEccPoint_t;

typedef enum
{
    ps_ecc_key_type_ecdsa = 0,
    ps_ecc_key_type_ecdhe = 1
} psEccKeyType_t;

typedef struct
{
    pstm_int k;                 /* The private key */
    psEccPoint_t pubkey;        /* The public key */
    const psEccCurve_t *curve;  /* pointer to named curve */
    psPool_t *pool;
    uint8_t type;               /* Type of key, PS_PRIVKEY or PS_PUBKEY */
# ifdef USE_ROT_ECC
    ValAssetId_t pubAsset;
    ValAssetId_t domainAsset;
    ValAssetId_t privAsset;
    psBool_t longTermPrivAsset;
    psEccKeyType_t rotKeyType;
    unsigned char pubValue[64];
# endif
} psEccKey_t;

# ifdef USE_ROT_ECC
/* RoT-specific structure for the ECC curves. */
typedef struct
{
    uint32_t CurveBits;
    const uint8_t * P_p;
    uint32_t PLen;
    const uint8_t * A_p;
    uint32_t ALen;
    const uint8_t * B_p;
    uint32_t BLen;
    const uint8_t * ECPointX_p;
    uint32_t ECPointXLen;
    const uint8_t * ECPointY_p;
    uint32_t ECPointYLen;
    const uint8_t * Order_p;
    uint32_t OrderLen;
    const uint8_t Cofactor;
} psRotCurve_t;
# endif /* USE_ROT_ECC */

# endif

/******************************************************************************/

# ifdef USE_MATRIX_DH

typedef struct
{
    pstm_int p;     /* The Prime value */
    pstm_int g;     /* The Generator/Base value */
    psPool_t *pool;
    psSize_t size;  /* Size of 'p' in bytes */
    psSize_t x_bitlen; /* Recommended size of private key in bits (optional). */
} psDhParams_t;

typedef struct
{
    pstm_int priv, pub;
    psSize_t size;
    uint8_t type;     /* PS_PRIVKEY or PS_PUBKEY */
} psDhKey_t;

# endif

/******************************************************************************/

#endif /* _h_MATRIX_PUBKEY */

