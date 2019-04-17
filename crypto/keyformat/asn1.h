/**
 *      @file    asn1.h
 *      @version $Format:%h%d$
 *
 *      ASN.1 header.
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

/* Allow inclusion of asn1.h as standalone. */
#ifndef _h_PS_CRYPTOAPI
# include "../cryptoApi.h"
#endif /* _h_PS_CRYPTOAPI */

/* Provide deprecation warnings for using deprecated functions. */
#include "pscompilerdep.h"

#ifndef _h_PS_ASN1
# define _h_PS_ASN1

/******************************************************************************/
/*
    8 bit bit masks for ASN.1 tag field
 */
# define ASN_PRIMITIVE           0x0
# define ASN_CONSTRUCTED         0x20

# define ASN_UNIVERSAL           0x0
# define ASN_APPLICATION         0x40
# define ASN_CONTEXT_SPECIFIC    0x80
# define ASN_PRIVATE             0xC0

/*
    ASN.1 primitive data types
 */
enum
{
    ASN_BOOLEAN = 1,
    ASN_INTEGER,
    ASN_BIT_STRING,
    ASN_OCTET_STRING,
    ASN_NULL,
    ASN_OID,
    ASN_ENUMERATED = 10,
    ASN_UTF8STRING = 12,
    ASN_SEQUENCE = 16,
    ASN_SET,
    ASN_PRINTABLESTRING = 19,
    ASN_T61STRING,
    ASN_IA5STRING = 22,
    ASN_UTCTIME,
    ASN_GENERALIZEDTIME,
    ASN_VISIBLE_STRING = 26,
    ASN_GENERAL_STRING,
    ASN_BMPSTRING = 30
};

# define ASN_UNKNOWN_LEN 65533

extern uint32_t getAsnTagLenUnsafe(const unsigned char *p);

extern int32_t getAsnLength(const unsigned char **p, psSizeL_t size,
                            psSize_t *valLen);
extern int32_t getAsnLength32(const unsigned char **p, psSizeL_t size,
                              uint32_t *valLen, uint32_t indefinite);
extern int32_t getAsnSequence(const unsigned char **pp, psSizeL_t size,
                              psSize_t *seqlen);
extern int32_t getAsnSequence32(const unsigned char **pp, psSizeL_t size,
                                psSize32_t *len, uint32_t indefinite);
extern int32_t getAsnSet(const unsigned char **pp,  psSizeL_t size,
                         psSize_t *setlen);
extern int32_t getAsnSet32(const unsigned char **pp, psSizeL_t size,
                           psSize32_t *len, uint32_t indefinite);
extern int32_t getAsnEnumerated(const unsigned char **pp, psSizeL_t size,
                                int32_t *val);

extern int32_t getAsnInteger(const unsigned char **pp, psSizeL_t size,
                             int32_t *val);
extern int32_t getAsnAlgorithmIdentifier(const unsigned char **pp, psSizeL_t size,
                                         int32_t *oi, psSize_t *paramLen);
extern int32_t getAsnOID(const unsigned char **pp, psSizeL_t size,
			 int32_t *oi,
			 uint8_t checkForParams, psSize_t *paramLen);

# define MAX_OID_LEN     16     /**< Maximum number of segments in OID */
# define MAX_OID_BYTES   32     /**< Maximum number of bytes in OID. */
# define MAX_OID_PRINTED_LEN_NAMED 64 /* Maximum length of known OID in
                                         printed form. */
# define MAX_OID_PRINTED_LEN_BYTES (4 * MAX_OID_BYTES) /* Maximum length of
                                                          unknown OIDs. */
# define MAX_OID_PRINTED_LEN                                            \
    ((MAX_OID_PRINTED_LEN_NAMED) > (MAX_OID_PRINTED_LEN_BYTES) ?        \
     (MAX_OID_PRINTED_LEN_NAMED) : (MAX_OID_PRINTED_LEN_BYTES))

typedef uint8_t psAsnOid_t[MAX_OID_BYTES];

extern uint8_t asnParseOid(const unsigned char *der, psSizeL_t derlen,
                           uint32_t oid[MAX_OID_LEN]) PSDEPRECATED_WARN;

/* Copy Oid / Store Oid for later use. */
extern uint8_t asnCopyOid(const unsigned char *der, psSizeL_t derlen,
                          psAsnOid_t oid);

/* Get length of ASN.1 OID as an DER encoded byte sequence.
   Will return 0 for failure. */
extern psSizeL_t asnOidLenBytes(psAsnOid_t oid);

/* Get length of ASN.1 OID as numbers (or 0 for failure).
   Will return 0 for failure. */
extern uint8_t asnOidLenSegments(psAsnOid_t oid);

/* Format OID tag as string for printing. */
extern char *asnFormatOid(psPool_t *pool,
                          const unsigned char *oid, size_t oidlen);

/* Format octet string representing ASN.1 in Der encoded format. */
extern char *asnFormatDer(psPool_t *pool,
                          const unsigned char *Der_p,
                          size_t DerLen,
                          size_t MaxElements,
                          size_t MaxDepth,
                          size_t MaxElementOutput,
                          unsigned char Flags);

/* Format psAsnOid_t in dotted notation to provided character array.
   Returns a pointer to the array for convenience.

   The function is able to provide symbolic name for some X.509 OIDs.

   Note: This function is implemented by x509.c, but described here as
   logically the function belongs with the rest of ASN.1 decoding. */
const char *psSprintAsnOid(psAsnOid_t oid,
                           char out[MAX_OID_PRINTED_LEN]);

/******************************************************************************/

#endif  /* _h_PS_ASN1 */

/******************************************************************************/

