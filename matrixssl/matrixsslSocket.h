/* matrixsslSocket.h
 *
 * Build psSocket_t based on matrixsslNet.
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from INSIDE Secure.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* INSIDE Secure.
*
* For more information or support, please go to our online support system at
* https://essoemsupport.insidesecure.com.
* In case you do not have an account for this system, please send an e-mail to
* ESSEmbeddedHW-Support@insidesecure.com.
*****************************************************************************/

#ifndef INCLUDE_GUARD_MATRIXSSLSOCKET_H
#define INCLUDE_GUARD_MATRIXSSLSOCKET_H

/* This code is extension on core.h's USE_PS_NETWORKING */
#include "core/coreApi.h"

#ifdef USE_PS_NETWORKING

/* Obtain TLS socket internally using MatrixSSL. */
const psSocketFunctions_t *psGetSocketFunctionsTLS(void);

struct psSocketTls
{
    /* Configuration items for TLS Socket. */
    const char *capath;
    int tls_version;
    int ciphers;
    const psCipher16_t *cipherlist;
    /* Internal use only */
    int nested_call;
    int handshaked;
    matrixSslInteract_t msi;
};

#endif /* USE_PS_NETWORKING */

#endif /* INCLUDE_GUARD_MATRIXSSLSOCKET_H */

/* end of file matrixsslSocket.h */
