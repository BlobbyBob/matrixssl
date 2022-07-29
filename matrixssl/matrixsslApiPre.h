/**
 *      @file    matrixsslApiPre.h
 *      @version $Format:%h%d$
 *
 *      Public header file for MatrixSSL.
 *      This sub-header of matrixsslApi.h contains a preamble.
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

#ifndef _h_MATRIXSSL_API_PRE
# define _h_MATRIXSSL_API_PRE

# include "coreApi.h"     /* cryptoApi.h and matrixsslApi.h depend on this */
# include "../crypto/cryptoApi.h" /* matrixsslApi.h depend on cryptoApi.h. */

# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <matrixsslConfig.h> /* Get matrixssl configuration from -I dir. */
# else
#  include "matrixsslConfig.h" /* Get local matrixssl configuration file. */
# endif

# ifdef DISABLE_TLS_1_3
#  undef USE_TLS_1_3
#  undef USE_TLS_AES_128_GCM_SHA256
#  undef USE_TLS_AES_256_GCM_SHA384
#  undef USE_TLS_CHACHA20_POLY1305_SHA256
# endif

# include "version.h"

/*
    Build the configuration string with the relevant build options for
    runtime validation of compile-time configuration.
 */
#  define HW_CONFIG_STR "N"

# define MATRIXSSL_CONFIG \
    "Y" \
    HW_CONFIG_STR \
    PSCRYPTO_CONFIG

#endif
