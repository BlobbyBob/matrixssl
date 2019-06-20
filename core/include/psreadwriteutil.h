/**
 *      @file    psreadwriteutil.h
 *      @version $Format:%h%d$
 *
 *  Util funtion for chechking errno.
 *
 */
/*
 *      Copyright (c) 2019 INSIDE Secure Corporation
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

#ifndef INCLUDE_GUARD_PSREADWRITEUTIL_H
#define INCLUDE_GUARD_PSREADWRITEUTIL_H 1

#include "osdep_errno.h"
#include "pscompilerdep.h"

/*
    Return whether the errno passed as a parameter tells that the
    operation would block.

    @param err errno following a read or write

    @retval 1 operation would block.
    @retval 0 operation would not block.
 */
static inline int psCheckWouldBlock (int err)
{
    switch (err)
    {
# ifdef EAGAIN
        case EAGAIN:
# endif

# ifdef EWOULDBLOCK
#  ifdef EAGAIN
#   if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#   endif
#  else
        case EWOULDBLOCK:
#  endif
# endif
            return 1;
        default:
            break;
    }
    return 0;
}

#endif /* INCLUDE_GUARD_PSREADWRITEUTIL_H */

/* end of psreadwriteutil.h */
