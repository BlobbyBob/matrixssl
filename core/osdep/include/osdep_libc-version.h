/** osdep_libc-version.h
 *
 * Wrapper for system header osdep_libc-version.h
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
*
* The latest version of this code is available at http://www.matrixssl.org
*
* This software is open source; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This General Public License does NOT permit incorporating this software
* into proprietary programs.  If you are unable to comply with the GPL, a
* commercial license for this software may be purchased from INSIDE at
* http://www.insidesecure.com/
*
* This program is distributed in WITHOUT ANY WARRANTY; without even the
* implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

/* This file just includes system header gnu/libc-version.h.
   In case your system does not include all functions
    via that file or
   does not have implementation of gnu/libc-version.h, please
   customize this place holder header.
*/

#ifndef OSDEP_LIBC_VERSION_H_DEFINED
#define OSDEP_LIBC_VERSION_H_DEFINED 1

/* Get (build time) libc version on Linux from GLIBC headers.
   This header is no-op on other systems.
   Android systems are autodetected, they do not use GLIBC.
   There is -DPS_NO_GLIBC for other linux kernel based systems not using
   GLIBC. */

#ifdef __unix__
#ifdef __linux__
#ifndef __ANDROID__
#ifndef PS_NO_GLIBC
#include <gnu/libc-version.h>
#endif /* PS_NO_GLIBC */
#endif /* __ANDROID__ */
#endif /* __linux__ */
#endif /* __unix__ */

#endif /* OSDEP_LIBC_VERSION_H_DEFINED */
