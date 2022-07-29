/**
 *      @file    psUtil.c
 *      @version $Format:%h%d$
 *
 *      Useful utility macros and functions. These macros and functions
 *  are intended to allow easier use of common idioms and to provide
 *  simple extensions to functions provided by C language standard.
 *
 *  These macros and functions can be used in programs using SafeZone
 *  and MatrixSSL software or related software components.
 */
/*
 *      Copyright (c) 2017 Rambus Inc.
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
 *      commercial license for this software may be purchased from Rambus Inc at
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

#include "osdep.h"
#include "psUtil.h"

/* Initialize memory with specified value.
   This call is never optimized out by the compiler. */
void *psMemsetSR(void *s, int c, psSizeL_t n)
{
    if (s)
    {
        memset_s(s, n, c, n);
    }
    return s;
}

/* Initialize memory with zero value.
   This call is never optimized out by the compiler. */
void *psMemzeroSR(void *s, psSizeL_t n)
{
    if (s)
    {
        memset_s(s, n, 0x00, n);
    }
    return s;
}

/* Initialize memory with specified value.
   This call is never optimized out by the compiler. */
void psMemsetS(void *s, int c, psSizeL_t n)
{
    if (s)
    {
        memset_s(s, n, c, n);
    }
}

/* Initialize memory with zero value.
   This call is never optimized out by the compiler. */
void psMemzeroS(void *s, psSizeL_t n)
{
    if (s)
    {
        memset_s(s, n, 0x00, n);
    }
}

/* Initialize memory with specified value.
   This call is never optimized out by the compiler. */
void *psMemsetSRR(void *s, int c, psSizeL_t n, void *ret)
{
    if (s)
    {
        memset_s(s, n, c, n);
    }
    return ret;
}

/* Initialize memory with zero value.
   This call is never optimized out by the compiler. */
void *psMemzeroSRR(void *s, psSizeL_t n, void *ret)
{
    if (s)
    {
        memset_s(s, n, 0x00, n);
    }
    return ret;
}

char *psStrdupN(const char *string)
{
    size_t len;
    char *new_str;

    if (string == NULL)
    {
        return NULL;
    }
    len = psStrlen(string);
    new_str = psMallocN(len + 1);
    if (new_str)
    {
        psMemcpy(new_str, string, len);
        new_str[len] = 0;
    }
    return new_str;
}

void psFreeN(void *ptr)
{
    psFreeNoPool(ptr);
}

/* Call free function and return specified return value. */
void *psFreeFRR(void (*free_func)(void *ptr), void *ptr, void *ret)
{
    free_func(ptr);
    return ret;
}

#ifdef USE_MULTITHREADING
#include "osdep_pthread.h"
#ifdef PTHREAD_MUTEX_INITIALIZER
#define PS_ONCE_CAN_LOCK 1
#endif /* PTHREAD_MUTEX_INITIALIZER */
#endif /* USE_MULTITHREADING */

static
void psOnce_internal(psOnce_t *once_control, psOnceInitFunction init_routine);

void psOnce(psOnce_t *once_control, psOnceInitFunction init_routine)
{
    if (*once_control == PS_ONCE_INIT)
    {
        /* slow path: not yet initialized. */
        psOnce_internal(once_control, init_routine);
    }
}

/* Perform initialization. */
static
void psOnce_internal(psOnce_t *once_control, psOnceInitFunction init_routine)
{
#ifdef PS_ONCE_CAN_LOCK
    static pthread_mutex_t once_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif /* PS_ONCE_CAN_LOCK */

#ifdef PS_ONCE_CAN_LOCK
    Pthread_mutex_lock(&once_mutex);
#endif /* PS_ONCE_CAN_LOCK */

    /* Ensure *once_control is still uninitialized. */
    if (*once_control == PS_ONCE_INIT)
    {
        /* slow path: perform initialization. */
        init_routine();
        *once_control = 1;
    }

#ifdef PS_ONCE_CAN_LOCK
    Pthread_mutex_unlock(&once_mutex);
#endif /* PS_ONCE_CAN_LOCK */
        
}

/* end of file psUtil.c */
