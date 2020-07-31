/** osdep_sys_random.h
 *
 * Wrapper for system header sys_random.h
 */

/*****************************************************************************
* Copyright (c) 2018 INSIDE Secure Oy. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from INSIDE Secure.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* INSIDE Secure.
*****************************************************************************/

/* This file just includes system header sys_random.h.
   In case your system does not include all functions
   malloc/free/calloc/realloc/abort/getenv via that file or
   does not have implementation of sys_random.h, please
   customize this place holder header. 
*/

#ifndef OSDEP_SYS_RANDOM_H_DEFINED
#define OSDEP_SYS_RANDOM_H_DEFINED 1

#ifdef OSDEP_HAVE_GLIBC_GETRANDOM
/* Obtain getrandom() if available.
   It's available in Glibc starting with 2.25 (2017). */
#include <sys/random.h>

#define Getrandom getrandom
#elif defined(__linux__) && !defined(OSDEP_NO_LINUX_GETRANDOM)

/* Emulate getrandom() function using the system call.
   The system call is available starting with Linux 3.17 kernel. */

#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifdef SYS_getrandom
#include <linux/random.h>
#endif /* SYS_getrandom */

/* Provide prototype for syscall function. */
long syscall(long number, ...);

#ifdef __GNUC__
/* Request always inlining for this function. */
static inline
ssize_t getrandom_inline(void *buf, size_t buflen, unsigned int flags)
__attribute__((__always_inline__));
#endif

#ifdef SYS_getrandom
static inline
ssize_t getrandom_inline(void *buf, size_t buflen, unsigned int flags)
{
    return syscall(__NR_getrandom, buf, buflen, flags);
}
#define Getrandom getrandom_inline
#endif /* SYS_getrandom */

#endif /* OSDEP_HAVE_GLIBC_GETRANDOM */

#endif /* OSDEP_SYS_RANDOM_H_DEFINED */
