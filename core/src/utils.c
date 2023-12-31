#include "sl_chacha20poly1305ietf_config.h"
#if defined USE_SL_CHACHA20_POLY1305_IETF || defined USE_SL_SODIUM
# ifndef __STDC_WANT_LIB_EXT1__
#  define __STDC_WANT_LIB_EXT1__ 1
# endif
# include "osdep_assert.h"
# include "osdep_errno.h"
# include "osdep_limits.h"
# include "osdep_signal.h"
# include "osdep_stddef.h"
# include "osdep_stdint.h"
# include "osdep_stdlib.h"
# include "osdep_string.h"

# ifdef HAVE_SYS_MMAN_H
#  include "osdep_sys_mman.h"
# endif

# ifdef _WIN32
#  include "osdep_windows.h"
#  include "osdep_wincrypt.h"
# else
#  include "osdep_unistd.h"
# endif

# ifndef NO_SODIUM_MEMORY_MANAGEMENT
#  include "randombytes.h"
# endif
# include "utils.h"

# ifndef ENOSYS
#  define ENOSYS ENXIO
# endif

# if defined(_WIN32) && \
    (!defined(WINAPI_FAMILY) || WINAPI_FAMILY == WINAPI_FAMILY_DESKTOP_APP)
#  define WINAPI_DESKTOP
# endif

# define CANARY_SIZE 16U
# define GARBAGE_VALUE 0xdb

# ifndef MAP_NOCORE
#  define MAP_NOCORE 0
# endif
# if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#  define MAP_ANON MAP_ANONYMOUS
# endif
# if defined(WINAPI_DESKTOP) || (defined(MAP_ANON) && defined(HAVE_MMAP)) || \
    defined(HAVE_POSIX_MEMALIGN)
#  define HAVE_ALIGNED_MALLOC
# endif
# if defined(HAVE_MPROTECT) && \
    !(defined(PROT_NONE) && defined(PROT_READ) && defined(PROT_WRITE))
#  undef HAVE_MPROTECT
# endif
# if defined(HAVE_ALIGNED_MALLOC) && \
    (defined(WINAPI_DESKTOP) || defined(HAVE_MPROTECT))
#  define HAVE_PAGE_PROTECTION
# endif
# if !defined(MADV_DODUMP) && defined(MADV_CORE)
#  define MADV_DODUMP   MADV_CORE
#  define MADV_DONTDUMP MADV_NOCORE
# endif

#ifndef NO_SODIUM_MEMORY_MANAGEMENT
static size_t        page_size;
static unsigned char canary[CANARY_SIZE];
#endif /* NO_SODIUM_MEMORY_MANAGEMENT */

# ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
SLSodium_memzero_as_a_weak_symbol_to_prevent_lto(void *const  pnt,
                                                  const size_t len)
{
    unsigned char *pnt_ = (unsigned char *) pnt;
    size_t         i    = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
}
# endif

void
SLSodium_memzero(void *const pnt, const size_t len)
{
# ifdef _WIN32
    SecureZeroMemory(pnt, len);
# elif defined(HAVE_MEMSET_S)
    if (memset_s(pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
        Abort(); /* LCOV_EXCL_LINE */
    }
# elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(pnt, len);
# elif HAVE_WEAK_SYMBOLS
    SLSodium_memzero_as_a_weak_symbol_to_prevent_lto(pnt, len);
# else
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
# endif
}

# ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
SLSodium_dummy_symbol_to_prevent_memcmp_lto(const unsigned char *b1,
                                             const unsigned char *b2,
                                             const size_t         len)
{
    (void) b1;
    (void) b2;
    (void) len;
}
# endif

int
SLSodium_memcmp(const void *const b1_, const void *const b2_, size_t len)
{
# ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
# else
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
# endif
    size_t        i;
    unsigned char d = (unsigned char) 0U;

# if HAVE_WEAK_SYMBOLS
    SLSodium_dummy_symbol_to_prevent_memcmp_lto(b1, b2, len);
# endif
    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

# ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
SLSodium_dummy_symbol_to_prevent_compare_lto(const unsigned char *b1,
                                              const unsigned char *b2,
                                              const size_t         len)
{
    (void) b1;
    (void) b2;
    (void) len;
}
# endif

int
SLSodium_compare(const unsigned char *b1_, const unsigned char *b2_, size_t len)
{
# ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = b1_;
    const unsigned char *b2 = b2_;
# else
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
# endif
    unsigned char gt = 0U;
    unsigned char eq = 1U;
    size_t        i;

# if HAVE_WEAK_SYMBOLS
    SLSodium_dummy_symbol_to_prevent_compare_lto(b1, b2, len);
# endif
    i = len;
    while (i != 0U) {
        i--;
        gt |= ((b2[i] - b1[i]) >> 8) & eq;
        eq &= ((b2[i] ^ b1[i]) - 1) >> 8;
    }
    return (int) (gt + gt + eq) - 1;
}

int
SLSodium_is_zero(const unsigned char *n, const size_t nlen)
{
    size_t        i;
    unsigned char d = 0U;

    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
}

void
SLSodium_increment(unsigned char *n, const size_t nlen)
{
    size_t        i = 0U;
    uint_fast16_t c = 1U;

# ifdef HAVE_AMD64_ASM
    uint64_t t64, t64_2;
    uint32_t t32;

    if (nlen == 12U) {
        __asm__ __volatile__(
            "xorq %[t64], %[t64] \n"
            "xorl %[t32], %[t32] \n"
            "stc \n"
            "adcq %[t64], (%[out]) \n"
            "adcl %[t32], 8(%[out]) \n"
            : [t64] "=&r"(t64), [t32] "=&r"(t32)
            : [out] "D"(n)
            : "memory", "flags", "cc");
        return;
    } else if (nlen == 24U) {
        __asm__ __volatile__(
            "movq $1, %[t64] \n"
            "xorq %[t64_2], %[t64_2] \n"
            "addq %[t64], (%[out]) \n"
            "adcq %[t64_2], 8(%[out]) \n"
            "adcq %[t64_2], 16(%[out]) \n"
            : [t64] "=&r"(t64), [t64_2] "=&r"(t64_2)
            : [out] "D"(n)
            : "memory", "flags", "cc");
        return;
    } else if (nlen == 8U) {
        __asm__ __volatile__("incq (%[out]) \n"
                             :
                             : [out] "D"(n)
                             : "memory", "flags", "cc");
        return;
    }
# endif
    for (; i < nlen; i++) {
        c += (uint_fast16_t) n[i];
        n[i] = (unsigned char) c;
        c >>= 8;
    }
}

void
SLSodium_add(unsigned char *a, const unsigned char *b, const size_t len)
{
    size_t        i = 0U;
    uint_fast16_t c = 0U;

# ifdef HAVE_AMD64_ASM
    uint64_t t64, t64_2, t64_3;
    uint32_t t32;

    if (len == 12U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "movl 8(%[in]), %[t32] \n"
            "addq %[t64], (%[out]) \n"
            "adcl %[t32], 8(%[out]) \n"
            : [t64] "=&r"(t64), [t32] "=&r"(t32)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    } else if (len == 24U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "movq 8(%[in]), %[t64_2] \n"
            "movq 16(%[in]), %[t64_3] \n"
            "addq %[t64], (%[out]) \n"
            "adcq %[t64_2], 8(%[out]) \n"
            "adcq %[t64_3], 16(%[out]) \n"
            : [t64] "=&r"(t64), [t64_2] "=&r"(t64_2), [t64_3] "=&r"(t64_3)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    } else if (len == 8U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "addq %[t64], (%[out]) \n"
            : [t64] "=&r"(t64)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    }
# endif
    for (; i < len; i++) {
        c += (uint_fast16_t) a[i] + (uint_fast16_t) b[i];
        a[i] = (unsigned char) c;
        c >>= 8;
    }
}

#ifndef FL_EXCLUDE_FEATURE
/* Derived from original code by CodesInChaos */
char *
SLSodium_bin2hex(char *const hex, const size_t hex_maxlen,
                 const unsigned char *const bin, const size_t bin_len)
{
    size_t       i = (size_t) 0U;
    unsigned int x;
    int          b;
    int          c;

    if (bin_len >= SIZE_MAX / 2 || hex_maxlen <= bin_len * 2U) {
        Abort(); /* LCOV_EXCL_LINE */
    }
    while (i < bin_len) {
        c = bin[i] & 0xf;
        b = bin[i] >> 4;
        x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8 |
            (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
        i++;
    }
    hex[i * 2U] = 0U;

    return hex;
}

int
SLSodium_hex2bin(unsigned char *const bin, const size_t bin_maxlen,
                 const char *const hex, const size_t hex_len,
                 const char *const ignore, size_t *const bin_len,
                 const char **const hex_end)
{
    size_t        bin_pos = (size_t) 0U;
    size_t        hex_pos = (size_t) 0U;
    int           ret     = 0;
    unsigned char c;
    unsigned char c_acc = 0U;
    unsigned char c_alpha0, c_alpha;
    unsigned char c_num0, c_num;
    unsigned char c_val;
    unsigned char state = 0U;

    while (hex_pos < hex_len) {
        c        = (unsigned char) hex[hex_pos];
        c_num    = c ^ 48U;
        c_num0   = (c_num - 10U) >> 8;
        c_alpha  = (c & ~32U) - 55U;
        c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
        if ((c_num0 | c_alpha0) == 0U) {
            if (ignore != NULL && state == 0U && Strchr(ignore, c) != NULL) {
                hex_pos++;
                continue;
            }
            break;
        }
        c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
        if (bin_pos >= bin_maxlen) {
            ret   = -1;
            errno = ERANGE;
            break;
        }
        if (state == 0U) {
            c_acc = c_val * 16U;
        } else {
            bin[bin_pos++] = c_acc | c_val;
        }
        state = ~state;
        hex_pos++;
    }
    if (state != 0U) {
        hex_pos--;
    }
    if (hex_end != NULL) {
        *hex_end = &hex[hex_pos];
    }
    if (bin_len != NULL) {
        *bin_len = bin_pos;
    }
    return ret;
}
#endif /* FL_EXCLUDE_FEATURE */ 

#ifndef NO_SODIUM_MEMORY_MANAGEMENT
int
SLSodium_alloc_init(void)
{
# ifdef HAVE_ALIGNED_MALLOC
#  if defined(_SC_PAGESIZE)
    long page_size_ = Sysconf(_SC_PAGESIZE);
    if (page_size_ > 0L) {
        page_size = (size_t) page_size_;
    }
#  elif defined(WINAPI_DESKTOP)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    page_size = (size_t) si.dwPageSize;
#  endif
    if (page_size < CANARY_SIZE || page_size < sizeof(size_t)) {
        Abort(); /* LCOV_EXCL_LINE */
    }
# endif
    randombytes_buf(canary, sizeof canary);

    return 0;
}
#endif /* NO_SODIUM_MEMORY_MANAGEMENT */

#ifndef FL_EXCLUDE_FEATURE
int
SLSodium_mlock(void *const addr, const size_t len)
{
# if defined(MADV_DONTDUMP) && defined(HAVE_MADVISE)
    (void) madvise(addr, len, MADV_DONTDUMP);
# endif
# ifdef HAVE_MLOCK
    return mlock(addr, len);
# elif defined(WINAPI_DESKTOP)
    return -(VirtualLock(addr, len) == 0);
# else
    errno = ENOSYS;
    return -1;
# endif
}

int
SLSodium_munlock(void *const addr, const size_t len)
{
    SLSodium_memzero(addr, len);
# if defined(MADV_DODUMP) && defined(HAVE_MADVISE)
    (void) madvise(addr, len, MADV_DODUMP);
# endif
# ifdef HAVE_MLOCK
    return munlock(addr, len);
# elif defined(WINAPI_DESKTOP)
    return -(VirtualUnlock(addr, len) == 0);
# else
    errno = ENOSYS;
    return -1;
# endif
}

static int
SLMprotect_noaccess(void *ptr, size_t size)
{
# ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_NONE);
# elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_NOACCESS, &old) == 0);
# else
    errno = ENOSYS;
    return -1;
# endif
}

static int
SLMprotect_readonly(void *ptr, size_t size)
{
# ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_READ);
# elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_READONLY, &old) == 0);
# else
    errno = ENOSYS;
    return -1;
# endif
}

static int
SLMprotect_readwrite(void *ptr, size_t size)
{
# ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_READ | PROT_WRITE);
# elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_READWRITE, &old) == 0);
# else
    errno = ENOSYS;
    return -1;
# endif
}
#endif /* FL_EXCLUDE_FEATURE */ 

#ifndef NO_SODIUM_MEMORY_MANAGEMENT
# ifdef HAVE_ALIGNED_MALLOC

__attribute__((noreturn)) static void
_out_of_bounds(void)
{
#  ifdef SIGSEGV
    raise(SIGSEGV);
#  elif defined(SIGKILL)
    raise(SIGKILL);
#  endif
    Abort();
} /* LCOV_EXCL_LINE */

static inline size_t
_page_round(const size_t size)
{
    const size_t page_mask = page_size - 1U;

    return (size + page_mask) & ~page_mask;
}

static __attribute__((malloc)) unsigned char *
_alloc_aligned(const size_t size)
{
    void *ptr;

#  if defined(MAP_ANON) && defined(HAVE_MMAP)
    if ((ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_ANON | MAP_PRIVATE | MAP_NOCORE, -1, 0)) ==
        MAP_FAILED) {
        ptr = NULL; /* LCOV_EXCL_LINE */
    }               /* LCOV_EXCL_LINE */
#  elif defined(HAVE_POSIX_MEMALIGN)
    if (posix_memalign(&ptr, page_size, size) != 0) {
        ptr = NULL; /* LCOV_EXCL_LINE */
    }               /* LCOV_EXCL_LINE */
#  elif defined(WINAPI_DESKTOP)
    ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#  else
#   error Bug
#  endif
    return (unsigned char *) ptr;
}

static void
_free_aligned(unsigned char *const ptr, const size_t size)
{
#  if defined(MAP_ANON) && defined(HAVE_MMAP)
    (void) munmap(ptr, size);
#  elif defined(HAVE_POSIX_MEMALIGN)
    Free(ptr);
#  elif defined(WINAPI_DESKTOP)
    VirtualFree(ptr, 0U, MEM_RELEASE);
#  else
#   error Bug
# endif
}

static unsigned char *
_unprotected_ptr_from_user_ptr(void *const ptr)
{
    uintptr_t      unprotected_ptr_u;
    unsigned char *canary_ptr;
    size_t         page_mask;

    canary_ptr = ((unsigned char *) ptr) - sizeof canary;
    page_mask = page_size - 1U;
    unprotected_ptr_u = ((uintptr_t) canary_ptr & (uintptr_t) ~page_mask);
    if (unprotected_ptr_u <= page_size * 2U) {
        Abort(); /* LCOV_EXCL_LINE */
    }
    return (unsigned char *) unprotected_ptr_u;
}

# endif /* HAVE_ALIGNED_MALLOC */

# ifndef HAVE_ALIGNED_MALLOC
static __attribute__((malloc)) void *
SLSodium_malloc(const size_t size)
{
    return Malloc(size > (size_t) 0U ? size : (size_t) 1U);
}
# else
static __attribute__((malloc)) void *
SLSodium_malloc(const size_t size)
{
    void          *user_ptr;
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    size_t         size_with_canary;
    size_t         total_size;
    size_t         unprotected_size;

    if (size >= (size_t) SIZE_MAX - page_size * 4U) {
        errno = ENOMEM;
        return NULL;
    }
    if (page_size <= sizeof canary || page_size < sizeof unprotected_size) {
        Abort(); /* LCOV_EXCL_LINE */
    }
    size_with_canary = (sizeof canary) + size;
    unprotected_size = _page_round(size_with_canary);
    total_size       = page_size + page_size + unprotected_size + page_size;
    if ((base_ptr = _alloc_aligned(total_size)) == NULL) {
        return NULL; /* LCOV_EXCL_LINE */
    }
    unprotected_ptr = base_ptr + page_size * 2U;
    _mprotect_noaccess(base_ptr + page_size, page_size);
#  ifndef HAVE_PAGE_PROTECTION
    Memcpy(unprotected_ptr + unprotected_size, canary, sizeof canary);
#  endif
    _mprotect_noaccess(unprotected_ptr + unprotected_size, page_size);
    SLSodium_mlock(unprotected_ptr, unprotected_size);
    canary_ptr =
        unprotected_ptr + _page_round(size_with_canary) - size_with_canary;
    user_ptr = canary_ptr + sizeof canary;
    Memcpy(canary_ptr, canary, sizeof canary);
    Memcpy(base_ptr, &unprotected_size, sizeof unprotected_size);
    _mprotect_readonly(base_ptr, page_size);
    Assert(_unprotected_ptr_from_user_ptr(user_ptr) == unprotected_ptr);

    return user_ptr;
}
# endif /* !HAVE_ALIGNED_MALLOC */

__attribute__((malloc)) void *
SLSodium_malloc(const size_t size)
{
    void *ptr;

    if ((ptr = SLSodium_malloc(size)) == NULL) {
        return NULL;
    }
    Memset(ptr, (int) GARBAGE_VALUE, size);

    return ptr;
}

__attribute__((malloc)) void *
SLSodium_allocarray(size_t count, size_t size)
{
    size_t total_size;

    if (count > (size_t) 0U && size >= (size_t) SIZE_MAX / count) {
        errno = ENOMEM;
        return NULL;
    }
    total_size = count * size;

    return SLSodium_malloc(total_size);
}

# ifndef HAVE_ALIGNED_MALLOC
void
SLSodium_free(void *ptr)
{
    Free(ptr);
}
# else
void
SLSodium_free(void *ptr)
{
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    size_t         total_size;
    size_t         unprotected_size;

    if (ptr == NULL) {
        return;
    }
    canary_ptr      = ((unsigned char *) ptr) - sizeof canary;
    unprotected_ptr = _unprotected_ptr_from_user_ptr(ptr);
    base_ptr        = unprotected_ptr - page_size * 2U;
    Memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);
    total_size = page_size + page_size + unprotected_size + page_size;
    _mprotect_readwrite(base_ptr, total_size);
    if (SLSodium_memcmp(canary_ptr, canary, sizeof canary) != 0) {
        _out_of_bounds();
    }
#  ifndef HAVE_PAGE_PROTECTION
    if (SLSodium_memcmp(unprotected_ptr + unprotected_size, canary, sizeof canary) != 0) {
        _out_of_bounds();
    }
#  endif
    SLSodium_munlock(unprotected_ptr, unprotected_size);
    _free_aligned(base_ptr, total_size);
}
# endif /* HAVE_ALIGNED_MALLOC */

#endif /* NO_SODIUM_MEMORY_MANAGEMENT */

#ifndef FL_EXCLUDE_FEATURE
# ifndef HAVE_PAGE_PROTECTION
static int
SLSodium_mprotect(void *ptr, int (*cb)(void *ptr, size_t size))
{
    (void) ptr;
    (void) cb;
    errno = ENOSYS;
    return -1;
}
# else
static int
SLSodium_mprotect(void *ptr, int (*cb)(void *ptr, size_t size))
{
    unsigned char *base_ptr;
    unsigned char *unprotected_ptr;
    size_t         unprotected_size;

    unprotected_ptr = _unprotected_ptr_from_user_ptr(ptr);
    base_ptr        = unprotected_ptr - page_size * 2U;
    Memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);

    return cb(unprotected_ptr, unprotected_size);
}
# endif

int
SLSodium_mprotect_noaccess(void *ptr)
{
    return SLSodium_mprotect(ptr, SLMprotect_noaccess);
}

int
SLSodium_mprotect_readonly(void *ptr)
{
    return SLSodium_mprotect(ptr, SLMprotect_readonly);
}

int
SLSodium_mprotect_readwrite(void *ptr)
{
    return SLSodium_mprotect(ptr, SLMprotect_readwrite);
}
#endif /* FL_EXCLUDE_FEATURE */

#endif /* USE_SL_CHACHA20_POLY1305_IETF || USE_SL_SODIUM */
