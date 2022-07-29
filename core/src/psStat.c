/* psStat.c
 * Functions for computing misc useful statistics. Work-in-progress.
 *
 */

/*****************************************************************************
* Copyright (c) 2018 Rambus Inc. All Rights Reserved.
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
* commercial license for this software may be purchased from Rambus Inc at
* http://www.rambus.com/
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

#include "osdep.h"
#include "osdep_stdio.h"
#include "osdep_stdlib.h"
#include "osdep_string.h"
#include "osdep_math.h"
#include "psStat.h"
#include "psUtil.h"
#ifdef USE_PS_STAT_CL
#include "pthread.h"
#endif /* USE_PS_STAT_CL */

psStatCompByteSeqResult_t psStatCompByteSeq(const unsigned char *a,
        const char *aName,
        const unsigned char *b,
        const char *bName,
        psSizeL_t len)
{
    int i;
    int num_diffs = 0;
    int num_common = 0;
    int first_diff_ix = -1;
    int last_diff_ix = 0;
    int longest_diff_run = 0;
    int longest_diff_run_start = 0;
    int longest_match_run = 0;
    int longest_match_run_start = 0;
    int num_longest_match_runs = 0;
    int num_longest_diff_runs = 0;
    int run_len = 0;
    int run_start = 0;
    int num_match_runs = 0;
    int num_diff_runs = 0;
    int sum_match_runs = 0;
    int sum_diff_runs = 0;
    psStatCompByteSeqResult_t res;

    i = 0;
    while (i < len)
    {
        /* Handle runs of common bytes. */
        run_len = 0;
        run_start = i;
        while (i < len && a[i] == b[i])
        {
            i++;
            run_len++;
            num_common++;
            if (run_len > longest_match_run)
            {
                longest_match_run = run_len;
                longest_match_run_start = run_start;
                num_longest_match_runs = 1;
            }
            else if (run_len == longest_match_run)
            {
                num_longest_match_runs++;
            }
        }
        if (i < len)
        {
            num_match_runs++;
            sum_match_runs += run_len;
        }

        /* Handle runs of mismatching bytes. */
        run_len = 0;
        run_start = i;
        while (i < len && a[i] != b[i])
        {
            i++;
            run_len++;
            num_diffs++;
            if (run_len > longest_diff_run)
            {
                longest_diff_run = run_len;
                longest_diff_run_start = run_start;
                num_longest_diff_runs = 1;
            }
            else if (run_len == longest_diff_run)
            {
                num_longest_diff_runs++;
            }
            if (first_diff_ix == -1)
            {
                first_diff_ix = i;
            }
            last_diff_ix = i;
        }
        if (i < len)
        {
            num_diff_runs++;
            sum_diff_runs += run_len;
        }
    }

    psAssert(num_common + num_diffs == len);

    res.a = a;
    res.b = b;
    res.aName = aName;
    res.bName = bName;

    res.len = len;
    res.num_diffs = num_diffs;
    res.num_matches = num_common;
    res.first_diff_ix = first_diff_ix;
    res.last_diff_ix = last_diff_ix;

    res.luss_len = longest_diff_run;
    res.luss_start_ix = longest_diff_run_start;
    res.luss_end_ix =
        longest_diff_run_start + longest_diff_run;
    res.luss_freq = num_longest_diff_runs;

    res.lcss_len = longest_match_run;
    res.lcss_start_ix = longest_match_run_start;
    res.lcss_end_ix =
        longest_match_run_start + longest_match_run;
    res.lcss_freq = num_longest_match_runs;

    res.num_match_runs = num_match_runs;
    if (num_match_runs > 0)
        res.avg_match_run_len = (int)((double)sum_match_runs /
                (double)num_match_runs);
    else
        res.avg_match_run_len = 0;

    res.num_diff_runs = num_diff_runs;
    if (num_diff_runs > 0)
        res.avg_diff_run_len = (int)((double)sum_diff_runs /
                (double)num_diff_runs);
    else
        res.avg_diff_run_len = 0;

    res.filled = 1;

    return res;
}

void psStatPrintCompByteSeqResult(psStatCompByteSeqResult_t res,
        psStatPrintCompByteSeqResultOpts_t *opts)
{
    char buf[4096] = {0};
    char lcssBuf[1024] = {0};
    char lussBufA[1024] = {0};
    char lussBufB[1024] = {0};
    psSizeL_t lcssLen, lussLen;
    psStatPrintCompByteSeqResultOpts_t defaultOpts =
    {
        .lcss_max_prefix_len = 16,
        .luss_max_prefix_len = 16
    };

    if (res.filled != 1)
    {
        return;
    }

    if (opts == NULL)
    {
        opts = &defaultOpts;
    }
    psTraceBytes(res.aName, res.a, res.len);
    psTraceBytes(res.bName, res.b, res.len);

    /* Print prefixes of the longest common and uncommon substrings. */
    lcssLen = res.lcss_len;
    psStatPrintHexSimple(lcssBuf, sizeof(lcssBuf),
            &res.a[res.lcss_start_ix],
            PS_MIN(lcssLen, opts->lcss_max_prefix_len));
    lussLen = res.luss_len;
    psStatPrintHexSimple(lussBufA, sizeof(lussBufA),
            &res.a[res.luss_start_ix],
            PS_MIN(lussLen, opts->lcss_max_prefix_len));
    psStatPrintHexSimple(lussBufB, sizeof(lussBufB),
            &res.b[res.luss_start_ix],
            PS_MIN(lussLen, opts->lcss_max_prefix_len));

    Snprintf(buf,
            sizeof(buf),
            "Total length of compared sequence: %zu\n"  \
            " %d matches\n"                             \
            " %d mismatches\n"                          \
            "  First mismatch at #%d\n"                 \
            "  Last mistmatch at #%d\n"                 \
            " Substring stats:\n"                       \
            "  Number of common substrings: %d\n"       \
            "  Average common substring len: %d\n"      \
            "  Number of uncommon substrings: %d\n"     \
            "  Avarage uncommon substring len: %d\n"    \
            " Longest common substring:\n"              \
            "  length: %d (%d runs of this length)\n"   \
            "  position: #%d to #%d\n"                  \
            "  first bytes: %s\n"                       \
            " Longest uncommon substring:\n"            \
            "  length: %d (%d runs of this length)\n"   \
            "  position: #%d to #%d\n"                  \
            "  first bytes (a): %s\n"                   \
            "  first bytes (b): %s\n",
            res.len,
            res.num_matches,
            res.num_diffs,
            res.first_diff_ix,
            res.last_diff_ix,
            res.num_match_runs,
            res.avg_match_run_len,
            res.num_diff_runs,
            res.avg_diff_run_len,
            res.lcss_len,
            res.lcss_freq,
            res.lcss_start_ix,
            res.lcss_end_ix,
            lcssBuf,
            res.luss_len,
            res.luss_freq,
            res.luss_start_ix,
            res.luss_end_ix,
            lussBufA,
            lussBufB);

    psTraceStr("%s\n", buf);
}

void psStatPrintHexSimple(char *resultBuf,
        psSizeL_t resultBufLen,
        const unsigned char *bytes,
        psSizeL_t bytesLen)
{
    int i;
    int pos = 0;
    psSizeL_t remainingLen = resultBufLen;
    int rc;

    for (i = 0; i < bytesLen; i++)
    {
        rc = Snprintf(resultBuf + pos, remainingLen,
                "%.2hhx ", bytes[i]);
        if (rc < 0)
        {
            return;
        }
        pos += rc;
        remainingLen -= rc;
    }
}

# ifdef PS_STAT_TEST
psRes_t psStatTest(void)
{
    psStatCompByteSeqResult_t compRes;
    unsigned char test1[] =
        {
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        };
    unsigned char test2[] =
        {
            0xbb, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xaa, 0xbb,
        };
    unsigned char test3[] =
        {
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            0xcc, 0xbb, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xaa,
        };
    psStatPrintCompByteSeqResultOpts_t opts;

    compRes = psStatCompByteSeq(test1, "test1",
            test2, "test2",
            sizeof(test1));
    if (compres.lcss_len != 17)
    {
        return PS_FAILURE;
    }
    opts.lcss_max_prefix_len = 16;
    psPrintCompByteSeqResult(compRes, &opts);

    compRes = psStatCompByteSeq(test1, "test1",
            test3, "test3",
            sizeof(test1));
    if (compRes.lcss_len != 2)
    {
        return PS_FAILURE;
    }

    assert(compRes.lcss_len == 2);
    opts.lcss_max_prefix_len = 16;
    psPrintCompByteSeqResult(compRes, &opts);

    return PS_SUCCESS;
}
# endif /* PS_STAT_TEST */


void psStatInit(psStat_t *stat)
{
    if (stat)
    {
        Memset(stat, 0, sizeof(*stat));
        stat->sumsq = (psStatItemFloat_t)0.0;
    }
}

void psStatUpdate(psStat_t *stat, psStatItem_t new)
{
    psStatItemFloat_t newf = (psStatItemFloat_t) new;

    if (stat)
    {
        if (stat->count == 0)
        {
            stat->min = new;
            stat->max = new;
        }
        else
        {
            if (new < stat->min)
            {
                stat->min = new;
            }
            if (new > stat->max)
            {
                stat->max = new;
            }
        }
        stat->sum += new;
        stat->count += 1;
        stat->sumsq += newf * newf;
    }
}

void psStatErase(psStat_t *stat)
{
    psStatInit(stat); /* Initialization also erases. */
}

psStatItem_t psStatGetCount(psStat_t * const stat)
{
    return stat ? stat->count : 0;
}

int psStatIsClear(psStat_t * const stat)
{
    return psStatGetCount(stat) == 0;
}

psStatItem_t psStatGetSum(psStat_t * const stat)
{
    return stat ? stat->sum : 0;
}

psStatItem_t psStatGetMin(psStat_t * const stat)
{
    return stat ? stat->min : 0;
}

psStatItem_t psStatGetMax(psStat_t * const stat)
{
    return stat ? stat->max : 0;
}

static psStatItemFloat_t psStatGetNan(void)
{
#ifdef NAN
    return (psStatItemFloat_t) NAN;
#else
    return (psStatItemFloat_t) (0.0 / 0.0);
#endif
}

psStatItemFloat_t psStatGetAverage(psStat_t * const stat)
{
    psStatItem_t div = psStatGetCount(stat);
    psStatItemFloat_t sumf = (psStatItemFloat_t) psStatGetSum(stat);

    return div > 0 ? sumf / div : psStatGetNan();
}

psStatItemFloat_t psStatGetVariance(psStat_t * const stat)
{
    psStatItem_t div = psStatGetCount(stat);

    if (div > 0)
    {
        psStatItemFloat_t sumsqf;

        sumsqf = (psStatItemFloat_t) psStatGetSum(stat);
        sumsqf = sumsqf * sumsqf;

        return (stat->sumsq - (sumsqf / div)) / div;
    }
    return psStatGetNan();
}

psStatItemFloat_t psStatGetStdDeviation(psStat_t * const stat)
{
    long double __builtin_sqrtl(long double x);
    psStatItemFloat_t r = psStatGetVariance(stat);

    return __builtin_sqrtl(r); /* Note: Use built-in function to avoid need for -lm. On non-x86 platforms use sqrtl() instead and add -lm. */
}

psStat_t *psStatNew(void)
{
    psStat_t *stat = Malloc(sizeof(psStat_t));

    psStatInit(stat);
    return stat;
}

void psStatFree(psStat_t *stat)
{
    psStatErase(stat);
    Free(stat);
}

psStat_t *psStatDup(psStat_t *stat)
{
    psStat_t *newStat = NULL;

    if (stat)
    {
        newStat = psStatNew();

        if (newStat)
        {
            Memcpy(newStat, stat, sizeof(psStat_t));
        }
    }

    return newStat;
}

#ifdef USE_PS_STAT_CL
/* Only provide psGetThreadSts and depent functions if USE_PS_STAT_CL
   is set. */
static pthread_mutex_t stat_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static psStatTimeSize_t *stat_list = NULL;
static __thread psStatTimeSize_t *thread_sts = NULL;

psStatTimeSize_t *psGetThreadSts(void)
{
    psStatTimeSize_t *sts;
    int count = 0;

    sts = thread_sts;
    if (sts == NULL)
    {
        sts = malloc(sizeof(psStatTimeSize_t));

        if (sts)
        {
            int i;

            for(i = 0; i < (int) PS_STAT_ID_NUM; i++)
            {
                psStatInit(&sts->stsi[i].time);
                psStatInit(&sts->stsi[i].size);
                psStatInit(&sts->stsi[i].time_per_size);
            }
            sts->next = NULL;

            /* Add statistics to the global list. */
            pthread_mutex_lock(&stat_list_mutex);
            thread_sts = sts;
            if (stat_list == NULL)
            {
                stat_list = thread_sts;
            }
            else
            {
                psStatTimeSize_t *next_ptr = NULL;

                next_ptr = stat_list;
                while (next_ptr->next)
                {
                    count++;
                    next_ptr = next_ptr->next;
                }
                next_ptr->next = sts;
            }
            pthread_mutex_unlock(&stat_list_mutex);
        }
        else
        {
            fprintf(stderr, "Memory allocation error: statistics\n");
            exit(1);
        }
    }
    return sts;
}

void psGetThreadStsUpdate(psStatId_t id,
                          psStatItem_t time,
                          psStatItem_t size)
{
    psStatTimeSize_t *sts = psGetThreadSts();

    if (sts)
    {
        psStatTimeSizeItem_t *stsi = &sts->stsi[(int) id];

        psStatUpdate(&stsi->time, time);
        if (size > 0)
        {
            psStatItem_t time_per_size = time / size;

            psStatUpdate(&stsi->size, size);
            psStatUpdate(&stsi->time_per_size, time_per_size);
        }
    }
}

void psGetThreadStsUpdateWait(psStatId_t id, psStatItem_t wait_time)
{
    psStatTimeSize_t *sts = psGetThreadSts();

    if (sts)
    {
        psStatTimeSizeItem_t *stsi = &sts->stsi[(int) id];

        psStatUpdate(&stsi->wait_time, wait_time);
    }
}

void psGetThreadStsUpdateEvent(psStatId_t id, psStatEvent_t e)
{
    psStatTimeSize_t *sts = psGetThreadSts();

    if (sts)
    {
        sts->events[id][e] ++;
    }
}
#endif /* USE_PS_STAT_CL */

#include "osdep_math.h"
/* Print number that can be nan.
   If number is nan, always produce "NaN" as output. */
static char *printoptnan(char *buf, psStatItemFloat_t val)
{
    if (val == val)
    {
        /* Number. */
        sprintf(buf, "%.2"PR_PSSTATF, val);
    }
    else
    {
        /* Not a number. */
        memcpy(buf, "NaN", 4);
    }

    return buf;
}

const char *resolve_ps_stat_id(psStatId_t id)
{
    const char *name;

    switch(id)
    {
    case PS_STAT_ID_CRYPT_AUTH_INIT: name = "crypt_auth_init"; break;
    case PS_STAT_ID_CIPHER_INIT: name = "cipher_init"; break;
    case PS_STAT_ID_CIPHER_CONTINUE: name = "cipher_continue"; break;
    case PS_STAT_ID_CIPHER_FINISH: name = "cipher_finish"; break;
    case PS_STAT_ID_CIPHER_INIT_CBC_ENC: name = "cipher_init_cbc_enc"; break;
    case PS_STAT_ID_CIPHER_CONTINUE_CBC_ENC: name = "cipher_continue_cbc_enc"; break;
    case PS_STAT_ID_CIPHER_INIT_CBC_DEC: name = "cipher_init_cbc_dec"; break;
    case PS_STAT_ID_CIPHER_CONTINUE_CBC_DEC: name = "cipher_continue_cbc_dec"; break;
    case PS_STAT_ID_CRYPT_AUTH_CONTINUE: name = "crypt_auth_continue"; break;
    case PS_STAT_ID_CRYPT_GCM_AAD_CONTINUE: name = "crypt_gcm_aad_continue"; break;
    case PS_STAT_ID_CRYPT_GCM_AAD_FINISH: name = "crypt_gcm_aad_finish"; break;
    case PS_STAT_ID_DECRYPT_AUTH_FINISH: name = "decrypt_auth_finish"; break;
    case PS_STAT_ID_DERIVE_TLS_PRF: name = "derive_tls_prf"; break;
    case PS_STAT_ID_ENCRYPT_AUTH_FINISH: name = "encrypt_auth_finish"; break;
    case PS_STAT_ID_ENCRYPT_AUTH_PACKET_FINISH: name = "encrypt_auth_packet_finish"; break;
    case PS_STAT_ID_MAC_GENERATE_CONTINUE: name = "mac_generate_continue"; break;
    case PS_STAT_ID_MAC_GENERATE_FINISH: name = "mac_generate_finish"; break;
    case PS_STAT_ID_MAC_GENERATE_INIT: name = "mac_generate_init"; break;
    case PS_STAT_ID_ASSET_FREE_LOCAL: name = "asset_free_local"; break;
    case PS_STAT_ID_ASSET_FREE: name = "asset_free"; break;
    case PS_STAT_ID_ASSET_STORE_STATUS: name = "asset_store_status"; break;
    case PS_STAT_ID_LIB_INIT: name = "lib_init"; break;
    case PS_STAT_ID_LIB_UNINIT: name = "lib_uninit"; break;
    case PS_STAT_ID_ROOT_KEY_ALLOCATE_AND_LOAD_VALUE: name = "root_key_allocate_and_load_value"; break;
    case PS_STAT_ID_RBG_REQUEST_SECURITY_STRENGTH: name = "rbg_request_security_strength"; break;
    case PS_STAT_ID_RBG_USE_NONBLOCKING_ENTROPY_SOURCE: name = "rbg_use_nonblocking_entropy_source"; break;
    case PS_STAT_ID_RBG_INSTALL_ENTROPY_SOURCE: name = "rbg_install_entropy_source"; break;
    case PS_STAT_ID_LIB_ENTER_USER_ROLE: name = "lib_enter_user_role"; break;
    case PS_STAT_ID_LIB_SELF_TEST: name = "lib_self_test"; break;
    case PS_STAT_ID_ASSET_ALLOCATE_BASIC: name = "asset_allocate_basic"; break;
    case PS_STAT_ID_ASSET_ALLOCATE: name = "asset_allocate"; break;
    case PS_STAT_ID_ASSET_ALLOCATE_AND_ASSOCIATE_KEY_EXTRA: name = "asset_allocate_and_associate_key_extra"; break;
    case PS_STAT_ID_ASSET_LOAD_VALUE: name = "asset_load_value"; break;
    case PS_STAT_ID_ASSET_LOAD_MULTIPART: name = "asset_load_multipart"; break;
    case PS_STAT_ID_ASSET_LOAD_MULTIPART_CONVERT_BIG_INT: name = "asset_load_multipart_convert_big_int"; break;
    case PS_STAT_ID_ASSET_LOAD_RANDOM: name = "asset_load_random"; break;
    case PS_STAT_ID_RBG_GENERATE_RANDOM: name = "rbg_generate_random"; break;
    case PS_STAT_ID_RBG_RESEED: name = "rbg_reseed"; break;
    case PS_STAT_ID_ASSET_GENERATE_KEY_PAIR: name = "asset_generate_key_pair"; break;
    case PS_STAT_ID_ASSET_SHOW: name = "asset_show"; break;
    case PS_STAT_ID_ASSET_CHECK: name = "asset_check"; break;
    case PS_STAT_ID_MAC_VERIFY_INIT: name = "mac_verify_init"; break;
    case PS_STAT_ID_MAC_VERIFY_CONTINUE: name = "mac_verify_continue"; break;
    case PS_STAT_ID_MAC_VERIFY_FINISH: name = "mac_verify_finish"; break;
    case PS_STAT_ID_HASH_INIT: name = "hash_init"; break;
    case PS_STAT_ID_HASH_CONTINUE: name = "hash_continue"; break;
    case PS_STAT_ID_HASH_FINISH: name = "hash_finish"; break;
    case PS_STAT_ID_HASH_SINGLE: name = "hash_single"; break;
    case PS_STAT_ID_RUNTIME_CONFIG_GET_PROPERTY: name = "runtime_config_get_property"; break;
    case PS_STAT_ID_RUNTIME_CONFIG_SET_PROPERTY: name = "runtime_config_set_property"; break;
    case PS_STAT_ID_ASSET_PEEK: name = "asset_peek"; break;
    case PS_STAT_ID_ASSET_POKE: name = "asset_poke"; break;
    case PS_STAT_ID_TRUSTED_KDK_DERIVE: name = "trusted_kdk_derive"; break;
    case PS_STAT_ID_TRUSTED_KEKDK_DERIVE: name = "trusted_kekdk_derive"; break;
    case PS_STAT_ID_TRUSTED_KEY_DERIVE: name = "trusted_key_derive"; break;
    case PS_STAT_ID_KEY_DERIVE_KDK: name = "key_derive_kdk"; break;
    case PS_STAT_ID_KEY_DERIVE_PBKDF2: name = "key_derive_pbkdf2"; break;
    case PS_STAT_ID_ASSETS_WRAP_RSA_OAEP: name = "assets_wrap_rsa_oaep"; break;
    case PS_STAT_ID_ASSETS_UNWRAP_RSA_OAEP: name = "assets_unwrap_rsa_oaep"; break;
    case PS_STAT_ID_CRYPT_KW: name = "crypt_kw"; break;
    case PS_STAT_ID_ASSETS_WRAP_AES: name = "assets_wrap_aes"; break;
    case PS_STAT_ID_ASSETS_WRAP_AES_38F: name = "assets_wrap_aes_38f"; break;
    case PS_STAT_ID_ASSETS_UNWRAP_AES: name = "assets_unwrap_aes"; break;
    case PS_STAT_ID_ASSETS_UNWRAP_AES_38F: name = "assets_unwrap_aes_38f"; break;
    case PS_STAT_ID_ASSETS_WRAP_TRUSTED: name = "assets_wrap_trusted"; break;
    case PS_STAT_ID_ASSETS_UNWRAP_TRUSTED: name = "assets_unwrap_trusted"; break;
    case PS_STAT_ID_PKCS1_RSAEP: name = "pkcs1_rsaep"; break;
    case PS_STAT_ID_PKCS1_RSADP: name = "pkcs1_rsadp"; break;
    case PS_STAT_ID_PKCS1_RSASP1: name = "pkcs1_rsasp1"; break;
    case PS_STAT_ID_PKCS1_RSAVP1: name = "pkcs1_rsavp1"; break;
    case PS_STAT_ID_ASSETS_WRAP_RSA_KEM: name = "assets_wrap_rsa_kem"; break;
    case PS_STAT_ID_ASSETS_UNWRAP_RSA_KEM: name = "assets_unwrap_rsa_kem"; break;
    case PS_STAT_ID_ASSETS_WRAP_PKCS1V15: name = "assets_wrap_pkcs1v15"; break;
    case PS_STAT_ID_ASSETS_UNWRAP_PKCS1V15: name = "assets_unwrap_pkcs1v15"; break;
    case PS_STAT_ID_HASH_SIGN_FIPS186_132: name = "hash_sign_fips186_132"; break;
    case PS_STAT_ID_HASH_SIGN_FIPS186: name = "hash_sign_fips186"; break;
    case PS_STAT_ID_HASH_SIGN_PKCS1: name = "hash_sign_pkcs1"; break;
    case PS_STAT_ID_HASH_VERIFY_FIPS186_132: name = "hash_verify_fips186_132"; break;
    case PS_STAT_ID_HASH_VERIFY_FIPS186: name = "hash_verify_fips186"; break;
    case PS_STAT_ID_HASH_VERIFY_RECOVER_PKCS1: name = "hash_verify_recover_pkcs1"; break;
    case PS_STAT_ID_HASH_VERIFY_PKCS1: name = "hash_verify_pkcs1"; break;
    case PS_STAT_ID_HASH_SIGN_PKCS1_PSS: name = "hash_sign_pkcs1_pss"; break;
    case PS_STAT_ID_HASH_VERIFY_PKCS1_PSS: name = "hash_verify_pkcs1_pss"; break;
    case PS_STAT_ID_DERIVE_DH: name = "derive_dh"; break;
    case PS_STAT_ID_ENCRYPT_AUTH_INIT_RANDOM: name = "encrypt_auth_init_random"; break;
    case PS_STAT_ID_ENCRYPT_AUTH_INIT_DETERMINISTIC: name = "encrypt_auth_init_deterministic"; break;
    case PS_STAT_ID_ASSET_COPY_VALUE: name = "asset_copy_value"; break;
    case PS_STAT_ID_ASSET_ALLOCATE_SAME_POLICY: name = "asset_allocate_same_policy"; break;
    case PS_STAT_ID_LOAD_FINISHED_HASH_STATE_ALGO: name = "load_finished_hash_state_algo"; break;
    case PS_STAT_ID_LOAD_FINISHED_HASH_STATE: name = "load_finished_hash_state"; break;
    case PS_STAT_ID_HASH_FINISH_KEEP: name = "hash_finish_keep"; break;
    case PS_STAT_ID_IKE_PRF_EXTRACT: name = "ike_prf_extract"; break;
    case PS_STAT_ID_IKEV2_EXTRACT_SKEYSEED: name = "ikev2_extract_skeyseed"; break;
    case PS_STAT_ID_IKEV1_EXTRACT_SKEYID_DSA: name = "ikev1_extract_skeyid_dsa"; break;
    case PS_STAT_ID_IKEV1_EXTRACT_SKEYID_PSK: name = "ikev1_extract_skeyid_psk"; break;
    case PS_STAT_ID_IKEV1_EXTRACT_SKEYID_PKE: name = "ikev1_extract_skeyid_pke"; break;
    case PS_STAT_ID_IKEV2_DERIVE_DKM: name = "ikev2_derive_dkm"; break;
    case PS_STAT_ID_IKEV2_EXTRACT_SKEYSEED_REKEY: name = "ikev2_extract_skeyseed_rekey"; break;
    case PS_STAT_ID_IKEV1_DERIVE_KEYING_MATERIAL: name = "ikev1_derive_keying_material"; break;
    case PS_STAT_ID_RBG_TEST_VECTOR: name = "rbg_test_vector"; break;
    case PS_STAT_ID_ASSET_ALLOCATE_EX: name = "asset_allocate_ex"; break;
    case PS_STAT_ID_ASSET_REBIND: name = "asset_rebind"; break;
    case PS_STAT_ID_ASSET_ALLOCATE_AND_ASSOCIATE_KEY_EXTRA_EX: name = "asset_allocate_and_associate_key_extra_ex"; break;
    case PS_STAT_ID_DH_DERIVE: name = "dh_derive"; break;
    case PS_STAT_ID_DH_KEYGEN: name = "dh_keygen"; break;
    default: /* PS_STAT_ID_UNDEFINED etc. */
        name = "undefined";
    }

    return name;
}

static const char *resolve_ps_stat_event(psStatEvent_t event)
{
    const char *name;

    switch(event)
    {
    case PS_STAT_EVENT_NORMAL_LOCK: name = "locks"; break;
    case PS_STAT_EVENT_NORMAL_UNLOCK: name = "unlocks"; break;
    case PS_STAT_EVENT_SKIP_LOCK: name = "skip_lock"; break;
    case PS_STAT_EVENT_SKIP_UNLOCK: name = "skip_unlock"; break;
    case PS_STAT_EVENT_ERROR_CODE: name = "errors"; break;
    case PS_STAT_EVENT_TEMPORARIES_ACCESS: name = "temp_access"; break;
    default: /* PS_STAT_EVENT_UNDEFINED etc. */
        name = "undefined";
    }

    return name;
}

#ifdef USE_PS_STAT_CL
/* Dump CL statistics at the end of software binary execution.
   The intent is that statistics are not being updated during this function,
   but unfortunately, the function cannot prevent that from happening. In the
   most cases, operating system should call destructor when there is no longer
   active processing with threads.

   This destructor assumes standard IO can be performed while executing the
   destructor.
*/
void psDumpThreadSts(void) __attribute__((__destructor__));
void psDumpThreadSts(void)
{
    FILE *out = stderr;
    int thread_idx;
    int close_out = 0;
    psStatTimeSize_t *sts;
    int first = 1;

    if (getenv("STATS_FILE_APPEND") != NULL)
    {
        out = fopen(getenv("STATS_FILE_APPEND"), "a");
        if (out == NULL)
        {
            fprintf(stderr, "Cannot open %s for output; statistics skipped.\n",
                    getenv("STATS_FILE_APPEND"));
            return;
        }
        close_out = 1;
    }
    else if (getenv("STATS_FILE") != NULL)
    {
        out = fopen(getenv("STATS_FILE"), "w");
        if (out == NULL)
        {
            fprintf(stderr, "Cannot open %s for output; statistics skipped.\n",
                    getenv("STATS_FILE"));
            return;
        }
        close_out = 1;
    }
    
    pthread_mutex_lock(&stat_list_mutex);
    sts = stat_list;
    thread_idx = 0;
    while(sts != NULL)
    {
        int i;

        for(i = (int) PS_STAT_ID_UNDEFINED; i < (int) PS_STAT_ID_NUM; i++)
        {
            const char *name;
            psStatTimeSizeItem_t *stsi;
            char out2[100];
            char out3[100];
            psStat_t *s;

            name = resolve_ps_stat_id((psStatId_t) i);

            stsi = &sts->stsi[(int) i];
            s = &stsi->time;

            if (!psStatIsClear(s))
            {
                if (first)
                {
                    FILE *f;

                    fprintf(out, "---statistics---\n");
                    fprintf(out, "thread,stat,aspect,count,avg,min,max,std");
                    f = popen("cat /proc/cpuinfo | grep 'cpu MHz'", "r");
                    if (f)
                    {
                        char buf[128];
                        char *s;

                        memset(buf, 0, sizeof(buf));
                        s = fgets(buf, 100, f);
                        if (s)
                        {
                            s = strchr(buf, ':');
                        }
                        if (s)
                        {
                            fprintf(out, ",hz=%s", s + 2);
                        }
                        else
                        {
                            fprintf(out, "\n");
                        }
                        pclose(f);
                    }
                    else
                    {
                        fprintf(out, "\n");
                    }
                    first = 0;
                }
                fprintf(out,
                        "%d,%s,%s,%"PR_PSSTAT",%s,%"PR_PSSTAT",%"PR_PSSTAT
                        ",%s\n",
                        thread_idx,
                        name,
                        "time",
                        psStatGetCount(s),
                        printoptnan(out2, psStatGetAverage(s)),
                        psStatGetMin(s),
                        psStatGetMax(s),
                        printoptnan(out3, psStatGetStdDeviation(s)));

                s = &stsi->size;
                if (!psStatIsClear(s))
                {
                    fprintf(out,
                            "%d,%s,%s,%"PR_PSSTAT",%s,%"PR_PSSTAT",%"PR_PSSTAT
                            ",%s\n",
                            thread_idx,
                            name,
                            "size",
                            psStatGetCount(s),
                            printoptnan(out2, psStatGetAverage(s)),
                            psStatGetMin(s),
                            psStatGetMax(s),
                            printoptnan(out3, psStatGetStdDeviation(s)));
                }

                s = &stsi->time_per_size;
                if (!psStatIsClear(s))
                {
                    fprintf(out,
                            "%d,%s,%s,%"PR_PSSTAT",%s,%"PR_PSSTAT",%"PR_PSSTAT
                            ",%s\n",
                            thread_idx,
                            name,
                            "time_per_size",
                            psStatGetCount(s),
                            printoptnan(out2, psStatGetAverage(s)),
                            psStatGetMin(s),
                            psStatGetMax(s),
                            printoptnan(out3, psStatGetStdDeviation(s)));
                }

                s = &stsi->wait_time;
                if (!psStatIsClear(s))
                {
                    fprintf(out,
                            "%d,%s,%s,%"PR_PSSTAT",%s,%"PR_PSSTAT",%"PR_PSSTAT
                            ",%s\n",
                            thread_idx,
                            name,
                            "wait_time",
                            psStatGetCount(s),
                            printoptnan(out2, psStatGetAverage(s)),
                            psStatGetMin(s),
                            psStatGetMax(s),
                            printoptnan(out3, psStatGetStdDeviation(s)));
                }
            }
        }
        sts = sts->next;
        thread_idx ++;
    }
    if (first == 0)
    {
        fprintf(out, "---statistics---\n");
    }

    sts = stat_list;
    thread_idx = 0;
    first = 1;
    while(sts != NULL)
    {
        int i;
        int l;

        for(i = (int) PS_STAT_ID_UNDEFINED; i < (int) PS_STAT_ID_NUM; i++)
        {
            const char *name;
            char out2[100];

            name = resolve_ps_stat_id((psStatId_t) i);
            for (l = 0; l < (int) PS_STAT_EVENT_NUM; l++)
            {
                psStatItem_t event = sts->events[i][l];
                if (event > 0)
                {
                    if (first == 1)
                    {
                        fprintf(out, "---events---\n");
                        fprintf(out, "thread,stat");
                        for (l = 0; l < (int) PS_STAT_EVENT_NUM; l++)
                        {
                            fprintf(out, ",%s",
                                    resolve_ps_stat_event((psStatEvent_t) l));
                        }
                        fprintf(out, "\n");
                        first = 0;
                    }
                    fprintf(out, "%d,%s", thread_idx, name);
                    for (l = 0; l < (int) PS_STAT_EVENT_NUM; l++)
                    {
                        psStatItem_t event = sts->events[i][l];
                        fprintf(out, ",%"PR_PSSTAT, event);
                    }
                    fprintf(out, "\n");
                    break;
                }
            }
        }
        sts = sts->next;
        thread_idx ++;
    }
    if (first == 0)
    {
        fprintf(out, "---events---\n");
    }
    pthread_mutex_unlock(&stat_list_mutex);
    
    if (close_out)
    {
        fclose(out);
    }
}
#endif /* USE_PS_STAT_CL */

/* end of file psStat.c */
