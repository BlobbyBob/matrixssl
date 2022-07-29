/* psStat.h
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef INCLUDE_GUARD_PSSTAT_H
#define INCLUDE_GUARD_PSSTAT_H

typedef long long psStatItem_t;
typedef long double psStatItemFloat_t;

/* Macros for printf formatting. */
#define PR_PSSTAT "lld"
#define PR_PSSTATF "Lf"

typedef struct
{
    psStatItem_t min;
    psStatItem_t max;
    psStatItem_t sum;
    psStatItemFloat_t sumsq;
    psStatItem_t count;
} psStat_t;

psStat_t *psStatNew(void);
void psStatFree(psStat_t *stat);
psStat_t *psStatDup(psStat_t *stat);
void psStatInit(psStat_t *stat);
void psStatUpdate(psStat_t *stat, psStatItem_t new);
void psStatErase(psStat_t *stat);
int psStatIsClear(psStat_t * const stat);
psStatItem_t psStatGetCount(psStat_t * const stat);
psStatItem_t psStatGetSum(psStat_t * const stat);
psStatItemFloat_t psStatGetAverage(psStat_t * const stat);
psStatItem_t psStatGetMin(psStat_t * const stat);
psStatItem_t psStatGetMax(psStat_t * const stat);
psStatItemFloat_t psStatGetVariance(psStat_t * const stat);
psStatItemFloat_t psStatGetStdDeviation(psStat_t * const stat);

typedef enum
{
    PS_STAT_ID_UNDEFINED,
    PS_STAT_ID_CRYPT_AUTH_INIT,
    PS_STAT_ID_CIPHER_CONTINUE,
    PS_STAT_ID_CIPHER_CONTINUE_CBC_DEC,
    PS_STAT_ID_CIPHER_CONTINUE_CBC_ENC,
    PS_STAT_ID_CIPHER_FINISH,
    PS_STAT_ID_CIPHER_INIT,
    PS_STAT_ID_CIPHER_INIT_CBC_DEC,
    PS_STAT_ID_CIPHER_INIT_CBC_ENC,
    PS_STAT_ID_CRYPT_AUTH_CONTINUE,
    PS_STAT_ID_CRYPT_GCM_AAD_CONTINUE,
    PS_STAT_ID_CRYPT_GCM_AAD_FINISH,
    PS_STAT_ID_DECRYPT_AUTH_FINISH,
    PS_STAT_ID_DERIVE_TLS_PRF,
    PS_STAT_ID_ENCRYPT_AUTH_FINISH,
    PS_STAT_ID_ENCRYPT_AUTH_PACKET_FINISH,
    PS_STAT_ID_MAC_GENERATE_CONTINUE,
    PS_STAT_ID_MAC_GENERATE_FINISH,
    PS_STAT_ID_MAC_GENERATE_INIT,
    PS_STAT_ID_ASSET_FREE_LOCAL,
    PS_STAT_ID_ASSET_FREE,
    PS_STAT_ID_ASSET_STORE_STATUS,
    PS_STAT_ID_LIB_INIT,
    PS_STAT_ID_LIB_UNINIT,
    PS_STAT_ID_ROOT_KEY_ALLOCATE_AND_LOAD_VALUE,
    PS_STAT_ID_RBG_REQUEST_SECURITY_STRENGTH,
    PS_STAT_ID_RBG_USE_NONBLOCKING_ENTROPY_SOURCE,
    PS_STAT_ID_RBG_INSTALL_ENTROPY_SOURCE,
    PS_STAT_ID_LIB_ENTER_USER_ROLE,
    PS_STAT_ID_LIB_SELF_TEST,
    PS_STAT_ID_ASSET_ALLOCATE_BASIC,
    PS_STAT_ID_ASSET_ALLOCATE,
    PS_STAT_ID_ASSET_ALLOCATE_AND_ASSOCIATE_KEY_EXTRA,
    PS_STAT_ID_ASSET_LOAD_VALUE,
    PS_STAT_ID_ASSET_LOAD_MULTIPART,
    PS_STAT_ID_ASSET_LOAD_MULTIPART_CONVERT_BIG_INT,
    PS_STAT_ID_ASSET_LOAD_RANDOM,
    PS_STAT_ID_RBG_GENERATE_RANDOM,
    PS_STAT_ID_RBG_RESEED,
    PS_STAT_ID_ASSET_GENERATE_KEY_PAIR,
    PS_STAT_ID_ASSET_SHOW,
    PS_STAT_ID_ASSET_CHECK,
    PS_STAT_ID_MAC_VERIFY_INIT,
    PS_STAT_ID_MAC_VERIFY_CONTINUE,
    PS_STAT_ID_MAC_VERIFY_FINISH,
    PS_STAT_ID_HASH_INIT,
    PS_STAT_ID_HASH_CONTINUE,
    PS_STAT_ID_HASH_FINISH,
    PS_STAT_ID_HASH_SINGLE,
    PS_STAT_ID_RUNTIME_CONFIG_GET_PROPERTY,
    PS_STAT_ID_RUNTIME_CONFIG_SET_PROPERTY,
    PS_STAT_ID_ASSET_PEEK,
    PS_STAT_ID_ASSET_POKE,
    PS_STAT_ID_TRUSTED_KDK_DERIVE,
    PS_STAT_ID_TRUSTED_KEKDK_DERIVE,
    PS_STAT_ID_TRUSTED_KEY_DERIVE,
    PS_STAT_ID_KEY_DERIVE_KDK,
    PS_STAT_ID_KEY_DERIVE_PBKDF2,
    PS_STAT_ID_ASSETS_WRAP_RSA_OAEP,
    PS_STAT_ID_ASSETS_UNWRAP_RSA_OAEP,
    PS_STAT_ID_CRYPT_KW,
    PS_STAT_ID_ASSETS_WRAP_AES,
    PS_STAT_ID_ASSETS_WRAP_AES_38F,
    PS_STAT_ID_ASSETS_UNWRAP_AES,
    PS_STAT_ID_ASSETS_UNWRAP_AES_38F,
    PS_STAT_ID_ASSETS_WRAP_TRUSTED,
    PS_STAT_ID_ASSETS_UNWRAP_TRUSTED,
    PS_STAT_ID_PKCS1_RSAEP,
    PS_STAT_ID_PKCS1_RSADP,
    PS_STAT_ID_PKCS1_RSASP1,
    PS_STAT_ID_PKCS1_RSAVP1,
    PS_STAT_ID_ASSETS_WRAP_RSA_KEM,
    PS_STAT_ID_ASSETS_UNWRAP_RSA_KEM,
    PS_STAT_ID_ASSETS_WRAP_PKCS1V15,
    PS_STAT_ID_ASSETS_UNWRAP_PKCS1V15,
    PS_STAT_ID_HASH_SIGN_FIPS186_132,
    PS_STAT_ID_HASH_SIGN_FIPS186,
    PS_STAT_ID_HASH_SIGN_PKCS1,
    PS_STAT_ID_HASH_VERIFY_FIPS186_132,
    PS_STAT_ID_HASH_VERIFY_FIPS186,
    PS_STAT_ID_HASH_VERIFY_RECOVER_PKCS1,
    PS_STAT_ID_HASH_VERIFY_PKCS1,
    PS_STAT_ID_HASH_SIGN_PKCS1_PSS,
    PS_STAT_ID_HASH_VERIFY_PKCS1_PSS,
    PS_STAT_ID_DERIVE_DH,
    PS_STAT_ID_ENCRYPT_AUTH_INIT_RANDOM,
    PS_STAT_ID_ENCRYPT_AUTH_INIT_DETERMINISTIC,
    PS_STAT_ID_ASSET_COPY_VALUE,
    PS_STAT_ID_ASSET_ALLOCATE_SAME_POLICY,
    PS_STAT_ID_LOAD_FINISHED_HASH_STATE_ALGO,
    PS_STAT_ID_LOAD_FINISHED_HASH_STATE,
    PS_STAT_ID_HASH_FINISH_KEEP,
    PS_STAT_ID_IKE_PRF_EXTRACT,
    PS_STAT_ID_IKEV2_EXTRACT_SKEYSEED,
    PS_STAT_ID_IKEV1_EXTRACT_SKEYID_DSA,
    PS_STAT_ID_IKEV1_EXTRACT_SKEYID_PSK,
    PS_STAT_ID_IKEV1_EXTRACT_SKEYID_PKE,
    PS_STAT_ID_IKEV2_DERIVE_DKM,
    PS_STAT_ID_IKEV2_EXTRACT_SKEYSEED_REKEY,
    PS_STAT_ID_IKEV1_DERIVE_KEYING_MATERIAL,
    PS_STAT_ID_RBG_TEST_VECTOR,
    PS_STAT_ID_RBG_RAW_ENTROPY,
    PS_STAT_ID_ASSET_ALLOCATE_EX,
    PS_STAT_ID_ASSET_REBIND,
    PS_STAT_ID_ASSET_ALLOCATE_AND_ASSOCIATE_KEY_EXTRA_EX,
    PS_STAT_ID_DH_DERIVE,
    PS_STAT_ID_DH_KEYGEN,
    PS_STAT_ID_NUM
} psStatId_t;

const char *resolve_ps_stat_id(psStatId_t id);

typedef enum
{
    PS_STAT_EVENT_NORMAL_LOCK,
    PS_STAT_EVENT_NORMAL_UNLOCK,
    PS_STAT_EVENT_SKIP_LOCK,
    PS_STAT_EVENT_SKIP_UNLOCK,
    PS_STAT_EVENT_ERROR_CODE,
    PS_STAT_EVENT_TEMPORARIES_ACCESS,
    PS_STAT_EVENT_NUM
} psStatEvent_t;

/* Per function statistics. */
typedef struct
{
    psStat_t time;
    psStat_t size;
    psStat_t time_per_size;
    psStat_t wait_time;
} psStatTimeSizeItem_t;

typedef struct psStatTimeSize
{
    psStatTimeSizeItem_t stsi[(int)PS_STAT_ID_NUM];
    psStatItem_t events[(int)PS_STAT_ID_NUM][(int)PS_STAT_EVENT_NUM];
    struct psStatTimeSize *next;
} psStatTimeSize_t;

#ifdef USE_PS_STAT_CL
/* Only provide psGetThreadSts and depent functions if USE_PS_STAT_CL
   is set. */
psStatTimeSize_t *psGetThreadSts(void);
void psGetThreadStsUpdate(psStatId_t id, psStatItem_t time, psStatItem_t size);
void psGetThreadStsUpdateWait(psStatId_t id, psStatItem_t wait_time);
void psGetThreadStsUpdateEvent(psStatId_t id, psStatEvent_t e);
#endif /* USE_PS_STAT_CL */

typedef struct
{
    int filled;
    int num_diffs;
    int num_matches;
    int first_diff_ix;
    int last_diff_ix;
    int num_match_runs;
    int avg_match_run_len;
    int num_diff_runs;
    int avg_diff_run_len;
    /* Longest common substring (LCSS): */
    int lcss_start_ix;
    int lcss_end_ix;
    int lcss_len;
    int lcss_freq;
    /* Longest uncommon substring (LUSS): */
    int luss_start_ix;
    int luss_end_ix;
    int luss_len;
    int luss_freq;
    const unsigned char *a;
    const char *aName;
    const unsigned char *b;
    const char *bName;
    psSizeL_t len;
} psStatCompByteSeqResult_t;

typedef struct
{
    int lcss_max_prefix_len;
    int luss_max_prefix_len;
} psStatPrintCompByteSeqResultOpts_t;

/** Compare two byte sequences and compute statistics, such as the
    number of mismatches, the longest common subsequence, etc.
    The result can be printed with psPrintCompByteSeqResult. */
psStatCompByteSeqResult_t psStatCompByteSeq(const unsigned char *a,
        const char *aName,
        const unsigned char *b,
        const char *bName,
        psSizeL_t len);

/** Print the result of psStatByteSeq. */
void psStatPrintCompByteSeqResult(psStatCompByteSeqResult_t res,
        psStatPrintCompByteSeqResultOpts_t *opts);

/** Simple hex dump without extra printouts (c.f. psTraceBytes). */
void psStatPrintHexSimple(char *resultBuf,
        psSizeL_t resultBufLen,
        const unsigned char *bytes,
        psSizeL_t bytesLen);

#endif /* INCLUDE_GUARD_PSSTAT_H */

/* end of file psStat.h */
