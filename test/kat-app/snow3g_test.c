/*****************************************************************************
 Copyright (c) 2009-2024, Intel Corporation
 Copyright (c) 2022, Nokia

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "intel-ipsec-mb.h"

#include "utils.h"

#include "cipher_test.h"
#include "mac_test.h"

#define IMB_SNOW3G_PAD_LEN               16
#define IMB_SNOW3G_MAX_DATA_LEN          3048
#define IMB_SNOW3G_NUM_SUPPORTED_BUFFERS 16

static struct cipher_test *snow3g_f8_vectors;
static struct cipher_test *snow3g_f8_linear_vectors;

static int
load_snow3g_f8_vectors(struct test_json_alloc_ctx **ctx_f8, struct test_json_alloc_ctx **ctx_linear)
{
        if (load_cipher_vectors(kat_vector_dir, "snow3g_f8_test.json", &snow3g_f8_vectors, ctx_f8) <
            0)
                return -1;
        return load_cipher_vectors(kat_vector_dir, "snow3g_f8_linear_test.json",
                                   &snow3g_f8_linear_vectors, ctx_linear);
}

static void
free_snow3g_f8_vectors(struct test_json_alloc_ctx *ctx_f8, struct test_json_alloc_ctx *ctx_linear)
{
        json_free_test_ctx(ctx_f8);
        snow3g_f8_vectors = NULL;
        json_free_test_ctx(ctx_linear);
        snow3g_f8_linear_vectors = NULL;
}
static struct mac_test *snow3g_f9_vectors;

static void
free_snow3g_f9_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        snow3g_f9_vectors = NULL;
}

int
snow3g_test(struct IMB_MGR *mb_mgr);
static void
validate_snow3g_f8_1_block(struct IMB_MGR *mb_mgr, unsigned int job_api,
                           struct test_suite_context *uea2_ctx,
                           struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f8_2_blocks(struct IMB_MGR *mb_mgr, uint32_t job_api,
                            struct test_suite_context *uea2_ctx,
                            struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f8_4_blocks(struct IMB_MGR *mb_mgr, uint32_t job_api,
                            struct test_suite_context *uea2_ctx,
                            struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f8_8_blocks(struct IMB_MGR *mb_mgr, uint32_t job_api,
                            struct test_suite_context *uea2_ctx,
                            struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f8_8_blocks_multi_key(struct IMB_MGR *mb_mgr, uint32_t job_api,
                                      struct test_suite_context *uea2_ctx,
                                      struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f8_n_blocks(struct IMB_MGR *mb_mgr, uint32_t job_api,
                            struct test_suite_context *uea2_ctx,
                            struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f8_n_blocks_linear(struct IMB_MGR *mb_mgr, uint32_t job_api,
                                   struct test_suite_context *uea2_ctx,
                                   struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f8_n_blocks_linear_mkeys(struct IMB_MGR *mb_mgr, uint32_t job_api,
                                         struct test_suite_context *uea2_ctx,
                                         struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f8_n_blocks_multi(struct IMB_MGR *mb_mgr, uint32_t job_api,
                                  struct test_suite_context *uea2_ctx,
                                  struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f9(struct IMB_MGR *mb_mgr, uint32_t job_api, struct test_suite_context *uea2_ctx,
                   struct test_suite_context *uia2_ctx);
/* snow3g validation function pointer table */
struct {
        void (*func)(struct IMB_MGR *, uint32_t job_api, struct test_suite_context *uea2_ctx,
                     struct test_suite_context *uia2_ctx);
        const char *func_name;
} snow3g_func_tab[] = {
        { validate_snow3g_f8_1_block, "validate_snow3g_f8_1_block" },
        { validate_snow3g_f8_2_blocks, "validate_snow3g_f8_2_blocks" },
        { validate_snow3g_f8_4_blocks, "validate_snow3g_f8_4_blocks" },
        { validate_snow3g_f8_8_blocks, "validate_snow3g_f8_8_blocks" },
        { validate_snow3g_f8_8_blocks_multi_key, "validate_snow3g_f8_8_blocks_multi_key" },
        { validate_snow3g_f8_n_blocks, "validate_snow3g_f8_n_blocks" },
        { validate_snow3g_f8_n_blocks_linear, "validate_snow3g_f8_n_blocks_linear" },
        { validate_snow3g_f8_n_blocks_linear_mkeys,
          "validate_snow3g_f8_n_blocks_linear_multi_keys" },
        { validate_snow3g_f8_n_blocks_multi, "validate_snow3g_f8_n_blocks_multi" },
        { validate_snow3g_f9, "validate_snow3g_f9" }
};

struct cipher_iv_gen_params {
        size_t tcId;
        const char *count;
        const char *bearer;
        const char *dir;
};

struct hash_iv_gen_params {
        size_t tcId;
        const char *count;
        const char *fresh;
        const char *dir;
};

const struct cipher_iv_gen_params snow3g_iv_params_f8_json[] = {
        { 1, "\x00\x00\x00\x00", "\x00", "\x00" },
        { 3, "\x26\x6b\x55\xfa", "\x03", "\x01" },
        { 0, NULL, NULL, NULL }
};

const struct hash_iv_gen_params snow3g_iv_params_f9_json[] = {
        { 4, "\x41\x3e\x79\x14", "\xfd\xe8\x97\x03", "\x01" },
        { 5, "\x3c\x39\x6f\x29", "\x37\x77\x22\x6b", "\x01" },
        { 6, "\x3c\x39\x6f\x29", "\x37\x77\x22\x6b", "\x01" },
        { 0, NULL, NULL, NULL }
};

/******************************************************************************
 * @description - utility function to dump test buffers
 *
 * @param message [IN] - debug message to print
 * @param ptr [IN] - pointer to beginning of buffer.
 * @param len [IN] - length of buffer.
 ******************************************************************************/
static inline void
snow3g_hexdump(const char *message, const uint8_t *ptr, int len)
{
        int ctr;

        printf("%s:\n", message);
        for (ctr = 0; ctr < len; ctr++) {
                printf("0x%02X ", ptr[ctr] & 0xff);
                if (!((ctr + 1) % 16))
                        printf("\n");
        }
        printf("\n");
        printf("\n");
}

static inline int
submit_uea2_jobs(struct IMB_MGR *mb_mgr, snow3g_key_schedule_t *const *keys, uint8_t **const ivs,
                 uint8_t **const src, uint8_t **const dst, const uint32_t *bytelens,
                 const uint32_t *byte_offsets, const int dir, const unsigned int num_jobs)
{
        IMB_JOB *job;
        unsigned int i;
        unsigned int jobs_rx = 0;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_SNOW3G_UEA2;
                job->src = src[i];
                job->dst = dst[i];
                job->iv = ivs[i];
                job->iv_len_in_bytes = 16;
                job->enc_keys = keys[i];
                job->key_len_in_bytes = 16;

                job->cipher_start_src_offset_in_bytes = byte_offsets[i];
                job->msg_len_to_cipher_in_bytes = bytelens[i];
                job->hash_alg = IMB_AUTH_NULL;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (job->status != IMB_STATUS_COMPLETED) {
                                printf("%d error status:%d, job %u", __LINE__, job->status, i);
                                return -1;
                        }
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("%d error status:%d\n", __LINE__, job->status);
                        return -1;
                }
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                return -1;
        }

        return 0;
}

static inline int
submit_uia2_job(struct IMB_MGR *mb_mgr, uint8_t *key, uint8_t *iv, uint8_t *src, uint8_t *tag,
                const uint32_t byte_len, const uint8_t *exp_out, const int num_jobs)
{
        int i, err, jobs_rx = 0;
        IMB_JOB *job;

        /* flush the scheduler */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->src = src;
                job->u.SNOW3G_UIA2._iv = iv;
                job->u.SNOW3G_UIA2._key = key;

                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = byte_len;
                job->hash_alg = IMB_AUTH_SNOW3G_UIA2;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = 4;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        /* got job back */
                        jobs_rx++;
                        if (job->status != IMB_STATUS_COMPLETED) {
                                printf("%d error status:%d", __LINE__, job->status);
                                goto end;
                        }
                        /*Compare the digest with the expected in the vectors*/
                        if (memcmp(job->auth_tag_output, exp_out, IMB_SNOW3G_DIGEST_LEN) != 0) {
                                printf("IMB_AUTH_SNOW3G_UIA2 "
                                       "job num:%d\n",
                                       i);
                                snow3g_hexdump("Actual:", job->auth_tag_output,
                                               IMB_SNOW3G_DIGEST_LEN);
                                snow3g_hexdump("Expected:", exp_out, IMB_SNOW3G_DIGEST_LEN);
                                goto end;
                        }
                } else {
                        /* no job returned - check for error */
                        err = imb_get_errno(mb_mgr);
                        if (err != 0) {
                                printf("Error: %s!\n", imb_get_strerror(err));
                                goto end;
                        }
                }
        }

        /* flush any outstanding jobs */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                err = imb_get_errno(mb_mgr);
                if (err != 0) {
                        printf("Error: %s!\n", imb_get_strerror(err));
                        goto end;
                }

                if (memcmp(job->auth_tag_output, exp_out, IMB_SNOW3G_DIGEST_LEN) != 0) {
                        printf("IMB_AUTH_SNOW3G_UIA2 job num:%d\n", i);
                        snow3g_hexdump("Actual:", job->auth_tag_output, IMB_SNOW3G_DIGEST_LEN);
                        snow3g_hexdump("Expected:", exp_out, IMB_SNOW3G_DIGEST_LEN);
                        goto end;
                }
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }

        return 0;

end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        return -1;
}

static void
validate_snow3g_f8_1_block(struct IMB_MGR *mb_mgr, uint32_t job_api,
                           struct test_suite_context *uea2_ctx, struct test_suite_context *uia2_ctx)
{
        int numVectors = 0, i;
        size_t size = 0;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = IMB_KEY_256_BYTES;
        uint8_t srcBuff[IMB_SNOW3G_MAX_DATA_LEN];
        uint8_t dstBuff[IMB_SNOW3G_MAX_DATA_LEN];
        uint8_t *pSrcBuff = srcBuff;
        uint8_t *pIV = NULL;
        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_1_BUFFER (%s):\n", job_api ? "Job API" : "Direct API");
#endif

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(dstBuff, 0, sizeof(dstBuff));

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_1_buffer_exit;
        }

        pIV = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
        if (!pIV) {
                printf("malloc(pIV):failed !\n");
                goto snow3g_f8_1_buffer_exit;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pKey):failed !\n");
                goto snow3g_f8_1_buffer_exit;
        }
        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f8_1_buffer_exit;

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr)): failed!\n");
                goto snow3g_f8_1_buffer_exit;
        }

        /*Copy the data for for Snow3g 1 Packet version */
        for (i = 0; i < numVectors; i++) {
                const int length = (int) testVectors[i].msgSize / 8;

                memcpy(pKey, testVectors[i].key, testVectors->keySize / 8);
                memcpy(srcBuff, testVectors[i].msg, length);

                memcpy(pIV, testVectors[i].iv, testVectors->ivSize / 8);
                memcpy(dstBuff, testVectors[i].ct, length);

                /*setup the keysched to be used*/
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched) != 0) {
                        printf("CPU check failed\n");
                        goto snow3g_f8_1_buffer_exit;
                }

                /*Validate encrypt*/
                if (job_api) {
                        const uint32_t byte_len = (uint32_t) length;
                        const uint32_t byte_offset = 0;

                        submit_uea2_jobs(mb_mgr, &pKeySched, &pIV, &pSrcBuff, &pSrcBuff, &byte_len,
                                         &byte_offset, IMB_DIR_ENCRYPT, 1);
                }

                /*check against the ciphertext in the vector against the
                 * encrypted plaintext*/
                if (memcmp(srcBuff, dstBuff, length) != 0) {
                        printf("IMB_SNOW3G_F8_1_BUFFER(Enc) vector: %zu\n", testVectors[i].tcId);
                        snow3g_hexdump("Actual:", srcBuff, length);
                        snow3g_hexdump("Expected:", dstBuff, length);
                        goto snow3g_f8_1_buffer_exit;
                }

                memcpy(dstBuff, testVectors[i].msg, length);

                /*Validate Decrypt*/
                if (job_api) {
                        const uint32_t byte_len = (uint32_t) length;
                        const uint32_t byte_offset = 0;

                        submit_uea2_jobs(mb_mgr, &pKeySched, &pIV, &pSrcBuff, &pSrcBuff, &byte_len,
                                         &byte_offset, IMB_DIR_DECRYPT, 1);
                }

                if (memcmp(srcBuff, dstBuff, length) != 0) {
                        printf("IMB_SNOW3G_F8_1_BUFFER(Dec) vector: %zu\n", testVectors[i].tcId);
                        snow3g_hexdump("Actual:", srcBuff, length);
                        snow3g_hexdump("Expected:", dstBuff, length);
                        goto snow3g_f8_1_buffer_exit;
                }
        } /* for numVectors */

        /* no errors detected */
        status = 0;

snow3g_f8_1_buffer_exit:
        free(pIV);
        free(pKey);
        free(pKeySched);

        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f8_2_blocks(struct IMB_MGR *mb_mgr, uint32_t job_api,
                            struct test_suite_context *uea2_ctx,
                            struct test_suite_context *uia2_ctx)
{
        int i, j, numVectors = 0, numPackets = 2;
        size_t size = 0;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        snow3g_key_schedule_t *pKeySched[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pKey[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pSrcBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pDstBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pIV[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t packetLen[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_2_BUFFER: (%s):\n", job_api ? "Job API" : "Direct API");
#endif

        memset(pSrcBuff, 0, sizeof(pSrcBuff));
        memset(pDstBuff, 0, sizeof(pDstBuff));
        memset(pIV, 0, sizeof(pIV));
        memset(pKeySched, 0, sizeof(pKeySched));
        memset(pKey, 0, sizeof(pKey));

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_2_buffer_exit;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f8_2_buffer_exit;

        /* Test with all vectors */
        for (j = 0; j < numVectors; j++) {
                uint32_t bitOffsets[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
                uint32_t byteLens[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];

                const int length = (int) testVectors[j].msgSize / 8;

                /* Create test Data for num Packets */
                for (i = 0; i < numPackets; i++) {
                        packetLen[i] = length;
                        byteLens[i] = (uint32_t) length;
                        bitOffsets[i] = 0;

                        pKey[i] = malloc(IMB_KEY_256_BYTES);
                        if (!pKey[i]) {
                                printf("malloc(pKey[%d]):failed !\n", i);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        pKeySched[i] = malloc(size);
                        if (!pKeySched[i]) {
                                printf("malloc(pKeySched[%d]): failed !\n", i);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        pSrcBuff[i] = malloc(length);
                        if (!pSrcBuff[i]) {
                                printf("malloc(pSrcBuff[%d]):failed !\n", i);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        pDstBuff[i] = malloc(length);
                        if (!pDstBuff[i]) {
                                printf("malloc(pDstBuff[%d]):failed !\n", i);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                        if (!pIV[i]) {
                                printf("malloc(pIV[%d]):failed !\n", i);
                                goto snow3g_f8_2_buffer_exit;
                        }

                        memcpy(pKey[i], testVectors[j].key, testVectors[j].keySize / 8);

                        memcpy(pSrcBuff[i], testVectors[j].msg, length);

                        memset(pDstBuff[i], 0, length);

                        memcpy(pIV[i], testVectors[j].iv, testVectors[j].ivSize / 8);

                        /* init key shed */
                        if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                                printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                                goto snow3g_f8_2_buffer_exit;
                        }
                }

                /* TEST IN-PLACE ENCRYPTION/DECRYPTION */
                /*Test the encrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pSrcBuff, byteLens,
                                         bitOffsets, IMB_DIR_ENCRYPT, 2);

                /*compare the ciphertext with the encrypted plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pSrcBuff[i], testVectors[j].ct, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_2_BUFFER(Enc) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pSrcBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].ct,
                                               packetLen[i]);
                                goto snow3g_f8_2_buffer_exit;
                        }
                }

                /* Set the source buffer with ciphertext, and clear destination
                 * buffer */
                for (i = 0; i < numPackets; i++)
                        memcpy(pSrcBuff[i], testVectors[j].ct, length);

                /*Test the decrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pSrcBuff, byteLens,
                                         bitOffsets, IMB_DIR_DECRYPT, 2);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pSrcBuff[i], testVectors[j].msg, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_2_BUFFER(Dec) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pSrcBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].msg,
                                               packetLen[i]);
                                goto snow3g_f8_2_buffer_exit;
                        }
                }

                /* TEST OUT-OF-PLACE ENCRYPTION/DECRYPTION */
                /*Test the encrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_ENCRYPT, 2);

                /*compare the ciphertext with the encrypted plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pDstBuff[i], testVectors[j].ct, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_2_BUFFER(Enc) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].ct,
                                               packetLen[i]);
                                goto snow3g_f8_2_buffer_exit;
                        }
                }
                /* Set the source buffer with ciphertext, and clear destination
                 * buffer */
                for (i = 0; i < numPackets; i++) {
                        memcpy(pSrcBuff[i], testVectors[j].ct, length);
                        memset(pDstBuff[i], 0, length);
                }

                /*Test the decrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_DECRYPT, 2);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pDstBuff[i], testVectors[j].msg, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_2_BUFFER(Dec) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].msg,
                                               packetLen[i]);
                                goto snow3g_f8_2_buffer_exit;
                        }
                }
                /* free buffers before next iteration */
                for (i = 0; i < numPackets; i++) {
                        if (pKey[i] != NULL) {
                                free(pKey[i]);
                                pKey[i] = NULL;
                        }
                        if (pKeySched[i] != NULL) {
                                free(pKeySched[i]);
                                pKeySched[i] = NULL;
                        }
                        if (pSrcBuff[i] != NULL) {
                                free(pSrcBuff[i]);
                                pSrcBuff[i] = NULL;
                        }
                        if (pDstBuff[i] != NULL) {
                                free(pDstBuff[i]);
                                pDstBuff[i] = NULL;
                        }
                        if (pIV[i] != NULL) {
                                free(pIV[i]);
                                pIV[i] = NULL;
                        }
                }
        }

        /* no errors detected */
        status = 0;

snow3g_f8_2_buffer_exit:
        for (i = 0; i < numPackets; i++) {
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);
                if (pSrcBuff[i] != NULL)
                        free(pSrcBuff[i]);
                if (pDstBuff[i] != NULL)
                        free(pDstBuff[i]);
                if (pIV[i] != NULL)
                        free(pIV[i]);
        }
        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f8_4_blocks(struct IMB_MGR *mb_mgr, uint32_t job_api,
                            struct test_suite_context *uea2_ctx,
                            struct test_suite_context *uia2_ctx)
{
        int i, j, numVectors = 0, numPackets = 4;
        size_t size = 0;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        snow3g_key_schedule_t *pKeySched[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pKey[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pSrcBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pDstBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pIV[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t packetLen[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t bitOffsets[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t byteLens[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        int keyLen = IMB_KEY_256_BYTES;
        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_4_BUFFER: (%s):\n", job_api ? "Job API" : "Direct API");
#endif

        memset(pSrcBuff, 0, sizeof(pSrcBuff));
        memset(pDstBuff, 0, sizeof(pDstBuff));
        memset(pIV, 0, sizeof(pIV));
        memset(pKeySched, 0, sizeof(pKeySched));
        memset(pKey, 0, sizeof(pKey));

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_4_buffer_exit;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f8_4_buffer_exit;

        /* Test with all vectors */
        for (j = 0; j < numVectors; j++) {
                const int length = (int) testVectors[j].msgSize / 8;

                /* Create test Data for num Packets */
                for (i = 0; i < numPackets; i++) {
                        packetLen[i] = length;
                        byteLens[i] = (uint32_t) length;
                        bitOffsets[i] = 0;

                        pKey[i] = malloc(keyLen);
                        if (!pKey[i]) {
                                printf("malloc(pKey[%d]):failed !\n", i);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        pKeySched[i] = malloc(size);
                        if (!pKeySched[i]) {
                                printf("malloc(pKeySched[%d]): failed !\n", i);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        pSrcBuff[i] = malloc(length);
                        if (!pSrcBuff[i]) {
                                printf("malloc(pSrcBuff[%d]):failed !\n", i);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        pDstBuff[i] = malloc(length);
                        if (!pDstBuff[i]) {
                                printf("malloc(pDstBuff[%d]):failed !\n", i);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                        if (!pIV[i]) {
                                printf("malloc(pIV[%d]):failed !\n", i);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        memcpy(pKey[i], testVectors[j].key, testVectors[j].keySize / 8);

                        memcpy(pSrcBuff[i], testVectors[j].msg, length);

                        memset(pDstBuff[i], 0, length);

                        memcpy(pIV[i], testVectors[j].iv, testVectors[j].ivSize / 8);
                        /* init key shed */
                        if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                                printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                                goto snow3g_f8_4_buffer_exit;
                        }
                }

                /* TEST IN-PLACE ENCRYPTION/DECRYPTION */
                /*Test the encrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pSrcBuff, byteLens,
                                         bitOffsets, IMB_DIR_ENCRYPT, 4);

                /* compare the ciphertext with the encrypted plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pSrcBuff[i], testVectors[j].ct, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_4_BUFFER(Enc) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pSrcBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].ct,
                                               packetLen[i]);
                                goto snow3g_f8_4_buffer_exit;
                        }
                }

                /* Set the source buffer with ciphertext, and clear destination
                 * buffer */
                for (i = 0; i < numPackets; i++)
                        memcpy(pSrcBuff[i], testVectors[j].ct, length);

                /*Test the decrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pSrcBuff, byteLens,
                                         bitOffsets, IMB_DIR_DECRYPT, 4);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pSrcBuff[i], testVectors[j].msg, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_4_BUFFER(Dec) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pSrcBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].msg,
                                               packetLen[i]);
                                goto snow3g_f8_4_buffer_exit;
                        }
                }
                /* TEST OUT-OF-PLACE ENCRYPTION/DECRYPTION */
                /*Test the encrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_ENCRYPT, 4);

                /*compare the ciphertext with the encrypted plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pDstBuff[i], testVectors[j].ct, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_4_BUFFER(Enc) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].ct,
                                               packetLen[i]);
                                goto snow3g_f8_4_buffer_exit;
                        }
                }

                /* Set the source buffer with ciphertext, and clear destination
                 * buffer */
                for (i = 0; i < numPackets; i++) {
                        memcpy(pSrcBuff[i], testVectors[j].ct, length);
                        memset(pDstBuff[i], 0, length);
                }
                /*Test the decrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_DECRYPT, 4);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pDstBuff[i], testVectors[j].msg, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_4_BUFFER(Dec) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].msg,
                                               packetLen[i]);
                                goto snow3g_f8_4_buffer_exit;
                        }
                }
                /* free buffers before next iteration */
                for (i = 0; i < numPackets; i++) {
                        if (pKey[i] != NULL) {
                                free(pKey[i]);
                                pKey[i] = NULL;
                        }
                        if (pKeySched[i] != NULL) {
                                free(pKeySched[i]);
                                pKeySched[i] = NULL;
                        }
                        if (pSrcBuff[i] != NULL) {
                                free(pSrcBuff[i]);
                                pSrcBuff[i] = NULL;
                        }
                        if (pDstBuff[i] != NULL) {
                                free(pDstBuff[i]);
                                pDstBuff[i] = NULL;
                        }
                        if (pIV[i] != NULL) {
                                free(pIV[i]);
                                pIV[i] = NULL;
                        }
                }
        }

        /* use vectors[1] as it is large enough for test case */
        /* vectors are in bits used to round up to bytes */
        const int length = (int) testVectors[1].msgSize / 8;

        if (testVectors[1].msg == NULL)
                goto snow3g_f8_4_buffer_exit;

        /*Create test Data for num Packets*/
        for (i = 0; i < numPackets; i++) {
                /* Test for packets of different length. */
                packetLen[i] = length - (i * 12);
                byteLens[i] = packetLen[i];
                bitOffsets[i] = 0;

                pKey[i] = malloc(keyLen);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_4_buffer_exit;
                }
                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]): failed !\n", i);
                        goto snow3g_f8_4_buffer_exit;
                }
                pSrcBuff[i] = malloc(packetLen[i]);
                if (!pSrcBuff[i]) {
                        printf("malloc(pSrcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_4_buffer_exit;
                }
                pDstBuff[i] = malloc(packetLen[i]);
                if (!pDstBuff[i]) {
                        printf("malloc(pDstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_4_buffer_exit;
                }
                pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                if (!pIV[i]) {
                        printf("malloc(pIV[%d]):failed !\n", i);
                        goto snow3g_f8_4_buffer_exit;
                }
                memcpy(pKey[i], testVectors[1].key, testVectors[1].keySize / 8);

                memcpy(pSrcBuff[i], testVectors[1].msg, packetLen[i]);

                memset(pDstBuff[i], 0, packetLen[i]);

                memcpy(pIV[i], testVectors[1].iv, testVectors[1].ivSize / 8);

                /* init key shed */
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_4_buffer_exit;
                }
        }

        /* Test the encrypt */
        if (job_api)
                submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens, bitOffsets,
                                 IMB_DIR_ENCRYPT, 4);

        /*compare the ciphertext with the encrypted plaintext*/
        for (i = 0; i < numPackets; i++) {
                if (memcmp(pDstBuff[i], (const uint8_t *) testVectors[1].ct, packetLen[i]) != 0) {
                        printf("IMB_SNOW3G_F8_4_BUFFER(Enc, diff size) "
                               "vector:%d buffer:%d\n",
                               1, i);
                        snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", (const uint8_t *) testVectors[1].ct,
                                       packetLen[i]);
                        goto snow3g_f8_4_buffer_exit;
                }
        }

        /* no errors detected */
        status = 0;

snow3g_f8_4_buffer_exit:
        for (i = 0; i < numPackets; i++) {
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);
                if (pSrcBuff[i] != NULL)
                        free(pSrcBuff[i]);
                if (pDstBuff[i] != NULL)
                        free(pDstBuff[i]);
                if (pIV[i] != NULL)
                        free(pIV[i]);
        }
        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f8_8_blocks(struct IMB_MGR *mb_mgr, uint32_t job_api,
                            struct test_suite_context *uea2_ctx,
                            struct test_suite_context *uia2_ctx)
{
        int i, j, numVectors = 0, numPackets = 8;
        size_t size = 0;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        snow3g_key_schedule_t *pKeySched[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pKey[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pSrcBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pDstBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pIV[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t packetLen[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t bitOffsets[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t byteLens[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        int keyLen = IMB_KEY_256_BYTES;
        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_8_BUFFER: (%s):\n", job_api ? "Job API" : "Direct API");
#endif

        memset(pSrcBuff, 0, sizeof(pSrcBuff));
        memset(pDstBuff, 0, sizeof(pDstBuff));
        memset(pIV, 0, sizeof(pIV));
        memset(pKeySched, 0, sizeof(pKeySched));
        memset(pKey, 0, sizeof(pKey));

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_8_buffer_exit;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f8_8_buffer_exit;

        /* Test with all vectors */
        for (j = 0; j < numVectors; j++) {
                const int length = (int) testVectors[j].msgSize / 8;

                /* Create test Data for num Packets */
                for (i = 0; i < numPackets; i++) {
                        packetLen[i] = length;
                        byteLens[i] = (uint32_t) length;
                        bitOffsets[i] = 0;

                        pKey[i] = malloc(keyLen);
                        if (!pKey[i]) {
                                printf("malloc(pKey[%d]):failed !\n", i);
                                goto snow3g_f8_8_buffer_exit;
                        }
                        pKeySched[i] = malloc(size);
                        if (!pKeySched[i]) {
                                printf("malloc(pKeySched[%d]): failed !\n", i);
                                goto snow3g_f8_8_buffer_exit;
                        }
                        pSrcBuff[i] = malloc(length);
                        if (!pSrcBuff[i]) {
                                printf("malloc(pSrcBuff[%d]):failed !\n", i);
                                goto snow3g_f8_8_buffer_exit;
                        }
                        pDstBuff[i] = malloc(length);
                        if (!pDstBuff[i]) {
                                printf("malloc(pDstBuff[%d]):failed !\n", i);
                                goto snow3g_f8_8_buffer_exit;
                        }
                        pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                        if (!pIV[i]) {
                                printf("malloc(pIV[%d]):failed !\n", i);
                                goto snow3g_f8_8_buffer_exit;
                        }
                        memcpy(pKey[i], testVectors[j].key, testVectors[j].keySize / 8);

                        memcpy(pSrcBuff[i], testVectors[j].msg, length);

                        memset(pDstBuff[i], 0, length);

                        memcpy(pIV[i], testVectors[j].iv, testVectors[j].ivSize / 8);

                        /* init key shed */
                        if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                                printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                                goto snow3g_f8_8_buffer_exit;
                        }
                }

                /*Test the encrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_ENCRYPT, 8);

                /*compare the ciphertext with the encrypted plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pDstBuff[i], testVectors[j].ct, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_8_BUFFER(Enc) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].ct,
                                               packetLen[i]);
                                goto snow3g_f8_8_buffer_exit;
                        }
                }

                /*Test the decrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pDstBuff, pSrcBuff, byteLens,
                                         bitOffsets, IMB_DIR_DECRYPT, 8);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(pSrcBuff[i], testVectors[j].msg, packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_8_BUFFER(Dec) vector:%zu "
                                       "buffer:%d\n",
                                       testVectors[j].tcId, i);
                                snow3g_hexdump("Actual:", pSrcBuff[i], packetLen[i]);
                                snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].msg,
                                               packetLen[i]);
                                goto snow3g_f8_8_buffer_exit;
                        }
                }
                /* free buffers before next iteration */
                for (i = 0; i < numPackets; i++) {
                        if (pKey[i] != NULL) {
                                free(pKey[i]);
                                pKey[i] = NULL;
                        }
                        if (pKeySched[i] != NULL) {
                                free(pKeySched[i]);
                                pKeySched[i] = NULL;
                        }
                        if (pSrcBuff[i] != NULL) {
                                free(pSrcBuff[i]);
                                pSrcBuff[i] = NULL;
                        }
                        if (pDstBuff[i] != NULL) {
                                free(pDstBuff[i]);
                                pDstBuff[i] = NULL;
                        }
                        if (pIV[i] != NULL) {
                                free(pIV[i]);
                                pIV[i] = NULL;
                        }
                }
        }
        /* use vectors[1] as it is large enough for test case */
        /* vectors are in bits used to round up to bytes */
        const int length = (int) testVectors[1].msgSize / 8;

        if (testVectors[1].msg == NULL)
                goto snow3g_f8_8_buffer_exit;

        /*Create test Data for num Packets*/
        for (i = 0; i < numPackets; i++) {
                /* Test for packets of different length. */
                packetLen[i] = length - (i * 12);
                byteLens[i] = packetLen[i];
                bitOffsets[i] = 0;

                pKey[i] = malloc(keyLen);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_exit;
                }
                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]): failed !\n", i);
                        goto snow3g_f8_8_buffer_exit;
                }
                pSrcBuff[i] = malloc(packetLen[i]);
                if (!pSrcBuff[i]) {
                        printf("malloc(pSrcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_exit;
                }
                pDstBuff[i] = malloc(packetLen[i]);
                if (!pDstBuff[i]) {
                        printf("malloc(pDstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_exit;
                }
                pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                if (!pIV[i]) {
                        printf("malloc(pIV[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_exit;
                }
                memcpy(pKey[i], testVectors[1].key, testVectors[1].keySize / 8);

                memcpy(pSrcBuff[i], testVectors[1].msg, packetLen[i]);

                memset(pDstBuff[i], 0, packetLen[i]);

                memcpy(pIV[i], testVectors[1].iv, testVectors[1].ivSize / 8);

                /* init key shed */
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_8_buffer_exit;
                }
        }

        /* Test the encrypt */
        if (job_api)
                submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens, bitOffsets,
                                 IMB_DIR_ENCRYPT, 8);

        /*compare the ciphertext with the encrypted plaintext*/
        for (i = 0; i < numPackets; i++) {
                if (memcmp(pDstBuff[i], testVectors[1].ct, packetLen[i]) != 0) {
                        printf("IMB_SNOW3G_F8_8_BUFFER(Enc, diff size) "
                               "vector:%d buffer:%d\n",
                               1, i);
                        snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", (const uint8_t *) testVectors[1].ct,
                                       packetLen[i]);
                        goto snow3g_f8_8_buffer_exit;
                }
        }
        /* no errors detected */
        status = 0;

snow3g_f8_8_buffer_exit:
        for (i = 0; i < numPackets; i++) {
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);
                if (pSrcBuff[i] != NULL)
                        free(pSrcBuff[i]);
                if (pDstBuff[i] != NULL)
                        free(pDstBuff[i]);
                if (pIV[i] != NULL)
                        free(pIV[i]);
        }

        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f8_8_blocks_multi_key(struct IMB_MGR *mb_mgr, uint32_t job_api,
                                      struct test_suite_context *uea2_ctx,
                                      struct test_suite_context *uia2_ctx)
{
        int length, i, j, numVectors = 0;
        const int numPackets = 8;
        size_t size = 0;

        const struct cipher_test *testVectors = snow3g_f8_vectors;

        snow3g_key_schedule_t *pKeySched[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pKey[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pSrcBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pDstBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pIV[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t packetLen[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t bitOffsets[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t byteLens[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];

        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_8_BUFFER_MULTIKEY: (%s):\n",
               job_api ? "Job API" : "Direct API");
#endif

        memset(pSrcBuff, 0, sizeof(pSrcBuff));
        memset(pDstBuff, 0, sizeof(pDstBuff));
        memset(pIV, 0, sizeof(pIV));
        memset(pKey, 0, sizeof(pKey));
        memset(packetLen, 0, sizeof(packetLen));
        memset(pKeySched, 0, sizeof(pKeySched));

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_8_buffer_multikey_exit;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                printf("snow3g_key_sched_multi_size() failure !\n");
                goto snow3g_f8_8_buffer_multikey_exit;
        }

        /* Test with all vectors */
        for (i = 0; i < numPackets; i++) {
                j = i % numVectors;

                length = (int) testVectors[j].msgSize / 8;
                packetLen[i] = length;
                byteLens[i] = (uint32_t) length;
                bitOffsets[i] = 0;

                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                pSrcBuff[i] = malloc(length);
                if (!pSrcBuff[i]) {
                        printf("malloc(pSrcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                pDstBuff[i] = malloc(length);
                if (!pDstBuff[i]) {
                        printf("malloc(pDstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                pKey[i] = malloc(testVectors[j].keySize / 8);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                if (!pIV[i]) {
                        printf("malloc(pIV[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }

                memcpy(pKey[i], testVectors[j].key, testVectors[j].keySize / 8);

                memcpy(pSrcBuff[i], testVectors[j].msg, length);

                memcpy(pIV[i], testVectors[j].iv, testVectors[j].ivSize / 8);

                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
        }

        /*Test the encrypt*/
        if (job_api)
                submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens, bitOffsets,
                                 IMB_DIR_ENCRYPT, 8);

        /*compare the ciphertext with the encrypted plaintext*/
        for (i = 0; i < numPackets; i++) {
                j = i % numVectors;

                if (memcmp(pDstBuff[i], testVectors[j].ct, packetLen[i]) != 0) {
                        printf("snow3g_f8_8_multi_buffer(Enc) vector:%zu "
                               "buffer:%d\n",
                               testVectors[j].tcId, i);
                        snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].ct,
                                       packetLen[i]);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
        }

        /*Test the decrypt*/
        if (job_api)
                submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens, bitOffsets,
                                 IMB_DIR_DECRYPT, 8);

        /*Compare the plaintext with the decrypted ciphertext*/
        for (i = 0; i < numPackets; i++) {
                j = i % numVectors;

                if (memcmp(pSrcBuff[i], testVectors[j].msg, packetLen[i]) != 0) {
                        printf("snow3g_f8_8_multi_buffer(Dec) vector:%zu "
                               "buffer:%d\n",
                               testVectors[j].tcId, i);
                        snow3g_hexdump("Actual:", pSrcBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].msg,
                                       packetLen[i]);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
        }
        /* no errors detected */
        status = 0;

snow3g_f8_8_buffer_multikey_exit:
        for (i = 0; i < numPackets; i++) {
                if (pSrcBuff[i] != NULL)
                        free(pSrcBuff[i]);
                if (pDstBuff[i] != NULL)
                        free(pDstBuff[i]);
                if (pIV[i] != NULL)
                        free(pIV[i]);
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);
        }

        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f8_n_blocks(struct IMB_MGR *mb_mgr, uint32_t job_api,
                            struct test_suite_context *uea2_ctx,
                            struct test_suite_context *uia2_ctx)
{
        int numVectors = 0, i, numPackets = IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
        size_t size = 0;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        snow3g_key_schedule_t *pKeySched[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pKey[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pSrcBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pDstBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pIV[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t packetLen[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t bitOffsets[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t byteLens[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        int keyLen = IMB_KEY_256_BYTES;
        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_N_BUFFER: (%s):\n", job_api ? "Job API" : "Direct API");
#endif

        memset(pSrcBuff, 0, sizeof(pSrcBuff));
        memset(pDstBuff, 0, sizeof(pDstBuff));
        memset(pIV, 0, sizeof(pIV));
        memset(pKey, 0, sizeof(pKey));
        memset(packetLen, 0, sizeof(packetLen));
        memset(pKeySched, 0, sizeof(pKeySched));

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_n_buffer_exit;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f8_n_buffer_exit;

        /*vectors are in bits used to round up to bytes*/
        const int length = (int) testVectors[0].msgSize / 8;

        /*Create test Data for num Packets*/
        for (i = 0; i < numPackets; i++) {

                packetLen[i] = length;
                byteLens[i] = (uint32_t) length;
                bitOffsets[i] = 0;

                pKey[i] = malloc(keyLen);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_exit;
                }
                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]): failed !\n", i);
                        goto snow3g_f8_n_buffer_exit;
                }
                pSrcBuff[i] = malloc(length);
                if (!pSrcBuff[i]) {
                        printf("malloc(pSrcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_exit;
                }
                pDstBuff[i] = malloc(length);
                if (!pDstBuff[i]) {
                        printf("malloc(pDstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_exit;
                }
                pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                if (!pIV[i]) {
                        printf("malloc(pIV[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_exit;
                }

                memcpy(pKey[i], testVectors[0].key, testVectors[0].keySize / 8);

                memcpy(pSrcBuff[i], testVectors[0].msg, length);

                memset(pDstBuff[i], 0, length);

                memcpy(pIV[i], testVectors[0].iv, testVectors[0].ivSize / 8);

                /* init key shed */
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_n_buffer_exit;
                }
        }

        for (i = 0; i < IMB_SNOW3G_NUM_SUPPORTED_BUFFERS; i++) {
                /*Test the encrypt*/
                if (job_api) {
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_ENCRYPT, i + 1);
                }

                /*Compare the data in the pDstBuff with the cipher pattern*/
                if (memcmp(testVectors[0].ct, pDstBuff[i], packetLen[i]) != 0) {
                        printf("IMB_SNOW3G_F8_N_BUFFER(Enc) , vector:%d\n", i);
                        snow3g_hexdump("Actual:", pDstBuff[i], packetLen[0]);
                        snow3g_hexdump("Expected:", (const uint8_t *) testVectors[0].ct,
                                       packetLen[0]);
                        goto snow3g_f8_n_buffer_exit;
                }

                /*Test the Decrypt*/
                if (job_api) {
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_DECRYPT, i + 1);
                }

                /*Compare the data in the pSrcBuff with the pDstBuff*/
                if (memcmp(pSrcBuff[i], testVectors[0].msg, packetLen[i]) != 0) {
                        printf("snow3g_f8_n_buffer equal sizes, vector:%d\n", i);
                        snow3g_hexdump("Actual:", pSrcBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", (const uint8_t *) testVectors[0].msg,
                                       packetLen[0]);
                        goto snow3g_f8_n_buffer_exit;
                }
        }
        /* no errors detected */
        status = 0;

snow3g_f8_n_buffer_exit:
        for (i = 0; i < numPackets; i++) {
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);
                if (pSrcBuff[i] != NULL)
                        free(pSrcBuff[i]);
                if (pDstBuff[i] != NULL)
                        free(pDstBuff[i]);
                if (pIV[i] != NULL)
                        free(pIV[i]);
        }

        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f8_n_blocks_linear(struct IMB_MGR *mb_mgr, uint32_t job_api,
                                   struct test_suite_context *uea2_ctx,
                                   struct test_suite_context *uia2_ctx)
{
        int i, j, numPackets = IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
        size_t size = 0;
        const struct cipher_test *testVectors = snow3g_f8_linear_vectors;

        snow3g_key_schedule_t *pKeySched[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pKey[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pSrcBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pDstBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pSrcBuff_const[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pDstBuff_const[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pIV[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t packetLen[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t bitOffsets[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t byteLens[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        int keyLen = IMB_KEY_256_BYTES;
        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_N_BUFFER: (%s):\n", job_api ? "Job API" : "Direct API");
#endif
        memset(pSrcBuff, 0, sizeof(pSrcBuff));
        memset(pSrcBuff_const, 0, sizeof(pSrcBuff_const));
        memset(pDstBuff, 0, sizeof(pDstBuff));
        memset(pDstBuff_const, 0, sizeof(pDstBuff_const));
        memset(pIV, 0, sizeof(pIV));
        memset(pKey, 0, sizeof(pKey));
        memset(packetLen, 0, sizeof(packetLen));
        memset(pKeySched, 0, sizeof(pKeySched));

        /* use first vector for all tests */
        if (testVectors[0].msg == NULL) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_n_buffer_linear_exit;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f8_n_buffer_linear_exit;

        /* Create test Data for num Packets*/
        for (i = 0; i < numPackets; i++) {
                /*vectors are in bits used to round up to bytes*/
                const int length = (int) testVectors[0].msgSize / 8;

                packetLen[i] = length;
                byteLens[i] = (uint32_t) length;
                bitOffsets[i] = 0;

                pKey[i] = malloc(keyLen);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_linear_exit;
                }
                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]): failed !\n", i);
                        goto snow3g_f8_n_buffer_linear_exit;
                }
                pSrcBuff[i] = malloc(length);
                if (!pSrcBuff[i]) {
                        printf("malloc(pSrcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_linear_exit;
                }
                pDstBuff[i] = malloc(length);
                if (!pDstBuff[i]) {
                        printf("malloc(pDstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_linear_exit;
                }
                pSrcBuff_const[i] = malloc(length);
                if (!pSrcBuff_const[i]) {
                        printf("malloc(pSrcBuff_const[%d]): failed !\n", i);
                        goto snow3g_f8_n_buffer_linear_exit;
                }
                pDstBuff_const[i] = malloc(length);
                if (!pDstBuff_const[i]) {
                        printf("malloc(pDstBuff_const[%d]): failed !\n", i);
                        goto snow3g_f8_n_buffer_linear_exit;
                }
                pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                if (!pIV[i]) {
                        printf("malloc(pIV[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_linear_exit;
                }

                memcpy(pKey[i], testVectors[0].key, testVectors[0].keySize / 8);

                memset(pSrcBuff[i], 0, length);
                memcpy(pSrcBuff_const[i], testVectors[0].msg, length);

                memset(pDstBuff[i], 0, length);
                memcpy(pDstBuff_const[i], testVectors[0].ct, length);

                memcpy(pIV[i], testVectors[0].iv, testVectors[0].ivSize / 8);

                /* init key shed */
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_n_buffer_linear_exit;
                }
        }

        for (i = 0; i < numPackets; i++) {
                const char *fn_name = "submit_uea2_jobs";

                const int length = (int) testVectors[0].msgSize / 8;

                for (j = 0; j < i; j++) {
                        /* Cleanup previous values */
                        memset(pSrcBuff[j], 0, length);
                        memset(pDstBuff[j], 0, length);
                }

                /*Test the encrypt*/
                if (job_api) {
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff_const, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_ENCRYPT, i + 1);
                }

                /*Compare the data in the pDstBuff with the cipher pattern*/
                for (j = 0; j < i; j++) {
                        if (memcmp(pDstBuff_const[j], pDstBuff[j], packetLen[j]) != 0) {
                                printf("%s(Enc) %s nb_packets:%d vector:%d\n", fn_name, __func__, i,
                                       j);
                                snow3g_hexdump("Actual:", pDstBuff[j], packetLen[j]);
                                snow3g_hexdump("Expected:", pDstBuff_const[j], packetLen[j]);
                        }
                }

                /*Test the Decrypt*/
                if (job_api) {
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pDstBuff_const, pSrcBuff, byteLens,
                                         bitOffsets, IMB_DIR_DECRYPT, i + 1);
                }

                /*Compare the data in the pSrcBuff with the pDstBuff*/
                for (j = 0; j < i; j++) {
                        if (memcmp(pSrcBuff[j], pSrcBuff_const[j], packetLen[j]) != 0) {
                                printf("%s(Dec) %s nb_packets:%d vector:%d\n", fn_name, __func__, i,
                                       j);
                                snow3g_hexdump("Actual:", pSrcBuff[j], packetLen[j]);
                                snow3g_hexdump("Expected:", pSrcBuff_const[j], packetLen[j]);
                                goto snow3g_f8_n_buffer_linear_exit;
                        }
                }
        }

        /* no errors detected */
        status = 0;

snow3g_f8_n_buffer_linear_exit:
        for (i = 0; i < numPackets; i++) {
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);
                if (pSrcBuff[i] != NULL)
                        free(pSrcBuff[i]);
                if (pDstBuff[i] != NULL)
                        free(pDstBuff[i]);
                if (pSrcBuff_const[i] != NULL)
                        free(pSrcBuff_const[i]);
                if (pDstBuff_const[i] != NULL)
                        free(pDstBuff_const[i]);
                if (pIV[i] != NULL)
                        free(pIV[i]);
        }

        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f8_n_blocks_linear_mkeys(struct IMB_MGR *mb_mgr, uint32_t job_api,
                                         struct test_suite_context *uea2_ctx,
                                         struct test_suite_context *uia2_ctx)
{
        int numVectors = 0, i, j;
        size_t size = 0;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        snow3g_key_schedule_t **pKeySched = NULL;
        uint8_t **pKey = NULL;
        uint8_t **pSrcBuff = NULL;
        uint8_t **pDstBuff = NULL;
        uint8_t **pSrcBuff_const = NULL;
        uint8_t **pDstBuff_const = NULL;
        uint8_t **pIV = NULL;
        uint32_t *packetLen = NULL;
        uint32_t *bitOffsets = NULL;
        uint32_t *byteLens = NULL;
        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_N_BUFFER_MULTI for usecase %s: (%s):\n", __func__,
               job_api ? "Job API" : "Direct API");
#endif
        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_n_buff_linear_mkey_early_exit;
        }

        pSrcBuff = malloc(sizeof(*pSrcBuff) * numVectors);
        pSrcBuff_const = malloc(sizeof(*pSrcBuff_const) * numVectors);
        pDstBuff = malloc(sizeof(*pDstBuff) * numVectors);
        pDstBuff_const = malloc(sizeof(*pDstBuff_const) * numVectors);
        pIV = malloc(sizeof(*pIV) * numVectors);
        pKey = malloc(sizeof(*pKey) * numVectors);
        pKeySched = malloc(sizeof(*pKeySched) * numVectors);
        packetLen = malloc(sizeof(*packetLen) * numVectors);
        bitOffsets = malloc(sizeof(*bitOffsets) * numVectors);
        byteLens = malloc(sizeof(*byteLens) * numVectors);

        if (!pSrcBuff || !pSrcBuff_const || !pDstBuff || !pDstBuff_const || !pIV || !pKey ||
            !pKeySched || !packetLen || !bitOffsets || !byteLens)
                goto snow3g_f8_n_buff_linear_mkey_early_exit;

        memset(pSrcBuff, 0, sizeof(*pSrcBuff) * numVectors);
        memset(pSrcBuff_const, 0, sizeof(*pSrcBuff_const) * numVectors);
        memset(pDstBuff, 0, sizeof(*pDstBuff) * numVectors);
        memset(pDstBuff_const, 0, sizeof(*pDstBuff_const) * numVectors);
        memset(pIV, 0, sizeof(*pIV) * numVectors);
        memset(pKey, 0, sizeof(*pKey) * numVectors);
        memset(pKeySched, 0, sizeof(*pKeySched) * numVectors);
        memset(packetLen, 0, sizeof(*packetLen) * numVectors);
        memset(bitOffsets, 0, sizeof(*bitOffsets) * numVectors);
        memset(byteLens, 0, sizeof(*byteLens) * numVectors);

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f8_n_buff_linear_mkey_exit;

        /* Create test Data for num Vectors */
        for (i = 0; i < numVectors; i++) {
                j = i % numVectors;

                /*vectors are in bits used to round up to bytes*/
                const int length = (int) testVectors[j].msgSize / 8;

                packetLen[i] = length;
                byteLens[i] = (uint32_t) length;
                bitOffsets[i] = 0;

                pKey[i] = malloc(testVectors[j].keySize / 8);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_n_buff_linear_mkey_exit;
                }
                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]): failed !\n", i);
                        goto snow3g_f8_n_buff_linear_mkey_exit;
                }
                pSrcBuff[i] = malloc(length);
                if (!pSrcBuff[i]) {
                        printf("malloc(pSrcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buff_linear_mkey_exit;
                }
                pDstBuff[i] = malloc(length);
                if (!pDstBuff[i]) {
                        printf("malloc(pDstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buff_linear_mkey_exit;
                }
                pSrcBuff_const[i] = malloc(length);
                if (!pSrcBuff_const[i]) {
                        printf("malloc(pSrcBuff_const[%d]):failed !\n", i);
                        goto snow3g_f8_n_buff_linear_mkey_exit;
                }
                pDstBuff_const[i] = malloc(length);
                if (!pDstBuff_const[i]) {
                        printf("malloc(pDstBuff_const[%d]):failed !\n", i);
                        goto snow3g_f8_n_buff_linear_mkey_exit;
                }
                pIV[i] = malloc(testVectors[j].ivSize / 8);
                if (!pIV[i]) {
                        printf("malloc(pIV[%d]):failed !\n", i);
                        goto snow3g_f8_n_buff_linear_mkey_exit;
                }

                memcpy(pKey[i], testVectors[j].key, testVectors[j].keySize / 8);

                memset(pSrcBuff[i], 0, length);
                memcpy(pSrcBuff_const[i], testVectors[j].msg, length);

                memset(pDstBuff[i], 0, length);
                memcpy(pDstBuff_const[i], testVectors[j].ct, length);

                memcpy(pIV[i], testVectors[j].iv, testVectors[j].ivSize / 8);

                /* init key shed */
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_n_buff_linear_mkey_exit;
                }
        }

        for (i = 0; i < numVectors; i++) {
                int nb_elem, nb_remain_elem = i + 1, idx = 0;
                const char *fn_name = "submit_uea2_jobs";

                for (j = 0; j <= i; j++) {
                        /* Cleanup previous values */
                        memset(pSrcBuff[j], 0, packetLen[j]);
                        memset(pDstBuff[j], 0, packetLen[j]);
                }

                /*Test the encrypt*/
                while (nb_remain_elem > 0) {
                        if (nb_remain_elem >= IMB_SNOW3G_NUM_SUPPORTED_BUFFERS) {
                                nb_elem = IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
                                nb_remain_elem -= IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
                        } else {
                                nb_elem = nb_remain_elem;
                                nb_remain_elem = 0;
                        }

                        if (job_api) {
                                submit_uea2_jobs(mb_mgr, &pKeySched[idx], &pIV[idx],
                                                 &pSrcBuff_const[idx], &pDstBuff[idx],
                                                 &byteLens[idx], &bitOffsets[idx], IMB_DIR_ENCRYPT,
                                                 nb_elem);
                        }

                        if (nb_elem == IMB_SNOW3G_NUM_SUPPORTED_BUFFERS)
                                idx += IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
                }

                /*Compare the data in the pDstBuff with the cipher pattern*/
                for (j = 0; j <= i; j++) {
                        if (memcmp(pDstBuff_const[j], pDstBuff[j], packetLen[j]) != 0) {
                                printf("%s(Enc) %s nb_packets:%d vector: %d\n", fn_name, __func__,
                                       i, j);
                                snow3g_hexdump("Actual:", pDstBuff[j], packetLen[j]);
                                snow3g_hexdump("Expected:", pDstBuff_const[j], packetLen[j]);
                                goto snow3g_f8_n_buff_linear_mkey_exit;
                        }
                }

                nb_remain_elem = i + 1;
                idx = 0;
                while (nb_remain_elem > 0) {
                        if (nb_remain_elem >= IMB_SNOW3G_NUM_SUPPORTED_BUFFERS) {
                                nb_elem = IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
                                nb_remain_elem -= IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
                        } else {
                                nb_elem = nb_remain_elem;
                                nb_remain_elem = 0;
                        }
                        /*Test the Decrypt*/
                        if (job_api) {
                                submit_uea2_jobs(mb_mgr, &pKeySched[idx], &pIV[idx],
                                                 &pDstBuff_const[idx], &pSrcBuff[idx],
                                                 &byteLens[idx], &bitOffsets[idx], IMB_DIR_DECRYPT,
                                                 nb_elem);
                        }

                        if (nb_elem == IMB_SNOW3G_NUM_SUPPORTED_BUFFERS)
                                idx += IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
                }
                /*Compare the data in the pSrcBuff with the pDstBuff*/
                for (j = 0; j <= i; j++) {
                        if (memcmp(pSrcBuff[j], pSrcBuff_const[j], packetLen[j]) != 0) {
                                printf("%s(Dec) %s nb_packets:%d vector: %d\n", fn_name, __func__,
                                       i, j);
                                snow3g_hexdump("Actual:", pSrcBuff[j], packetLen[j]);
                                snow3g_hexdump("Expected:", pSrcBuff_const[j], packetLen[j]);
                                goto snow3g_f8_n_buff_linear_mkey_exit;
                        }
                }
        }

        /* no errors detected */
        status = 0;

snow3g_f8_n_buff_linear_mkey_exit:
        for (i = 0; i < numVectors; i++) {
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);
                if (pSrcBuff[i] != NULL)
                        free(pSrcBuff[i]);
                if (pDstBuff[i] != NULL)
                        free(pDstBuff[i]);
                if (pSrcBuff_const[i] != NULL)
                        free(pSrcBuff_const[i]);
                if (pDstBuff_const[i] != NULL)
                        free(pDstBuff_const[i]);
                if (pIV[i] != NULL)
                        free(pIV[i]);
        }
snow3g_f8_n_buff_linear_mkey_early_exit:
        if (pKey != NULL)
                free(pKey);
        if (pSrcBuff != NULL)
                free(pSrcBuff);
        if (pSrcBuff_const != NULL)
                free(pSrcBuff_const);
        if (pDstBuff != NULL)
                free(pDstBuff);
        if (pDstBuff_const != NULL)
                free(pDstBuff_const);
        if (pIV != NULL)
                free(pIV);
        if (packetLen != NULL)
                free(packetLen);
        if (pKeySched != NULL)
                free(pKeySched);
        if (bitOffsets != NULL)
                free(bitOffsets);
        if (byteLens != NULL)
                free(byteLens);

        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f8_n_blocks_multi(struct IMB_MGR *mb_mgr, uint32_t job_api,
                                  struct test_suite_context *uea2_ctx,
                                  struct test_suite_context *uia2_ctx)
{
        int i, j, numVectors = 0, numPackets = IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;
        size_t size = 0;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        snow3g_key_schedule_t *pKeySched[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pKey[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pSrcBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pDstBuff[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint8_t *pIV[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t packetLen[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t bitOffsets[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        uint32_t byteLens[IMB_SNOW3G_NUM_SUPPORTED_BUFFERS];
        int status = -1;

        (void) uia2_ctx;

#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F8_N_BUFFER_MULTIKEY: (%s):\n",
               job_api ? "Job API" : "Direct API");
#endif

        memset(pSrcBuff, 0, sizeof(pSrcBuff));
        memset(pDstBuff, 0, sizeof(pDstBuff));
        memset(pIV, 0, sizeof(pIV));
        memset(pKeySched, 0, sizeof(pKeySched));
        memset(pKey, 0, sizeof(pKey));
        memset(packetLen, 0, sizeof(packetLen));

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f8_n_buffer_multikey_exit;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f8_n_buffer_multikey_exit;

        for (i = 0; i < numPackets; i++) {
                j = i % numVectors;

                const int length = (int) testVectors[j].msgSize / 8;

                packetLen[i] = length;
                byteLens[i] = (uint32_t) length;
                bitOffsets[i] = 0;

                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                pSrcBuff[i] = malloc(length);
                if (!pSrcBuff[i]) {
                        printf("malloc(pSrcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                pDstBuff[i] = malloc(length);
                if (!pDstBuff[i]) {
                        printf("malloc(pDstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                pKey[i] = malloc(testVectors[j].keySize / 8);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                pIV[i] = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
                if (!pIV[i]) {
                        printf("malloc(pIV[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }

                memcpy(pKey[i], testVectors[j].key, testVectors[j].keySize / 8);

                memcpy(pSrcBuff[i], testVectors[j].msg, length);

                memcpy(pIV[i], testVectors[j].iv, testVectors[j].ivSize / 8);

                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i]) != 0) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED() error\n");
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
        }

        for (i = 0; i < numPackets; i++) {
                j = i % numVectors;

                /*Test the encrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pSrcBuff, pDstBuff, byteLens,
                                         bitOffsets, IMB_DIR_ENCRYPT, i + 1);

                if (pDstBuff[0] == NULL) {
                        printf("N buffer failure\n");
                        goto snow3g_f8_n_buffer_multikey_exit;
                }

                /*Compare the data in the pDstBuff with the cipher pattern*/
                if (memcmp(testVectors[j].ct, pDstBuff[i], packetLen[i]) != 0) {
                        printf("IMB_SNOW3G_F8_N_BUFFER(Enc) , vector:%d "
                               "buffer: %d\n",
                               0, i);
                        snow3g_hexdump("Actual:", pDstBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].ct,
                                       packetLen[i]);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }

                /*Test the Decrypt*/
                if (job_api)
                        submit_uea2_jobs(mb_mgr, pKeySched, pIV, pDstBuff, pSrcBuff, byteLens,
                                         bitOffsets, IMB_DIR_DECRYPT, i + 1);

                if (pSrcBuff[0] == NULL) {
                        printf("N buffer failure\n");
                        goto snow3g_f8_n_buffer_multikey_exit;
                }

                /*Compare the data in the pSrcBuff with the pDstBuff*/
                if (memcmp(pSrcBuff[i], testVectors[j].msg, packetLen[i]) != 0) {
                        printf("snow3g_f8_n_buffer equal sizes, vector:%d "
                               "buffer: %d\n",
                               0, i);
                        snow3g_hexdump("Actual:", pSrcBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", (const uint8_t *) testVectors[j].msg,
                                       packetLen[i]);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
        }
        /* no errors detected */
        status = 0;

snow3g_f8_n_buffer_multikey_exit:
        for (i = 0; i < numPackets; i++) {
                if (pSrcBuff[i] != NULL)
                        free(pSrcBuff[i]);
                if (pDstBuff[i] != NULL)
                        free(pDstBuff[i]);
                if (pIV[i] != NULL)
                        free(pIV[i]);
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);
        }
        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f9(struct IMB_MGR *mb_mgr, uint32_t job_api, struct test_suite_context *uea2_ctx,
                   struct test_suite_context *uia2_ctx)
{
        int numVectors = 0, i;
        size_t size = 0;
        const struct mac_test *testVectors = snow3g_f9_vectors;

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = IMB_KEY_256_BYTES;
        uint8_t srcBuff[IMB_SNOW3G_MAX_DATA_LEN];
        uint8_t digest[IMB_SNOW3G_DIGEST_LEN];
        uint8_t *pIV = NULL;
        int status = -1;

        (void) uea2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F9_1_BUFFER: (%s):\n", job_api ? "Job API" : "Direct API");
#endif

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f9_1_buffer_exit;
        }

        pIV = malloc(IMB_SNOW3G_IV_LEN_IN_BYTES);
        if (!pIV) {
                printf("malloc(pIV):failed !\n");
                goto snow3g_f9_1_buffer_exit;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pKey):failed !\n");
                goto snow3g_f9_1_buffer_exit;
        }
        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size)
                goto snow3g_f9_1_buffer_exit;

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr)): "
                       "failed !\n");
                goto snow3g_f9_1_buffer_exit;
        }

        /*Get test data for for Snow3g 1 Packet version*/
        for (i = 0; i < numVectors; i++) {
                const int inputLen = ((int) testVectors[i].msgSize + 7) / 8;

                memcpy(pKey, testVectors[i].key, testVectors[i].keySize / 8);
                memcpy(srcBuff, testVectors[i].msg, inputLen);
                memcpy(pIV, testVectors[i].iv, testVectors[i].ivSize / 8);

                /*Only 1 key sched is used*/
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched) != 0) {
                        printf("IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr): error\n");
                        goto snow3g_f9_1_buffer_exit;
                }

                /*test the integrity for f9_user with IV*/
                if (job_api) {
                        unsigned j;

                        for (j = 0; j < test_num_jobs_size; j++) {
                                int ret = submit_uia2_job(
                                        mb_mgr, (uint8_t *) pKeySched, pIV, srcBuff, digest,
                                        (const uint32_t)(testVectors[i].msgSize / 8),
                                        (const uint8_t *) testVectors[i].tag, test_num_jobs[j]);
                                if (ret < 0) {
                                        printf("IMB_SNOW3G_F9 JOB API vector num:%zu\n",
                                               testVectors[i].tcId);
                                        goto snow3g_f9_1_buffer_exit;
                                }
                        }
                }

        } /* for numVectors */
        /* no errors detected */
        status = 0;

snow3g_f9_1_buffer_exit:
        free(pIV);
        free(pKey);
        free(pKeySched);

        if (status < 0)
                test_suite_update(uia2_ctx, 0, 1);
        else
                test_suite_update(uia2_ctx, 1, 0);
}

static int
validate_f8_iv_gen(void)
{
        uint32_t i, numParams = 0;
        uint8_t IV[16];

#ifdef DEBUG
        printf("Testing snow3g_f8_iv_gen:\n");
#endif
        const struct cipher_iv_gen_params *iv_params = snow3g_iv_params_f8_json;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        /* calculate number of iv_params entries */
        for (i = 0; iv_params[i].count != NULL; i++)
                numParams++;

        if (!numParams) {
                printf("No Snow3G test vectors found !\n");
                return 1;
        }

        /* skip first entry as it's not part of test data */
        for (i = 1; i < numParams; i++) {
                const size_t tc_idx = iv_params[i].tcId - 1; /* tcId is 1-based */

                memset(IV, 0, sizeof(IV));

                /* generate IV */
                if (snow3g_f8_iv_gen(*(const uint32_t *) iv_params[i].count,
                                     *(const uint8_t *) iv_params[i].bearer,
                                     *(const uint8_t *) iv_params[i].dir, &IV) < 0)
                        return 1;

                /* validate result */
                if (memcmp(IV, testVectors[tc_idx].iv, 16) != 0) {
                        printf("snow3g_f8_iv_gen vector num: %zu\n", testVectors[tc_idx].tcId);
                        snow3g_hexdump("Actual", IV, 16);
                        snow3g_hexdump("Expected", (const uint8_t *) testVectors[tc_idx].iv, 16);
                        return 1;
                }
        }

        return 0;
}

static int
validate_f9_iv_gen(void)
{
        uint32_t i, numVectors = 0;
        uint8_t IV[16];

#ifdef DEBUG
        printf("Testing snow3g_f9_iv_gen:\n");
#endif

        /* 6 test sets */
        const struct hash_iv_gen_params *iv_params = snow3g_iv_params_f9_json;
        const struct mac_test *testVectors = snow3g_f9_vectors;

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return 1;
        }

        for (i = 0; i < numVectors; i++) {
                memset(IV, 0, sizeof(IV));

                /* generate IV */
                if (snow3g_f9_iv_gen(*(const uint32_t *) iv_params[i].count,
                                     *(const uint32_t *) iv_params[i].fresh,
                                     *(const uint8_t *) iv_params[i].dir, &IV) < 0)
                        return 1;

                /* validate result */
                if (memcmp(IV, testVectors[i].iv, 16) != 0) {
                        printf("snow3g_f9_iv_gen vector num: %zu\n", testVectors[i].tcId);
                        snow3g_hexdump("Actual", IV, 16);
                        snow3g_hexdump("Expected", (const uint8_t *) testVectors[i].iv, 16);
                        return 1;
                }
        }

        return 0;
}

int
snow3g_test(struct IMB_MGR *mb_mgr)
{
        int errors = 0;
        uint32_t i;
        struct test_suite_context uea2_ctx;
        struct test_suite_context uia2_ctx;
        struct test_json_alloc_ctx *f9_jctx = NULL;
        struct test_json_alloc_ctx *f8_jctx = NULL;
        struct test_json_alloc_ctx *f8_linear_jctx = NULL;

        if (load_mac_vectors(kat_vector_dir, "snow3g_f9_test.json", &snow3g_f9_vectors, &f9_jctx) <
            0)
                return 1;
        if (load_snow3g_f8_vectors(&f8_jctx, &f8_linear_jctx) < 0) {
                free_snow3g_f8_vectors(f8_jctx, f8_linear_jctx);
                free_snow3g_f9_vectors(f9_jctx);
                return 1;
        }

        test_suite_start(&uea2_ctx, "SNOW3G-UEA2");
        test_suite_start(&uia2_ctx, "SNOW3G-UIA2");

        if (validate_f8_iv_gen()) {
                printf("validate_snow3g_f8_iv_gen:: FAIL\n");
                test_suite_update(&uea2_ctx, 0, 1);
        } else
                test_suite_update(&uea2_ctx, 1, 0);
        if (validate_f9_iv_gen()) {
                printf("validate_snow3g_f9_iv_gen:: FAIL\n");
                test_suite_update(&uia2_ctx, 0, 1);
        } else
                test_suite_update(&uia2_ctx, 1, 0);

        /* validate job api */
        for (i = 0; i < DIM(snow3g_func_tab); i++)
                snow3g_func_tab[i].func(mb_mgr, 1, &uea2_ctx, &uia2_ctx);

        errors += test_suite_end(&uea2_ctx);
        errors += test_suite_end(&uia2_ctx);

        free_snow3g_f8_vectors(f8_jctx, f8_linear_jctx);
        free_snow3g_f9_vectors(f9_jctx);
        return errors;
}
