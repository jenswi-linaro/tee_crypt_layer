/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TEE_CIPHER_H
#define TEE_CIPHER_H

#include <tee_api_types.h>

typedef TEE_Result (*tee_cipher_init_func_t)(void *ctx, TEE_OperationMode mode,
		const uint8_t *key1, size_t key1_len,
		const uint8_t *key2, size_t key2_len,
		const uint8_t *iv, size_t iv_len);
typedef TEE_Result (*tee_cipher_update_func_t)(void *ctx, bool last_block,
		const uint8_t *data, size_t len, uint8_t *dst);
typedef void (*tee_cipher_final_func_t)(void *ctx);


struct tee_cipher_prop {
	uint16_t block_size;
	uint16_t context_size;
	tee_cipher_init_func_t init;
	tee_cipher_update_func_t update;
	tee_cipher_final_func_t final;
};

struct tee_cipher_context;

/*
 * Algorithms in this files are as specified with the TEE_ALG_XXX from
 * TEE Internal API.
 */

TEE_Result tee_cipher_register_algo(uint32_t algo,
		const struct tee_cipher_prop *prop);

TEE_Result tee_cipher_get_ctx_size(uint32_t algo, size_t *size);

TEE_Result tee_cipher_get_block_size(uint32_t algo, size_t *size);


TEE_Result tee_cipher_init3(struct tee_cipher_context *ctx, uint32_t algo,
            TEE_OperationMode mode, const uint8_t *key1, size_t key1_len,
            const uint8_t *key2, size_t key2_len, const uint8_t *iv,
            size_t iv_len);

static inline TEE_Result tee_cipher_init(struct tee_cipher_context *ctx,
		uint32_t algo, TEE_OperationMode mode,
		const uint8_t *key, size_t key_len)
{
	return tee_cipher_init3(ctx, algo, mode, key, key_len,
				NULL, 0, NULL, 0);
}

static inline TEE_Result tee_cipher_init2(struct tee_cipher_context *ctx,
		uint32_t algo, TEE_OperationMode mode,
		const uint8_t *key, size_t key_len,
		const uint8_t *iv, size_t iv_len)
{
	return tee_cipher_init3(ctx, algo, mode, key, key_len,
				NULL, 0, iv, iv_len);
}

TEE_Result tee_cipher_update(struct tee_cipher_context *ctx, uint32_t algo,
            TEE_OperationMode mode, bool last_block, const uint8_t *data,
            size_t len, uint8_t *dst);

void tee_cipher_final(struct tee_cipher_context *ctx, uint32_t algo);

#endif /*TEE_CIPHER_H*/

