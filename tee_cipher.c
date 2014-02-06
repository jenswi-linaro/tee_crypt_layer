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

#include <tee_cipher.h>
#include <tee_api_defines.h>
#include <utee_defines.h>

#include <stdlib.h>

struct tee_cipher_context {
	const struct tee_cipher_prop *prop;
};

static const struct tee_cipher_prop *cipher_props[9];

static int get_prop_index(uint32_t algo)
{
	/* TODO calculate index based on algo instead */
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		return 0;
	case TEE_ALG_AES_CBC_NOPAD:
		return 1;
	case TEE_ALG_AES_CTR:
		return 2;
	case TEE_ALG_AES_CTS:
		return 3;
	case TEE_ALG_AES_XTS:
		return 4;
	case TEE_ALG_DES_ECB_NOPAD:
		return 5;
	case TEE_ALG_DES_CBC_NOPAD:
		return 6;
	case TEE_ALG_DES3_ECB_NOPAD:
		return 7;
	case TEE_ALG_DES3_CBC_NOPAD:
		return 8;
	default:
		return -1;
	}
}

static const struct tee_cipher_prop *get_prop(uint32_t algo)
{
	int idx = get_prop_index(algo);

	if (idx == -1)
		return NULL;
	return cipher_props[idx];
}

TEE_Result tee_cipher_register_algo(uint32_t algo,
		const struct tee_cipher_prop *prop)
{
	int idx = get_prop_index(algo);

	if (idx == -1)
		return TEE_ERROR_GENERIC;

	cipher_props[idx] = prop;
	return TEE_SUCCESS;
}

TEE_Result tee_cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	const struct tee_cipher_prop *prop = get_prop(algo);

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = prop->context_size + sizeof(struct tee_cipher_context);
	return TEE_SUCCESS;
}

TEE_Result tee_cipher_get_block_size(uint32_t algo, size_t *size)
{
	const struct tee_cipher_prop *prop = get_prop(algo);

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = prop->block_size;
	return TEE_SUCCESS;
}

TEE_Result tee_cipher_init3(struct tee_cipher_context *ctx, uint32_t algo,
            TEE_OperationMode mode, const uint8_t *key1, size_t key1_len,
            const uint8_t *key2, size_t key2_len, const uint8_t *iv,
            size_t iv_len)
{
	ctx->prop = get_prop(algo);

	if (!ctx->prop)
		return TEE_ERROR_NOT_SUPPORTED;

	return ctx->prop->init(ctx + 1, mode, key1, key1_len, key2, key2_len,
			  iv, iv_len);
}

TEE_Result tee_cipher_update(struct tee_cipher_context *ctx, uint32_t algo,
            TEE_OperationMode mode, bool last_block, const uint8_t *data,
            size_t len, uint8_t *dst)
{
	return ctx->prop->update(ctx + 1, last_block, data, len, dst);
}

void tee_cipher_final(struct tee_cipher_context *ctx, uint32_t algo)
{
	ctx->prop->final(ctx + 1);
}
