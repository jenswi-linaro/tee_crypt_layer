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

#include <tee_authenc.h>
#include <tee_api_defines.h>
#include <string.h>

struct tee_authenc_context {
	const struct tee_authenc_prop *prop;
};

static const struct tee_authenc_prop *authenc_props[2];


static int get_prop_index(uint32_t algo)
{
	/* TODO calculate index based on algo instead */
	switch (algo) {
	case TEE_ALG_AES_CCM:
		return 0;
	case TEE_ALG_AES_GCM:
		return 1;
	default:
		return -1;
	}
}

static const struct tee_authenc_prop *get_prop(uint32_t algo)
{
	int idx = get_prop_index(algo);

	if (idx == -1)
		return NULL;
	return authenc_props[idx];
}

TEE_Result tee_authenc_register_algo(uint32_t algo,
		const struct tee_authenc_prop *prop)
{
	int idx = get_prop_index(algo);

	if (idx == -1)
		return TEE_ERROR_GENERIC;

	authenc_props[idx] = prop;
	return TEE_SUCCESS;
}

TEE_Result tee_authenc_get_ctx_size(uint32_t algo, size_t *size)
{
	const struct tee_authenc_prop *prop = get_prop(algo);

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = prop->context_size + sizeof(struct tee_authenc_context);
	return TEE_SUCCESS;
}

TEE_Result tee_authenc_init(struct tee_authenc_context *ctx, uint32_t algo,
            TEE_OperationMode mode, const uint8_t *key, size_t key_len,
            const uint8_t *nonce, size_t nonce_len, size_t tag_len,
            size_t aad_len, size_t payload_len)
{
	ctx->prop = get_prop(algo);

	if (!ctx->prop)
		return TEE_ERROR_NOT_SUPPORTED;

	return ctx->prop->init(ctx + 1, mode, key, key_len, nonce, nonce_len,
				tag_len, aad_len, payload_len);
}

TEE_Result tee_authenc_update_aad(struct tee_authenc_context *ctx,
            uint32_t algo, TEE_OperationMode mode, const uint8_t *data,
            size_t len)
{
	return ctx->prop->update_aad(ctx + 1, mode, data, len);
}

TEE_Result tee_authenc_update_payload(struct tee_authenc_context *ctx,
            uint32_t algo, TEE_OperationMode mode, const uint8_t *src_data,
            size_t src_len, uint8_t *dst_data)
{
	return ctx->prop->update_payload(ctx + 1, mode, src_data, src_len,
					dst_data);
}

TEE_Result tee_authenc_enc_final(struct tee_authenc_context *ctx,
            uint32_t algo, const uint8_t *src_data, size_t src_len,
            uint8_t *dst_data, uint8_t *dst_tag, size_t *dst_tag_len)
{
	return ctx->prop->enc_final(ctx + 1, src_data, src_len, dst_data,
					dst_tag, dst_tag_len);
}

TEE_Result tee_authenc_dec_final(struct tee_authenc_context *ctx,
            uint32_t algo, const uint8_t *src_data, size_t src_len,
            uint8_t *dst_data, const uint8_t *tag, size_t tag_len)
{
	return ctx->prop->dec_final(ctx + 1, src_data, src_len, dst_data,
					tag, tag_len);
}

void tee_authenc_final(struct tee_authenc_context *ctx, uint32_t algo)
{
	ctx->prop->final(ctx + 1);
}
