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

#include <tee_mac.h>
#include <tee_api_defines.h>
#include <utee_defines.h>

#include <stdlib.h>

struct tee_mac_context {
	const struct tee_mac_prop *prop;
};

static const struct tee_mac_prop *mac_props[13];

static int get_prop_index(uint32_t algo)
{
	/* TODO calculate index based on algo instead */
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
		return 0;
	case TEE_ALG_HMAC_SHA1:
		return 1;
	case TEE_ALG_HMAC_SHA224:
		return 2;
	case TEE_ALG_HMAC_SHA256:
		return 3;
	case TEE_ALG_HMAC_SHA384:
		return 4;
	case TEE_ALG_HMAC_SHA512:
		return 5;
	case TEE_ALG_AES_CBC_MAC_NOPAD:
		return 6;
	case TEE_ALG_AES_CBC_MAC_PKCS5:
		return 7;
	case TEE_ALG_AES_CMAC:
		return 8;
	case TEE_ALG_DES_CBC_MAC_NOPAD:
		return 9;
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		return 10;
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
		return 11;
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return 12;
	default:
		return -1;
	}
}

static const struct tee_mac_prop *get_prop(uint32_t algo)
{
	int idx = get_prop_index(algo);

	if (idx == -1)
		return NULL;
	return mac_props[idx];
}

TEE_Result tee_mac_register_algo(uint32_t algo,
		const struct tee_mac_prop *prop)
{
	int idx = get_prop_index(algo);

	if (idx == -1)
		return TEE_ERROR_GENERIC;

	mac_props[idx] = prop;
	return TEE_SUCCESS;
}

TEE_Result tee_mac_get_ctx_size(uint32_t algo, size_t *size)
{
	const struct tee_mac_prop *prop = get_prop(algo);

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = prop->context_size + sizeof(struct tee_mac_context);
	return TEE_SUCCESS;
}

TEE_Result tee_mac_get_digest_size(uint32_t algo, size_t *size)
{
	const struct tee_mac_prop *prop = get_prop(algo);

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = prop->digest_size;
	return TEE_SUCCESS;
}

TEE_Result tee_mac_init(struct tee_mac_context *ctx, uint32_t algo,
                const uint8_t *key, size_t len)
{
	ctx->prop = get_prop(algo);

	if (!ctx->prop)
		return TEE_ERROR_NOT_SUPPORTED;

	return ctx->prop->init(ctx + 1, key, len);
}

TEE_Result tee_mac_update(struct tee_mac_context *ctx, uint32_t algo,
                const uint8_t *data, size_t len)
{
	return ctx->prop->update(ctx + 1, data, len);
}

TEE_Result tee_mac_final(struct tee_mac_context *ctx, uint32_t algo,
                const uint8_t *data, size_t data_len, uint8_t *digest,
                size_t digest_len)
{
	return ctx->prop->final(ctx + 1, data, data_len, digest, digest_len);
}
