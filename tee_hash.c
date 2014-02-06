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

#include <tee_hash.h>
#include <tee_api_defines.h>
#include <utee_defines.h>

#include <stdlib.h>

struct tee_hash_context {
	const struct tee_hash_prop *prop;
};

static const struct tee_hash_prop *hash_props[0x7];

static const struct tee_hash_prop *get_prop(uint32_t algo)
{
	return hash_props[algo & 0x7];
}

TEE_Result tee_hash_register_algo(uint32_t algo,
		const struct tee_hash_prop *prop)
{
	if (algo != TEE_ALG_HASH_ALGO(TEE_ALG_GET_MAIN_ALG(algo)))
		return TEE_ERROR_GENERIC;

	hash_props[algo & 0x7] = prop;
	return TEE_SUCCESS;
}

TEE_Result tee_hash_get_digest_size(uint32_t algo, size_t *size)
{
	const struct tee_hash_prop *prop = get_prop(algo);

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = prop->digest_size;
	return TEE_SUCCESS;
}

TEE_Result tee_hash_get_ctx_size(uint32_t algo, size_t *size)
{
	const struct tee_hash_prop *prop = get_prop(algo);

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = prop->context_size + sizeof(struct tee_hash_context);
	return TEE_SUCCESS;
}

TEE_Result tee_hash_init(struct tee_hash_context *ctx, uint32_t algo)
{
	const struct tee_hash_prop *prop = get_prop(algo);

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	ctx->prop = prop;
	return prop->init(ctx + 1);
}

TEE_Result tee_hash_update(struct tee_hash_context *ctx, uint32_t algo,
                const uint8_t *data, size_t len)
{
	return ctx->prop->update(ctx + 1, data, len);
}

TEE_Result tee_hash_final(struct tee_hash_context *ctx, uint32_t algo,
                uint8_t *digest, size_t len)
{
	return ctx->prop->final(ctx + 1, digest, len);
}

TEE_Result tee_hash_createdigest(uint32_t algo, const uint8_t *data,
                size_t datalen, uint8_t *digest, size_t digestlen)
{
	TEE_Result res;
	const struct tee_hash_prop *prop = get_prop(algo);
	void *ctx = NULL;

	if (!prop)
		return TEE_ERROR_NOT_SUPPORTED;

	ctx = malloc(prop->context_size);
	if (!ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = prop->init(ctx);
	if (res != TEE_SUCCESS)
		goto out;

	if (datalen) {
		res = prop->update(ctx, data, datalen);
		if (res != TEE_SUCCESS)
			goto out;
	}

	res = prop->final(ctx, digest, digestlen);
out:
	free(ctx);
	return res;
}
