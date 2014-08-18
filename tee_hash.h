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

#ifndef TEE_HASH_H
#define TEE_HASH_H

#include <tee_api_types.h>

struct tee_hash_prop {
	uint16_t digest_size;
	uint16_t context_size;
	TEE_Result (*init)(void *ctx);
	TEE_Result (*update)(void *ctx, const uint8_t *data, size_t len);
	TEE_Result (*final)(void *ctx, uint8_t *digest, size_t len);
};

/*
 * Algorithms in this files are as specified with the TEE_ALG_XXX from
 * TEE Internal API.
 */

struct tee_hash_context;

TEE_Result tee_hash_register_algo(uint32_t algo,
		const struct tee_hash_prop *prop);

TEE_Result tee_hash_get_digest_size(uint32_t algo, size_t *size);

/* Returns required size of context for the specified algorithm */
TEE_Result tee_hash_get_ctx_size(uint32_t algo, size_t *size);

TEE_Result tee_hash_init(struct tee_hash_context *ctx, uint32_t algo);

TEE_Result tee_hash_update(struct tee_hash_context *ctx, uint32_t algo,
                const uint8_t *data, size_t len);

TEE_Result tee_hash_final(struct tee_hash_context *ctx, uint32_t algo,
                uint8_t *digest, size_t len);

TEE_Result tee_hash_createdigest(uint32_t algo, const uint8_t *data,
                size_t datalen, uint8_t *digest, size_t digestlen);

#endif /*TEE_HASH_H*/

