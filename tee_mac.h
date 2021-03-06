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

#ifndef TEE_HMAC_H
#define TEE_HMAC_H

#include <tee_api_types.h>

typedef TEE_Result (*tee_mac_init_func_t)(void *ctx, const uint8_t *key,
				size_t len);
typedef TEE_Result (*tee_mac_update_func_t)(void *ctx, const uint8_t *data,
				size_t len);
typedef TEE_Result (*tee_mac_final_func_t)(void *ctx,
				const uint8_t *data, size_t data_len,
				uint8_t *digest, size_t digest_len);
struct tee_mac_prop {
	uint16_t digest_size;
	uint16_t context_size;
	tee_mac_init_func_t init;
	tee_mac_update_func_t update;
	tee_mac_final_func_t final;
};

struct tee_mac_context;

/*
 * Algorithms in this files are as specified with the TEE_ALG_XXX from
 * TEE Internal API.
 */


TEE_Result tee_mac_register_algo(uint32_t algo,
		const struct tee_mac_prop *prop);

TEE_Result tee_mac_get_digest_size(uint32_t algo, size_t *size);

/* Returns required size of context for the specified algorithm */
TEE_Result tee_mac_get_ctx_size(uint32_t algo, size_t *size);

TEE_Result tee_mac_init(struct tee_mac_context *ctx, uint32_t algo,
                const uint8_t *key, size_t len);

TEE_Result tee_mac_update(struct tee_mac_context *ctx, uint32_t algo,
                const uint8_t *data, size_t len);

TEE_Result tee_mac_final(struct tee_mac_context *ctx, uint32_t algo,
                const uint8_t *data, size_t data_len, uint8_t *digest,
                size_t digest_len);

#endif /*TEE_HMAC_H*/


