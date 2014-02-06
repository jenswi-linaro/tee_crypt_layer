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

#ifndef TEE_OPENSSL_H
#define TEE_OPENSSL_H

#include <tee_api_types.h>

struct tee_openssl_md5_context;

extern const struct tee_hash_prop tee_openssl_md5_prop;

TEE_Result tee_openssl_md5_init(struct tee_openssl_md5_context *ctx);
TEE_Result tee_openssl_md5_update(struct tee_openssl_md5_context *ctx,
		const uint8_t *data, size_t len);
TEE_Result tee_openssl_md5_final(struct tee_openssl_md5_context *ctx,
		uint8_t *digest, size_t len);

struct tee_openssl_aescbc_context;

extern const struct tee_cipher_prop tee_openssl_aescbc_prop;

TEE_Result tee_openssl_aescbc_init(struct tee_openssl_aescbc_context *ctx,
		TEE_OperationMode mode,
		const uint8_t *key1, size_t key1_len,
		const uint8_t *key2, size_t key2_len,
		const uint8_t *iv, size_t iv_len);

TEE_Result tee_openssl_aescbc_update(struct tee_openssl_aescbc_context *ctx,
		bool last_block, const uint8_t *data, size_t len, uint8_t *dst);

void tee_openssl_aescbc_final(struct tee_openssl_aescbc_context *ctx);

struct tee_openssl_hmacmd5_context;

extern const struct tee_mac_prop tee_openssl_hmacmd5_prop;

TEE_Result tee_openssl_hmacmd5_init(struct tee_openssl_md5_context *ctx,
		const uint8_t *key, size_t len);
TEE_Result tee_openssl_hmacmd5_update(struct tee_openssl_md5_context *ctx,
		const uint8_t *data, size_t len);
TEE_Result tee_openssl_hmacmd5_final(struct tee_openssl_md5_context *ctx,
                const uint8_t *data, size_t data_len,
		uint8_t *digest, size_t digest_len);


struct tee_openssl_aesgcm_context;
extern const struct tee_authenc_prop tee_openssl_aesgcm_prop;

TEE_Result tee_openssl_aesgcm_init(struct tee_openssl_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *key, size_t key_len,
		const uint8_t *nonce, size_t nonce_len, size_t tag_len,
		size_t aad_len, size_t payload_len);

TEE_Result tee_openssl_aesgcm_update_aad(struct tee_openssl_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *data, size_t len);

TEE_Result tee_openssl_aesgcm_update_payload(
		struct tee_openssl_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *src_data,
		size_t src_len, uint8_t *dst_data);

TEE_Result tee_openssl_aesgcm_enc_final(struct tee_openssl_aesgcm_context *ctx,
		const uint8_t *src_data, size_t src_len,
		uint8_t *dst_data, uint8_t *dst_tag, size_t *dst_tag_len);

TEE_Result tee_openssl_aesgcm_dec_final(struct tee_openssl_aesgcm_context *ctx,
		const uint8_t *src_data, size_t src_len,
		uint8_t *dst_data, const uint8_t *tag, size_t tag_len);

void tee_openssl_aesgcm_final(struct tee_openssl_aesgcm_context *ctx);


#endif /*TEE_OPENSSL_H*/
