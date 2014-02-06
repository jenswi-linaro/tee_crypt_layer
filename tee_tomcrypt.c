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

#include <string.h>

#include <tee_hash.h>
#include <tee_cipher.h>
#include <tee_mac.h>
#include <tee_authenc.h>
#include <utee_defines.h>
#include <tee_tomcrypt.h>

#include <tomcrypt.h>

#define MD5_DIGEST_LENGTH	TEE_MD5_HASH_SIZE

void tee_tomcrypt_init(void)
{
	if (register_hash(&md5_desc) == -1 ||
	    register_cipher(&aes_desc) == -1)
		abort();
}


static TEE_Result tc_ret_to_tee_result(int tc_ret)
{
	switch (tc_ret) {
	case CRYPT_OK:
		return TEE_SUCCESS;
	/* TODO more details */
	default:
		return TEE_ERROR_GENERIC;
	}
}

const struct tee_hash_prop tee_tomcrypt_md5_prop = {
	.digest_size = MD5_DIGEST_LENGTH,
	.context_size = sizeof(hash_state),
	.init = (TEE_Result (*)(void *))tee_tomcrypt_md5_init,
	.update = (TEE_Result (*)(void *, const uint8_t *, size_t))
			tee_tomcrypt_md5_update,
	.final = (TEE_Result (*)(void *, uint8_t *, size_t))
			tee_tomcrypt_md5_final,
};

TEE_Result tee_tomcrypt_md5_init(struct tee_tomcrypt_md5_context *ctx)
{
	int tc_ret = md5_init((hash_state *)ctx);

	return tc_ret_to_tee_result(tc_ret);
}

TEE_Result tee_tomcrypt_md5_update(struct tee_tomcrypt_md5_context *ctx,
		const uint8_t *data, size_t len)
{
	int tc_ret = md5_process((hash_state *)ctx, data, len);

	return tc_ret_to_tee_result(tc_ret);
}

TEE_Result tee_tomcrypt_md5_final(struct tee_tomcrypt_md5_context *ctx,
		uint8_t *digest, size_t len)
{
	int tc_ret;

	if (len < MD5_DIGEST_LENGTH) {
		uint8_t d[MD5_DIGEST_LENGTH];

		tc_ret = md5_done((hash_state *)ctx, d);
		if (tc_ret == CRYPT_OK)
			memcpy(digest, d, len);
	} else {
		tc_ret = md5_done((hash_state *)ctx, digest);
	}

	return tc_ret_to_tee_result(tc_ret);
}

struct tee_tomcrypt_aescbc_context {
	symmetric_CBC cbc;
	bool enc;
};

const struct tee_cipher_prop tee_tomcrypt_aescbc_prop = {
	.block_size = TEE_AES_BLOCK_SIZE,
	.context_size = sizeof(struct tee_tomcrypt_aescbc_context),
	.init = (tee_cipher_init_func_t)tee_tomcrypt_aescbc_init,
	.update = (tee_cipher_update_func_t)tee_tomcrypt_aescbc_update,
	.final = (tee_cipher_final_func_t)tee_tomcrypt_aescbc_final,
};

TEE_Result tee_tomcrypt_aescbc_init(struct tee_tomcrypt_aescbc_context *ctx,
		TEE_OperationMode mode,
		const uint8_t *key1, size_t key1_len,
		const uint8_t *key2, size_t key2_len,
		const uint8_t *iv, size_t iv_len)
{
	int tc_ret;

	if (key2 || key2_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!iv || iv_len != TEE_AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (mode == TEE_MODE_ENCRYPT)
		ctx->enc = true;
	else if (mode == TEE_MODE_DECRYPT)
		ctx->enc = false;
	else
		return TEE_ERROR_BAD_PARAMETERS;

	tc_ret = cbc_start(find_cipher("aes"), iv, key1, key1_len,
			   0, &ctx->cbc);
	return tc_ret_to_tee_result(tc_ret);
}

TEE_Result tee_tomcrypt_aescbc_update(struct tee_tomcrypt_aescbc_context *ctx,
		bool last_block, const uint8_t *data, size_t len, uint8_t *dst)
{
	int tc_ret;

	if (ctx->enc)
		tc_ret = cbc_encrypt(data, dst, len, &ctx->cbc);
	else
		tc_ret = cbc_decrypt(data, dst, len, &ctx->cbc);

	return tc_ret_to_tee_result(tc_ret);
}

void tee_tomcrypt_aescbc_final(struct tee_tomcrypt_aescbc_context *ctx)
{
	int tc_ret = cbc_done(&ctx->cbc);

	assert(tc_ret == CRYPT_OK);
}

struct tee_tomcrypt_hmacmd5_context {
	hmac_state hmac;
};

const struct tee_mac_prop tee_tomcrypt_hmacmd5_prop = {
	.digest_size = MD5_DIGEST_LENGTH,
	.context_size = sizeof(struct tee_tomcrypt_hmacmd5_context),
	.init = (tee_mac_init_func_t)tee_tomcrypt_hmacmd5_init,
	.update = (tee_mac_update_func_t)tee_tomcrypt_hmacmd5_update,
	.final = (tee_mac_final_func_t)tee_tomcrypt_hmacmd5_final,
};

TEE_Result tee_tomcrypt_hmacmd5_init(struct tee_tomcrypt_hmacmd5_context *ctx,
		const uint8_t *key, size_t len)
{
	int tc_ret = hmac_init(&ctx->hmac, find_hash("md5"), key, len);

	return tc_ret_to_tee_result(tc_ret);
}

TEE_Result tee_tomcrypt_hmacmd5_update(struct tee_tomcrypt_hmacmd5_context *ctx,
		const uint8_t *data, size_t len)
{
	int tc_ret = hmac_process(&ctx->hmac, data, len);

	return tc_ret_to_tee_result(tc_ret);
}

TEE_Result tee_tomcrypt_hmacmd5_final(struct tee_tomcrypt_hmacmd5_context *ctx,
                const uint8_t *data, size_t data_len,
		uint8_t *digest, size_t digest_len)
{
	int tc_ret;
	unsigned long l;

	if (data_len) {
		tc_ret = hmac_process(&ctx->hmac, data, data_len);
		if (tc_ret != CRYPT_OK)
			goto out;
	}

	if (digest_len < MD5_DIGEST_LENGTH) {
		uint8_t d[MD5_DIGEST_LENGTH];

		tc_ret = hmac_done(&ctx->hmac, d, &l);
		if (tc_ret != CRYPT_OK)
			goto out;

		memcpy(digest, d, digest_len);
	} else {
		tc_ret = hmac_done(&ctx->hmac, digest, &l);
	}

out:
	assert(tc_ret != CRYPT_OK || l == MD5_DIGEST_LENGTH);
	return tc_ret_to_tee_result(tc_ret);
}

struct tee_tomcrypt_aesgcm_context {
	gcm_state gcm;
	bool enc;
};

const struct tee_authenc_prop tee_tomcrypt_aesgcm_prop = {
	.context_size = sizeof(struct tee_tomcrypt_aesgcm_context),
	.init = (tee_authenc_init_func_t)tee_tomcrypt_aesgcm_init,
	.update_aad = (tee_authenc_update_aad_func_t)
			tee_tomcrypt_aesgcm_update_aad,
	.update_payload = (tee_authenc_update_payload_func_t)
			tee_tomcrypt_aesgcm_update_payload,
	.enc_final = (tee_authenc_enc_final_func_t)
			tee_tomcrypt_aesgcm_enc_final,
	.dec_final = (tee_authenc_dec_final_func_t)
			tee_tomcrypt_aesgcm_dec_final,
	.final = (tee_authenc_final_func_t)tee_tomcrypt_aesgcm_final,
};

TEE_Result tee_tomcrypt_aesgcm_init(struct tee_tomcrypt_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *key, size_t key_len,
		const uint8_t *nonce, size_t nonce_len, size_t tag_len,
		size_t aad_len, size_t payload_len)
{
	int tc_ret;

	tc_ret = gcm_init(&ctx->gcm, find_cipher("aes"), key, key_len);
	if (tc_ret != CRYPT_OK)
		goto out;

	tc_ret = gcm_add_iv(&ctx->gcm, nonce, nonce_len);

out:
	return tc_ret_to_tee_result(tc_ret);
}

TEE_Result tee_tomcrypt_aesgcm_update_aad(
		struct tee_tomcrypt_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *data, size_t len)
{
	int tc_ret = gcm_add_aad(&ctx->gcm, data, len);

	return tc_ret_to_tee_result(tc_ret);
}

TEE_Result tee_tomcrypt_aesgcm_update_payload(
		struct tee_tomcrypt_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *src_data,
		size_t src_len, uint8_t *dst_data)
{
	int tc_ret;
	int direction;

	if (mode == TEE_MODE_ENCRYPT)
		direction = GCM_ENCRYPT;
	else if (mode == TEE_MODE_DECRYPT)
		direction = GCM_DECRYPT;
	else
		return TEE_ERROR_BAD_PARAMETERS;

	tc_ret = gcm_process(&ctx->gcm, (uint8_t *)src_data, src_len,
				dst_data, direction);

	return tc_ret_to_tee_result(tc_ret);
}

TEE_Result tee_tomcrypt_aesgcm_enc_final(
		struct tee_tomcrypt_aesgcm_context *ctx,
		const uint8_t *src_data, size_t src_len,
		uint8_t *dst_data, uint8_t *dst_tag, size_t *dst_tag_len)
{
	int tc_ret1 = CRYPT_OK;
	int tc_ret2;
	unsigned long tl;

	if (src_len) {
		tc_ret1 = gcm_process(&ctx->gcm, (uint8_t *)src_data, src_len,
					dst_data, GCM_ENCRYPT);
	}

	tl = *dst_tag_len;
	tc_ret2 = gcm_done(&ctx->gcm, dst_tag, &tl);
	if (tc_ret1 == CRYPT_OK && tc_ret2 == CRYPT_OK)
		*dst_tag_len = tl;

	if (tc_ret1 != CRYPT_OK)
		return tc_ret_to_tee_result(tc_ret1);
	return tc_ret_to_tee_result(tc_ret2);
}

TEE_Result tee_tomcrypt_aesgcm_dec_final(
		struct tee_tomcrypt_aesgcm_context *ctx,
		const uint8_t *src_data, size_t src_len,
		uint8_t *dst_data, const uint8_t *tag, size_t tag_len)
{
	int tc_ret1 = CRYPT_OK;
	int tc_ret2;
	unsigned long tl;

	if (src_len) {
		tc_ret1 = gcm_process(&ctx->gcm, (uint8_t *)src_data, src_len,
					dst_data, GCM_DECRYPT);
	}

	tl = tag_len;
	tc_ret2 = gcm_done(&ctx->gcm, (uint8_t *)tag, &tl);
	if (tc_ret1 == CRYPT_OK && tc_ret2 == CRYPT_OK && tl != tag_len)
		return TEE_ERROR_GENERIC;

	if (tc_ret1 != CRYPT_OK)
		return tc_ret_to_tee_result(tc_ret1);
	return tc_ret_to_tee_result(tc_ret2);
}

void tee_tomcrypt_aesgcm_final(struct tee_tomcrypt_aesgcm_context *ctx)
{
}
