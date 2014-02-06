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
#include <tee_openssl.h>

#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

const struct tee_hash_prop tee_openssl_md5_prop = {
	.digest_size = MD5_DIGEST_LENGTH,
	.context_size = sizeof(MD5_CTX),
	.init = (TEE_Result (*)(void *))tee_openssl_md5_init,
	.update = (TEE_Result (*)(void *, const uint8_t *, size_t))
			tee_openssl_md5_update,
	.final = (TEE_Result (*)(void *, uint8_t *, size_t))
			tee_openssl_md5_final,
};

TEE_Result tee_openssl_md5_init(struct tee_openssl_md5_context *ctx)
{
	if (MD5_Init((MD5_CTX *)ctx))
		return TEE_SUCCESS;
	return TEE_ERROR_GENERIC;
}

TEE_Result tee_openssl_md5_update(struct tee_openssl_md5_context *ctx,
		const uint8_t *data, size_t len)
{
	if (MD5_Update((MD5_CTX *)ctx, data, len))
		return TEE_SUCCESS;
	return TEE_ERROR_GENERIC;
}

TEE_Result tee_openssl_md5_final(struct tee_openssl_md5_context *ctx,
		uint8_t *digest, size_t len)
{
	if (len < MD5_DIGEST_LENGTH) {
		uint8_t d[MD5_DIGEST_LENGTH];

		if (MD5_Final(d, (MD5_CTX *)ctx)) {
			memcpy(digest, d, len);
			return TEE_SUCCESS;
		}
	} else {
		if (MD5_Final(digest, (MD5_CTX *)ctx))
			return TEE_SUCCESS;
	}
	return TEE_ERROR_GENERIC;
}

struct tee_openssl_aescbc_context {
	AES_KEY key;
	uint8_t iv[TEE_AES_BLOCK_SIZE];
	bool enc;
};

const struct tee_cipher_prop tee_openssl_aescbc_prop = {
	.block_size = TEE_AES_BLOCK_SIZE,
	.context_size = sizeof(struct tee_openssl_aescbc_context),
	.init = (tee_cipher_init_func_t)tee_openssl_aescbc_init,
	.update = (tee_cipher_update_func_t)tee_openssl_aescbc_update,
	.final = (tee_cipher_final_func_t)tee_openssl_aescbc_final,
};

TEE_Result tee_openssl_aescbc_init(struct tee_openssl_aescbc_context *ctx,
		TEE_OperationMode mode,
		const uint8_t *key1, size_t key1_len,
		const uint8_t *key2, size_t key2_len,
		const uint8_t *iv, size_t iv_len)
{
	if (key2 || key2_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!iv || iv_len != TEE_AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (mode == TEE_MODE_ENCRYPT) {
		if (AES_set_encrypt_key(key1, key1_len * 8, &ctx->key))
			return TEE_ERROR_BAD_PARAMETERS;
		ctx->enc = true;
	} else if (mode == TEE_MODE_DECRYPT) {
		if (AES_set_decrypt_key(key1, key1_len * 8, &ctx->key))
			return TEE_ERROR_BAD_PARAMETERS;
		ctx->enc = false;
	} else
		return TEE_ERROR_BAD_PARAMETERS;


	memcpy(ctx->iv, iv, TEE_AES_BLOCK_SIZE);
	return TEE_SUCCESS;
}

TEE_Result tee_openssl_aescbc_update(struct tee_openssl_aescbc_context *ctx,
		bool last_block, const uint8_t *data, size_t len, uint8_t *dst)
{
	if ((len % TEE_AES_BLOCK_SIZE) != 0)
		return TEE_ERROR_BAD_PARAMETERS;
	AES_cbc_encrypt(data, dst, len, &ctx->key, ctx->iv, ctx->enc);
	return TEE_SUCCESS;
}

void tee_openssl_aescbc_final(struct tee_openssl_aescbc_context *ctx)
{
}

struct tee_openssl_hmacmd5_context;

const struct tee_mac_prop tee_openssl_hmacmd5_prop = {
	.digest_size = MD5_DIGEST_LENGTH,
	.context_size = sizeof(HMAC_CTX),
	.init = (tee_mac_init_func_t)tee_openssl_hmacmd5_init,
	.update = (tee_mac_update_func_t)tee_openssl_hmacmd5_update,
	.final = (tee_mac_final_func_t)tee_openssl_hmacmd5_final,
};

TEE_Result tee_openssl_hmacmd5_init(struct tee_openssl_md5_context *ctx,
		const uint8_t *key, size_t len)
{
	HMAC_CTX *hmac_ctx = (HMAC_CTX *)ctx;

	HMAC_CTX_init(hmac_ctx);
	/*
	 * This call will cause a couple of calls to malloc(), that's not
	 * 100% compliant with Global Platform as there's a requirement
	 * that all memory should be pre-allocated at an earlier stage to
	 * avoid out of memory errors at this stage.
	 */
	if (!HMAC_Init_ex(hmac_ctx, key, len, EVP_md5(), NULL))
		return TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

TEE_Result tee_openssl_hmacmd5_update(struct tee_openssl_md5_context *ctx,
		const uint8_t *data, size_t len)
{
	if (!HMAC_Update((HMAC_CTX *)ctx, data, len))
		return TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

TEE_Result tee_openssl_hmacmd5_final(struct tee_openssl_md5_context *ctx,
                const uint8_t *data, size_t data_len,
		uint8_t *digest, size_t digest_len)
{
	unsigned int l;

	if (data_len && !HMAC_Update((HMAC_CTX *)ctx, data, data_len))
		return TEE_ERROR_GENERIC;

	if (digest_len < MD5_DIGEST_LENGTH) {
		uint8_t d[MD5_DIGEST_LENGTH];

		l = sizeof(d);
		if (HMAC_Final((HMAC_CTX *)ctx, d, &l)) {
			memcpy(digest, d, digest_len);
			return TEE_SUCCESS;
		}
	} else {
		l = digest_len;
		if (HMAC_Final((HMAC_CTX *)ctx, digest, &l))
			return TEE_SUCCESS;
	}
	return TEE_ERROR_GENERIC;
}

struct tee_openssl_aesgcm_context;

const struct tee_authenc_prop tee_openssl_aesgcm_prop = {
	.context_size = sizeof(EVP_CIPHER_CTX),
	.init = (tee_authenc_init_func_t)tee_openssl_aesgcm_init,
	.update_aad = (tee_authenc_update_aad_func_t)
			tee_openssl_aesgcm_update_aad,
	.update_payload = (tee_authenc_update_payload_func_t)
			tee_openssl_aesgcm_update_payload,
	.enc_final = (tee_authenc_enc_final_func_t)
			tee_openssl_aesgcm_enc_final,
	.dec_final = (tee_authenc_dec_final_func_t)
			tee_openssl_aesgcm_dec_final,
	.final = (tee_authenc_final_func_t)tee_openssl_aesgcm_final,
};

TEE_Result tee_openssl_aesgcm_init(struct tee_openssl_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *key, size_t key_len,
		const uint8_t *nonce, size_t nonce_len, size_t tag_len,
		size_t aad_len, size_t payload_len)
{
	EVP_CIPHER_CTX *ciph_ctx = (EVP_CIPHER_CTX *)ctx;
	const EVP_CIPHER *cipher;

	switch (key_len * 8) {
	case 128:
		cipher = EVP_aes_128_gcm();
		break;
	case 192:
		cipher = EVP_aes_192_gcm();
		break;
	case 256:
		cipher = EVP_aes_256_gcm();
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	EVP_CIPHER_CTX_init(ciph_ctx);

	if (mode == TEE_MODE_ENCRYPT) {
		if (!EVP_EncryptInit_ex(ciph_ctx, cipher, NULL, NULL, NULL))
			return TEE_ERROR_GENERIC;
		if (!EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_GCM_SET_IVLEN,
				nonce_len, NULL))
			return TEE_ERROR_GENERIC;
		if (!EVP_EncryptInit_ex(ciph_ctx, NULL, NULL, key, nonce))
			return TEE_ERROR_GENERIC;
	} else if (mode == TEE_MODE_DECRYPT) {
		if (!EVP_DecryptInit_ex(ciph_ctx, cipher, NULL, NULL, NULL))
			return TEE_ERROR_GENERIC;
		if (!EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_GCM_SET_IVLEN,
				nonce_len, NULL))
			return TEE_ERROR_GENERIC;
		if (!EVP_DecryptInit_ex(ciph_ctx, NULL, NULL, key, nonce))
			return TEE_ERROR_GENERIC;
	} else
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

TEE_Result tee_openssl_aesgcm_update_aad(struct tee_openssl_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *data, size_t len)
{
	EVP_CIPHER_CTX *ciph_ctx = (EVP_CIPHER_CTX *)ctx;
	int outlen = 0;

	if (mode == TEE_MODE_ENCRYPT) {
		if (!EVP_EncryptUpdate(ciph_ctx, NULL, &outlen, data, len))
			return TEE_ERROR_GENERIC;
	} else if (mode == TEE_MODE_DECRYPT) {
		if (!EVP_DecryptUpdate(ciph_ctx, NULL, &outlen, data, len))
			return TEE_ERROR_GENERIC;
	} else
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

TEE_Result tee_openssl_aesgcm_update_payload(
		struct tee_openssl_aesgcm_context *ctx,
		TEE_OperationMode mode, const uint8_t *src_data,
		size_t src_len, uint8_t *dst_data)
{
	EVP_CIPHER_CTX *ciph_ctx = (EVP_CIPHER_CTX *)ctx;
	int outlen = src_len;

	if (mode == TEE_MODE_ENCRYPT) {
		if (!EVP_EncryptUpdate(ciph_ctx, dst_data, &outlen,
					src_data, src_len))
			return TEE_ERROR_GENERIC;
	} else if (mode == TEE_MODE_DECRYPT) {
		if (!EVP_DecryptUpdate(ciph_ctx, dst_data, &outlen,
					src_data, src_len))
			return TEE_ERROR_GENERIC;
	} else
		return TEE_ERROR_BAD_PARAMETERS;
	if (outlen != src_len)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result tee_openssl_aesgcm_enc_final(struct tee_openssl_aesgcm_context *ctx,
		const uint8_t *src_data, size_t src_len,
		uint8_t *dst_data, uint8_t *dst_tag, size_t *dst_tag_len)
{
	EVP_CIPHER_CTX *ciph_ctx = (EVP_CIPHER_CTX *)ctx;
	int outlen;
	uint8_t outbuf[8];

	if (src_data && src_len) {
		outlen = src_len;
		if (!EVP_EncryptUpdate(ciph_ctx, dst_data, &outlen,
					src_data, src_len))
			return TEE_ERROR_GENERIC;
		if (outlen != src_len)
			return TEE_ERROR_GENERIC;
	}

	outlen = sizeof(outbuf);
	if (!EVP_EncryptFinal_ex(ciph_ctx, outbuf, &outlen))
		return TEE_ERROR_GENERIC;
	if (outlen != 0)
		return TEE_ERROR_GENERIC;

	if (!EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_GCM_GET_TAG,
				*dst_tag_len, dst_tag))
		return TEE_ERROR_GENERIC;

	EVP_CIPHER_CTX_cleanup(ciph_ctx);

	return TEE_SUCCESS;
}

TEE_Result tee_openssl_aesgcm_dec_final(struct tee_openssl_aesgcm_context *ctx,
		const uint8_t *src_data, size_t src_len,
		uint8_t *dst_data, const uint8_t *tag, size_t tag_len)
{
	EVP_CIPHER_CTX *ciph_ctx = (EVP_CIPHER_CTX *)ctx;
	int outlen;
	uint8_t outbuf[8];

	if (src_data && src_len) {
		outlen = src_len;
		if (!EVP_DecryptUpdate(ciph_ctx, dst_data, &outlen,
					src_data, src_len))
			return TEE_ERROR_GENERIC;
		if (outlen != src_len)
			return TEE_ERROR_GENERIC;
	}

	if (!EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_GCM_SET_TAG,
				tag_len, (uint8_t *)tag))
		return TEE_ERROR_GENERIC;

	outlen = sizeof(outbuf);
	if (!EVP_DecryptFinal_ex(ciph_ctx, outbuf, &outlen))
		return TEE_ERROR_GENERIC;
	if (outlen != 0)
		return TEE_ERROR_GENERIC;

	EVP_CIPHER_CTX_cleanup(ciph_ctx);

	return TEE_SUCCESS;
}

void tee_openssl_aesgcm_final(struct tee_openssl_aesgcm_context *ctx)
{
}
