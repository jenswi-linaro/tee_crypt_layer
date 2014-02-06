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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_cipher.h>
#include <tee_hash.h>
#include <tee_mac.h>
#include <tee_authenc.h>
#include <utee_defines.h>

#include <tee_openssl.h>
#include <tee_tomcrypt.h>

#include <assert.h>

static void test_hash(bool tomcrypt)
{
	TEE_Result res;
	size_t n;
	struct tee_hash_context *ctx;
	uint8_t buf[32];
	const struct tee_hash_prop *prop;

	printf("Hash Started\n");
	if (tomcrypt)
		prop = &tee_tomcrypt_md5_prop;
	else
		prop = &tee_openssl_md5_prop;
	res = tee_hash_register_algo(TEE_ALG_MD5, prop);
	assert(res == TEE_SUCCESS);

	res = tee_hash_get_ctx_size(TEE_ALG_MD5, &n);
	assert(res == TEE_SUCCESS);
	printf("TEE_ALG_MD5 ctx size %zu\n", n);

	ctx = malloc(n);
	assert(ctx);

	res = tee_hash_get_digest_size(TEE_ALG_MD5, &n);
	assert(res == TEE_SUCCESS);
	printf("TEE_ALG_MD5 digest size %zu\n", n);

	res = tee_hash_init(ctx, TEE_ALG_MD5);
	assert(res == TEE_SUCCESS);

	res = tee_hash_update(ctx, TEE_ALG_MD5, (const uint8_t *)"hej", 3);
	assert(res == TEE_SUCCESS);

	memset(buf, 0xff, sizeof(buf));
	res = tee_hash_final(ctx, TEE_ALG_MD5, buf, sizeof(buf));
	assert(res == TEE_SUCCESS);

	free(ctx);

	for (n = 0; n < sizeof(buf); n++)
		printf("0x%02x ", buf[n]);
	printf("\n");

	printf("Hash Done\n");
}

static void test_cipher(bool tomcrypt)
{
	TEE_Result res;
	size_t n;
	struct tee_cipher_context *ctx;
	uint8_t in[] = {
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,  /* 23456789 */
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31,  /* ABCDEF01 */
		0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41,  /* 3456789A */
		0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32,  /* BCDEF012 */
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42,  /* 456789AB */
		0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33,  /* CDEF0123 */
	};
	uint8_t key[] = {
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  /* 01234567 */
		0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,  /* 89ABCDEF */
	};
	uint8_t iv[]= {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,  /* 12345678 */
		0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30,  /* 9ABCDEF0 */
	};
	uint8_t exp_out[] = {
		0x8D, 0x9F, 0x88, 0xD8, 0xAF, 0x9F, 0xC1, 0x3B,  /* .......; */
		0x02, 0x15, 0x43, 0x6A, 0x8C, 0x1E, 0x34, 0x5C,  /* ..Cj..4\ */
		0x83, 0xF4, 0x85, 0x3E, 0x43, 0x0F, 0xE5, 0x5F,  /* ...>C.._ */
		0x81, 0x4C, 0xC0, 0x28, 0x3F, 0xD9, 0x98, 0x53,  /* .L.(?..S */
		0xB1, 0x44, 0x51, 0x38, 0x21, 0xAB, 0x10, 0xCE,  /* .DQ8!... */
		0xC2, 0xEC, 0x65, 0x54, 0xDD, 0x5C, 0xEA, 0xDC,  /* ..eT.\.. */
	};
	uint8_t buf[sizeof(exp_out)];
	const struct tee_cipher_prop *prop;

	printf("Cipher Started\n");
	if (tomcrypt)
		prop = &tee_tomcrypt_aescbc_prop;
	else
		prop = &tee_openssl_aescbc_prop;
	res = tee_cipher_register_algo(TEE_ALG_AES_CBC_NOPAD, prop);
	assert(res == TEE_SUCCESS);

	res = tee_cipher_get_ctx_size(TEE_ALG_AES_CBC_NOPAD, &n);
	assert(res == TEE_SUCCESS);
	printf("TEE_ALG_AES_CBC_NOPAD ctx size %zu\n", n);

	ctx = malloc(n);
	assert(ctx);

	res = tee_cipher_get_block_size(TEE_ALG_AES_CBC_NOPAD, &n);
	assert(res == TEE_SUCCESS);
	printf("TEE_ALG_AES_CBC_NOPAD block size %zu\n", n);

	res = tee_cipher_init2(ctx, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_ENCRYPT,
				key, sizeof(key), iv, sizeof(iv));
	assert(res == TEE_SUCCESS);

	res = tee_cipher_update(ctx, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_ENCRYPT,
		true, in, sizeof(in), buf);
	assert(res == TEE_SUCCESS);

	tee_cipher_final(ctx, TEE_ALG_AES_CBC_NOPAD);

	if (memcmp(buf, exp_out, sizeof(buf)) != 0) {
		printf("Unexpected output\n");
		for (n = 0; n < sizeof(buf); n++)
			printf("0x%02x ", buf[n]);
		printf("\n");
	}

	res = tee_cipher_init2(ctx, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT,
				key, sizeof(key), iv, sizeof(iv));
	assert(res == TEE_SUCCESS);

	res = tee_cipher_update(ctx, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT,
		true, exp_out, sizeof(exp_out), buf);
	assert(res == TEE_SUCCESS);

	tee_cipher_final(ctx, TEE_ALG_AES_CBC_NOPAD);

	if (memcmp(buf, in, sizeof(buf)) != 0) {
		printf("Unexpected output\n");
		for (n = 0; n < sizeof(buf); n++)
			printf("0x%02x ", buf[n]);
		printf("\n");
	}

	free(ctx);

	printf("Cipher Done\n");
}

static void test_mac(bool tomcrypt)
{
	TEE_Result res;
	size_t n;
	struct tee_mac_context *ctx;
	uint8_t in[] = {
		0x54,0x68,0x65,0x20, 0x71,0x75,0x69,0x63,  /* The quic */
		0x6B,0x20,0x62,0x72, 0x6F,0x77,0x6E,0x20,  /* k brown  */
		0x66,0x6F,0x78,0x20, 0x6A,0x75,0x6D,0x70,  /* fox jump */
		0x73,0x20,0x6F,0x76, 0x65,0x72,0x20,0x74,  /* s over t */
		0x68,0x65,0x20,0x6C, 0x61,0x7A,0x79,0x20,  /* he lazy  */
		0x64,0x6F,0x67, /* dog */
	};
	uint8_t key[] = {
		0x6B,0x65,0x79, /* key */
	};
	uint8_t exp_out[] = {
		0x80,0x07,0x07,0x13, 0x46,0x3e,0x77,0x49,
		0xb9,0x0c,0x2d,0xc2, 0x49,0x11,0xe2,0x75
	};
	uint8_t buf[sizeof(exp_out)];
	const struct tee_mac_prop *prop;

	printf("MAC Started\n");
	if (tomcrypt)
		prop = &tee_tomcrypt_hmacmd5_prop;
	else
		prop = &tee_openssl_hmacmd5_prop;
	res = tee_mac_register_algo(TEE_ALG_HMAC_MD5, prop);
	assert(res == TEE_SUCCESS);

	res = tee_mac_get_ctx_size(TEE_ALG_HMAC_MD5, &n);
	assert(res == TEE_SUCCESS);
	printf("TEE_ALG_HMAC_MD5 ctx size %zu\n", n);

	ctx = malloc(n);
	assert(ctx);

	res = tee_mac_get_digest_size(TEE_ALG_HMAC_MD5, &n);
	assert(res == TEE_SUCCESS);
	printf("TEE_ALG_HMAC_MD5 block size %zu\n", n);

	res = tee_mac_init(ctx, TEE_ALG_HMAC_MD5, key, sizeof(key));
	assert(res == TEE_SUCCESS);

	res = tee_mac_update(ctx, TEE_ALG_HMAC_MD5, in, sizeof(in));
	assert(res == TEE_SUCCESS);

	tee_mac_final(ctx, TEE_ALG_HMAC_MD5, NULL, 0, buf, sizeof(buf));

	if (memcmp(buf, exp_out, sizeof(buf)) != 0) {
		printf("Unexpected output\n");
		for (n = 0; n < sizeof(buf); n++)
			printf("0x%02x ", buf[n]);
		printf("\n");
	}

	free(ctx);

	printf("MAC Done\n");
}

static void test_authenc(bool tomcrypt)
{
	TEE_Result res;
	size_t n;
	struct tee_authenc_context *ctx;
	/*
	 * AES-GCM vectors from the reviced "The Galois/Counter Mode of
	 * Operation (GCM)" 2005-05-31 spec
	 */
	/*
	 * Test case 4
	 *              K feffe9928665731c6d6a8f9467308308
	 *              P d9313225f88406e5a55909c5aff5269a
	 *                86a7a9531534f7da2e4c303d8a318a72
	 *                1c3c0c95956809532fcf0e2449a6b525
	 *                b16aedf5aa0de657ba637b39
	 *              A feedfacedeadbeeffeedfacedeadbeef
	 *                abaddad2
	 *             IV cafebabefacedbaddecaf888
	 *              H b83b533708bf535d0aa6e52980d53b78
	 *             Y0 cafebabefacedbaddecaf88800000001
	 *       E(K, Y0) 3247184b3c4f69a44dbcd22887bbb418
	 *             X1 ed56aaf8a72d67049fdb9228edba1322
	 *             X2 cd47221ccef0554ee4bb044c88150352
	 *             Y1 cafebabefacedbaddecaf88800000002
	 *       E(K, Y1) 9bb22ce7d9f372c1ee2b28722b25f206
	 *             Y2 cafebabefacedbaddecaf88800000003
	 *       E(K, Y2) 650d887c3936533a1b8d4e1ea39d2b5c
	 *             Y3 cafebabefacedbaddecaf88800000004
	 *       E(K, Y3) 3de91827c10e9a4f5240647ee5221f20
	 *             Y4 cafebabefacedbaddecaf88800000005
	 *       E(K, Y4) aac9e6ccc0074ac0873b9ba85d908bd0
	 *             X3 54f5e1b2b5a8f9525c23924751a3ca51
	 *             X4 324f585c6ffc1359ab371565d6c45f93
	 *             X5 ca7dd446af4aa70cc3c0cd5abba6aa1c
	 *             X6 1590df9b2eb6768289e57d56274c8570
	 * len(A)||len(C) 00000000000000a000000000000001e0
	 *  GHASH(H, A,C) 698e57f70e6ecc7fd9463b7260a9ae5f
	 *              C 42831ec2217774244b7221b784d0d49c
	 *                e3aa212f2c02a4e035c17e2329aca12e
	 *                21d514b25466931c7d8f6a5aac84aa05
	 *                1ba30b396a0aac973d58e091
	 *              T 5bc94fbc3221a5db94fae95ae7121a47
	 */

	static const uint8_t ae_data_aes_gcm_vect4_key[] = {
		0xfe,0xff,0xe9,0x92, 0x86,0x65,0x73,0x1c,
		0x6d,0x6a,0x8f,0x94, 0x67,0x30,0x83,0x08
	};
	static const uint8_t ae_data_aes_gcm_vect4_nonce[] = {
		0xca,0xfe,0xba,0xbe, 0xfa,0xce,0xdb,0xad,
		0xde,0xca,0xf8,0x88
	};
	static const uint8_t ae_data_aes_gcm_vect4_aad[] = {
		0xfe,0xed,0xfa,0xce, 0xde,0xad,0xbe,0xef,
		0xfe,0xed,0xfa,0xce, 0xde,0xad,0xbe,0xef,
		0xab,0xad,0xda,0xd2
	};
	static const uint8_t ae_data_aes_gcm_vect4_ptx[] = {
		0xd9,0x31,0x32,0x25, 0xf8,0x84,0x06,0xe5,
		0xa5,0x59,0x09,0xc5, 0xaf,0xf5,0x26,0x9a,
		0x86,0xa7,0xa9,0x53, 0x15,0x34,0xf7,0xda,
		0x2e,0x4c,0x30,0x3d, 0x8a,0x31,0x8a,0x72,
		0x1c,0x3c,0x0c,0x95, 0x95,0x68,0x09,0x53,
		0x2f,0xcf,0x0e,0x24, 0x49,0xa6,0xb5,0x25,
		0xb1,0x6a,0xed,0xf5, 0xaa,0x0d,0xe6,0x57,
		0xba,0x63,0x7b,0x39
	};
	static const uint8_t ae_data_aes_gcm_vect4_ctx[] = {
		0x42,0x83,0x1e,0xc2, 0x21,0x77,0x74,0x24,
		0x4b,0x72,0x21,0xb7, 0x84,0xd0,0xd4,0x9c,
		0xe3,0xaa,0x21,0x2f, 0x2c,0x02,0xa4,0xe0,
		0x35,0xc1,0x7e,0x23, 0x29,0xac,0xa1,0x2e,
		0x21,0xd5,0x14,0xb2, 0x54,0x66,0x93,0x1c,
		0x7d,0x8f,0x6a,0x5a, 0xac,0x84,0xaa,0x05,
		0x1b,0xa3,0x0b,0x39, 0x6a,0x0a,0xac,0x97,
		0x3d,0x58,0xe0,0x91
	};
	static const uint8_t ae_data_aes_gcm_vect4_tag[] = {
		0x5b,0xc9,0x4f,0xbc, 0x32,0x21,0xa5,0xdb,
		0x94,0xfa,0xe9,0x5a, 0xe7,0x12,0x1a,0x47
	};

	uint8_t buf[sizeof(ae_data_aes_gcm_vect4_ctx)];
	uint8_t tag_buf[sizeof(ae_data_aes_gcm_vect4_tag)];
	size_t tag_buf_len = sizeof(tag_buf);
	const struct tee_authenc_prop *prop;


	printf("Authenc Started\n");
	if (tomcrypt)
		prop = &tee_tomcrypt_aesgcm_prop;
	else
		prop = &tee_openssl_aesgcm_prop;
	res = tee_authenc_register_algo(TEE_ALG_AES_GCM, prop);
	assert(res == TEE_SUCCESS);

	res = tee_authenc_get_ctx_size(TEE_ALG_AES_GCM, &n);
	assert(res == TEE_SUCCESS);
	printf("TEE_ALG_AES_GCM ctx size %zu\n", n);

	ctx = malloc(n);
	assert(ctx);

	res = tee_authenc_init(ctx, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT,
		ae_data_aes_gcm_vect4_key, sizeof(ae_data_aes_gcm_vect4_key),
		ae_data_aes_gcm_vect4_nonce,
			sizeof(ae_data_aes_gcm_vect4_nonce),
		sizeof(ae_data_aes_gcm_vect4_tag),
		sizeof(ae_data_aes_gcm_vect4_aad),
		sizeof(ae_data_aes_gcm_vect4_ptx));
	assert(res == TEE_SUCCESS);

	res = tee_authenc_update_aad(ctx, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT,
			ae_data_aes_gcm_vect4_aad, sizeof(ae_data_aes_gcm_vect4_aad));
	assert(res == TEE_SUCCESS);

	res = tee_authenc_update_payload(ctx, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT,
			ae_data_aes_gcm_vect4_ptx, sizeof(ae_data_aes_gcm_vect4_ptx), buf);
	assert(res == TEE_SUCCESS);

	res = tee_authenc_enc_final(ctx, TEE_ALG_AES_GCM, NULL, 0, NULL,
				tag_buf, &tag_buf_len);
	assert(res == TEE_SUCCESS);
	tee_authenc_final(ctx, TEE_ALG_AES_GCM);

	if (memcmp(buf, ae_data_aes_gcm_vect4_ctx, sizeof(buf)) != 0) {
		printf("Unexpected output\n");
		for (n = 0; n < sizeof(buf); n++)
			printf("0x%02x ", buf[n]);
		printf("\n");
	}

	if (memcmp(tag_buf, ae_data_aes_gcm_vect4_tag, sizeof(tag_buf)) != 0) {
		printf("Unexpected output tag\n");
		for (n = 0; n < sizeof(tag_buf); n++)
			printf("0x%02x ", tag_buf[n]);
		printf("\n");
	}

	free(ctx);

	printf("MAC Done\n");
}

int main(int argc, const char *argv[])
{
	printf("Started\n");
	tee_tomcrypt_init();

	/* OpenSSL tests */
	test_hash(false);
	test_cipher(false);
	test_mac(false);
	test_authenc(false);

	/* TomCrypt tests */
	test_hash(true);
	test_cipher(true);
	test_mac(true);
	test_authenc(true);

	printf("Done\n");
	return 0;
}
