/**
 * @file openssl/aes.c  AES (Advanced Encryption Standard) using OpenSSL
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_aes.h>


#ifdef EVP_CIPH_CTR_MODE


struct aes {
	EVP_CIPHER_CTX *ctx;
};


static void destructor(void *arg)
{
	struct aes *st = arg;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (st->ctx)
		EVP_CIPHER_CTX_free(st->ctx);
#else
	if (st->ctx)
		EVP_CIPHER_CTX_cleanup(st->ctx);
	mem_deref(st->ctx);
#endif
}


int aes_alloc(struct aes **aesp, enum aes_mode mode,
	      const uint8_t *key, size_t key_bits,
	      const uint8_t iv[AES_BLOCK_SIZE])
{
	const EVP_CIPHER *cipher;
	struct aes *st;
	int err = 0, r;
	bool decrypt = mode == AES_MODE_CBC_DECRYPT;

	if (!aesp || !key)
		return EINVAL;

	st = mem_zalloc(sizeof(*st), destructor);
	if (!st)
		return ENOMEM;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	st->ctx = EVP_CIPHER_CTX_new();
	if (!st->ctx) {
		ERR_clear_error();
		err = ENOMEM;
		goto out;
	}

#else
	st->ctx = mem_zalloc(sizeof(*st->ctx), NULL);
	if (!st->ctx) {
		err = ENOMEM;
		goto out;
	}

	EVP_CIPHER_CTX_init(st->ctx);
#endif

	switch (mode) {

	case AES_MODE_CTR:
		switch (key_bits) {

		case 128: cipher = EVP_aes_128_ctr(); break;
		case 192: cipher = EVP_aes_192_ctr(); break;
		case 256: cipher = EVP_aes_256_ctr(); break;
		default:
			re_fprintf(stderr, "aes: unknown key: %zu bits\n",
				   key_bits);
			err = EINVAL;
			goto out;
		}
		break;

	case AES_MODE_CBC_ENCRYPT:
	case AES_MODE_CBC_DECRYPT:
		switch (key_bits) {

		case 128: cipher = EVP_aes_128_cbc(); break;
		case 192: cipher = EVP_aes_192_cbc(); break;
		case 256: cipher = EVP_aes_256_cbc(); break;
		default:
			re_fprintf(stderr, "aes: unknown key: %zu bits\n",
				   key_bits);
			err = EINVAL;
			goto out;
		}
		break;

	default:
		err = ENOTSUP;
		goto out;
	}

	/* NOTE: for CBC-mode, Encrypt and Decrypt is different */
	if (decrypt) {
		r = EVP_DecryptInit_ex(st->ctx, cipher, NULL, key, iv);
		if (!r) {
			ERR_clear_error();
			err = EPROTO;
		}
	}
	else {
		r = EVP_EncryptInit_ex(st->ctx, cipher, NULL, key, iv);
		if (!r) {
			ERR_clear_error();
			err = EPROTO;
		}
	}

	/* disable padding, this is needed for CBC-mode */
	EVP_CIPHER_CTX_set_padding(st->ctx, 0);

 out:
	if (err)
		mem_deref(st);
	else
		*aesp = st;

	return err;
}


void aes_set_iv(struct aes *aes, const uint8_t iv[AES_BLOCK_SIZE])
{
	int r;

	if (!aes || !iv)
		return;

	r = EVP_EncryptInit_ex(aes->ctx, NULL, NULL, NULL, iv);
	if (!r)
		ERR_clear_error();
}


int aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int c_len;

	if (!aes || !out || !in)
		return EINVAL;

	if (!EVP_EncryptUpdate(aes->ctx, out, &c_len, in, (int)len)) {
		ERR_clear_error();
		return EPROTO;
	}

	return 0;
}


int aes_decr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int len_upd;

	if (!aes || !out || !in)
		return EINVAL;

	if (!EVP_DecryptUpdate(aes->ctx, out, &len_upd, in, (int)len)) {
		ERR_clear_error();
		return EPROTO;
	}

	return 0;
}


#else /* EVP_CIPH_CTR_MODE */


struct aes {
	AES_KEY key;
	uint8_t iv[AES_BLOCK_SIZE];
};


static void destructor(void *arg)
{
	struct aes *st = arg;

	memset(&st->key, 0, sizeof(st->key));
}


int aes_alloc(struct aes **aesp, enum aes_mode mode,
	      const uint8_t *key, size_t key_bits,
	      const uint8_t iv[AES_BLOCK_SIZE])
{
	struct aes *st;
	int err = 0, r;

	if (!aesp || !key)
		return EINVAL;

	if (mode != AES_MODE_CTR)
		return ENOTSUP;

	st = mem_zalloc(sizeof(*st), destructor);
	if (!st)
		return ENOMEM;

	r = AES_set_encrypt_key(key, (int)key_bits, &st->key);
	if (r != 0) {
		err = EPROTO;
		goto out;
	}
	if (iv)
		memcpy(st->iv, iv, sizeof(st->iv));

 out:
	if (err)
		mem_deref(st);
	else
		*aesp = st;

	return err;
}


void aes_set_iv(struct aes *aes, const uint8_t iv[AES_BLOCK_SIZE])
{
	if (!aes)
		return;

	if (iv)
		memcpy(aes->iv, iv, sizeof(aes->iv));
}


int aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	unsigned char ec[AES_BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	unsigned int num = 0;

	if (!aes || !out || !in)
		return EINVAL;

	AES_ctr128_encrypt(in, out, len, &aes->key, aes->iv, ec, &num);

	return 0;
}


#endif /* EVP_CIPH_CTR_MODE */
