/**
 * @file cipher.c TLS ciphers
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_srtp.h>
#include <re_tls.h>


/* key exchange types */
#define K_NULL       TLS_KE_K_NULL
#define RSA          TLS_KE_RSA

/* ciphers */
#define C_NULL       TLS_C_NULL
#define AES_128_CBC  TLS_AES_128_CBC
#define AES_256_CBC  TLS_AES_256_CBC

/* MAC */
#define M_NULL       TLS_MAC_NULL
#define SHA          TLS_MAC_HMAC_SHA1
#define SHA1         TLS_MAC_HMAC_SHA1
#define SHA256       TLS_MAC_HMAC_SHA256


static const struct tls_suite suites[] = {

/*
 * Cipher Suite                          Key           Cipher          Mac
 *                                       Exchange
 */

{TLS_NULL_WITH_NULL_NULL,                K_NULL,       C_NULL,         M_NULL},

{TLS_RSA_WITH_NULL_SHA,                  RSA,          C_NULL,         SHA   },
{TLS_RSA_WITH_NULL_SHA256,               RSA,          C_NULL,         SHA256},
{TLS_RSA_WITH_AES_128_CBC_SHA,           RSA,          AES_128_CBC,    SHA   },
{TLS_RSA_WITH_AES_256_CBC_SHA,           RSA,          AES_256_CBC,    SHA   },
{TLS_RSA_WITH_AES_128_CBC_SHA256,        RSA,          AES_128_CBC,    SHA256},
{TLS_RSA_WITH_AES_256_CBC_SHA256,        RSA,          AES_256_CBC,    SHA256},

};


unsigned tls_cipher_suite_count(void)
{
	return ARRAY_SIZE(suites);
}


const struct tls_suite *tls_suite_lookup(enum tls_cipher_suite cipher_suite)
{
	unsigned i;

	for (i=0; i<ARRAY_SIZE(suites); i++) {

		if (cipher_suite == suites[i].suite)
			return &suites[i];
	}

	return NULL;
}


enum tls_ciphertype tls_cipher_type(enum tls_cipher cipher)
{
	switch (cipher) {

	case C_NULL:          return TLS_CIPHERTYPE_STREAM;
	case AES_128_CBC:     return TLS_CIPHERTYPE_BLOCK;
	case AES_256_CBC:     return TLS_CIPHERTYPE_BLOCK;

	default: return (enum tls_ciphertype)-1;
	}
}


unsigned tls_cipher_keymaterial(enum tls_cipher cipher)
{
	switch (cipher) {

	case C_NULL:          return 0;
	case AES_128_CBC:     return 16;
	case AES_256_CBC:     return 32;
	default: return 0;
	}
}


unsigned tls_cipher_ivsize(enum tls_cipher cipher)
{
	switch (cipher) {

	case C_NULL:          return 0;
	case AES_128_CBC:     return 16;
	case AES_256_CBC:     return 16;
	default: return 0;
	}
}


unsigned tls_cipher_blocksize(enum tls_cipher cipher)
{
	switch (cipher) {

	case C_NULL:          return 0;
	case AES_128_CBC:     return 16;
	case AES_256_CBC:     return 16;
	default: return 0;
	}
}


enum tls_bulkcipher_algorithm tls_cipher_algorithm(enum tls_cipher cipher)
{
	switch (cipher) {

	case C_NULL:          return TLS_BULKCIPHER_NULL;
	case AES_128_CBC:     return TLS_BULKCIPHER_AES;
	case AES_256_CBC:     return TLS_BULKCIPHER_AES;
	default: return TLS_BULKCIPHER_NULL;
	}
}


/* bytes */
unsigned tls_mac_length(enum tls_mac_algorithm mac)
{
	switch (mac) {

	case TLS_MAC_NULL:        return 0;
	case TLS_MAC_HMAC_SHA1:   return 20;
	case TLS_MAC_HMAC_SHA256: return 32;
	/*case TLS_MAC_HMAC_SHA384: return 48;*/
	/*case TLS_MAC_HMAC_SHA512: return 64;*/
	default: return 0;
	}
}

#define CIPH(a) {a, #a}

static const struct {
	enum tls_cipher_suite cs;
	const char *name;
} table[] = {

	CIPH(TLS_RSA_WITH_NULL_SHA),
	CIPH(TLS_RSA_WITH_NULL_SHA256),
	CIPH(TLS_RSA_WITH_AES_128_CBC_SHA),
	CIPH(TLS_RSA_WITH_AES_256_CBC_SHA),
	CIPH(TLS_RSA_WITH_AES_128_CBC_SHA256),
	CIPH(TLS_RSA_WITH_AES_256_CBC_SHA256),
};


const char *tls_cipher_suite_name(enum tls_cipher_suite cs)
{
	switch (cs) {

	case TLS_NULL_WITH_NULL_NULL:
		return "TLS_NULL_WITH_NULL_NULL";

	case TLS_RSA_WITH_NULL_SHA:
		return "TLS_RSA_WITH_NULL_SHA";

	case TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA";

	case TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA";

	case TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256";

	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		return "TLS_RSA_WITH_AES_256_CBC_SHA256";

	default:
		return "???";
	}
}


enum tls_cipher_suite tls_cipher_suite_resolve(const char *name)
{
	size_t i;
	for (i=0; i<ARRAY_SIZE(table); i++) {
		if (0 == str_casecmp(name, table[i].name))
			return table[i].cs;
	}
	return TLS_NULL_WITH_NULL_NULL;
}
