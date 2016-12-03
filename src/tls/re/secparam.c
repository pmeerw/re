
#include <string.h>
#include <time.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sys.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


/*
 * RFC 5246 A.6.  The Security Parameters
 */


int tls_secparam_init(struct tls_secparam *sp,
		       const uint8_t random[32],
		       bool is_write, bool client)
{
	if (!sp)
		return EINVAL;

	memset(sp, 0, sizeof(*sp));

	sp->entity                = client ? TLS_CLIENT : TLS_SERVER;
	sp->prf_algorithm         = TLS_PRF_TLS_PRF_SHA256; /* fixed */

	if (client) {
		mem_cpy(sp->client_random, sizeof(sp->client_random),
			random, 32);
	}
	else {
		mem_cpy(sp->server_random, sizeof(sp->server_random),
			random, 32);
	}

	sp->is_write = is_write;

	return 0;
}


int tls_secparam_set(struct tls_secparam *sp,
		      const struct tls_suite *suite)
{
	if (!sp || !suite)
		return EINVAL;

	sp->bulk_cipher_algorithm = tls_cipher_algorithm(suite->cipher);
	sp->cipher_type           = tls_cipher_type(suite->cipher);
	sp->enc_key_length        = tls_cipher_keymaterial(suite->cipher);
	sp->block_length          = tls_cipher_blocksize(suite->cipher);
	sp->fixed_iv_length       = tls_cipher_ivsize(suite->cipher);
	sp->record_iv_length      = tls_cipher_ivsize(suite->cipher);
	sp->mac_algorithm         = suite->mac;
	sp->mac_length            = tls_mac_length(suite->mac);
	sp->mac_key_length        = tls_mac_length(suite->mac);

	return 0;
}


static const char *tls_bulkcipher_name(enum tls_bulkcipher_algorithm algo)
{
	switch (algo) {

	case TLS_BULKCIPHER_NULL:  return "Null";
	case TLS_BULKCIPHER_AES:   return "AES";
	default: return "???";
	}
}


static const char *tls_ciphertype_name(enum tls_ciphertype type)
{
	switch (type) {

	case TLS_CIPHERTYPE_STREAM:  return "Stream";
	case TLS_CIPHERTYPE_BLOCK:   return "Block";
	/*case TLS_CIPHERTYPE_AEAD:    return "AEAD";*/
	default: return "???";
	}
}


static const char *tls_mac_name(enum tls_mac_algorithm mac)
{
	switch (mac) {

	case TLS_MAC_NULL:         return "Null";
	case TLS_MAC_HMAC_SHA1:    return "HMAC_SHA1";
	case TLS_MAC_HMAC_SHA256:  return "HMAC_SHA256";
	/*case TLS_MAC_HMAC_SHA384:  return "HMAC_SHA384";*/
	/*case TLS_MAC_HMAC_SHA512:  return "HMAC_SHA512";*/
	default: return "???";
	}
}


void tls_secparam_dump(const struct tls_secparam *sp)
{
	if (!sp)
		return;

	re_printf("SecurityParameters (%s):\n",
		  sp->entity == TLS_CLIENT ? "Client" : "Server");
	re_printf("PRF:               %s\n",
	  sp->prf_algorithm==TLS_PRF_TLS_PRF_SHA256 ? "SHA256" : "?");
	re_printf("bulk_cipher:       %s\n",
		  tls_bulkcipher_name(sp->bulk_cipher_algorithm));
	re_printf("cipher_type:       %s\n",
		  tls_ciphertype_name(sp->cipher_type));
	re_printf("enc_key_length:    %zu bytes\n", sp->enc_key_length);
	re_printf("block_length:      %zu bytes\n", sp->block_length);
	re_printf("fixed_iv_length:   %zu bytes\n", sp->fixed_iv_length);
	re_printf("record_iv_length:  %zu bytes\n", sp->record_iv_length);
	re_printf("mac_algorithm:     %s\n",
		  tls_mac_name(sp->mac_algorithm));
	re_printf("mac_length:        %zu bytes\n", sp->mac_length);
	re_printf("mac_key_length:    %zu bytes\n", sp->mac_key_length);

	re_printf("master_secret[]:   %w\n",
		  sp->master_secret, sizeof(sp->master_secret));
	re_printf("client_random[]:   %w\n",
		  sp->client_random, sizeof(sp->client_random));
	re_printf("server_random[]:   %w\n",
		  sp->server_random, sizeof(sp->server_random));
	re_printf("\n");
}
