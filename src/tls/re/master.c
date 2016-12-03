
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


/*
 * RFC 5246 Section 8.1.  Computing the Master Secret
 *
 * <pre>
   master_secret = PRF(pre_master_secret, "master secret",
                       ClientHello.random + ServerHello.random)
                       [0..47];
 * <pre>
 */
static const uint8_t empty_random[32] = {0};


int tls_master_secret_compute(uint8_t master_secret[48],
			      const uint8_t *pre_master_secret,
			      size_t pre_master_secret_len,
			      const uint8_t client_random[32],
			      const uint8_t server_random[32])
{
	static const uint8_t label[13] = "master secret";
	uint8_t seed[TLS_CLIENT_RANDOM_LEN + TLS_SERVER_RANDOM_LEN];

	if (!master_secret || !pre_master_secret || !pre_master_secret_len ||
	    !client_random || !server_random)
		return EINVAL;

	if (0 == memcmp(client_random, empty_random, sizeof(empty_random)) ||
	    0 == memcmp(server_random, empty_random, sizeof(empty_random))) {
		re_printf("master_secret_compute: client/server random"
			  " is not set\n");
		return EPROTO;
	}

	mem_cpy(&seed[ 0], 32, client_random, TLS_CLIENT_RANDOM_LEN);
	mem_cpy(&seed[32], 32, server_random, TLS_SERVER_RANDOM_LEN);

	return tls_prf_sha256(master_secret, TLS_MASTER_SECRET_LEN,
			  pre_master_secret, pre_master_secret_len,
			  label, sizeof(label),
			  seed, sizeof(seed));
}
