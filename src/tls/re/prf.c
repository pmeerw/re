/**
 * @file prf.c TLS Pseudorandom Function (PRF)
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_hmac.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


static int a_func(uint8_t *out, size_t out_len,
		  const uint8_t *secret, size_t secret_len,
		  const uint8_t *a_prev, size_t a_prev_len)
{
	return hmac_sha256(secret, secret_len,
			   a_prev, a_prev_len,
			   out, out_len);
}


static int P_hash_sha256(uint8_t *output, size_t output_len,
			 const uint8_t *secret, size_t secret_len,
			 const uint8_t *seed, size_t seed_len)
{
	uint8_t a[32];
	int err;

	a_func(a, sizeof(a), secret, secret_len, seed, seed_len);

	while (output_len != 0) {
		uint8_t data[256];
		uint8_t md[32];
		size_t chunk_len = min(32, output_len);
		size_t data_len = 0;

		if (sizeof(a) + seed_len > sizeof(data))
			return EINVAL;

		memcpy(&data[data_len], a, sizeof(a));   data_len += sizeof(a);
		memcpy(&data[data_len], seed, seed_len); data_len += seed_len;

		err = hmac_sha256(secret, secret_len, data, data_len,
				  md, sizeof(md));
		if (err)
			break;

		a_func(a, sizeof(a), secret, secret_len, a, sizeof(a));

		mem_cpy(output, output_len, md, chunk_len);

		output     += chunk_len;
		output_len -= chunk_len;
	}

	return err;
}


/*
 * RFC 5246 Section 5
 *
 * 5.  HMAC and the Pseudorandom Function
 *
      P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                             HMAC_hash(secret, A(2) + seed) +
                             HMAC_hash(secret, A(3) + seed) + ...

      PRF(secret, label, seed) = P_<hash>(secret, label + seed)

 */
int tls_prf_sha256(uint8_t *output, size_t output_len,
		   const uint8_t *secret, size_t secret_len,
		   const uint8_t *label, size_t label_len,
		   const uint8_t *seed, size_t seed_len)
{
	uint8_t label_seed[256];

	if (label_len + seed_len > sizeof(label_seed))
		return EINVAL;

	memcpy(label_seed, label, label_len);
	memcpy(&label_seed[label_len], seed, seed_len);

	return P_hash_sha256(output, output_len,
			     secret, secret_len,
			     label_seed, label_len + seed_len);
}
