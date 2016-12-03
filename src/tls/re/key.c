/**
 * @file key.c TLS key routines
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/* 6.3.  Key Calculation */


#define KEY_INIT(key, p, l)			\
	if ((l) > sizeof((key)->k)) {		\
		re_printf("%s: key too big (%zu > %zu)\n", __func__, \
			  (l), sizeof((key)->k));	 \
		return EOVERFLOW;		\
	}					\
	memcpy((key)->k, (p), (l));		\
	(key)->len = (l);			\
	(p) += (l);


static const uint8_t empty_master_secret[TLS_MASTER_SECRET_LEN] = {0};


/*
      key_block = PRF(SecurityParameters.master_secret,
                      "key expansion",
                      SecurityParameters.server_random +
                      SecurityParameters.client_random);
 */
int tls_keys_generate(struct tls_key_block *keys,
		       const struct tls_secparam *sp)
{
	size_t wanted_len;
	uint8_t *buf=0, *p=0;
	static const uint8_t label[13] = "key expansion";
	uint8_t seed[TLS_CLIENT_RANDOM_LEN + TLS_SERVER_RANDOM_LEN];
	int err = 0;

	if (!keys || !sp)
		return EINVAL;

	if (keys->client_write_key.len) {
		DEBUG_WARNING("keys already generated\n");
		return EALREADY;
	}

	if (0 == memcmp(sp->master_secret, empty_master_secret,
			sizeof(sp->master_secret))) {
		DEBUG_WARNING("tls_keys_generate: master secret not set\n");
		return EPROTO;
	}

	wanted_len = sp->mac_key_length * 2 + sp->enc_key_length * 2;

	buf = mem_alloc(wanted_len, NULL);
	if (!buf)
		return ENOMEM;

	p = buf;

	mem_cpy(&seed[ 0], 32, sp->server_random, sizeof(sp->server_random));
	mem_cpy(&seed[32], 32, sp->client_random, sizeof(sp->client_random));

	err = tls_prf_sha256(p, wanted_len,
			      sp->master_secret, sizeof(sp->master_secret),
			      label, sizeof(label),
			      seed, sizeof(seed));
	if (err)
		goto out;

	KEY_INIT(&keys->client_write_MAC_key, p, sp->mac_key_length);
	KEY_INIT(&keys->server_write_MAC_key, p, sp->mac_key_length);
	KEY_INIT(&keys->client_write_key, p, sp->enc_key_length);
	KEY_INIT(&keys->server_write_key, p, sp->enc_key_length);

 out:
	mem_deref(buf);
	return err;
}
