/**
 * @file hmac.c TLS HMAC routines
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_list.h>
#include <re_hmac.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


int hmac_sha256(const uint8_t *key,
		size_t         key_len,
		const uint8_t *data,
		size_t         data_len,
		uint8_t*       out,
		size_t         out_size)
{
	struct hmac *hmac;
	int err;

	err = hmac_create(&hmac, HMAC_HASH_SHA256, key, key_len);
	if (err)
		return err;

	err = hmac_digest(hmac, out, out_size, data, data_len);

	mem_deref(hmac);

	return err;
}
