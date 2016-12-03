/**
 * @file vector.c TLS vector
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define VECTOR_MAX_LENGTH (1U<<24)


int tls_vector_init(struct tls_vector *vect,
		    const uint8_t *data, size_t len)
{
	if (!vect)
		return EINVAL;

	vect->bytes = len;

	if (data && len) {

		vect->data = mem_alloc(len, NULL);
		if (!vect->data)
			return ENOMEM;

		mem_cpy(vect->data, vect->bytes, data, len);
	}
	else {
		vect->data = NULL;
	}

	return 0;
}


int tls_vector_encode(struct mbuf *mb, const struct tls_vector *vect,
		      unsigned hdr_bytes)
{
	int err = 0;

	if (hdr_bytes == 1)
		err = mbuf_write_u8(mb, vect->bytes);
	else if (hdr_bytes == 2)
		err = mbuf_write_u16(mb, htons(vect->bytes));
	else if (hdr_bytes == 3)
		err = mbuf_write_u24_hton(mb, (uint32_t)vect->bytes);
	else {
		DEBUG_WARNING("vector: invalid hdr_bytes=%zu\n", hdr_bytes);
		return EINVAL;
	}

	if (vect->bytes) {
		err |= mbuf_write_mem(mb, vect->data, vect->bytes);
	}

	return err;
}


int tls_vector_decode(struct tls_vector *vect, unsigned hdr_bytes,
		      struct mbuf *mb)
{
	int err = 0;

	if (hdr_bytes > mbuf_get_left(mb))
		return ENODATA;

	if (hdr_bytes == 1)
		vect->bytes = mbuf_read_u8(mb);
	else if (hdr_bytes == 2)
		vect->bytes = ntohs(mbuf_read_u16(mb));
	else if (hdr_bytes == 3)
		vect->bytes = mbuf_read_u24_ntoh(mb);
	else
		return EINVAL;

	if (vect->bytes) {
		vect->data = mem_alloc(vect->bytes, NULL);
		if (!vect->data)
			return ENOMEM;

		err = mbuf_read_mem(mb, vect->data, vect->bytes);
	}
	else {
		vect->data = NULL;
	}

	return err;
}


int tls_vector_decode_hdr(struct tls_vector *vect, unsigned hdr_bytes,
			  struct mbuf *mb)
{
	int err = 0;

	if (mbuf_get_left(mb) < hdr_bytes)
		return ENODATA;

	if (hdr_bytes == 1)
		vect->bytes = mbuf_read_u8(mb);
	else if (hdr_bytes == 2)
		vect->bytes = ntohs(mbuf_read_u16(mb));
	else if (hdr_bytes == 3)
		vect->bytes = mbuf_read_u24_ntoh(mb);
	else
		return EINVAL;

	if (mbuf_get_left(mb) < vect->bytes)
		return ENODATA;

	vect->data = mbuf_buf(mb);

	return err;
}


void tls_vector_reset(struct tls_vector *vect)
{
	if (!vect)
		return;

	vect->bytes = 0;
	vect->data = mem_deref(vect->data);
}
