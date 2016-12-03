/**
 * @file mbuf.c TLS mbuf routines
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re_types.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


int mbuf_write_u24_hton(struct mbuf *mb, uint24_t u)
{
	int err = 0;

	err |= mbuf_write_u8(mb, u >> 16);
	err |= mbuf_write_u8(mb, u >> 8);
	err |= mbuf_write_u8(mb, u >> 0);

	return err;
}


uint24_t mbuf_read_u24_ntoh(struct mbuf *mb)
{
	uint24_t u;

	u  = (uint24_t)mbuf_read_u8(mb) << 16;
	u |= (uint24_t)mbuf_read_u8(mb) << 8;
	u |= (uint24_t)mbuf_read_u8(mb) << 0;

	return u;
}


int mbuf_write_u48_hton(struct mbuf *mb, uint48_t u)
{
	int err = 0;

	err |= mbuf_write_u16(mb, htons(u >> 32));
	err |= mbuf_write_u32(mb, htonl(u & 0xffffffff));

	return err;
}


uint48_t mbuf_read_u48_ntoh(struct mbuf *mb)
{
	uint48_t v;

	v   = (uint64_t)ntohs(mbuf_read_u16(mb)) << 32;
	v  |= ntohl(mbuf_read_u32(mb));

	return v;
}
