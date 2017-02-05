/**
 * @file util.c TLS utilities
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <string.h>
#include <assert.h>  /* XXX: temporary during development */
#include <re_types.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


void mem_cpy(uint8_t *dst, size_t dst_sz,
	     const uint8_t *src, size_t src_sz)
{
	if (src_sz > dst_sz) {
		DEBUG_WARNING("mem_cpy: dst buf too small (%zu > %zu)\n",
			      src_sz, dst_sz);
		assert(0);
		return;
	}

	memcpy(dst, src, src_sz);
}


const char *tls_trace_name(enum tls_trace_flags flag)
{
	switch (flag) {

	case TLS_TRACE_RECORD:             return "RECORD";
	case TLS_TRACE_CHANGE_CIPHER_SPEC: return "CHANGE_CIPHER_SPEC";
	case TLS_TRACE_ALERT:              return "ALERT";
	case TLS_TRACE_HANDSHAKE:          return "HANDSHAKE";
	case TLS_TRACE_APPLICATION_DATA:   return "APPLICATION_DATA";
	default:                            return "???";
	}
}
