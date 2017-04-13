/**
 * @file trace.c TLS message tracing
 *
 * Copyright (C) 2010 - 2017 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


void tls_trace(struct tls_session *sess, enum tls_trace_flags flags,
		const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	int r;

	if (!sess || !fmt)
		return;

	if (!(sess->trace_flags & flags))
		return;
	if (!sess->traceh)
		return;

	va_start(ap, fmt);
	r = re_vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (r < 0)
		return;

	sess->traceh(flags, buf, sess->arg);
}


void tls_set_trace(struct tls_session *sess, enum tls_trace_flags flags,
		    tls_trace_h *traceh)
{
	if (!sess)
		return;

	sess->trace_flags = flags;
	sess->traceh = traceh;
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
