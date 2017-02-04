/**
 * @file tls_tcp.c TLS with TCP-transport
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_main.h>
#include <re_sa.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tcp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/* NOTE: shadow struct defined in tls_*.c */
struct tls_conn {
	struct tls_session *ssl;  /* inheritance */
	struct tls *tls;          /* inheritance */

	struct tcp_helper *th;
	struct tcp_conn *tcp;
	struct mbuf *mb;
	bool active;
	bool up;
	bool closed;
	int err;
};


static void destructor(void *arg)
{
	struct tls_conn *tc = arg;

#if 0
	tls_session_dump(tc->ssl);
#endif

	if (tc->ssl) {
		tls_session_shutdown(tc->ssl);
		mem_deref(tc->ssl);
	}
	mem_deref(tc->th);
	mem_deref(tc->tcp);
	mem_deref(tc->tls);
	mem_deref(tc->mb);
}


static int dtls_send_handler(struct mbuf *mb, void *arg)
{
	struct tls_conn *tc = arg;

	DEBUG_INFO("send %zu bytes\n", mbuf_get_left(mb));

	return tcp_send_helper(tc->tcp, mb, tc->th);
}


static void dtls_data_recv_handler(uint8_t *data, size_t datalen, void *arg)
{
	struct tls_conn *tc = arg;

	if (!tc->mb)
		tc->mb = mbuf_alloc(datalen);

	tc->mb->pos = tc->mb->end;
	mbuf_write_mem(tc->mb, data, datalen);
}


static void dtls_sess_close_handler(int err, void *arg)
{
	struct tls_conn *tc = arg;

	tc->up = false;
	tc->closed = true;

	tc->err = err;
}


static int tls_connect(struct tls_conn *tc)
{
	struct tls *tls = tc->tls;
	int err = 0;

	if (!tc->ssl) {

		err = tls_session_alloc(&tc->ssl, tls,
					 TLS_CLIENT,
					 tls->version ,
					 tls->suitev, tls->suitec,
					 dtls_send_handler,
					 NULL,
					 dtls_data_recv_handler,
					 dtls_sess_close_handler, tc);
		if (err)
			return err;

		if (tc->tls->cert)
			tls_session_set_certificate2(tc->ssl, tc->tls->cert);

		err = tls_session_start(tc->ssl);
	}

	return err;
}


static int tls_accept(struct tls_conn *tc)
{
	struct tls *tls = tc->tls;
	int err = 0;

	if (!tc->ssl) {

		err = tls_session_alloc(&tc->ssl, tls,
					 TLS_SERVER,
					 tls->version ,
					 tls->suitev, tls->suitec,
					 dtls_send_handler,
					 NULL,
					 dtls_data_recv_handler,
					 dtls_sess_close_handler, tc);
		if (err)
			return err;

		if (tc->tls->cert)
			tls_session_set_certificate2(tc->ssl, tc->tls->cert);
	}

	return err;
}


static bool estab_handler(int *err, bool active, void *arg)
{
	struct tls_conn *tc = arg;

	DEBUG_INFO("tcp established (active=%u)\n", active);

	if (!active)
		return true;

	tc->active = true;
	*err = tls_connect(tc);

	return true;
}


static bool recv_handler(int *err, struct mbuf *mb, bool *estab, void *arg)
{
	struct tls_conn *tc = arg;

	DEBUG_INFO("[up=%d] recv %zu bytes\n", tc->up, mbuf_get_left(mb));

	if (!tc->up) {

		if (tc->active) {
			*err = tls_connect(tc);
		}
		else {
			*err = tls_accept(tc);
		}
	}

	/* feed SSL data to the BIO */
	tls_session_recvtcp(tc->ssl, mb);

	if (tc->closed) {
		*err = tc->err;
		return true;
	}

	if (!tc->up) {

		/* TLS connection is established */

		if (!tls_session_is_estab(tc->ssl))
			return true;

		*estab = true;
		tc->up = true;
	}

	mbuf_set_pos(mb, 0);

	if (mbuf_get_space(mb) < 4096) {
		*err = mbuf_resize(mb, mb->size + 8192);
		if (*err)
			return true;
	}

	if (tc->mb) {

		mbuf_write_mem(mb, tc->mb->buf, tc->mb->end);

		tc->mb = mem_deref(tc->mb);
	}

	mbuf_set_end(mb, mb->pos);
	mbuf_set_pos(mb, 0);

	return false;
}


static bool send_handler(int *err, struct mbuf *mb, void *arg)
{
	struct tls_conn *tc = arg;

	*err = tls_session_send_data(tc->ssl,
				      mbuf_buf(mb), mbuf_get_left(mb));

	return true;
}


int tls_start_tcp(struct tls_conn **ptc, struct tls *tls, struct tcp_conn *tcp,
		  int layer)
{
	struct tls_conn *tc;
	int err;

	if (!ptc || !tls || !tcp)
		return EINVAL;

	tc = mem_zalloc(sizeof(*tc), destructor);
	if (!tc)
		return ENOMEM;

	err = tcp_register_helper(&tc->th, tcp, layer, estab_handler,
				  send_handler, recv_handler, tc);
	if (err)
		goto out;

	tc->tcp = mem_ref(tcp);
	tc->tls = mem_ref(tls);

	err = 0;

 out:
	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}
