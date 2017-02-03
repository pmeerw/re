/**
 * @file tls_udp.c TLS with UDP-transport
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_sa.h>
#include <re_srtp.h>
#include <re_udp.h>
#include <re_tmr.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "dtls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


enum {
	MTU_DEFAULT  = 1400,
	MTU_FALLBACK = 548,
};


struct dtls_sock {
	struct sa peer;
	struct udp_helper *uh;
	struct udp_sock *us;
	struct hash *ht;
	struct mbuf *mb;
	dtls_conn_h *connh;
	void *arg;
	size_t mtu;
};


/* NOTE: shadow struct defined in tls_*.c */
struct tls_conn {
	struct tls_session *ssl;  /* inheritance */
	struct tls *tls;          /* inheritance */

	struct sa peer;
	struct le he;
	struct dtls_sock *sock;
	dtls_estab_h *estabh;
	dtls_recv_h *recvh;
	dtls_close_h *closeh;
	void *arg;
	bool active;
	bool up;
	bool closed;
};


static void tls_close(struct tls_conn *tc)
{
	if (!tc->ssl)
		return;

	tls_session_shutdown(tc->ssl);
	tc->ssl = mem_deref(tc->ssl);
}


static void conn_destructor(void *arg)
{
	struct tls_conn *tc = arg;

	hash_unlink(&tc->he);
	tls_close(tc);
	mem_deref(tc->sock);
	mem_deref(tc->tls);
}


static void conn_close(struct tls_conn *tc, int err)
{
	tc->closed = true;
	tls_close(tc);
	tc->up = false;

	if (tc->closeh)
		tc->closeh(err, tc->arg);
}


static int dtls_send_handler(struct mbuf *mb, void *arg)
{
	struct tls_conn *tc = arg;

	return udp_send_helper(tc->sock->us, &tc->peer, mb, tc->sock->uh);
}


static void dtls_data_recv_handler(uint8_t *data, size_t datalen, void *arg)
{
	struct tls_conn *tc = arg;
	struct mbuf *mb = mbuf_alloc(datalen);

	mbuf_write_mem(mb, data, datalen);
	mb->pos = 0;

	if (tc->recvh)
		tc->recvh(mb, tc->arg);

	mem_deref(mb);
}


static void dtls_sess_close_handler(int err, void *arg)
{
	struct tls_conn *tc = arg;

	re_printf("### closed (%m) ###\n", err);

	conn_close(tc, err);
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


static void conn_recv(struct tls_conn *tc, struct mbuf *mb)
{
	int err;

	if (!tc->up) {

		if (tc->active) {
			err = tls_connect(tc);
		}
		else {
			err = tls_accept(tc);
		}

		if (err) {
			conn_close(tc, err);
			return;
		}
	}

	tls_session_recvudp(tc->ssl, mb);

	if (tc->closed)
		return;

	if (!tc->up) {

		DEBUG_INFO("%s: state: up=%d estab=%d\n",
			   tc->active ? "client" : "server",
			   tc->up,
			   tls_session_is_estab(tc->ssl));

		/* TLS connection is established */
		if (!tls_session_is_estab(tc->ssl))
			return;

		tc->up = true;

		if (tc->estabh) {
			uint32_t nrefs;

			mem_ref(tc);

			tc->estabh(tc->arg);

			nrefs = mem_nrefs(tc);
			mem_deref(tc);

			/* check if connection was deref'd from handler */
			if (nrefs == 1)
				return;
		}
	}
}


static int conn_alloc(struct tls_conn **ptc, struct tls *tls,
		      struct dtls_sock *sock, const struct sa *peer,
		      dtls_estab_h *estabh, dtls_recv_h *recvh,
		      dtls_close_h *closeh, void *arg)
{
	struct tls_conn *tc;
	int err = 0;

	tc = mem_zalloc(sizeof(*tc), conn_destructor);
	if (!tc)
		return ENOMEM;

	hash_append(sock->ht, sa_hash(peer, SA_ALL), &tc->he, tc);

	tc->sock   = mem_ref(sock);
	tc->tls    = mem_ref(tls);
	tc->peer   = *peer;
	tc->estabh = estabh;
	tc->recvh  = recvh;
	tc->closeh = closeh;
	tc->arg    = arg;

	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}


int dtls_connect(struct tls_conn **ptc, struct tls *tls,
		 struct dtls_sock *sock, const struct sa *peer,
		 dtls_estab_h *estabh, dtls_recv_h *recvh,
		 dtls_close_h *closeh, void *arg)
{
	struct tls_conn *tc;
	int err;

	if (!ptc || !tls || !sock || !peer)
		return EINVAL;

	err = conn_alloc(&tc, tls, sock, peer, estabh, recvh, closeh, arg);
	if (err)
		return err;

	tc->active = true;

	err = tls_connect(tc);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}


int dtls_accept(struct tls_conn **ptc, struct tls *tls,
		struct dtls_sock *sock,
		dtls_estab_h *estabh, dtls_recv_h *recvh,
		dtls_close_h *closeh, void *arg)
{
	struct tls_conn *tc;
	int err;

	if (!ptc || !tls || !sock || !sock->mb)
		return EINVAL;

	err = conn_alloc(&tc, tls, sock, &sock->peer, estabh, recvh, closeh,
			 arg);
	if (err)
		return err;

	tc->active = false;

#if 1

	err = tls_accept(tc);
	if (err)
		goto out;

	tls_session_recvudp(tc->ssl, sock->mb);
#endif

	sock->mb = mem_deref(sock->mb);

 out:
	if (err)
		mem_deref(tc);
	else
		*ptc = tc;

	return err;
}


int dtls_send(struct tls_conn *tc, struct mbuf *mb)
{
	if (!tc || !mb)
		return EINVAL;

	if (!tc->up || !tc->ssl)
		return ENOTCONN;

	return tls_session_send_data(tc->ssl,
				      mbuf_buf(mb), mbuf_get_left(mb));
}


void dtls_set_handlers(struct tls_conn *tc, dtls_estab_h *estabh,
		       dtls_recv_h *recvh, dtls_close_h *closeh, void *arg)
{
	if (!tc)
		return;

	tc->estabh = estabh;
	tc->recvh  = recvh;
	tc->closeh = closeh;
	tc->arg    = arg;
}


static void sock_destructor(void *arg)
{
	struct dtls_sock *sock = arg;

	hash_clear(sock->ht);
	mem_deref(sock->uh);
	mem_deref(sock->us);
	mem_deref(sock->ht);
	mem_deref(sock->mb);
}


static bool cmp_handler(struct le *le, void *arg)
{
	struct tls_conn *tc = le->data;

	return sa_cmp(&tc->peer, arg, SA_ALL);
}


static struct tls_conn *conn_lookup(struct dtls_sock *sock,
				    const struct sa *peer)
{
	return list_ledata(hash_lookup(sock->ht, sa_hash(peer, SA_ALL),
				       cmp_handler, (void *)peer));
}


static bool recv_handler(struct sa *src, struct mbuf *mb, void *arg)
{
	struct dtls_sock *sock = arg;
	struct tls_conn *tc;
	uint8_t b;

	DEBUG_INFO("recv %zu bytes from %J\n",
		   mbuf_get_left(mb), src);

	if (mbuf_get_left(mb) < 1)
		return false;

	b = mb->buf[mb->pos];
	if (b < 20 || b > 63)
		return false;

	tc = conn_lookup(sock, src);
	if (tc) {
		conn_recv(tc, mb);
		return true;
	}

	if (sock->connh) {

		mem_deref(sock->mb);
		sock->mb   = mem_ref(mb);
		sock->peer = *src;

		sock->connh(src, sock->arg);
	}

	return true;
}


int dtls_listen(struct dtls_sock **sockp, const struct sa *laddr,
		struct udp_sock *us, uint32_t htsize, int layer,
		dtls_conn_h *connh, void *arg)
{
	struct dtls_sock *sock;
	int err;

	if (!sockp)
		return EINVAL;

	sock = mem_zalloc(sizeof(*sock), sock_destructor);
	if (!sock)
		return ENOMEM;

	if (us) {
		sock->us = mem_ref(us);
	}
	else {
		err = udp_listen(&sock->us, laddr, NULL, NULL);
		if (err)
			goto out;
	}

	err = udp_register_helper(&sock->uh, sock->us, layer,
				  NULL, recv_handler, sock);
	if (err)
		goto out;

	err = hash_alloc(&sock->ht, hash_valid_size(htsize));
	if (err)
		goto out;

	sock->mtu   = MTU_DEFAULT;
	sock->connh = connh;
	sock->arg   = arg;

 out:
	if (err)
		mem_deref(sock);
	else
		*sockp = sock;

	return err;
}


struct udp_sock *dtls_udp_sock(struct dtls_sock *sock)
{
	return sock ? sock->us : NULL;
}


void dtls_set_mtu(struct dtls_sock *sock, size_t mtu)
{
	if (!sock)
		return;

	sock->mtu = mtu;
}
