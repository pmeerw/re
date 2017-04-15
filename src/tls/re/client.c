/**
 * @file client.c TLS client
 *
 * Copyright (C) 2010 - 2017 Creytiv.com
 */

#include <string.h>
#include <assert.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_sys.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int tls_client_send_clienthello(struct tls_session *sess)
{
	union handshake hand;
	struct clienthello *hello = &hand.clienthello;
	enum tls_compression_method compr_methods[1] = {
		TLS_COMPRESSION_NULL
	};
	uint16_t *datav = NULL;
	size_t i;
	int err;

	if (!sess)
		return EINVAL;

	assert(TLS_CLIENT == sess->conn_end);

	datav = mem_alloc(sess->cipherc * sizeof(uint16_t), NULL);
	if (!datav)
		return ENOMEM;

	memset(&hand, 0, sizeof(hand));

	hello->client_version = sess->version;

	mem_cpy(hello->random, sizeof(hello->random),
		sess->sp_write.client_random,
		sizeof(sess->sp_write.client_random));

	/* Optional cookie for DTLS */
	if (sess->handshake.cookie_len) {
		hello->cookie.data = sess->handshake.cookie;
		hello->cookie.bytes = sess->handshake.cookie_len;
	}

	for (i=0; i<sess->cipherc; i++) {
		datav[i] = htons(sess->cipherv[i]);
	}

	hello->cipher_suites.bytes = 2 * sess->cipherc;
	hello->cipher_suites.data = datav;

	hello->compression_methods.bytes = 1;
	hello->compression_methods.data = compr_methods;

	/* Local extensions */
	if (sess->tls && !list_isempty(&sess->tls->exts_local)) {

		err = tls_extensions_encode(&hello->extensions,
					    &sess->tls->exts_local);
		if (err) {
			DEBUG_WARNING("ext encode error (%m)\n", err);
			goto out;
		}
	}

	err = tls_handshake_layer_send(sess, TLS_CLIENT_HELLO, &hand,
				   true, false);
	if (err)
		goto out;

 out:
	tls_vector_reset(&hello->extensions);
	mem_deref(datav);
	return err;
}


int tls_client_handle_server_hello(struct tls_session *sess,
				   const struct serverhello *hell)
{
	int err = 0;

	if (!sess || !hell)
		return EINVAL;

	if (TLS_CLIENT != sess->conn_end)
		return EPROTO;

	if (sess->state != TLS_STATE_CLIENT_HELLO_SENT) {
		DEBUG_WARNING("client: recv_server_hello:"
			      " illegal state %d\n", sess->state);
		return EPROTO;
	}
	if (sess->got_cert)
		return EPROTO;

	/* save the Server-random */
	mem_cpy(sess->sp_read.server_random,
		sizeof(sess->sp_read.server_random),
		hell->random, sizeof(hell->random));
	mem_cpy(sess->sp_write.server_random,
		sizeof(sess->sp_write.server_random),
		hell->random, sizeof(hell->random));

	/* the cipher-suite is now decided */
	if (!tls_cipher_suite_lookup(sess, hell->cipher_suite)) {
		DEBUG_WARNING("the server gave us a cipher-suite that"
			      " we did not offer!\n");
		return EPROTO;
	}

	sess->selected_cipher_suite = hell->cipher_suite;

	sess->suite = tls_suite_lookup(sess->selected_cipher_suite);
	if (!sess->suite) {
		DEBUG_WARNING("cipher suite not found (%s)\n",
			      tls_cipher_suite_name(hell->cipher_suite));
		return EPROTO;
	}

	/* decode extensions from remote */
	if (hell->extensions.bytes) {

		err = tls_extensions_decode(&sess->exts_remote,
					    &hell->extensions);
		if (err) {
			DEBUG_WARNING("server_hello: extension error"
				      " (%m)\n", err);
			goto out;
		}
	}

 out:
	return err;
}


/* send Client Key Exchange message */
int tls_client_send_clientkeyexchange(struct tls_session *sess)
{
	struct tls_handshake hand;
	int err;

	if (!sess)
		return EINVAL;

	assert(TLS_CLIENT == sess->conn_end);

	memset(&hand, 0, sizeof(hand));

	err = tls_vector_init(&hand.u.client_key_exchange.encr_pms,
			       sess->encr_pre_master_secret,
			       sess->encr_pre_master_secret_len);
	if (err)
		goto out;

	err = tls_handshake_layer_send(sess, TLS_CLIENT_KEY_EXCHANGE,
				   &hand.u, false, false);
	if (err)
		goto out;

#if 1
	/* XXX: this can be moved elsewhere ? */

	err = tls_master_secret_compute(sess->sp_read.master_secret,
					sess->pre_master_secret,
					sizeof(sess->pre_master_secret),
					sess->sp_read.client_random,
					sess->sp_read.server_random);
	if (err) {
		DEBUG_WARNING("master_secret_compute error (%m)\n", err);
		goto out;
	}

	err = tls_master_secret_compute(sess->sp_write.master_secret,
					sess->pre_master_secret,
					sizeof(sess->pre_master_secret),
					sess->sp_write.client_random,
					sess->sp_write.server_random);
	if (err) {
		DEBUG_WARNING("master_secret_compute error (%m)\n", err);
		goto out;
	}
#endif

 out:
	tls_vector_reset(&hand.u.client_key_exchange.encr_pms);
	return err;
}
