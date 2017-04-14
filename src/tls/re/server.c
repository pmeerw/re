/**
 * @file server.c TLS server
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


static int send_serverhello(struct tls_session *sess)
{
	union handshake hand;
	struct serverhello *hello = &hand.serverhello;
	int err = 0;

	memset(&hand, 0, sizeof(hand));

	hello->server_version = sess->version;

	mem_cpy(hello->random, sizeof(hello->random),
		sess->sp_write.server_random,
		sizeof(sess->sp_write.server_random));

	/* XXX: we only support 1 cipher-suite for now
	 *      add support for cipher-suite negotiation
	 */
	hello->cipher_suite = sess->selected_cipher_suite;
	hello->compression_method = TLS_COMPRESSION_NULL;

	/* Local extensions */

	/* XXX: intersect local and remote extensions */
	if (sess->tls && !list_isempty(&sess->tls->exts_local)) {

		err = tls_extensions_encode(&hello->extensions,
					    &sess->tls->exts_local);
		if (err) {
			DEBUG_WARNING("ext encode error (%m)\n", err);
			goto out;
		}
	}

	err = tls_handshake_layer_send(sess, TLS_SERVER_HELLO, &hand,
				   false, false);
	if (err)
		goto out;

 out:
	tls_vector_reset(&hello->extensions);

	return 0;
}


static int send_serverhellodone(struct tls_session *sess)
{
	int err;

	err = tls_handshake_layer_send(sess, TLS_SERVER_HELLO_DONE, NULL,
				   true, false);
	if (err)
		return err;

	return 0;
}


int tls_server_handle_client_hello(struct tls_session *sess,
				   const struct clienthello *chell)
{
	uint16_t *suites;
	size_t i, n;
	bool supported = false;
	int err;

	if (sess->conn_end != TLS_SERVER) {
		DEBUG_WARNING("client: did not expect ClientHello\n");
		err = EPROTO;
		goto out;
	}

	if (sess->state != TLS_STATE_IDLE) {
		DEBUG_WARNING("client_hello:"
			      " illegal state %s\n",
			      tls_state_name(sess->state));
		return EPROTO;
	}

	tls_session_set_state(sess, TLS_STATE_CLIENT_HELLO_RECV);

	suites = chell->cipher_suites.data;
	n      = chell->cipher_suites.bytes / 2;

	/* check for a common cipher-suite */
	for (i=0; i<n; i++) {
		enum tls_cipher_suite cs = ntohs(suites[i]);

		if (tls_cipher_suite_lookup(sess, cs)) {
			sess->selected_cipher_suite = cs;
			supported = true;
			break;
		}
	}
	if (!supported) {
		DEBUG_WARNING("no common cipher suites"
			      " (server=%zu, client=%zu)\n",
			      sess->cipherc, n);
#if 0
		send_alert(sess, TLS_LEVEL_FATAL,
			   TLS_ALERT_HANDSHAKE_FAILURE);
#endif
		err = EPROTO;
		goto out;
	}

	/* decode extensions from Client */
	if (chell->extensions.bytes) {

		err = tls_extensions_decode(&sess->exts_remote,
					    &chell->extensions);
		if (err) {
			DEBUG_WARNING("extension error (%m)\n", err);
			goto out;
		}
	}

	/* save the Client-random */
	mem_cpy(sess->sp_read.client_random,
		sizeof(sess->sp_read.client_random),
		chell->random, sizeof(chell->random));
	mem_cpy(sess->sp_write.client_random,
		sizeof(sess->sp_write.client_random),
		chell->random, sizeof(chell->random));

	err = send_serverhello(sess);
	if (err) {
		DEBUG_WARNING("send serverhello failed (%m)\n", err);
		goto out;
	}

	err = tls_send_certificate(sess);
	if (err) {
		DEBUG_WARNING("send certificate failed (%m)\n", err);
		goto out;
	}

	err = send_serverhellodone(sess);
	if (err) {
		DEBUG_WARNING("send ServerHelloDone failed (%m)\n",
			      err);
		goto out;
	}

#if 1
	/* the cipher-suite is now decided */
	sess->suite = tls_suite_lookup(sess->selected_cipher_suite);
	if (!sess->suite) {
		DEBUG_WARNING("cipher suite not found (%s)\n",
		      tls_cipher_suite_name(sess->selected_cipher_suite));
		err = EPROTO;
		goto out;
	}
#endif

 out:
	return err;
}
