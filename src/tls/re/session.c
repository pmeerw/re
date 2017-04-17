/**
 * @file session.c TLS session
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
#include <re_cert.h>
#include <re_sha.h>
#include <re_aes.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * TODO: for DTLS Server, add option to send HelloVerifyRequest
 *
 */


#define TCP_BUFSIZE_MAX (1<<24)
#define TLS_SEED_SIZE 32
#define MBUF_HEADROOM 4


static int encrypt_send_record(struct tls_session *sess,
			       enum tls_content_type type, struct mbuf *data);
static void handshake_layer_append(struct tls_session *sess,
				   bool is_write,
				   const uint8_t *data, size_t len);
static int handle_change_cipher_spec(struct tls_session *sess);


void tls_session_set_state(struct tls_session *sess, enum tls_state state)
{
	if (state < sess->state) {
		DEBUG_WARNING("illegal decrementing state transition from"
			      " %d to %d\n", sess->state, state);
		return;
	}

#if 0
	re_printf("*** [%s] state transition:  %-22s  --->  %s\n",
		  sess->conn_end == TLS_CLIENT ? "Client" : "Server",
		  tls_state_name(sess->state),
		  tls_state_name(state));
#endif

	sess->state = state;
}


/*
 * HANDSHAKE LAYER
 */


int tls_handshake_layer_send(struct tls_session *sess,
			     enum tls_handshake_type msg_type,
			     const union handshake *hand,
			     bool flush_now, bool crypt)
{
	struct mbuf *mb = NULL;
	int err;

	tls_trace(sess, TLS_TRACE_HANDSHAKE,
		   "send handshake: type=%s\n",
		   tls_handshake_name(msg_type));

	mb = mbuf_alloc(32);
	if (!mb)
		return ENOMEM;

	err = tls_handshake_encode(mb, sess->version, msg_type,
				    sess->handshake.seq_write, 0, hand);
	if (err)
		goto out;

	handshake_layer_append(sess, true, mb->buf, mb->end);

	mb->pos = 0;

	if (crypt) {
		err = encrypt_send_record(sess, TLS_HANDSHAKE, mb);
	}
	else {
		err = tls_record_layer_send(sess, TLS_HANDSHAKE,
					    mb, flush_now);
	}
	if (err)
		goto out;

	++sess->handshake.seq_write;

 out:
	mem_deref(mb);
	return err;
}


static void handshake_layer_append(struct tls_session *sess,
				   bool is_write,
				   const uint8_t *data, size_t len)
{
	if (!sess || !data)
		return;

	if (is_write)
		sess->handshake.bytes_write += len;
	else
		sess->handshake.bytes_read += len;

	SHA256_Update(&sess->handshake.ctx, data, len);

#if 0
	re_printf("   >>> HANDSHAKE %s: %zu bytes (Total %zu)\n",
		  is_write ? "WRITE" : "READ",
		  len,
		  is_write ? sess->hand_bytes_write : sess->hand_bytes_read);
#endif
}


static int handshake_layer_get_md(const struct tls_session *sess,
				  uint8_t md[])
{
	SHA256_CTX copy;

	if (!sess || !md)
		return EINVAL;

	copy = sess->handshake.ctx;
	SHA256_Final(md, &copy);

	return 0;
}


/*
 * END LAYERS
 */


bool tls_cipher_suite_lookup(const struct tls_session *sess,
			     enum tls_cipher_suite cs)
{
	size_t i;

	for (i=0; i<sess->cipherc; i++) {

		if (cs == sess->cipherv[i])
			return true;
	}

	return false;
}


static int send_alert(struct tls_session *sess,
		      enum tls_alertlevel level, enum tls_alertdescr descr)
{
	struct tls_alert alert;
	struct mbuf *mb;
	int err;

	if (sess->alert_sent)
		return 0;

	tls_trace(sess, TLS_TRACE_ALERT, "send alert: %s\n",
		   tls_alert_name(descr));

	if (!sess)
		return EINVAL;

	alert.level = level;
	alert.descr = descr;

	mb = mbuf_alloc(2);
	if (!mb)
		return ENOMEM;

	err = tls_alert_encode(mb, &alert);
	if (err)
		goto out;
	mb->pos = 0;

	err = encrypt_send_record(sess, TLS_ALERT, mb);
	if (err)
		goto out;

	sess->alert_sent = true;

 out:
	mem_deref(mb);

	return err;
}


static void conn_close(struct tls_session *sess, int err)
{
	enum tls_alertdescr descr = TLS_ALERT_INTERNAL_ERROR;

	sess->closed = true;

	if (err == 0)
		descr = TLS_ALERT_CLOSE_NOTIFY;
	else if (err == EBADMSG)
		descr = TLS_ALERT_DECODE_ERROR;

	/* send alert to peer */
	send_alert(sess, TLS_LEVEL_FATAL, descr);

	/* call close-handler */
	if (sess->closeh) {
		sess->closeh(err, sess->arg);
		sess->closeh = NULL;
	}
}


int tls_send_certificate(struct tls_session *sess)
{
	union handshake hand;
	struct certificate *cert = &hand.certificate;
	uint8_t *der = NULL;
	size_t der_len = 0;
	int err;

	memset(&hand, 0, sizeof(hand));

	if (!sess->cert_local) {
		DEBUG_WARNING("no local certificate\n");
		return ENOENT;
	}

	err = cert_encode_der(sess->cert_local, &der, &der_len);
	if (err)
		goto out;

	err = tls_vector_init(&cert->certlist[0], der, der_len);
	if (err)
		goto out;

	cert->count = 1;

	err = tls_handshake_layer_send(sess, TLS_CERTIFICATE, &hand,
				       NO_FLUSH, false);
	if (err)
		goto out;

 out:
	tls_vector_reset(&cert->certlist[0]);
	mem_deref(der);

	return err;
}


static void destructor(void *data)
{
	struct tls_session *sess = data;

	sess->tls = NULL;

#if 0
	re_printf("\n -- session summary --\n");
	re_printf("Remote %H\n", tls_extensions_print, &sess->exts_remote);
#endif

	/* send close notify alert, if session was established */
	if (sess->estab)
		send_alert(sess, TLS_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);

	mem_deref(sess->handshake.mb);
	mem_deref(sess->record_layer.mb);
	mem_deref(sess->record_layer.mb_write);
	mem_deref(sess->cert_local);
	mem_deref(sess->cert_remote);
	mem_deref(sess->cipherv);
	list_flush(&sess->exts_remote);

	secure_memclear(sess->sp_write.master_secret,
			sizeof(sess->sp_write.master_secret));
	secure_memclear(sess->sp_read.master_secret,
			sizeof(sess->sp_read.master_secret));
}


int  tls_session_alloc(struct tls_session **sessp,
		       struct tls *tls,
			enum tls_connection_end conn_end,
			enum tls_version ver,
			const enum tls_cipher_suite *cipherv, size_t cipherc,
			tls_sess_send_h *sendh,
			tls_sess_estab_h *estabh,
			tls_data_recv_h *datarecvh,
			tls_sess_close_h *closeh, void *arg)
{
	struct tls_session *sess;
	uint8_t sp_random[32];
	size_t i;
	int err = 0;

	if (!sessp || !cipherv || !cipherc)
		return EINVAL;

	for (i=0; i<cipherc; i++) {
		enum tls_cipher_suite cs = cipherv[i];

		if (!tls_suite_lookup(cs)) {
			DEBUG_WARNING("alloc: cipher suite not supported"
				      " 0x%04x (%s)\n",
				      cs, tls_cipher_suite_name(cs));
			return ENOTSUP;
		}
	}

	sess = mem_zalloc(sizeof(*sess), destructor);
	if (!sess)
		return ENOMEM;

	sess->tls = tls;
	sess->conn_end = conn_end;
	sess->version = ver;

	sess->cipherv = mem_reallocarray(NULL, cipherc,
					 sizeof(*cipherv), NULL);
	if (!sess->cipherv) {
		err = ENOMEM;
		goto out;
	}
	memcpy(sess->cipherv, cipherv, cipherc * sizeof(*cipherv));
	sess->cipherc = cipherc;

	rand_bytes(sp_random, sizeof(sp_random));

	err |= tls_secparam_init(&sess->sp_write, sp_random,
				  1, conn_end == TLS_CLIENT);
	err |= tls_secparam_init(&sess->sp_read, sp_random,
				  0, conn_end == TLS_CLIENT);
	if (err)
		goto out;

	sess->sendh = sendh;
	sess->estabh = estabh;
	sess->datarecvh = datarecvh;
	sess->closeh = closeh;
	sess->arg = arg;

	if (conn_end == TLS_CLIENT) {
		/* generate 48-byte premaster secret */
		rand_bytes(sess->pre_master_secret,
			   sizeof(sess->pre_master_secret));
		sess->pre_master_secret[0] = (unsigned)ver >> 8;
		sess->pre_master_secret[1] = (unsigned)ver & 0xff;
	}

	SHA256_Init(&sess->handshake.ctx);

	// XXX add tls_record_layer_init
	sess->record_layer.mb_write = mbuf_alloc(64);
	if (!sess->record_layer.mb_write) {
		err = ENOMEM;
		goto out;
	}

	sess->record_layer.mb_write->pos = MBUF_HEADROOM;
	sess->record_layer.mb_write->end = MBUF_HEADROOM;

	sess->record_fragment_size = TLS_RECORD_FRAGMENT_SIZE;

 out:
	if (err)
		mem_deref(sess);
	else
		*sessp = sess;

	return err;
}


int tls_session_start(struct tls_session *sess)
{
	if (!sess)
		return EINVAL;

	if (sess->state != TLS_STATE_IDLE) {
		DEBUG_WARNING("start: illegal state %d\n", sess->state);
		return EPROTO;
	}

	tls_session_set_state(sess, TLS_STATE_CLIENT_HELLO_SENT);

	return tls_client_send_clienthello(sess);
}


static int send_change_cipher_spec(struct tls_session *sess)
{
	struct mbuf mb_pld = { (uint8_t*)"\x01", 1, 0, 1};
	int err;

	tls_trace(sess, TLS_TRACE_CHANGE_CIPHER_SPEC,
		   "send ChangeCipherSpec\n");

	err = tls_record_layer_write(sess, TLS_CHANGE_CIPHER_SPEC,
				     mb_pld.buf, mb_pld.end,
				     false);
	if (err)
		goto out;

	tls_record_layer_new_epoch(sess, WRITE);

	err = tls_secparam_set(&sess->sp_write, sess->suite);
	if (err) {
		DEBUG_WARNING("tls_secparam_set failed (%m)\n", err);
		goto out;
	}

 out:
	return err;
}


static int encrypt_send_record(struct tls_session *sess,
			       enum tls_content_type type, struct mbuf *data)
{
	struct mbuf *mb_enc = mbuf_alloc(64);
	uint8_t mac[TLS_MAX_MAC_SIZE];
	size_t mac_sz = sess->sp_write.mac_length;
	int err = 0;
	struct key *write_MAC_key;
	struct key *write_key;

	if (sess->conn_end == TLS_CLIENT)
		write_MAC_key = &sess->key_block.client_write_MAC_key;
	else if (sess->conn_end == TLS_SERVER)
		write_MAC_key = &sess->key_block.server_write_MAC_key;
	else
		return EINVAL;

	switch (sess->sp_write.mac_algorithm) {

	case TLS_MAC_NULL:
		mac_sz = 0;
		break;

	case TLS_MAC_HMAC_SHA1:
	case TLS_MAC_HMAC_SHA256:

		err = tls_mac_generate(mac, mac_sz, write_MAC_key,
				       tls_record_get_write_seqnum(sess),
				       type, sess->version,
				       data->end, /* length w/o MAC */
				       data->buf);
		if (err) {
			DEBUG_WARNING("mac_generate failed (%m)\n", err);
			goto out;
		}
		break;

	default:
		DEBUG_WARNING("session: send_record: mac algorithm"
			      " is not supported (%d)\n",
			      sess->sp_write.mac_algorithm);
		err = ENOTSUP;
		goto out;
		break;
	}

	/* append the MAC trailer */
	if (mac_sz) {
		data->pos = data->end;
		err = mbuf_write_mem(data, mac, mac_sz);
		if (err)
			goto out;
	}

	if (sess->conn_end == TLS_CLIENT)
		write_key = &sess->key_block.client_write_key;
	else if (sess->conn_end == TLS_SERVER)
		write_key = &sess->key_block.server_write_key;
	else
		return EINVAL;

	switch (sess->sp_write.bulk_cipher_algorithm) {

	case TLS_BULKCIPHER_NULL:
		err = mbuf_write_mem(mb_enc, data->buf, data->end);
		break;

	case TLS_BULKCIPHER_AES:
		err = tls_crypt_encrypt(write_key, mb_enc, data);

		assert(mb_enc->pos <= mb_enc->size);
		assert(mb_enc->end <= mb_enc->size);
		break;

	default:
		DEBUG_WARNING("unknown bulk_cipher %d\n",
			      sess->sp_write.bulk_cipher_algorithm);
		err = ENOTSUP;
		goto out;
		break;
	}

	if (err)
		goto out;

	mb_enc->pos = 0;

	err = tls_record_layer_write(sess, type,
				     mbuf_buf(mb_enc), mbuf_get_left(mb_enc),
				     true);
	if (err)
		goto out;

 out:
	mem_deref(mb_enc);
	return err;
}


/*
 * A Finished message is always sent immediately after a change
 * cipher spec message to verify that the key exchange and
 * authentication processes were successful.
 */
static int send_finished(struct tls_session *sess)
{
	union handshake hand;
	uint8_t seed[TLS_SEED_SIZE];
	int err;

	tls_trace(sess, TLS_TRACE_HANDSHAKE, "send Finished\n");

	memset(&hand, 0, sizeof(hand));

	err = handshake_layer_get_md(sess, seed);
	if (err)
		goto out;

	err = tls_finish_calc(hand.finished.verify_data,
			       sess->sp_write.master_secret,
			       seed, sess->conn_end);
	if (err) {
		DEBUG_WARNING("finished: calc failed (%m)\n", err);
		goto out;
	}

	if (sess->conn_end == TLS_CLIENT) {

		/* todo: move this to another place? */
		err = tls_keys_generate(&sess->key_block, &sess->sp_write);
		if (err) {
			DEBUG_WARNING("send_finished: "
				      "tls_keys_generate failed (%m)\n", err);
			goto out;
		}
	}

	err = tls_handshake_layer_send(sess, TLS_FINISHED, &hand,
				       FLUSH, true);
	if (err) {
		DEBUG_WARNING("finished: handshake_layer_send failed %m\n",
			      err);
		goto out;
	}

 out:
	return err;
}


static int handle_certificate(struct tls_session *sess,
			      const struct certificate *certificate)
{
	int err;

	if (sess->got_cert) {
		DEBUG_WARNING("already got certificate\n");
		return EPROTO;
	}

	sess->got_cert = true;

	if (certificate->count > 0) {

		/* The sender's certificate MUST come first in the list */
		const struct tls_vector *first = &certificate->certlist[0];

		if (sess->cert_remote) {
			re_printf("cert reset\n");
			sess->cert_remote = mem_deref(sess->cert_remote);
		}

		err = cert_decode(&sess->cert_remote,
				  first->data, first->bytes);
		if (err) {
			DEBUG_WARNING("certificate: cert_decode"
				      " %zu bytes failed (%m)\n",
				      first->bytes, err);
			return err;
		}

#if 0
		cert_dump(cert->cert_remote);
#endif

		/* TODO: verify certificate, add callback? */
	}
	else {
		DEBUG_WARNING("no certificates\n");
		return EPROTO;
	}

	/* encrypt it using the public key from the server's certificate */
	sess->encr_pre_master_secret_len
		= sizeof(sess->encr_pre_master_secret);

	err = cert_public_encrypt(sess->cert_remote,
				  sess->encr_pre_master_secret,
				  &sess->encr_pre_master_secret_len,
				  sess->pre_master_secret,
				  sizeof(sess->pre_master_secret));
	if (err) {
		DEBUG_WARNING("cert_public_encrypt failed (%m)\n", err);
		return err;
	}

	return err;
}


static int verify_finished(struct tls_session *sess,
			   const struct finished *fin)
{
	uint8_t seed[TLS_SEED_SIZE];
	uint8_t verify_data[TLS_VERIFY_DATA_SIZE];
	int err;

	err = handshake_layer_get_md(sess, seed);
	if (err)
		return err;

	err = tls_finish_calc(verify_data,
			       sess->sp_write.master_secret,
			       seed,
			       !sess->conn_end);
	if (err) {
		DEBUG_WARNING("finished: calc failed (%m)\n", err);
		return err;
	}

	if (sizeof(verify_data) != sizeof(fin->verify_data) ||
	    0 != secure_compare(verify_data, fin->verify_data,
				sizeof(verify_data))) {

		DEBUG_WARNING("finished: verify_data mismatch\n");

		re_printf("finished: packet = %w\n",
			  fin->verify_data, sizeof(fin->verify_data));
		re_printf("          calcul = %w\n",
			  verify_data, sizeof(verify_data));

		return EPROTO;
	}

	return 0;
}


static int client_handle_server_hello_done(struct tls_session *sess)
{
	int err;

	if (!sess->got_cert) {
		DEBUG_WARNING("handle_server_hello_done: no certificate\n");
		return EPROTO;
	}

	if (sess->state != TLS_STATE_CLIENT_HELLO_SENT) {
		DEBUG_WARNING("client: recv_server_hello_done:"
			      " illegal state %d\n", sess->state);
		return EPROTO;
	}

	tls_session_set_state(sess, TLS_STATE_SERVER_HELLO_DONE_RECV);

	/* NOTE: we must wait for all handshake messages
	 * to be processed and hashed
	 */
	err = tls_client_send_clientkeyexchange(sess);
	if (err)
		return err;

	/* Send ChangeCipherSpec protocol */
	err = send_change_cipher_spec(sess);
	if (err) {
		DEBUG_WARNING("send_change_cipher_spec failed"
			      " (%m)\n", err);
		return err;
	}

	/* Send "Finished" message (encrypted) */
	err = send_finished(sess);
	if (err) {
		DEBUG_WARNING("client: send_finished failed (%m)\n", err);
		return err;
	}

	return 0;
}


static int handle_finished(struct tls_session *sess,
			   const struct finished *fin)
{
	int err;

	if (!sess->got_ccs) {
		DEBUG_WARNING("recv Finished, but no CCS received\n");
		return EPROTO;
	}

	switch (sess->conn_end) {

	case TLS_CLIENT:
		if (sess->state != TLS_STATE_SERVER_HELLO_DONE_RECV) {
			DEBUG_WARNING("finished:"
				      " illegal state %s\n",
				      tls_state_name(sess->state));
			return EPROTO;
		}
		break;

	case TLS_SERVER:
		if (sess->state != TLS_STATE_CLIENT_HELLO_RECV) {
			DEBUG_WARNING("finished:"
				      " illegal state %s\n",
				      tls_state_name(sess->state));
			return EPROTO;
		}
		break;
	}

	tls_session_set_state(sess, TLS_STATE_FINISHED_RECV);

	err = verify_finished(sess, fin);
	if (err) {
		goto out;
	}

	sess->estab = true;
	if (sess->estabh)
		sess->estabh(sess->arg);

 out:
	return err;
}


static void process_handshake(struct tls_session *sess,
			      const uint8_t *fragment, size_t length,
			      const struct tls_handshake *hand)
{
	int err = EPROTO;

	tls_trace(sess, TLS_TRACE_HANDSHAKE,
		   "recv handshake: type=%s, payload_length=%zu\n",
		   tls_handshake_name(hand->msg_type), hand->length);

	++sess->handshake.seq_read;

	/* XXX: exclude Finished, that is a hack */
	if (hand->msg_type != TLS_FINISHED) {

		handshake_layer_append(sess, false,
				       fragment, length);
	}

	switch (hand->msg_type) {

	case TLS_CLIENT_HELLO:
		err = tls_server_handle_client_hello(sess,
						     &hand->u.clienthello);
		break;

	case TLS_SERVER_HELLO:
		err = tls_client_handle_server_hello(sess,
						     &hand->u.serverhello);
		break;

	case TLS_HELLO_VERIFY_REQUEST: {
		const struct tls_vector *cook;

		cook = &hand->u.hello_verify_req.cookie;

		/* save the cookie from server */
		memcpy(sess->handshake.cookie, cook->data, cook->bytes);
		sess->handshake.cookie_len = cook->bytes;

		/*
		 * in cases where the cookie exchange is used, the initial
		 * ClientHello and HelloVerifyRequest MUST NOT be included
		 * in the CertificateVerify or Finished MAC computations.
		 */
		SHA256_Init(&sess->handshake.ctx);

		err = tls_client_send_clienthello(sess);
	}
		break;

	case TLS_CERTIFICATE:
		err = handle_certificate(sess, &hand->u.certificate);
		break;

	case TLS_SERVER_HELLO_DONE:
		err = client_handle_server_hello_done(sess);
		break;

	case TLS_CLIENT_KEY_EXCHANGE:
		err = tls_server_handle_clientkeyexchange(sess,
					  &hand->u.client_key_exchange);
		break;

	case TLS_FINISHED:
		err = handle_finished(sess, &hand->u.finished);
		if (err)
			goto out;

		/* NOTE: append hash AFTER finish calculated,
		 *       but BEFORE we send out Finished!
		 */
		handshake_layer_append(sess, false,
				       fragment, length);

		/*
		 * NOTE: after Finished is verified,
		 *       we must send CCS and Finished
		 */
		if (sess->conn_end == TLS_SERVER) {

			/* Send ChangeCipherSpec protocol */
			err = send_change_cipher_spec(sess);
			if (err) {
				DEBUG_WARNING("send_change_cipher_spec failed"
					      " (%m)\n", err);
				goto out;
			}

			/* Send "Finished" message (encrypted) */
			err = send_finished(sess);
			if (err) {
				DEBUG_WARNING("server: send_finished"
					      " failed (%m)\n",
					      err);
				goto out;
			}
		}

		break;

	default:
		err = EPROTO;
		DEBUG_WARNING("session: handshake message"
			      " not handled (%s) (%d)\n",
			      tls_handshake_name(hand->msg_type),
			      hand->msg_type);
		break;
	}

 out:
	if (err) {
		conn_close(sess, err);
	}

	return;
}


static int handle_handshake_fragment(struct tls_session *sess,
				     const struct tls_record *rec)
{
	enum tls_version ver = rec->proto_ver;
	size_t pos;
	int err;

	/*
	 * Part I -- write record to handshake buffer
	 */
	if (!sess->handshake.mb) {
		sess->handshake.mb = mbuf_alloc(64);
		if (!sess->handshake.mb)
			return ENOMEM;
	}

	pos = sess->handshake.mb->pos;

	sess->handshake.mb->pos = sess->handshake.mb->end;

	err = mbuf_write_mem(sess->handshake.mb, rec->fragment, rec->length);
	if (err)
		return err;

	sess->handshake.mb->pos = pos;

	rec = NULL;  /* not used anymore */


	/*
	 * Part II -- read handshakes from buffer
	 */
	for (;;) {
		struct tls_handshake *handshake = 0;
		uint8_t *frag;
		size_t length;
		bool stop = false;

		pos = sess->handshake.mb->pos;

		frag = mbuf_buf(sess->handshake.mb);

		err = tls_handshake_decode(&handshake,
					    ver, sess->handshake.mb);
		if (err) {
			sess->handshake.mb->pos = pos;
			if (err == ENODATA)
				err = 0;
			break;
		}

		length = sess->handshake.mb->pos - pos;

		mem_ref(sess);
		process_handshake(sess, frag, length, handshake);

		mem_deref(handshake);

		/* todo: the handler might deref session */
		if (sess->handshake.mb->pos >= sess->handshake.mb->end) {
			sess->handshake.mb = mem_deref(sess->handshake.mb);
			stop = true;
		}
		if (sess->closed)
			stop = true;
		mem_deref(sess);
		if (stop)
			break;
	}

	return err;
}


/* This is the place for de-multiplexing incoming Records */
void tls_handle_cleartext_record(struct tls_session *sess,
				    const struct tls_record *rec)
{
	struct mbuf mb_wrap = {rec->fragment, rec->length, 0, rec->length};
	struct mbuf *mb = &mb_wrap;
	int err = 0;

	if (sess->closed)
		return;

	switch (rec->content_type) {

	case TLS_CHANGE_CIPHER_SPEC: {
		struct tls_change_cipher_spec css;

		if (mbuf_get_left(mb) < 1) {
			err = EPROTO;
			goto out;
		}

		css.byte = mbuf_read_u8(mb);

		if (css.byte != 1) {
			DEBUG_WARNING("ChangeCipherSpec:"
				      " expected 0x01, got 0x%02x\n",
				      css.byte);
			err = EPROTO;
			goto out;
		}
		err = handle_change_cipher_spec(sess);
	}
		break;

	case TLS_ALERT: {
		struct tls_alert alert;

		err = tls_alert_decode(&alert, mb);
		if (err)
			goto out;

		DEBUG_WARNING("received alert: %s\n",
			      tls_alert_name(alert.descr));

		tls_trace(sess, TLS_TRACE_ALERT, "recv alert: %s\n",
			   tls_alert_name(alert.descr));

		if (alert.descr == TLS_ALERT_CLOSE_NOTIFY)
			conn_close(sess, 0);
		else
			conn_close(sess, EPROTO); /* XXX: translate */
	}
		break;

	case TLS_HANDSHAKE:
		err = handle_handshake_fragment(sess, rec);
		break;

	case TLS_APPLICATION_DATA:

		tls_trace(sess, TLS_TRACE_APPLICATION_DATA,
			   "receive %zu bytes\n", rec->length);

		if (sess->datarecvh)
			sess->datarecvh(rec->fragment, rec->length, sess->arg);
		break;

	default:
		DEBUG_WARNING("record: don't know how to"
			      " decode content-type %d"
			      " (%s)"
			      " [ver=%04x, epoch=%u, seq=%llu, len=%u]\n",
			      rec->content_type,
			      tls_content_type_name(rec->content_type),
			      rec->proto_ver, rec->epoch, rec->seq,
			      rec->length);
		err = EPROTO;
		break;
	}

 out:
	if (err && err != ENODATA) {
		DEBUG_WARNING("record: decode payload (%s, %zu bytes)"
			      " failed"
			      " (%m)\n",
			      tls_content_type_name(rec->content_type),
			      rec->length, err);

		conn_close(sess, err);
	}
}


static int session_record_decode(struct tls_session *sess, struct mbuf *mb)
{
	struct tls_record *rec = NULL;
	int err;

	err = tls_record_decode(&rec, mb);
	if (err)
		return err;

	err = tls_record_layer_handle_record(sess, rec);
	if (err)
		goto out;

 out:
	mem_deref(rec);

	return err;
}


static int handle_change_cipher_spec(struct tls_session *sess)
{
	const struct tls_suite *suite;
	int err;

	tls_trace(sess, TLS_TRACE_CHANGE_CIPHER_SPEC,
		   "receive ChangeCipherSpec\n");

	suite = tls_suite_lookup(sess->selected_cipher_suite);
	if (!suite) {
		DEBUG_WARNING("cipher suite not found (%s)\n",
		      tls_cipher_suite_name(sess->selected_cipher_suite));
		return EPROTO;
	}

	err = tls_secparam_set(&sess->sp_read, suite);
	if (err) {
		DEBUG_WARNING("tls_secparam_set failed (%m)\n", err);
		return err;
	}

	/* new epoch, reset sequence number */
	tls_record_layer_new_epoch(sess, READ);

	if (sess->conn_end == TLS_SERVER) {

		/* todo: move this to another place? */
		err = tls_keys_generate(&sess->key_block,
					 &sess->sp_read);
		if (err) {
			DEBUG_WARNING("css: tls_keys_generate failed"
				      " (%m)\n", err);
			return err;
		}
	}

	sess->got_ccs = true;

	return 0;
}


int tls_session_send_data(struct tls_session *sess,
			   const uint8_t *data, size_t data_len)
{
	struct mbuf *mb;
	int err;

	if (!sess || !data || !data_len)
		return EINVAL;

	tls_trace(sess, TLS_TRACE_APPLICATION_DATA,
		   "send %zu bytes\n", data_len);

	mb = mbuf_alloc(data_len);
	if (!mb)
		return ENOMEM;

	err = mbuf_write_mem(mb, data, data_len);
	if (err)
		goto out;

	mb->pos = 0;

	err = encrypt_send_record(sess, TLS_APPLICATION_DATA, mb);

 out:
	mem_deref(mb);

	return err;
}


void tls_session_recvtcp(struct tls_session *sess, struct mbuf *mbx)
{
	size_t pos;
	int err = 0;

	if (!sess || !mbx)
		return;

	sess->record_layer.read.bytes += mbuf_get_left(mbx);

	if (sess->record_layer.mb) {
		pos = sess->record_layer.mb->pos;

		sess->record_layer.mb->pos = sess->record_layer.mb->end;

		err = mbuf_write_mem(sess->record_layer.mb,
				     mbuf_buf(mbx),mbuf_get_left(mbx));
		if (err)
			goto out;

		sess->record_layer.mb->pos = pos;

		if (mbuf_get_left(sess->record_layer.mb) > TCP_BUFSIZE_MAX) {
			err = EOVERFLOW;
			goto out;
		}
	}
	else {
		sess->record_layer.mb = mbuf_alloc(mbuf_get_left(mbx));
		if (!sess->record_layer.mb) {
			err = ENOMEM;
			goto out;
		}

		err = mbuf_write_mem(sess->record_layer.mb,
				     mbuf_buf(mbx),mbuf_get_left(mbx));
		if (err)
			goto out;

		sess->record_layer.mb->pos = 0;
	}

	mbx = NULL;  /* unused after this */

	for (;;) {

		if (mbuf_get_left(sess->record_layer.mb) < 5)
			break;

		pos = sess->record_layer.mb->pos;

		err = session_record_decode(sess, sess->record_layer.mb);
		if (err) {
			sess->record_layer.mb->pos = pos;
			if (err == ENODATA)
				err = 0;
			break;
		}

		if (sess->record_layer.mb->pos >= sess->record_layer.mb->end) {
			sess->record_layer.mb =
				mem_deref(sess->record_layer.mb);
			break;
		}
		if (sess->closed)
			break;
	}

 out:
	if (err) {
		conn_close(sess, err);
	}
}


void tls_session_recvudp(struct tls_session *sess, struct mbuf *mb)
{
	int err = 0;

	if (!sess || !mb)
		return;

	sess->record_layer.read.bytes += mbuf_get_left(mb);

	while (mbuf_get_left(mb) >= 5) {

		err = session_record_decode(sess, mb);
		if (err)
			break;

		if (sess->closed)
			break;
	}
}


struct tls_secparam *tls_session_secparam(struct tls_session *sess,
					  bool write)
{
	if (!sess)
		return NULL;

	if (write)
		return &sess->sp_write;
	else
		return &sess->sp_read;
}


void tls_session_dump(const struct tls_session *sess)
{
	if (!sess)
		return;

	re_printf("~~~~~ DTLS Session ~~~~~\n");

	re_printf("cipher_spec:       0x%02x 0x%02x (%s)\n",
		  sess->selected_cipher_suite>>8,
		  sess->selected_cipher_suite&0xff,
		  tls_cipher_suite_name(sess->selected_cipher_suite));
	re_printf("pre_master_secret[%zu]: %w\n",
		  sizeof(sess->pre_master_secret),
		  sess->pre_master_secret, sizeof(sess->pre_master_secret));

	re_printf("key_block:  client_write_MAC: %zu bytes\n",
		  sess->key_block.client_write_MAC_key.len);
	re_printf("            server_write_MAC: %zu bytes\n",
		  sess->key_block.server_write_MAC_key.len);
	re_printf("            client_write_key: %zu bytes\n",
		  sess->key_block.client_write_key.len);
	re_printf("            server_write_key: %zu bytes\n",
		  sess->key_block.server_write_key.len);

	re_printf("WRITE:\n");
	tls_secparam_dump(&sess->sp_write);
	re_printf("READ:\n");
	tls_secparam_dump(&sess->sp_read);
}


void tls_session_summary(const struct tls_session *sess)
{
	if (!sess)
		return;

	re_printf("~~~ Handshake-layer:  ~~~\n");
	re_printf("___ write_seq: %u    (%zu bytes)\n",
		  sess->handshake.seq_write, sess->handshake.bytes_write);
	re_printf("___ read_seq:  %u    (%zu bytes)\n",
		  sess->handshake.seq_read, sess->handshake.bytes_read);
	re_printf("\n");

	// XXX: add tls_record_layer_summary
	re_printf("~~~ Record-layer:  ~~~\n");
	re_printf("___ write_seq %u.%llu    (%zu bytes)\n",
		  sess->record_layer.write.epoch,
		  sess->record_layer.write.seq,
		  sess->record_layer.write.bytes);
	re_printf("___ read_seq  %u.%llu    (%zu bytes)\n",
		  sess->record_layer.read.epoch,
		  sess->record_layer.read.seq,
		  sess->record_layer.read.bytes);

	if (sess->record_layer.mb_write->end) {
		re_printf("___ pending write: %zu bytes\n",
			  sess->record_layer.mb_write->end);
	}

	re_printf("selected_cipher_suite:    0x%04x (%s)\n",
		  sess->selected_cipher_suite,
		  tls_cipher_suite_name(sess->selected_cipher_suite));

	re_printf("\n");
}


int tls_session_set_certificate(struct tls_session *sess,
				 const char *pem, size_t len)
{
	if (!sess || !pem || !len)
		return EINVAL;

	sess->cert_local = mem_deref(sess->cert_local);

	return cert_decode_pem(&sess->cert_local, pem, len);
}


void tls_session_set_certificate2(struct tls_session *sess,
				   struct cert *cert)
{
	if (!sess || !cert)
		return;

	mem_deref(sess->cert_local);
	sess->cert_local = mem_ref(cert);
}


enum tls_cipher_suite tls_session_cipher(struct tls_session *sess)
{
	if (!sess)
		return TLS_CIPHER_NULL_WITH_NULL_NULL;

	return sess->selected_cipher_suite;
}


int tls_session_set_fragment_size(struct tls_session *sess, size_t size)
{
	if (!sess || size<2)
		return EINVAL;

	sess->record_fragment_size = size;

	return 0;
}


struct cert *tls_session_peer_certificate(const struct tls_session *sess)
{
	return sess ? sess->cert_remote : NULL;
}


bool tls_session_is_estab(const struct tls_session *sess)
{
	return sess ? sess->estab : false;
}


void tls_session_shutdown(struct tls_session *sess)
{
	DEBUG_INFO("shutdown\n");

	if (!sess || sess->closed)
		return;

	sess->closed = true;

	send_alert(sess, TLS_LEVEL_FATAL, TLS_ALERT_CLOSE_NOTIFY);
}


const struct list *tls_session_remote_exts(const struct tls_session *sess)
{
	return sess ? &sess->exts_remote : NULL;
}


int tls_session_get_servername(struct tls_session *sess,
			       char *servername, size_t sz)
{
	struct tls_extension *ext;

	if (!sess || !servername || !sz)
		return EINVAL;

	ext = tls_extension_find(tls_session_remote_exts(sess),
				 TLS_EXT_SERVER_NAME);
	if (!ext) {
		DEBUG_WARNING("remote server_name is missing\n");
		return ENOENT;
	}

	if (ext->v.server_name.type != 0)
		return ENOTSUP;

	str_ncpy(servername, ext->v.server_name.host, sz);

	return 0;
}


const char *tls_state_name(enum tls_state st)
{
	switch (st) {

	case TLS_STATE_IDLE:                   return "IDLE";
	case TLS_STATE_CLIENT_HELLO_SENT:      return "CLIENT_HELLO_SENT";
	case TLS_STATE_CLIENT_HELLO_RECV:      return "CLIENT_HELLO_RECV";
	case TLS_STATE_SERVER_HELLO_DONE_RECV: return "SERVER_HELLO_DONE_RECV";
	case TLS_STATE_FINISHED_RECV:          return "FINISHED_RECV";

	default: return "???";
	}
}
