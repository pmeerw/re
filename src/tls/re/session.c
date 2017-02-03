/**
 * @file session.c TLS session
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <string.h>
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


#define MAX_MAC_SIZE 32
#define IV_SIZE 16
#define TCP_BUFSIZE_MAX (1<<24)
#define MAX_RSA_BYTES 512  /* 4096 bits */
#define SEED_SIZE 32
#define DTLS_COOKIE_LENGTH 256
#define MBUF_HEADROOM 4


/* XXX: split into client.c and server.c */
struct tls_session {
	const struct tls *tls;               /* pointer to parent context */

	struct tls_secparam sp_write;
	struct tls_secparam sp_read;

	struct tls_key_block key_block;

	enum tls_connection_end conn_end;
	enum tls_version version;

	enum tls_cipher_suite *cipherv;
	size_t cipherc;

	enum tls_cipher_suite selected_cipher_suite;

	const struct tls_suite *suite;

	uint8_t pre_master_secret[48];
	uint8_t encr_pre_master_secret[MAX_RSA_BYTES];
	size_t encr_pre_master_secret_len;

	/* certificates (X509v3) */
	struct cert *cert_local;
	struct cert *cert_remote;

	/* callback handlers */
	tls_sess_send_h *sendh;
	tls_data_recv_h *datarecvh;
	tls_sess_estab_h *estabh;
	tls_sess_close_h *closeh;
	void *arg;

	enum tls_trace_flags trace_flags;
	tls_trace_h *traceh;

	bool estab;
	bool closed;
	bool alert_sent;
	bool got_ccs;

	/*
	 * PROTOCOL LAYERS BELOW:
	 */

	/* handshake layer: */
	SHA256_CTX hand_ctx;          /* hash of Handshakes sent/received */
	uint16_t hand_seq_write;
	uint16_t hand_seq_read;
	size_t hand_bytes_write;
	size_t hand_bytes_read;
	struct mbuf *hand_mb;         /* buffer incoming handshake fragments */

	uint8_t hand_cookie[DTLS_COOKIE_LENGTH];    /* DTLS only */
	size_t hand_cookie_len;

	/* record layer: */
	struct mbuf *mb_write;        /* buffer outgoing records */
	struct mbuf *mb;              /* buffer for incoming TCP-packets */
	uint64_t record_seq_write;    /* sequence number for each record */
	uint64_t record_seq_read;     /* sequence number for each record */
	uint16_t epoch_write;         /* only for DTLS */
	uint16_t epoch_read;          /* only for DTLS */
	size_t record_bytes_write;
	size_t record_bytes_read;
	size_t record_fragment_size;
	uint64_t next_receive_seq;  /* DTLS only */

	struct list exts_remote;
};


static int encrypt_send_record(struct tls_session *sess,
			       enum tls_content_type type, struct mbuf *data);
static int record_layer_flush(struct tls_session *sess);
static int record_layer_write(struct tls_session *sess,
			      enum tls_content_type type,
			      const uint8_t *frag, size_t fraglen,
			      bool flush_now);
static int record_layer_send(struct tls_session *sess,
			     enum tls_content_type type,
			     struct mbuf *mb_data, bool flush_now);
static void handshake_layer_append(struct tls_session *sess,
				   bool is_write,
				   const uint8_t *data, size_t len);
static int handle_change_cipher_spec(struct tls_session *sess);


/*
 * HANDSHAKE LAYER
 */


static int handshake_layer_send(struct tls_session *sess,
				enum tls_handshake_type msg_type,
				const union handshake *hand,
				bool flush_now, bool crypt)
{
	struct mbuf *mb = NULL;
	int err;

	tls_trace(sess, TLS_TRACE_HANDSHAKE,
		   "send handshake: type=%s\n",
		   tls_handshake_name(msg_type));

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err = tls_handshake_encode(mb, sess->version, msg_type,
				    sess->hand_seq_write, 0, hand);
	if (err)
		goto out;

	handshake_layer_append(sess, true, mb->buf, mb->end);

	mb->pos = 0;

	if (crypt) {
		err = encrypt_send_record(sess, TLS_HANDSHAKE, mb);
	}
	else {
		err = record_layer_send(sess, TLS_HANDSHAKE, mb, flush_now);
	}
	if (err)
		goto out;

	++sess->hand_seq_write;

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
		sess->hand_bytes_write += len;
	else
		sess->hand_bytes_read += len;

	SHA256_Update(&sess->hand_ctx, data, len);

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

	copy = sess->hand_ctx;
	SHA256_Final(md, &copy);

	return 0;
}


/*
 * RECORD LAYER
 */


/* this function sends a large payload data, and does fragmentation */
static int record_layer_send(struct tls_session *sess,
			     enum tls_content_type type,
			     struct mbuf *mb_data, bool flush_now)
{
	int err = 0;

#if 0
	tls_trace(sess, TLS_TRACE_RECORD,
		   "record layer send "
		   "(type=%s datalen=%zu bytes %s)\n",
		   tls_content_type_name(type), mbuf_get_left(mb_data),
		   flush_now ? "FLUSH" : "");
#endif

	while (mbuf_get_left(mb_data)) {

		size_t sz = min(sess->record_fragment_size,
				mbuf_get_left(mb_data));

		err = record_layer_write(sess,
					 type,
					 mbuf_buf(mb_data), sz,
					 flush_now);
		if (err)
			return err;

		mbuf_advance(mb_data, sz);
	}

	return err;
}


/* this function sends only 1 (one) fragment (!) */
static int record_layer_write(struct tls_session *sess,
			      enum tls_content_type type,
			      const uint8_t *frag, size_t fraglen,
			      bool flush_now)
{
	int err;

	tls_trace(sess, TLS_TRACE_RECORD,
		   "record layer write fragment "
		   "(type=%s fraglen=%zu bytes %s)\n",
		   tls_content_type_name(type), fraglen,
		   flush_now ? "FLUSH" : "");

	mbuf_skip_to_end(sess->mb_write);

	err = tls_record_encode(sess->mb_write, sess->version, type,
				 sess->epoch_write,
				 sess->record_seq_write,
				 frag, fraglen);
	if (err)
		goto out;

	++sess->record_seq_write;

	if (flush_now) {
		err = record_layer_flush(sess);
		if (err)
			goto out;
	}

 out:
	return err;
}


/* Flush the buffer to the network */
static int record_layer_flush(struct tls_session *sess)
{
	int err;

	sess->mb_write->pos = MBUF_HEADROOM;

	if (!mbuf_get_left(sess->mb_write)) {
		DEBUG_WARNING("record_layer_flush: no data to send!\n");
		return EINVAL;
	}

	sess->record_bytes_write += mbuf_get_left(sess->mb_write);

	if (sess->sendh)
		err = sess->sendh(sess->mb_write, sess->arg);
	else
		err = EIO;
	if (err)
		goto out;

	sess->mb_write->pos = MBUF_HEADROOM;
	sess->mb_write->end = MBUF_HEADROOM;

 out:
	return err;
}


static void record_layer_new_write_epoch(struct tls_session *sess)
{
	/* new epoch, reset sequence number */
	++sess->epoch_write;
	sess->record_seq_write = 0;
}


static void record_layer_new_read_epoch(struct tls_session *sess)
{
	/* new epoch, reset sequence number */
	++sess->epoch_read;
	sess->record_seq_read = 0;

	sess->next_receive_seq = 0;
}


static uint64_t record_get_read_seqnum(const struct tls_session *sess)
{
	uint64_t epoch_seq;

	epoch_seq = sess->record_seq_read;

	if (tls_version_is_dtls(sess->version)) {
		epoch_seq |= ((uint64_t)sess->epoch_read) << 48;
	}

	return epoch_seq;
}


static uint64_t record_get_write_seqnum(const struct tls_session *sess)
{
	uint64_t epoch_seq;

	epoch_seq = sess->record_seq_write;

	if (tls_version_is_dtls(sess->version)) {
		epoch_seq |= ((uint64_t)sess->epoch_write) << 48;
	}

	return epoch_seq;
}


/*
 * END LAYERS
 */


static bool cipher_suite_lookup(const struct tls_session *sess,
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


static int send_clienthello(struct tls_session *sess)
{
	union handshake hand;
	struct clienthello *hello = &hand.clienthello;
	enum tls_compression_method compr_methods[1] = {
		TLS_COMPRESSION_NULL
	};
	uint16_t *datav = NULL;
	size_t i;
	int err;

	datav = mem_alloc(sess->cipherc * sizeof(uint16_t), NULL);

	memset(&hand, 0, sizeof(hand));

	hello->client_version = sess->version;

	mem_cpy(hello->random, sizeof(hello->random),
		sess->sp_write.client_random,
		sizeof(sess->sp_write.client_random));

	/* Optional cookie for DTLS */
	if (sess->hand_cookie_len) {
		hello->cookie.data = sess->hand_cookie;
		hello->cookie.bytes = sess->hand_cookie_len;
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

	err = handshake_layer_send(sess, TLS_CLIENT_HELLO, &hand,
				   true, false);
	if (err)
		goto out;

 out:
	tls_vector_reset(&hello->extensions);
	mem_deref(datav);
	return err;
}


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
	// XXX: intersect with remote
	if (sess->tls && !list_isempty(&sess->tls->exts_local)) {

		err = tls_extensions_encode(&hello->extensions,
					    &sess->tls->exts_local);
		if (err) {
			DEBUG_WARNING("ext encode error (%m)\n", err);
			goto out;
		}
	}

	err = handshake_layer_send(sess, TLS_SERVER_HELLO, &hand,
				   false, false);
	if (err)
		goto out;

 out:
	tls_vector_reset(&hello->extensions);

	return 0;
}


static int send_certificate(struct tls_session *sess)
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

	err = handshake_layer_send(sess, TLS_CERTIFICATE, &hand,
				   false, false);
	if (err)
		goto out;

 out:
	tls_vector_reset(&cert->certlist[0]);
	mem_deref(der);

	return err;
}


static int send_serverhellodone(struct tls_session *sess)
{
	int err;

	err = handshake_layer_send(sess, TLS_SERVER_HELLO_DONE, NULL,
				   true, false);
	if (err)
		return err;

	return 0;
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

	mem_deref(sess->hand_mb);
	mem_deref(sess->mb);
	mem_deref(sess->mb_write);
	mem_deref(sess->cert_local);
	mem_deref(sess->cert_remote);
	mem_deref(sess->cipherv);
	list_flush(&sess->exts_remote);
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
			DEBUG_WARNING("cipher suite not supported"
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

	SHA256_Init(&sess->hand_ctx);

	sess->mb_write = mbuf_alloc(512);
	if (!sess->mb_write) {
		err = ENOMEM;
		goto out;
	}

	sess->mb_write->pos = MBUF_HEADROOM;
	sess->mb_write->end = MBUF_HEADROOM;

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

	return send_clienthello(sess);
}


static int send_change_cipher_spec(struct tls_session *sess)
{
	struct mbuf mb_pld = { (uint8_t*)"\x01", 1, 0, 1};
	int err;

	tls_trace(sess, TLS_TRACE_CHANGE_CIPHER_SPEC,
		   "send ChangeCipherSpec\n");

	err = record_layer_write(sess, TLS_CHANGE_CIPHER_SPEC,
				 mb_pld.buf, mb_pld.end,
				 false);
	if (err)
		goto out;

	record_layer_new_write_epoch(sess);

	err = tls_secparam_set(&sess->sp_write, sess->suite);
	if (err) {
		DEBUG_WARNING("tls_secparam_set failed (%m)\n", err);
		goto out;
	}

 out:
	return err;
}


/* send Client Key Exchange message */
static int send_clientkeyexchange(struct tls_session *sess)
{
	struct tls_handshake hand;
	int err;

	memset(&hand, 0, sizeof(hand));

	err = tls_vector_init(&hand.u.client_key_exchange.encr_pms,
			       sess->encr_pre_master_secret,
			       sess->encr_pre_master_secret_len);
	if (err)
		goto out;

	err = handshake_layer_send(sess, TLS_CLIENT_KEY_EXCHANGE,
				   &hand.u, false, false);
	if (err)
		goto out;

#if 1
	/* XXX: this can be moved elsewhere ? */
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


static int encrypt_send_record(struct tls_session *sess,
			       enum tls_content_type type, struct mbuf *data)
{
	struct mbuf *mb_enc = mbuf_alloc(1024);
	uint8_t mac[MAX_MAC_SIZE];
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
				       record_get_write_seqnum(sess),
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

	err = record_layer_write(sess, type,
				 mbuf_buf(mb_enc), mbuf_get_left(mb_enc),
				 true);
	if (err)
		goto out;

 out:
	// TODO: crash in mem_deref, written past end (trailer)
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
	uint8_t seed[SEED_SIZE];
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

	err = handshake_layer_send(sess, TLS_FINISHED, &hand,
				   true, true);
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
	uint8_t seed[SEED_SIZE];
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
	    0 != memcmp(verify_data, fin->verify_data, sizeof(verify_data))) {
		DEBUG_WARNING("finished: verify_data mismatch\n");

		re_printf("finished: packet = %w\n",
			  fin->verify_data, sizeof(fin->verify_data));
		re_printf("          calcul = %w\n",
			  verify_data, sizeof(verify_data));

		return EPROTO;
	}

	return 0;
}


static int handle_clientkeyexchange(struct tls_session *sess,
				    const struct client_key_exchange *cke)
{
	uint8_t buf[512];
	size_t buf_len = sizeof(buf);
	uint16_t ver_be = htons(sess->version);
	int err;

	/* decrypt PMS using local cert's private key */
	err = cert_private_decrypt(sess->cert_local,
				   buf, &buf_len,
				   cke->encr_pms.data,
				   cke->encr_pms.bytes);
	if (err) {
		DEBUG_WARNING("private_decrypt failed (%m)\n", err);
		goto out;
	}

	/* TODO: continue the handshake to avoid the Bleichenbacher attack
	 */
	if (0 != memcmp(buf, &ver_be, 2)) {
		DEBUG_WARNING("version rollback attack [0x%02x 0x%02x]\n",
			      buf[0], buf[1]);
	}

	/* save the Pre master secret (cleartext) */
	if (buf_len != sizeof(sess->pre_master_secret)) {
		DEBUG_WARNING("illegal pms length\n");
		err = EPROTO;
		goto out;
	}
	mem_cpy(sess->pre_master_secret,
		sizeof(sess->pre_master_secret),
		buf, buf_len);

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
	return err;
}


static int client_handle_server_hello(struct tls_session *sess,
				      const struct serverhello *hell)
{
	int err = 0;

	/* save the Server-random */
	mem_cpy(sess->sp_read.server_random,
		sizeof(sess->sp_read.server_random),
		hell->random, sizeof(hell->random));
	mem_cpy(sess->sp_write.server_random,
		sizeof(sess->sp_write.server_random),
		hell->random, sizeof(hell->random));

	/* the cipher-suite is now decided */
	if (!cipher_suite_lookup(sess, hell->cipher_suite)) {
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


static int client_handle_server_hello_done(struct tls_session *sess)
{
	int err;

	/* NOTE: we must wait for all handshake messages
	 * to be processed and hashed
	 */
	send_clientkeyexchange(sess);

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


static int server_handle_client_hello(struct tls_session *sess,
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

	suites = chell->cipher_suites.data;
	n      = chell->cipher_suites.bytes / 2;

	/* check for a common cipher-suite */
	for (i=0; i<n; i++) {
		enum tls_cipher_suite cs = ntohs(suites[i]);

		if (cipher_suite_lookup(sess, cs)) {
			sess->selected_cipher_suite = cs;
			supported = true;
			break;
		}
	}
	if (!supported) {
		DEBUG_WARNING("no common cipher suites"
			      " (server=%zu, client=%zu)\n",
			      sess->cipherc, n);
		send_alert(sess, TLS_LEVEL_FATAL,
			   TLS_ALERT_HANDSHAKE_FAILURE);
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

	err = send_certificate(sess);
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


static int handle_finished(struct tls_session *sess,
			   const struct finished *fin)
{
	int err;

	if (!sess->got_ccs) {
		DEBUG_WARNING("recv Finished, but no CCS received\n");
		return EPROTO;
	}

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

	++sess->hand_seq_read;

	/* XXX: exclude Finished, that is a hack */
	if (hand->msg_type != TLS_FINISHED) {

		handshake_layer_append(sess, false,
				       fragment, length);
	}

	switch (hand->msg_type) {

	case TLS_CLIENT_HELLO:
		err = server_handle_client_hello(sess, &hand->u.clienthello);
		break;

	case TLS_SERVER_HELLO:
		err = client_handle_server_hello(sess, &hand->u.serverhello);
		break;

	case TLS_HELLO_VERIFY_REQUEST: {
		const struct tls_vector *cook;

		cook = &hand->u.hello_verify_req.cookie;

		/* save the cookie from server */
		memcpy(sess->hand_cookie, cook->data, cook->bytes);
		sess->hand_cookie_len = cook->bytes;

		/*
		 * in cases where the cookie exchange is used, the initial
		 * ClientHello and HelloVerifyRequest MUST NOT be included
		 * in the CertificateVerify or Finished MAC computations.
		 */
		SHA256_Init(&sess->hand_ctx);

		err = send_clienthello(sess);
	}
		break;

	case TLS_CERTIFICATE:
		err = handle_certificate(sess, &hand->u.certificate);
		break;

	case TLS_SERVER_HELLO_DONE:
		err = client_handle_server_hello_done(sess);
		break;

	case TLS_CLIENT_KEY_EXCHANGE:
		err = handle_clientkeyexchange(sess,
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


/*
 * NOTE: Record layer
 *
 * 1. Decrypt payload using AES
 * 2. Calculate and verify the MAC
 *
 * <pre>
 *      struct {
 *          opaque IV[SecurityParameters.record_iv_length];
 *          block-ciphered struct {
 *              opaque content[TLSCompressed.length];
 *              opaque MAC[SecurityParameters.mac_length];
 *              uint8 padding[GenericBlockCipher.padding_length];
 *              uint8 padding_length;
 *          };
 *      } GenericBlockCipher;
 * <pre>
 *
 */
static int record_decrypt_aes_and_unmac(struct tls_session *sess,
				 struct tls_record *rec,
				 struct mbuf *mb)
{
	const struct key *write_key, *write_MAC_key;
	uint8_t mac_pkt[MAX_MAC_SIZE], mac_gen[MAX_MAC_SIZE], padding;
	size_t start, pos_content, pos_mac, mac_sz, content_len;
	int err = 0;

	if (!sess || !rec || mbuf_get_left(mb) < (IV_SIZE+20))
		return EINVAL;

	start       = mb->pos;
	pos_content = start + IV_SIZE;
	mac_sz      = sess->sp_read.mac_length;

	if (sess->conn_end == TLS_CLIENT)
		write_key = &sess->key_block.server_write_key;
	else if (sess->conn_end == TLS_SERVER)
		write_key = &sess->key_block.client_write_key;
	else
		return EINVAL;

	err = tls_crypt_decrypt(write_key, mb, rec->length, &padding);
	if (err) {
		DEBUG_WARNING("crypt_decrypt error (%m)\n", err);
		return err;
	}

	pos_mac     = start + rec->length - mac_sz - padding - 1;
	content_len = rec->length - IV_SIZE - mac_sz - padding - 1;

	mb->pos = pos_mac;
	err = mbuf_read_mem(mb, mac_pkt, mac_sz);
	if (err)
		return err;

	if (sess->conn_end == TLS_CLIENT)
		write_MAC_key = &sess->key_block.server_write_MAC_key;
	else if (sess->conn_end == TLS_SERVER)
		write_MAC_key = &sess->key_block.client_write_MAC_key;
	else
		return EINVAL;

	err = tls_mac_generate(mac_gen, mac_sz, write_MAC_key,
			       record_get_read_seqnum(sess), rec->content_type,
			       rec->proto_ver, content_len,
			       &mb->buf[pos_content]);
	if (err)
		return err;

	if (0 != memcmp(mac_gen, mac_pkt, mac_sz)) {
		DEBUG_WARNING("decrypt: *** MAC Mismatch!"
			      " (record type '%s', length %u) ***"
			      "\n",
			      tls_content_type_name(rec->content_type),
			      rec->length);
		re_printf("write_MAC_key:  %w\n",
			  write_MAC_key->k, write_MAC_key->len);
		re_printf("read_seq_num:   %llu\n",
			  record_get_read_seqnum(sess));
		re_printf("MAC: generated: %w\n", mac_gen, mac_sz);
		re_printf("     packet:    %w\n", mac_pkt, mac_sz);
		return EBADMSG;
	}

	/* update mbuf */
	mb->pos = pos_content;
	mb->end = pos_content + content_len;

	// TODO: does this work if there are more records coming in this mbuf?
	err = mbuf_shift(mb, -IV_SIZE);
	if (err)
		return err;

	/* update record header with length of clear-text record */
	rec->length = content_len;

	return 0;
}


static int handle_handshake_fragment(struct tls_session *sess,
				     const struct tls_record *rec,
				     struct mbuf *mb)
{
	enum tls_version ver = rec->proto_ver;
	size_t pos;
	int err;

	/*
	 * Part I -- write record to handshake buffer
	 */
	if (!sess->hand_mb) {
		sess->hand_mb = mbuf_alloc(512);
		if (!sess->hand_mb)
			return ENOMEM;
	}

	pos = sess->hand_mb->pos;

	sess->hand_mb->pos = sess->hand_mb->end;

	err = mbuf_write_mem(sess->hand_mb, rec->fragment, rec->length);
	if (err)
		return err;

	mb->pos += rec->length;

	sess->hand_mb->pos = pos;

	rec = NULL;  /* not used anymore */


	/*
	 * Part II -- read handshakes from buffer
	 */
	for (;;) {
		struct tls_handshake *handshake = 0;
		uint8_t *frag;
		size_t length;
		bool stop = false;

		pos = sess->hand_mb->pos;

		frag = mbuf_buf(sess->hand_mb);

		err = tls_handshake_decode(&handshake,
					    ver, sess->hand_mb);
		if (err) {
			sess->hand_mb->pos = pos;
			if (err == ENODATA)
				err = 0;
			break;
		}

		length = sess->hand_mb->pos - pos;

		mem_ref(sess);
		process_handshake(sess, frag, length, handshake);

		mem_deref(handshake);

		// todo: the handler might deref session
		if (sess->hand_mb->pos >= sess->hand_mb->end) {
			sess->hand_mb = mem_deref(sess->hand_mb);
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
static void handle_cleartext_record(struct tls_session *sess,
				    const struct tls_record *rec,
				    struct mbuf *mb)
{
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
		err = handle_handshake_fragment(sess, rec, mb);
		break;

	case TLS_APPLICATION_DATA:
		mbuf_advance(mb, rec->length);

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


static int tls_session_record_decode(struct tls_session *sess,
			       struct tls_record **recp, struct mbuf *mb)
{
	size_t start, stop;
	struct tls_record *rec = NULL;
	size_t data_start;
	int err;

	if (!sess || !recp || !mb)
		return EINVAL;

	start = mb->pos;

	err = tls_record_header_decode(&rec, mb);
	if (err)
		goto out;

	stop = start + tls_record_hdrsize(rec->proto_ver) + rec->length;

	tls_trace(sess, TLS_TRACE_RECORD,
		   "{%u.%llu} decode type '%s' fragment_length=%zu\n",
		   rec->epoch, rec->seq,
		   tls_content_type_name(rec->content_type), rec->length);

	if (tls_version_is_dtls(sess->version)) {

		if (rec->epoch == sess->epoch_read &&
		    rec->seq == sess->next_receive_seq) {

			++sess->next_receive_seq;
		}
		else {
			/* SHOULD queue the message but MAY discard it. */
			DEBUG_INFO("discard message: epoch_seq=%u.%llu\n",
				   rec->epoch, rec->seq);

			mb->pos = stop;
			goto out;
		}
	}

	data_start = mb->pos;

	switch (sess->sp_read.bulk_cipher_algorithm) {

	case TLS_BULKCIPHER_NULL:
		//rec->length -= sess->sp_read.mac_length;
		break;

	case TLS_BULKCIPHER_AES:
		err = record_decrypt_aes_and_unmac(sess, rec, mb);
		break;

	default:
		DEBUG_WARNING("session_record_decode: unknown"
			      " bulk cipher algo %d\n",
			      sess->sp_read.bulk_cipher_algorithm);
		err = ENOTSUP;
		goto out;
		break;
	}
	if (err) {
		DEBUG_WARNING("session: record decrypt error "
			      "on type '%s' (%m)\n",
			      tls_content_type_name(rec->content_type), err);
		goto out;
	}

	mb->pos = data_start;

	/* increment sequence number, before passing on to upper layer */
	++sess->record_seq_read;

	/* Pass the Record on to upper layers */
	handle_cleartext_record(sess, rec, mb);

	/* update stop position after decrypting the record */
	stop = start + tls_record_hdrsize(rec->proto_ver) + rec->length;

	/* todo: check this stuff here.. */
	if (mb->pos != stop) {
		re_printf("adjust pos: %zu -> %zu\n", mb->pos, stop);
		mbuf_set_pos(mb, stop);
	}

 out:
	if (err)
		mem_deref(rec);
	else
		*recp = rec;

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
	record_layer_new_read_epoch(sess);

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


void tls_session_recvtcp(struct tls_session *sess, struct mbuf *mb)
{
	size_t pos;
	int err = 0;

	if (!sess || !mb)
		return;

	sess->record_bytes_read += mbuf_get_left(mb);

	if (sess->mb) {
		pos = sess->mb->pos;

		sess->mb->pos = sess->mb->end;

		err = mbuf_write_mem(sess->mb, mbuf_buf(mb),mbuf_get_left(mb));
		if (err)
			goto out;

		sess->mb->pos = pos;

		if (mbuf_get_left(sess->mb) > TCP_BUFSIZE_MAX) {
			err = EOVERFLOW;
			goto out;
		}
	}
	else {
		sess->mb = mem_ref(mb);
	}

	for (;;) {
		struct tls_record *rec = 0;

		if (mbuf_get_left(sess->mb) < 5)
			break;

		pos = sess->mb->pos;

		err = tls_session_record_decode(sess, &rec, sess->mb);
		if (err) {
			sess->mb->pos = pos;
			if (err == ENODATA)
				err = 0;
			break;
		}

		mem_deref(rec);

		if (sess->mb->pos >= sess->mb->end) {
			sess->mb = mem_deref(sess->mb);
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
	struct tls_record *rec = NULL;
	int err = 0;

	if (!sess || !mb)
		return;

	sess->record_bytes_read += mbuf_get_left(mb);

	while (mbuf_get_left(mb) >= 5) {

		err = tls_session_record_decode(sess, &rec, mb);
		if (err)
			break;

		rec = mem_deref(rec);

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
		  sess->hand_seq_write, sess->hand_bytes_write);
	re_printf("___ read_seq:  %u    (%zu bytes)\n",
		  sess->hand_seq_read, sess->hand_bytes_read);
	re_printf("\n");

	re_printf("~~~ Record-layer:  ~~~\n");
	re_printf("___ write_seq %u.%llu    (%zu bytes)\n",
		  sess->epoch_write, sess->record_seq_write,
		  sess->record_bytes_write);
	re_printf("___ read_seq  %u.%llu    (%zu bytes)\n",
		  sess->epoch_read, sess->record_seq_read,
		  sess->record_bytes_read);

	if (sess->mb_write->end) {
		re_printf("___ pending write: %zu bytes\n",
			  sess->mb_write->end);
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
	if (!sess || sess->closed)
		return;

	sess->closed = true;

	send_alert(sess, TLS_LEVEL_FATAL, TLS_ALERT_CLOSE_NOTIFY);
}


const struct list *tls_session_remote_exts(const struct tls_session *sess)
{
	return sess ? &sess->exts_remote : NULL;
}
