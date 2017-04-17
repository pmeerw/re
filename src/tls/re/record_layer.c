/**
 * @file record_layer.c TLS session -- Record layer
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


#define MBUF_HEADROOM 4


static int record_layer_flush(struct tls_session *sess);


/* this function sends a large payload data, and does fragmentation */
int tls_record_layer_send(struct tls_session *sess,
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

		err = tls_record_layer_write(sess,
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
int tls_record_layer_write(struct tls_session *sess,
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

	mbuf_skip_to_end(sess->record_layer.mb_write);

	err = tls_record_encode(sess->record_layer.mb_write,
				sess->version, type,
				sess->record_layer.write.epoch,
				sess->record_layer.write.seq,
				frag, fraglen);
	if (err)
		goto out;

	++sess->record_layer.write.seq;

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

	sess->record_layer.mb_write->pos = MBUF_HEADROOM;

	if (!mbuf_get_left(sess->record_layer.mb_write)) {
		DEBUG_WARNING("record_layer_flush: no data to send!\n");
		return EINVAL;
	}

	sess->record_layer.write.bytes +=
		mbuf_get_left(sess->record_layer.mb_write);

	if (sess->sendh)
		err = sess->sendh(sess->record_layer.mb_write, sess->arg);
	else
		err = EIO;
	if (err)
		goto out;

	sess->record_layer.mb_write->pos = MBUF_HEADROOM;
	sess->record_layer.mb_write->end = MBUF_HEADROOM;

 out:
	return err;
}


void tls_record_layer_new_epoch(struct tls_record_layer *record_layer, int rw)
{
	if (!record_layer)
		return;

	if (rw == READ) {
		/* new epoch, reset sequence number */
		++record_layer->read.epoch;
		record_layer->read.seq = 0;

		record_layer->next_receive_seq = 0;
	}
	else {
		/* new epoch, reset sequence number */
		++record_layer->write.epoch;
		record_layer->write.seq = 0;
	}
}


uint64_t tls_record_get_read_seqnum(const struct tls_session *sess)
{
	uint64_t epoch_seq;

	epoch_seq = sess->record_layer.read.seq;

	if (tls_version_is_dtls(sess->version)) {
		epoch_seq |= ((uint64_t)sess->record_layer.read.epoch) << 48;
	}

	return epoch_seq;
}


uint64_t tls_record_get_write_seqnum(const struct tls_session *sess)
{
	uint64_t epoch_seq;

	epoch_seq = sess->record_layer.write.seq;

	if (tls_version_is_dtls(sess->version)) {
		epoch_seq |= ((uint64_t)sess->record_layer.write.epoch) << 48;
	}

	return epoch_seq;
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
					struct tls_record *rec)
{
	const struct key *write_key, *write_MAC_key;
	uint8_t mac_pkt[TLS_MAX_MAC_SIZE], mac_gen[TLS_MAX_MAC_SIZE], padding;
	size_t start;
	size_t pos_content;
	size_t pos_mac;
	size_t mac_sz;
	size_t content_len;
	int err = 0;
	struct mbuf mbf;

	if (!sess || !rec)
		return EINVAL;

	if (rec->length < (TLS_IV_SIZE+20)) {
		DEBUG_WARNING("record too short\n");
		return EBADMSG;
	}

	mbf.buf  = rec->fragment;
	mbf.size = rec->length;
	mbf.pos  = 0;
	mbf.end  = rec->length;

	start       = 0;
	pos_content = start + TLS_IV_SIZE;
	mac_sz      = sess->sp_read.mac_length;

	if (sess->conn_end == TLS_CLIENT)
		write_key = &sess->key_block.server_write_key;
	else if (sess->conn_end == TLS_SERVER)
		write_key = &sess->key_block.client_write_key;
	else
		return EINVAL;

	err = tls_crypt_decrypt(write_key, &mbf, rec->length, &padding);
	assert(mbf.pos <= mbf.size);
	assert(mbf.end <= mbf.size);
	if (err) {
		DEBUG_WARNING("crypt_decrypt error (%m)\n", err);
		return err;
	}

	pos_mac     = start + rec->length - mac_sz - padding - 1;
	content_len = rec->length - TLS_IV_SIZE - mac_sz - padding - 1;

	mbf.pos = pos_mac;
	err = mbuf_read_mem(&mbf, mac_pkt, mac_sz);
	if (err)
		return err;

	if (sess->conn_end == TLS_CLIENT)
		write_MAC_key = &sess->key_block.server_write_MAC_key;
	else if (sess->conn_end == TLS_SERVER)
		write_MAC_key = &sess->key_block.client_write_MAC_key;
	else
		return EINVAL;

	err = tls_mac_generate(mac_gen, mac_sz, write_MAC_key,
			       tls_record_get_read_seqnum(sess),
			       rec->content_type,
			       rec->proto_ver, content_len,
			       &mbf.buf[pos_content]);
	if (err)
		return err;

	if (0 != secure_compare(mac_gen, mac_pkt, mac_sz)) {
		DEBUG_WARNING("decrypt: *** MAC Mismatch!"
			      " (record type '%s', length %u) ***"
			      "\n",
			      tls_content_type_name(rec->content_type),
			      rec->length);
		re_printf("write_MAC_key:  %w\n",
			  write_MAC_key->k, write_MAC_key->len);
		re_printf("read_seq_num:   %llu\n",
			  tls_record_get_read_seqnum(sess));
		re_printf("MAC: generated: %w\n", mac_gen, mac_sz);
		re_printf("     packet:    %w\n", mac_pkt, mac_sz);
		return EBADMSG;
	}

#if 1
	/* strip away the leading IV in the front */
	memmove(rec->fragment, rec->fragment + TLS_IV_SIZE, content_len);
#else
	uint8_t *clear;

	clear = mem_zalloc(content_len, NULL);

	mem_cpy(clear, content_len, &rec->fragment[pos_content], content_len);

	mem_deref(rec->fragment);
	rec->fragment = clear;
#endif

	/* update record header with length of clear-text record */
	rec->length = content_len;

	return 0;
}


int tls_record_layer_handle_record(struct tls_session *sess,
				   struct tls_record *rec)
{
	int err = 0;

	tls_trace(sess, TLS_TRACE_RECORD,
		  "%Hdecode type '%s' fragment_length=%u\n",
		  tls_record_print_prefix, rec,
		  tls_content_type_name(rec->content_type), rec->length);

	if (tls_version_is_dtls(sess->version)) {

		if (rec->epoch == sess->record_layer.read.epoch &&
		    rec->seq == sess->record_layer.next_receive_seq) {

			++sess->record_layer.next_receive_seq;
		}
		else {
			/* SHOULD queue the message but MAY discard it. */
			DEBUG_INFO("discard message: epoch_seq=%u.%llu\n",
				   rec->epoch, rec->seq);

			return 0;
		}
	}

	switch (sess->sp_read.bulk_cipher_algorithm) {

	case TLS_BULKCIPHER_NULL:
		rec->length -= sess->sp_read.mac_length;
		break;

	case TLS_BULKCIPHER_AES:
		err = record_decrypt_aes_and_unmac(sess, rec);
		if (err)
			return err;
		break;

	default:
		DEBUG_WARNING("session_record_decode: unknown"
			      " bulk cipher algo %d\n",
			      sess->sp_read.bulk_cipher_algorithm);
		return ENOTSUP;
	}
	if (err) {
		DEBUG_WARNING("session: record decrypt error "
			      "on type '%s' (%m)\n",
			      tls_content_type_name(rec->content_type), err);
		goto out;
	}

	/* increment sequence number, before passing on to upper layer */
	++sess->record_layer.read.seq;

	/* Pass the Record on to upper layers */
	tls_handle_cleartext_record(sess, rec);

 out:
	return err;
}


void tls_record_layer_summary(const struct tls_record_layer *record_layer)
{
	if (!record_layer)
		return;

	re_printf("~~~ Record-layer:  ~~~\n");
	re_printf("___ write_seq %u.%llu    (%zu bytes)\n",
		  record_layer->write.epoch,
		  record_layer->write.seq,
		  record_layer->write.bytes);
	re_printf("___ read_seq  %u.%llu    (%zu bytes)\n",
		  record_layer->read.epoch,
		  record_layer->read.seq,
		  record_layer->read.bytes);

	if (record_layer->mb_write->end) {
		re_printf("___ pending write: %zu bytes\n",
			  record_layer->mb_write->end);
	}
}
