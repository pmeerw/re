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

	sess->record_layer.mb_write->pos = MBUF_HEADROOM;

	if (!mbuf_get_left(sess->record_layer.mb_write)) {
		DEBUG_WARNING("record_layer_flush: no data to send!\n");
		return EINVAL;
	}

	sess->record_bytes_write += mbuf_get_left(sess->record_layer.mb_write);

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


void tls_record_layer_new_write_epoch(struct tls_session *sess)
{
	/* new epoch, reset sequence number */
	++sess->epoch_write;
	sess->record_seq_write = 0;
}


void tls_record_layer_new_read_epoch(struct tls_session *sess)
{
	/* new epoch, reset sequence number */
	++sess->epoch_read;
	sess->record_seq_read = 0;

	sess->next_receive_seq = 0;
}


uint64_t tls_record_get_read_seqnum(const struct tls_session *sess)
{
	uint64_t epoch_seq;

	epoch_seq = sess->record_seq_read;

	if (tls_version_is_dtls(sess->version)) {
		epoch_seq |= ((uint64_t)sess->epoch_read) << 48;
	}

	return epoch_seq;
}


uint64_t tls_record_get_write_seqnum(const struct tls_session *sess)
{
	uint64_t epoch_seq;

	epoch_seq = sess->record_seq_write;

	if (tls_version_is_dtls(sess->version)) {
		epoch_seq |= ((uint64_t)sess->epoch_write) << 48;
	}

	return epoch_seq;
}
