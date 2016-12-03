/**
 * @file handshake.c TLS handshake
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_net.h>
#include <re_cert.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "dtls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void handshake_destructor(void *data)
{
	struct tls_handshake *hand = data;

	switch (hand->msg_type) {

	case TLS_CLIENT_HELLO: {
		struct clienthello *hello;

		hello = &hand->u.clienthello;

		mem_deref(hello->session_id.data);
		mem_deref(hello->cookie.data);
		mem_deref(hello->cipher_suites.data);
		mem_deref(hello->compression_methods.data);
		tls_vector_reset(&hello->extensions);
	}
		break;

	case TLS_SERVER_HELLO: {
		struct serverhello *hello;

		hello = &hand->u.serverhello;

		mem_deref(hello->session_id.data);
		tls_vector_reset(&hello->extensions);
	}
		break;

	case TLS_HELLO_VERIFY_REQUEST:
		tls_vector_reset(&hand->u.hello_verify_req.cookie);
		break;

	case TLS_CERTIFICATE: {
		struct certificate *cert;
		size_t i;

		cert = &hand->u.certificate;
		for (i=0; i<cert->count; i++)
			tls_vector_reset(&cert->certlist[i]);
		cert->count = 0;
	}

	case TLS_CLIENT_KEY_EXCHANGE: {
		struct client_key_exchange *exch;

		exch = &hand->u.client_key_exchange;

		tls_vector_reset(&exch->encr_pms);
	}
		break;

	default:
		break;
	}
}


static size_t tls_handshake_hdrsize(enum tls_version ver)
{
	if (tls_version_is_dtls(ver))
		return 12;
	else
		return 4;
}


static int clienthello_encode(struct mbuf *mb, const struct clienthello *hello)
{
	int err = 0;

	err |= mbuf_write_u16(mb, htons(hello->client_version));
	err |= mbuf_write_mem(mb, hello->random, sizeof(hello->random));
	err |= tls_vector_encode(mb, &hello->session_id, 1);
	if (hello->client_version == DTLS1_2_VERSION) {
		err |= tls_vector_encode(mb, &hello->cookie, 1);
	}
	err |= tls_vector_encode(mb, &hello->cipher_suites, 2);
	err |= tls_vector_encode(mb, &hello->compression_methods, 1);

	return err;
}


static int clienthello_decode(struct clienthello *hello, size_t stop,
			      struct mbuf *mb)
{
	size_t extensions_bytes;
	int err;

	if (mbuf_get_left(mb) < 2)
		return ENODATA;

	hello->client_version = ntohs(mbuf_read_u16(mb));
	err = mbuf_read_mem(mb, hello->random, sizeof(hello->random));
	if (err)
		return err;

	err = tls_vector_decode(&hello->session_id, 1, mb);
	if (err)
		return err;

	if (hello->client_version == DTLS1_2_VERSION) {
		err = tls_vector_decode(&hello->cookie, 1, mb);
		if (err)
			return err;
	}

	err = tls_vector_decode(&hello->cipher_suites, 2, mb);
	if (err)
		return err;
	err = tls_vector_decode(&hello->compression_methods, 1, mb);
	if (err)
		return err;

	extensions_bytes = stop - mb->pos;

	if (extensions_bytes) {

		err = tls_vector_decode(&hello->extensions, 2, mb);
		if (err)
			return err;
	}
	else {
		hello->extensions.data = NULL;
		hello->extensions.bytes = 0;
	}

	return 0;
}


static int serverhello_encode(struct mbuf *mb, const struct serverhello *hello)
{
	int err = 0;

	err |= mbuf_write_u16(mb, htons(hello->server_version));
	err |= mbuf_write_mem(mb, hello->random, sizeof(hello->random));
	err |= tls_vector_encode(mb, &hello->session_id, 1);
	err |= mbuf_write_u16(mb, htons(hello->cipher_suite));
	err |= mbuf_write_u8(mb, hello->compression_method);

	return err;
}


static int serverhello_decode(struct serverhello *hello, size_t stop,
			      struct mbuf *mb)
{
	int err;

	hello->server_version = ntohs(mbuf_read_u16(mb));
	err = mbuf_read_mem(mb, hello->random, sizeof(hello->random));
	if (err)
		return err;

	err = tls_vector_decode(&hello->session_id, 1, mb);
	if (err)
		return err;

	hello->cipher_suite = ntohs(mbuf_read_u16(mb));

	hello->compression_method = mbuf_read_u8(mb);

	if (mb->pos < stop) {

		err = tls_vector_decode(&hello->extensions, 2, mb);
		if (err)
			return err;
	}
	else {
		hello->extensions.data = NULL;
		hello->extensions.bytes = 0;
	}

	return 0;
}


static int hello_verify_request_decode(struct hello_verify_req *ver,
				       struct mbuf *mb)
{
	int err;

	if (mbuf_get_left(mb) < 2)
		return EBADMSG;

	ver->server_version = ntohs(mbuf_read_u16(mb));

	err = tls_vector_decode(&ver->cookie, 1, mb);
	if (err)
		return err;

	return 0;
}


static int certificate_encode(struct mbuf *mb, const struct certificate *cert)
{
	struct tls_vector outer;
	struct mbuf *inner;
	size_t i;
	int err;

	inner = mbuf_alloc(1024);

	for (i=0; i<cert->count; i++) {

		const struct tls_vector *v = &cert->certlist[i];

		err = tls_vector_encode(inner, v, 3);
		if (err) {
			DEBUG_WARNING("cert: inner vect (%m)\n", err);
			goto out;
		}
	}

	outer.data  = inner->buf;
	outer.bytes = inner->end;

	err = tls_vector_encode(mb, &outer, 3);
	if (err) {
		DEBUG_WARNING("cert: outer %m\n", err);
	}

 out:
	mem_deref(inner);

	return err;
}


static int certificate_decode(struct certificate *cert, struct mbuf *mb)
{
	struct tls_vector vect;
	size_t i = 0;
	size_t stop;
	int err;

	err = tls_vector_decode_hdr(&vect, 3, mb);
	if (err)
		return err;

	if (mbuf_get_left(mb) < vect.bytes) {
		return ENODATA;
	}

	stop = mb->pos + vect.bytes;

	while (mb->pos < stop) {

		if (i >= ARRAY_SIZE(cert->certlist))
			return ENOSPC;

		err = tls_vector_decode(&cert->certlist[i], 3, mb);
		if (err)
			return err;

		++i;
	}

	cert->count = i;

	return 0;
}


static int client_key_exchange_encode(struct mbuf *mb,
				      const struct client_key_exchange *exch)
{
	if (!exch)
		return EINVAL;

	return tls_vector_encode(mb, &exch->encr_pms, 2);
}


int tls_handshake_encode(struct mbuf *mb, enum tls_version ver,
			 enum tls_handshake_type msg_type,
			 uint16_t message_seq,
			 uint24_t fragment_offset,
			 const union handshake *hand)
{
	size_t start;
	size_t length;
	int err = 0;

	start = mb->pos;

	mb->pos = start + tls_handshake_hdrsize(ver);

	switch (msg_type) {

	case TLS_CLIENT_HELLO:
		err = clienthello_encode(mb, &hand->clienthello);
		if (err) {
			DEBUG_WARNING("clienthello_encode ERROR (%m)\n", err);
			return err;
		}
		break;

	case TLS_SERVER_HELLO:
		err = serverhello_encode(mb, &hand->serverhello);
		if (err) {
			DEBUG_WARNING("serverhello_encode ERROR (%m)\n", err);
			return err;
		}
		break;

	case TLS_CLIENT_KEY_EXCHANGE:
		err = client_key_exchange_encode(mb,
						 &hand->client_key_exchange);
		break;

	case TLS_FINISHED:
		err = mbuf_write_mem(mb, hand->finished.verify_data,
				     sizeof(hand->finished.verify_data));
		break;

	case TLS_CERTIFICATE:
		err = certificate_encode(mb, &hand->certificate);
		break;

	case TLS_SERVER_HELLO_DONE:
		/* no payload */
		break;

	default:
		DEBUG_WARNING("handshake: don't know how to encode %d (%s)\n",
			      msg_type, tls_handshake_name(msg_type));
		return EPROTO;
		break;
	}
	if (err)
		return err;

	length = mb->pos - start - tls_handshake_hdrsize(ver);

	mb->pos = start;

	err |= mbuf_write_u8(mb, msg_type);
	err |= mbuf_write_u24_hton(mb, (uint32_t)length);
	if (ver == DTLS1_2_VERSION) {
		err |= mbuf_write_u16(mb, htons(message_seq));
		err |= mbuf_write_u24_hton(mb, fragment_offset);
		err |= mbuf_write_u24_hton(mb, (uint32_t)length);
	}
	if (err)
		return err;

	mb->pos = mb->end;

	return 0;
}


int tls_handshake_decode(struct tls_handshake **handp,
			 enum tls_version ver, struct mbuf *mb)
{
	struct tls_handshake *hand = NULL;
	size_t stop;
	int err = 0;

	if (!handp || !mb)
		return EINVAL;

	hand = mem_zalloc(sizeof(*hand), handshake_destructor);
	if (!hand)
		return ENOMEM;

	if (mbuf_get_left(mb) < 4) {
		err = ENODATA;
		goto out;
	}
	hand->msg_type = mbuf_read_u8(mb);
	hand->length   = mbuf_read_u24_ntoh(mb);

	if (ver == DTLS1_2_VERSION) {
		if (mbuf_get_left(mb) < 8) {
			err = ENODATA;
			goto out;
		}

		hand->message_seq = ntohs(mbuf_read_u16(mb));
		hand->fragment_offset = mbuf_read_u24_ntoh(mb);
		hand->fragment_length = mbuf_read_u24_ntoh(mb);
	}

	if (mbuf_get_left(mb) < hand->length) {
		DEBUG_INFO("handshake: incomplete packet (missing %d bytes)\n",
			   (int)(hand->length - mbuf_get_left(mb)));
		err = ENODATA;
		goto out;
	}

	stop = mb->pos + hand->length;

	switch (hand->msg_type) {

	case TLS_CLIENT_HELLO:
		err = clienthello_decode(&hand->u.clienthello, stop, mb);
		if (err)
			goto out;
		break;

	case TLS_SERVER_HELLO:
		err = serverhello_decode(&hand->u.serverhello, stop, mb);
		if (err)
			goto out;
		break;

	case TLS_HELLO_VERIFY_REQUEST:
		err = hello_verify_request_decode(&hand->u.hello_verify_req,
						  mb);
		if (err)
			goto out;
		break;

	case TLS_CERTIFICATE:
		err = certificate_decode(&hand->u.certificate, mb);
		if (err)
			goto out;
		break;

	case TLS_SERVER_HELLO_DONE:
		/* empty struct */
		break;

	case TLS_CLIENT_KEY_EXCHANGE:
		err = tls_vector_decode(&hand->u.client_key_exchange.encr_pms,
					 2, mb);
		break;

	case TLS_FINISHED:
		err = mbuf_read_mem(mb, hand->u.finished.verify_data,
				    sizeof(hand->u.finished.verify_data));
		break;

	default:
		DEBUG_WARNING("handshake: don't know how to decode %d (%s)"
			      " (%u bytes)\n",
			      hand->msg_type,
			      tls_handshake_name(hand->msg_type),
			      hand->length);
		err = EPROTO;
		break;
	}
	if (err)
		goto out;

	if (mb->pos != stop) {
		re_printf("handshake(%s): decode: skipped %d bytes\n",
			  tls_handshake_name(hand->msg_type),
			  (int)(stop - mb->pos));
		mbuf_set_pos(mb, stop);
	}

 out:
	if (err)
		mem_deref(hand);
	else
		*handp = hand;

	return err;
}


const char *tls_handshake_name(enum tls_handshake_type typ)
{
	switch (typ) {

	case TLS_HELLO_REQUEST:        return "HelloRequest";
	case TLS_CLIENT_HELLO:         return "ClientHello";
	case TLS_SERVER_HELLO:         return "ServerHello";
	case TLS_HELLO_VERIFY_REQUEST: return "HelloVerifyRequest";
	case TLS_CERTIFICATE:          return "Certificate";
	case TLS_SERVER_KEY_EXCHANGE:  return "ServerKeyExchange";
	case TLS_CERTIFICATE_REQUEST:  return "CertificateRequest";
	case TLS_SERVER_HELLO_DONE:    return "ServerHelloDone";
	case TLS_CERTIFICATE_VERIFY:   return "CertificateVerify";
	case TLS_CLIENT_KEY_EXCHANGE:  return "ClientKeyExchange";
	case TLS_FINISHED:             return "Finished";
	default: return "???";
	}
}


void tls_handshake_dump(const struct tls_handshake *hand,
			 enum tls_version ver)
{
	if (!hand)
		return;

	re_printf("msg_type: %s (%d)\n",
		  tls_handshake_name(hand->msg_type), hand->msg_type);
	re_printf("length:          %u\n", hand->length);

	if (tls_version_is_dtls(ver)) {
		re_printf("message_seq:     %u\n",
			  hand->message_seq);
		re_printf("fragment_offset: %u\n",
			  hand->fragment_offset);
		re_printf("fragment_length: %u\n",
			  hand->fragment_length);
	}
	re_printf("\n");

	switch (hand->msg_type) {

	case TLS_CLIENT_HELLO: {
		const struct clienthello *hello = &hand->u.clienthello;

		re_printf("ClientHello payload:\n");
		re_printf("proto_version:       %s\n",
			  tls_version_name(hello->client_version));
		re_printf("random[%zu]:          %w\n",
			  sizeof(hello->random),
			  hello->random,
			  sizeof(hello->random));
		re_printf("session_id:          %u bytes\n",
			  hello->session_id.bytes);
		if (tls_version_is_dtls(ver)) {
			re_printf("cookie:              %u bytes\n",
				  hello->cookie.bytes);
		}
		re_printf("cipher_suites:       %u suites\n",
			  hello->cipher_suites.bytes / 2);
		re_printf("compression_methods: %u methods\n",
			  hello->compression_methods.bytes);
		re_printf("extensions:          %u bytes\n",
			  hello->extensions.bytes);
	}
		break;

	case TLS_SERVER_HELLO: {
		const struct serverhello *hello = &hand->u.serverhello;

		re_printf("ServerHello payload:\n");
		re_printf("server_version:      %s\n",
			  tls_version_name(hello->server_version));
		re_printf("random[%zu]:          %w\n",
			  sizeof(hello->random),
			  hello->random,
			  sizeof(hello->random));
		re_printf("session_id:          %u bytes\n",
			  hello->session_id.bytes);
		re_printf("cipher_suite:        0x%02x,0x%02x (%s)\n",
			  hello->cipher_suite>>8,
			  hello->cipher_suite&0xff,
			  tls_cipher_suite_name(hello->cipher_suite));
		re_printf("compression_method:  %d\n",
			  hello->compression_method);
		re_printf("extensions:          %u bytes\n",
			  hello->extensions.bytes);
	}
		break;

	default:
		break;
	}
}
