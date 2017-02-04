/**
 * @file record.c TLS records
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * The Record-layer is opaque to the payload it carries
 */


static void record_destructor(void *data)
{
	struct tls_record *rec = data;

	mem_deref(rec->fragment);
}


int tls_record_encode(struct mbuf *mb, enum tls_version ver,
		       enum tls_content_type type,
		       uint16_t epoch, uint64_t seq,
		       const uint8_t *frag, size_t fraglen)
{
	int err = 0;

	if (!mb || !frag || !fraglen)
		return EINVAL;

	if (fraglen > TLS_RECORD_FRAGMENT_SIZE)
		return EOVERFLOW;

	err |= mbuf_write_u8(mb, type);
	err |= mbuf_write_u16(mb, htons(ver));
	if (tls_version_is_dtls(ver)) {
		err |= mbuf_write_u16(mb, htons(epoch));
		err |= mbuf_write_u48_hton(mb, seq);
	}
	err |= mbuf_write_u16(mb, htons(fraglen));
	if (err)
		return err;

	err = mbuf_write_mem(mb, frag, fraglen);
	if (err)
		return err;

	return 0;
}


/* returns ENODATA if record is not complete */
int tls_record_decode(struct tls_record **recp, struct mbuf *mb)
{
	struct tls_record *rec;
	int err = 0;

	if (!recp || !mb)
		return EINVAL;

	rec = mem_zalloc(sizeof(*rec), record_destructor);
	if (!rec)
		return ENOMEM;

	if (mbuf_get_left(mb) < 3) {
		err = ENODATA;
		goto out;
	}

	rec->content_type  = mbuf_read_u8(mb);
	rec->proto_ver     = ntohs(mbuf_read_u16(mb));

	if (tls_version_is_dtls(rec->proto_ver)) {

		if (mbuf_get_left(mb) < 8) {
			err = ENODATA;
			goto out;
		}

		rec->epoch = ntohs(mbuf_read_u16(mb));
		rec->seq   = mbuf_read_u48_ntoh(mb);
	}

	if (mbuf_get_left(mb) < 2) {
		err = ENODATA;
		goto out;
	}

	rec->length        = ntohs(mbuf_read_u16(mb));

	if (rec->length > TLS_RECORD_FRAGMENT_SIZE) {
		DEBUG_WARNING("record_decode: length too long (%u)"
			      " [type=%d, ver=%d, mbuf=%zu:%zu:%zu]\n",
			      rec->length,
			      rec->content_type, rec->proto_ver,
			      mb->pos, mb->end, mb->size);
		err = EBADMSG;
		goto out;
	}
	if (rec->length > mbuf_get_left(mb)) {
		err = ENODATA;
		goto out;
	}

	/* NOTE: we copy the buffer to be safe. optimize later. */
	rec->fragment = mem_alloc(rec->length, NULL);
	if (!rec->fragment) {
		err = ENOMEM;
		goto out;
	}

	err = mbuf_read_mem(mb, rec->fragment, rec->length);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(rec);
	else
		*recp = rec;

	return err;
}


size_t tls_record_hdrsize(enum tls_version ver)
{
	if (tls_version_is_dtls(ver))
		return 5+8;
	else
		return 5;
}


const char *tls_content_type_name(enum tls_content_type typ)
{
	switch (typ) {

	case TLS_CHANGE_CIPHER_SPEC: return "change_cipher_spec";
	case TLS_ALERT:              return "alert";
	case TLS_HANDSHAKE:          return "handshake";
	case TLS_APPLICATION_DATA:   return "application_data";
	default: return "???";
	}
}


void tls_record_dump(const struct tls_record *rec)
{
	re_printf("\x1b[33m");

	re_printf("----- TLS record: -----\n");
	re_printf("type=%s, ", tls_content_type_name(rec->content_type));
	re_printf("version=%s (0x%04x), ",
		  tls_version_name(rec->proto_ver), rec->proto_ver);
	if (tls_version_is_dtls(rec->proto_ver)) {
		re_printf("epoch=%u, ", rec->epoch);
		re_printf("sequence=%llu, ", rec->seq);
	}
	re_printf("length=%u\n", rec->length);
	re_printf("\n");
	re_printf("\x1b[;m");
}
