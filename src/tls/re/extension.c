/**
 * @file extension.c TLS extensions
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <string.h>
#include <assert.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_list.h>
#include <re_mbuf.h>
#include <re_main.h>
#include <re_sa.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_sys.h>
#include <re_tcp.h>
#include <re_cert.h>
#include <re_tls.h>
#include "tls.h"


#define DEBUG_MODULE "tls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void ext_destructor(void *data)
{
	struct tls_extension *ext = data;

	switch (ext->type) {

	case TLS_EXT_SERVER_NAME:
		mem_deref(ext->v.server_name.host);
		break;

	default:
		break;
	}

	list_unlink(&ext->le);
}


/* NOTE: the caller must fill in the data */
int tls_extension_add(struct tls_extension **extp, struct list *extl,
		      enum tls_extension_type type)
{
	struct tls_extension *ext;

	ext = mem_zalloc(sizeof(*ext), ext_destructor);
	if (!ext)
		return ENOMEM;

	ext->type = type;

	if (extp)
		*extp = ext;

	list_append(extl, &ext->le, ext);

	return 0;
}


int tls_extensions_encode(struct tls_vector *vect,
			  const struct list *extl)
{
	struct mbuf *mb = mbuf_alloc(128);
	struct le *le;
	size_t i;
	int err = 0;

	if (!vect || !extl)
		return EINVAL;

	assert(vect->data == NULL);

	for (le = list_head(extl); le; le = le->next) {
		struct tls_extension *ext = le->data;
		size_t pos;
		size_t length;

		err = mbuf_write_u16(mb, htons(ext->type));

		pos = mb->pos;

		mb->pos += 2;

		switch (ext->type) {

		case TLS_EXT_SERVER_NAME: {
			size_t len = str_len(ext->v.server_name.host);

			err |= mbuf_write_u16(mb, htons(len + 3));
			err |= mbuf_write_u8(mb, ext->v.server_name.type);
			err |= mbuf_write_u16(mb, htons(len));
			err |= mbuf_write_str(mb, ext->v.server_name.host);
		}
			break;

		case TLS_EXT_USE_SRTP:
			for (i=0; i<ext->v.use_srtp.profilec; i++) {
				uint16_t prof = ext->v.use_srtp.profilev[i];
				err |= mbuf_write_u16(mb, htons(prof));
			}
			break;

		default:
			DEBUG_WARNING("cannot encode ext %d\n", ext->type);
			err = ENOTSUP;
			goto out;
		}
		if (err)
			goto out;

		length = mb->pos - pos - 2;
		mb->pos = pos;
		err = mbuf_write_u16(mb, htons(length));
		mb->pos  = pos + 2 + length;
	}

	vect->data = mem_ref(mb->buf);
	vect->bytes = mb->end;

 out:
	mem_deref(mb);
	return err;
}


int tls_extensions_decode(struct list *extl,
			  const struct tls_vector *vect)
{
	struct mbuf mb;
	int err = 0;

	if (!extl || !vect)
		return EINVAL;

	mb.buf = vect->data;
	mb.pos = 0;
	mb.end = mb.size = vect->bytes;

	while (mbuf_get_left(&mb) >= 4) {

		struct tls_extension *ext;
		uint16_t type, length;
		size_t i, n;
		size_t stop;

		type   = ntohs(mbuf_read_u16(&mb));
		length = ntohs(mbuf_read_u16(&mb));

		if (mbuf_get_left(&mb) < length) {
			DEBUG_WARNING("extension short length (%zu < %u bytes)"
				      "\n",
				      mbuf_get_left(&mb), length);
			return EBADMSG;
		}

#if 0
		re_printf("## ext: decode %u (%s) %u bytes\n", type,
			  tls_extension_name(type), length);
#endif

		err = tls_extension_add(&ext, extl, type);
		if (err)
			return err;

		ext->length = length;

		stop = mb.pos + length;

		/* decode any known extensions */
		switch (type) {

		case TLS_EXT_SERVER_NAME: {

			uint16_t sni_list_length;
			uint16_t sni_length;

			if (length == 0)
				break;

			sni_list_length = ntohs(mbuf_read_u16(&mb));

			if (mbuf_get_left(&mb) < sni_list_length) {
				DEBUG_WARNING("sni: short length\n");
				return EBADMSG;
			}

			ext->v.server_name.type = mbuf_read_u8(&mb);
			sni_length = ntohs(mbuf_read_u16(&mb));

			err = mbuf_strdup(&mb, &ext->v.server_name.host,
					  sni_length);
		}
			break;

		case TLS_EXT_USE_SRTP:
			n = length / 2;
			for (i=0; i<n; i++) {
				uint16_t prof;
				prof = ntohs(mbuf_read_u16(&mb));
				ext->v.use_srtp.profilev[i] = prof;
			}
			ext->v.use_srtp.profilec = i;
			break;

		default:
			DEBUG_INFO("ext: dont know how to decode"
				     " extension %d (%s)\n",
				     type,
				     tls_extension_name(type));
			break;
		}

		mb.pos = stop;
	}

	return err;
}


static int tls_extension_print(struct re_printf *pf,
			       const struct tls_extension *ext)
{
	size_t i;
	int err;

	if (!ext)
		return 0;

	err = re_hprintf(pf, "type=%d %-16s  length=%zu",
			 ext->type, tls_extension_name(ext->type),
			 ext->length);
	if (err)
		return err;

	/* print all known extensions */
	switch (ext->type) {

	case TLS_EXT_SERVER_NAME:
		err = re_hprintf(pf, " type=%u host='%s'",
				 ext->v.server_name.type,
				 ext->v.server_name.host);
		break;

	case TLS_EXT_USE_SRTP:
		err = re_hprintf(pf, " profiles=[ ");
		for (i=0; i<ext->v.use_srtp.profilec; i++) {
			err |= re_hprintf(pf, "0x%04x ",
					  ext->v.use_srtp.profilev[i]);
		}
		err = re_hprintf(pf, "]");
		break;

	default:
		break;
	}

	return err;
}


struct tls_extension *tls_extension_find(const struct list *extl,
					 enum tls_extension_type type)
{
	struct le *le;

	for (le = list_head(extl); le; le = le->next) {
		struct tls_extension *ext = le->data;

		if (type == ext->type)
			return ext;
	}

	return NULL;
}


int tls_extensions_print(struct re_printf *pf,
			 const struct list *extl)
{
	struct le *le;
	uint32_t n = list_count(extl);
	int err;

	err = re_hprintf(pf, "extensions: (%u)\n", n);

	if (!n)
		return err;

	for (le = list_head(extl); le; le = le->next) {
		const struct tls_extension *ext = le->data;

		err |= re_hprintf(pf, ".. %H\n", tls_extension_print, ext);
	}

	return err;
}


const char *tls_extension_name(enum tls_extension_type ext)
{
	switch (ext) {

	case TLS_EXT_SERVER_NAME:           return "server_name";
	case TLS_EXT_USE_SRTP:              return "use_srtp";
	default:                            return "???";
	}
}


struct tls_extension *tls_extensions_apply(const struct list *extl,
					   tls_extension_h *exth, void *arg)
{
	struct le *le = list_head(extl);

	while (le) {
		struct tls_extension *ext = le->data;

		le = le->next;

		if (exth && exth(ext, arg))
			return ext;
	}

	return NULL;
}
