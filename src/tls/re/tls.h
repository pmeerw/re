/**
 * @file re/tls.h  TLS backend using libre (Internal API)
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */


struct tls {
	struct cert *cert;
	enum tls_version version;

	enum tls_cipher_suite *suitev;
	size_t suitec;

	struct list exts_local;  /* Local extensions */
};


/* crypt */

int tls_crypt_encrypt(const struct key *write_key,
		      struct mbuf *mb_enc, struct mbuf *data);
int tls_crypt_decrypt(const struct key *write_key,
		      struct mbuf *mb, size_t rec_length,
		      uint8_t *paddingp);


/* hmac */

int hmac_sha256(const uint8_t *key,
		size_t         key_len,
		const uint8_t *data,
		size_t         data_len,
		uint8_t*       out,
		size_t         out_size);


/* mbuf */

int      mbuf_write_u24_hton(struct mbuf *mb, uint24_t u);
int      mbuf_write_u48_hton(struct mbuf *mb, uint48_t u);
uint24_t mbuf_read_u24_ntoh(struct mbuf *mb);
uint48_t mbuf_read_u48_ntoh(struct mbuf *mb);


/* memory utils */

void mem_cpy(uint8_t *dst, size_t dst_sz,
	     const uint8_t *src, size_t src_sz);


/*
 * extensions
 */

enum tls_extension_type {
	TLS_EXT_SERVER_NAME = 0, /* RFC 6066 */
	TLS_EXT_USE_SRTP = 14,  /* RFC 5764 */
};

struct tls_extension {
	struct le le;
	enum tls_extension_type type;
	size_t length;                 /* only set for decoded ext's */

	//struct tls_vector data;

	union {
		struct {
			uint8_t type;
			char *host;
		} server_name;

		struct {
			uint16_t profilev[4];
			size_t profilec;
			/* srtp_mki */
		} use_srtp;
	} v;
};


typedef bool (tls_extension_h)(const struct tls_extension *ext, void *arg);


int tls_extension_add(struct tls_extension **extp, struct list *extl,
		      enum tls_extension_type type);
int tls_extensions_encode(struct tls_vector *vect,
			  const struct list *extl);
int tls_extensions_decode(struct list *extl,
			  const struct tls_vector *vect);
struct tls_extension *tls_extension_find(const struct list *extl,
					 enum tls_extension_type type);
int tls_extensions_print(struct re_printf *pf,
			 const struct list *extl);
const char *tls_extension_name(enum tls_extension_type ext);
struct tls_extension *tls_extensions_apply(const struct list *extl,
					   tls_extension_h *exth, void *arg);


/*
 * session
 */

const struct list *tls_session_remote_exts(const struct tls_session *sess);


/*
 * version
 */

bool tls_version_isvalid(enum tls_version ver);
