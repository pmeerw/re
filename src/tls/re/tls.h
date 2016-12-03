

struct tls {
	struct cert *cert;
	char *pass;  /* password for private key */
	enum tls_version version;

	enum tls_cipher_suite *suitev;
	size_t suitec;
};


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


