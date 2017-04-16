/**
 * @file re/tls.h  TLS backend using libre (Internal API)
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */


#define TLS_MAX_RSA_BYTES 512  /* 4096 bits */

#define DTLS_COOKIE_LENGTH 256


/*
  State Machine:

IDLE                                   IDLE

      -------- ClientHello ------->
CH                                      CH
      <------- ServerHello -------
      <------- Certificate -------
      <----- ServerHelloDone -----
SHD
      ----- ClientKeyExchange ---->

      ===== ChangeCipherSpec =====>
      -------- Finished (*) ------>    FINI

      <===== ChangeCipherSpec =====
      <--------- Finished (*) -----
FINI

XXX: very simple fsm for now, improve later
*/
enum tls_state {

	TLS_STATE_IDLE                   =  0,

	TLS_STATE_CLIENT_HELLO_SENT      =  2,  /* client */
	TLS_STATE_CLIENT_HELLO_RECV      =  3,  /* server */

	TLS_STATE_SERVER_HELLO_DONE_RECV =  8,  /* client */
	TLS_STATE_FINISHED_RECV          = 10,
};


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
	uint8_t encr_pre_master_secret[TLS_MAX_RSA_BYTES];
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
	bool got_cert;

	/*
	 * PROTOCOL LAYERS BELOW:
	 */

	/* handshake layer: */
	struct {

		SHA256_CTX ctx;          /* hash of Handshakes sent/received */

		uint16_t seq_write;
		uint16_t seq_read;
		size_t bytes_write;
		size_t bytes_read;

		struct mbuf *mb;     /* buffer incoming handshake fragments */

		uint8_t cookie[DTLS_COOKIE_LENGTH];    /* DTLS only */
		size_t cookie_len;

	} handshake;

	enum tls_state state;

	/* record layer: */
	struct tls_record_layer {
		struct mbuf *mb_write;  /* buffer outgoing records         */
		struct mbuf *mb;        /* buffer for incoming TCP-packets */

		uint64_t seq_write;     /* sequence number for each record */
		uint64_t seq_read;      /* sequence number for each record */
		uint16_t epoch_write;   /* only for DTLS */
		uint16_t epoch_read;    /* only for DTLS */

		size_t bytes_write;
		size_t bytes_read;

		uint64_t next_receive_seq;  /* DTLS only */
	} record_layer;

	size_t record_fragment_size;

	struct list exts_remote;
};

const struct list *tls_session_remote_exts(const struct tls_session *sess);
bool tls_cipher_suite_lookup(const struct tls_session *sess,
			     enum tls_cipher_suite cs);
void tls_session_set_state(struct tls_session *sess, enum tls_state state);
const char *tls_state_name(enum tls_state st);
int tls_send_certificate(struct tls_session *sess);
void tls_handle_cleartext_record(struct tls_session *sess,
				 const struct tls_record *rec);

int tls_client_send_clienthello(struct tls_session *sess);
int tls_client_handle_server_hello(struct tls_session *sess,
				   const struct serverhello *hell);
int tls_client_send_clientkeyexchange(struct tls_session *sess);

int tls_server_handle_client_hello(struct tls_session *sess,
				   const struct clienthello *chell);
int tls_server_handle_clientkeyexchange(struct tls_session *sess,
					const struct client_key_exchange *cke);

int tls_handshake_layer_send(struct tls_session *sess,
				enum tls_handshake_type msg_type,
				const union handshake *hand,
			     bool flush_now, bool crypt);

int tls_record_layer_write(struct tls_session *sess,
			   enum tls_content_type type,
			   const uint8_t *frag, size_t fraglen,
			   bool flush_now);
int tls_record_layer_send(struct tls_session *sess,
			  enum tls_content_type type,
			  struct mbuf *mb_data, bool flush_now);
void tls_record_layer_new_write_epoch(struct tls_session *sess);
void tls_record_layer_new_read_epoch(struct tls_session *sess);
uint64_t tls_record_get_read_seqnum(const struct tls_session *sess);
uint64_t tls_record_get_write_seqnum(const struct tls_session *sess);
int tls_record_layer_handle_record(struct tls_session *sess,
				   struct tls_record *rec);


/*
 * version
 */

bool tls_version_isvalid(enum tls_version ver);


int tls_record_print_prefix(struct re_printf *pf,
			    const struct tls_record *rec);
