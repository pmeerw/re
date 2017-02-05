/**
 * @file re_tls.h  Interface to Transport Layer Security
 *
 * Copyright (C) 2010 Creytiv.com
 */


// TODO: temp to test nameclash
#if 1
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#endif


struct sa;
struct tls;
struct tls_conn;
struct tcp_conn;
struct udp_sock;


/** Defines the TLS method */
enum tls_method {
	TLS_METHOD_SSLV23,
	TLS_METHOD_DTLSV1,
	TLS_METHOD_DTLS,      /* DTLS 1.0 and 1.2 */
	TLS_METHOD_DTLSV1_2,  /* DTLS 1.2 */
};

enum tls_fingerprint {
	TLS_FINGERPRINT_SHA1,
	TLS_FINGERPRINT_SHA256,
};

enum tls_keytype {
	TLS_KEYTYPE_RSA,
	TLS_KEYTYPE_EC,
};


int tls_alloc(struct tls **tlsp, enum tls_method method, const char *keyfile,
	      const char *pwd);
int tls_add_ca(struct tls *tls, const char *capath);
int tls_set_selfsigned(struct tls *tls, const char *cn);
int tls_set_certificate_pem(struct tls *tls, const char *cert, size_t len_cert,
			    const char *key, size_t len_key);
int tls_set_certificate_der(struct tls *tls, enum tls_keytype keytype,
			    const uint8_t *cert, size_t len_cert,
			    const uint8_t *key, size_t len_key);
int tls_set_certificate(struct tls *tls, const char *cert, size_t len);
void tls_set_verify_client(struct tls *tls);
int tls_set_srtp(struct tls *tls, const char *suites);
int tls_fingerprint(const struct tls *tls, enum tls_fingerprint type,
		    uint8_t *md, size_t size);

int tls_peer_fingerprint(const struct tls_conn *tc, enum tls_fingerprint type,
			 uint8_t *md, size_t size);
int tls_peer_common_name(const struct tls_conn *tc, char *cn, size_t size);
int tls_peer_verify(const struct tls_conn *tc);
int tls_srtp_keyinfo(const struct tls_conn *tc, enum srtp_suite *suite,
		     uint8_t *cli_key, size_t cli_key_size,
		     uint8_t *srv_key, size_t srv_key_size);
const char *tls_cipher_name(const struct tls_conn *tc);
int tls_set_ciphers(struct tls *tls, const char *cipherv[], size_t count);
int tls_set_servername(struct tls_conn *tc, const char *servername);
int tls_get_servername(struct tls_conn *tc, char *servername, size_t sz);


/* TCP */

int tls_start_tcp(struct tls_conn **ptc, struct tls *tls,
		  struct tcp_conn *tcp, int layer);


/* UDP (DTLS) */

typedef void (dtls_conn_h)(const struct sa *peer, void *arg);
typedef void (dtls_estab_h)(void *arg);
typedef void (dtls_recv_h)(struct mbuf *mb, void *arg);
typedef void (dtls_close_h)(int err, void *arg);

struct dtls_sock;

int dtls_listen(struct dtls_sock **sockp, const struct sa *laddr,
		struct udp_sock *us, uint32_t htsize, int layer,
		dtls_conn_h *connh, void *arg);
struct udp_sock *dtls_udp_sock(struct dtls_sock *sock);
void dtls_set_mtu(struct dtls_sock *sock, size_t mtu);
int dtls_connect(struct tls_conn **ptc, struct tls *tls,
		 struct dtls_sock *sock, const struct sa *peer,
		 dtls_estab_h *estabh, dtls_recv_h *recvh,
		 dtls_close_h *closeh, void *arg);
int dtls_accept(struct tls_conn **ptc, struct tls *tls,
		struct dtls_sock *sock,
		dtls_estab_h *estabh, dtls_recv_h *recvh,
		dtls_close_h *closeh, void *arg);
int dtls_send(struct tls_conn *tc, struct mbuf *mb);
void dtls_set_handlers(struct tls_conn *tc, dtls_estab_h *estabh,
		       dtls_recv_h *recvh, dtls_close_h *closeh, void *arg);
const struct sa *dtls_peer(const struct tls_conn *tc);
void dtls_set_peer(struct tls_conn *tc, const struct sa *peer);


#ifndef USE_OPENSSL_TLS

/*
 * Low-level API for native TLS-stack
 */


/* forward declarations */

struct mbuf;
struct cert;


/* TLS constants */
enum {
	TLS_MASTER_SECRET_LEN     = 48,
	TLS_CLIENT_RANDOM_LEN     = 32,
	TLS_SERVER_RANDOM_LEN     = 32,

	TLS_RECORD_FRAGMENT_SIZE  = 16384,  /* 2^14 */

	TLS_VERIFY_DATA_SIZE      = 12,
};


/* Basic types */

typedef uint32_t uint24_t;
typedef uint64_t uint48_t;

struct tls_vector {
	size_t bytes;
	void *data;      /* note: network byte order */
};


/* Security Parameters */

enum tls_connection_end {
	TLS_CLIENT = 0,
	TLS_SERVER = 1
};

enum tls_bulkcipher_algorithm {
	TLS_BULKCIPHER_NULL = 0,
	TLS_BULKCIPHER_AES
};

enum tls_ciphertype {
	TLS_CIPHERTYPE_STREAM = 0,
	TLS_CIPHERTYPE_BLOCK,
	/*TLS_CIPHERTYPE_AEAD*/
};

enum tls_cipher {
	TLS_C_NULL = 0,
	TLS_AES_128_CBC,
	TLS_AES_256_CBC,
};

enum tls_mac_algorithm {
	TLS_MAC_NULL=0,
	TLS_MAC_HMAC_SHA1,
	TLS_MAC_HMAC_SHA256,
	/*TLS_MAC_HMAC_SHA384,*/
	/*TLS_MAC_HMAC_SHA512*/
};

enum tls_compression_method {
	TLS_COMPRESSION_NULL    = 0,
};


/* Basic TLS Protocol types */

enum tls_content_type {
	TLS_CHANGE_CIPHER_SPEC = 20,
	TLS_ALERT              = 21,
	TLS_HANDSHAKE          = 22,
	TLS_APPLICATION_DATA   = 23,
};

/** DTLS versions (host endianness) */
enum tls_version {
#undef  TLS1_2_VERSION
	TLS1_2_VERSION          = 0x0303,
#undef  DTLS1_2_VERSION
	DTLS1_2_VERSION         = 0xfefd,
};


/* Handshake types */

enum tls_handshake_type {
	TLS_HELLO_REQUEST        =  0,
	TLS_CLIENT_HELLO         =  1,
	TLS_SERVER_HELLO         =  2,
	TLS_HELLO_VERIFY_REQUEST =  3,  /* DTLS only */
	TLS_CERTIFICATE          = 11,
	TLS_SERVER_KEY_EXCHANGE  = 12,
	TLS_CERTIFICATE_REQUEST  = 13,
	TLS_SERVER_HELLO_DONE    = 14,
	TLS_CERTIFICATE_VERIFY   = 15,
	TLS_CLIENT_KEY_EXCHANGE  = 16,
	TLS_FINISHED             = 20,
};

enum tls_alertlevel {
	TLS_LEVEL_WARNING = 1,
	TLS_LEVEL_FATAL   = 2
};

enum tls_alertdescr {
	TLS_ALERT_CLOSE_NOTIFY            =   0,
	TLS_ALERT_UNEXPECTED_MESSAGE      =  10,
	TLS_ALERT_BAD_RECORD_MAC          =  20,
	TLS_ALERT_RECORD_OVERFLOW         =  22,
	TLS_ALERT_DECOMPRESSION_FAILURE   =  30,
	TLS_ALERT_HANDSHAKE_FAILURE       =  40,
	TLS_ALERT_BAD_CERTIFICATE         =  42,
	TLS_ALERT_UNSUPPORTED_CERTIFICATE =  43,
	TLS_ALERT_CERTIFICATE_REVOKED     =  44,
	TLS_ALERT_CERTIFICATE_EXPIRED     =  45,
	TLS_ALERT_CERTIFICATE_UNKNOWN     =  46,
	TLS_ALERT_ILLEGAL_PARAMETER       =  47,
	TLS_ALERT_UNKNOWN_CA              =  48,
	TLS_ALERT_ACCESS_DENIED           =  49,
	TLS_ALERT_DECODE_ERROR            =  50,
	TLS_ALERT_DECRYPT_ERROR           =  51,
	TLS_ALERT_PROTOCOL_VERSION        =  70,
	TLS_ALERT_INSUFFICIENT_SECURITY   =  71,
	TLS_ALERT_INTERNAL_ERROR          =  80,
	TLS_ALERT_USER_CANCELED           =  90,
	TLS_ALERT_NO_RENEGOTIATION        = 100,
	TLS_ALERT_UNSUPPORTED_EXTENSION   = 110,
};

#define CIPHER(a,b)  (a)<<8 | (b)
enum tls_cipher_suite {

	TLS_CIPHER_NULL_WITH_NULL_NULL            = CIPHER(0x00,0x00),

	/* RSA cipher-suites */
	TLS_CIPHER_RSA_WITH_NULL_SHA              = CIPHER(0x00,0x02),
	TLS_CIPHER_RSA_WITH_NULL_SHA256           = CIPHER(0x00,0x3B),
	TLS_CIPHER_RSA_WITH_AES_128_CBC_SHA       = CIPHER(0x00,0x2F), /*mand*/
	TLS_CIPHER_RSA_WITH_AES_256_CBC_SHA       = CIPHER(0x00,0x35),
	TLS_CIPHER_RSA_WITH_AES_128_CBC_SHA256    = CIPHER(0x00,0x3C),
	TLS_CIPHER_RSA_WITH_AES_256_CBC_SHA256    = CIPHER(0x00,0x3D),
};

struct tls_change_cipher_spec {
	uint8_t byte;
};

struct tls_alert {
	enum tls_alertlevel level;
	enum tls_alertdescr descr;
};

struct tls_handshake {
	enum tls_handshake_type msg_type;
	uint24_t length;
	uint16_t message_seq;                               /* DTLS only */
	uint24_t fragment_offset;                           /* DTLS only */
	uint24_t fragment_length;                           /* DTLS only */

	union handshake {
		struct clienthello {
			enum tls_version client_version;
			uint8_t random[TLS_CLIENT_RANDOM_LEN];
			struct tls_vector session_id;
			struct tls_vector cookie;          /* DTLS only */
			struct tls_vector cipher_suites;
			struct tls_vector compression_methods;
			struct tls_vector extensions;
		} clienthello;

		struct serverhello {
			enum tls_version server_version;
			uint8_t random[TLS_SERVER_RANDOM_LEN];
			struct tls_vector session_id;
			enum tls_cipher_suite cipher_suite;
			enum tls_compression_method compression_method;
			struct tls_vector extensions;
		} serverhello;

		struct hello_verify_req {
			enum tls_version server_version;
			struct tls_vector cookie;
		} hello_verify_req;

		struct certificate {
			struct tls_vector certlist[4];
			size_t count;
		} certificate;

		struct client_key_exchange {
			struct tls_vector encr_pms;
		} client_key_exchange;

		struct finished {
			uint8_t verify_data[TLS_VERIFY_DATA_SIZE];
		} finished;
	} u;
};


/**
 * Defines a TLS Record.
 *
 * 1 record can contain multiple handshake messages,
 * or N records can contain 1 handshake message
 */
struct tls_record {
	enum tls_content_type content_type;
	enum tls_version proto_ver;
	uint16_t epoch;                       /* DTLS only */
	uint48_t seq;                         /* DTLS only */
	uint16_t length;                      /* fragment length */
	uint8_t *fragment;
};


enum tls_key_exchange {
	TLS_KE_K_NULL = 0,
	TLS_KE_RSA,        /* RSA public key algorithm */
};

struct tls_suite {
	enum tls_cipher_suite suite;
	enum tls_key_exchange key_exchange;
	enum tls_cipher cipher;
	enum tls_mac_algorithm mac;
};


/* vector */

int  tls_vector_init(struct tls_vector *vect,
		     const uint8_t *data, size_t len);
int  tls_vector_encode(struct mbuf *mb, const struct tls_vector *vect,
		       unsigned hdr_bytes);
int  tls_vector_decode(struct tls_vector *vect, unsigned hdr_bytes,
		       struct mbuf *mb);
int  tls_vector_decode_hdr(struct tls_vector *vect, unsigned hdr_bytes,
			   struct mbuf *mb);
void tls_vector_reset(struct tls_vector *vect);


/* alert */

int         tls_alert_encode(struct mbuf *mb, const struct tls_alert *alert);
int         tls_alert_decode(struct tls_alert *alert, struct mbuf *mb);
const char *tls_alert_name(enum tls_alertdescr descr);


/* handshake */

int  tls_handshake_encode(struct mbuf *mb, enum tls_version ver,
			  enum tls_handshake_type msg_type,
			  uint16_t message_seq,
			  uint24_t fragment_offset,
			  const union handshake *hand);
int  tls_handshake_decode(struct tls_handshake **handp,
			  enum tls_version ver, struct mbuf *mb);
const char *tls_handshake_name(enum tls_handshake_type typ);
void tls_handshake_dump(const struct tls_handshake *hand,
			enum tls_version ver);


/* record */

int tls_record_encode(struct mbuf *mb, enum tls_version ver,
		      enum tls_content_type type,
		      uint16_t epoch, uint64_t seq,
		      const uint8_t *frag, size_t fraglen);
int tls_record_decode(struct tls_record **recp, struct mbuf *mb);
size_t tls_record_hdrsize(enum tls_version ver);
const char *tls_content_type_name(enum tls_content_type typ);
void tls_record_dump(const struct tls_record *rec);


/* cipher */

enum tls_ciphertype tls_cipher_type(enum tls_cipher cipher);
unsigned tls_cipher_keymaterial(enum tls_cipher cipher);
unsigned tls_cipher_ivsize(enum tls_cipher cipher);
unsigned tls_cipher_blocksize(enum tls_cipher cipher);
enum tls_bulkcipher_algorithm tls_cipher_algorithm(enum tls_cipher cipher);


unsigned tls_cipher_suite_count(void);
const struct tls_suite *tls_suite_lookup(enum tls_cipher_suite cipher_suite);
unsigned tls_mac_length(enum tls_mac_algorithm mac);
const char *tls_cipher_suite_name(enum tls_cipher_suite cs);
enum tls_cipher_suite tls_cipher_suite_resolve(const char *name);


/* PRF (Pseudorandom Function) */

int tls_prf_sha256(uint8_t *output, size_t output_len,
		   const uint8_t *secret, size_t secret_len,
		   const uint8_t *label, size_t label_len,
		   const uint8_t *seed, size_t seed_len);


/* secparam (Security Parameters) */

struct tls_secparam {
	enum tls_connection_end        entity;
	enum tls_bulkcipher_algorithm  bulk_cipher_algorithm;
	enum tls_ciphertype            cipher_type;
	unsigned                       enc_key_length;         /* bytes */
	unsigned                       block_length;           /* bytes */
	unsigned                       fixed_iv_length;        /* bytes */
	unsigned                       record_iv_length;       /* bytes */
	enum tls_mac_algorithm         mac_algorithm;
	unsigned                       mac_length;
	unsigned                       mac_key_length;
	uint8_t                        master_secret[TLS_MASTER_SECRET_LEN];
	uint8_t                        client_random[TLS_CLIENT_RANDOM_LEN];
	uint8_t                        server_random[TLS_SERVER_RANDOM_LEN];

	bool is_write;
};

int  tls_secparam_init(struct tls_secparam *sp,
		       const uint8_t random[32],
		       bool is_write, bool client);
int  tls_secparam_set(struct tls_secparam *sp,
		      const struct tls_suite *suite);
void tls_secparam_dump(const struct tls_secparam *sp);


/* key generation */

#define TLS_MAX_KEY_SIZE 32
struct key {
	uint8_t k[TLS_MAX_KEY_SIZE];
	size_t len;
};

struct tls_key_block {
	struct key client_write_MAC_key;
	struct key server_write_MAC_key;
	struct key client_write_key;
	struct key server_write_key;
	/*client_write_IV[SecurityParameters.fixed_iv_length] for AEAD */
	/*server_write_IV[SecurityParameters.fixed_iv_length] for AEAD */
};

int tls_keys_generate(struct tls_key_block *keys,
		       const struct tls_secparam *sp);


/* session */

typedef int  (tls_sess_send_h)(struct mbuf *mb, void *arg);
typedef void (tls_sess_estab_h)(void *arg);
typedef void (tls_data_recv_h)(uint8_t *data, size_t datalen, void *arg);
typedef void (tls_sess_close_h)(int err, void *arg);

struct tls_session;

int  tls_session_alloc(struct tls_session **sessp, struct tls *tls,
		       enum tls_connection_end conn_end,
		       enum tls_version ver,
		       const enum tls_cipher_suite *cipherv, size_t cipherc,
		       tls_sess_send_h *sendh,
		       tls_sess_estab_h *estabh,
		       tls_data_recv_h *datarecvh,
		       tls_sess_close_h *closeh, void *arg);
int  tls_session_start(struct tls_session *sess);
struct tls_secparam *tls_session_secparam(struct tls_session *sess,
					  bool write);
int  tls_session_send_data(struct tls_session *sess,
			    const uint8_t *data, size_t data_len);
void tls_session_recvtcp(struct tls_session *sess, struct mbuf *mb);
void tls_session_recvudp(struct tls_session *sess, struct mbuf *mb);
void tls_session_dump(const struct tls_session *sess);
void tls_session_summary(const struct tls_session *sess);
int  tls_session_set_certificate(struct tls_session *sess,
				  const char *pem, size_t len);
void tls_session_set_certificate2(struct tls_session *sess,
				   struct cert *cert);
enum tls_cipher_suite tls_session_cipher(struct tls_session *sess);
int tls_session_set_fragment_size(struct tls_session *sess, size_t size);
struct cert *tls_session_peer_certificate(const struct tls_session *sess);
bool tls_session_is_estab(const struct tls_session *sess);
void tls_session_shutdown(struct tls_session *sess);


/* master secret */

int tls_master_secret_compute(uint8_t master_secret[48],
			      const uint8_t *pre_master_secret,
			      size_t pre_master_secret_len,
			      const uint8_t client_random[32],
			      const uint8_t server_random[32]);


/* MAC */

int tls_mac_generate(uint8_t *mac, size_t mac_sz,
		     const struct key *mac_write_key,
		     uint64_t seq_num,
		     enum tls_content_type content_type,
		     enum tls_version proto_ver,
		     uint16_t fragment_length,
		     const uint8_t *fragment);

/*
 * TLS Version
 */

bool        tls_version_is_dtls(enum tls_version ver);
const char *tls_version_name(enum tls_version ver);


/* finish */

int tls_finish_calc(uint8_t verify_data[TLS_VERIFY_DATA_SIZE],
		    const uint8_t master_secret[TLS_MASTER_SECRET_LEN],
		    const uint8_t seed[32],
		    enum tls_connection_end sender);


/* trace */

enum tls_trace_flags {

	TLS_TRACE_RECORD              = 1<<0,

	TLS_TRACE_CHANGE_CIPHER_SPEC  = 1<<1,
	TLS_TRACE_ALERT               = 1<<2,
	TLS_TRACE_HANDSHAKE           = 1<<3,
	TLS_TRACE_APPLICATION_DATA    = 1<<4,

	TLS_TRACE_ALL = ~0,
};

typedef void (tls_trace_h)(enum tls_trace_flags flag, const char *msg,
			   void *arg);

void tls_trace(struct tls_session *sess, enum tls_trace_flags flags,
	       const char *fmt, ...);
void tls_set_trace(struct tls_session *sess, enum tls_trace_flags flags,
		   tls_trace_h *traceh);
const char *tls_trace_name(enum tls_trace_flags flag);


#endif  /* USE_OPENSSL_TLS */
