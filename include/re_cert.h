/**
 * @file re_cert.h Interface to Certificate handling
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */


struct cert;

int  cert_decode(struct cert **certp, const uint8_t *p, size_t len);
int  cert_decode_pem(struct cert **certp, const char *pem, size_t len);
int  cert_load_file(struct cert **certp, const char *filename);
int  cert_encode_der(const struct cert *cert, uint8_t **derp, size_t *lenp);
int  cert_generate_rsa(struct cert **certp, const char *cn, unsigned bits);

int  cert_public_encrypt(struct cert *cert,
			 uint8_t *out, size_t *out_len,
			 const uint8_t *in, size_t in_len);
int  cert_private_decrypt(struct cert *cert,
			  uint8_t *out, size_t *out_len,
			  const uint8_t *in, size_t in_len);

int  cert_version(const struct cert *cert);
long cert_serial(const struct cert *cert);
int  cert_get_issuer(const struct cert *cert, char *buf, size_t size);
int  cert_get_subject(const struct cert *cert, char *buf, size_t size);
int  cert_get_fingerprint(const struct cert *cert, int type,
			  uint8_t *md, size_t size);


void cert_dump(const struct cert *cert);
