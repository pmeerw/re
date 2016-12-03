/**
 * @file tls.c TLS context
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
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


/* NOTE: shadow struct defined in tls_*.c */
struct tls_conn {
	struct tls_session *ssl;
};


/*
 * Default list of supported Cipher-Suites, sorted by strength
 */
static const enum tls_cipher_suite default_suitev[] = {

	TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
};


static void destructor(void *data)
{
	struct tls *tls = data;

	mem_deref(tls->suitev);
	mem_deref(tls->cert);
	mem_deref(tls->pass);
}


int tls_alloc(struct tls **tlsp, enum tls_method method, const char *keyfile,
	      const char *pwd)
{
	struct tls *tls;
	int err;

	if (!tlsp)
		return EINVAL;

	tls = mem_zalloc(sizeof(*tls), destructor);
	if (!tls)
		return ENOMEM;

	switch (method) {

	case TLS_METHOD_SSLV23:
		tls->version = TLS1_2_VERSION;
		break;

	case TLS_METHOD_DTLSV1:
	case TLS_METHOD_DTLS:
	case TLS_METHOD_DTLSV1_2:
		tls->version = DTLS1_2_VERSION;
		break;

	default:
		DEBUG_WARNING("tls method %d not supported\n", method);
		err = ENOSYS;
		goto out;
	}

	tls->suitec = ARRAY_SIZE(default_suitev);
	tls->suitev = mem_reallocarray(NULL, tls->suitec,
				       sizeof(*tls->suitev), NULL);
	memcpy(tls->suitev, default_suitev, sizeof(default_suitev));

#if 0
	re_printf("context: suitec=%zu\n", tls->suitec);
	for (i=0; i<tls->suitec; i++) {
		enum tls_cipher_suite cs = tls->suitev[i];

		re_printf("....  0x%04x (%s)\n",
			  cs, tls_cipher_suite_name(cs));
	}
#endif

	/* Load our keys and certificates */
	if (keyfile) {
		if (pwd) {
			err = str_dup(&tls->pass, pwd);
			if (err)
				goto out;
		}

		err = cert_load_file(&tls->cert, keyfile);
		if (err)
			goto out;
	}

	DEBUG_INFO("created context with %s (%s)\n",
		   dtls_version_name(tls->version), keyfile);

	err = 0;
 out:
	if (err)
		mem_deref(tls);
	else
		*tlsp = tls;

	return err;
}


int tls_add_ca(struct tls *tls, const char *capath)
{
	return ENOSYS;
}


int tls_set_selfsigned(struct tls *tls, const char *cn)
{
	struct cert *cert = NULL;
	int err;

	if (!tls || !cn)
		return EINVAL;

	err = cert_generate_rsa(&cert, cn, 1024);
	if (err)
		return err;

	mem_deref(tls->cert);
	tls->cert = cert;

	return 0;
}


int tls_set_certificate(struct tls *tls, const char *pem, size_t len)
{
	struct cert *cert;
	int err;

	if (!tls || !pem || !len)
		return EINVAL;

	err = cert_decode_pem(&cert, pem, len);
	if (err)
		return err;

	mem_deref(tls->cert);
	tls->cert = cert;

	return 0;
}


void tls_set_verify_client(struct tls *tls)
{
	if (!tls)
		return;

	re_printf("TODO: implement %s\n", __REFUNC__);
}


int tls_set_srtp(struct tls *tls, const char *suites)
{
	(void)tls;
	(void)suites;

	return ENOSYS;
}


int tls_fingerprint(const struct tls *tls, enum tls_fingerprint type,
		    uint8_t *md, size_t size)
{
	if (!tls || !tls->cert || !md)
		return EINVAL;

	return cert_get_fingerprint(tls->cert, type, md, size);
}


int tls_set_ciphers(struct tls *tls, const char *cipherv[], size_t count)
{
	enum tls_cipher_suite *suitev;
	size_t i, sz;
	int err = 0;

	if (!tls || !cipherv || !count)
		return EINVAL;

	sz = count * sizeof(enum tls_cipher_suite);

	suitev = mem_zalloc(sz, NULL);
	if (!suitev)
		return ENOMEM;

	for (i=0; i<count; i++) {

		enum tls_cipher_suite cs;

		cs = tls_cipher_suite_resolve(cipherv[i]);
		if (cs == TLS_NULL_WITH_NULL_NULL) {
			DEBUG_WARNING("cipher suite not supported: %s\n",
				      cipherv[i]);
			err = ENOTSUP;
			goto out;
		}

		suitev[i] = cs;
	}

	mem_deref(tls->suitev);
	tls->suitev = suitev;
	tls->suitec = count;

	suitev = NULL;

 out:
	mem_deref(suitev);
	return err;
}


int tls_peer_fingerprint(const struct tls_conn *tc, enum tls_fingerprint type,
			 uint8_t *md, size_t size)
{
	struct cert *cert;

	if (!tc || !md)
		return EINVAL;

	cert = tls_session_peer_certificate(tc->ssl);
	if (!cert)
		return ENOENT;

	return cert_get_fingerprint(cert, type, md, size);
}


int tls_peer_common_name(const struct tls_conn *tc, char *cn, size_t size)
{
	struct cert *cert;

	if (!tc || !cn || !size)
		return EINVAL;

	cert = tls_session_peer_certificate(tc->ssl);
	if (!cert)
		return ENOENT;

	return cert_get_subject(cert, cn, size);
}


int tls_peer_verify(const struct tls_conn *tc)
{
	return ENOSYS;
}


int tls_srtp_keyinfo(const struct tls_conn *tc, enum srtp_suite *suite,
		     uint8_t *cli_key, size_t cli_key_size,
		     uint8_t *srv_key, size_t srv_key_size)
{
	(void)tc;
	(void)suite;
	(void)cli_key;
	(void)cli_key_size;
	(void)srv_key;
	(void)srv_key_size;

	return ENOSYS;
}


const char *tls_cipher_name(const struct tls_conn *tc)
{
	if (!tc)
		return NULL;

	return tls_cipher_suite_name(tls_session_cipher(tc->ssl));
}
