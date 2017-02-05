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
#include <re_list.h>
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


# define SRTP_AES128_CM_SHA1_80 0x0001
# define SRTP_AES128_CM_SHA1_32 0x0002


/* NOTE: shadow struct defined in tls_*.c */
struct tls_conn {
	struct tls_session *ssl;
	struct tls *tls;
};


/*
 * Default list of supported Cipher-Suites, sorted by strength
 */
static const enum tls_cipher_suite default_suitev[] = {

	TLS_CIPHER_RSA_WITH_AES_256_CBC_SHA256,
	TLS_CIPHER_RSA_WITH_AES_128_CBC_SHA256,
	TLS_CIPHER_RSA_WITH_AES_256_CBC_SHA,
	TLS_CIPHER_RSA_WITH_AES_128_CBC_SHA,
};


static void destructor(void *data)
{
	struct tls *tls = data;

#if 0
	re_printf("\n -- context summary --\n");
	re_printf("Local %H\n", tls_extensions_print, &tls->exts_local);
#endif

	mem_deref(tls->suitev);
	mem_deref(tls->cert);
	list_flush(&tls->exts_local);
}


int tls_alloc(struct tls **tlsp, enum tls_method method, const char *keyfile,
	      const char *pwd)
{
	struct tls *tls;
	int err;
	(void)pwd;

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
	(void)tls;
	(void)capath;
	DEBUG_WARNING("add_ca: not implemented\n");
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


static uint16_t profile_decode(const struct pl *pl)
{
	if (!pl_strcasecmp(pl, "SRTP_AES128_CM_SHA1_80"))
		return SRTP_AES128_CM_SHA1_80;
	else if (!pl_strcasecmp(pl, "SRTP_AES128_CM_SHA1_32"))
		return SRTP_AES128_CM_SHA1_32;
	else {
		return 0;
	}
}


int tls_set_srtp(struct tls *tls, const char *suites)
{
	struct tls_extension *ext;
	struct pl pl;
	size_t i=0;
	int err;

	if (!tls || !suites)
		return EINVAL;

	err = tls_extension_add(&ext, &tls->exts_local, TLS_EXT_USE_SRTP);
	if (err)
		return err;

	pl_set_str(&pl, suites);

	while (pl.l) {
		struct pl pl_suite, pl_colon;
		uint16_t profile;

		err = re_regex(pl.p, pl.l, "[^:]+[:]*", &pl_suite, &pl_colon);
		if (err) {
			DEBUG_WARNING("invalid suites string\n");
			goto out;
		}

		profile = profile_decode(&pl_suite);
		if (!profile) {
			DEBUG_WARNING("suite not supported: %r\n", &pl_suite);
			err = ENOTSUP;
			goto out;
		}

		ext->v.use_srtp.profilev[i] = profile;

		++i;
		pl_advance(&pl, pl_suite.l + pl_colon.l);
	}

	ext->v.use_srtp.profilec = i;

 out:
	return err;
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
		if (cs == TLS_CIPHER_NULL_WITH_NULL_NULL) {
			DEBUG_WARNING("set_ciphers: cipher suite"
				      " not supported: %s\n",
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
	(void)tc;
	DEBUG_WARNING("peer_verify: not implemented\n");
	return ENOSYS;
}


#define LABEL_LEN 19
int tls_srtp_keyinfo(const struct tls_conn *tc, enum srtp_suite *suite,
		     uint8_t *cli_key, size_t cli_key_size,
		     uint8_t *srv_key, size_t srv_key_size)
{
	static const uint8_t label[LABEL_LEN] = "EXTRACTOR-dtls_srtp";
	struct tls_secparam *secparam;
	struct tls_extension *extl, *extr;
	size_t key_size, salt_size, size;
	uint16_t common_profile = 0;
	uint8_t output[2 * 30];
	uint8_t seed[TLS_CLIENT_RANDOM_LEN + TLS_SERVER_RANDOM_LEN];
	uint8_t *sp = seed, *p;
	bool write = false;
	size_t i, j;
	int err;

	if (!tc || !suite || !cli_key || !srv_key)
		return EINVAL;

	extl = tls_extension_find(&tc->tls->exts_local, TLS_EXT_USE_SRTP);
	extr = tls_extension_find(tls_session_remote_exts(tc->ssl),
				 TLS_EXT_USE_SRTP);
	if (!extl) {
		DEBUG_WARNING("keyinfo: no local extensions\n");
		return ENOENT;
	}
	if (!extr) {
		DEBUG_WARNING("keyinfo: no remote extensions\n");
		return ENOENT;
	}

	/* find a common SRTP profile */
	for (i=0; i<extr->v.use_srtp.profilec && !common_profile; i++) {

		uint16_t rprofile = extr->v.use_srtp.profilev[i];

		for (j=0; j<extl->v.use_srtp.profilec; j++) {

			uint16_t lprofile = extl->v.use_srtp.profilev[j];
			if (rprofile == lprofile) {
				common_profile = rprofile;
				break;
			}
		}
	}
	if (!common_profile) {
		DEBUG_WARNING("keyinfo: no common srtp profile\n");
		return ENOENT;
	}

	switch (common_profile) {

	case SRTP_AES128_CM_SHA1_80:
		*suite = SRTP_AES_CM_128_HMAC_SHA1_80;
		key_size  = 16;
		salt_size = 14;
		break;

	case SRTP_AES128_CM_SHA1_32:
		*suite = SRTP_AES_CM_128_HMAC_SHA1_32;
		key_size  = 16;
		salt_size = 14;
		break;

	default:
		DEBUG_WARNING("keyinfo: unsupported profile 0x%04x\n",
			      common_profile);
		return ENOSYS;
	}

	size = key_size + salt_size;

	if (cli_key_size < size || srv_key_size < size)
		return EOVERFLOW;

	secparam = tls_session_secparam(tc->ssl, write);

	memcpy(sp, secparam->client_random, TLS_CLIENT_RANDOM_LEN);
	sp += TLS_CLIENT_RANDOM_LEN;
	memcpy(sp, secparam->server_random, TLS_SERVER_RANDOM_LEN);

	err = tls_prf_sha256(output, sizeof(output),
			     secparam->master_secret, TLS_MASTER_SECRET_LEN,
			     label, LABEL_LEN,
			     seed, sizeof(seed));
	if (err) {
		DEBUG_WARNING("srtp_keyinfo: prf_sha256 failed (%m)\n", err);
		return err;
	}

	p = output;

	memcpy(cli_key,            p, key_size);  p += key_size;
	memcpy(srv_key,            p, key_size);  p += key_size;
	memcpy(cli_key + key_size, p, salt_size); p += salt_size;
	memcpy(srv_key + key_size, p, salt_size);

	return 0;
}


const char *tls_cipher_name(const struct tls_conn *tc)
{
	if (!tc)
		return NULL;

	return tls_cipher_suite_name(tls_session_cipher(tc->ssl));
}


int tls_set_servername(struct tls_conn *tc, const char *servername)
{
	struct tls_extension *ext;
	struct tls *tls;
	int err;

	if (!tc || !servername)
		return EINVAL;

	tls = tc->tls; // XXX not correct
	if (!tls) {
		DEBUG_WARNING("set_servername: no tls context\n");
		return ENOTSUP;
	}

	err = tls_extension_add(&ext, &tls->exts_local, TLS_EXT_SERVER_NAME);
	if (err)
		return err;

	ext->v.server_name.type = 0;
	err = str_dup(&ext->v.server_name.host, servername);

	return err;
}


int tls_get_servername(struct tls_conn *tc, char *servername, size_t sz)
{
	struct tls_extension *ext;

	if (!tc || !servername || !sz)
		return EINVAL;

	ext = tls_extension_find(tls_session_remote_exts(tc->ssl),
				 TLS_EXT_SERVER_NAME);
	if (!ext) {
		DEBUG_WARNING("remote server_name is missing\n");
		return ENOENT;
	}

	if (ext->v.server_name.type != 0)
		return ENOTSUP;

	str_ncpy(servername, ext->v.server_name.host, sz);

	return 0;
}
