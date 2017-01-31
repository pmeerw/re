/**
 * @file cert.c Certificate handling
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

/* for certificate parsing */
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sys.h>
#include <re_srtp.h>
#include <re_tls.h>
#include <re_cert.h>


#define DEBUG_MODULE "cert"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/* XXX: only RSA supported for now */


struct cert {
	X509 *x509;
	RSA *rsa;
};


static void destructor(void *data)
{
	struct cert *cert = data;

	if (cert->rsa)
		RSA_free(cert->rsa);
	if (cert->x509)
		X509_free(cert->x509);
}


/* X.509v3 in ASN.1 format */
int cert_decode(struct cert **certp, const uint8_t *p, size_t len)
{
	const unsigned char *data;
	struct cert *cert;
	int err = 0;

	if (!certp || !p || !len)
		return EINVAL;

	cert = mem_zalloc(sizeof(*cert), destructor);
	if (!cert)
		return ENOMEM;

	data = p;

	cert->x509 = d2i_X509(NULL, &data, len);
	if (!cert->x509) {
		DEBUG_WARNING("unable to parse certificate %zu bytes in memory"
			      " at offset %zu\n", len, data - p);
		ERR_print_errors_fp(stderr);
		err = EBADMSG;
		goto out;
	}

 out:
	if (err)
		mem_deref(cert);
	else
		*certp = cert;

	return err;
}


/* Certificate in PEM format (Cert + Private key) */
int cert_decode_pem(struct cert **certp, const char *pem, size_t len)
{
	BIO *bio = NULL, *kbio = NULL;
	struct cert *cert;
	int err = 0;

	if (!certp || !pem || !len)
		return EINVAL;

	cert = mem_zalloc(sizeof(*cert), destructor);
	if (!cert)
		return ENOMEM;

	bio  = BIO_new_mem_buf((char *)pem, (int)len);
	kbio = BIO_new_mem_buf((char *)pem, (int)len);
	if (!bio || !kbio) {
		err = ENOMEM;
		goto out;
	}

	cert->x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
	if (!cert->x509) {
		DEBUG_WARNING("unable to parse PEM certificate (%zu bytes)\n",
			      len);
		ERR_print_errors_fp(stderr);
		err = EBADMSG;
		goto out;
	}

	cert->rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
	if (!cert->rsa) {
		DEBUG_WARNING("decode_pem: RSA read error\n");
		err = EBADMSG;
		goto out;
	}


 out:
	if (kbio)
		BIO_free(kbio);
	if (bio)
		BIO_free(bio);
	if (err)
		ERR_clear_error();

	if (err)
		mem_deref(cert);
	else
		*certp = cert;

	return err;
}


/* Certificate in PEM format (Cert + Private key) */
int cert_load_file(struct cert **certp, const char *filename)
{
	BIO *bio = NULL, *kbio = NULL;
	struct cert *cert;
	int err = 0;

	if (!certp || !filename)
		return EINVAL;

	cert = mem_zalloc(sizeof(*cert), destructor);
	if (!cert)
		return ENOMEM;

	bio  = BIO_new_file(filename, "r");
	kbio = BIO_new_file(filename, "r");
	if (!bio || !kbio) {
		err = ENOMEM;
		goto out;
	}

	cert->x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
	if (!cert->x509) {
		DEBUG_WARNING("unable to parse PEM certificate (%s)\n",
			      filename);
		ERR_print_errors_fp(stderr);
		err = EBADMSG;
		goto out;
	}

	cert->rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
	if (!cert->rsa) {
		DEBUG_WARNING("decode_pem: RSA read error (%s)\n", filename);
		err = EBADMSG;
		goto out;
	}

 out:
	if (kbio)
		BIO_free(kbio);
	if (bio)
		BIO_free(bio);
	if (err)
		ERR_clear_error();

	if (err)
		mem_deref(cert);
	else
		*certp = cert;

	return err;
}


int cert_encode_der(const struct cert *cert, uint8_t **derp, size_t *lenp)
{
	uint8_t *der = NULL, *p;
	int sz, len;
	int err = 0;

	if (!cert || !derp || !lenp)
		return EINVAL;

	sz = i2d_X509(cert->x509, NULL);
	if (sz < 0) {
		/* error */
		ERR_clear_error();

		err = EBADMSG;
		goto out;
	}

	der = mem_alloc(sz, NULL);
	if (!der)
		return ENOMEM;

	p = der;

	len = i2d_X509(cert->x509, &p);
	if (len < 0) {
		/* error */
		ERR_clear_error();

		err = EBADMSG;
		goto out;
	}

	*derp = der;
	*lenp = len;

 out:
	if (err)
		mem_deref(der);

	return err;
}


int cert_generate_rsa(struct cert **certp, const char *cn, unsigned bits)
{
	X509_NAME *subj = NULL;
	EVP_PKEY *key = NULL;
	X509 *x509 = NULL;
	BIGNUM *bn = NULL;
	RSA *rsa = NULL;
	int err = ENOMEM;
	struct cert *cert = 0;

	if (!certp || !cn)
		return EINVAL;

	cert = mem_zalloc(sizeof(*cert), destructor);
	if (!cert)
		return ENOMEM;

	rsa = RSA_new();
	if (!rsa)
		goto out;

	bn = BN_new();
	if (!bn)
		goto out;

	BN_set_word(bn, RSA_F4);
	if (!RSA_generate_key_ex(rsa, bits, bn, NULL))
		goto out;

	key = EVP_PKEY_new();
	if (!key)
		goto out;

	if (!EVP_PKEY_set1_RSA(key, rsa))
		goto out;

	x509 = X509_new();
	if (!x509)
		goto out;

	if (!X509_set_version(x509, 2))
		goto out;

	if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), rand_u32()))
		goto out;

	subj = X509_NAME_new();
	if (!subj)
		goto out;

	if (!X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
					(unsigned char *)cn,
					(int)str_len(cn), -1, 0))
		goto out;

	if (!X509_set_issuer_name(x509, subj) ||
	    !X509_set_subject_name(x509, subj))
		goto out;

	if (!X509_gmtime_adj(X509_get_notBefore(x509), -3600*24*365) ||
	    !X509_gmtime_adj(X509_get_notAfter(x509),   3600*24*365*10))
		goto out;

	if (!X509_set_pubkey(x509, key))
		goto out;

	if (!X509_sign(x509, key, EVP_sha1()))
		goto out;

	cert->x509 = x509;
	x509 = NULL;

	cert->rsa = rsa;
	rsa = NULL;

	*certp = cert;

	err = 0;

 out:
	if (subj)
		X509_NAME_free(subj);

	if (x509)
		X509_free(x509);

	if (key)
		EVP_PKEY_free(key);

	if (rsa)
		RSA_free(rsa);

	if (bn)
		BN_free(bn);

	if (err)
		ERR_clear_error();

	return err;
}


int cert_version(const struct cert *cert)
{
	if (!cert)
		return 0;

	return (int)X509_get_version(cert->x509);
}


long cert_serial(const struct cert *cert)
{
	ASN1_INTEGER *a;

	if (!cert)
		return 0;

	a = X509_get_serialNumber(cert->x509);
	if (!a)
		return 0;

	return ASN1_INTEGER_get(a);
}


/* asymmetric encrypt using this Certificate's public key */
int cert_public_encrypt(struct cert *cert,
			uint8_t *out, size_t *out_len,
			const uint8_t *in, size_t in_len)
{
	EVP_PKEY *pubkey = NULL;
	RSA *rsa_key;
	int key_length;
	int algonid, r;
	int err = 0;

	if (!cert || !out || !out_len || !*out_len || !in || !in_len)
		return EINVAL;

	pubkey = X509_get_pubkey(cert->x509);
	if (!pubkey) {
		DEBUG_WARNING("cert: could not get public key\n");
		err = ENOENT;
		goto out;
	}

	algonid = EVP_PKEY_id(pubkey);
#if 0
	algonid = OBJ_obj2nid(cert->x509->cert_info->key->algor->algorithm);
#endif

	DEBUG_INFO("cert: public key has algorithm '%s'\n",
		   OBJ_nid2ln(algonid));

	switch (algonid) {

	case EVP_PKEY_RSA:
		rsa_key = EVP_PKEY_get1_RSA(pubkey);
		if (!rsa_key) {
			DEBUG_WARNING("no rsa_key\n");
			err = ENOENT;
			goto out;
		}

#if 0
		re_fprintf(stderr, "RSA public key:\n");
		RSA_print_fp(stderr, rsa_key, 16);
#endif

		key_length = RSA_size(rsa_key);
		if (key_length > (int)*out_len) {
			re_printf("cert: RSA key is %d bits, but out"
				  " size is only %d bits\n",
				  key_length * 8,
				  *out_len * 8);
			err = EINVAL;
			goto out;
		}

		r = RSA_public_encrypt((int)in_len, in,
				       out,
				       rsa_key, RSA_PKCS1_PADDING);
		if (r == -1) {
			DEBUG_WARNING("encrypt: %s\n",
				      ERR_error_string(ERR_get_error(), NULL));
			goto out;
		}
		if (r > (int)(*out_len)) {
			DEBUG_WARNING("cert: out buffer too small\n");
			err = ENOBUFS;
			goto out;
		}
		*out_len = r;
		break;

	default:
		DEBUG_WARNING("cert: unsupported public key algonid %d\n",
			      algonid);
		err = EPROTO;
		goto out;
	}

 out:
	if (pubkey)
		EVP_PKEY_free(pubkey);

	return err;
}


/* asymmetric decrypt using this Certificate's private key */
int cert_private_decrypt(struct cert *cert,
			uint8_t *out, size_t *out_len,
			const uint8_t *in, size_t in_len)
{
	int key_length;
	int r;
	int err = 0;

	if (!cert || !out || !out_len || !*out_len || !in || !in_len)
		return EINVAL;

	if (!cert->rsa) {
		DEBUG_WARNING("decrypt: no private RSA\n");
		return EINVAL;
	}

	key_length = RSA_size(cert->rsa);
	if (key_length > (int)*out_len) {
		re_printf("cert: RSA key is %d bits, but out"
			  " size is only %d bits\n",
			  key_length * 8,
			  *out_len * 8);
		err = EINVAL;
		goto out;
	}

	r = RSA_private_decrypt((int)in_len, in,
				out, cert->rsa, RSA_PKCS1_PADDING);
	if (r == -1) {
		DEBUG_WARNING("decrypt: %s\n",
			      ERR_error_string(ERR_get_error(), NULL));
		goto out;
	}
	if (r > (int)(*out_len)) {
		DEBUG_WARNING("cert: out buffer too small\n");
		err = ENOBUFS;
		goto out;
	}
	*out_len = r;

 out:
	return err;
}


int cert_get_issuer(const struct cert *cert, char *buf, size_t size)
{
	if (!cert)
		return EINVAL;

	X509_NAME_oneline(X509_get_issuer_name(cert->x509), buf, (int)size);

	return 0;
}


int cert_get_subject(const struct cert *cert, char *buf, size_t size)
{
	int n;

	if (!cert)
		return EINVAL;

	n = X509_NAME_get_text_by_NID(X509_get_subject_name(cert->x509),
				      NID_commonName, buf, (int)size);
	if (n < 0) {
		ERR_clear_error();
		return ENOENT;
	}

	return 0;
}


int cert_get_fingerprint(const struct cert *cert, int type,
			 uint8_t *md, size_t size)
{
	unsigned int len = (unsigned int)size;
	int n;

	switch (type) {

	case TLS_FINGERPRINT_SHA1:
		if (size < 20)
			return EOVERFLOW;

		n = X509_digest(cert->x509, EVP_sha1(), md, &len);
		break;

	case TLS_FINGERPRINT_SHA256:
		if (size < 32)
			return EOVERFLOW;

		n = X509_digest(cert->x509, EVP_sha256(), md, &len);
		break;

	default:
		return ENOSYS;
	}

	if (n != 1) {
		ERR_clear_error();
		return ENOENT;
	}

	return 0;
}


void cert_dump(const struct cert *cert)
{
	if (!cert)
		return;

	X509_print_fp(stderr, cert->x509);
}
