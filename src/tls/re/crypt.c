
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sys.h>
#include <re_cert.h>
#include <re_sha.h>
#include <re_aes.h>
#include <re_srtp.h>
#include <re_tls.h>


#define DEBUG_MODULE "dtls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


#define IV_SIZE 16


int tls_crypt_encrypt(const struct key *write_key,
		       struct mbuf *mb_enc, struct mbuf *data)
{
	struct aes *aes = NULL;
	uint8_t iv[AES_BLOCK_SIZE]={1,2,3}; /* TODO: random */
	size_t padding;
	int err;

	if (!write_key || !mb_enc || !data)
		return EINVAL;

	err = aes_alloc(&aes, AES_MODE_CBC_ENCRYPT,
			write_key->k,
			write_key->len*8,
			iv);
	if (err) {
		DEBUG_WARNING("encrypt: aes_alloc failed (%m)\n", err);
		goto out;
	}

	padding = 16 - (data->end % 16) - 1;

	/* complete the input for block-ciphered struct */
	if (padding)
		err = mbuf_fill(data, padding, padding);
	err |= mbuf_write_u8(data, padding);
	err |= mbuf_write_mem(mb_enc, iv, sizeof(iv));
	if (err)
		goto out;

	err = aes_encr(aes, mbuf_buf(mb_enc), data->buf, data->end);
	if (err)
		goto out;

	mb_enc->pos = sizeof iv + data->end;
	mb_enc->end = sizeof iv + data->end;

 out:
	mem_deref(aes);
	return err;
}


int tls_crypt_decrypt(const struct key *write_key,
		       struct mbuf *mb, size_t rec_length,
		       uint8_t *paddingp)
{
	struct aes *aes = NULL;
	uint8_t iv[IV_SIZE], padding;
	size_t start, pos_pad, block_len;
	int err;

	if (!write_key || !mb)
		return EINVAL;
	if (rec_length % AES_BLOCK_SIZE) {
		DEBUG_WARNING("decrypt: length %zu not divisble by"
			      " AES_BLOCK_SIZE (16)\n", rec_length);
		return EBADMSG;
	}
	if (rec_length < sizeof(iv))
		return ENODATA;

	start     = mb->pos;
	pos_pad   = start + rec_length - 1;
	block_len = rec_length - sizeof(iv);

	err = mbuf_read_mem(mb, iv, sizeof(iv));
	if (err)
		goto out;

	if (mbuf_get_left(mb) < block_len) {
		DEBUG_WARNING("decrypt: not enough data in mbuf for "
			      "block-cipher (%d bytes missing)\n",
			      (int)(block_len - mbuf_get_left(mb)));
		err = ENODATA;
		goto out;
	}

	err = aes_alloc(&aes, AES_MODE_CBC_DECRYPT,
			write_key->k,
			write_key->len*8,
			iv);
	if (err)
		goto out;

	err = aes_decr(aes, mbuf_buf(mb), mbuf_buf(mb), block_len);
	if (err)
		goto out;

	/* the MBUF now contains a cleartext record */

	padding = mb->buf[pos_pad];

	*paddingp = padding;

 out:
	mem_deref(aes);
	return err;
}
