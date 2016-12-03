
#include <string.h>
#include <assert.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_hmac.h>
#include <re_sys.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>


#define DEBUG_MODULE "dtls"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * Generate MAC for the record layer
 *
 *    MAC(MAC_write_key, seq_num +
 *                           TLSCompressed.type +
 *                           TLSCompressed.version +
 *                           TLSCompressed.length +
 *                           TLSCompressed.fragment);
 */
int tls_mac_generate(uint8_t *mac, size_t mac_sz,
		     const struct key *mac_write_key,
		     uint64_t seq_num,
		     enum tls_content_type content_type,
		     enum tls_version proto_ver,
		     uint16_t fragment_length,
		     const uint8_t *fragment)
{
	struct mbuf *mb;
	struct hmac *hmac = NULL;
	enum hmac_hash hash;
	int err = 0;

	if (mac_sz == 20)
		hash = HMAC_HASH_SHA1;
	else if (mac_sz == 32)
		hash = HMAC_HASH_SHA256;
	else
		return EINVAL;

	if (!mac || !mac_sz)
		return EINVAL;
	if (!mac_write_key || !mac_write_key->len) {
		DEBUG_WARNING("mac: write_key not set\n");
		return EINVAL;
	}
	if (!fragment_length || !fragment)
		return EINVAL;

	mb = mbuf_alloc(256);
	if (!mb)
		return ENOMEM;

	err |= mbuf_write_u64(mb, sys_htonll(seq_num));
	err |= mbuf_write_u8(mb, content_type);
	err |= mbuf_write_u16(mb, htons(proto_ver));
	err |= mbuf_write_u16(mb, htons(fragment_length));

	assert(mb->end == 13);

	err |= mbuf_write_mem(mb, fragment, fragment_length);
	if (err)
		goto out;

	err = hmac_create(&hmac, hash, mac_write_key->k, mac_write_key->len);
	if (err)
		goto out;
	err = hmac_digest(hmac, mac, mac_sz, mb->buf, mb->end);
	if (err)
		goto out;

 out:
	mem_deref(hmac);
	mem_deref(mb);
	return err;
}
