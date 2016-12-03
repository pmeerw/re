
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sys.h>
#include <re_cert.h>
#include <re_sha.h>
#include <re_aes.h>
#include <re_net.h>
#include <re_srtp.h>
#include <re_tls.h>


#define LABEL_LEN 15


int tls_finish_calc(uint8_t verify_data[TLS_VERIFY_DATA_SIZE],
		     const uint8_t master_secret[TLS_MASTER_SECRET_LEN],
		     const uint8_t seed[32],
		     enum tls_connection_end sender)
{
	static const uint8_t label_client[LABEL_LEN] = "client finished";
	static const uint8_t label_server[LABEL_LEN] = "server finished";
	const uint8_t *label;
	int err;

	if (sender == TLS_CLIENT)
		label = label_client;
	else if (sender == TLS_SERVER)
		label = label_server;
	else
		return EINVAL;

	err = tls_prf_sha256(verify_data, TLS_VERIFY_DATA_SIZE,
			      master_secret, TLS_MASTER_SECRET_LEN,
			      label, LABEL_LEN,
			      seed, 32);
	if (err) {
		return err;
	}

	return 0;
}
