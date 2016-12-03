
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_srtp.h>
#include <re_tls.h>


int tls_alert_encode(struct mbuf *mb, const struct tls_alert *alert)
{
	int err = 0;

	if (!mb || !alert)
		return EINVAL;

	err |= mbuf_write_u8(mb, alert->level);
	err |= mbuf_write_u8(mb, alert->descr);

	return err;
}


int tls_alert_decode(struct tls_alert *alert, struct mbuf *mb)
{
	if (!alert || !mb)
		return EINVAL;
	if (mbuf_get_left(mb) < 2)
		return ENODATA;

	alert->level = mbuf_read_u8(mb);
	alert->descr = mbuf_read_u8(mb);

	return 0;
}


const char *tls_alert_name(enum tls_alertdescr descr)
{
	switch (descr) {

	case TLS_ALERT_CLOSE_NOTIFY:          return "close_notify";
	case TLS_ALERT_UNEXPECTED_MESSAGE:    return "unexpected_message";
	case TLS_ALERT_BAD_RECORD_MAC:        return "bad_record_mac";
	case TLS_ALERT_RECORD_OVERFLOW:       return "record_overflow";
	case TLS_ALERT_DECOMPRESSION_FAILURE: return "decompression_failure";
	case TLS_ALERT_HANDSHAKE_FAILURE:     return "handshake_failure";
	case TLS_ALERT_BAD_CERTIFICATE:       return "bad_certificate";
	case TLS_ALERT_UNSUPPORTED_CERTIFICATE:
		return "unsupported_certificate";
	case TLS_ALERT_CERTIFICATE_REVOKED:   return "certificate_revoked";
	case TLS_ALERT_CERTIFICATE_EXPIRED:   return "certificate_expired";
	case TLS_ALERT_CERTIFICATE_UNKNOWN:   return "certificate_unknown";
	case TLS_ALERT_ILLEGAL_PARAMETER:     return "illegal_parameter";
	case TLS_ALERT_UNKNOWN_CA:            return "unknown_ca";
	case TLS_ALERT_ACCESS_DENIED:         return "access_denied";
	case TLS_ALERT_DECODE_ERROR:          return "decode_error";
	case TLS_ALERT_DECRYPT_ERROR:         return "decrypt_error";
	case TLS_ALERT_PROTOCOL_VERSION:      return "protocol_version";
	case TLS_ALERT_INSUFFICIENT_SECURITY: return "insufficient_security";
	case TLS_ALERT_INTERNAL_ERROR:        return "internal_error";
	case TLS_ALERT_USER_CANCELED:         return "user_canceled";
	case TLS_ALERT_NO_RENEGOTIATION:      return "no_renegotiation";
	case TLS_ALERT_UNSUPPORTED_EXTENSION: return "unsupported_extension";

	default: return "???";
	}
}
