#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_srtp.h>
#include <re_tls.h>


bool tls_version_is_dtls(enum tls_version ver)
{
	switch (ver) {

	case DTLS1_2_VERSION: return true;
	default: return false;
	}
}


const char *tls_version_name(enum tls_version ver)
{
	switch (ver) {

	case TLS1_2_VERSION:  return "TLSv1.2";
	case DTLS1_2_VERSION: return "DTLSv1.2";
	default: return "???";
	}
}
