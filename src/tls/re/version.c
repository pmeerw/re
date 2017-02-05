/**
 * @file version.c TLS version
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_srtp.h>
#include <re_tls.h>
#include "tls.h"


#undef  TLS1_0_VERSION
#define TLS1_0_VERSION  (enum tls_version)(0x0301)


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


bool tls_version_isvalid(enum tls_version ver)
{
	switch (ver) {

	case  TLS1_2_VERSION:  return true;
	case DTLS1_2_VERSION:  return true;
	default:
		if (ver == TLS1_0_VERSION)
			return true;
		return false;
	}
}
