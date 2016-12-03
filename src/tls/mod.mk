#
# mod.mk
#
# Copyright (C) 2010 Creytiv.com
#

ifneq ($(USE_OPENSSL_TLS),)
SRCS	+= tls/openssl/tls.c
SRCS	+= tls/openssl/tls_tcp.c
SRCS	+= tls/openssl/tls_udp.c
else

SRCS	+= tls/re/alert.c
SRCS	+= tls/re/cipher.c
SRCS	+= tls/re/crypt.c
SRCS	+= tls/re/finish.c
SRCS	+= tls/re/handshake.c
SRCS	+= tls/re/hmac.c
SRCS	+= tls/re/key.c
SRCS	+= tls/re/mac.c
SRCS	+= tls/re/master.c
SRCS	+= tls/re/mbuf.c
SRCS	+= tls/re/prf.c
SRCS	+= tls/re/record.c
SRCS	+= tls/re/secparam.c
SRCS	+= tls/re/session.c
SRCS	+= tls/re/util.c
SRCS	+= tls/re/vector.c
SRCS	+= tls/re/version.c

SRCS	+= tls/re/tls.c
SRCS	+= tls/re/tls_tcp.c
SRCS	+= tls/re/tls_udp.c

endif
