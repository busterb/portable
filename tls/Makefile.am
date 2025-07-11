#
# Copyright (c) 2014 Brent Cook
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

include $(top_srcdir)/Makefile.am.common

-include $(abs_top_builddir)/crypto/libcrypto_la_objects.mk
-include $(abs_top_builddir)/ssl/libssl_la_objects.mk

lib_LTLIBRARIES = libtls.la

EXTRA_DIST = VERSION
EXTRA_DIST += CMakeLists.txt
EXTRA_DIST += tls.sym
EXTRA_DIST += empty.c

CLEANFILES = libtls_la_objects.mk

EXTRA_libtls_la_DEPENDENCIES = libtls_la_objects.mk

libtls_la_objects.mk: Makefile
	@echo "libtls_la_objects= $(libtls_la_OBJECTS)" \
	  | sed -e 's/ *$$//' -e 's/  */ $$\(top_builddir\)\/tls\//g' \
	  > libtls_la_objects.mk

libtls_la_LDFLAGS = -version-info @LIBTLS_VERSION@ -no-undefined -export-symbols $(top_srcdir)/tls/tls.sym

if ENABLE_LIBTLS_ONLY
libtls_la_LIBADD = $(libcrypto_la_objects)
libtls_la_LIBADD += $(libssl_la_objects)
else
libtls_la_LIBADD = $(abs_top_builddir)/crypto/libcrypto.la
libtls_la_LIBADD += $(abs_top_builddir)/ssl/libssl.la
endif

libtls_la_LIBADD += $(libcompat_la_objects)
libtls_la_LIBADD += $(libcompatnoopt_la_objects)
libtls_la_LIBADD += $(PLATFORM_LDADD)

libtls_la_CPPFLAGS = $(AM_CPPFLAGS)
if OPENSSLDIR_DEFINED
libtls_la_CPPFLAGS += -DTLS_DEFAULT_CA_FILE=\"@OPENSSLDIR@/cert.pem\"
else
libtls_la_CPPFLAGS += -DTLS_DEFAULT_CA_FILE=\"$(sysconfdir)/ssl/cert.pem\"
endif

libtls_la_SOURCES = tls.c
libtls_la_SOURCES += tls_client.c
libtls_la_SOURCES += tls_bio_cb.c
libtls_la_SOURCES += tls_config.c
libtls_la_SOURCES += tls_conninfo.c
libtls_la_SOURCES += tls_keypair.c
libtls_la_SOURCES += tls_server.c
libtls_la_SOURCES += tls_signer.c
libtls_la_SOURCES += tls_ocsp.c
libtls_la_SOURCES += tls_peer.c
libtls_la_SOURCES += tls_util.c
libtls_la_SOURCES += tls_verify.c
noinst_HEADERS = tls_internal.h

if HOST_WIN
libtls_la_SOURCES += compat/ftruncate.c
libtls_la_SOURCES += compat/pread.c
libtls_la_SOURCES += compat/pwrite.c
endif
